using System.Diagnostics;
using System.Net;
using System.Runtime.CompilerServices;
using System.Threading.Channels;

namespace DogfighterAD.Collectors.ActiveDirectory.Sysvol;

/// <summary>
/// Creates a SYSVOL client that owns Kerberos/SMB authentication instead of relying on
/// the host OS SMB redirector. Credentials are sent only over the worker's redirected
/// stdin; they are never placed in argv, environment variables, logs, or artifacts.
/// </summary>
public sealed class PortableKerberosSysvolClientFactory : IReadOnlySysvolClientFactory
{
    private readonly NetworkCredential _credential;
    private readonly string _server;
    private readonly string _workerExecutablePath;
    private readonly TimeSpan _operationTimeout;
    private readonly TimeSpan _terminationGracePeriod;

    public PortableKerberosSysvolClientFactory(NetworkCredential credential, string server)
        : this(
            credential,
            server,
            SystemSysvolClientFactory.GetDefaultWorkerExecutablePath(),
            SystemSysvolClientFactory.DefaultOperationTimeout,
            SystemSysvolClientFactory.DefaultTerminationGracePeriod)
    {
    }

    internal PortableKerberosSysvolClientFactory(
        NetworkCredential credential,
        string server,
        string workerExecutablePath,
        TimeSpan operationTimeout,
        TimeSpan terminationGracePeriod)
    {
        _credential = credential ?? throw new ArgumentNullException(nameof(credential));
        _server = ValidateServer(server);
        ArgumentException.ThrowIfNullOrWhiteSpace(workerExecutablePath);
        if (operationTimeout <= TimeSpan.Zero || operationTimeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(operationTimeout));
        }
        if (terminationGracePeriod <= TimeSpan.Zero || terminationGracePeriod == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(terminationGracePeriod));
        }

        _workerExecutablePath = workerExecutablePath;
        _operationTimeout = operationTimeout;
        _terminationGracePeriod = terminationGracePeriod;
    }

    public ValueTask<IReadOnlySysvolClient> CreateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!File.Exists(_workerExecutablePath))
        {
            throw new FileNotFoundException(
                "The DogfighterAD SYSVOL worker executable was not found.",
                _workerExecutablePath);
        }

        return ValueTask.FromResult<IReadOnlySysvolClient>(new PortableKerberosSysvolClient(
            _credential,
            _server,
            _workerExecutablePath,
            _operationTimeout,
            _terminationGracePeriod));
    }

    private static string ValidateServer(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var server = value.Trim().TrimEnd('.');
        if (IPAddress.TryParse(server, out _) ||
            server.IndexOfAny(['\\', '/', ':', '\0']) >= 0 ||
            !server.Contains('.', StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Portable Kerberos SYSVOL requires an explicit DNS server/FQDN target.",
                nameof(value));
        }
        return server;
    }
}

internal sealed class PortableKerberosSysvolClient : IReadOnlySysvolClient
{
    private readonly NetworkCredential _credential;
    private readonly string _server;
    private readonly string _workerExecutablePath;
    private readonly TimeSpan _operationTimeout;
    private readonly TimeSpan _terminationGracePeriod;
    private readonly SemaphoreSlim _operationGate = new(1, 1);

    private Process? _worker;
    private Task<string>? _stderrDrain;
    private bool _disposed;

    public PortableKerberosSysvolClient(
        NetworkCredential credential,
        string server,
        string workerExecutablePath,
        TimeSpan operationTimeout,
        TimeSpan terminationGracePeriod)
    {
        _credential = credential;
        _server = server;
        _workerExecutablePath = workerExecutablePath;
        _operationTimeout = operationTimeout;
        _terminationGracePeriod = terminationGracePeriod;
    }

    public async IAsyncEnumerable<SysvolFileEntry> EnumerateFilesAsync(
        string rootPath,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var request = CreateRequest(SysvolWorkerOperation.Enumerate, rootPath, 0);
        var channel = Channel.CreateBounded<SysvolFileEntry>(new BoundedChannelOptions(16)
        {
            SingleReader = true,
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait
        });
        using var iterationCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var producer = ProduceEnumerationAsync(request, channel.Writer, iterationCts.Token);

        try
        {
            await foreach (var item in channel.Reader.ReadAllAsync(cancellationToken))
            {
                yield return item;
            }
        }
        finally
        {
            iterationCts.Cancel();
            try
            {
                await producer.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (iterationCts.IsCancellationRequested)
            {
            }
        }
    }

    public async Task<byte[]> ReadFileAsync(
        string fullPath,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (maxBytes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytes));
        }

        var request = CreateRequest(SysvolWorkerOperation.Read, fullPath, maxBytes);
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[]? result = null;
            await RunWorkerOperationAsync(
                async operationToken =>
                {
                    await SendRequestAsync(request, operationToken).ConfigureAwait(false);
                    using var output = new MemoryStream(Math.Min(maxBytes, 64 * 1024));
                    while (true)
                    {
                        var frame = await ReadFrameAsync(operationToken).ConfigureAwait(false)
                            ?? throw new EndOfStreamException("SYSVOL worker exited during file read.");
                        switch (frame.Kind)
                        {
                            case SysvolWorkerFrameKind.Data:
                                if ((long)output.Length + frame.Payload.LongLength > maxBytes)
                                {
                                    throw new InvalidDataException("SYSVOL worker exceeded the parent read budget.");
                                }
                                output.Write(frame.Payload, 0, frame.Payload.Length);
                                break;
                            case SysvolWorkerFrameKind.Complete:
                                result = output.ToArray();
                                return;
                            case SysvolWorkerFrameKind.Error:
                                throw CreateWorkerException(
                                    SysvolWorkerProtocol.DeserializeError(frame.Payload),
                                    fullPath,
                                    maxBytes);
                            default:
                                throw new InvalidDataException("SYSVOL worker returned an invalid read frame.");
                        }
                    }
                },
                cancellationToken).ConfigureAwait(false);

            return result ?? throw new InvalidDataException("SYSVOL worker completed without a file result.");
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        await TerminateWorkerAsync().ConfigureAwait(false);
        _operationGate.Dispose();
    }

    private async Task ProduceEnumerationAsync(
        SysvolWorkerRequest request,
        ChannelWriter<SysvolFileEntry> writer,
        CancellationToken cancellationToken)
    {
        try
        {
            await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await RunWorkerOperationAsync(
                    async operationToken =>
                    {
                        await SendRequestAsync(request, operationToken).ConfigureAwait(false);
                        while (true)
                        {
                            var frame = await ReadFrameAsync(operationToken).ConfigureAwait(false)
                                ?? throw new EndOfStreamException("SYSVOL worker exited during enumeration.");
                            switch (frame.Kind)
                            {
                                case SysvolWorkerFrameKind.Entry:
                                    var entry = SysvolWorkerProtocol.DeserializeEntry(frame.Payload);
                                    await writer.WriteAsync(new SysvolFileEntry
                                    {
                                        FullPath = entry.FullPath,
                                        RelativePath = entry.RelativePath,
                                        Length = entry.Length,
                                        LastWriteTimeUtc = entry.LastWriteTimeUtc
                                    }, operationToken).ConfigureAwait(false);
                                    break;
                                case SysvolWorkerFrameKind.Complete:
                                    return;
                                case SysvolWorkerFrameKind.Error:
                                    throw CreateWorkerException(
                                        SysvolWorkerProtocol.DeserializeError(frame.Payload),
                                        request.Path,
                                        null);
                                default:
                                    throw new InvalidDataException("SYSVOL worker returned an invalid enumeration frame.");
                            }
                        }
                    }, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _operationGate.Release();
            }
            writer.TryComplete();
        }
        catch (Exception exception)
        {
            writer.TryComplete(exception);
        }
    }

    private SysvolWorkerRequest CreateRequest(SysvolWorkerOperation operation, string path, int maxBytes)
    {
        var rewrittenPath = RewriteAuthorityAndGetDomain(path, _server, out var domainDnsName);
        var user = NormalizeUser(_credential.UserName, domainDnsName);
        var password = _credential.Password;
        if (string.IsNullOrEmpty(password))
        {
            throw new InvalidOperationException("Portable Kerberos SYSVOL requires a non-empty credential password.");
        }

        return new SysvolWorkerRequest
        {
            Operation = operation,
            Path = rewrittenPath,
            MaxBytes = maxBytes,
            Transport = SysvolWorkerTransport.PortableKerberos,
            Server = _server,
            KerberosRealm = domainDnsName.ToUpperInvariant(),
            KerberosUser = user,
            KerberosPassword = password
        };
    }

    private static string RewriteAuthorityAndGetDomain(string path, string server, out string domainDnsName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var normalized = path.Trim().Replace('/', '\\').TrimEnd('\\');
        if (!normalized.StartsWith("\\\\", StringComparison.Ordinal) ||
            normalized.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
            normalized.StartsWith("\\\\.\\", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Portable SYSVOL path must be a normal UNC path.");
        }

        var parts = normalized[2..].Split('\\', StringSplitOptions.None);
        if (parts.Length < 4 ||
            !parts[1].Equals("SYSVOL", StringComparison.OrdinalIgnoreCase) ||
            parts.Any(part => string.IsNullOrWhiteSpace(part) || part is "." or ".."))
        {
            throw new InvalidDataException("Portable SYSVOL path is outside the expected SYSVOL namespace.");
        }

        domainDnsName = parts[2].Trim().TrimEnd('.');
        if (domainDnsName.Length == 0 || !domainDnsName.Contains('.', StringComparison.Ordinal))
        {
            throw new InvalidDataException("Portable SYSVOL path does not contain a DNS domain name.");
        }

        parts[0] = server;
        return "\\\\" + string.Join("\\", parts);
    }

    private static string NormalizeUser(string username, string domainDnsName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        var at = username.LastIndexOf('@');
        if (at > 0 && at < username.Length - 1)
        {
            var suffix = username[(at + 1)..].Trim().TrimEnd('.');
            if (!suffix.Equals(domainDnsName, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Credential UPN realm does not match the SYSVOL domain.");
            }
            return username[..at];
        }
        if (username.IndexOfAny(['\\', '/', ':', '\0']) >= 0)
        {
            throw new InvalidOperationException("Credential account name is invalid for portable Kerberos SYSVOL.");
        }
        return username;
    }

    private async Task RunWorkerOperationAsync(Func<CancellationToken, Task> operation, CancellationToken callerToken)
    {
        using var timeoutCts = new CancellationTokenSource(_operationTimeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(callerToken, timeoutCts.Token);
        try
        {
            await operation(linkedCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception)
            when (timeoutCts.IsCancellationRequested && !callerToken.IsCancellationRequested)
        {
            await TerminateWorkerAsync().ConfigureAwait(false);
            throw new SysvolIoTimeoutException(_operationTimeout, exception);
        }
        catch (OperationCanceledException) when (callerToken.IsCancellationRequested)
        {
            await TerminateWorkerAsync().ConfigureAwait(false);
            callerToken.ThrowIfCancellationRequested();
            throw;
        }
        catch (EndOfStreamException exception)
        {
            await TerminateWorkerAsync().ConfigureAwait(false);
            throw new IOException("SYSVOL worker terminated unexpectedly.", exception);
        }
        catch (InvalidDataException exception)
        {
            await TerminateWorkerAsync().ConfigureAwait(false);
            throw new IOException("SYSVOL worker protocol failed validation.", exception);
        }
    }

    private async Task SendRequestAsync(SysvolWorkerRequest request, CancellationToken cancellationToken)
    {
        var worker = EnsureWorker();
        var serialized = SysvolWorkerProtocol.SerializeRequest(request);
        await worker.StandardInput.WriteLineAsync(serialized.AsMemory(), cancellationToken).ConfigureAwait(false);
        await worker.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<SysvolWorkerFrame?> ReadFrameAsync(CancellationToken cancellationToken)
    {
        var worker = _worker ?? throw new InvalidOperationException("SYSVOL worker is not running.");
        return await SysvolWorkerProtocol.ReadFrameAsync(worker.StandardOutput.BaseStream, cancellationToken)
            .ConfigureAwait(false);
    }

    private Process EnsureWorker()
    {
        if (_worker is not null)
        {
            if (!_worker.HasExited)
            {
                return _worker;
            }
            _worker.Dispose();
            _worker = null;
            _stderrDrain = null;
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = _workerExecutablePath,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        var worker = new Process { StartInfo = startInfo };
        if (!worker.Start())
        {
            worker.Dispose();
            throw new IOException("The SYSVOL worker process could not be started.");
        }
        _worker = worker;
        _stderrDrain = worker.StandardError.ReadToEndAsync();
        return worker;
    }

    private async Task TerminateWorkerAsync()
    {
        var worker = _worker;
        var stderrDrain = _stderrDrain;
        _worker = null;
        _stderrDrain = null;
        if (worker is null)
        {
            return;
        }

        try
        {
            if (!worker.HasExited)
            {
                try
                {
                    worker.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                }
            }
            try
            {
                await worker.WaitForExitAsync().WaitAsync(_terminationGracePeriod).ConfigureAwait(false);
            }
            catch (TimeoutException exception)
            {
                throw new SysvolIoIsolationException(
                    "The portable SYSVOL worker did not terminate within the configured grace period.",
                    exception);
            }
            if (stderrDrain is not null)
            {
                try
                {
                    _ = await stderrDrain.WaitAsync(_terminationGracePeriod).ConfigureAwait(false);
                }
                catch (TimeoutException)
                {
                }
            }
        }
        finally
        {
            worker.Dispose();
        }
    }

    private static Exception CreateWorkerException(SysvolWorkerErrorCode errorCode, string path, int? maxBytes) =>
        errorCode switch
        {
            SysvolWorkerErrorCode.NotFound => new FileNotFoundException("SYSVOL path was not found.", path),
            SysvolWorkerErrorCode.AccessDenied => new UnauthorizedAccessException("SYSVOL access was denied."),
            SysvolWorkerErrorCode.TooLarge when maxBytes is not null => new SysvolFileTooLargeException(path, maxBytes.Value),
            SysvolWorkerErrorCode.InvalidRequest => new IOException("SYSVOL worker rejected the portable request."),
            SysvolWorkerErrorCode.IoFailure => new IOException("Portable SYSVOL I/O failed."),
            _ => new IOException("Portable SYSVOL worker failed.")
        };
}
