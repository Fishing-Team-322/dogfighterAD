using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Channels;

namespace DogfighterAD.Collectors.ActiveDirectory.Sysvol;

public interface IReadOnlySysvolClientFactory
{
    ValueTask<IReadOnlySysvolClient> CreateAsync(CancellationToken cancellationToken);
}

public interface IReadOnlySysvolClient : IAsyncDisposable
{
    IAsyncEnumerable<SysvolFileEntry> EnumerateFilesAsync(
        string rootPath,
        CancellationToken cancellationToken);

    Task<byte[]> ReadFileAsync(
        string fullPath,
        int maxBytes,
        CancellationToken cancellationToken);
}

public sealed record SysvolFileEntry
{
    public required string FullPath { get; init; }
    public required string RelativePath { get; init; }
    public long Length { get; init; }
    public DateTimeOffset? LastWriteTimeUtc { get; init; }
}

public sealed record SysvolClientOptions
{
    public int MaxFileBytes { get; init; } = 8 * 1024 * 1024;
    public int MaxFilesPerGpo { get; init; } = 10_000;

    /// <summary>
    /// Additional explicitly approved SYSVOL authorities, such as alternate DCs that may
    /// be used by an intentional DFS/referral policy. The GPO domain DFS authority and
    /// the current collection target are approved by the collector automatically.
    /// </summary>
    public IReadOnlySet<string> ApprovedAuthorities { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Creates a SYSVOL client whose potentially blocking filesystem operations execute in
/// a disposable helper process. The parent enforces a per-operation deadline and kills
/// the helper process tree on timeout or cancellation so blocked SMB/filesystem calls do
/// not outlive the collection operation.
/// </summary>
public sealed class SystemSysvolClientFactory : IReadOnlySysvolClientFactory
{
    public static readonly TimeSpan DefaultOperationTimeout = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan DefaultTerminationGracePeriod = TimeSpan.FromSeconds(2);

    private readonly string _workerExecutablePath;
    private readonly TimeSpan _operationTimeout;
    private readonly TimeSpan _terminationGracePeriod;
    private readonly IReadOnlyDictionary<string, string> _workerEnvironment;

    public SystemSysvolClientFactory()
        : this(
            GetDefaultWorkerExecutablePath(),
            DefaultOperationTimeout,
            DefaultTerminationGracePeriod,
            new Dictionary<string, string>(StringComparer.Ordinal))
    {
    }

    public SystemSysvolClientFactory(
        string workerExecutablePath,
        TimeSpan operationTimeout)
        : this(
            workerExecutablePath,
            operationTimeout,
            DefaultTerminationGracePeriod,
            new Dictionary<string, string>(StringComparer.Ordinal))
    {
    }

    internal SystemSysvolClientFactory(
        string workerExecutablePath,
        TimeSpan operationTimeout,
        TimeSpan terminationGracePeriod,
        IReadOnlyDictionary<string, string> workerEnvironment)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workerExecutablePath);
        ArgumentNullException.ThrowIfNull(workerEnvironment);

        if (operationTimeout <= TimeSpan.Zero || operationTimeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(operationTimeout));
        }

        if (terminationGracePeriod <= TimeSpan.Zero ||
            terminationGracePeriod == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(terminationGracePeriod));
        }

        _workerExecutablePath = workerExecutablePath;
        _operationTimeout = operationTimeout;
        _terminationGracePeriod = terminationGracePeriod;
        _workerEnvironment = workerEnvironment;
    }

    public ValueTask<IReadOnlySysvolClient> CreateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!File.Exists(_workerExecutablePath))
        {
            throw new FileNotFoundException(
                "The DogfighterAD SYSVOL worker executable was not found. " +
                "The worker must be deployed next to the host application or supplied explicitly.",
                _workerExecutablePath);
        }

        return ValueTask.FromResult<IReadOnlySysvolClient>(new SystemSysvolClient(
            _workerExecutablePath,
            _operationTimeout,
            _terminationGracePeriod,
            _workerEnvironment));
    }

    internal static string GetDefaultWorkerExecutablePath() =>
        Path.Combine(
            AppContext.BaseDirectory,
            OperatingSystem.IsWindows()
                ? "DogfighterAD.SysvolWorker.exe"
                : "DogfighterAD.SysvolWorker");
}

internal sealed class SystemSysvolClient : IReadOnlySysvolClient
{
    private readonly string _workerExecutablePath;
    private readonly TimeSpan _operationTimeout;
    private readonly TimeSpan _terminationGracePeriod;
    private readonly IReadOnlyDictionary<string, string> _workerEnvironment;
    private readonly SemaphoreSlim _operationGate = new(1, 1);

    private Process? _worker;
    private Task<string>? _stderrDrain;
    private bool _disposed;

    public SystemSysvolClient(
        string workerExecutablePath,
        TimeSpan operationTimeout,
        TimeSpan terminationGracePeriod,
        IReadOnlyDictionary<string, string> workerEnvironment)
    {
        _workerExecutablePath = workerExecutablePath;
        _operationTimeout = operationTimeout;
        _terminationGracePeriod = terminationGracePeriod;
        _workerEnvironment = workerEnvironment;
    }

    public async IAsyncEnumerable<SysvolFileEntry> EnumerateFilesAsync(
        string rootPath,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);

        var channel = Channel.CreateBounded<SysvolFileEntry>(new BoundedChannelOptions(16)
        {
            SingleReader = true,
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait
        });
        using var iterationCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var producer = ProduceEnumerationAsync(rootPath, channel.Writer, iterationCts.Token);

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
                // Consumer cancellation or early disposal intentionally stops the worker operation.
            }
        }
    }

    public async Task<byte[]> ReadFileAsync(
        string fullPath,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(fullPath);
        if (maxBytes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytes));
        }

        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[]? result = null;
            await RunWorkerOperationAsync(
                async operationToken =>
                {
                    await SendRequestAsync(
                            new SysvolWorkerRequest
                            {
                                Operation = SysvolWorkerOperation.Read,
                                Path = fullPath,
                                MaxBytes = maxBytes
                            },
                            operationToken)
                        .ConfigureAwait(false);

                    using var output = new MemoryStream(Math.Min(maxBytes, 64 * 1024));
                    while (true)
                    {
                        var frame = await ReadFrameAsync(operationToken).ConfigureAwait(false)
                            ?? throw new EndOfStreamException("SYSVOL worker exited during file read.");

                        switch (frame.Value.Kind)
                        {
                            case SysvolWorkerFrameKind.Data:
                                if ((long)output.Length + frame.Value.Payload.LongLength > maxBytes)
                                {
                                    throw new InvalidDataException(
                                        "SYSVOL worker exceeded the parent read budget.");
                                }

                                output.Write(frame.Value.Payload, 0, frame.Value.Payload.Length);
                                break;

                            case SysvolWorkerFrameKind.Complete:
                                result = output.ToArray();
                                return;

                            case SysvolWorkerFrameKind.Error:
                                throw CreateWorkerException(
                                    SysvolWorkerProtocol.DeserializeError(frame.Value.Payload),
                                    fullPath,
                                    maxBytes);

                            default:
                                throw new InvalidDataException(
                                    "SYSVOL worker returned an invalid frame for a file read.");
                        }
                    }
                },
                cancellationToken)
                .ConfigureAwait(false);

            return result ?? throw new InvalidDataException(
                "SYSVOL worker completed without a file result.");
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
        string rootPath,
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
                            await SendRequestAsync(
                                    new SysvolWorkerRequest
                                    {
                                        Operation = SysvolWorkerOperation.Enumerate,
                                        Path = rootPath
                                    },
                                    operationToken)
                                .ConfigureAwait(false);

                            while (true)
                            {
                                var frame = await ReadFrameAsync(operationToken).ConfigureAwait(false)
                                    ?? throw new EndOfStreamException(
                                        "SYSVOL worker exited during enumeration.");

                                switch (frame.Value.Kind)
                                {
                                    case SysvolWorkerFrameKind.Entry:
                                        var entry = SysvolWorkerProtocol.DeserializeEntry(
                                            frame.Value.Payload);
                                        await writer.WriteAsync(
                                                new SysvolFileEntry
                                                {
                                                    FullPath = entry.FullPath,
                                                    RelativePath = entry.RelativePath,
                                                    Length = entry.Length,
                                                    LastWriteTimeUtc = entry.LastWriteTimeUtc
                                                },
                                                operationToken)
                                            .ConfigureAwait(false);
                                        break;

                                    case SysvolWorkerFrameKind.Complete:
                                        return;

                                    case SysvolWorkerFrameKind.Error:
                                        throw CreateWorkerException(
                                            SysvolWorkerProtocol.DeserializeError(frame.Value.Payload),
                                            rootPath,
                                            maxBytes: null);

                                    default:
                                        throw new InvalidDataException(
                                            "SYSVOL worker returned an invalid frame for enumeration.");
                                }
                            }
                        },
                        cancellationToken)
                    .ConfigureAwait(false);
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

    private async Task RunWorkerOperationAsync(
        Func<CancellationToken, Task> operation,
        CancellationToken callerToken)
    {
        using var timeoutCts = new CancellationTokenSource(_operationTimeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
            callerToken,
            timeoutCts.Token);

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
        catch (OperationCanceledException)
            when (callerToken.IsCancellationRequested)
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

    private async Task SendRequestAsync(
        SysvolWorkerRequest request,
        CancellationToken cancellationToken)
    {
        var worker = EnsureWorker();
        var serialized = SysvolWorkerProtocol.SerializeRequest(request);
        await worker.StandardInput
            .WriteLineAsync(serialized.AsMemory(), cancellationToken)
            .ConfigureAwait(false);
        await worker.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<SysvolWorkerFrame?> ReadFrameAsync(
        CancellationToken cancellationToken)
    {
        var worker = _worker
            ?? throw new InvalidOperationException("SYSVOL worker is not running.");
        return await SysvolWorkerProtocol
            .ReadFrameAsync(worker.StandardOutput.BaseStream, cancellationToken)
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
        foreach (var item in _workerEnvironment)
        {
            startInfo.Environment[item.Key] = item.Value;
        }

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
                    // Process exited between HasExited and Kill.
                }
            }

            try
            {
                await worker.WaitForExitAsync()
                    .WaitAsync(_terminationGracePeriod)
                    .ConfigureAwait(false);
            }
            catch (TimeoutException exception)
            {
                throw new SysvolIoIsolationException(
                    "The SYSVOL worker did not terminate within the configured grace period.",
                    exception);
            }

            if (stderrDrain is not null)
            {
                try
                {
                    _ = await stderrDrain
                        .WaitAsync(_terminationGracePeriod)
                        .ConfigureAwait(false);
                }
                catch (TimeoutException)
                {
                    // The process is already terminated; stderr drain is diagnostic-only.
                }
            }
        }
        finally
        {
            worker.Dispose();
        }
    }

    private static Exception CreateWorkerException(
        SysvolWorkerErrorCode errorCode,
        string path,
        int? maxBytes) => errorCode switch
    {
        SysvolWorkerErrorCode.NotFound =>
            new DirectoryNotFoundException("The requested SYSVOL path was not found."),
        SysvolWorkerErrorCode.AccessDenied =>
            new UnauthorizedAccessException("Access to the requested SYSVOL path was denied."),
        SysvolWorkerErrorCode.TooLarge when maxBytes is not null =>
            new SysvolFileTooLargeException(path, (long)maxBytes.Value + 1, maxBytes.Value),
        SysvolWorkerErrorCode.InvalidRequest =>
            new IOException("The SYSVOL worker rejected the operation request."),
        SysvolWorkerErrorCode.IoFailure =>
            new IOException("The SYSVOL worker reported a filesystem I/O failure."),
        _ => new IOException("The SYSVOL worker reported an internal failure.")
    };
}

internal static class SysvolBoundedReader
{
    public static async Task<byte[]> ReadAsync(
        Stream stream,
        string path,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (maxBytes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytes));
        }

        cancellationToken.ThrowIfCancellationRequested();

        var initialLength = stream.CanSeek ? stream.Length : 0L;
        if (initialLength > maxBytes)
        {
            throw new SysvolFileTooLargeException(path, initialLength, maxBytes);
        }

        using var output = initialLength > 0
            ? new MemoryStream(checked((int)initialLength))
            : new MemoryStream();
        var rented = ArrayPool<byte>.Shared.Rent(
            (int)Math.Min(64 * 1024L, (long)maxBytes + 1));

        try
        {
            var remainingBudget = (long)maxBytes + 1;
            while (remainingBudget > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var requested = (int)Math.Min(rented.Length, remainingBudget);
                var read = await stream
                    .ReadAsync(rented.AsMemory(0, requested), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                output.Write(rented, 0, read);
                if (output.Length > maxBytes)
                {
                    throw new SysvolFileTooLargeException(path, output.Length, maxBytes);
                }

                remainingBudget -= read;
            }

            if (stream.CanSeek && stream.Length > maxBytes)
            {
                throw new SysvolFileTooLargeException(path, stream.Length, maxBytes);
            }

            return output.ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }
}

public sealed class SysvolIoTimeoutException : IOException
{
    public SysvolIoTimeoutException(TimeSpan timeout, Exception? innerException = null)
        : base($"SYSVOL filesystem operation exceeded its {timeout} deadline.", innerException)
    {
        Timeout = timeout;
    }

    public TimeSpan Timeout { get; }
}

public sealed class SysvolIoIsolationException : IOException
{
    public SysvolIoIsolationException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}

public sealed class SysvolFileTooLargeException : IOException
{
    public SysvolFileTooLargeException(string path, long length, int maxBytes)
        : base($"SYSVOL file '{path}' is {length} bytes and exceeds the read limit of {maxBytes} bytes.")
    {
        Path = path;
        Length = length;
        MaxBytes = maxBytes;
    }

    public string Path { get; }
    public long Length { get; }
    public int MaxBytes { get; }
}
