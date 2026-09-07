using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Entities;
using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.Client.Authentication;
using SMBLibrary.SMB2;
using SmbFileAttributes = SMBLibrary.FileAttributes;

namespace DogfighterAD.PortableSysvolPrototype;

internal static class Program
{
    private const int ExitSuccess = 0;
    private const int ExitArguments = 64;
    private const int ExitRuntime = 70;
    private const int ExitCanceled = 130;

    public static async Task<int> Main(string[] args)
    {
        if (!PrototypeOptions.TryParse(args, out var options, out var error))
        {
            Console.Error.WriteLine(error);
            WriteUsage(Console.Error);
            return ExitArguments;
        }

        if (options.ShowHelp)
        {
            WriteUsage(Console.Out);
            return ExitSuccess;
        }

        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };
        Console.CancelKeyPress += cancelHandler;

        string password;
        try
        {
            password = ReadHiddenPassword($"Kerberos password for {options.User}@{options.Realm}: ");
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException)
        {
            Console.Error.WriteLine("credential-input: failed");
            Console.CancelKeyPress -= cancelHandler;
            return ExitRuntime;
        }

        try
        {
            Console.Error.WriteLine(
                $"probe: server={options.Server} kdc={options.Kdc} realm={options.Realm} " +
                $"domain={options.Domain} gpo={options.GpoGuid:B} timeout={options.Timeout} max-bytes={options.MaxBytes}");

            var stopwatch = Stopwatch.StartNew();
            var result = await PortableSysvolProbe.ExecuteAsync(
                    options,
                    password,
                    static stage => Console.Error.WriteLine($"[{DateTimeOffset.UtcNow:O}] {stage}"),
                    cancellation.Token)
                .ConfigureAwait(false);
            stopwatch.Stop();

            Console.WriteLine("kerberos: success");
            Console.WriteLine("smb-session: success");
            Console.WriteLine($"smb-dialect: {result.Dialect}");
            Console.WriteLine("smb-signing: required-and-verified-by-client");
            Console.WriteLine("tree-connect: SYSVOL success");
            Console.WriteLine($"path-scope: accepted {result.RelativePath}");
            Console.WriteLine($"read: {result.BytesRead} bytes");
            Console.WriteLine($"sha256: {result.Sha256Hex}");
            Console.WriteLine($"elapsed: {stopwatch.Elapsed}");
            return ExitSuccess;
        }
        catch (TimeoutException)
        {
            Console.Error.WriteLine($"probe: timeout after {options.Timeout}");
            return ExitRuntime;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            Console.Error.WriteLine("probe: canceled");
            return ExitCanceled;
        }
        catch (KerberosProtocolException exception)
        {
            Console.Error.WriteLine($"kerberos: failed code={exception.Error?.ErrorCode.ToString() ?? "unknown"}");
            return ExitRuntime;
        }
        catch (ProbeException exception)
        {
            Console.Error.WriteLine($"probe: failed stage={exception.Stage} code={exception.Code}");
            return ExitRuntime;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"probe: failed type={exception.GetType().Name}");
            return ExitRuntime;
        }
        finally
        {
            password = string.Empty;
            Console.CancelKeyPress -= cancelHandler;
        }
    }

    private static string ReadHiddenPassword(string prompt)
    {
        if (Console.IsInputRedirected)
        {
            throw new InvalidOperationException("Redirected password input is intentionally unsupported.");
        }

        Console.Error.Write(prompt);
        var buffer = new StringBuilder();
        try
        {
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.Error.WriteLine();
                    return buffer.ToString();
                }

                if (key.Key == ConsoleKey.Backspace)
                {
                    if (buffer.Length > 0)
                    {
                        buffer.Length--;
                    }
                    continue;
                }

                if (!char.IsControl(key.KeyChar))
                {
                    buffer.Append(key.KeyChar);
                }
            }
        }
        finally
        {
            buffer.Clear();
        }
    }

    private static void WriteUsage(TextWriter writer)
    {
        writer.WriteLine("DogfighterAD portable SYSVOL Kerberos/SMB prototype");
        writer.WriteLine();
        writer.WriteLine("Usage:");
        writer.WriteLine(
            "  dotnet run --project prototypes/DogfighterAD.PortableSysvolPrototype -- " +
            "--server <dc-fqdn> --domain <domain-fqdn> --user <account> --gpo <guid> " +
            "[--realm <KERBEROS.REALM>] [--kdc <kdc-fqdn>] [--timeout-seconds <5-120>] [--max-bytes <1-1048576>]");
        writer.WriteLine();
        writer.WriteLine("The password is read only from a hidden interactive prompt; no password argument exists.");
        writer.WriteLine("The only readable path is SYSVOL/<domain>/Policies/{GPO-GUID}/GPT.INI on the explicitly named server.");
    }
}

internal sealed record PrototypeOptions
{
    public bool ShowHelp { get; init; }
    public required string Server { get; init; }
    public required string Kdc { get; init; }
    public required string Domain { get; init; }
    public required string Realm { get; init; }
    public required string User { get; init; }
    public required Guid GpoGuid { get; init; }
    public required TimeSpan Timeout { get; init; }
    public required int MaxBytes { get; init; }

    public static bool TryParse(
        IReadOnlyList<string> args,
        out PrototypeOptions options,
        out string error)
    {
        options = null!;
        error = string.Empty;

        if (args.Count is 1 && args[0] is "-h" or "--help")
        {
            options = new PrototypeOptions
            {
                ShowHelp = true,
                Server = string.Empty,
                Kdc = string.Empty,
                Domain = string.Empty,
                Realm = string.Empty,
                User = string.Empty,
                GpoGuid = Guid.Empty,
                Timeout = TimeSpan.FromSeconds(20),
                MaxBytes = 64 * 1024
            };
            return true;
        }

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Count; i++)
        {
            var name = args[i];
            if (name is "--password" or "-p" || name.StartsWith("--password=", StringComparison.OrdinalIgnoreCase))
            {
                error = "Password command-line arguments are intentionally rejected.";
                return false;
            }

            if (!name.StartsWith("--", StringComparison.Ordinal) || i + 1 >= args.Count)
            {
                error = $"Invalid argument '{name}'.";
                return false;
            }

            if (!values.TryAdd(name, args[++i]))
            {
                error = $"Duplicate argument '{name}'.";
                return false;
            }
        }

        if (!TryRequired(values, "--server", out var server, out error) ||
            !TryRequired(values, "--domain", out var domain, out error) ||
            !TryRequired(values, "--user", out var user, out error) ||
            !TryRequired(values, "--gpo", out var gpoText, out error))
        {
            return false;
        }

        if (!IsDnsName(server) || IPAddress.TryParse(server, out _))
        {
            error = "--server must be a DNS hostname/FQDN, not an IP literal.";
            return false;
        }

        if (!IsDnsName(domain))
        {
            error = "--domain must be a DNS domain name.";
            return false;
        }

        if (user.IndexOfAny(['\\', '/', '@', ':', '\0']) >= 0 || string.IsNullOrWhiteSpace(user))
        {
            error = "--user must be an account name only; provide the Kerberos realm separately.";
            return false;
        }

        if (!Guid.TryParse(gpoText, out var gpoGuid) || gpoGuid == Guid.Empty)
        {
            error = "--gpo must be a non-empty GPO GUID.";
            return false;
        }

        var realm = values.GetValueOrDefault("--realm", domain.ToUpperInvariant()).Trim().TrimEnd('.');
        if (!IsDnsName(realm))
        {
            error = "--realm must be a valid Kerberos realm name.";
            return false;
        }

        var kdc = values.GetValueOrDefault("--kdc", server).Trim().TrimEnd('.');
        if (!IsDnsName(kdc) || IPAddress.TryParse(kdc, out _))
        {
            error = "--kdc must be a DNS hostname/FQDN.";
            return false;
        }

        var timeoutSeconds = 20;
        if (values.TryGetValue("--timeout-seconds", out var timeoutText) &&
            (!int.TryParse(timeoutText, out timeoutSeconds) || timeoutSeconds is < 5 or > 120))
        {
            error = "--timeout-seconds must be between 5 and 120.";
            return false;
        }

        var maxBytes = 64 * 1024;
        if (values.TryGetValue("--max-bytes", out var maxBytesText) &&
            (!int.TryParse(maxBytesText, out maxBytes) || maxBytes is < 1 or > 1024 * 1024))
        {
            error = "--max-bytes must be between 1 and 1048576.";
            return false;
        }

        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "--server", "--domain", "--realm", "--kdc", "--user", "--gpo", "--timeout-seconds", "--max-bytes"
        };
        var unknown = values.Keys.FirstOrDefault(key => !known.Contains(key));
        if (unknown is not null)
        {
            error = $"Unknown argument '{unknown}'.";
            return false;
        }

        options = new PrototypeOptions
        {
            ShowHelp = false,
            Server = server.Trim().TrimEnd('.'),
            Kdc = kdc,
            Domain = domain.Trim().TrimEnd('.').ToLowerInvariant(),
            Realm = realm.ToUpperInvariant(),
            User = user.Trim(),
            GpoGuid = gpoGuid,
            Timeout = TimeSpan.FromSeconds(timeoutSeconds),
            MaxBytes = maxBytes
        };
        return true;
    }

    private static bool TryRequired(
        IReadOnlyDictionary<string, string> values,
        string name,
        out string value,
        out string error)
    {
        if (!values.TryGetValue(name, out value!) || string.IsNullOrWhiteSpace(value))
        {
            error = $"Missing required argument {name}.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static bool IsDnsName(string value)
    {
        var candidate = value.Trim().TrimEnd('.');
        if (candidate.Length is < 1 or > 253 || candidate.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        var labels = candidate.Split('.', StringSplitOptions.None);
        return labels.All(label =>
            label.Length is >= 1 and <= 63 &&
            char.IsLetterOrDigit(label[0]) &&
            char.IsLetterOrDigit(label[^1]) &&
            label.All(character => char.IsLetterOrDigit(character) || character == '-'));
    }
}

internal sealed record ProbeResult(
    string Dialect,
    string RelativePath,
    int BytesRead,
    string Sha256Hex);

internal static class PortableSysvolProbe
{
    public static async Task<ProbeResult> ExecuteAsync(
        PrototypeOptions options,
        string password,
        Action<string> progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(progress);

        var task = Task.Run(
            () => ExecuteBlocking(options, password, progress, cancellationToken),
            CancellationToken.None);

        return await task.WaitAsync(options.Timeout, cancellationToken).ConfigureAwait(false);
    }

    private static ProbeResult ExecuteBlocking(
        PrototypeOptions options,
        string password,
        Action<string> progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var relativePath = BuildScopedRelativePath(options.Domain, options.GpoGuid);
        var spn = $"cifs/{options.Server}";

        progress("kerberos: acquiring TGT");
        using var authentication = KerberosSmbAuthenticationClient.Create(
            options.User,
            password,
            options.Realm,
            options.Kdc,
            spn,
            cancellationToken);
        progress("kerberos: TGT acquired");

        var responseTimeoutMilliseconds = checked((int)Math.Min(options.Timeout.TotalMilliseconds, int.MaxValue));
        var client = new SMB2Client(responseTimeoutMilliseconds, enableSMB311Support: true);
        var loggedIn = false;
        ISMBFileStore? fileStore = null;
        object? fileHandle = null;

        try
        {
            progress("smb: connecting direct TCP/445");
            if (!client.Connect(options.Server, SMBTransportType.DirectTCPTransport))
            {
                throw new ProbeException("smb-connect", "connect-failed");
            }

            var negotiated = SmbSecurityIntrospection.Read(client);
            if (negotiated.Dialect != SMB2Dialect.SMB311 || !negotiated.SigningRequired)
            {
                throw new ProbeException("smb-negotiate", "signing-not-provable");
            }
            progress($"smb: negotiated {negotiated.Dialect}; signing required");

            cancellationToken.ThrowIfCancellationRequested();
            progress("smb: Kerberos session setup");
            var loginStatus = client.Login(authentication);
            if (loginStatus != NTStatus.STATUS_SUCCESS)
            {
                throw new ProbeException("smb-login", $"ntstatus-0x{(uint)loginStatus:X8}");
            }
            loggedIn = true;

            negotiated = SmbSecurityIntrospection.Read(client);
            if (!negotiated.SigningRequired)
            {
                throw new ProbeException("smb-login", "signed-session-not-enforced");
            }
            progress("smb: authenticated signed session established");

            cancellationToken.ThrowIfCancellationRequested();
            progress("smb: tree connect SYSVOL");
            fileStore = client.TreeConnect("SYSVOL", out var treeStatus);
            if (treeStatus != NTStatus.STATUS_SUCCESS || fileStore is null)
            {
                throw new ProbeException("tree-connect", $"ntstatus-0x{(uint)treeStatus:X8}");
            }

            progress($"smb: opening scoped path {relativePath}");
            var openStatus = fileStore.CreateFile(
                out fileHandle,
                out _,
                relativePath,
                AccessMask.GENERIC_READ | AccessMask.SYNCHRONIZE,
                SmbFileAttributes.Normal,
                ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT,
                null);

            if (openStatus != NTStatus.STATUS_SUCCESS || fileHandle is null)
            {
                throw new ProbeException("file-open", $"ntstatus-0x{(uint)openStatus:X8}");
            }

            var bytes = ReadBounded(fileStore, fileHandle, client.MaxReadSize, options.MaxBytes, cancellationToken);
            progress($"smb: read complete bytes={bytes.Length}");
            var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            return new ProbeResult(negotiated.Dialect.ToString(), relativePath, bytes.Length, hash);
        }
        finally
        {
            if (fileHandle is not null && fileStore is not null)
            {
                _ = fileStore.CloseFile(fileHandle);
            }
            if (fileStore is not null)
            {
                _ = fileStore.Disconnect();
            }
            if (loggedIn)
            {
                _ = client.Logoff();
            }
            client.Disconnect();
        }
    }

    private static string BuildScopedRelativePath(string domain, Guid gpoGuid)
    {
        if (string.IsNullOrWhiteSpace(domain) || gpoGuid == Guid.Empty)
        {
            throw new ProbeException("path-scope", "invalid-scope");
        }

        return $"{domain}\\Policies\\{gpoGuid:B}\\GPT.INI";
    }

    private static byte[] ReadBounded(
        ISMBFileStore fileStore,
        object fileHandle,
        uint clientMaxReadSize,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        using var destination = new MemoryStream(Math.Min(maxBytes, 64 * 1024));
        long offset = 0;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var remainingDetectionBudget = (long)maxBytes + 1 - destination.Length;
            if (remainingDetectionBudget <= 0)
            {
                throw new ProbeException("file-read", "too-large");
            }

            var requested = (int)Math.Min(
                Math.Min(clientMaxReadSize, int.MaxValue),
                remainingDetectionBudget);
            var status = fileStore.ReadFile(out var data, fileHandle, offset, requested);
            if (status != NTStatus.STATUS_SUCCESS && status != NTStatus.STATUS_END_OF_FILE)
            {
                throw new ProbeException("file-read", $"ntstatus-0x{(uint)status:X8}");
            }

            if (data is { Length: > 0 })
            {
                if (destination.Length + data.Length > maxBytes)
                {
                    throw new ProbeException("file-read", "too-large");
                }
                destination.Write(data, 0, data.Length);
                offset += data.Length;
            }

            if (status == NTStatus.STATUS_END_OF_FILE || data is null || data.Length == 0)
            {
                return destination.ToArray();
            }
        }
    }
}

internal sealed class KerberosSmbAuthenticationClient : IAuthenticationClient, IDisposable
{
    private readonly KerberosClient _client;
    private readonly string _approvedSpn;
    private readonly CancellationToken _cancellationToken;
    private string _spn;
    private byte[] _sessionKey = [];

    private KerberosSmbAuthenticationClient(
        KerberosClient client,
        string approvedSpn,
        CancellationToken cancellationToken)
    {
        _client = client;
        _approvedSpn = approvedSpn;
        _spn = approvedSpn;
        _cancellationToken = cancellationToken;
    }

    public static KerberosSmbAuthenticationClient Create(
        string user,
        string password,
        string realm,
        string kdc,
        string spn,
        CancellationToken cancellationToken)
    {
        var client = new KerberosClient();
        try
        {
            client.Configuration.Defaults.AllowWeakCrypto = false;
            client.PinKdc(realm, kdc);
            var credential = new KerberosPasswordCredential(user, password, realm);
            client.Authenticate(credential).GetAwaiter().GetResult();
            return new KerberosSmbAuthenticationClient(client, spn, cancellationToken);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    public byte[] InitializeSecurityContext(byte[] inputToken)
    {
        _cancellationToken.ThrowIfCancellationRequested();
        EnsureApprovedSpn(_spn);

        var context = _client.GetServiceTicket(
                new RequestServiceTicket
                {
                    ServicePrincipalName = _spn
                },
                _cancellationToken)
            .GetAwaiter()
            .GetResult();

        if (_sessionKey.Length > 0)
        {
            CryptographicOperations.ZeroMemory(_sessionKey);
        }
        _sessionKey = context.SessionKey.KeyValue.ToArray();
        return context.ApReq.EncodeGssApi().ToArray();
    }

    public byte[] GetSessionKey()
    {
        if (_sessionKey.Length == 0)
        {
            throw new SecurityException("Kerberos session key is unavailable before service-ticket creation.");
        }
        return _sessionKey.ToArray();
    }

    public void ResetSecurityContext(string spn)
    {
        EnsureApprovedSpn(spn);
        _spn = spn;
        if (_sessionKey.Length > 0)
        {
            CryptographicOperations.ZeroMemory(_sessionKey);
            _sessionKey = [];
        }
    }

    public void Dispose()
    {
        if (_sessionKey.Length > 0)
        {
            CryptographicOperations.ZeroMemory(_sessionKey);
            _sessionKey = [];
        }
        _client.Dispose();
    }

    private void EnsureApprovedSpn(string spn)
    {
        if (!string.Equals(spn, _approvedSpn, StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException("SMB authentication attempted to leave the explicitly approved CIFS SPN.");
        }
    }
}

internal sealed record SmbSecurityState(SMB2Dialect Dialect, bool SigningRequired);

internal static class SmbSecurityIntrospection
{
    private static readonly FieldInfo DialectField =
        typeof(SMB2Client).GetField("m_dialect", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new TypeInitializationException(
            typeof(SmbSecurityIntrospection).FullName,
            new MissingFieldException(typeof(SMB2Client).FullName, "m_dialect"));

    private static readonly FieldInfo SigningRequiredField =
        typeof(SMB2Client).GetField("m_signingRequired", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new TypeInitializationException(
            typeof(SmbSecurityIntrospection).FullName,
            new MissingFieldException(typeof(SMB2Client).FullName, "m_signingRequired"));

    public static SmbSecurityState Read(SMB2Client client)
    {
        var dialect = DialectField.GetValue(client) is SMB2Dialect value
            ? value
            : throw new ProbeException("smb-negotiate", "dialect-unavailable");
        var signingRequired = SigningRequiredField.GetValue(client) is bool value2 && value2;
        return new SmbSecurityState(dialect, signingRequired);
    }
}

internal sealed class ProbeException : Exception
{
    public ProbeException(string stage, string code)
        : base($"{stage}:{code}")
    {
        Stage = stage;
        Code = code;
    }

    public string Stage { get; }
    public string Code { get; }
}
