using System.Security.Cryptography;
using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.SMB2;
using SmbFileAttributes = SMBLibrary.FileAttributes;

namespace DogfighterAD.PortableSysvolPrototype;

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

        var relativePath = BuildScopedRelativePath(options.Domain, options.GpoGuid);
        var spn = $"cifs/{options.Server}";

        progress("kerberos: acquiring TGT");
        var authenticationTask = Task.Run(
            () => KerberosSmbAuthenticationClient.Create(
                options.User,
                password,
                options.Realm,
                options.Kdc,
                spn,
                cancellationToken),
            CancellationToken.None);

        KerberosSmbAuthenticationClient authentication;
        try
        {
            authentication = await authenticationTask
                .WaitAsync(options.PhaseTimeout, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (TimeoutException exception)
        {
            throw new ProbeTimeoutException("kerberos-tgt", options.PhaseTimeout, exception);
        }

        progress("kerberos: TGT acquired");
        using (authentication)
        {
            var stage = new ProbeStageTracker("smb-connect");
            void Report(string stageName, string message)
            {
                stage.Set(stageName);
                progress(message);
            }

            var smbTask = Task.Run(
                () => ExecuteSmbBlocking(
                    options,
                    authentication,
                    relativePath,
                    Report,
                    cancellationToken),
                CancellationToken.None);

            try
            {
                return await smbTask
                    .WaitAsync(options.PhaseTimeout, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (TimeoutException exception)
            {
                throw new ProbeTimeoutException(stage.Value, options.PhaseTimeout, exception);
            }
        }
    }

    private static ProbeResult ExecuteSmbBlocking(
        PrototypeOptions options,
        KerberosSmbAuthenticationClient authentication,
        string relativePath,
        Action<string, string> progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var responseBudget = options.PhaseTimeout - TimeSpan.FromSeconds(1);
        if (responseBudget < TimeSpan.FromSeconds(1))
        {
            responseBudget = TimeSpan.FromSeconds(1);
        }
        var responseTimeoutMilliseconds = checked((int)Math.Min(responseBudget.TotalMilliseconds, int.MaxValue));
        var client = new SMB2Client(responseTimeoutMilliseconds, enableSMB311Support: true);
        var loggedIn = false;
        ISMBFileStore? fileStore = null;
        object? fileHandle = null;

        try
        {
            progress("smb-connect", "smb: connecting direct TCP/445");
            if (!client.Connect(options.Server, SMBTransportType.DirectTCPTransport))
            {
                throw new ProbeException("smb-connect", "connect-failed");
            }

            var negotiated = SmbSecurityIntrospection.Read(client);
            if (negotiated.Dialect != SMB2Dialect.SMB311 || !negotiated.SigningRequired)
            {
                throw new ProbeException("smb-negotiate", "signing-not-provable");
            }
            progress("smb-negotiate", $"smb: negotiated {negotiated.Dialect}; signing required");

            cancellationToken.ThrowIfCancellationRequested();
            progress("smb-login", "smb: Kerberos session setup");
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
            progress("smb-login", "smb: authenticated signed session established");

            cancellationToken.ThrowIfCancellationRequested();
            progress("tree-connect", "smb: tree connect SYSVOL");
            fileStore = client.TreeConnect("SYSVOL", out var treeStatus);
            if (treeStatus != NTStatus.STATUS_SUCCESS || fileStore is null)
            {
                throw new ProbeException("tree-connect", $"ntstatus-0x{(uint)treeStatus:X8}");
            }

            progress("file-open", $"smb: opening scoped path {relativePath}");
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

            progress("file-read", "smb: reading scoped file");
            var bytes = ReadBounded(fileStore, fileHandle, client.MaxReadSize, options.MaxBytes, cancellationToken);
            progress("file-read", $"smb: read complete bytes={bytes.Length}");
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

internal sealed class ProbeStageTracker
{
    private string _value;

    public ProbeStageTracker(string initialValue)
    {
        _value = initialValue;
    }

    public string Value => Volatile.Read(ref _value);

    public void Set(string value) => Volatile.Write(ref _value, value);
}

internal sealed class ProbeTimeoutException : TimeoutException
{
    public ProbeTimeoutException(string stage, TimeSpan timeout, Exception innerException)
        : base($"{stage}:{timeout}", innerException)
    {
        Stage = stage;
        Timeout = timeout;
    }

    public string Stage { get; }
    public TimeSpan Timeout { get; }
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
