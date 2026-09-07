using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using DogfighterAD.Collectors.ActiveDirectory.Sysvol;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Entities;
using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.Client.Authentication;
using SMBLibrary.SMB2;
using SmbFileAttributes = SMBLibrary.FileAttributes;

namespace DogfighterAD.SysvolWorker;

internal sealed class PortableKerberosSysvolBackend : IDisposable
{
    private const int SmbResponseTimeoutMilliseconds = 20_000;
    private const uint StatusNoMoreFiles = 0x80000006;
    private const uint StatusAccessDenied = 0xC0000022;
    private const uint StatusNoSuchFile = 0xC000000F;
    private const uint StatusObjectNameNotFound = 0xC0000034;
    private const uint StatusObjectPathNotFound = 0xC000003A;

    private readonly string _server;
    private readonly string _realm;
    private readonly string _user;
    private readonly KerberosSmbAuthenticationClient _authentication;
    private readonly SMB2Client _client;
    private readonly ISMBFileStore _fileStore;
    private bool _disposed;

    private PortableKerberosSysvolBackend(
        string server,
        string realm,
        string user,
        KerberosSmbAuthenticationClient authentication,
        SMB2Client client,
        ISMBFileStore fileStore)
    {
        _server = server;
        _realm = realm;
        _user = user;
        _authentication = authentication;
        _client = client;
        _fileStore = fileStore;
    }

    public static PortableKerberosSysvolBackend Create(SysvolWorkerRequest request)
    {
        ValidatePortableRequest(request);
        var server = request.Server!;
        var realm = request.KerberosRealm!;
        var user = request.KerberosUser!;
        var password = request.KerberosPassword!;
        var spn = $"cifs/{server}";

        KerberosSmbAuthenticationClient? authentication = null;
        SMB2Client? client = null;
        ISMBFileStore? fileStore = null;
        try
        {
            authentication = KerberosSmbAuthenticationClient.Create(
                user,
                password,
                realm,
                server,
                spn);

            client = new SMB2Client(SmbResponseTimeoutMilliseconds, enableSMB311Support: true);
            if (!client.Connect(server, SMBTransportType.DirectTCPTransport))
            {
                throw new PortableSysvolException(SysvolWorkerErrorCode.IoFailure);
            }

            var security = SmbSecurityIntrospection.Read(client);
            if (security.Dialect != SMB2Dialect.SMB311 || !security.SigningRequired)
            {
                throw new PortableSysvolException(SysvolWorkerErrorCode.AccessDenied);
            }

            var loginStatus = client.Login(authentication);
            if (loginStatus != NTStatus.STATUS_SUCCESS)
            {
                throw FromStatus(loginStatus);
            }

            security = SmbSecurityIntrospection.Read(client);
            if (!security.SigningRequired)
            {
                throw new PortableSysvolException(SysvolWorkerErrorCode.AccessDenied);
            }

            fileStore = client.TreeConnect("SYSVOL", out var treeStatus);
            if (treeStatus != NTStatus.STATUS_SUCCESS || fileStore is null)
            {
                throw FromStatus(treeStatus);
            }

            return new PortableKerberosSysvolBackend(
                server,
                realm,
                user,
                authentication,
                client,
                fileStore);
        }
        catch
        {
            if (fileStore is not null)
            {
                _ = fileStore.Disconnect();
            }
            if (client is not null)
            {
                try
                {
                    _ = client.Logoff();
                }
                catch
                {
                }
                client.Disconnect();
            }
            authentication?.Dispose();
            throw;
        }
    }

    public bool Matches(SysvolWorkerRequest request) =>
        request.Transport == SysvolWorkerTransport.PortableKerberos &&
        string.Equals(request.Server, _server, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(request.KerberosRealm, _realm, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(request.KerberosUser, _user, StringComparison.OrdinalIgnoreCase);

    public IReadOnlyList<SysvolWorkerEntry> Enumerate(string uncRoot)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var root = ParsePortableUnc(uncRoot, _server);
        var result = new List<SysvolWorkerEntry>();
        EnumerateDirectory(root.RelativePath, root.RelativePath, result);
        return result;
    }

    public byte[] Read(string uncPath, int maxBytes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (maxBytes < 1)
        {
            throw new PortableSysvolException(SysvolWorkerErrorCode.InvalidRequest);
        }

        var path = ParsePortableUnc(uncPath, _server);
        object? handle = null;
        try
        {
            var openStatus = _fileStore.CreateFile(
                out handle,
                out _,
                path.RelativePath,
                AccessMask.GENERIC_READ | AccessMask.SYNCHRONIZE,
                SmbFileAttributes.Normal,
                ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT,
                null);
            if (openStatus != NTStatus.STATUS_SUCCESS || handle is null)
            {
                throw FromStatus(openStatus);
            }

            using var destination = new MemoryStream(Math.Min(maxBytes, 64 * 1024));
            long offset = 0;
            while (true)
            {
                var remainingDetectionBudget = (long)maxBytes + 1 - destination.Length;
                if (remainingDetectionBudget <= 0)
                {
                    throw new PortableSysvolException(SysvolWorkerErrorCode.TooLarge);
                }

                var requested = (int)Math.Min(
                    Math.Min(_client.MaxReadSize, int.MaxValue),
                    remainingDetectionBudget);
                var status = _fileStore.ReadFile(out var data, handle, offset, requested);
                if (status != NTStatus.STATUS_SUCCESS && status != NTStatus.STATUS_END_OF_FILE)
                {
                    throw FromStatus(status);
                }

                if (data is { Length: > 0 })
                {
                    if (destination.Length + data.Length > maxBytes)
                    {
                        throw new PortableSysvolException(SysvolWorkerErrorCode.TooLarge);
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
        finally
        {
            if (handle is not null)
            {
                _ = _fileStore.CloseFile(handle);
            }
        }
    }

    private void EnumerateDirectory(
        string rootRelativePath,
        string currentRelativePath,
        List<SysvolWorkerEntry> output)
    {
        object? directoryHandle = null;
        try
        {
            var openStatus = _fileStore.CreateFile(
                out directoryHandle,
                out _,
                currentRelativePath,
                (AccessMask)DirectoryAccessMask.FILE_LIST_DIRECTORY |
                (AccessMask)DirectoryAccessMask.FILE_READ_ATTRIBUTES |
                AccessMask.SYNCHRONIZE,
                SmbFileAttributes.Directory,
                ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT,
                null);
            if (openStatus != NTStatus.STATUS_SUCCESS || directoryHandle is null)
            {
                throw FromStatus(openStatus);
            }

            var queryStatus = _fileStore.QueryDirectory(
                out var entries,
                directoryHandle,
                "*",
                FileInformationClass.FileDirectoryInformation);
            if (queryStatus != NTStatus.STATUS_SUCCESS && (uint)queryStatus != StatusNoMoreFiles)
            {
                throw FromStatus(queryStatus);
            }

            foreach (var entry in entries.OfType<FileDirectoryInformation>())
            {
                if (entry.FileName is "." or ".." ||
                    string.IsNullOrWhiteSpace(entry.FileName) ||
                    entry.FileName.IndexOfAny(['\\', '/', ':', '\0']) >= 0)
                {
                    continue;
                }

                var childPath = string.IsNullOrEmpty(currentRelativePath)
                    ? entry.FileName
                    : currentRelativePath + "\\" + entry.FileName;
                var isDirectory = (entry.FileAttributes & SmbFileAttributes.Directory) != 0;
                var isReparsePoint = (entry.FileAttributes & SmbFileAttributes.ReparsePoint) != 0;

                if (isDirectory)
                {
                    if (!isReparsePoint)
                    {
                        EnumerateDirectory(rootRelativePath, childPath, output);
                    }
                    continue;
                }

                if (!childPath.StartsWith(rootRelativePath, StringComparison.OrdinalIgnoreCase))
                {
                    throw new PortableSysvolException(SysvolWorkerErrorCode.InvalidRequest);
                }

                var relative = childPath.Length == rootRelativePath.Length
                    ? string.Empty
                    : childPath[(rootRelativePath.Length + 1)..];
                if (string.IsNullOrWhiteSpace(relative))
                {
                    continue;
                }

                output.Add(new SysvolWorkerEntry
                {
                    FullPath = $"\\\\{_server}\\SYSVOL\\{childPath}",
                    RelativePath = relative,
                    Length = Math.Max(0, entry.EndOfFile),
                    LastWriteTimeUtc = ToDateTimeOffset(entry.LastWriteTime)
                });
            }
        }
        finally
        {
            if (directoryHandle is not null)
            {
                _ = _fileStore.CloseFile(directoryHandle);
            }
        }
    }

    private static DateTimeOffset? ToDateTimeOffset(DateTime value)
    {
        if (value == DateTime.MinValue || value == DateTime.MaxValue)
        {
            return null;
        }
        var utc = value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();
        return new DateTimeOffset(utc);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        try
        {
            _ = _fileStore.Disconnect();
        }
        catch
        {
        }
        try
        {
            _ = _client.Logoff();
        }
        catch
        {
        }
        _client.Disconnect();
        _authentication.Dispose();
    }

    private static void ValidatePortableRequest(SysvolWorkerRequest request)
    {
        if (request.Transport != SysvolWorkerTransport.PortableKerberos ||
            string.IsNullOrWhiteSpace(request.Server) ||
            string.IsNullOrWhiteSpace(request.KerberosRealm) ||
            string.IsNullOrWhiteSpace(request.KerberosUser) ||
            string.IsNullOrEmpty(request.KerberosPassword))
        {
            throw new PortableSysvolException(SysvolWorkerErrorCode.InvalidRequest);
        }
        _ = ParsePortableUnc(request.Path, request.Server);
    }

    private static PortableUncPath ParsePortableUnc(string value, string server)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new PortableSysvolException(SysvolWorkerErrorCode.InvalidRequest);
        }

        var normalized = value.Trim().Replace('/', '\\').TrimEnd('\\');
        if (!normalized.StartsWith("\\\\", StringComparison.Ordinal) ||
            normalized.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
            normalized.StartsWith("\\\\.\\", StringComparison.Ordinal))
        {
            throw new PortableSysvolException(SysvolWorkerErrorCode.InvalidRequest);
        }

        var parts = normalized[2..].Split('\\', StringSplitOptions.None);
        if (parts.Length < 4 ||
            !parts[0].Equals(server, StringComparison.OrdinalIgnoreCase) ||
            !parts[1].Equals("SYSVOL", StringComparison.OrdinalIgnoreCase) ||
            parts.Any(part => string.IsNullOrWhiteSpace(part) || part is "." or ".."))
        {
            throw new PortableSysvolException(SysvolWorkerErrorCode.InvalidRequest);
        }

        return new PortableUncPath(string.Join("\\", parts.Skip(2)));
    }

    private static PortableSysvolException FromStatus(NTStatus status)
    {
        var code = (uint)status;
        return code switch
        {
            StatusAccessDenied => new PortableSysvolException(SysvolWorkerErrorCode.AccessDenied),
            StatusNoSuchFile or StatusObjectNameNotFound or StatusObjectPathNotFound =>
                new PortableSysvolException(SysvolWorkerErrorCode.NotFound),
            _ => new PortableSysvolException(SysvolWorkerErrorCode.IoFailure)
        };
    }

    private sealed record PortableUncPath(string RelativePath);
}

internal sealed class KerberosSmbAuthenticationClient : IAuthenticationClient, IDisposable
{
    private readonly KerberosClient _client;
    private readonly string _approvedSpn;
    private string _spn;
    private byte[] _sessionKey = [];

    private KerberosSmbAuthenticationClient(KerberosClient client, string approvedSpn)
    {
        _client = client;
        _approvedSpn = approvedSpn;
        _spn = approvedSpn;
    }

    public static KerberosSmbAuthenticationClient Create(
        string user,
        string password,
        string realm,
        string kdc,
        string spn)
    {
        var client = new KerberosClient();
        try
        {
            client.Configuration.Defaults.AllowWeakCrypto = false;
            client.PinKdc(realm, kdc);
            var credential = new KerberosPasswordCredential(user, password, realm);
            client.Authenticate(credential).GetAwaiter().GetResult();
            return new KerberosSmbAuthenticationClient(client, spn);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    public byte[] InitializeSecurityContext(byte[] inputToken)
    {
        EnsureApprovedSpn(_spn);
        var context = _client.GetServiceTicket(new RequestServiceTicket
        {
            ServicePrincipalName = _spn
        }).GetAwaiter().GetResult();

        var cacheItem = _client.Cache.GetCacheItem(_spn);
        if (cacheItem is not KerberosClientCacheEntry cachedTicket)
        {
            throw new SecurityException("Kerberos service-ticket cache entry is unavailable.");
        }

        if (_sessionKey.Length > 0)
        {
            CryptographicOperations.ZeroMemory(_sessionKey);
        }
        _sessionKey = NormalizeSmbSessionKey(cachedTicket.SessionKey.KeyValue.Span);
        return context.ApReq.EncodeGssApi().ToArray();
    }

    public byte[] GetSessionKey()
    {
        if (_sessionKey.Length == 0)
        {
            throw new SecurityException("Kerberos session key is unavailable.");
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
            throw new SecurityException("SMB authentication attempted to leave the approved CIFS SPN.");
        }
    }

    private static byte[] NormalizeSmbSessionKey(ReadOnlySpan<byte> key)
    {
        if (key.IsEmpty)
        {
            throw new SecurityException("Kerberos session key is empty.");
        }
        var result = new byte[16];
        key[..Math.Min(key.Length, result.Length)].CopyTo(result);
        return result;
    }
}

internal sealed record SmbSecurityState(SMB2Dialect Dialect, bool SigningRequired);

internal static class SmbSecurityIntrospection
{
    private static readonly FieldInfo DialectField =
        typeof(SMB2Client).GetField("m_dialect", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingFieldException(typeof(SMB2Client).FullName, "m_dialect");

    private static readonly FieldInfo SigningRequiredField =
        typeof(SMB2Client).GetField("m_signingRequired", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingFieldException(typeof(SMB2Client).FullName, "m_signingRequired");

    public static SmbSecurityState Read(SMB2Client client)
    {
        var dialect = DialectField.GetValue(client) is SMB2Dialect value
            ? value
            : throw new SecurityException("SMB dialect is unavailable.");
        var signingRequired = SigningRequiredField.GetValue(client) is bool value2 && value2;
        return new SmbSecurityState(dialect, signingRequired);
    }
}

internal sealed class PortableSysvolException : Exception
{
    public PortableSysvolException(SysvolWorkerErrorCode errorCode)
    {
        ErrorCode = errorCode;
    }

    public SysvolWorkerErrorCode ErrorCode { get; }
}
