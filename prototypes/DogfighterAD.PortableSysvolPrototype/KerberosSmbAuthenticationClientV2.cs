using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Entities;
using SMBLibrary.Client;
using SMBLibrary.Client.Authentication;
using SMBLibrary.SMB2;

namespace DogfighterAD.PortableSysvolPrototype;

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
