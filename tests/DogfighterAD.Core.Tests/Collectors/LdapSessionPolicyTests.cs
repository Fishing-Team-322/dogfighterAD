using System.DirectoryServices.Protocols;
using System.Net;
using System.Net.Sockets;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class LdapSessionPolicyTests
{
    public static bool IsWindows => OperatingSystem.IsWindows();

    [Fact(SkipUnless = nameof(IsWindows), Skip = "Windows native LDAP session regression.")]
    public void WindowsNonTlsSession_RequiresSigningSealingAndDisablesReferralsBeforeBind()
    {
        // Configuring the native handle does not bind or send a request. No server is needed.
        using var connection = new LdapConnection(new LdapDirectoryIdentifier("localhost", 389, true, false));
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.All;
        connection.SessionOptions.Signing = false;
        connection.SessionOptions.Sealing = false;

        SystemLdapClientFactory.ConfigureSession(connection, useLdaps: false);

        Assert.Equal(ReferralChasingOptions.None, connection.SessionOptions.ReferralChasing);
        Assert.Equal(3, connection.SessionOptions.ProtocolVersion);
        Assert.False(connection.SessionOptions.SecureSocketLayer);
        Assert.True(connection.SessionOptions.Signing);
        Assert.True(connection.SessionOptions.Sealing);
    }

    [Fact(SkipUnless = nameof(IsWindows), Skip = "Windows native LDAP session regression.")]
    public async Task WindowsLdapsSession_StartsTlsHandshakeAndDisablesReferrals()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var connection = new LdapConnection(new LdapDirectoryIdentifier("127.0.0.1", port, false, false))
        {
            AuthType = AuthType.Anonymous,
            AutoBind = false,
            Timeout = TimeSpan.FromSeconds(5)
        };
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.All;

        SystemLdapClientFactory.ConfigureSession(connection, useLdaps: true);

        Assert.Equal(ReferralChasingOptions.None, connection.SessionOptions.ReferralChasing);
        Assert.Equal(3, connection.SessionOptions.ProtocolVersion);
        // WLDAP32 can read back SSL=false before connecting despite a successful setter.
        // Check the actual wire boundary instead: the first message must be a TLS ClientHello.
        // Anonymous auth and loopback ensure no credentials or external infrastructure are used.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        var bind = Task.Run(() => Record.Exception(() => connection.Bind()));
        try
        {
            using var peer = await listener.AcceptTcpClientAsync(deadline.Token);
            var header = new byte[6];
            await peer.GetStream().ReadExactlyAsync(header, deadline.Token);
            Assert.Equal(0x16, header[0]); // TLS handshake record, not plaintext LDAP BER (0x30).
            Assert.Equal(0x03, header[1]); // TLS record legacy major version.
            Assert.Equal(0x01, header[5]); // ClientHello handshake message.
        }
        finally
        {
            listener.Stop();
            // Closing the peer aborts the handshake; observe native Bind before disposing its handle.
            await bind.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        }
        Assert.IsType<LdapException>(await bind);
        // No VerifyServerCertificate callback is installed: platform certificate validation remains
        // the LDAPS trust/identity boundary. Signing/sealing are not mechanically layered on TLS.
    }
}
