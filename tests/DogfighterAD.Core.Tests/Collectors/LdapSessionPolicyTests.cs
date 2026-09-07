using System.DirectoryServices.Protocols;
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
    public void WindowsLdapsSession_EnablesTlsAndDisablesReferralsBeforeBind()
    {
        using var connection = new LdapConnection(new LdapDirectoryIdentifier("localhost", 636, true, false));
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.All;

        SystemLdapClientFactory.ConfigureSession(connection, useLdaps: true);

        Assert.Equal(ReferralChasingOptions.None, connection.SessionOptions.ReferralChasing);
        Assert.Equal(3, connection.SessionOptions.ProtocolVersion);
        Assert.True(connection.SessionOptions.SecureSocketLayer);
        // No VerifyServerCertificate callback is installed: platform certificate validation remains
        // the LDAPS trust/identity boundary. Signing/sealing are not mechanically layered on TLS.
    }
}
