using System.DirectoryServices.Protocols;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class LdapSessionPolicyTests
{
    public static bool IsWindows => OperatingSystem.IsWindows();

    [Theory(SkipUnless = nameof(IsWindows), Skip = "Windows native LDAP session regression.")]
    [InlineData(false)]
    [InlineData(true)]
    public void WindowsSession_DisablesNativeReferralChasingBeforeBind(bool useLdaps)
    {
        // Configuring the native handle does not bind or send a request. No server is needed.
        using var connection = new LdapConnection(new LdapDirectoryIdentifier("localhost", 389, true, false));
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.All;

        SystemLdapClientFactory.ConfigureSession(connection, useLdaps);

        Assert.Equal(ReferralChasingOptions.None, connection.SessionOptions.ReferralChasing);
        Assert.Equal(3, connection.SessionOptions.ProtocolVersion);
        // TLS establishment needs a real TLS endpoint; this test asserts pre-bind referral policy only.
    }
}
