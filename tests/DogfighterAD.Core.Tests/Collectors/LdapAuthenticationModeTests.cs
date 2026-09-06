using System.DirectoryServices.Protocols;
using System.Net;
using DogfighterAD.Cli;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class LdapAuthenticationModeTests
{
    [Fact]
    public void DownLevelExplicitCredential_UsesNtlm()
    {
        var credential = new NetworkCredential("alice", "synthetic-test-password", "MINILAB");

        Assert.Equal(
            LdapAuthenticationMode.Ntlm,
            CollectionComposition.SelectAuthenticationMode(credential));
        Assert.Equal(
            AuthType.Ntlm,
            SystemLdapClientFactory.MapAuthenticationMode(LdapAuthenticationMode.Ntlm));
    }

    [Fact]
    public void UpnExplicitCredential_RetainsNegotiate()
    {
        var credential = new NetworkCredential("alice@mini.lab", "synthetic-test-password");

        Assert.Equal(
            LdapAuthenticationMode.Negotiate,
            CollectionComposition.SelectAuthenticationMode(credential));
    }

    [Fact]
    public void CurrentSecurityContext_RetainsNegotiate()
    {
        Assert.Equal(
            LdapAuthenticationMode.Negotiate,
            CollectionComposition.SelectAuthenticationMode(null));
    }

    [Fact]
    public void NonPositiveBindTimeout_IsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new SystemLdapClientFactory(new LdapClientOptions
            {
                BindTimeout = TimeSpan.Zero
            }));
    }
}
