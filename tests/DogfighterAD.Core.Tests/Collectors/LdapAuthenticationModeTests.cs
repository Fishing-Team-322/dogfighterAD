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
    public void ExplicitCredential_UsesNamedServerBinding()
    {
        var credential = new NetworkCredential("alice", "synthetic-test-password", "MINILAB");

        Assert.True(CollectionComposition.UsesExplicitNamedServerBinding(credential));
        Assert.False(CollectionComposition.UsesExplicitNamedServerBinding(null));
    }

    [Fact]
    public void DirectoryIdentifier_CanMarkExactFqdnServer()
    {
        var identifier = SystemLdapClientFactory.CreateDirectoryIdentifier(
            "dc.mini.lab",
            389,
            fullyQualifiedDnsHostName: true);

        Assert.True(identifier.FullyQualifiedDnsHostName);
        Assert.False(identifier.Connectionless);
        Assert.Equal(389, identifier.PortNumber);
        Assert.Equal(new[] { "dc.mini.lab" }, identifier.Servers);
    }

    [Fact]
    public void DirectoryIdentifier_PreservesDiscoverySemanticsWhenServerBindIsNotRequested()
    {
        var identifier = SystemLdapClientFactory.CreateDirectoryIdentifier(
            "mini.lab",
            389,
            fullyQualifiedDnsHostName: false);

        Assert.False(identifier.FullyQualifiedDnsHostName);
        Assert.False(identifier.Connectionless);
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
