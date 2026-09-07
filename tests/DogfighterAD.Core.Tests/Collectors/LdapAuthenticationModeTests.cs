using System.DirectoryServices.Protocols;
using System.Net;
using DogfighterAD.Cli;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class LdapAuthenticationModeTests
{
    [Fact]
    public void DownLevelExplicitCredential_DefaultsToNegotiate()
    {
        var command = Command();
        var credential = new NetworkCredential("alice", "synthetic-test-password", "MINILAB");

        Assert.Equal(
            LdapAuthenticationMode.Negotiate,
            CollectionComposition.SelectAuthenticationMode(command));
        Assert.True(CollectionComposition.UsesExplicitNamedServerBinding(credential));
    }

    [Fact]
    public void ExplicitNtlmCompatibilityMode_UsesNtlm()
    {
        var command = Command() with
        {
            LdapAuthenticationMode = LdapAuthenticationMode.Ntlm,
            Username = "MINILAB\\alice"
        };

        Assert.Equal(
            LdapAuthenticationMode.Ntlm,
            CollectionComposition.SelectAuthenticationMode(command));
        Assert.Equal(
            AuthType.Ntlm,
            SystemLdapClientFactory.MapAuthenticationMode(LdapAuthenticationMode.Ntlm));
    }

    [Fact]
    public void UpnExplicitCredential_DefaultsToNegotiate()
    {
        var command = Command() with { Username = "alice@mini.lab" };

        Assert.Equal(
            LdapAuthenticationMode.Negotiate,
            CollectionComposition.SelectAuthenticationMode(command));
    }

    [Fact]
    public void CurrentSecurityContext_DefaultsToNegotiate()
    {
        Assert.Equal(
            LdapAuthenticationMode.Negotiate,
            CollectionComposition.SelectAuthenticationMode(Command()));
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

    private static ScanCommand Command() =>
        new()
        {
            Target = "dc.mini.lab",
            OutputPath = "out.dogad"
        };
}
