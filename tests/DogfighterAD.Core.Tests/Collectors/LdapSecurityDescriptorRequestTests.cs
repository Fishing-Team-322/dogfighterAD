using System.DirectoryServices.Protocols;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class LdapSecurityDescriptorRequestTests
{
    [Fact]
    public void MapSecurityMasks_DaclOnly_DoesNotRequestOwnerGroupOrSacl()
    {
        var mapped = SystemLdapClient.MapSecurityMasks(
            LdapSecurityDescriptorSections.Dacl);

        Assert.Equal(SecurityMasks.Dacl, mapped);
        Assert.False(mapped.HasFlag(SecurityMasks.Owner));
        Assert.False(mapped.HasFlag(SecurityMasks.Group));
        Assert.False(mapped.HasFlag(SecurityMasks.Sacl));
    }

    [Fact]
    public void MapSecurityMasks_PreservesExplicitCompositeSelection()
    {
        var mapped = SystemLdapClient.MapSecurityMasks(
            LdapSecurityDescriptorSections.Owner |
            LdapSecurityDescriptorSections.Dacl);

        Assert.Equal(SecurityMasks.Owner | SecurityMasks.Dacl, mapped);
    }

    [Fact]
    public void SearchRequest_DefaultsToNoSecurityDescriptorControl()
    {
        var request = new LdapSearchRequest
        {
            BaseDn = "DC=mini,DC=lab",
            Filter = "(objectClass=*)",
            Scope = LdapSearchScope.Subtree
        };

        Assert.Equal(
            LdapSecurityDescriptorSections.None,
            request.SecurityDescriptorSections);
    }
}
