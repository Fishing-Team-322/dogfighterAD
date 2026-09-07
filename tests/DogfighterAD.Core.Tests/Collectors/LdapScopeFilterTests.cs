using DogfighterAD.Collectors.ActiveDirectory.Collectors;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class LdapScopeFilterTests
{
    [Fact]
    public void AclFilter_PinsDomainByObjectGuidInsteadOfMatchingEveryDomainDnsObject()
    {
        var filter = AclCollector.BuildFilter(
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));

        Assert.Contains(
            "(objectGUID=\\AA\\AA\\AA\\AA\\AA\\AA\\AA\\AA\\AA\\AA\\AA\\AA\\AA\\AA\\AA\\AA)",
            filter,
            StringComparison.Ordinal);
        Assert.DoesNotContain("(objectClass=domainDNS)", filter, StringComparison.Ordinal);
        Assert.Contains("(objectClass=organizationalUnit)", filter, StringComparison.Ordinal);
    }

    [Fact]
    public void GpoLinkFilter_PinsDomainByObjectGuidInsteadOfMatchingDnsApplicationPartitions()
    {
        var filter = GpoLinkCollector.BuildFilter(
            Guid.Parse("11111111-1111-1111-1111-111111111111"));

        Assert.Contains(
            "(objectGUID=\\11\\11\\11\\11\\11\\11\\11\\11\\11\\11\\11\\11\\11\\11\\11\\11)",
            filter,
            StringComparison.Ordinal);
        Assert.DoesNotContain("(objectClass=domainDNS)", filter, StringComparison.Ordinal);
        Assert.Contains("(objectClass=organizationalUnit)", filter, StringComparison.Ordinal);
    }
}
