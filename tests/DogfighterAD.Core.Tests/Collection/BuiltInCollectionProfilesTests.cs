using DogfighterAD.Application.Collection;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collection;

public sealed class BuiltInCollectionProfilesTests
{
    [Fact]
    public void Minimal_IsStableLightweightReadOnlyInventoryProfile()
    {
        var profile = BuiltInCollectionProfiles.Get(BuiltInCollectionProfiles.MinimalName);

        Assert.Equal("minimal", profile.Name);
        Assert.Contains(CollectionCapabilities.DirectoryMemberships, profile.RequestedCapabilities);
        Assert.Contains(CollectionCapabilities.DirectoryTrusts, profile.RequestedCapabilities);
        Assert.DoesNotContain(CollectionCapabilities.DirectoryAcls, profile.RequestedCapabilities);
        Assert.DoesNotContain(CollectionCapabilities.GroupPolicyMetadata, profile.RequestedCapabilities);
        Assert.DoesNotContain(CollectionCapabilities.GroupPolicyLinks, profile.RequestedCapabilities);
        Assert.DoesNotContain(CollectionCapabilities.GroupPolicySysvol, profile.RequestedCapabilities);
        Assert.DoesNotContain(CollectionCapabilities.AdcsAuthorities, profile.RequestedCapabilities);
        Assert.DoesNotContain(CollectionCapabilities.AdcsTemplates, profile.RequestedCapabilities);
        Assert.Equal(2, profile.MaxConcurrency);
    }

    [Fact]
    public void AuditFull_IncludesAllCurrentlyImplementedAuditCapabilitiesButNotLegacyPlaceholder()
    {
        var profile = BuiltInCollectionProfiles.Get(BuiltInCollectionProfiles.AuditFullName);

        Assert.Contains(CollectionCapabilities.DirectoryAcls, profile.RequestedCapabilities);
        Assert.Contains(CollectionCapabilities.GroupPolicyMetadata, profile.RequestedCapabilities);
        Assert.Contains(CollectionCapabilities.GroupPolicyLinks, profile.RequestedCapabilities);
        Assert.Contains(CollectionCapabilities.GroupPolicySysvol, profile.RequestedCapabilities);
        Assert.Contains(CollectionCapabilities.AdcsAuthorities, profile.RequestedCapabilities);
        Assert.Contains(CollectionCapabilities.AdcsTemplates, profile.RequestedCapabilities);
        Assert.Contains(CollectionCapabilities.AdcsPublication, profile.RequestedCapabilities);
        Assert.Contains(CollectionCapabilities.AdcsAcls, profile.RequestedCapabilities);
        Assert.Contains(CollectionCapabilities.AdcsTrust, profile.RequestedCapabilities);
        Assert.DoesNotContain(CollectionCapabilities.AdcsDirectory, profile.RequestedCapabilities);
        Assert.Equal(4, profile.MaxConcurrency);
    }

    [Fact]
    public void Get_UnknownProfileFailsExplicitly()
    {
        var exception = Assert.Throws<KeyNotFoundException>(() =>
            BuiltInCollectionProfiles.Get("does-not-exist"));

        Assert.Contains("Unknown collection profile", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Get_ReturnsIndependentProfileInstances()
    {
        var first = BuiltInCollectionProfiles.Get(BuiltInCollectionProfiles.MinimalName);
        var second = BuiltInCollectionProfiles.Get(BuiltInCollectionProfiles.MinimalName);

        Assert.NotSame(first, second);
        Assert.NotSame(first.RequestedCapabilities, second.RequestedCapabilities);
    }
}
