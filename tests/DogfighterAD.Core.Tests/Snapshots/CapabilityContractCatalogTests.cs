using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Snapshots;

public sealed class CapabilityContractCatalogTests
{
    [Fact]
    public void CurrentBuiltInContractVersion_IsAvailable()
    {
        Assert.True(CapabilityContractCatalog.TryGetCurrentVersion(
            CollectionCapabilities.DirectoryCore,
            out var version));
        Assert.Equal(1, version);
    }

    [Fact]
    public void Requirement_IsSatisfiedBySameOrNewerCompleteContract()
    {
        var coverage = new CapabilityCoverage
        {
            CapabilityId = CollectionCapabilities.DirectoryUsers,
            ContractVersion = 2,
            Status = CapabilityStatus.Complete,
            StartedAt = DateTimeOffset.UnixEpoch,
            CompletedAt = DateTimeOffset.UnixEpoch
        };

        Assert.True(CapabilityContractCatalog.IsSatisfied(
            coverage,
            new CapabilityRequirement(CollectionCapabilities.DirectoryUsers, 1)));

        Assert.True(CapabilityContractCatalog.IsSatisfied(
            coverage,
            new CapabilityRequirement(CollectionCapabilities.DirectoryUsers, 2)));
    }

    [Fact]
    public void Requirement_IsNotSatisfiedByOlderOrIncompleteContract()
    {
        var oldCoverage = new CapabilityCoverage
        {
            CapabilityId = CollectionCapabilities.DirectoryUsers,
            ContractVersion = 1,
            Status = CapabilityStatus.Complete,
            StartedAt = DateTimeOffset.UnixEpoch,
            CompletedAt = DateTimeOffset.UnixEpoch
        };

        var partialCoverage = oldCoverage with
        {
            ContractVersion = 2,
            Status = CapabilityStatus.Partial
        };

        var requirement = new CapabilityRequirement(
            CollectionCapabilities.DirectoryUsers,
            2);

        Assert.False(CapabilityContractCatalog.IsSatisfied(oldCoverage, requirement));
        Assert.False(CapabilityContractCatalog.IsSatisfied(partialCoverage, requirement));
    }
}
