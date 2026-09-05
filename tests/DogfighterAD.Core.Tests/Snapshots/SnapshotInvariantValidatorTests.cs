using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Snapshots;

public sealed class SnapshotInvariantValidatorTests
{
    [Fact]
    public void Validate_RejectsNonPositiveCapabilityContractVersion()
    {
        var snapshot = new AdSnapshot
        {
            Metadata = new SnapshotMetadata
            {
                SnapshotId = Guid.Parse("7de3d7e8-c324-47a3-88dc-b4b50b321878"),
                SchemaVersion = SnapshotSchema.CurrentVersion,
                ProductVersion = "test",
                StartedAt = DateTimeOffset.UnixEpoch,
                CompletedAt = DateTimeOffset.UnixEpoch,
                CompletionStatus = SnapshotCompletionStatus.Complete,
                Target = new TargetIdentity { InitialTarget = "mini.lab" },
                RequestedCapabilities = [CollectionCapabilities.DirectoryUsers]
            },
            Coverage =
            [
                new CapabilityCoverage
                {
                    CapabilityId = CollectionCapabilities.DirectoryUsers,
                    ContractVersion = 0,
                    Status = CapabilityStatus.Complete,
                    StartedAt = DateTimeOffset.UnixEpoch,
                    CompletedAt = DateTimeOffset.UnixEpoch
                }
            ]
        };

        var violations = SnapshotInvariantValidator.Validate(snapshot);

        Assert.Contains(
            violations,
            violation => violation.Code == "snapshot.coverage.invalid-contract-version");
    }
}
