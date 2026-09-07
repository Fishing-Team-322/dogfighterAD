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

    [Fact]
    public void Validate_RejectsInvalidGpoLinkAndContainerPolicyReferences()
    {
        var domainId = new AdObjectId(Guid.Parse("11111111-1111-1111-1111-111111111111"));
        var gpoId = new AdObjectId(Guid.Parse("22222222-2222-2222-2222-222222222222"));
        var unknownId = new AdObjectId(Guid.Parse("33333333-3333-3333-3333-333333333333"));

        var snapshot = new AdSnapshot
        {
            Metadata = new SnapshotMetadata
            {
                SnapshotId = Guid.Parse("44444444-4444-4444-4444-444444444444"),
                SchemaVersion = SnapshotSchema.CurrentVersion,
                ProductVersion = "test",
                StartedAt = DateTimeOffset.UnixEpoch,
                CompletedAt = DateTimeOffset.UnixEpoch,
                CompletionStatus = SnapshotCompletionStatus.Complete,
                Target = new TargetIdentity { InitialTarget = "mini.lab" }
            },
            Content = new SnapshotContent
            {
                Domains =
                [
                    new AdDomain
                    {
                        Id = domainId,
                        DistinguishedName = "DC=mini,DC=lab",
                        DnsName = "mini.lab"
                    }
                ],
                GroupPolicyObjects =
                [
                    new AdGroupPolicyObject
                    {
                        Id = gpoId,
                        DistinguishedName = "CN={AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA},CN=Policies,CN=System,DC=mini,DC=lab",
                        GpoGuid = Guid.Parse("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")
                    }
                ],
                GroupPolicyLinks =
                [
                    new AdGpoLink(domainId, gpoId, 0, true, false)
                ],
                GroupPolicyContainerPolicies =
                [
                    new AdGpoContainerPolicy(unknownId, 0, false),
                    new AdGpoContainerPolicy(unknownId, 0, false)
                ]
            }
        };

        var violations = SnapshotInvariantValidator.Validate(snapshot);

        Assert.Contains(violations, violation => violation.Code == "snapshot.gpo-link.invalid-order");
        Assert.Contains(violations, violation => violation.Code == "snapshot.gpo-container-policy.unknown-container");
        Assert.Contains(violations, violation => violation.Code == "snapshot.gpo-container-policy.duplicate-container");
    }
}
