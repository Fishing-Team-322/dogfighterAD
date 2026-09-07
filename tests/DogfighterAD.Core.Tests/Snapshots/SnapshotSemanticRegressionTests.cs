using DogfighterAD.Domain.Snapshots;
using DogfighterAD.Serialization;

namespace DogfighterAD.Core.Tests.Snapshots;

public sealed class SnapshotSemanticRegressionTests
{
    private static readonly DateTimeOffset FixedNow =
        new(2026, 9, 7, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void CompletionStatus_CompleteWithFailedRequestedCoverage_IsRejected()
    {
        const string capability = CollectionCapabilities.DirectoryUsers;
        var snapshot = BaseSnapshot() with
        {
            Metadata = BaseSnapshot().Metadata with
            {
                RequestedCapabilities = [capability],
                CompletionStatus = SnapshotCompletionStatus.Complete
            },
            Coverage =
            [
                new CapabilityCoverage
                {
                    CapabilityId = capability,
                    Status = CapabilityStatus.Failed,
                    StartedAt = FixedNow,
                    CompletedAt = FixedNow
                }
            ]
        };

        var violations = SnapshotInvariantValidator.Validate(snapshot);

        Assert.Contains(violations, violation =>
            violation.Code == "snapshot.completion-status.inconsistent");
        Assert.Equal(
            SnapshotCompletionStatus.Failed,
            SnapshotCompletionStatusCalculator.Calculate(
                snapshot.Metadata.RequestedCapabilities,
                snapshot.Coverage));
    }

    [Fact]
    public async Task TypedAces_PreserveDuplicateInstancesAndSourceOrderAcrossRoundTrip()
    {
        var targetId = new AdObjectId(Guid.Parse("c1a8ff8b-88ee-44ad-8d0f-54ab647fc4d8"));
        var snapshot = BaseSnapshot() with
        {
            Content = new SnapshotContent
            {
                Users =
                [
                    new AdUser
                    {
                        Id = targetId,
                        DistinguishedName = "CN=Alice,DC=mini,DC=lab",
                        UserAccountControl = 512
                    }
                ],
                Aces =
                [
                    Ace(targetId, 0, AdAccessControlType.Deny),
                    Ace(targetId, 1, AdAccessControlType.Allow),
                    Ace(targetId, 2, AdAccessControlType.Allow)
                ]
            }
        };

        var serializer = new DogadArtifactSerializer();
        await using var artifact = new MemoryStream();
        await serializer.WriteAsync(
            snapshot,
            artifact,
            TestContext.Current.CancellationToken);
        artifact.Position = 0;

        var restored = await serializer.ReadAsync(
            artifact,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(3, restored.Content.Aces.Count);
        Assert.Equal(new[] { 0, 1, 2 }, restored.Content.Aces.Select(ace => ace.AceIndex));
        Assert.Equal(
            new[]
            {
                AdAccessControlType.Deny,
                AdAccessControlType.Allow,
                AdAccessControlType.Allow
            },
            restored.Content.Aces.Select(ace => ace.AccessType));
        Assert.Equal(
            restored.Content.Aces[1] with { AceIndex = 2 },
            restored.Content.Aces[2]);
    }

    [Fact]
    public async Task SameAceSetInDifferentSourceOrder_ProducesDifferentCanonicalArtifact()
    {
        var targetId = new AdObjectId(Guid.Parse("c1a8ff8b-88ee-44ad-8d0f-54ab647fc4d8"));
        var first = WithAces(
            targetId,
            [Ace(targetId, 0, AdAccessControlType.Deny), Ace(targetId, 1, AdAccessControlType.Allow)]);
        var second = WithAces(
            targetId,
            [Ace(targetId, 0, AdAccessControlType.Allow), Ace(targetId, 1, AdAccessControlType.Deny)]);

        var serializer = new DogadArtifactSerializer();
        await using var firstStream = new MemoryStream();
        await using var secondStream = new MemoryStream();
        await serializer.WriteAsync(first, firstStream, TestContext.Current.CancellationToken);
        await serializer.WriteAsync(second, secondStream, TestContext.Current.CancellationToken);

        Assert.NotEqual(firstStream.ToArray(), secondStream.ToArray());
    }

    private static AdSnapshot WithAces(AdObjectId targetId, IReadOnlyList<AdAce> aces) =>
        BaseSnapshot() with
        {
            Content = new SnapshotContent
            {
                Users =
                [
                    new AdUser
                    {
                        Id = targetId,
                        DistinguishedName = "CN=Alice,DC=mini,DC=lab",
                        UserAccountControl = 512
                    }
                ],
                Aces = aces
            }
        };

    private static AdAce Ace(
        AdObjectId targetId,
        int index,
        AdAccessControlType accessType) =>
        new()
        {
            TargetObjectId = targetId,
            AceIndex = index,
            TrusteeSid = "S-1-5-21-1-2-3-1001",
            AccessType = accessType,
            AccessMask = 0x00020000,
            AceFlags = 0,
            IsInherited = false
        };

    private static AdSnapshot BaseSnapshot() =>
        new()
        {
            Metadata = new SnapshotMetadata
            {
                SnapshotId = Guid.Parse("00f8e635-8f66-4fd5-9200-5701623f7fb1"),
                SchemaVersion = SnapshotSchema.CurrentVersion,
                ProductVersion = "review-regression",
                StartedAt = FixedNow,
                CompletedAt = FixedNow,
                CompletionStatus = SnapshotCompletionStatus.Complete,
                Target = new TargetIdentity { InitialTarget = "dc.mini.lab" },
                RequestedCapabilities = [],
                Collectors = []
            }
        };
}
