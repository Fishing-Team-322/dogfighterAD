using DogfighterAD.Application.Snapshots;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Snapshots;

public sealed class SnapshotFragmentMergerTests
{
    [Fact]
    public void Merge_IsDeterministicAcrossFragmentOrder()
    {
        var firstUser = CreateUser(
            "11111111-1111-1111-1111-111111111111",
            "CN=Alpha,DC=mini,DC=lab",
            "alpha");
        var secondUser = CreateUser(
            "22222222-2222-2222-2222-222222222222",
            "CN=Beta,DC=mini,DC=lab",
            "beta");

        var firstFact = CreateFact("fact:v1:b", "subject:b", "user.b", "b");
        var secondFact = CreateFact("fact:v1:a", "subject:a", "user.a", "a");

        var fragmentA = new SnapshotFragment
        {
            Content = new SnapshotContent { Users = [secondUser] },
            Coverage = [CreateCoverage("test.b")],
            Observations = [firstFact]
        };
        var fragmentB = new SnapshotFragment
        {
            Content = new SnapshotContent { Users = [firstUser] },
            Coverage = [CreateCoverage("test.a")],
            Observations = [secondFact]
        };

        var merger = new SnapshotFragmentMerger();
        var forward = merger.Merge([fragmentA, fragmentB]);
        var reverse = merger.Merge([fragmentB, fragmentA]);

        Assert.Equal(
            forward.Content.Users.Select(x => x.Id).ToArray(),
            reverse.Content.Users.Select(x => x.Id).ToArray());
        Assert.Equal(
            [firstUser.Id, secondUser.Id],
            forward.Content.Users.Select(x => x.Id).ToArray());
        Assert.Equal(
            ["test.a", "test.b"],
            forward.Coverage.Select(x => x.CapabilityId).ToArray());
        Assert.Equal(
            ["fact:v1:a", "fact:v1:b"],
            forward.Observations.Select(x => x.FactId).ToArray());
    }

    [Fact]
    public void Merge_DuplicateFactIdIsRejected()
    {
        var fact = CreateFact("fact:v1:duplicate", "subject", "path", "value");
        var merger = new SnapshotFragmentMerger();

        var exception = Assert.Throws<SnapshotMergeException>(() =>
            merger.Merge(
            [
                new SnapshotFragment { Observations = [fact] },
                new SnapshotFragment { Observations = [fact] }
            ]));

        Assert.Equal("snapshot.fragment.duplicate-fact", exception.Violation.Code);
    }

    [Fact]
    public void Merge_ConflictingCoverageBecomesPartial()
    {
        var now = DateTimeOffset.UtcNow;
        var complete = CreateCoverage("directory.users") with
        {
            Status = CapabilityStatus.Complete,
            StartedAt = now,
            CompletedAt = now
        };
        var failed = CreateCoverage("directory.users") with
        {
            Status = CapabilityStatus.Failed,
            StartedAt = now,
            CompletedAt = now
        };

        var merged = new SnapshotFragmentMerger().Merge(
        [
            new SnapshotFragment { Coverage = [complete] },
            new SnapshotFragment { Coverage = [failed] }
        ]);

        Assert.Equal(CapabilityStatus.Partial, Assert.Single(merged.Coverage).Status);
    }

    private static AdUser CreateUser(string id, string dn, string samAccountName) =>
        new()
        {
            Id = new AdObjectId(Guid.Parse(id)),
            DistinguishedName = dn,
            SamAccountName = samAccountName,
            UserAccountControl = 512
        };

    private static CapabilityCoverage CreateCoverage(string capability) =>
        new()
        {
            CapabilityId = capability,
            Status = CapabilityStatus.Complete,
            StartedAt = DateTimeOffset.UnixEpoch,
            CompletedAt = DateTimeOffset.UnixEpoch
        };

    private static ObservedFact CreateFact(
        string factId,
        string subjectId,
        string path,
        string value) =>
        new()
        {
            FactId = factId,
            CapabilityId = "test",
            SubjectId = subjectId,
            Path = path,
            Value = value,
            ValueKind = FactValueKind.Text,
            Source = new ObservationSource
            {
                CollectorId = "test",
                CollectorVersion = "test",
                SourceKind = "test"
            },
            ObservedAt = DateTimeOffset.UnixEpoch
        };
}
