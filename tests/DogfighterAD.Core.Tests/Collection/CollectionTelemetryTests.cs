using DogfighterAD.Application.Collection;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collection;

public sealed class CollectionTelemetryTests
{
    [Fact]
    public void Build_ProducesDeterministicExecutionSummary()
    {
        var scanId = Guid.Parse("8d2acbd9-ff2f-4f47-8dbd-8d72cf07ec51");
        var started = DateTimeOffset.Parse("2026-09-05T10:00:00+00:00");
        var result = new CollectionExecutionResult
        {
            ScanId = scanId,
            Target = "mini.lab",
            StartedAt = started,
            CompletedAt = started.AddSeconds(12),
            Data = new SnapshotFragment
            {
                Coverage =
                [
                    Coverage(CollectionCapabilities.DirectoryCore, CapabilityStatus.Complete),
                    Coverage(CollectionCapabilities.DirectoryUsers, CapabilityStatus.Partial),
                    Coverage(CollectionCapabilities.DirectoryGroups, CapabilityStatus.Complete)
                ]
            },
            Collectors =
            [
                Record("z.collector", CollectorExecutionStatus.TimedOut, started.AddSeconds(2), started.AddSeconds(10), CollectionCapabilities.DirectoryUsers),
                Record("a.collector", CollectorExecutionStatus.Completed, started, started.AddSeconds(2), CollectionCapabilities.DirectoryCore),
                Record("m.collector", CollectorExecutionStatus.Blocked, started.AddSeconds(10), started.AddSeconds(10), CollectionCapabilities.DirectoryGroups)
            ]
        };

        var telemetry = CollectionTelemetry.Build(result);

        Assert.Equal(scanId, telemetry.ScanId);
        Assert.Equal(TimeSpan.FromSeconds(12), telemetry.Duration);
        Assert.Equal(3, telemetry.CollectorCount);
        Assert.Equal(1, telemetry.CompletedCollectorCount);
        Assert.Equal(0, telemetry.FailedCollectorCount);
        Assert.Equal(1, telemetry.TimedOutCollectorCount);
        Assert.Equal(1, telemetry.BlockedCollectorCount);
        Assert.Equal(2, telemetry.CapabilityStatusCounts[CapabilityStatus.Complete]);
        Assert.Equal(1, telemetry.CapabilityStatusCounts[CapabilityStatus.Partial]);
        Assert.Equal(["a.collector", "m.collector", "z.collector"], telemetry.Collectors.Select(item => item.CollectorId).ToArray());
        Assert.Equal(TimeSpan.FromSeconds(8), telemetry.Collectors.Single(item => item.CollectorId == "z.collector").Duration);
    }

    [Fact]
    public void Build_ClampsInvalidNegativeDurationsToZero()
    {
        var timestamp = DateTimeOffset.UnixEpoch;
        var result = new CollectionExecutionResult
        {
            ScanId = Guid.NewGuid(),
            Target = "mini.lab",
            StartedAt = timestamp.AddSeconds(10),
            CompletedAt = timestamp,
            Data = new SnapshotFragment(),
            Collectors =
            [
                Record(
                    "collector",
                    CollectorExecutionStatus.Completed,
                    timestamp.AddSeconds(5),
                    timestamp,
                    CollectionCapabilities.DirectoryCore)
            ]
        };

        var telemetry = CollectionTelemetry.Build(result);

        Assert.Equal(TimeSpan.Zero, telemetry.Duration);
        Assert.Equal(TimeSpan.Zero, telemetry.Collectors.Single().Duration);
    }

    private static CapabilityCoverage Coverage(string capabilityId, CapabilityStatus status) => new()
    {
        CapabilityId = capabilityId,
        ContractVersion = 1,
        Status = status,
        StartedAt = DateTimeOffset.UnixEpoch,
        CompletedAt = DateTimeOffset.UnixEpoch
    };

    private static CollectorExecutionRecord Record(
        string collectorId,
        CollectorExecutionStatus status,
        DateTimeOffset startedAt,
        DateTimeOffset completedAt,
        params string[] capabilities) => new()
        {
            CollectorId = collectorId,
            CollectorVersion = "1.0.0",
            SelectedCapabilities = capabilities,
            Status = status,
            StartedAt = startedAt,
            CompletedAt = completedAt
        };
}
