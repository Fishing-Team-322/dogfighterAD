namespace DogfighterAD.Application.Collection;

/// <summary>
/// Deterministic execution telemetry derived from a completed collection run.
/// This layer intentionally reports measurements; it does not reinterpret failed/partial collection
/// as a security result. Query-level and memory telemetry can be added later without changing
/// collector contracts.
/// </summary>
public static class CollectionTelemetry
{
    public static CollectionExecutionTelemetry Build(CollectionExecutionResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var collectors = result.Collectors
            .OrderBy(record => record.CollectorId, StringComparer.Ordinal)
            .ThenBy(record => record.CollectorVersion, StringComparer.Ordinal)
            .Select(record => new CollectorTelemetry
            {
                CollectorId = record.CollectorId,
                CollectorVersion = record.CollectorVersion,
                Status = record.Status,
                Duration = NonNegativeDuration(record.StartedAt, record.CompletedAt),
                SelectedCapabilities = record.SelectedCapabilities
                    .OrderBy(capability => capability, StringComparer.Ordinal)
                    .ToArray()
            })
            .ToArray();

        var capabilityStatusCounts = result.Data.Coverage
            .GroupBy(item => item.Status)
            .ToDictionary(group => group.Key, group => group.Count());

        return new CollectionExecutionTelemetry
        {
            ScanId = result.ScanId,
            Target = result.Target,
            Duration = NonNegativeDuration(result.StartedAt, result.CompletedAt),
            CollectorCount = collectors.Length,
            CompletedCollectorCount = collectors.Count(item => item.Status == CollectorExecutionStatus.Completed),
            FailedCollectorCount = collectors.Count(item => item.Status == CollectorExecutionStatus.Failed),
            TimedOutCollectorCount = collectors.Count(item => item.Status == CollectorExecutionStatus.TimedOut),
            BlockedCollectorCount = collectors.Count(item => item.Status == CollectorExecutionStatus.Blocked),
            CapabilityStatusCounts = capabilityStatusCounts,
            Collectors = collectors
        };
    }

    private static TimeSpan NonNegativeDuration(DateTimeOffset startedAt, DateTimeOffset completedAt) =>
        completedAt >= startedAt ? completedAt - startedAt : TimeSpan.Zero;
}

public sealed record CollectionExecutionTelemetry
{
    public required Guid ScanId { get; init; }
    public required string Target { get; init; }
    public required TimeSpan Duration { get; init; }
    public required int CollectorCount { get; init; }
    public required int CompletedCollectorCount { get; init; }
    public required int FailedCollectorCount { get; init; }
    public required int TimedOutCollectorCount { get; init; }
    public required int BlockedCollectorCount { get; init; }
    public required IReadOnlyDictionary<DogfighterAD.Domain.Snapshots.CapabilityStatus, int> CapabilityStatusCounts { get; init; }
    public required IReadOnlyList<CollectorTelemetry> Collectors { get; init; }
}

public sealed record CollectorTelemetry
{
    public required string CollectorId { get; init; }
    public required string CollectorVersion { get; init; }
    public required CollectorExecutionStatus Status { get; init; }
    public required TimeSpan Duration { get; init; }
    public required IReadOnlyList<string> SelectedCapabilities { get; init; }
}
