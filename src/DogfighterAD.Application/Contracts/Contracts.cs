using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Contracts;

public interface ICollector
{
    string Id { get; }
    string Version { get; }
    IReadOnlySet<string> ProvidesCapabilities { get; }
    IReadOnlySet<string> RequiresCapabilities { get; }

    Task<CollectorResult> CollectAsync(
        CollectionContext context,
        CancellationToken cancellationToken);
}

public sealed record CollectionContext(
    Guid ScanId,
    string Target,
    IReadOnlySet<string> RequestedCapabilities);

public sealed record CollectorResult(
    string CollectorId,
    string CollectorVersion,
    SnapshotFragment Fragment);

public interface IRule
{
    RuleMetadata Metadata { get; }

    IEnumerable<Finding> Evaluate(
        AdSnapshot snapshot,
        RuleContext context);
}

public sealed record RuleMetadata
{
    public required string Id { get; init; }
    public required string Version { get; init; }
    public required string Title { get; init; }
    public required string Category { get; init; }
    public required FindingSeverity DefaultSeverity { get; init; }
    public IReadOnlySet<string> RequiredCapabilities { get; init; } = new HashSet<string>();
    public IReadOnlyList<RuleReference> References { get; init; } = [];
}

public sealed record RuleReference(
    string Kind,
    string Value,
    string? Url = null);

public sealed record RuleContext(
    DateTimeOffset AnalysisTime,
    string RulePackVersion);

public interface ISnapshotRepository
{
    Task SaveAsync(AdSnapshot snapshot, CancellationToken cancellationToken);
    Task<AdSnapshot?> GetAsync(Guid snapshotId, CancellationToken cancellationToken);
}
