using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Contracts;

public interface ICollector
{
    string Id { get; }
    string Version { get; }
    IReadOnlySet<string> ProvidesCapabilities { get; }

    Task<CollectorResult> CollectAsync(
        CollectionContext context,
        CancellationToken cancellationToken);
}

public sealed record CollectionContext(
    string Target,
    IReadOnlySet<string> RequestedCapabilities);

public sealed record CollectorResult(
    string CollectorId,
    string CollectorVersion,
    bool Succeeded,
    IReadOnlyList<CollectionCapability> Capabilities,
    IReadOnlyList<object> Facts,
    IReadOnlyList<string> Warnings);

public interface IRule
{
    RuleMetadata Metadata { get; }

    IEnumerable<Finding> Evaluate(
        AdSnapshot snapshot,
        RuleContext context);
}

public sealed record RuleMetadata(
    string Id,
    string Version,
    string Title,
    IReadOnlySet<string> RequiredCapabilities);

public sealed record RuleContext(DateTimeOffset AnalysisTime);

public interface ISnapshotRepository
{
    Task SaveAsync(AdSnapshot snapshot, CancellationToken cancellationToken);
    Task<AdSnapshot?> GetAsync(Guid snapshotId, CancellationToken cancellationToken);
}
