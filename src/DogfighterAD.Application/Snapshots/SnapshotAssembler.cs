using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Snapshots;

public sealed class SnapshotAssembler
{
    private readonly SnapshotFragmentMerger _fragmentMerger;

    public SnapshotAssembler()
        : this(new SnapshotFragmentMerger())
    {
    }

    public SnapshotAssembler(SnapshotFragmentMerger fragmentMerger)
    {
        _fragmentMerger = fragmentMerger ?? throw new ArgumentNullException(nameof(fragmentMerger));
    }

    public AdSnapshot Assemble(SnapshotAssemblyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var merged = _fragmentMerger.Merge(request.Fragments);
        var completionStatus = DetermineCompletionStatus(
            request.RequestedCapabilities,
            merged.Coverage);

        var collectors = merged.Coverage
            .SelectMany(x => x.Collectors)
            .Distinct()
            .OrderBy(x => x.Id, StringComparer.Ordinal)
            .ThenBy(x => x.Version, StringComparer.Ordinal)
            .ToArray();

        var snapshot = new AdSnapshot
        {
            Metadata = new SnapshotMetadata
            {
                SnapshotId = request.SnapshotId,
                SchemaVersion = SnapshotSchema.CurrentVersion,
                ProductVersion = request.ProductVersion,
                StartedAt = request.StartedAt,
                CompletedAt = request.CompletedAt,
                CompletionStatus = completionStatus,
                Target = request.Target,
                CollectionProfile = request.CollectionProfile,
                RequestedCapabilities = request.RequestedCapabilities
                    .OrderBy(x => x, StringComparer.Ordinal)
                    .ToArray(),
                Collectors = collectors
            },
            Content = merged.Content,
            Coverage = merged.Coverage,
            Observations = merged.Observations
        };

        var violations = SnapshotInvariantValidator.Validate(snapshot);
        if (violations.Count > 0)
        {
            throw new SnapshotAssemblyException(violations);
        }

        return snapshot;
    }

    private static SnapshotCompletionStatus DetermineCompletionStatus(
        IReadOnlySet<string> requestedCapabilities,
        IReadOnlyList<CapabilityCoverage> coverage)
    {
        if (requestedCapabilities.Count == 0)
        {
            return SnapshotCompletionStatus.Complete;
        }

        var coverageByCapability = coverage.ToDictionary(
            x => x.CapabilityId,
            StringComparer.Ordinal);

        var statuses = requestedCapabilities
            .Select(capability => coverageByCapability.TryGetValue(capability, out var item)
                ? item.Status
                : CapabilityStatus.Failed)
            .ToArray();

        if (statuses.All(IsSatisfied))
        {
            return SnapshotCompletionStatus.Complete;
        }

        if (statuses.Any(x => x is CapabilityStatus.Complete or CapabilityStatus.Partial or CapabilityStatus.NotApplicable))
        {
            return SnapshotCompletionStatus.Partial;
        }

        return SnapshotCompletionStatus.Failed;
    }

    private static bool IsSatisfied(CapabilityStatus status) =>
        status is CapabilityStatus.Complete or CapabilityStatus.NotApplicable;
}

public sealed record SnapshotAssemblyRequest
{
    public required Guid SnapshotId { get; init; }
    public required string ProductVersion { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public required TargetIdentity Target { get; init; }
    public string? CollectionProfile { get; init; }
    public IReadOnlySet<string> RequestedCapabilities { get; init; } = new HashSet<string>();
    public IReadOnlyList<SnapshotFragment> Fragments { get; init; } = [];
}

public sealed class SnapshotAssemblyException : Exception
{
    public SnapshotAssemblyException(IReadOnlyList<SnapshotInvariantViolation> violations)
        : base(BuildMessage(violations))
    {
        Violations = violations;
    }

    public IReadOnlyList<SnapshotInvariantViolation> Violations { get; }

    private static string BuildMessage(IReadOnlyList<SnapshotInvariantViolation> violations) =>
        $"Snapshot assembly failed with {violations.Count} invariant violation(s): " +
        string.Join("; ", violations.Select(x => $"{x.Code}: {x.Message}"));
}
