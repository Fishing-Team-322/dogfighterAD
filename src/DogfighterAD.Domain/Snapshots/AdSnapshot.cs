namespace DogfighterAD.Domain.Snapshots;

public static class SnapshotSchema
{
    public const int CurrentVersion = 1;
}

public sealed record AdSnapshot
{
    public required SnapshotMetadata Metadata { get; init; }
    public SnapshotContent Content { get; init; } = new();
    public IReadOnlyList<CapabilityCoverage> Coverage { get; init; } = [];
    public IReadOnlyList<ObservedFact> Observations { get; init; } = [];
}

public sealed record SnapshotMetadata
{
    public required Guid SnapshotId { get; init; }
    public required int SchemaVersion { get; init; }
    public required string ProductVersion { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public required SnapshotCompletionStatus CompletionStatus { get; init; }
    public required TargetIdentity Target { get; init; }
    public string? CollectionProfile { get; init; }
    public IReadOnlyList<string> RequestedCapabilities { get; init; } = [];
    public IReadOnlyList<CollectorIdentity> Collectors { get; init; } = [];
}

public sealed record TargetIdentity
{
    public required string InitialTarget { get; init; }
    public string? ForestDnsName { get; init; }
    public string? DomainDnsName { get; init; }
    public string? DomainSid { get; init; }
    public string? RootDseDnsHostName { get; init; }
}

public sealed record CollectorIdentity(string Id, string Version);

public enum SnapshotCompletionStatus
{
    Complete,
    Partial,
    Failed
}
