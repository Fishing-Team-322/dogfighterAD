namespace DogfighterAD.Domain.Snapshots;

public sealed record ObservedFact
{
    public required string FactId { get; init; }
    public required string CapabilityId { get; init; }
    public required string SubjectId { get; init; }
    public required string Path { get; init; }
    public string? Value { get; init; }
    public required FactValueKind ValueKind { get; init; }
    public FactDisposition Disposition { get; init; } = FactDisposition.Stored;
    public required ObservationSource Source { get; init; }
    public required DateTimeOffset ObservedAt { get; init; }
}

public sealed record ObservationSource
{
    public required string CollectorId { get; init; }
    public required string CollectorVersion { get; init; }
    public required string SourceKind { get; init; }
    public string? Endpoint { get; init; }
    public string? Locator { get; init; }
}

public enum FactValueKind
{
    Text,
    Integer,
    Boolean,
    Timestamp,
    Guid,
    Sid,
    DistinguishedName,
    Binary,
    Json
}

public enum FactDisposition
{
    Stored,
    Redacted,
    MetadataOnly
}
