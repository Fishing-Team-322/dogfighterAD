namespace DogfighterAD.Domain.Findings;

public sealed record Finding
{
    public required string RuleId { get; init; }
    public required string RuleVersion { get; init; }
    public required string Fingerprint { get; init; }
    public required FindingSeverity Severity { get; init; }
    public required FindingStatus Status { get; init; }
    public required FindingConfidence Confidence { get; init; }
    public required string Title { get; init; }
    public required string Description { get; init; }
    public required string Risk { get; init; }
    public required string Remediation { get; init; }
    public IReadOnlyList<ObjectReference> AffectedObjects { get; init; } = [];
    public IReadOnlyList<Evidence> Evidence { get; init; } = [];
}

public sealed record Evidence(
    string Kind,
    string Source,
    string Path,
    string? Value,
    DateTimeOffset ObservedAt,
    string CollectorId,
    string CollectorVersion);

public sealed record ObjectReference(
    string Kind,
    string StableId,
    string? DistinguishedName = null,
    string? DisplayName = null);

public enum FindingSeverity
{
    Informational,
    Low,
    Medium,
    High,
    Critical
}

public enum FindingStatus
{
    Confirmed,
    Potential,
    NotVerified,
    NotApplicable,
    Resolved,
    Error
}

public enum FindingConfidence
{
    Low,
    Medium,
    High
}
