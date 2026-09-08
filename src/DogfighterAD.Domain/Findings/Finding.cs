namespace DogfighterAD.Domain.Findings;

public sealed record Finding
{
    public required string RuleId { get; init; }
    public required string RuleVersion { get; init; }
    public required string Fingerprint { get; init; }
    public int FingerprintVersion { get; init; } = 1;
    public required FindingSeverity Severity { get; init; }
    public required FindingStatus Status { get; init; }
    public required FindingConfidence Confidence { get; init; }
    public ValidationStatus ValidationStatus { get; init; } = ValidationStatus.NotRequested;
    public required string Title { get; init; }
    public required string Description { get; init; }
    public required string Risk { get; init; }
    public required string Remediation { get; init; }
    public IReadOnlyList<ObjectReference> AffectedObjects { get; init; } = [];
    public IReadOnlyList<Evidence> Evidence { get; init; } = [];
}

public sealed record Evidence
{
    public required string Kind { get; init; }
    public string? SubjectId { get; init; }
    public string? CapabilityId { get; init; }
    public string? FactId { get; init; }
    public required string Source { get; init; }
    public required string Path { get; init; }
    public string? Value { get; init; }
    public required DateTimeOffset ObservedAt { get; init; }
    public required string CollectorId { get; init; }
    public required string CollectorVersion { get; init; }
}

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
    Present,
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

public enum ValidationStatus
{
    NotRequested,
    NotSupported,
    Pending,
    Confirmed,
    Rejected,
    Inconclusive,
    Blocked
}
