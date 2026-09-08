using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Application.Analysis;
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
    IReadOnlySet<string> RequestedCapabilities,
    SnapshotFragment AvailableData);

public sealed record CollectorResult(
    string CollectorId,
    string CollectorVersion,
    SnapshotFragment Fragment);

/// <summary>
/// Represents an expected operational collection failure whose issue code and message are safe to
/// persist in snapshot coverage. Inner exception data remains runtime-only and is never copied into
/// snapshot artifacts or default CLI output.
/// </summary>
public sealed class CollectorOperationalException : Exception
{
    public CollectorOperationalException(
        string issueCode,
        string safeMessage,
        Exception? innerException = null)
        : base(safeMessage, innerException)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issueCode);
        ArgumentException.ThrowIfNullOrWhiteSpace(safeMessage);

        IssueCode = issueCode;
        SafeMessage = safeMessage;
    }

    public string IssueCode { get; }
    public string SafeMessage { get; }
}

public interface IRule
{
    RuleMetadata Metadata { get; }

    IEnumerable<RuleEvaluation> Evaluate(
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

    /// <summary>
    /// Minimum snapshot capability contracts required to evaluate this rule safely.
    /// Missing or older data must result in NotVerified rather than a clean result.
    /// </summary>
    public IReadOnlyList<CapabilityRequirement> RequiredCapabilities { get; init; } = [];

    public IReadOnlyList<RuleReference> References { get; init; } = [];
    public IReadOnlyList<string> RequiredFields { get; init; } = [];
    public string Risk { get; init; } = "Review the observed configuration in its deployment context.";
    public string Remediation { get; init; } = "Validate the configuration and apply the approved security baseline.";
}

public sealed record RuleReference(
    string Kind,
    string Value,
    string? Url = null);

public sealed record RuleContext(
    DateTimeOffset AnalysisTime,
    string RulePackVersion)
{
    public required ObservationIndex Facts { get; init; }
    public AnalysisPolicy Policy { get; init; } = new();
    public CancellationToken CancellationToken { get; init; }
    internal PrivilegedMembershipIndex? MembershipIndex { get; set; }
}

public interface ISnapshotRepository
{
    Task SaveAsync(AdSnapshot snapshot, CancellationToken cancellationToken);
    Task<AdSnapshot?> GetAsync(Guid snapshotId, CancellationToken cancellationToken);
}
