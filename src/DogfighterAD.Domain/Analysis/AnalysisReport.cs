using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Domain.Analysis;

// NotDetected means only that the evaluated predicate was false for the stated subject.
// It is deliberately not named Safe, Passed or Resolved.
public enum RuleOutcome { Present, Potential, NotDetected, NotVerified, NotApplicable, Error }
public enum AnalysisCompletion { Complete, Partial, Error }

public sealed record DataGap(string CapabilityId, string SubjectId, string Path, string Code);

public sealed record RuleEvaluation
{
    public required string RuleId { get; init; }
    public required string RuleVersion { get; init; }
    public required ObjectReference Subject { get; init; }
    public string CheckKey { get; init; } = "default";
    public required RuleOutcome Outcome { get; init; }
    public required string Code { get; init; }
    public required string Message { get; init; }
    public IReadOnlyList<Evidence> Evidence { get; init; } = [];
    public IReadOnlyList<DataGap> MissingData { get; init; } = [];
}

public sealed record RuleRunSummary
{
    public required string RuleId { get; init; }
    public required string RuleVersion { get; init; }
    public required string Title { get; init; }
    public required string Category { get; init; }
    public required FindingSeverity Severity { get; init; }
    public required AnalysisCompletion Completion { get; init; }
    public IReadOnlyList<CapabilityRequirement> RequiredCapabilities { get; init; } = [];
    public IReadOnlyList<string> RequiredFields { get; init; } = [];
    public IReadOnlyList<string> ReferenceUrls { get; init; } = [];
    public int Present { get; init; }
    public int Potential { get; init; }
    public int NotDetected { get; init; }
    public int NotVerified { get; init; }
    public int NotApplicable { get; init; }
    public int Errors { get; init; }
}

/// <summary>Explicit organizational thresholds, not inferred directory defaults.</summary>
public sealed record AnalysisPolicy
{
    public int MinimumPasswordLength { get; init; } = 14;
    public int MinimumPasswordHistory { get; init; } = 24;
    public int MaximumLockoutThreshold { get; init; } = 10;
    public int MinimumLockoutMinutes { get; init; } = 15;
    public int UserPasswordAgeDays { get; init; } = 365;
    public int ComputerPasswordAgeDays { get; init; } = 90;
    public int KrbtgtPasswordAgeDays { get; init; } = 180;
    public int ReplicatedLogonAgeDays { get; init; } = 90;

    public void Validate()
    {
        if (MinimumPasswordLength is < 1 or > 256 || MinimumPasswordHistory is < 0 or > 1024 ||
            MaximumLockoutThreshold is < 1 or > 999 || MinimumLockoutMinutes is < 1 or > 10080 ||
            UserPasswordAgeDays is < 1 or > 36500 || ComputerPasswordAgeDays is < 1 or > 36500 ||
            KrbtgtPasswordAgeDays is < 1 or > 36500 || ReplicatedLogonAgeDays is < 1 or > 36500)
            throw new ArgumentOutOfRangeException(nameof(AnalysisPolicy), "Analysis policy thresholds are outside supported bounds.");
    }
}

public sealed record AnalysisReport
{
    public int ReportSchemaVersion { get; init; } = 1;
    public required string EngineVersion { get; init; }
    public required string RulePackId { get; init; }
    public required string RulePackVersion { get; init; }
    public required Guid SnapshotId { get; init; }
    public required int SnapshotSchemaVersion { get; init; }
    public required DateTimeOffset SnapshotCompletedAt { get; init; }
    public required DateTimeOffset AnalysisTime { get; init; }
    public string? InputArtifactSha256 { get; init; }
    public required AnalysisPolicy Policy { get; init; }
    public required string PolicySha256 { get; init; }
    public required AnalysisCompletion Completion { get; init; }
    public IReadOnlyList<CapabilityCoverage> Coverage { get; init; } = [];
    public IReadOnlyList<RuleRunSummary> Rules { get; init; } = [];
    public IReadOnlyList<RuleEvaluation> Evaluations { get; init; } = [];
    public IReadOnlyList<Finding> Findings { get; init; } = [];
}
