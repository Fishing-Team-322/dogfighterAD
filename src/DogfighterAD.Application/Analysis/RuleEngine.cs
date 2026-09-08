using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis;

public sealed record RuleEngineOptions
{
    public AnalysisPolicy Policy { get; init; } = new();
    public DateTimeOffset? AnalysisTime { get; init; }
    public IReadOnlySet<string>? RuleIds { get; init; }
    public int MaxEvaluations { get; init; } = 2_000_000;
}

public sealed class RuleEngine
{
    public const string Version = "0.2.0";
    private readonly IRule[] _rules;
    private readonly string _packId;
    private readonly string _packVersion;

    public RuleEngine(IEnumerable<IRule> rules, string rulePackId = "dogfighterad.core", string rulePackVersion = "1.0.0")
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentException.ThrowIfNullOrWhiteSpace(rulePackId);
        ArgumentException.ThrowIfNullOrWhiteSpace(rulePackVersion);
        _rules = rules.OrderBy(r => r.Metadata.Id, StringComparer.Ordinal).ToArray();
        if (_rules.Length == 0 || _rules.Any(r => string.IsNullOrWhiteSpace(r.Metadata.Id) ||
                string.IsNullOrWhiteSpace(r.Metadata.Version)) ||
            _rules.Select(r => r.Metadata.Id).Distinct(StringComparer.Ordinal).Count() != _rules.Length)
            throw new ArgumentException("A rule pack must contain uniquely identified, versioned rules.", nameof(rules));
        _packId = rulePackId; _packVersion = rulePackVersion;
    }

    public IReadOnlyList<RuleMetadata> Catalog => _rules.Select(r => r.Metadata).ToArray();

    public AnalysisReport Analyze(AdSnapshot snapshot, RuleEngineOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        options ??= new();
        ArgumentNullException.ThrowIfNull(options.Policy);
        options.Policy.Validate();
        if (options.MaxEvaluations is < 1 or > 10_000_000) throw new ArgumentOutOfRangeException(nameof(options));
        if (SnapshotInvariantValidator.Validate(snapshot).Count != 0)
            throw new ArgumentException("Snapshot invariants must hold before analysis.", nameof(snapshot));
        var asOf = options.AnalysisTime ?? snapshot.Metadata.CompletedAt;
        if (asOf < snapshot.Metadata.CompletedAt)
            throw new ArgumentOutOfRangeException(nameof(options), "Analysis time cannot precede snapshot completion.");
        var selected = options.RuleIds;
        if (selected is not null && (selected.Count == 0 || selected.Any(id => !_rules.Any(r => r.Metadata.Id == id))))
            throw new ArgumentException("Rule selection contains no rules or an unknown rule ID.", nameof(options));
        cancellationToken.ThrowIfCancellationRequested();
        var context = new RuleContext(asOf, _packVersion)
        { Facts = new ObservationIndex(snapshot), Policy = options.Policy, CancellationToken = cancellationToken };
        var coverage = snapshot.Coverage.ToDictionary(x => x.CapabilityId, StringComparer.Ordinal);
        var all = new List<RuleEvaluation>();
        var summaries = new List<RuleRunSummary>();
        var findings = new List<Finding>();
        foreach (var rule in _rules.Where(r => selected is null || selected.Contains(r.Metadata.Id)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var results = new List<RuleEvaluation>();
            var gaps = rule.Metadata.RequiredCapabilities.Where(req => !coverage.TryGetValue(req.CapabilityId, out var item) ||
                item.ContractVersion < req.MinimumContractVersion ||
                item.Status is not (CapabilityStatus.Complete or CapabilityStatus.Partial or CapabilityStatus.NotApplicable))
                .Select(req => new DataGap(req.CapabilityId, AnalysisSubjects.Snapshot(snapshot).StableId, "coverage",
                    coverage.TryGetValue(req.CapabilityId, out var item) && item.ContractVersion < req.MinimumContractVersion
                        ? "capability.contract-too-old" : "capability.unavailable")).ToArray();
            gaps = gaps.Concat(rule.Metadata.RequiredCapabilities
                .Where(req => coverage.TryGetValue(req.CapabilityId, out var item) &&
                    (item.Status is CapabilityStatus.Complete or CapabilityStatus.Partial) &&
                    (item.Collectors.Count == 0 || (item.Status == CapabilityStatus.Complete &&
                        SnapshotInventory.Count(snapshot, req.CapabilityId) is int count && count != item.ObservedItemCount)))
                .Select(req => new DataGap(req.CapabilityId, AnalysisSubjects.Snapshot(snapshot).StableId,
                    "coverage/observedItemCount/collectors", "capability.inventory-or-provenance-inconsistent"))).ToArray();
            if (gaps.Length > 0)
            {
                var check = new RuleCheck(rule.Metadata, context, AnalysisSubjects.Snapshot(snapshot));
                check.AddGaps(gaps); results.Add(check.Unknown() with { CheckKey = "coverage" });
            }
            else if (rule.Metadata.RequiredCapabilities.Any(req => coverage[req.CapabilityId].Status == CapabilityStatus.NotApplicable))
                results.Add(new RuleCheck(rule.Metadata, context, AnalysisSubjects.Snapshot(snapshot))
                    .NotApplicable("A required capability was explicitly collected as not applicable."));
            else
            {
                // Rule packs are trusted in-process code. Exceptions are isolated; cancellation is
                // cooperative. Never echo arbitrary exception messages into a security report.
                try
                {
                    var keys = new HashSet<(string Subject, string Key)>();
                    foreach (var result in rule.Evaluate(snapshot, context))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        if (all.Count + results.Count >= options.MaxEvaluations)
                            throw new AnalysisLimitException();
                        if (result.RuleId != rule.Metadata.Id || result.RuleVersion != rule.Metadata.Version ||
                            !keys.Add((result.Subject.StableId, result.CheckKey)) ||
                            ((result.Outcome is RuleOutcome.Present or RuleOutcome.Potential or RuleOutcome.NotDetected) && result.Evidence.Count == 0))
                            throw new InvalidOperationException("Invalid rule result contract.");
                        results.Add(result);
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (AnalysisLimitException) { throw; }
                catch (Exception)
                {
                    results.Clear();
                    results.Add(new RuleCheck(rule.Metadata, context, AnalysisSubjects.Snapshot(snapshot))
                        .Result(RuleOutcome.Error, "analysis.rule-error", "The rule failed; no clean result was inferred."));
                }
                foreach (var req in rule.Metadata.RequiredCapabilities.Where(req => coverage[req.CapabilityId].Status == CapabilityStatus.Partial))
                {
                    var check = new RuleCheck(rule.Metadata, context, AnalysisSubjects.Snapshot(snapshot));
                    check.AddGaps([new(req.CapabilityId, AnalysisSubjects.Snapshot(snapshot).StableId, "coverage", "capability.partial-inventory")]);
                    results.Add(check.Unknown() with { CheckKey = $"coverage:{req.CapabilityId}" });
                }
                if (results.Count == 0)
                    results.Add(new RuleCheck(rule.Metadata, context, AnalysisSubjects.Snapshot(snapshot))
                        .NotApplicable("The completely enumerated rule scope contains no applicable subjects."));
            }
            if (all.Count + results.Count > options.MaxEvaluations) throw new AnalysisLimitException();
            all.AddRange(results);
            summaries.Add(Summarize(rule.Metadata, results));
            foreach (var result in results.Where(x => x.Outcome is RuleOutcome.Present or RuleOutcome.Potential))
                findings.Add(new Finding
                {
                    RuleId = rule.Metadata.Id, RuleVersion = rule.Metadata.Version,
                    Fingerprint = Fingerprint(_packId, rule.Metadata.Id, result.Subject.StableId, result.CheckKey),
                    Severity = rule.Metadata.DefaultSeverity,
                    Status = result.Outcome == RuleOutcome.Present ? FindingStatus.Present : FindingStatus.Potential,
                    Confidence = result.Outcome == RuleOutcome.Present ? FindingConfidence.High : FindingConfidence.Medium,
                    Title = rule.Metadata.Title, Description = result.Message,
                    Risk = rule.Metadata.Risk, Remediation = rule.Metadata.Remediation,
                    AffectedObjects = [result.Subject], Evidence = result.Evidence
                });
        }
        cancellationToken.ThrowIfCancellationRequested();
        return new AnalysisReport
        {
            EngineVersion = Version, RulePackId = _packId, RulePackVersion = _packVersion,
            SnapshotId = snapshot.Metadata.SnapshotId, SnapshotSchemaVersion = snapshot.Metadata.SchemaVersion,
            SnapshotCompletedAt = snapshot.Metadata.CompletedAt, AnalysisTime = asOf, Policy = options.Policy,
            PolicySha256 = Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(options.Policy))),
            Completion = Completion(all), Coverage = snapshot.Coverage.OrderBy(x => x.CapabilityId, StringComparer.Ordinal).Select(c => c with
            {
                Collectors = c.Collectors.OrderBy(x => x.Id, StringComparer.Ordinal).ThenBy(x => x.Version, StringComparer.Ordinal).ToArray(),
                Issues = c.Issues.OrderBy(x => x.Code, StringComparer.Ordinal).ThenBy(x => x.Severity)
                    .ThenBy(x => x.CollectorId, StringComparer.Ordinal).ThenBy(x => x.Target, StringComparer.Ordinal)
                    .ThenBy(x => x.Message, StringComparer.Ordinal).ToArray()
            }).ToArray(),
            Rules = summaries, Evaluations = all.OrderBy(x => x.RuleId, StringComparer.Ordinal)
                .ThenBy(x => x.Subject.StableId, StringComparer.Ordinal).ThenBy(x => x.CheckKey, StringComparer.Ordinal).ToArray(),
            Findings = findings.OrderByDescending(x => x.Severity).ThenBy(x => x.RuleId, StringComparer.Ordinal)
                .ThenBy(x => x.Fingerprint, StringComparer.Ordinal).ToArray()
        };
    }

    public static string Fingerprint(string packId, string ruleId, string subjectId, string checkKey)
    {
        static string Frame(string x) => Encoding.UTF8.GetByteCount(x).ToString(CultureInfo.InvariantCulture) + ":" + x;
        return "finding:v1:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            Frame(packId) + Frame(ruleId) + Frame(subjectId) + Frame(checkKey))));
    }
    private static AnalysisCompletion Completion(IEnumerable<RuleEvaluation> checks) =>
        checks.Any(x => x.Outcome == RuleOutcome.Error) ? AnalysisCompletion.Error :
        checks.Any(x => x.Outcome == RuleOutcome.NotVerified) ? AnalysisCompletion.Partial : AnalysisCompletion.Complete;
    private static RuleRunSummary Summarize(RuleMetadata meta, IReadOnlyList<RuleEvaluation> checks) => new()
    {
        RuleId = meta.Id, RuleVersion = meta.Version, Title = meta.Title, Category = meta.Category,
        Severity = meta.DefaultSeverity, Completion = Completion(checks),
        RequiredCapabilities = meta.RequiredCapabilities.OrderBy(x => x.CapabilityId, StringComparer.Ordinal).ToArray(),
        RequiredFields = meta.RequiredFields.OrderBy(x => x, StringComparer.Ordinal).ToArray(),
        ReferenceUrls = meta.References.Where(x => x.Url is not null).Select(x => x.Url!)
            .Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray(),
        Present = checks.Count(x => x.Outcome == RuleOutcome.Present), Potential = checks.Count(x => x.Outcome == RuleOutcome.Potential),
        NotDetected = checks.Count(x => x.Outcome == RuleOutcome.NotDetected), NotVerified = checks.Count(x => x.Outcome == RuleOutcome.NotVerified),
        NotApplicable = checks.Count(x => x.Outcome == RuleOutcome.NotApplicable), Errors = checks.Count(x => x.Outcome == RuleOutcome.Error)
    };
}

public sealed class AnalysisLimitException : Exception
{
    public AnalysisLimitException() : base("Analysis evaluation budget exceeded; no truncated report was published.") { }
}
