using DogfighterAD.Application.Contracts;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis;

/// <summary>Accumulates the exact operands and refuses a verdict if any required operand is unknown.</summary>
public sealed class RuleCheck
{
    private readonly RuleMetadata _metadata;
    private readonly RuleContext _context;
    private readonly ObjectReference _subject;
    private readonly List<Evidence> _evidence = [];
    private readonly List<DataGap> _gaps = [];
    public bool Known => _gaps.Count == 0;

    public RuleCheck(RuleMetadata metadata, RuleContext context, ObjectReference subject)
    { _metadata = metadata; _context = context; _subject = subject; }

    public long Integer(string capability, string path, string? subject = null) =>
        Read(_context.Facts.Integer(capability, subject ?? _subject.StableId, path), capability, subject, path);
    public bool Boolean(string capability, string path, string? subject = null) =>
        Read(_context.Facts.Boolean(capability, subject ?? _subject.StableId, path), capability, subject, path);
    public string Text(string capability, string path, FactValueKind kind = FactValueKind.Text, string? subject = null) =>
        Read(_context.Facts.Text(capability, subject ?? _subject.StableId, path, kind), capability, subject, path);
    public IReadOnlyList<string> Values(string capability, string path, FactValueKind kind = FactValueKind.Text, string? subject = null) =>
        Read(_context.Facts.Values(capability, subject ?? _subject.StableId, path, kind), capability, subject, path) ?? [];

    public bool ConfirmedAbsent(string capability, string path)
    {
        var absent = _context.Facts.Absence(capability, _subject.StableId, path);
        if (!absent.Known || !absent.Value) return false;
        _evidence.AddRange(absent.Evidence);
        return true;
    }
    public void Require(bool condition, string capability, string path, string code)
    { if (!condition) _gaps.Add(new(capability, _subject.StableId, path, code)); }
    public void AddEvidence(IEnumerable<Evidence> evidence) => _evidence.AddRange(evidence);
    public void AddGaps(IEnumerable<DataGap> gaps) => _gaps.AddRange(gaps);

    public RuleEvaluation Result(RuleOutcome outcome, string code, string message, string checkKey = "default") => new()
    {
        RuleId = _metadata.Id, RuleVersion = _metadata.Version, Subject = _subject, CheckKey = checkKey,
        Outcome = Known ? outcome : RuleOutcome.NotVerified,
        Code = Known ? code : "analysis.required-data-unavailable",
        Message = Known ? message : "Required snapshot evidence is missing, conflicting, not stored or invalid; no value was inferred.",
        Evidence = _evidence.DistinctBy(x => x.FactId, StringComparer.Ordinal)
            .OrderBy(x => x.FactId, StringComparer.Ordinal).ToArray(),
        MissingData = _gaps.Distinct().OrderBy(x => x.CapabilityId, StringComparer.Ordinal)
            .ThenBy(x => x.SubjectId, StringComparer.Ordinal).ThenBy(x => x.Path, StringComparer.Ordinal)
            .ThenBy(x => x.Code, StringComparer.Ordinal).ToArray()
    };
    public RuleEvaluation Unknown() => Result(RuleOutcome.NotVerified, "analysis.required-data-unavailable", "Required data is unavailable.");
    public RuleEvaluation NotApplicable(string reason) => Result(RuleOutcome.NotApplicable, "analysis.not-applicable", reason);
    public RuleEvaluation Verdict(bool match, string message, bool potential = false, string checkKey = "default") =>
        Result(match ? (potential ? RuleOutcome.Potential : RuleOutcome.Present) : RuleOutcome.NotDetected,
            match ? "analysis.condition-observed" : "analysis.condition-not-observed", message, checkKey);

    private T Read<T>(FactRead<T> value, string capability, string? subject, string path)
    {
        _context.CancellationToken.ThrowIfCancellationRequested();
        if (!value.Known) _gaps.Add(new(capability, subject ?? _subject.StableId, path, value.Code ?? "field.unknown"));
        else _evidence.AddRange(value.Evidence);
        return value.Value;
    }
}

public static class AnalysisSubjects
{
    public static ObjectReference For(AdDirectoryObject item) => new(
        item switch { AdUser => "user", AdComputer => "computer", AdGroup => "group", AdDomain => "domain",
            AdGroupPolicyObject => "gpo", AdOrganizationalUnit => "ou", _ => "directory-object" },
        $"ad-object:{item.Id}", item.DistinguishedName, item.Name);
    public static IEnumerable<AdDirectoryObject> Objects(SnapshotContent content) =>
        content.Domains.Cast<AdDirectoryObject>().Concat(content.Users).Concat(content.Computers)
            .Concat(content.Groups).Concat(content.OrganizationalUnits).Concat(content.GroupPolicyObjects)
            .Concat(content.ForeignSecurityPrincipals).Concat(content.OtherDirectoryObjects);
    public static ObjectReference Snapshot(AdSnapshot snapshot) => new("snapshot", $"snapshot:{snapshot.Metadata.SnapshotId:D}");
}
