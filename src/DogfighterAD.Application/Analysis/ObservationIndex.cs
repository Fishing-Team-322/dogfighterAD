using System.Globalization;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis;

/// <summary>
/// Only persisted observations are operands. A typed CLR zero/false/empty collection is never
/// substituted for missing evidence. This index does not authenticate the snapshot's origin.
/// </summary>
public sealed class ObservationIndex
{
    private readonly Dictionary<(string Capability, string Subject, string Path), ObservedFact[]> _facts;
    private readonly Dictionary<string, CapabilityCoverage> _coverage;
    private readonly DateTimeOffset _started;
    private readonly DateTimeOffset _completed;

    public ObservationIndex(AdSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        _started = snapshot.Metadata.StartedAt;
        _completed = snapshot.Metadata.CompletedAt;
        _coverage = snapshot.Coverage.ToDictionary(x => x.CapabilityId, StringComparer.Ordinal);
        _facts = snapshot.Observations.GroupBy(x => (x.CapabilityId, x.SubjectId, x.Path))
            .ToDictionary(g => g.Key, g => g.OrderBy(x => x.FactId, StringComparer.Ordinal).ToArray());
    }

    public IReadOnlyList<string> Subjects(string capability, string path) => _facts.Keys
        .Where(k => k.Capability == capability && k.Path == path).Select(k => k.Subject)
        .Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray();

    public FactRead<string> Text(string capability, string subject, string path,
        FactValueKind kind = FactValueKind.Text) => Scalar(capability, subject, path, kind, value =>
            (kind switch { FactValueKind.Sid => IsSid(value), FactValueKind.Guid => Guid.TryParse(value, out _),
                FactValueKind.DistinguishedName => !string.IsNullOrWhiteSpace(value), _ => true }, value));

    public FactRead<long> Integer(string capability, string subject, string path) =>
        Scalar(capability, subject, path, FactValueKind.Integer, value =>
            (long.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var parsed), parsed));

    public FactRead<bool> Boolean(string capability, string subject, string path) =>
        Scalar(capability, subject, path, FactValueKind.Boolean, value =>
            (bool.TryParse(value, out var parsed), parsed));

    // Nonempty returned values establish existence, not completeness of an LDAP attribute.
    // An omitted multivalue attribute is Unknown, not an empty set.
    public FactRead<IReadOnlyList<string>> Values(string capability, string subject, string path,
        FactValueKind kind = FactValueKind.Text)
    {
        var checkedFacts = Checked(capability, subject, path, kind);
        if (checkedFacts.Code is not null)
            return FactRead<IReadOnlyList<string>>.Unknown(checkedFacts.Code);
        IReadOnlyList<string> values = checkedFacts.Facts.Select(x => x.Value!)
            .Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        return new(true, values, checkedFacts.Facts.Select(ToEvidence).ToArray(), null);
    }

    private FactRead<T> Scalar<T>(string capability, string subject, string path, FactValueKind kind,
        Func<string, (bool Valid, T Value)> parse)
    {
        var checkedFacts = Checked(capability, subject, path, kind);
        if (checkedFacts.Code is not null) return FactRead<T>.Unknown(checkedFacts.Code);
        var parsed = checkedFacts.Facts.Select(x => parse(x.Value!)).ToArray();
        if (parsed.Any(x => !x.Valid)) return FactRead<T>.Unknown("field.invalid-format");
        var distinct = parsed.Select(x => x.Value).Distinct().ToArray();
        if (distinct.Length != 1) return FactRead<T>.Unknown("field.conflicting-observations");
        return new(true, distinct[0], checkedFacts.Facts.Select(ToEvidence).ToArray(), null);
    }

    private (ObservedFact[] Facts, string? Code) Checked(string capability, string subject, string path, FactValueKind kind)
    {
        if (!_facts.TryGetValue((capability, subject, path), out var facts) || facts.Length == 0)
            return ([], "field.not-observed");
        foreach (var fact in facts)
        {
            if (fact.Disposition != FactDisposition.Stored) return ([], "field.not-stored");
            if (fact.Value is null) return ([], "field.null");
            if (fact.ValueKind != kind) return ([], "field.wrong-kind");
            if (kind == FactValueKind.Sid && !IsSid(fact.Value)) return ([], "field.invalid-sid");
            if (fact.ObservedAt < _started || fact.ObservedAt > _completed)
                return ([], "evidence.outside-collection-window");
            if (string.IsNullOrWhiteSpace(fact.Source.SourceKind) ||
                string.IsNullOrWhiteSpace(fact.Source.CollectorId) ||
                string.IsNullOrWhiteSpace(fact.Source.CollectorVersion) ||
                !_coverage.TryGetValue(capability, out var coverage) ||
                !coverage.Collectors.Any(c => c.Id == fact.Source.CollectorId && c.Version == fact.Source.CollectorVersion))
                return ([], "evidence.provenance-unavailable");
            var expectedId = FactIdFactory.Create(capability, subject, path, fact.ValueKind, fact.Value);
            if (!StringComparer.Ordinal.Equals(expectedId, fact.FactId))
                return ([], "evidence.fact-id-mismatch");
        }
        return (facts, null);
    }

    private static bool IsSid(string value)
    {
        var p = value.Split('-');
        return p.Length is >= 3 and <= 18 && p[0].Equals("S", StringComparison.OrdinalIgnoreCase) && p[1] == "1" &&
            ulong.TryParse(p[2], NumberStyles.None, CultureInfo.InvariantCulture, out var authority) && authority <= 0xffffffffffffUL &&
            p.Skip(3).All(x => uint.TryParse(x, NumberStyles.None, CultureInfo.InvariantCulture, out _));
    }

    private static Evidence ToEvidence(ObservedFact fact) => new()
    {
        Kind = "observed-fact", FactId = fact.FactId, SubjectId = fact.SubjectId,
        CapabilityId = fact.CapabilityId, Path = fact.Path, Value = fact.Value,
        Source = $"{fact.Source.SourceKind}:{fact.Source.Endpoint}:{fact.Source.Locator}",
        ObservedAt = fact.ObservedAt, CollectorId = fact.Source.CollectorId,
        CollectorVersion = fact.Source.CollectorVersion
    };
}

public sealed record FactRead<T>(bool Known, T Value, IReadOnlyList<Evidence> Evidence, string? Code)
{
    public static FactRead<T> Unknown(string code) => new(false, default!, [], code);
}
