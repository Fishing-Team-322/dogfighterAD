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

    internal bool HasObservation(string capability, string subject, string path) => _facts.ContainsKey((capability, subject, path));

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

    public FactRead<bool> Absence(string capability, string subject, string path)
    {
        var expectedAttribute = path.Split('.').Last() switch
        {
            "servicePrincipalName" => "servicePrincipalName", "sidHistory" => "sIDHistory",
            "allowedToDelegateTo" => "msDS-AllowedToDelegateTo", "supportedEncryptionTypes" => "msDS-SupportedEncryptionTypes",
            "lastLogonTimestamp" => "lastLogonTimestamp", "member" => "member", _ => null
        };
        var version = capability == CollectionCapabilities.DirectoryMemberships ? 3 : 2;
        if (expectedAttribute is null || !_coverage.TryGetValue(capability, out var coverage) || coverage.ContractVersion < version)
            return FactRead<bool>.Unknown("field.absence-contract-unavailable");
        if (_facts.ContainsKey((capability, subject, path))) return FactRead<bool>.Unknown("field.conflicting-absence");
        var marker = Boolean(capability, subject, path + ".absenceConfirmed");
        var method = Text(capability, subject, path + ".absenceProof");
        var attribute = Text(capability, subject, path + ".absenceAttribute");
        var flags = Integer(capability, subject, path + ".absenceSearchFlags");
        var hash = Text(capability, subject, path + ".absenceDaclSha256");
        var schemaId = Text(capability, subject, path + ".absenceSchemaId", FactValueKind.Guid);
        var propertySet = Text(capability, subject, path + ".absencePropertySetId");
        if (!marker.Known || !marker.Value || !method.Known || method.Value != "authenticated-schema-read-v1" ||
            !attribute.Known || attribute.Value != expectedAttribute || !flags.Known || flags.Value < 0 || (flags.Value & ~0x17fL) != 0 ||
            !hash.Known || hash.Value.Length != 64 || !hash.Value.All(Uri.IsHexDigit) ||
            !schemaId.Known || !Guid.TryParse(schemaId.Value, out var schemaGuid) || schemaGuid == Guid.Empty ||
            !propertySet.Known || (propertySet.Value.Length > 0 && !Guid.TryParse(propertySet.Value, out _)))
            return FactRead<bool>.Unknown("field.absence-proof-invalid");
        var evidence = marker.Evidence.Concat(method.Evidence).Concat(attribute.Evidence).Concat(flags.Evidence).Concat(hash.Evidence).Concat(schemaId.Evidence).Concat(propertySet.Evidence).ToArray();
        if (evidence.Select(e => (e.Source, e.ObservedAt, e.CollectorId, e.CollectorVersion)).Distinct().Count() != 1)
            return FactRead<bool>.Unknown("field.absence-proof-conflicting-source");
        return new(true, true, evidence, null);
    }
    // Nonempty returned values establish existence, not completeness of an LDAP attribute.
    // An omitted multivalue attribute is Unknown, not an empty set.
    public FactRead<IReadOnlyList<string>> Values(string capability, string subject, string path,
        FactValueKind kind = FactValueKind.Text)
    {
        if (_facts.ContainsKey((capability, subject, path + ".absenceConfirmed")))
        {
            var absent = Absence(capability, subject, path);
            return absent.Known ? new(true, [], absent.Evidence, null)
                : FactRead<IReadOnlyList<string>>.Unknown(absent.Code!);
        }
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
        if (_facts.ContainsKey((capability, subject, path + ".absenceConfirmed")))
            return FactRead<T>.Unknown("field.absence-not-scalar");
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
