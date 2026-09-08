using System.Globalization;
using System.Security.Cryptography;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Collectors.ActiveDirectory.Collectors;

/// <summary>Conservative sufficient proof, not a general Windows access-check evaluator.</summary>
internal sealed class LdapAttributeAbsenceProof
{
    internal const string ProofMethod = "authenticated-schema-read-v1";
    private static readonly string[] Attributes =
        ["servicePrincipalName", "sIDHistory", "msDS-AllowedToDelegateTo", "msDS-SupportedEncryptionTypes", "lastLogonTimestamp", "member"];
    private readonly Dictionary<string, SchemaReadDefinition> _schema = new(StringComparer.OrdinalIgnoreCase);
    private readonly bool _authenticated;
    private LdapAttributeAbsenceProof(bool authenticated) => _authenticated = authenticated;

    public static async Task<LdapAttributeAbsenceProof> CreateAsync(IReadOnlyLdapClient client,
        string? schemaDn, CancellationToken token)
    {
        var proof = new LdapAttributeAbsenceProof(client.IsAuthenticated);
        if (!client.IsAuthenticated || string.IsNullOrWhiteSpace(schemaDn)) return proof;
        try
        {
            var result = await client.SearchAsync(new LdapSearchRequest
            {
                BaseDn = schemaDn, Scope = LdapSearchScope.OneLevel,
                Filter = "(&(objectClass=attributeSchema)(|" + string.Concat(Attributes.Select(a => "(lDAPDisplayName=" + a + ")")) + "))",
                Attributes = ["lDAPDisplayName", "searchFlags", "schemaIDGUID", "attributeSecurityGUID"], PageSize = 100
            }, token).ConfigureAwait(false);
            foreach (var group in result.Entries.GroupBy(e => e.GetSingleTextValue("lDAPDisplayName") ?? "", StringComparer.OrdinalIgnoreCase))
            {
                if (group.Count() != 1 || !Attributes.Contains(group.Key, StringComparer.OrdinalIgnoreCase)) continue;
                var values = group.Single().GetTextValues("searchFlags");
                if (values.Count == 1 && int.TryParse(values[0], NumberStyles.None, CultureInfo.InvariantCulture, out var flags)
                    && IsOrdinarySchema(flags))
                {
                    var id = ReadSchemaGuid(group.Single(), "schemaIDGUID");
                    if (id is not null && id != Guid.Empty)
                        proof._schema.Add(group.Key, new(flags, id.Value, ReadSchemaGuid(group.Single(), "attributeSecurityGUID")));
                }
            }
        }
        catch (DogfighterAD.Application.Contracts.CollectorOperationalException)
        {
            // Schema evidence is optional. Ordinary attribute collection may still succeed;
            // no absence assertions are permitted when this proof could not be obtained.
        }
        return proof;
    }

    private static Guid? ReadSchemaGuid(LdapSearchEntry entry, string name)
    {
        if (!entry.Attributes.TryGetValue(name, out var values) || values.Count != 1 || values[0].Bytes is not { Length: 16 } bytes)
            return null;
        var guid = new Guid(bytes);
        return guid == Guid.Empty ? null : guid;
    }

    internal static bool IsOrdinarySchema(int flags) => flags >= 0 && (flags & ~0x17f) == 0;

    public ConfirmedAbsence? Confirm(LdapSearchEntry entry, string attribute)
    {
        if (!_authenticated || !_schema.TryGetValue(attribute, out var schema) ||
            entry.Attributes.Keys.Any(k => k.Equals(attribute, StringComparison.OrdinalIgnoreCase) ||
                k.StartsWith(attribute + ";", StringComparison.OrdinalIgnoreCase))) return null;
        var descriptors = entry.GetBinaryValues("nTSecurityDescriptor");
        if (descriptors.Count != 1) return null;
        var parsed = new SecurityDescriptorDaclParser().Parse(descriptors[0]);
        if (!HasUnconditionalRead(parsed, _authenticated, schema.AttributeId, schema.PropertySetId)) return null;
        return new(attribute, schema.Flags, Convert.ToHexString(SHA256.HashData(descriptors[0])).ToLowerInvariant(), schema.AttributeId, schema.PropertySetId);
    }

    internal static bool HasUnconditionalRead(ParsedDacl descriptor, bool authenticated, Guid? attributeId = null, Guid? propertySetId = null)
    {
        if (!authenticated || !descriptor.Complete || !descriptor.DescriptorStateReliable) return false;
        if (descriptor.State == AdDaclState.Null) return true;
        if (descriptor.State != AdDaclState.Present) return false;
        // READ_PROPERTY, GENERIC_READ or GENERIC_ALL. Ignore no denies whose token applicability
        // would require guessing identity, nesting, SID history, SELF or property-set membership.
        const uint read = 0x10 | 0x80000000 | 0x10000000;
        if (descriptor.Aces.Any(a => (a.AceFlags & ~0x1f) != 0)) return false;
        var applicable = descriptor.Aces.Where(a => (a.AceFlags & 0x08) == 0).ToArray();
        if (applicable.Any(a => a.AccessType != AdAccessControlType.Allow && (a.AccessMask & read) != 0)) return false;
        return applicable.Any(a => a.AccessType == AdAccessControlType.Allow && (a.ObjectType is null || a.ObjectType == attributeId || a.ObjectType == propertySetId) &&
            (a.AccessMask & read) != 0 && a.TrusteeSid is "S-1-1-0" or "S-1-5-11");
    }
}

internal sealed record SchemaReadDefinition(int Flags, Guid AttributeId, Guid? PropertySetId);
internal sealed record ConfirmedAbsence(string Attribute, int SearchFlags, string DaclSha256, Guid AttributeId, Guid? PropertySetId);

internal static class AbsenceFactWriter
{
    public static void Add(ICollection<ObservedFact> facts, ConfirmedAbsence proof, string capability,
        string subject, string path, string collector, string version, string endpoint, string locator, DateTimeOffset at)
    {
        var source = new ObservationSource { SourceKind = "ldap", CollectorId = collector, CollectorVersion = version,
            Endpoint = endpoint, Locator = locator };
        void Add(string suffix, string value, FactValueKind kind) => facts.Add(new ObservedFact
        {
            FactId = FactIdFactory.Create(capability, subject, path + suffix, kind, value), CapabilityId = capability,
            SubjectId = subject, Path = path + suffix, Value = value, ValueKind = kind, Source = source, ObservedAt = at
        });
        Add(".absenceConfirmed", "true", FactValueKind.Boolean);
        Add(".absenceProof", LdapAttributeAbsenceProof.ProofMethod, FactValueKind.Text);
        Add(".absenceAttribute", proof.Attribute, FactValueKind.Text);
        Add(".absenceSearchFlags", proof.SearchFlags.ToString(CultureInfo.InvariantCulture), FactValueKind.Integer);
        Add(".absenceDaclSha256", proof.DaclSha256, FactValueKind.Text);
        Add(".absenceSchemaId", proof.AttributeId.ToString("D"), FactValueKind.Guid);
        Add(".absencePropertySetId", proof.PropertySetId?.ToString("D") ?? "", FactValueKind.Text);
    }
}
