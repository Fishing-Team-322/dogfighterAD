using System.Globalization;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Collectors.ActiveDirectory.Collectors;

/// <summary>
/// Collects domain defaults and PSO configurations as versioned observations. Missing LDAP values
/// remain missing, including server omissions caused by access controls. No password/secret is read.
/// PSO applicability and a user's resultant policy are deliberately not calculated here.
/// </summary>
public sealed class SecurityPolicyCollector : ICollector
{
    public const string CollectorId = "ad.ldap.security-policy";
    public const string CollectorVersion = "0.2.0";
    private const string Capability = CollectionCapabilities.DirectorySecurityPolicy;
    private readonly IReadOnlyLdapClientFactory _factory;
    private readonly TimeProvider _time;
    public SecurityPolicyCollector(IReadOnlyLdapClientFactory factory, TimeProvider? timeProvider = null)
    { _factory = factory ?? throw new ArgumentNullException(nameof(factory)); _time = timeProvider ?? TimeProvider.System; }
    public string Id => CollectorId;
    public string Version => CollectorVersion;
    public IReadOnlySet<string> ProvidesCapabilities { get; } = new HashSet<string>(StringComparer.Ordinal) { Capability };
    public IReadOnlySet<string> RequiresCapabilities { get; } = new HashSet<string>(StringComparer.Ordinal)
    { CollectionCapabilities.DirectoryCore, CollectionCapabilities.DirectoryDomains };

    private static readonly (string Attribute, string Path)[] DomainFields =
    [
        ("minPwdLength", "minimumPasswordLength"), ("pwdHistoryLength", "passwordHistoryLength"),
        ("lockoutThreshold", "lockoutThreshold"), ("lockoutDuration", "lockoutDurationTicks"),
        ("lockOutObservationWindow", "lockoutObservationWindowTicks"), ("minPwdAge", "minimumPasswordAgeTicks"),
        ("maxPwdAge", "maximumPasswordAgeTicks"), ("ms-DS-MachineAccountQuota", "machineAccountQuota")
    ];
    private static readonly (string Attribute, string Path)[] PsoFields =
    [
        ("msDS-MinimumPasswordLength", "minimumPasswordLength"), ("msDS-PasswordHistoryLength", "passwordHistoryLength"),
        ("msDS-LockoutThreshold", "lockoutThreshold"), ("msDS-LockoutDuration", "lockoutDurationTicks"),
        ("msDS-LockoutObservationWindow", "lockoutObservationWindowTicks"), ("msDS-MinimumPasswordAge", "minimumPasswordAgeTicks"),
        ("msDS-MaximumPasswordAge", "maximumPasswordAgeTicks"), ("msDS-PasswordSettingsPrecedence", "precedence")
    ];

    public async Task<CollectorResult> CollectAsync(CollectionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var started = _time.GetUtcNow();
        var facts = new List<ObservedFact>();
        var issues = new List<CollectionIssue>();
        var count = 0;
        var domains = context.AvailableData.Content.Domains;
        if (domains.Count != 1)
        {
            issues.Add(Issue("collection.security-policy.domain-unavailable", context.Target));
            return Finish();
        }
        var domain = domains[0];
        await using var client = await _factory.CreateAsync(context.Target, cancellationToken).ConfigureAwait(false);
        try
        {
            var response = await client.SearchAsync(new LdapSearchRequest
            {
                BaseDn = domain.DistinguishedName, Scope = LdapSearchScope.Base, Filter = "(objectClass=domainDNS)",
                Attributes = DomainFields.Select(x => x.Attribute).Concat(["objectGUID", "pwdProperties"]).ToArray()
            }, cancellationToken).ConfigureAwait(false);
            if (response.Entries.Count == 1 && LdapValueConverters.GetGuid(response.Entries[0], "objectGUID") == domain.Id.Value)
            {
                var entry = response.Entries[0];
                var subject = $"ad-object:{domain.Id}";
                Identity(entry, subject, "DefaultDomain");
                foreach (var field in DomainFields) Integer(entry, subject, field.Attribute, "policy." + field.Path);
                var properties = Integer(entry, subject, "pwdProperties", "policy.passwordProperties");
                if (properties is >= 0 and <= uint.MaxValue)
                {
                    Add(entry, subject, "policy.complexityEnabled", (properties.Value & 1) != 0 ? "true" : "false", FactValueKind.Boolean, "pwdProperties/bit-0");
                    Add(entry, subject, "policy.reversibleEncryptionEnabled", (properties.Value & 0x10) != 0 ? "true" : "false", FactValueKind.Boolean, "pwdProperties/bit-4");
                }
                else if (properties.HasValue) issues.Add(Issue("collection.security-policy.invalid-password-properties", context.Target));
                count++;
            }
            else issues.Add(Issue("collection.security-policy.domain-identity-mismatch", context.Target));
        }
        catch (CollectorOperationalException) { issues.Add(Issue("collection.security-policy.domain-read-failed", context.Target)); }

        try
        {
            var seen = new HashSet<Guid>();
            await foreach (var entry in client.SearchEntriesAsync(new LdapSearchRequest
            {
                BaseDn = $"CN=Password Settings Container,CN=System,{domain.DistinguishedName}",
                Scope = LdapSearchScope.Subtree, Filter = "(objectClass=msDS-PasswordSettings)", PageSize = 500,
                Attributes = PsoFields.Select(x => x.Attribute).Concat(
                    ["objectGUID", "msDS-PasswordComplexityEnabled", "msDS-PasswordReversibleEncryptionEnabled"]).ToArray()
            }, cancellationToken))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var id = LdapValueConverters.GetGuid(entry, "objectGUID");
                if (!id.HasValue || string.IsNullOrWhiteSpace(entry.DistinguishedName) || !seen.Add(id.Value))
                { issues.Add(Issue("collection.security-policy.pso-identity-invalid", context.Target)); continue; }
                var subject = $"password-policy:{id.Value:D}";
                Identity(entry, subject, "FineGrained");
                foreach (var field in PsoFields) Integer(entry, subject, field.Attribute, "policy." + field.Path);
                Boolean(entry, subject, "msDS-PasswordComplexityEnabled", "policy.complexityEnabled");
                Boolean(entry, subject, "msDS-PasswordReversibleEncryptionEnabled", "policy.reversibleEncryptionEnabled");
                count++;
            }
        }
        catch (CollectorOperationalException) { issues.Add(Issue("collection.security-policy.pso-enumeration-failed", context.Target)); }
        return Finish();

        void Identity(LdapSearchEntry entry, string subject, string kind)
        {
            Add(entry, subject, "policy.kind", kind, FactValueKind.Text, "objectClass");
            Add(entry, subject, "policy.distinguishedName", entry.DistinguishedName, FactValueKind.DistinguishedName, "distinguishedName");
        }
        long? Integer(LdapSearchEntry entry, string subject, string attribute, string path)
        {
            var values = entry.GetTextValues(attribute);
            if (values.Count != 1 || !long.TryParse(values[0], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var value))
            { Unavailable(entry, subject, attribute, path, values.Count == 0 ? "NotReturned" : "Invalid"); return null; }
            Add(entry, subject, path, value.ToString(CultureInfo.InvariantCulture), FactValueKind.Integer, attribute);
            return value;
        }
        void Boolean(LdapSearchEntry entry, string subject, string attribute, string path)
        {
            var values = entry.GetTextValues(attribute);
            if (values.Count != 1 || !bool.TryParse(values[0], out var value))
            { Unavailable(entry, subject, attribute, path, values.Count == 0 ? "NotReturned" : "Invalid"); return; }
            Add(entry, subject, path, value ? "true" : "false", FactValueKind.Boolean, attribute);
        }
        void Unavailable(LdapSearchEntry entry, string subject, string attribute, string path, string state)
        {
            Add(entry, subject, path + ".readState", state, FactValueKind.Text, attribute);
            issues.Add(Issue("collection.security-policy.attribute-unavailable", context.Target));
        }
        void Add(LdapSearchEntry entry, string subject, string path, string value, FactValueKind kind, string attribute)
        {
            facts.Add(new ObservedFact
            {
                FactId = FactIdFactory.Create(Capability, subject, path, kind, value), CapabilityId = Capability,
                SubjectId = subject, Path = path, Value = value, ValueKind = kind, ObservedAt = _time.GetUtcNow(),
                Source = new ObservationSource { CollectorId = Id, CollectorVersion = Version, SourceKind = "ldap",
                    Endpoint = context.Target, Locator = entry.DistinguishedName + "/" + attribute }
            });
        }
        CollectorResult Finish() => new(Id, Version, new SnapshotFragment
        {
            Observations = facts.DistinctBy(x => x.FactId, StringComparer.Ordinal).OrderBy(x => x.FactId, StringComparer.Ordinal).ToArray(),
            Coverage = [new CapabilityCoverage { CapabilityId = Capability, ContractVersion = 1,
                Status = issues.Count == 0 ? CapabilityStatus.Complete : count == 0 ? CapabilityStatus.Failed : CapabilityStatus.Partial,
                StartedAt = started, CompletedAt = _time.GetUtcNow(), ObservedItemCount = count,
                Collectors = [new(Id, Version)], Issues = issues.DistinctBy(x => x.Code, StringComparer.Ordinal).OrderBy(x => x.Code, StringComparer.Ordinal).ToArray() }]
        });
    }
    private static CollectionIssue Issue(string code, string target) => new()
    { Code = code, Severity = CollectionIssueSeverity.Warning, CapabilityId = Capability, CollectorId = CollectorId,
        Target = target, Message = "Security-policy data was not returned or could not be validated. Missing values are not defaulted; source payloads are omitted." };
}
