using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Collectors.ActiveDirectory.Collectors;

/// <summary>
/// Collects trustedDomain objects for the default domain without following trusts or contacting
/// remote domains. The collector records configured trust relationships only.
/// </summary>
public sealed class TrustCollector : ICollector
{
    public const string CollectorId = "ad.ldap.trusts";
    public const string CollectorVersion = "0.1.0";

    private static readonly IReadOnlySet<string> ProvidedCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryTrusts
        };

    private static readonly IReadOnlySet<string> RequiredCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryCore,
            CollectionCapabilities.DirectoryDomains
        };

    private static readonly string[] RequestedAttributes =
    [
        "objectGUID",
        "name",
        "trustPartner",
        "flatName",
        "securityIdentifier",
        "trustDirection",
        "trustType",
        "trustAttributes",
        "whenCreated",
        "whenChanged"
    ];

    private readonly IReadOnlyLdapClientFactory _ldapClientFactory;
    private readonly TimeProvider _timeProvider;

    public TrustCollector(
        IReadOnlyLdapClientFactory ldapClientFactory,
        TimeProvider? timeProvider = null)
    {
        _ldapClientFactory = ldapClientFactory ?? throw new ArgumentNullException(nameof(ldapClientFactory));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public string Id => CollectorId;
    public string Version => CollectorVersion;
    public IReadOnlySet<string> ProvidesCapabilities => ProvidedCapabilities;
    public IReadOnlySet<string> RequiresCapabilities => RequiredCapabilities;

    public async Task<CollectorResult> CollectAsync(
        CollectionContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var startedAt = _timeProvider.GetUtcNow();
        var baseDn = context.AvailableData.Content.DirectoryEnvironment?.DefaultNamingContext;
        var sourceDomains = context.AvailableData.Content.Domains;

        if (string.IsNullOrWhiteSpace(baseDn))
        {
            var completedAt = _timeProvider.GetUtcNow();
            return new CollectorResult(
                CollectorId,
                CollectorVersion,
                FailureFragment(
                    context.Target,
                    "collection.trusts.default-naming-context-unavailable",
                    "Trust collection requires RootDSE defaultNamingContext.",
                    startedAt,
                    completedAt));
        }

        if (sourceDomains.Count != 1 || string.IsNullOrWhiteSpace(sourceDomains[0].DnsName))
        {
            var completedAt = _timeProvider.GetUtcNow();
            return new CollectorResult(
                CollectorId,
                CollectorVersion,
                FailureFragment(
                    context.Target,
                    "collection.trusts.source-domain-unavailable",
                    "Trust collection requires exactly one normalized default-domain identity.",
                    startedAt,
                    completedAt));
        }

        var sourceDomainDnsName = sourceDomains[0].DnsName;

        await using var client = await _ldapClientFactory
            .CreateAsync(context.Target, cancellationToken)
            .ConfigureAwait(false);

        var result = await client.SearchAsync(
            new LdapSearchRequest
            {
                BaseDn = baseDn,
                Filter = "(objectClass=trustedDomain)",
                Scope = LdapSearchScope.Subtree,
                Attributes = RequestedAttributes
            },
            cancellationToken).ConfigureAwait(false);

        var completedAt = _timeProvider.GetUtcNow();
        var trusts = new List<AdTrust>();
        var issues = new List<CollectionIssue>();
        var observations = new List<ObservedFact>();

        foreach (var entry in result.Entries
                     .OrderBy(item => item.DistinguishedName, StringComparer.OrdinalIgnoreCase))
        {
            AddObservations(
                observations,
                entry,
                sourceDomainDnsName,
                context.Target,
                completedAt);

            var targetDomainDnsName = entry.GetSingleTextValue("trustPartner")?.Trim();
            var trustDirection = LdapValueConverters.GetInt32(entry, "trustDirection");
            var trustType = LdapValueConverters.GetInt32(entry, "trustType");
            var trustAttributes = LdapValueConverters.GetInt32(entry, "trustAttributes");

            var entryIssues = ValidateRequiredFields(
                entry,
                targetDomainDnsName,
                trustDirection,
                trustType,
                trustAttributes,
                context.Target);

            if (entryIssues.Count > 0)
            {
                issues.AddRange(entryIssues);
                continue;
            }

            trusts.Add(new AdTrust
            {
                SourceDomainDnsName = sourceDomainDnsName,
                TargetDomainDnsName = targetDomainDnsName!,
                TargetDomainSid = LdapValueConverters.GetSid(entry, "securityIdentifier"),
                TrustDirection = trustDirection!.Value,
                TrustType = trustType!.Value,
                TrustAttributes = trustAttributes!.Value
            });
        }

        var orderedTrusts = trusts
            .Distinct()
            .OrderBy(item => item.SourceDomainDnsName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.TargetDomainDnsName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.TrustDirection)
            .ThenBy(item => item.TrustType)
            .ToArray();

        var fragment = new SnapshotFragment
        {
            Content = new SnapshotContent
            {
                Trusts = orderedTrusts
            },
            Coverage =
            [
                new CapabilityCoverage
                {
                    CapabilityId = CollectionCapabilities.DirectoryTrusts,
                    ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                        CollectionCapabilities.DirectoryTrusts),
                    Status = issues.Count == 0
                        ? CapabilityStatus.Complete
                        : CapabilityStatus.Partial,
                    StartedAt = startedAt,
                    CompletedAt = completedAt,
                    ObservedItemCount = orderedTrusts.Length,
                    Issues = issues
                        .OrderBy(issue => issue.Code, StringComparer.Ordinal)
                        .ThenBy(issue => issue.Target, StringComparer.Ordinal)
                        .ThenBy(issue => issue.Message, StringComparer.Ordinal)
                        .ToArray()
                }
            ],
            Observations = observations
                .DistinctBy(fact => fact.FactId, StringComparer.Ordinal)
                .OrderBy(fact => fact.FactId, StringComparer.Ordinal)
                .ToArray()
        };

        return new CollectorResult(CollectorId, CollectorVersion, fragment);
    }

    private static IReadOnlyList<CollectionIssue> ValidateRequiredFields(
        LdapSearchEntry entry,
        string? targetDomainDnsName,
        int? trustDirection,
        int? trustType,
        int? trustAttributes,
        string target)
    {
        var issues = new List<CollectionIssue>();

        if (string.IsNullOrWhiteSpace(targetDomainDnsName))
        {
            issues.Add(Issue(
                "collection.trusts.partner-missing",
                $"Trusted-domain object '{entry.DistinguishedName}' has no trustPartner.",
                target));
        }

        if (!trustDirection.HasValue)
        {
            issues.Add(Issue(
                "collection.trusts.direction-invalid",
                $"Trusted-domain object '{entry.DistinguishedName}' has no parseable trustDirection.",
                target));
        }

        if (!trustType.HasValue)
        {
            issues.Add(Issue(
                "collection.trusts.type-invalid",
                $"Trusted-domain object '{entry.DistinguishedName}' has no parseable trustType.",
                target));
        }

        if (!trustAttributes.HasValue)
        {
            issues.Add(Issue(
                "collection.trusts.attributes-invalid",
                $"Trusted-domain object '{entry.DistinguishedName}' has no parseable trustAttributes.",
                target));
        }

        return issues;
    }

    private static void AddObservations(
        ICollection<ObservedFact> facts,
        LdapSearchEntry entry,
        string sourceDomainDnsName,
        string target,
        DateTimeOffset observedAt)
    {
        var objectGuid = LdapValueConverters.GetGuid(entry, "objectGUID");
        var partner = entry.GetSingleTextValue("trustPartner");
        var subjectId = objectGuid.HasValue
            ? $"ad-object:{new AdObjectId(objectGuid.Value)}"
            : $"ad-trust:{sourceDomainDnsName.ToLowerInvariant()}:{(partner ?? entry.DistinguishedName).ToLowerInvariant()}";

        AddFact(facts, subjectId, "trust.objectGuid", objectGuid?.ToString("D"), FactValueKind.Guid,
            target, entry.DistinguishedName, observedAt);
        AddFact(facts, subjectId, "trust.partner", partner, FactValueKind.Text,
            target, entry.DistinguishedName, observedAt);
        AddFact(facts, subjectId, "trust.flatName", entry.GetSingleTextValue("flatName"), FactValueKind.Text,
            target, entry.DistinguishedName, observedAt);
        AddFact(facts, subjectId, "trust.targetSid", LdapValueConverters.GetSid(entry, "securityIdentifier"), FactValueKind.Sid,
            target, entry.DistinguishedName, observedAt);
        AddFact(facts, subjectId, "trust.direction", entry.GetSingleTextValue("trustDirection"), FactValueKind.Integer,
            target, entry.DistinguishedName, observedAt);
        AddFact(facts, subjectId, "trust.type", entry.GetSingleTextValue("trustType"), FactValueKind.Integer,
            target, entry.DistinguishedName, observedAt);
        AddFact(facts, subjectId, "trust.attributes", entry.GetSingleTextValue("trustAttributes"), FactValueKind.Integer,
            target, entry.DistinguishedName, observedAt);
        AddFact(facts, subjectId, "trust.whenCreated", entry.GetSingleTextValue("whenCreated"), FactValueKind.Timestamp,
            target, entry.DistinguishedName, observedAt);
        AddFact(facts, subjectId, "trust.whenChanged", entry.GetSingleTextValue("whenChanged"), FactValueKind.Timestamp,
            target, entry.DistinguishedName, observedAt);
    }

    private static void AddFact(
        ICollection<ObservedFact> facts,
        string subjectId,
        string path,
        string? value,
        FactValueKind valueKind,
        string target,
        string locator,
        DateTimeOffset observedAt)
    {
        if (value is null)
        {
            return;
        }

        facts.Add(new ObservedFact
        {
            FactId = FactIdFactory.Create(
                CollectionCapabilities.DirectoryTrusts,
                subjectId,
                path,
                valueKind,
                value),
            CapabilityId = CollectionCapabilities.DirectoryTrusts,
            SubjectId = subjectId,
            Path = path,
            Value = value,
            ValueKind = valueKind,
            Source = new ObservationSource
            {
                CollectorId = CollectorId,
                CollectorVersion = CollectorVersion,
                SourceKind = "ldap",
                Endpoint = target,
                Locator = locator
            },
            ObservedAt = observedAt
        });
    }

    private static CollectionIssue Issue(string code, string message, string target) =>
        new()
        {
            Code = code,
            Severity = CollectionIssueSeverity.Error,
            Message = message,
            CapabilityId = CollectionCapabilities.DirectoryTrusts,
            CollectorId = CollectorId,
            Target = target
        };

    private static SnapshotFragment FailureFragment(
        string target,
        string code,
        string message,
        DateTimeOffset startedAt,
        DateTimeOffset completedAt) =>
        new()
        {
            Coverage =
            [
                new CapabilityCoverage
                {
                    CapabilityId = CollectionCapabilities.DirectoryTrusts,
                    ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                        CollectionCapabilities.DirectoryTrusts),
                    Status = CapabilityStatus.Failed,
                    StartedAt = startedAt,
                    CompletedAt = completedAt,
                    ObservedItemCount = 0,
                    Issues = [Issue(code, message, target)]
                }
            ]
        };
}
