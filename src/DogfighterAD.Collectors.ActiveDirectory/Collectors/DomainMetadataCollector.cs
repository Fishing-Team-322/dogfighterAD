using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Collectors.ActiveDirectory.Collectors;

public sealed class DomainMetadataCollector : ICollector
{
    public const string CollectorId = "ad.ldap.domain-metadata";
    public const string CollectorVersion = "0.1.0";

    private static readonly IReadOnlySet<string> ProvidedCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryDomains
        };

    private static readonly IReadOnlySet<string> RequiredCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryCore
        };

    private static readonly string[] RequestedAttributes =
    [
        "objectGUID",
        "objectSid",
        "name",
        "msDS-Behavior-Version",
        "whenCreated",
        "whenChanged"
    ];

    private readonly IReadOnlyLdapClientFactory _ldapClientFactory;
    private readonly TimeProvider _timeProvider;

    public DomainMetadataCollector(
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
        var environment = context.AvailableData.Content.DirectoryEnvironment;
        var baseDn = environment?.DefaultNamingContext;

        if (string.IsNullOrWhiteSpace(baseDn))
        {
            var failureCompletedAt = _timeProvider.GetUtcNow();
            return new CollectorResult(
                CollectorId,
                CollectorVersion,
                CreateFailureFragment(
                    context.Target,
                    "collection.domain.default-naming-context-unavailable",
                    "Domain metadata collection requires RootDSE defaultNamingContext.",
                    startedAt,
                    failureCompletedAt));
        }

        await using var client = await _ldapClientFactory
            .CreateAsync(context.Target, cancellationToken)
            .ConfigureAwait(false);

        var result = await client.SearchAsync(
            new LdapSearchRequest
            {
                BaseDn = baseDn,
                Filter = "(objectClass=domainDNS)",
                Scope = LdapSearchScope.Base,
                Attributes = RequestedAttributes
            },
            cancellationToken).ConfigureAwait(false);

        var completedAt = _timeProvider.GetUtcNow();

        if (result.Entries.Count != 1)
        {
            return new CollectorResult(
                CollectorId,
                CollectorVersion,
                CreateFailureFragment(
                    context.Target,
                    "collection.domain.invalid-entry-count",
                    $"Domain base search returned {result.Entries.Count} entries; exactly one was expected.",
                    startedAt,
                    completedAt,
                    result.Entries.Count));
        }

        var entry = result.Entries[0];
        var objectGuid = LdapValueConverters.GetGuid(entry, "objectGUID");
        var sid = LdapValueConverters.GetSid(entry, "objectSid");
        var dnsName = LdapValueConverters.DistinguishedNameToDnsName(entry.DistinguishedName);
        var functionalLevel = LdapValueConverters.GetInt32(entry, "msDS-Behavior-Version");

        var fatalIssues = new List<CollectionIssue>();
        if (objectGuid is null)
        {
            fatalIssues.Add(CreateIssue(
                "collection.domain.object-guid-missing",
                "Domain object did not contain a valid objectGUID.",
                context.Target));
        }

        if (string.IsNullOrWhiteSpace(dnsName))
        {
            fatalIssues.Add(CreateIssue(
                "collection.domain.dns-name-unavailable",
                "Domain DNS name could not be derived from the domain distinguished name.",
                context.Target));
        }

        if (fatalIssues.Count > 0)
        {
            return new CollectorResult(
                CollectorId,
                CollectorVersion,
                CreateFailureFragment(
                    context.Target,
                    "collection.domain.identity-unavailable",
                    "Domain identity could not be normalized safely.",
                    startedAt,
                    completedAt,
                    1,
                    fatalIssues));
        }

        var issues = new List<CollectionIssue>();
        if (string.IsNullOrWhiteSpace(sid))
        {
            issues.Add(CreateIssue(
                "collection.domain.sid-missing",
                "Domain object did not contain a valid objectSid.",
                context.Target));
        }

        if (functionalLevel is null)
        {
            issues.Add(CreateIssue(
                "collection.domain.functional-level-missing",
                "Domain functional level was not returned by LDAP.",
                context.Target));
        }

        var domain = new AdDomain
        {
            Id = new AdObjectId(objectGuid!.Value),
            DistinguishedName = entry.DistinguishedName,
            Sid = sid,
            Name = entry.GetSingleTextValue("name"),
            WhenCreated = LdapValueConverters.GetDateTimeOffset(entry, "whenCreated"),
            WhenChanged = LdapValueConverters.GetDateTimeOffset(entry, "whenChanged"),
            DnsName = dnsName!,
            NetbiosName = null,
            FunctionalLevel = functionalLevel
        };

        var status = issues.Count == 0
            ? CapabilityStatus.Complete
            : CapabilityStatus.Partial;

        var fragment = new SnapshotFragment
        {
            Content = new SnapshotContent
            {
                Domains = [domain]
            },
            Coverage =
            [
                new CapabilityCoverage
                {
                    CapabilityId = CollectionCapabilities.DirectoryDomains,
                    ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                        CollectionCapabilities.DirectoryDomains),
                    Status = status,
                    StartedAt = startedAt,
                    CompletedAt = completedAt,
                    ObservedItemCount = 1,
                    Issues = issues
                }
            ],
            Observations = BuildObservations(entry, domain, context.Target, completedAt)
        };

        return new CollectorResult(CollectorId, CollectorVersion, fragment);
    }

    private static IReadOnlyList<ObservedFact> BuildObservations(
        LdapSearchEntry entry,
        AdDomain domain,
        string target,
        DateTimeOffset observedAt)
    {
        var subjectId = $"ad-object:{domain.Id}";
        var facts = new List<ObservedFact>();

        AddFact(facts, subjectId, "domain.distinguishedName", domain.DistinguishedName,
            FactValueKind.DistinguishedName, target, entry.DistinguishedName, observedAt);
        AddFact(facts, subjectId, "domain.objectGuid", domain.Id.ToString(),
            FactValueKind.Guid, target, entry.DistinguishedName, observedAt);
        AddFact(facts, subjectId, "domain.objectSid", domain.Sid,
            FactValueKind.Sid, target, entry.DistinguishedName, observedAt);
        AddFact(facts, subjectId, "domain.dnsName", domain.DnsName,
            FactValueKind.Text, target, entry.DistinguishedName, observedAt);
        AddFact(facts, subjectId, "domain.name", domain.Name,
            FactValueKind.Text, target, entry.DistinguishedName, observedAt);
        AddFact(facts, subjectId, "domain.functionalLevel", domain.FunctionalLevel?.ToString(),
            FactValueKind.Integer, target, entry.DistinguishedName, observedAt);
        AddFact(facts, subjectId, "domain.whenCreated", domain.WhenCreated?.ToUniversalTime().ToString("O"),
            FactValueKind.Timestamp, target, entry.DistinguishedName, observedAt);
        AddFact(facts, subjectId, "domain.whenChanged", domain.WhenChanged?.ToUniversalTime().ToString("O"),
            FactValueKind.Timestamp, target, entry.DistinguishedName, observedAt);

        return facts.OrderBy(x => x.FactId, StringComparer.Ordinal).ToArray();
    }

    private static void AddFact(
        ICollection<ObservedFact> facts,
        string subjectId,
        string path,
        string? value,
        FactValueKind kind,
        string target,
        string distinguishedName,
        DateTimeOffset observedAt)
    {
        if (value is null)
        {
            return;
        }

        facts.Add(new ObservedFact
        {
            FactId = FactIdFactory.Create(
                CollectionCapabilities.DirectoryDomains,
                subjectId,
                path,
                kind,
                value),
            CapabilityId = CollectionCapabilities.DirectoryDomains,
            SubjectId = subjectId,
            Path = path,
            Value = value,
            ValueKind = kind,
            Source = new ObservationSource
            {
                CollectorId = CollectorId,
                CollectorVersion = CollectorVersion,
                SourceKind = "ldap",
                Endpoint = target,
                Locator = $"{distinguishedName}/{path}"
            },
            ObservedAt = observedAt
        });
    }

    private static CollectionIssue CreateIssue(
        string code,
        string message,
        string target) =>
        new()
        {
            Code = code,
            Severity = CollectionIssueSeverity.Error,
            Message = message,
            CapabilityId = CollectionCapabilities.DirectoryDomains,
            CollectorId = CollectorId,
            Target = target
        };

    private static SnapshotFragment CreateFailureFragment(
        string target,
        string code,
        string message,
        DateTimeOffset startedAt,
        DateTimeOffset completedAt,
        int observedItemCount = 0,
        IReadOnlyList<CollectionIssue>? additionalIssues = null)
    {
        var issues = new List<CollectionIssue>
        {
            CreateIssue(code, message, target)
        };

        if (additionalIssues is not null)
        {
            issues.AddRange(additionalIssues);
        }

        return new SnapshotFragment
        {
            Coverage =
            [
                new CapabilityCoverage
                {
                    CapabilityId = CollectionCapabilities.DirectoryDomains,
                    ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                        CollectionCapabilities.DirectoryDomains),
                    Status = CapabilityStatus.Failed,
                    StartedAt = startedAt,
                    CompletedAt = completedAt,
                    ObservedItemCount = observedItemCount,
                    Issues = issues
                }
            ]
        };
    }
}
