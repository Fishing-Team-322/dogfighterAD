using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Collectors.ActiveDirectory.Collectors;

public sealed class RootDseCollector : ICollector
{
    public const string CollectorId = "ad.ldap.rootdse";
    public const string CollectorVersion = "0.1.0";

    private static readonly IReadOnlySet<string> ProvidedCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryCore
        };

    private static readonly IReadOnlySet<string> RequiredCapabilities =
        new HashSet<string>(StringComparer.Ordinal);

    private static readonly string[] RequestedAttributes =
    [
        "dnsHostName",
        "defaultNamingContext",
        "configurationNamingContext",
        "schemaNamingContext",
        "rootDomainNamingContext",
        "namingContexts",
        "supportedCapabilities",
        "supportedControl",
        "supportedLDAPVersion"
    ];

    private readonly IReadOnlyLdapClientFactory _ldapClientFactory;
    private readonly TimeProvider _timeProvider;

    public RootDseCollector(
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
        await using var client = await _ldapClientFactory
            .CreateAsync(context.Target, cancellationToken)
            .ConfigureAwait(false);

        var result = await client.SearchAsync(
            new LdapSearchRequest
            {
                BaseDn = string.Empty,
                Filter = "(objectClass=*)",
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
                CreateInvalidRootDseFragment(
                    context.Target,
                    result.Entries.Count,
                    startedAt,
                    completedAt));
        }

        var entry = result.Entries[0];
        var environment = MapEnvironment(entry);
        var issues = ValidateEnvironment(environment, context.Target);
        var status = issues.Count == 0
            ? CapabilityStatus.Complete
            : CapabilityStatus.Partial;

        var observations = BuildObservations(
            entry,
            environment,
            context.Target,
            completedAt);

        var fragment = new SnapshotFragment
        {
            Content = new SnapshotContent
            {
                DirectoryEnvironment = environment
            },
            Coverage =
            [
                new CapabilityCoverage
                {
                    CapabilityId = CollectionCapabilities.DirectoryCore,
                    ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                        CollectionCapabilities.DirectoryCore),
                    Status = status,
                    StartedAt = startedAt,
                    CompletedAt = completedAt,
                    ObservedItemCount = 1,
                    Issues = issues
                }
            ],
            Observations = observations
        };

        return new CollectorResult(CollectorId, CollectorVersion, fragment);
    }

    private static DirectoryEnvironment MapEnvironment(LdapSearchEntry entry) =>
        new()
        {
            DnsHostName = entry.GetSingleTextValue("dnsHostName"),
            DefaultNamingContext = entry.GetSingleTextValue("defaultNamingContext"),
            ConfigurationNamingContext = entry.GetSingleTextValue("configurationNamingContext"),
            SchemaNamingContext = entry.GetSingleTextValue("schemaNamingContext"),
            RootDomainNamingContext = entry.GetSingleTextValue("rootDomainNamingContext"),
            NamingContexts = SortedDistinct(entry.GetTextValues("namingContexts")),
            SupportedCapabilities = SortedDistinct(entry.GetTextValues("supportedCapabilities")),
            SupportedControls = SortedDistinct(entry.GetTextValues("supportedControl")),
            SupportedLdapVersions = SortedDistinct(entry.GetTextValues("supportedLDAPVersion"))
        };

    private static IReadOnlyList<CollectionIssue> ValidateEnvironment(
        DirectoryEnvironment environment,
        string target)
    {
        var issues = new List<CollectionIssue>();

        AddMissingIssue(
            environment.DefaultNamingContext,
            "defaultNamingContext",
            "collection.rootdse.default-naming-context-missing",
            target,
            issues);
        AddMissingIssue(
            environment.ConfigurationNamingContext,
            "configurationNamingContext",
            "collection.rootdse.configuration-naming-context-missing",
            target,
            issues);
        AddMissingIssue(
            environment.SchemaNamingContext,
            "schemaNamingContext",
            "collection.rootdse.schema-naming-context-missing",
            target,
            issues);

        return issues;
    }

    private static void AddMissingIssue(
        string? value,
        string attributeName,
        string issueCode,
        string target,
        ICollection<CollectionIssue> issues)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        issues.Add(new CollectionIssue
        {
            Code = issueCode,
            Severity = CollectionIssueSeverity.Error,
            Message = $"RootDSE did not return required attribute '{attributeName}'.",
            CapabilityId = CollectionCapabilities.DirectoryCore,
            CollectorId = CollectorId,
            Target = target
        });
    }

    private static IReadOnlyList<ObservedFact> BuildObservations(
        LdapSearchEntry entry,
        DirectoryEnvironment environment,
        string target,
        DateTimeOffset observedAt)
    {
        var subjectId = $"ldap-rootdse:{(environment.DnsHostName ?? target).Trim().ToLowerInvariant()}";
        var facts = new List<ObservedFact>();

        foreach (var attributeName in RequestedAttributes.OrderBy(x => x, StringComparer.Ordinal))
        {
            foreach (var value in entry.GetTextValues(attributeName).OrderBy(x => x, StringComparer.Ordinal))
            {
                const FactValueKind valueKind = FactValueKind.Text;
                var path = $"rootDse.{attributeName}";

                facts.Add(new ObservedFact
                {
                    FactId = FactIdFactory.Create(
                        CollectionCapabilities.DirectoryCore,
                        subjectId,
                        path,
                        valueKind,
                        value),
                    CapabilityId = CollectionCapabilities.DirectoryCore,
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
                        Locator = $"RootDSE/{attributeName}"
                    },
                    ObservedAt = observedAt
                });
            }
        }

        return facts
            .OrderBy(x => x.FactId, StringComparer.Ordinal)
            .ToArray();
    }

    private static SnapshotFragment CreateInvalidRootDseFragment(
        string target,
        int entryCount,
        DateTimeOffset startedAt,
        DateTimeOffset completedAt) =>
        new()
        {
            Coverage =
            [
                new CapabilityCoverage
                {
                    CapabilityId = CollectionCapabilities.DirectoryCore,
                    ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                        CollectionCapabilities.DirectoryCore),
                    Status = CapabilityStatus.Failed,
                    StartedAt = startedAt,
                    CompletedAt = completedAt,
                    ObservedItemCount = entryCount,
                    Issues =
                    [
                        new CollectionIssue
                        {
                            Code = "collection.rootdse.invalid-entry-count",
                            Severity = CollectionIssueSeverity.Error,
                            Message = $"RootDSE base search returned {entryCount} entries; exactly one was expected.",
                            CapabilityId = CollectionCapabilities.DirectoryCore,
                            CollectorId = CollectorId,
                            Target = target
                        }
                    ]
                }
            ]
        };

    private static IReadOnlyList<string> SortedDistinct(IEnumerable<string> values) =>
        values
            .Distinct(StringComparer.Ordinal)
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToArray();
}
