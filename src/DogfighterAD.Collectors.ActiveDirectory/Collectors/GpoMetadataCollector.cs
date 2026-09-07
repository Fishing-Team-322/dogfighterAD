using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Collectors.ActiveDirectory.Collectors;

/// <summary>
/// Collects Group Policy Container metadata from CN=Policies,CN=System in the default domain.
/// SYSVOL content is intentionally outside this capability.
/// </summary>
public sealed class GpoMetadataCollector : ICollector
{
    public const string CollectorId = "ad.ldap.gpo-metadata";
    public const string CollectorVersion = "0.1.0";
    private const int DefaultPageSize = 500;

    private static readonly IReadOnlySet<string> ProvidedCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.GroupPolicyMetadata
        };

    private static readonly IReadOnlySet<string> RequiredCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryCore
        };

    private static readonly string[] RequestedAttributes =
    [
        "objectGUID",
        "name",
        "displayName",
        "gPCFileSysPath",
        "versionNumber",
        "flags",
        "whenCreated",
        "whenChanged"
    ];

    private readonly IReadOnlyLdapClientFactory _ldapClientFactory;
    private readonly TimeProvider _timeProvider;

    public GpoMetadataCollector(
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
        var defaultNamingContext = context.AvailableData.Content.DirectoryEnvironment?.DefaultNamingContext;
        if (string.IsNullOrWhiteSpace(defaultNamingContext))
        {
            var failureCompletedAt = _timeProvider.GetUtcNow();
            return new CollectorResult(
                CollectorId,
                CollectorVersion,
                FailureFragment(
                    context.Target,
                    "collection.gpo.metadata.default-naming-context-unavailable",
                    "GPO metadata collection requires RootDSE defaultNamingContext.",
                    startedAt,
                    failureCompletedAt));
        }

        var policiesDn = $"CN=Policies,CN=System,{defaultNamingContext}";
        var gpos = new List<AdGroupPolicyObject>();
        var observations = new List<ObservedFact>();
        var issues = new List<CollectionIssue>();
        var seenPolicyGuids = new HashSet<Guid>();

        await using var client = await _ldapClientFactory
            .CreateAsync(context.Target, cancellationToken)
            .ConfigureAwait(false);

        var request = new LdapSearchRequest
        {
            BaseDn = policiesDn,
            Filter = "(objectClass=groupPolicyContainer)",
            Scope = LdapSearchScope.OneLevel,
            Attributes = RequestedAttributes,
            PageSize = DefaultPageSize
        };

        await foreach (var entry in client.SearchEntriesAsync(request, cancellationToken))
        {
            var objectGuid = LdapValueConverters.GetGuid(entry, "objectGUID");
            var policyName = entry.GetSingleTextValue("name");

            if (!objectGuid.HasValue ||
                string.IsNullOrWhiteSpace(entry.DistinguishedName) ||
                !Guid.TryParse(policyName, out var gpoGuid))
            {
                issues.Add(Issue(
                    "collection.gpo.metadata.identity-invalid",
                    $"GPO entry '{entry.DistinguishedName}' has no usable objectGUID, distinguished name, or policy GUID name.",
                    context.Target));
                continue;
            }

            if (!seenPolicyGuids.Add(gpoGuid))
            {
                issues.Add(Issue(
                    "collection.gpo.metadata.duplicate-policy-guid",
                    $"GPO policy GUID '{gpoGuid:D}' appears more than once in CN=Policies.",
                    context.Target));
                continue;
            }

            var gpo = new AdGroupPolicyObject
            {
                Id = new AdObjectId(objectGuid.Value),
                DistinguishedName = entry.DistinguishedName,
                Name = policyName,
                WhenCreated = LdapValueConverters.GetDateTimeOffset(entry, "whenCreated"),
                WhenChanged = LdapValueConverters.GetDateTimeOffset(entry, "whenChanged"),
                GpoGuid = gpoGuid,
                DisplayName = entry.GetSingleTextValue("displayName"),
                FileSystemPath = entry.GetSingleTextValue("gPCFileSysPath"),
                VersionNumber = LdapValueConverters.GetInt32(entry, "versionNumber"),
                Flags = LdapValueConverters.GetInt32(entry, "flags")
            };

            gpos.Add(gpo);
            AddFacts(
                observations,
                entry,
                gpo,
                context.Target,
                _timeProvider.GetUtcNow());
        }

        var completedAt = _timeProvider.GetUtcNow();
        var orderedGpos = gpos
            .OrderBy(item => item.GpoGuid)
            .ThenBy(item => item.Id.Value)
            .ToArray();

        return new CollectorResult(
            CollectorId,
            CollectorVersion,
            new SnapshotFragment
            {
                Content = new SnapshotContent
                {
                    GroupPolicyObjects = orderedGpos
                },
                Coverage =
                [
                    new CapabilityCoverage
                    {
                        CapabilityId = CollectionCapabilities.GroupPolicyMetadata,
                        ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                            CollectionCapabilities.GroupPolicyMetadata),
                        Status = issues.Count == 0
                            ? CapabilityStatus.Complete
                            : CapabilityStatus.Partial,
                        StartedAt = startedAt,
                        CompletedAt = completedAt,
                        ObservedItemCount = orderedGpos.Length,
                        Issues = issues
                            .OrderBy(issue => issue.Code, StringComparer.Ordinal)
                            .ThenBy(issue => issue.Message, StringComparer.Ordinal)
                            .ToArray()
                    }
                ],
                Observations = observations
                    .DistinctBy(fact => fact.FactId, StringComparer.Ordinal)
                    .OrderBy(fact => fact.FactId, StringComparer.Ordinal)
                    .ToArray()
            });
    }

    private static void AddFacts(
        ICollection<ObservedFact> facts,
        LdapSearchEntry entry,
        AdGroupPolicyObject gpo,
        string endpoint,
        DateTimeOffset observedAt)
    {
        AddFact(facts, gpo.Id, "gpo.policyGuid", gpo.GpoGuid.ToString("D"), FactValueKind.Guid, endpoint, entry.DistinguishedName, observedAt);
        AddFact(facts, gpo.Id, "gpo.displayName", gpo.DisplayName, FactValueKind.Text, endpoint, entry.DistinguishedName, observedAt);
        AddFact(facts, gpo.Id, "gpo.fileSystemPath", gpo.FileSystemPath, FactValueKind.Text, endpoint, entry.DistinguishedName, observedAt);
        AddFact(facts, gpo.Id, "gpo.versionNumber", entry.GetSingleTextValue("versionNumber"), FactValueKind.Integer, endpoint, entry.DistinguishedName, observedAt);
        AddFact(facts, gpo.Id, "gpo.flags", entry.GetSingleTextValue("flags"), FactValueKind.Integer, endpoint, entry.DistinguishedName, observedAt);
        AddFact(facts, gpo.Id, "gpo.whenCreated", entry.GetSingleTextValue("whenCreated"), FactValueKind.Timestamp, endpoint, entry.DistinguishedName, observedAt);
        AddFact(facts, gpo.Id, "gpo.whenChanged", entry.GetSingleTextValue("whenChanged"), FactValueKind.Timestamp, endpoint, entry.DistinguishedName, observedAt);
    }

    private static void AddFact(
        ICollection<ObservedFact> facts,
        AdObjectId objectId,
        string path,
        string? value,
        FactValueKind valueKind,
        string endpoint,
        string locator,
        DateTimeOffset observedAt)
    {
        if (value is null)
        {
            return;
        }

        var subjectId = $"ad-object:{objectId}";
        facts.Add(new ObservedFact
        {
            FactId = FactIdFactory.Create(
                CollectionCapabilities.GroupPolicyMetadata,
                subjectId,
                path,
                valueKind,
                value),
            CapabilityId = CollectionCapabilities.GroupPolicyMetadata,
            SubjectId = subjectId,
            Path = path,
            Value = value,
            ValueKind = valueKind,
            Source = new ObservationSource
            {
                CollectorId = CollectorId,
                CollectorVersion = CollectorVersion,
                SourceKind = "ldap",
                Endpoint = endpoint,
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
            CapabilityId = CollectionCapabilities.GroupPolicyMetadata,
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
                    CapabilityId = CollectionCapabilities.GroupPolicyMetadata,
                    ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                        CollectionCapabilities.GroupPolicyMetadata),
                    Status = CapabilityStatus.Failed,
                    StartedAt = startedAt,
                    CompletedAt = completedAt,
                    ObservedItemCount = 0,
                    Issues = [Issue(code, message, target)]
                }
            ]
        };
}
