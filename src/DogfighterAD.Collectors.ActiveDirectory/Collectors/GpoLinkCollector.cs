using System.Globalization;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Collectors.ActiveDirectory.Collectors;

/// <summary>
/// Collects Group Policy links from domain/OU gPLink attributes and container inheritance state
/// from gpOptions. This collector does not read SYSVOL or calculate Resultant Set of Policy.
/// </summary>
public sealed class GpoLinkCollector : ICollector
{
    public const string CollectorId = "ad.ldap.gpo-links";
    public const string CollectorVersion = "0.1.0";
    private const int DefaultPageSize = 1000;
    private const int LinkDisabled = 0x1;
    private const int LinkEnforced = 0x2;
    private const int KnownLinkOptionMask = LinkDisabled | LinkEnforced;

    private static readonly IReadOnlySet<string> ProvidedCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.GroupPolicyLinks
        };

    private static readonly IReadOnlySet<string> RequiredCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryCore,
            CollectionCapabilities.DirectoryDomains,
            CollectionCapabilities.DirectoryOrganizationalUnits,
            CollectionCapabilities.GroupPolicyMetadata
        };

    private readonly IReadOnlyLdapClientFactory _ldapClientFactory;
    private readonly TimeProvider _timeProvider;

    public GpoLinkCollector(
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
        if (string.IsNullOrWhiteSpace(baseDn))
        {
            var completedAt = _timeProvider.GetUtcNow();
            return new CollectorResult(
                CollectorId,
                CollectorVersion,
                FailureFragment(
                    context.Target,
                    "collection.gpo.links.default-naming-context-unavailable",
                    "GPO link collection requires RootDSE defaultNamingContext.",
                    startedAt,
                    completedAt));
        }

        var containersById = context.AvailableData.Content.Domains
            .Cast<AdDirectoryObject>()
            .Concat(context.AvailableData.Content.OrganizationalUnits)
            .ToDictionary(item => item.Id);
        var expectedContainerIds = containersById.Keys.ToHashSet();
        var gposByDn = context.AvailableData.Content.GroupPolicyObjects
            .ToDictionary(item => item.DistinguishedName, item => item.Id, StringComparer.OrdinalIgnoreCase);

        var seenContainers = new HashSet<AdObjectId>();
        var links = new List<AdGpoLink>();
        var containerPolicies = new List<AdGpoContainerPolicy>();
        var observations = new List<ObservedFact>();
        var issues = new List<CollectionIssue>();

        await using var client = await _ldapClientFactory
            .CreateAsync(context.Target, cancellationToken)
            .ConfigureAwait(false);

        var request = new LdapSearchRequest
        {
            BaseDn = baseDn,
            Filter = BuildFilter(context.AvailableData.Content.Domains.Single().Id.Value),
            Scope = LdapSearchScope.Subtree,
            Attributes = ["objectGUID", "gPLink", "gPOptions"],
            PageSize = DefaultPageSize
        };

        await foreach (var entry in client.SearchEntriesAsync(request, cancellationToken))
        {
            var objectGuid = LdapValueConverters.GetGuid(entry, "objectGUID");
            if (!objectGuid.HasValue)
            {
                issues.Add(Issue(
                    "collection.gpo.links.container-guid-missing",
                    $"GPO scope container '{entry.DistinguishedName}' has no usable objectGUID.",
                    context.Target));
                continue;
            }

            var containerId = new AdObjectId(objectGuid.Value);
            if (!containersById.ContainsKey(containerId))
            {
                issues.Add(Issue(
                    "collection.gpo.links.unknown-container",
                    $"GPO scope container '{entry.DistinguishedName}' ({containerId}) is absent from prerequisite domain/OU data.",
                    context.Target));
                continue;
            }

            if (!seenContainers.Add(containerId))
            {
                issues.Add(Issue(
                    "collection.gpo.links.duplicate-container",
                    $"GPO scope container '{entry.DistinguishedName}' ({containerId}) was returned more than once.",
                    context.Target));
                continue;
            }

            var rawGpOptions = 0;
            var gpOptionsText = entry.GetSingleTextValue("gPOptions");
            if (gpOptionsText is not null &&
                (!int.TryParse(gpOptionsText, NumberStyles.Integer, CultureInfo.InvariantCulture, out rawGpOptions) || rawGpOptions < 0))
            {
                issues.Add(Issue(
                    "collection.gpo.links.gp-options-invalid",
                    $"Container '{entry.DistinguishedName}' has invalid gPOptions value '{gpOptionsText}'.",
                    context.Target));
                continue;
            }

            if ((rawGpOptions & ~1) != 0)
            {
                issues.Add(Issue(
                    "collection.gpo.links.gp-options-unsupported",
                    $"Container '{entry.DistinguishedName}' has unsupported gPOptions bits 0x{rawGpOptions:X}.",
                    context.Target));
            }

            containerPolicies.Add(new AdGpoContainerPolicy(
                containerId,
                rawGpOptions,
                (rawGpOptions & 1) != 0));

            if (gpOptionsText is not null)
            {
                AddFact(
                    observations,
                    containerId,
                    "gpo.container.gpOptions",
                    gpOptionsText,
                    FactValueKind.Integer,
                    context.Target,
                    entry.DistinguishedName,
                    _timeProvider.GetUtcNow());
            }

            var gPLink = entry.GetSingleTextValue("gPLink");
            if (string.IsNullOrEmpty(gPLink))
            {
                continue;
            }

            var parsed = ParseLinks(gPLink);
            if (!parsed.Success)
            {
                issues.Add(Issue(
                    "collection.gpo.links.syntax-invalid",
                    $"Container '{entry.DistinguishedName}' has invalid gPLink syntax: {parsed.Error}",
                    context.Target));
                continue;
            }

            foreach (var parsedLink in parsed.Links)
            {
                if ((parsedLink.Options & ~KnownLinkOptionMask) != 0)
                {
                    issues.Add(Issue(
                        "collection.gpo.links.options-unsupported",
                        $"Container '{entry.DistinguishedName}' has GPO link options 0x{parsedLink.Options:X} with unsupported bits.",
                        context.Target));
                }

                if (!gposByDn.TryGetValue(parsedLink.GpoDistinguishedName, out var gpoId))
                {
                    issues.Add(Issue(
                        "collection.gpo.links.gpo-unresolved",
                        $"Container '{entry.DistinguishedName}' links unknown GPO '{parsedLink.GpoDistinguishedName}'.",
                        context.Target));
                    continue;
                }

                links.Add(new AdGpoLink(
                    containerId,
                    gpoId,
                    parsedLink.Order,
                    Enabled: (parsedLink.Options & LinkDisabled) == 0,
                    Enforced: (parsedLink.Options & LinkEnforced) != 0)
                {
                    RawOptions = parsedLink.Options
                });

                var observedAt = _timeProvider.GetUtcNow();
                AddFact(
                    observations,
                    containerId,
                    $"gpo.link.{parsedLink.Order}.targetDn",
                    parsedLink.GpoDistinguishedName,
                    FactValueKind.DistinguishedName,
                    context.Target,
                    entry.DistinguishedName,
                    observedAt);
                AddFact(
                    observations,
                    containerId,
                    $"gpo.link.{parsedLink.Order}.options",
                    parsedLink.Options.ToString(CultureInfo.InvariantCulture),
                    FactValueKind.Integer,
                    context.Target,
                    entry.DistinguishedName,
                    observedAt);
            }
        }

        foreach (var missing in expectedContainerIds.Except(seenContainers).OrderBy(id => id.Value))
        {
            issues.Add(Issue(
                "collection.gpo.links.container-not-returned",
                $"Expected domain/OU container {missing} was not returned by GPO link enumeration.",
                context.Target));
        }

        var completed = _timeProvider.GetUtcNow();
        var orderedLinks = links
            .OrderBy(item => item.ContainerId.Value)
            .ThenBy(item => item.Order)
            .ThenBy(item => item.GpoId.Value)
            .ToArray();

        return new CollectorResult(
            CollectorId,
            CollectorVersion,
            new SnapshotFragment
            {
                Content = new SnapshotContent
                {
                    GroupPolicyLinks = orderedLinks,
                    GroupPolicyContainerPolicies = containerPolicies
                        .OrderBy(item => item.ContainerId.Value)
                        .ToArray()
                },
                Coverage =
                [
                    new CapabilityCoverage
                    {
                        CapabilityId = CollectionCapabilities.GroupPolicyLinks,
                        ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                            CollectionCapabilities.GroupPolicyLinks),
                        Status = issues.Count == 0
                            ? CapabilityStatus.Complete
                            : CapabilityStatus.Partial,
                        StartedAt = startedAt,
                        CompletedAt = completed,
                        ObservedItemCount = orderedLinks.Length,
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

    internal static string BuildFilter(Guid domainObjectGuid) =>
        "(|" +
        $"(objectGUID={LdapFilterEncoding.EncodeOctetString(domainObjectGuid.ToByteArray())})" +
        "(objectClass=organizationalUnit)" +
        ")";

    internal static GpoLinkParseResult ParseLinks(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var links = new List<ParsedGpoLink>();
        var offset = 0;
        var order = 1;

        while (offset < value.Length)
        {
            if (value[offset] != '[')
            {
                return GpoLinkParseResult.Failed($"Expected '[' at offset {offset}.");
            }

            var close = value.IndexOf(']', offset + 1);
            if (close < 0)
            {
                return GpoLinkParseResult.Failed($"Missing closing ']' for link beginning at offset {offset}.");
            }

            var segment = value[(offset + 1)..close];
            const string prefix = "LDAP://";
            if (!segment.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return GpoLinkParseResult.Failed($"Link {order} does not begin with LDAP://.");
            }

            var separator = segment.LastIndexOf(';');
            if (separator <= prefix.Length || separator == segment.Length - 1)
            {
                return GpoLinkParseResult.Failed($"Link {order} has no valid ';options' suffix.");
            }

            var targetDn = segment[prefix.Length..separator];
            var optionsText = segment[(separator + 1)..];
            if (string.IsNullOrWhiteSpace(targetDn) ||
                !int.TryParse(optionsText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var options) ||
                options < 0)
            {
                return GpoLinkParseResult.Failed($"Link {order} contains an invalid target DN or options value.");
            }

            links.Add(new ParsedGpoLink(order, targetDn, options));
            order++;
            offset = close + 1;
        }

        return GpoLinkParseResult.Succeeded(links);
    }

    private static void AddFact(
        ICollection<ObservedFact> facts,
        AdObjectId subjectObjectId,
        string path,
        string value,
        FactValueKind valueKind,
        string endpoint,
        string locator,
        DateTimeOffset observedAt)
    {
        var subjectId = $"ad-object:{subjectObjectId}";
        facts.Add(new ObservedFact
        {
            FactId = FactIdFactory.Create(
                CollectionCapabilities.GroupPolicyLinks,
                subjectId,
                path,
                valueKind,
                value),
            CapabilityId = CollectionCapabilities.GroupPolicyLinks,
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
            CapabilityId = CollectionCapabilities.GroupPolicyLinks,
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
                    CapabilityId = CollectionCapabilities.GroupPolicyLinks,
                    ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                        CollectionCapabilities.GroupPolicyLinks),
                    Status = CapabilityStatus.Failed,
                    StartedAt = startedAt,
                    CompletedAt = completedAt,
                    Issues = [Issue(code, message, target)]
                }
            ]
        };

    internal sealed record ParsedGpoLink(
        int Order,
        string GpoDistinguishedName,
        int Options);

    internal sealed record GpoLinkParseResult(
        bool Success,
        IReadOnlyList<ParsedGpoLink> Links,
        string? Error)
    {
        public static GpoLinkParseResult Succeeded(IReadOnlyList<ParsedGpoLink> links) =>
            new(true, links, null);

        public static GpoLinkParseResult Failed(string error) =>
            new(false, [], error);
    }
}
