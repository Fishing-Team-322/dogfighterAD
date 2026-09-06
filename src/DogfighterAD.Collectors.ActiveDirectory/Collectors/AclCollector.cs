using System.Globalization;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Collectors.ActiveDirectory.Collectors;

/// <summary>
/// Collects DACLs for the normalized default-domain objects already present in the snapshot.
/// The collector requests only the DACL section of nTSecurityDescriptor and never requests SACL data.
/// </summary>
public sealed class AclCollector : ICollector
{
    public const string CollectorId = "ad.ldap.acls";
    public const string CollectorVersion = "0.1.0";
    private const int DefaultPageSize = 500;

    private static readonly IReadOnlySet<string> ProvidedCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryAcls
        };

    private static readonly IReadOnlySet<string> RequiredCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryCore,
            CollectionCapabilities.DirectoryDomains,
            CollectionCapabilities.DirectoryUsers,
            CollectionCapabilities.DirectoryGroups,
            CollectionCapabilities.DirectoryComputers,
            CollectionCapabilities.DirectoryOrganizationalUnits
        };

    private readonly IReadOnlyLdapClientFactory _ldapClientFactory;
    private readonly SecurityDescriptorDaclParser _parser;
    private readonly TimeProvider _timeProvider;

    public AclCollector(
        IReadOnlyLdapClientFactory ldapClientFactory,
        TimeProvider? timeProvider = null)
    {
        _ldapClientFactory = ldapClientFactory ?? throw new ArgumentNullException(nameof(ldapClientFactory));
        _parser = new SecurityDescriptorDaclParser();
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
            var failureCompletedAt = _timeProvider.GetUtcNow();
            return new CollectorResult(
                CollectorId,
                CollectorVersion,
                FailureFragment(
                    context.Target,
                    "collection.acls.default-naming-context-unavailable",
                    "ACL collection requires RootDSE defaultNamingContext.",
                    startedAt,
                    failureCompletedAt));
        }

        var expectedTargets = BuildExpectedTargets(context.AvailableData.Content);
        var seenTargets = new HashSet<AdObjectId>();
        var descriptors = new List<AdSecurityDescriptor>();
        var aces = new List<AdAce>();
        var issues = new List<CollectionIssue>();
        var observations = new List<ObservedFact>();

        await using var client = await _ldapClientFactory
            .CreateAsync(context.Target, cancellationToken)
            .ConfigureAwait(false);

        var request = new LdapSearchRequest
        {
            BaseDn = baseDn,
            Filter = BuildFilter(context.AvailableData.Content.Domains.Single().Id.Value),
            Scope = LdapSearchScope.Subtree,
            Attributes = ["objectGUID", "nTSecurityDescriptor"],
            PageSize = DefaultPageSize,
            SecurityDescriptorSections = LdapSecurityDescriptorSections.Dacl
        };

        await foreach (var entry in client.SearchEntriesAsync(request, cancellationToken))
        {
            var objectGuid = LdapValueConverters.GetGuid(entry, "objectGUID");
            if (!objectGuid.HasValue)
            {
                issues.Add(Issue(
                    "collection.acls.object-guid-missing",
                    $"ACL search entry '{entry.DistinguishedName}' has no usable objectGUID.",
                    context.Target));
                continue;
            }

            var targetId = new AdObjectId(objectGuid.Value);
            if (!expectedTargets.ContainsKey(targetId))
            {
                issues.Add(Issue(
                    "collection.acls.unexpected-target",
                    $"ACL search returned object '{entry.DistinguishedName}' ({targetId}) that was not present in prerequisite snapshot data.",
                    context.Target));
                continue;
            }

            if (!seenTargets.Add(targetId))
            {
                issues.Add(Issue(
                    "collection.acls.duplicate-target",
                    $"ACL search returned target '{entry.DistinguishedName}' ({targetId}) more than once.",
                    context.Target));
                continue;
            }

            var descriptorValues = entry.GetBinaryValues("nTSecurityDescriptor");
            if (descriptorValues.Count != 1)
            {
                issues.Add(Issue(
                    "collection.acls.security-descriptor-unavailable",
                    $"Object '{entry.DistinguishedName}' returned {descriptorValues.Count} nTSecurityDescriptor values; exactly one DACL descriptor was expected.",
                    context.Target));
                continue;
            }

            var parsed = _parser.Parse(descriptorValues[0]);
            if (parsed.DescriptorStateReliable)
            {
                descriptors.Add(new AdSecurityDescriptor
                {
                    TargetObjectId = targetId,
                    DaclState = parsed.State,
                    ControlFlags = parsed.ControlFlags
                });

                AddDescriptorFacts(
                    observations,
                    targetId,
                    parsed,
                    context.Target,
                    entry.DistinguishedName,
                    _timeProvider.GetUtcNow());
            }

            for (var aceIndex = 0; aceIndex < parsed.Aces.Count; aceIndex++)
            {
                var parsedAce = parsed.Aces[aceIndex];
                var ace = new AdAce
                {
                    TargetObjectId = targetId,
                    TrusteeSid = parsedAce.TrusteeSid,
                    AccessType = parsedAce.AccessType,
                    AccessMask = parsedAce.AccessMask,
                    AceFlags = parsedAce.AceFlags,
                    ObjectType = parsedAce.ObjectType,
                    InheritedObjectType = parsedAce.InheritedObjectType,
                    IsInherited = parsedAce.IsInherited
                };

                aces.Add(ace);
                AddAceFacts(
                    observations,
                    targetId,
                    aceIndex,
                    ace,
                    context.Target,
                    entry.DistinguishedName,
                    _timeProvider.GetUtcNow());
            }

            if (!parsed.Complete)
            {
                issues.Add(Issue(
                    "collection.acls.security-descriptor-partial",
                    $"DACL for '{entry.DistinguishedName}' could not be fully normalized: {parsed.Error}",
                    context.Target));
            }
        }

        AddMissingTargetIssue(expectedTargets, seenTargets, issues, context.Target);

        var completedAt = _timeProvider.GetUtcNow();
        var orderedDescriptors = descriptors
            .OrderBy(item => item.TargetObjectId.Value)
            .ToArray();
        var orderedAces = aces
            .Distinct()
            .OrderBy(item => item.TargetObjectId.Value)
            .ThenBy(item => item.TrusteeSid, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.AccessType)
            .ThenBy(item => item.AccessMask)
            .ThenBy(item => item.ObjectType)
            .ThenBy(item => item.InheritedObjectType)
            .ThenBy(item => item.AceFlags)
            .ToArray();

        return new CollectorResult(
            CollectorId,
            CollectorVersion,
            new SnapshotFragment
            {
                Content = new SnapshotContent
                {
                    SecurityDescriptors = orderedDescriptors,
                    Aces = orderedAces
                },
                Coverage =
                [
                    new CapabilityCoverage
                    {
                        CapabilityId = CollectionCapabilities.DirectoryAcls,
                        ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                            CollectionCapabilities.DirectoryAcls),
                        Status = issues.Count == 0
                            ? CapabilityStatus.Complete
                            : CapabilityStatus.Partial,
                        StartedAt = startedAt,
                        CompletedAt = completedAt,
                        ObservedItemCount = orderedDescriptors.Length,
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

    private static IReadOnlyDictionary<AdObjectId, string> BuildExpectedTargets(SnapshotContent content)
    {
        return content.Domains.Cast<AdDirectoryObject>()
            .Concat(content.Users)
            .Concat(content.Groups)
            .Concat(content.Computers)
            .Concat(content.OrganizationalUnits)
            .ToDictionary(item => item.Id, item => item.DistinguishedName);
    }

    internal static string BuildFilter(Guid domainObjectGuid) =>
        "(|" +
        $"(objectGUID={LdapFilterEncoding.EncodeOctetString(domainObjectGuid.ToByteArray())})" +
        "(&(objectCategory=person)(objectClass=user))" +
        "(objectCategory=group)" +
        "(objectCategory=computer)" +
        "(objectClass=organizationalUnit)" +
        ")";

    private static void AddMissingTargetIssue(
        IReadOnlyDictionary<AdObjectId, string> expectedTargets,
        ISet<AdObjectId> seenTargets,
        ICollection<CollectionIssue> issues,
        string target)
    {
        var missing = expectedTargets
            .Where(pair => !seenTargets.Contains(pair.Key))
            .OrderBy(pair => pair.Value, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (missing.Length == 0)
        {
            return;
        }

        var sample = string.Join(
            ", ",
            missing.Take(10).Select(pair => $"'{pair.Value}'"));
        var suffix = missing.Length > 10 ? ", ..." : string.Empty;

        issues.Add(Issue(
            "collection.acls.targets-missing",
            $"ACL enumeration did not return {missing.Length} expected snapshot object(s). Sample: {sample}{suffix}",
            target));
    }

    private static void AddDescriptorFacts(
        ICollection<ObservedFact> facts,
        AdObjectId targetId,
        ParsedDacl parsed,
        string endpoint,
        string locator,
        DateTimeOffset observedAt)
    {
        AddFact(facts, targetId, "securityDescriptor.daclState", parsed.State.ToString(), FactValueKind.Text, endpoint, locator, observedAt);
        AddFact(
            facts,
            targetId,
            "securityDescriptor.controlFlags",
            parsed.ControlFlags.ToString(CultureInfo.InvariantCulture),
            FactValueKind.Integer,
            endpoint,
            locator,
            observedAt);
    }

    private static void AddAceFacts(
        ICollection<ObservedFact> facts,
        AdObjectId targetId,
        int aceIndex,
        AdAce ace,
        string endpoint,
        string locator,
        DateTimeOffset observedAt)
    {
        var prefix = $"securityDescriptor.dacl.ace[{aceIndex}]";
        AddFact(facts, targetId, $"{prefix}.trusteeSid", ace.TrusteeSid, FactValueKind.Sid, endpoint, locator, observedAt);
        AddFact(facts, targetId, $"{prefix}.accessType", ace.AccessType.ToString(), FactValueKind.Text, endpoint, locator, observedAt);
        AddFact(facts, targetId, $"{prefix}.accessMask", ace.AccessMask.ToString(CultureInfo.InvariantCulture), FactValueKind.Integer, endpoint, locator, observedAt);
        AddFact(facts, targetId, $"{prefix}.aceFlags", ace.AceFlags.ToString(CultureInfo.InvariantCulture), FactValueKind.Integer, endpoint, locator, observedAt);
        AddFact(facts, targetId, $"{prefix}.objectType", ace.ObjectType?.ToString("D"), FactValueKind.Guid, endpoint, locator, observedAt);
        AddFact(facts, targetId, $"{prefix}.inheritedObjectType", ace.InheritedObjectType?.ToString("D"), FactValueKind.Guid, endpoint, locator, observedAt);
        AddFact(facts, targetId, $"{prefix}.isInherited", ace.IsInherited.ToString(), FactValueKind.Boolean, endpoint, locator, observedAt);
    }

    private static void AddFact(
        ICollection<ObservedFact> facts,
        AdObjectId targetId,
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

        var subjectId = $"ad-object:{targetId}";
        facts.Add(new ObservedFact
        {
            FactId = FactIdFactory.Create(
                CollectionCapabilities.DirectoryAcls,
                subjectId,
                path,
                valueKind,
                value),
            CapabilityId = CollectionCapabilities.DirectoryAcls,
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
            CapabilityId = CollectionCapabilities.DirectoryAcls,
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
                    CapabilityId = CollectionCapabilities.DirectoryAcls,
                    ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                        CollectionCapabilities.DirectoryAcls),
                    Status = CapabilityStatus.Failed,
                    StartedAt = startedAt,
                    CompletedAt = completedAt,
                    ObservedItemCount = 0,
                    Issues = [Issue(code, message, target)]
                }
            ]
        };
}
