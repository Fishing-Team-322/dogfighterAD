using System.Globalization;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Collectors.ActiveDirectory.Collectors;

/// <summary>
/// Collects direct and primary-group membership relationships.
/// Direct group members are range-aware; supporting foreign/generic identities are materialized
/// only when they are not already owned by another directory-object capability.
/// </summary>
public sealed class GroupMembershipCollector : ICollector
{
    public const string CollectorId = "ad.ldap.group-memberships";
    public const string CollectorVersion = "0.1.0";
    private const int DefaultPageSize = 1000;

    private static readonly IReadOnlySet<string> ProvidedCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryMemberships
        };

    private static readonly IReadOnlySet<string> RequiredCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryCore,
            CollectionCapabilities.DirectoryUsers,
            CollectionCapabilities.DirectoryGroups,
            CollectionCapabilities.DirectoryComputers
        };

    private static readonly string[] SupportingPrincipalAttributes =
    [
        "objectClass",
        "objectGUID",
        "objectSid",
        "name",
        "primaryGroupID",
        "whenCreated",
        "whenChanged"
    ];

    private static readonly string[] ResolveObjectAttributes =
    [
        "objectClass",
        "objectGUID",
        "objectSid",
        "name",
        "primaryGroupID",
        "whenCreated",
        "whenChanged"
    ];

    private readonly IReadOnlyLdapClientFactory _ldapClientFactory;
    private readonly GroupMemberRangeReader _rangeReader;
    private readonly TimeProvider _timeProvider;

    public GroupMembershipCollector(
        IReadOnlyLdapClientFactory ldapClientFactory,
        TimeProvider? timeProvider = null)
    {
        _ldapClientFactory = ldapClientFactory ?? throw new ArgumentNullException(nameof(ldapClientFactory));
        _rangeReader = new GroupMemberRangeReader();
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
                    "collection.memberships.default-naming-context-unavailable",
                    "Membership collection requires RootDSE defaultNamingContext.",
                    startedAt,
                    completedAt));
        }

        var index = DirectoryObjectIndex.Create(context.AvailableData.Content);
        var memberships = new HashSet<AdGroupMembership>();
        var foreignSecurityPrincipals = new List<AdForeignSecurityPrincipal>();
        var otherDirectoryObjects = new List<AdGenericDirectoryObject>();
        var emittedSupportingIds = new HashSet<AdObjectId>();
        var issues = new List<CollectionIssue>();
        var observations = new List<ObservedFact>();
        var pendingDirectMemberships = new List<PendingDirectMembership>();
        var resolutionCache = new Dictionary<string, AdObjectId?>(StringComparer.OrdinalIgnoreCase);

        await using var client = await _ldapClientFactory
            .CreateAsync(context.Target, cancellationToken)
            .ConfigureAwait(false);

        await CollectSupportingPrincipalsAndPrimaryGroupsAsync(
            client,
            baseDn,
            context.Target,
            index,
            memberships,
            foreignSecurityPrincipals,
            otherDirectoryObjects,
            emittedSupportingIds,
            issues,
            observations,
            cancellationToken).ConfigureAwait(false);

        await CollectDirectMembershipDnsAsync(
            client,
            baseDn,
            context.Target,
            index,
            pendingDirectMemberships,
            issues,
            observations,
            cancellationToken).ConfigureAwait(false);

        foreach (var pending in pendingDirectMemberships
                     .OrderBy(item => item.GroupId.Value)
                     .ThenBy(item => item.MemberDistinguishedName, StringComparer.OrdinalIgnoreCase))
        {
            AdObjectId? resolvedMemberId;
            if (index.TryGetByDn(pending.MemberDistinguishedName, out var knownMemberId))
            {
                resolvedMemberId = knownMemberId;
            }
            else
            {
                resolvedMemberId = await ResolveUnknownMemberAsync(
                    client,
                    pending.MemberDistinguishedName,
                    context.Target,
                    index,
                    foreignSecurityPrincipals,
                    otherDirectoryObjects,
                    emittedSupportingIds,
                    memberships,
                    issues,
                    observations,
                    resolutionCache,
                    cancellationToken).ConfigureAwait(false);
            }

            if (!resolvedMemberId.HasValue)
            {
                issues.Add(Issue(
                    "collection.memberships.member-unresolved",
                    $"Could not resolve group member '{pending.MemberDistinguishedName}'.",
                    context.Target));
                continue;
            }

            memberships.Add(new AdGroupMembership(
                pending.GroupId,
                resolvedMemberId.Value,
                MembershipSource.Explicit));
        }

        var completed = _timeProvider.GetUtcNow();
        var orderedMemberships = memberships
            .OrderBy(item => item.GroupId.Value)
            .ThenBy(item => item.MemberId.Value)
            .ThenBy(item => item.Source)
            .ToArray();

        var fragment = new SnapshotFragment
        {
            Content = new SnapshotContent
            {
                ForeignSecurityPrincipals = foreignSecurityPrincipals
                    .OrderBy(item => item.Id.Value)
                    .ToArray(),
                OtherDirectoryObjects = otherDirectoryObjects
                    .OrderBy(item => item.Id.Value)
                    .ToArray(),
                GroupMemberships = orderedMemberships
            },
            Coverage =
            [
                new CapabilityCoverage
                {
                    CapabilityId = CollectionCapabilities.DirectoryMemberships,
                    ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                        CollectionCapabilities.DirectoryMemberships),
                    Status = issues.Count == 0
                        ? CapabilityStatus.Complete
                        : CapabilityStatus.Partial,
                    StartedAt = startedAt,
                    CompletedAt = completed,
                    ObservedItemCount = orderedMemberships.Length,
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
        };

        return new CollectorResult(CollectorId, CollectorVersion, fragment);
    }

    private async Task CollectSupportingPrincipalsAndPrimaryGroupsAsync(
        IReadOnlyLdapClient client,
        string baseDn,
        string target,
        DirectoryObjectIndex index,
        ISet<AdGroupMembership> memberships,
        ICollection<AdForeignSecurityPrincipal> foreignSecurityPrincipals,
        ICollection<AdGenericDirectoryObject> otherDirectoryObjects,
        ISet<AdObjectId> emittedSupportingIds,
        ICollection<CollectionIssue> issues,
        ICollection<ObservedFact> observations,
        CancellationToken cancellationToken)
    {
        var request = new LdapSearchRequest
        {
            BaseDn = baseDn,
            Filter = "(|(primaryGroupID=*)(objectClass=foreignSecurityPrincipal))",
            Scope = LdapSearchScope.Subtree,
            Attributes = SupportingPrincipalAttributes,
            PageSize = DefaultPageSize
        };

        await foreach (var entry in client.SearchEntriesAsync(request, cancellationToken))
        {
            var objectGuid = LdapValueConverters.GetGuid(entry, "objectGUID");
            if (objectGuid is null || string.IsNullOrWhiteSpace(entry.DistinguishedName))
            {
                issues.Add(Issue(
                    "collection.memberships.support-object-identity-unavailable",
                    $"Supporting membership object '{entry.DistinguishedName}' has no usable objectGUID or distinguished name.",
                    target));
                continue;
            }

            var id = new AdObjectId(objectGuid.Value);
            var sid = LdapValueConverters.GetSid(entry, "objectSid");
            EnsureSupportingIdentity(
                entry,
                id,
                sid,
                index,
                foreignSecurityPrincipals,
                otherDirectoryObjects,
                emittedSupportingIds,
                issues,
                observations,
                target,
                _timeProvider.GetUtcNow());

            var primaryGroupId = LdapValueConverters.GetInt32(entry, "primaryGroupID");
            if (primaryGroupId.HasValue)
            {
                AddIntegerObservation(
                    observations,
                    id,
                    "principal.primaryGroupId",
                    primaryGroupId.Value,
                    target,
                    entry.DistinguishedName,
                    _timeProvider.GetUtcNow());

                TryAddPrimaryGroupMembership(
                    id,
                    sid,
                    primaryGroupId.Value,
                    index,
                    memberships,
                    issues,
                    target,
                    entry.DistinguishedName);
            }
            else if (!entry.GetTextValues("objectClass")
                         .Contains("foreignSecurityPrincipal", StringComparer.OrdinalIgnoreCase))
            {
                issues.Add(Issue(
                    "collection.memberships.primary-group-id-invalid",
                    $"Principal '{entry.DistinguishedName}' matched primaryGroupID filter but the value could not be parsed.",
                    target));
            }
        }
    }

    private async Task CollectDirectMembershipDnsAsync(
        IReadOnlyLdapClient client,
        string baseDn,
        string target,
        DirectoryObjectIndex index,
        ICollection<PendingDirectMembership> pending,
        ICollection<CollectionIssue> issues,
        ICollection<ObservedFact> observations,
        CancellationToken cancellationToken)
    {
        var request = new LdapSearchRequest
        {
            BaseDn = baseDn,
            Filter = "(objectCategory=group)",
            Scope = LdapSearchScope.Subtree,
            Attributes = ["objectGUID", "member"],
            PageSize = DefaultPageSize
        };

        await foreach (var entry in client.SearchEntriesAsync(request, cancellationToken))
        {
            var objectGuid = LdapValueConverters.GetGuid(entry, "objectGUID");
            if (objectGuid is null)
            {
                issues.Add(Issue(
                    "collection.memberships.group-guid-missing",
                    $"Group '{entry.DistinguishedName}' has no valid objectGUID and its membership was skipped.",
                    target));
                continue;
            }

            var groupId = new AdObjectId(objectGuid.Value);
            if (!index.IsKnownGroup(groupId))
            {
                issues.Add(Issue(
                    "collection.memberships.group-not-in-snapshot",
                    $"Membership enumeration returned group '{entry.DistinguishedName}' ({groupId}) which is absent from directory.groups.",
                    target));
                continue;
            }

            var rangeResult = await _rangeReader
                .ReadAsync(client, entry, cancellationToken)
                .ConfigureAwait(false);

            if (!rangeResult.Complete)
            {
                issues.Add(Issue(
                    "collection.memberships.member-range-incomplete",
                    rangeResult.Error ?? $"Membership range for '{entry.DistinguishedName}' was incomplete.",
                    target));
            }

            foreach (var memberDn in rangeResult.Members)
            {
                pending.Add(new PendingDirectMembership(groupId, memberDn));
                AddFact(
                    observations,
                    groupId,
                    "group.member",
                    memberDn,
                    FactValueKind.DistinguishedName,
                    target,
                    entry.DistinguishedName,
                    _timeProvider.GetUtcNow());
            }
        }
    }

    private async Task<AdObjectId?> ResolveUnknownMemberAsync(
        IReadOnlyLdapClient client,
        string memberDn,
        string target,
        DirectoryObjectIndex index,
        ICollection<AdForeignSecurityPrincipal> foreignSecurityPrincipals,
        ICollection<AdGenericDirectoryObject> otherDirectoryObjects,
        ISet<AdObjectId> emittedSupportingIds,
        ISet<AdGroupMembership> memberships,
        ICollection<CollectionIssue> issues,
        ICollection<ObservedFact> observations,
        IDictionary<string, AdObjectId?> resolutionCache,
        CancellationToken cancellationToken)
    {
        if (resolutionCache.TryGetValue(memberDn, out var cached))
        {
            return cached;
        }

        var response = await client.SearchAsync(
            new LdapSearchRequest
            {
                BaseDn = memberDn,
                Filter = "(objectClass=*)",
                Scope = LdapSearchScope.Base,
                Attributes = ResolveObjectAttributes
            },
            cancellationToken).ConfigureAwait(false);

        if (response.Entries.Count != 1)
        {
            resolutionCache[memberDn] = null;
            return null;
        }

        var entry = response.Entries[0];
        var objectGuid = LdapValueConverters.GetGuid(entry, "objectGUID");
        if (objectGuid is null || string.IsNullOrWhiteSpace(entry.DistinguishedName))
        {
            resolutionCache[memberDn] = null;
            return null;
        }

        var id = new AdObjectId(objectGuid.Value);
        var sid = LdapValueConverters.GetSid(entry, "objectSid");
        EnsureSupportingIdentity(
            entry,
            id,
            sid,
            index,
            foreignSecurityPrincipals,
            otherDirectoryObjects,
            emittedSupportingIds,
            issues,
            observations,
            target,
            _timeProvider.GetUtcNow());

        var primaryGroupId = LdapValueConverters.GetInt32(entry, "primaryGroupID");
        if (primaryGroupId.HasValue)
        {
            AddIntegerObservation(
                observations,
                id,
                "principal.primaryGroupId",
                primaryGroupId.Value,
                target,
                entry.DistinguishedName,
                _timeProvider.GetUtcNow());
            TryAddPrimaryGroupMembership(
                id,
                sid,
                primaryGroupId.Value,
                index,
                memberships,
                issues,
                target,
                entry.DistinguishedName);
        }

        resolutionCache[memberDn] = id;
        return id;
    }

    private static void EnsureSupportingIdentity(
        LdapSearchEntry entry,
        AdObjectId id,
        string? sid,
        DirectoryObjectIndex index,
        ICollection<AdForeignSecurityPrincipal> foreignSecurityPrincipals,
        ICollection<AdGenericDirectoryObject> otherDirectoryObjects,
        ISet<AdObjectId> emittedSupportingIds,
        ICollection<CollectionIssue> issues,
        ICollection<ObservedFact> observations,
        string target,
        DateTimeOffset observedAt)
    {
        index.AddAlias(entry.DistinguishedName, id);

        if (index.ContainsId(id))
        {
            return;
        }

        var objectClasses = entry.GetTextValues("objectClass");
        var isForeignSecurityPrincipal = objectClasses
            .Contains("foreignSecurityPrincipal", StringComparer.OrdinalIgnoreCase);

        AdDirectoryObject supportingObject;
        if (isForeignSecurityPrincipal)
        {
            supportingObject = new AdForeignSecurityPrincipal
            {
                Id = id,
                DistinguishedName = entry.DistinguishedName,
                Sid = sid,
                Name = entry.GetSingleTextValue("name"),
                WhenCreated = LdapValueConverters.GetDateTimeOffset(entry, "whenCreated"),
                WhenChanged = LdapValueConverters.GetDateTimeOffset(entry, "whenChanged")
            };

            foreignSecurityPrincipals.Add((AdForeignSecurityPrincipal)supportingObject);

            if (sid is null)
            {
                issues.Add(Issue(
                    "collection.memberships.fsp-sid-missing",
                    $"Foreign security principal '{entry.DistinguishedName}' has no valid objectSid.",
                    target));
            }
        }
        else
        {
            supportingObject = new AdGenericDirectoryObject
            {
                Id = id,
                DistinguishedName = entry.DistinguishedName,
                Sid = sid,
                Name = entry.GetSingleTextValue("name"),
                WhenCreated = LdapValueConverters.GetDateTimeOffset(entry, "whenCreated"),
                WhenChanged = LdapValueConverters.GetDateTimeOffset(entry, "whenChanged"),
                ObjectClass = objectClasses.LastOrDefault() ?? "unknown"
            };

            otherDirectoryObjects.Add((AdGenericDirectoryObject)supportingObject);
        }

        index.AddObject(supportingObject);
        emittedSupportingIds.Add(id);
        AddSupportingObjectFacts(observations, supportingObject, target, observedAt);
    }

    private static void TryAddPrimaryGroupMembership(
        AdObjectId principalId,
        string? principalSid,
        int primaryGroupId,
        DirectoryObjectIndex index,
        ISet<AdGroupMembership> memberships,
        ICollection<CollectionIssue> issues,
        string target,
        string locator)
    {
        var groupSid = BuildPrimaryGroupSid(principalSid, primaryGroupId);
        if (groupSid is null)
        {
            issues.Add(Issue(
                "collection.memberships.primary-group-sid-invalid",
                $"Principal '{locator}' does not have a usable SID for primary group {primaryGroupId}.",
                target));
            return;
        }

        if (!index.TryGetGroupBySid(groupSid, out var groupId))
        {
            issues.Add(Issue(
                "collection.memberships.primary-group-unresolved",
                $"Primary group SID '{groupSid}' for principal '{locator}' is absent from directory.groups.",
                target));
            return;
        }

        memberships.Add(new AdGroupMembership(
            groupId,
            principalId,
            MembershipSource.PrimaryGroup));
    }

    private static string? BuildPrimaryGroupSid(string? principalSid, int primaryGroupId)
    {
        if (string.IsNullOrWhiteSpace(principalSid) || primaryGroupId < 0)
        {
            return null;
        }

        var separator = principalSid.LastIndexOf('-');
        if (separator <= 1 || separator == principalSid.Length - 1)
        {
            return null;
        }

        return string.Concat(
            principalSid.AsSpan(0, separator + 1),
            primaryGroupId.ToString(CultureInfo.InvariantCulture));
    }

    private static void AddSupportingObjectFacts(
        ICollection<ObservedFact> observations,
        AdDirectoryObject item,
        string target,
        DateTimeOffset observedAt)
    {
        AddFact(observations, item.Id, "support.distinguishedName", item.DistinguishedName, FactValueKind.DistinguishedName, target, item.DistinguishedName, observedAt);
        AddFact(observations, item.Id, "support.objectGuid", item.Id.ToString(), FactValueKind.Guid, target, item.DistinguishedName, observedAt);
        AddFact(observations, item.Id, "support.objectSid", item.Sid, FactValueKind.Sid, target, item.DistinguishedName, observedAt);

        if (item is AdGenericDirectoryObject generic)
        {
            AddFact(observations, item.Id, "support.objectClass", generic.ObjectClass, FactValueKind.Text, target, item.DistinguishedName, observedAt);
        }
        else if (item is AdForeignSecurityPrincipal)
        {
            AddFact(observations, item.Id, "support.objectClass", "foreignSecurityPrincipal", FactValueKind.Text, target, item.DistinguishedName, observedAt);
        }
    }

    private static void AddIntegerObservation(
        ICollection<ObservedFact> observations,
        AdObjectId subjectId,
        string path,
        int value,
        string target,
        string locator,
        DateTimeOffset observedAt) =>
        AddFact(
            observations,
            subjectId,
            path,
            value.ToString(CultureInfo.InvariantCulture),
            FactValueKind.Integer,
            target,
            locator,
            observedAt);

    private static void AddFact(
        ICollection<ObservedFact> observations,
        AdObjectId subjectId,
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

        var stableSubjectId = $"ad-object:{subjectId}";
        observations.Add(new ObservedFact
        {
            FactId = FactIdFactory.Create(
                CollectionCapabilities.DirectoryMemberships,
                stableSubjectId,
                path,
                valueKind,
                value),
            CapabilityId = CollectionCapabilities.DirectoryMemberships,
            SubjectId = stableSubjectId,
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
            CapabilityId = CollectionCapabilities.DirectoryMemberships,
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
                    CapabilityId = CollectionCapabilities.DirectoryMemberships,
                    ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                        CollectionCapabilities.DirectoryMemberships),
                    Status = CapabilityStatus.Failed,
                    StartedAt = startedAt,
                    CompletedAt = completedAt,
                    Issues = [Issue(code, message, target)]
                }
            ]
        };

    private sealed record PendingDirectMembership(
        AdObjectId GroupId,
        string MemberDistinguishedName);

    private sealed class DirectoryObjectIndex
    {
        private readonly Dictionary<string, AdObjectId> _byDn =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<AdObjectId> _byId = [];
        private readonly HashSet<AdObjectId> _groupIds = [];
        private readonly Dictionary<string, AdObjectId> _groupsBySid =
            new(StringComparer.OrdinalIgnoreCase);

        public static DirectoryObjectIndex Create(SnapshotContent content)
        {
            var index = new DirectoryObjectIndex();

            foreach (var item in EnumerateObjects(content))
            {
                index.AddObject(item);
            }

            foreach (var group in content.Groups)
            {
                index._groupIds.Add(group.Id);
                if (!string.IsNullOrWhiteSpace(group.Sid))
                {
                    index._groupsBySid[group.Sid] = group.Id;
                }
            }

            return index;
        }

        public bool ContainsId(AdObjectId id) => _byId.Contains(id);

        public bool IsKnownGroup(AdObjectId id) => _groupIds.Contains(id);

        public bool TryGetByDn(string distinguishedName, out AdObjectId id) =>
            _byDn.TryGetValue(distinguishedName, out id);

        public bool TryGetGroupBySid(string sid, out AdObjectId id) =>
            _groupsBySid.TryGetValue(sid, out id);

        public void AddAlias(string distinguishedName, AdObjectId id)
        {
            if (!string.IsNullOrWhiteSpace(distinguishedName))
            {
                _byDn[distinguishedName] = id;
            }
        }

        public void AddObject(AdDirectoryObject item)
        {
            _byId.Add(item.Id);
            AddAlias(item.DistinguishedName, item.Id);
        }

        private static IEnumerable<AdDirectoryObject> EnumerateObjects(SnapshotContent content) =>
            content.Domains.Cast<AdDirectoryObject>()
                .Concat(content.Users)
                .Concat(content.Groups)
                .Concat(content.Computers)
                .Concat(content.OrganizationalUnits)
                .Concat(content.GroupPolicyObjects)
                .Concat(content.ForeignSecurityPrincipals)
                .Concat(content.OtherDirectoryObjects);
    }
}
