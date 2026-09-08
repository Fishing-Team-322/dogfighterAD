using System.Globalization;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Collectors.ActiveDirectory.Collectors;

/// <summary>
/// Collects the high-volume, domain-naming-context directory objects in one paged subtree pass.
/// One collector owns users, groups, computers and OUs so enabling several of those capabilities
/// does not multiply whole-domain LDAP enumeration work.
/// </summary>
public sealed class DirectoryObjectsCollector : ICollector
{
    public const string CollectorId = "ad.ldap.directory-objects";
    public const string CollectorVersion = "0.2.0";
    private const int DefaultPageSize = 1000;

    private static readonly IReadOnlySet<string> ProvidedCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryUsers,
            CollectionCapabilities.DirectoryGroups,
            CollectionCapabilities.DirectoryComputers,
            CollectionCapabilities.DirectoryOrganizationalUnits
        };

    private static readonly IReadOnlySet<string> RequiredCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryCore
        };

    private static readonly string[] CommonAttributes =
    [
        "objectClass",
        "objectGUID",
        "objectSid",
        "name",
        "whenCreated",
        "whenChanged"
    ];

    private static readonly string[] UserAttributes =
    [
        "sAMAccountName",
        "userPrincipalName",
        "userAccountControl",
        "adminCount",
        "primaryGroupID",
        "pwdLastSet",
        "lastLogonTimestamp",
        "accountExpires",
        "msDS-SupportedEncryptionTypes",
        "servicePrincipalName",
        "sIDHistory",
        "msDS-AllowedToDelegateTo"
    ];

    private static readonly string[] GroupAttributes =
    [
        "sAMAccountName",
        "groupType",
        "adminCount"
    ];

    private static readonly string[] ComputerAttributes =
    [
        "sAMAccountName",
        "dNSHostName",
        "operatingSystem",
        "operatingSystemVersion",
        "userAccountControl",
        "pwdLastSet",
        "lastLogonTimestamp",
        "msDS-SupportedEncryptionTypes",
        "servicePrincipalName",
        "msDS-AllowedToDelegateTo"
    ];

    private readonly IReadOnlyLdapClientFactory _ldapClientFactory;
    private readonly TimeProvider _timeProvider;

    public DirectoryObjectsCollector(
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

        var selectedCapabilities = ProvidedCapabilities
            .Where(context.RequestedCapabilities.Contains)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();

        if (selectedCapabilities.Length == 0)
        {
            throw new InvalidOperationException(
                "DirectoryObjectsCollector was invoked without any of its capabilities being requested.");
        }

        var startedAt = _timeProvider.GetUtcNow();
        var baseDn = context.AvailableData.Content.DirectoryEnvironment?.DefaultNamingContext;
        if (string.IsNullOrWhiteSpace(baseDn))
        {
            var completedAt = _timeProvider.GetUtcNow();
            return new CollectorResult(
                CollectorId,
                CollectorVersion,
                CreateFailureFragment(
                    selectedCapabilities,
                    "collection.directory.default-naming-context-unavailable",
                    "Directory object collection requires RootDSE defaultNamingContext.",
                    context.Target,
                    startedAt,
                    completedAt));
        }

        var state = selectedCapabilities.ToDictionary(
            capability => capability,
            capability => new CapabilityCollectionState(capability),
            StringComparer.Ordinal);

        var users = new List<AdUser>();
        var groups = new List<AdGroup>();
        var computers = new List<AdComputer>();
        var organizationalUnits = new List<AdOrganizationalUnit>();
        var observations = new List<ObservedFact>();

        var request = new LdapSearchRequest
        {
            BaseDn = baseDn,
            Filter = BuildFilter(selectedCapabilities),
            Scope = LdapSearchScope.Subtree,
            Attributes = BuildAttributes(selectedCapabilities).Append("nTSecurityDescriptor").ToArray(),
            SecurityDescriptorSections = LdapSecurityDescriptorSections.Dacl,
            PageSize = DefaultPageSize
        };

        await using var client = await _ldapClientFactory
            .CreateAsync(context.Target, cancellationToken)
            .ConfigureAwait(false);

        var absenceProof = await LdapAttributeAbsenceProof.CreateAsync(client,
            context.AvailableData.Content.DirectoryEnvironment?.SchemaNamingContext, cancellationToken).ConfigureAwait(false);

        await foreach (var entry in client.SearchEntriesAsync(request, cancellationToken))
        {
            var capability = ClassifyCapability(entry);
            if (capability is null || !state.TryGetValue(capability, out var capabilityState))
            {
                MarkAllPartial(
                    state.Values,
                    "collection.directory.unclassified-entry",
                    $"LDAP returned an entry that could not be classified for the requested object capabilities: '{entry.DistinguishedName}'.",
                    context.Target);
                continue;
            }

            var objectGuid = LdapValueConverters.GetGuid(entry, "objectGUID");
            if (objectGuid is null || string.IsNullOrWhiteSpace(entry.DistinguishedName))
            {
                capabilityState.AddIssue(CreateIssue(
                    capability,
                    "collection.directory.identity-unavailable",
                    $"Directory entry '{entry.DistinguishedName}' has no usable objectGUID or distinguished name and was skipped.",
                    context.Target));
                continue;
            }

            switch (capability)
            {
                case CollectionCapabilities.DirectoryUsers:
                {
                    var user = MapUser(entry, objectGuid.Value, capabilityState, context.Target);
                    users.Add(user);
                    AddUserFacts(observations, entry, user, context.Target, _timeProvider.GetUtcNow());
                    AddAbsenceFacts(observations, entry, absenceProof, CollectionCapabilities.DirectoryUsers, user, "user", context.Target, _timeProvider.GetUtcNow());
                    capabilityState.ObserveItem();
                    break;
                }
                case CollectionCapabilities.DirectoryGroups:
                {
                    var group = MapGroup(entry, objectGuid.Value, capabilityState, context.Target);
                    groups.Add(group);
                    AddGroupFacts(observations, entry, group, context.Target, _timeProvider.GetUtcNow());
                    capabilityState.ObserveItem();
                    break;
                }
                case CollectionCapabilities.DirectoryComputers:
                {
                    var computer = MapComputer(entry, objectGuid.Value, capabilityState, context.Target);
                    computers.Add(computer);
                    AddComputerFacts(observations, entry, computer, context.Target, _timeProvider.GetUtcNow());
                    AddAbsenceFacts(observations, entry, absenceProof, CollectionCapabilities.DirectoryComputers, computer, "computer", context.Target, _timeProvider.GetUtcNow());
                    capabilityState.ObserveItem();
                    break;
                }
                case CollectionCapabilities.DirectoryOrganizationalUnits:
                {
                    var organizationalUnit = MapOrganizationalUnit(entry, objectGuid.Value);
                    organizationalUnits.Add(organizationalUnit);
                    AddCommonFacts(
                        observations,
                        capability,
                        entry,
                        organizationalUnit,
                        context.Target,
                        _timeProvider.GetUtcNow());
                    capabilityState.ObserveItem();
                    break;
                }
            }
        }

        var completed = _timeProvider.GetUtcNow();
        var fragment = new SnapshotFragment
        {
            Content = new SnapshotContent
            {
                Users = users,
                Groups = groups,
                Computers = computers,
                OrganizationalUnits = organizationalUnits
            },
            Coverage = state.Values
                .OrderBy(item => item.CapabilityId, StringComparer.Ordinal)
                .Select(item => item.ToCoverage(startedAt, completed))
                .ToArray(),
            Observations = observations
                .OrderBy(fact => fact.FactId, StringComparer.Ordinal)
                .ToArray()
        };

        return new CollectorResult(CollectorId, CollectorVersion, fragment);
    }

    private static void AddAbsenceFacts(ICollection<ObservedFact> facts, LdapSearchEntry entry,
        LdapAttributeAbsenceProof proof, string capability, AdDirectoryObject subject, string prefix,
        string target, DateTimeOffset at)
    {
        foreach (var (attribute, field) in new[]
        {
            ("servicePrincipalName", "servicePrincipalName"), ("sIDHistory", "sidHistory"),
            ("msDS-AllowedToDelegateTo", "allowedToDelegateTo"),
            ("msDS-SupportedEncryptionTypes", "supportedEncryptionTypes"), ("lastLogonTimestamp", "lastLogonTimestamp")
        })
        {
            if (prefix == "computer" && field == "sidHistory") continue; // Not requested for computers.
            var absent = proof.Confirm(entry, attribute);
            if (absent is not null) AbsenceFactWriter.Add(facts, absent, capability, $"ad-object:{subject.Id}",
                prefix + "." + field, CollectorId, CollectorVersion, target, entry.DistinguishedName, at);
        }
    }
    private static AdUser MapUser(
        LdapSearchEntry entry,
        Guid objectGuid,
        CapabilityCollectionState state,
        string target)
    {
        var sid = RequireSecurityPrincipalSid(entry, state, target);
        var userAccountControl = RequireInt64(
            entry,
            "userAccountControl",
            state,
            target,
            "collection.directory.user-uac-missing");
        var primaryGroupId = LdapValueConverters.GetInt32(entry, "primaryGroupID");
        if (primaryGroupId is null)
        {
            state.AddIssue(CreateIssue(
                state.CapabilityId,
                "collection.directory.user-primary-group-missing",
                $"User '{entry.DistinguishedName}' has no parseable primaryGroupID.",
                target));
        }

        var passwordLastSetRaw = LdapValueConverters.GetInt64(entry, "pwdLastSet");
        var accountExpiresRaw = LdapValueConverters.GetInt64(entry, "accountExpires");

        return new AdUser
        {
            Id = new AdObjectId(objectGuid),
            DistinguishedName = entry.DistinguishedName,
            Sid = sid,
            Name = entry.GetSingleTextValue("name"),
            WhenCreated = LdapValueConverters.GetDateTimeOffset(entry, "whenCreated"),
            WhenChanged = LdapValueConverters.GetDateTimeOffset(entry, "whenChanged"),
            SamAccountName = entry.GetSingleTextValue("sAMAccountName"),
            UserPrincipalName = entry.GetSingleTextValue("userPrincipalName"),
            UserAccountControl = userAccountControl ?? 0,
            AdminCount = LdapValueConverters.GetInt32(entry, "adminCount"),
            PrimaryGroupId = primaryGroupId,
            PasswordLastSet = LdapValueConverters.FileTimeToUtc(passwordLastSetRaw),
            PasswordMustChangeAtNextLogon = passwordLastSetRaw.HasValue
                ? passwordLastSetRaw.Value == 0
                : null,
            LastLogonTimestamp = LdapValueConverters.GetFileTimeUtc(entry, "lastLogonTimestamp"),
            AccountExpires = IsNeverFileTime(accountExpiresRaw)
                ? null
                : LdapValueConverters.FileTimeToUtc(accountExpiresRaw),
            AccountNeverExpires = accountExpiresRaw.HasValue
                ? IsNeverFileTime(accountExpiresRaw)
                : null,
            SupportedEncryptionTypes = LdapValueConverters.GetInt32(entry, "msDS-SupportedEncryptionTypes"),
            ServicePrincipalNames = SortedDistinct(entry.GetTextValues("servicePrincipalName")),
            SidHistory = LdapValueConverters.GetSids(entry, "sIDHistory"),
            AllowedToDelegateTo = SortedDistinct(entry.GetTextValues("msDS-AllowedToDelegateTo"))
        };
    }

    private static AdGroup MapGroup(
        LdapSearchEntry entry,
        Guid objectGuid,
        CapabilityCollectionState state,
        string target)
    {
        var sid = RequireSecurityPrincipalSid(entry, state, target);
        var groupType = LdapValueConverters.GetInt32(entry, "groupType");
        if (groupType is null)
        {
            state.AddIssue(CreateIssue(
                state.CapabilityId,
                "collection.directory.group-type-missing",
                $"Group '{entry.DistinguishedName}' has no parseable groupType.",
                target));
        }

        return new AdGroup
        {
            Id = new AdObjectId(objectGuid),
            DistinguishedName = entry.DistinguishedName,
            Sid = sid,
            Name = entry.GetSingleTextValue("name"),
            WhenCreated = LdapValueConverters.GetDateTimeOffset(entry, "whenCreated"),
            WhenChanged = LdapValueConverters.GetDateTimeOffset(entry, "whenChanged"),
            SamAccountName = entry.GetSingleTextValue("sAMAccountName"),
            GroupType = groupType,
            AdminCount = LdapValueConverters.GetInt32(entry, "adminCount")
        };
    }

    private static AdComputer MapComputer(
        LdapSearchEntry entry,
        Guid objectGuid,
        CapabilityCollectionState state,
        string target)
    {
        var sid = RequireSecurityPrincipalSid(entry, state, target);
        var userAccountControl = RequireInt64(
            entry,
            "userAccountControl",
            state,
            target,
            "collection.directory.computer-uac-missing");

        return new AdComputer
        {
            Id = new AdObjectId(objectGuid),
            DistinguishedName = entry.DistinguishedName,
            Sid = sid,
            Name = entry.GetSingleTextValue("name"),
            WhenCreated = LdapValueConverters.GetDateTimeOffset(entry, "whenCreated"),
            WhenChanged = LdapValueConverters.GetDateTimeOffset(entry, "whenChanged"),
            SamAccountName = entry.GetSingleTextValue("sAMAccountName"),
            DnsHostName = entry.GetSingleTextValue("dNSHostName"),
            OperatingSystem = entry.GetSingleTextValue("operatingSystem"),
            OperatingSystemVersion = entry.GetSingleTextValue("operatingSystemVersion"),
            UserAccountControl = userAccountControl ?? 0,
            PasswordLastSet = LdapValueConverters.GetFileTimeUtc(entry, "pwdLastSet"),
            LastLogonTimestamp = LdapValueConverters.GetFileTimeUtc(entry, "lastLogonTimestamp"),
            SupportedEncryptionTypes = LdapValueConverters.GetInt32(entry, "msDS-SupportedEncryptionTypes"),
            ServicePrincipalNames = SortedDistinct(entry.GetTextValues("servicePrincipalName")),
            AllowedToDelegateTo = SortedDistinct(entry.GetTextValues("msDS-AllowedToDelegateTo"))
        };
    }

    private static AdOrganizationalUnit MapOrganizationalUnit(
        LdapSearchEntry entry,
        Guid objectGuid) =>
        new()
        {
            Id = new AdObjectId(objectGuid),
            DistinguishedName = entry.DistinguishedName,
            Sid = null,
            Name = entry.GetSingleTextValue("name"),
            WhenCreated = LdapValueConverters.GetDateTimeOffset(entry, "whenCreated"),
            WhenChanged = LdapValueConverters.GetDateTimeOffset(entry, "whenChanged"),
            ProtectFromAccidentalDeletion = null
        };

    private static string? RequireSecurityPrincipalSid(
        LdapSearchEntry entry,
        CapabilityCollectionState state,
        string target)
    {
        var sid = LdapValueConverters.GetSid(entry, "objectSid");
        if (sid is null)
        {
            state.AddIssue(CreateIssue(
                state.CapabilityId,
                "collection.directory.sid-missing",
                $"Security principal '{entry.DistinguishedName}' has no valid objectSid.",
                target));
        }

        return sid;
    }

    private static long? RequireInt64(
        LdapSearchEntry entry,
        string attributeName,
        CapabilityCollectionState state,
        string target,
        string issueCode)
    {
        var value = LdapValueConverters.GetInt64(entry, attributeName);
        if (value is null)
        {
            state.AddIssue(CreateIssue(
                state.CapabilityId,
                issueCode,
                $"Entry '{entry.DistinguishedName}' has no parseable {attributeName}.",
                target));
        }

        return value;
    }

    private static string? ClassifyCapability(LdapSearchEntry entry)
    {
        var objectClasses = entry.GetTextValues("objectClass");

        if (objectClasses.Contains("computer", StringComparer.OrdinalIgnoreCase))
        {
            return CollectionCapabilities.DirectoryComputers;
        }

        if (objectClasses.Contains("group", StringComparer.OrdinalIgnoreCase))
        {
            return CollectionCapabilities.DirectoryGroups;
        }

        if (objectClasses.Contains("organizationalUnit", StringComparer.OrdinalIgnoreCase))
        {
            return CollectionCapabilities.DirectoryOrganizationalUnits;
        }

        if (objectClasses.Contains("user", StringComparer.OrdinalIgnoreCase))
        {
            return CollectionCapabilities.DirectoryUsers;
        }

        return null;
    }

    private static string BuildFilter(IReadOnlyCollection<string> selectedCapabilities)
    {
        var clauses = new List<string>();

        if (selectedCapabilities.Contains(CollectionCapabilities.DirectoryUsers))
        {
            clauses.Add("(&(objectCategory=person)(objectClass=user))");
        }

        if (selectedCapabilities.Contains(CollectionCapabilities.DirectoryGroups))
        {
            clauses.Add("(objectCategory=group)");
        }

        if (selectedCapabilities.Contains(CollectionCapabilities.DirectoryComputers))
        {
            clauses.Add("(objectCategory=computer)");
        }

        if (selectedCapabilities.Contains(CollectionCapabilities.DirectoryOrganizationalUnits))
        {
            clauses.Add("(objectClass=organizationalUnit)");
        }

        return clauses.Count switch
        {
            0 => throw new InvalidOperationException("No LDAP object filters were selected."),
            1 => clauses[0],
            _ => $"(|{string.Concat(clauses)})"
        };
    }

    private static IReadOnlyList<string> BuildAttributes(IReadOnlyCollection<string> selectedCapabilities)
    {
        var attributes = new HashSet<string>(CommonAttributes, StringComparer.OrdinalIgnoreCase);

        if (selectedCapabilities.Contains(CollectionCapabilities.DirectoryUsers))
        {
            attributes.UnionWith(UserAttributes);
        }

        if (selectedCapabilities.Contains(CollectionCapabilities.DirectoryGroups))
        {
            attributes.UnionWith(GroupAttributes);
        }

        if (selectedCapabilities.Contains(CollectionCapabilities.DirectoryComputers))
        {
            attributes.UnionWith(ComputerAttributes);
        }

        return attributes
            .OrderBy(attribute => attribute, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static bool IsNeverFileTime(long? value) =>
        value is 0 or long.MaxValue;

    private static IReadOnlyList<string> SortedDistinct(IEnumerable<string> values) =>
        values
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static void AddUserFacts(
        ICollection<ObservedFact> facts,
        LdapSearchEntry entry,
        AdUser user,
        string target,
        DateTimeOffset observedAt)
    {
        AddCommonFacts(facts, CollectionCapabilities.DirectoryUsers, entry, user, target, observedAt);
        var subjectId = $"ad-object:{user.Id}";
        AddTextFact(facts, CollectionCapabilities.DirectoryUsers, subjectId, "user.samAccountName", entry.GetSingleTextValue("sAMAccountName"), target, entry.DistinguishedName, observedAt);
        AddTextFact(facts, CollectionCapabilities.DirectoryUsers, subjectId, "user.userPrincipalName", entry.GetSingleTextValue("userPrincipalName"), target, entry.DistinguishedName, observedAt);
        AddIntegerFact(facts, CollectionCapabilities.DirectoryUsers, subjectId, "user.userAccountControl", entry.GetSingleTextValue("userAccountControl"), target, entry.DistinguishedName, observedAt);
        AddIntegerFact(facts, CollectionCapabilities.DirectoryUsers, subjectId, "user.adminCount", entry.GetSingleTextValue("adminCount"), target, entry.DistinguishedName, observedAt);
        AddIntegerFact(facts, CollectionCapabilities.DirectoryUsers, subjectId, "user.primaryGroupId", entry.GetSingleTextValue("primaryGroupID"), target, entry.DistinguishedName, observedAt);
        AddIntegerFact(facts, CollectionCapabilities.DirectoryUsers, subjectId, "user.pwdLastSet", entry.GetSingleTextValue("pwdLastSet"), target, entry.DistinguishedName, observedAt);
        AddIntegerFact(facts, CollectionCapabilities.DirectoryUsers, subjectId, "user.lastLogonTimestamp", entry.GetSingleTextValue("lastLogonTimestamp"), target, entry.DistinguishedName, observedAt);
        AddIntegerFact(facts, CollectionCapabilities.DirectoryUsers, subjectId, "user.accountExpires", entry.GetSingleTextValue("accountExpires"), target, entry.DistinguishedName, observedAt);
        AddIntegerFact(facts, CollectionCapabilities.DirectoryUsers, subjectId, "user.supportedEncryptionTypes", entry.GetSingleTextValue("msDS-SupportedEncryptionTypes"), target, entry.DistinguishedName, observedAt);
        AddMultiTextFacts(facts, CollectionCapabilities.DirectoryUsers, subjectId, "user.servicePrincipalName", entry.GetTextValues("servicePrincipalName"), target, entry.DistinguishedName, observedAt);
        AddMultiSidFacts(facts, CollectionCapabilities.DirectoryUsers, subjectId, "user.sidHistory", entry.GetBinaryValues("sIDHistory"), target, entry.DistinguishedName, observedAt);
        AddMultiTextFacts(facts, CollectionCapabilities.DirectoryUsers, subjectId, "user.allowedToDelegateTo", entry.GetTextValues("msDS-AllowedToDelegateTo"), target, entry.DistinguishedName, observedAt);
    }

    private static void AddGroupFacts(
        ICollection<ObservedFact> facts,
        LdapSearchEntry entry,
        AdGroup group,
        string target,
        DateTimeOffset observedAt)
    {
        AddCommonFacts(facts, CollectionCapabilities.DirectoryGroups, entry, group, target, observedAt);
        var subjectId = $"ad-object:{group.Id}";
        AddTextFact(facts, CollectionCapabilities.DirectoryGroups, subjectId, "group.samAccountName", entry.GetSingleTextValue("sAMAccountName"), target, entry.DistinguishedName, observedAt);
        AddIntegerFact(facts, CollectionCapabilities.DirectoryGroups, subjectId, "group.groupType", entry.GetSingleTextValue("groupType"), target, entry.DistinguishedName, observedAt);
        AddIntegerFact(facts, CollectionCapabilities.DirectoryGroups, subjectId, "group.adminCount", entry.GetSingleTextValue("adminCount"), target, entry.DistinguishedName, observedAt);
    }

    private static void AddComputerFacts(
        ICollection<ObservedFact> facts,
        LdapSearchEntry entry,
        AdComputer computer,
        string target,
        DateTimeOffset observedAt)
    {
        AddCommonFacts(facts, CollectionCapabilities.DirectoryComputers, entry, computer, target, observedAt);
        var subjectId = $"ad-object:{computer.Id}";
        AddTextFact(facts, CollectionCapabilities.DirectoryComputers, subjectId, "computer.samAccountName", entry.GetSingleTextValue("sAMAccountName"), target, entry.DistinguishedName, observedAt);
        AddTextFact(facts, CollectionCapabilities.DirectoryComputers, subjectId, "computer.dnsHostName", entry.GetSingleTextValue("dNSHostName"), target, entry.DistinguishedName, observedAt);
        AddTextFact(facts, CollectionCapabilities.DirectoryComputers, subjectId, "computer.operatingSystem", entry.GetSingleTextValue("operatingSystem"), target, entry.DistinguishedName, observedAt);
        AddTextFact(facts, CollectionCapabilities.DirectoryComputers, subjectId, "computer.operatingSystemVersion", entry.GetSingleTextValue("operatingSystemVersion"), target, entry.DistinguishedName, observedAt);
        AddIntegerFact(facts, CollectionCapabilities.DirectoryComputers, subjectId, "computer.userAccountControl", entry.GetSingleTextValue("userAccountControl"), target, entry.DistinguishedName, observedAt);
        AddIntegerFact(facts, CollectionCapabilities.DirectoryComputers, subjectId, "computer.pwdLastSet", entry.GetSingleTextValue("pwdLastSet"), target, entry.DistinguishedName, observedAt);
        AddIntegerFact(facts, CollectionCapabilities.DirectoryComputers, subjectId, "computer.lastLogonTimestamp", entry.GetSingleTextValue("lastLogonTimestamp"), target, entry.DistinguishedName, observedAt);
        AddIntegerFact(facts, CollectionCapabilities.DirectoryComputers, subjectId, "computer.supportedEncryptionTypes", entry.GetSingleTextValue("msDS-SupportedEncryptionTypes"), target, entry.DistinguishedName, observedAt);
        AddMultiTextFacts(facts, CollectionCapabilities.DirectoryComputers, subjectId, "computer.servicePrincipalName", entry.GetTextValues("servicePrincipalName"), target, entry.DistinguishedName, observedAt);
        AddMultiTextFacts(facts, CollectionCapabilities.DirectoryComputers, subjectId, "computer.allowedToDelegateTo", entry.GetTextValues("msDS-AllowedToDelegateTo"), target, entry.DistinguishedName, observedAt);
    }

    private static void AddCommonFacts(
        ICollection<ObservedFact> facts,
        string capability,
        LdapSearchEntry entry,
        AdDirectoryObject item,
        string target,
        DateTimeOffset observedAt)
    {
        var subjectId = $"ad-object:{item.Id}";
        AddFact(facts, capability, subjectId, "object.distinguishedName", item.DistinguishedName, FactValueKind.DistinguishedName, target, entry.DistinguishedName, observedAt);
        AddFact(facts, capability, subjectId, "object.objectGuid", item.Id.ToString(), FactValueKind.Guid, target, entry.DistinguishedName, observedAt);
        AddFact(facts, capability, subjectId, "object.objectSid", item.Sid, FactValueKind.Sid, target, entry.DistinguishedName, observedAt);
        AddTextFact(facts, capability, subjectId, "object.name", entry.GetSingleTextValue("name"), target, entry.DistinguishedName, observedAt);
        AddTextFact(facts, capability, subjectId, "object.whenCreated", entry.GetSingleTextValue("whenCreated"), target, entry.DistinguishedName, observedAt, FactValueKind.Timestamp);
        AddTextFact(facts, capability, subjectId, "object.whenChanged", entry.GetSingleTextValue("whenChanged"), target, entry.DistinguishedName, observedAt, FactValueKind.Timestamp);
    }

    private static void AddTextFact(
        ICollection<ObservedFact> facts,
        string capability,
        string subjectId,
        string path,
        string? value,
        string target,
        string locator,
        DateTimeOffset observedAt,
        FactValueKind kind = FactValueKind.Text) =>
        AddFact(facts, capability, subjectId, path, value, kind, target, locator, observedAt);

    private static void AddIntegerFact(
        ICollection<ObservedFact> facts,
        string capability,
        string subjectId,
        string path,
        string? value,
        string target,
        string locator,
        DateTimeOffset observedAt) =>
        AddFact(facts, capability, subjectId, path, value, FactValueKind.Integer, target, locator, observedAt);

    private static void AddMultiTextFacts(
        ICollection<ObservedFact> facts,
        string capability,
        string subjectId,
        string path,
        IEnumerable<string> values,
        string target,
        string locator,
        DateTimeOffset observedAt)
    {
        foreach (var value in SortedDistinct(values))
        {
            AddTextFact(facts, capability, subjectId, path, value, target, locator, observedAt);
        }
    }

    private static void AddMultiSidFacts(
        ICollection<ObservedFact> facts,
        string capability,
        string subjectId,
        string path,
        IEnumerable<byte[]> values,
        string target,
        string locator,
        DateTimeOffset observedAt)
    {
        foreach (var sid in values
                     .Select(value => LdapValueConverters.FormatSid(value))
                     .Where(value => value is not null)
                     .Cast<string>()
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .OrderBy(value => value, StringComparer.OrdinalIgnoreCase))
        {
            AddFact(facts, capability, subjectId, path, sid, FactValueKind.Sid, target, locator, observedAt);
        }
    }

    private static void AddFact(
        ICollection<ObservedFact> facts,
        string capability,
        string subjectId,
        string path,
        string? value,
        FactValueKind kind,
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
            FactId = FactIdFactory.Create(capability, subjectId, path, kind, value),
            CapabilityId = capability,
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
                Locator = locator
            },
            ObservedAt = observedAt
        });
    }

    private static void MarkAllPartial(
        IEnumerable<CapabilityCollectionState> states,
        string code,
        string message,
        string target)
    {
        foreach (var state in states)
        {
            state.AddIssue(CreateIssue(state.CapabilityId, code, message, target));
        }
    }

    private static CollectionIssue CreateIssue(
        string capability,
        string code,
        string message,
        string target) =>
        new()
        {
            Code = code,
            Severity = CollectionIssueSeverity.Error,
            Message = message,
            CapabilityId = capability,
            CollectorId = CollectorId,
            Target = target
        };

    private static SnapshotFragment CreateFailureFragment(
        IReadOnlyList<string> capabilities,
        string code,
        string message,
        string target,
        DateTimeOffset startedAt,
        DateTimeOffset completedAt) =>
        new()
        {
            Coverage = capabilities
                .Select(capability => new CapabilityCoverage
                {
                    CapabilityId = capability,
                    ContractVersion = CapabilityContractCatalog.GetCurrentVersion(capability),
                    Status = CapabilityStatus.Failed,
                    StartedAt = startedAt,
                    CompletedAt = completedAt,
                    Issues = [CreateIssue(capability, code, message, target)]
                })
                .ToArray()
        };

    private sealed class CapabilityCollectionState
    {
        private readonly List<CollectionIssue> _issues = [];

        public CapabilityCollectionState(string capabilityId)
        {
            CapabilityId = capabilityId;
        }

        public string CapabilityId { get; }
        public int ObservedItemCount { get; private set; }

        public void ObserveItem() => ObservedItemCount++;

        public void AddIssue(CollectionIssue issue) => _issues.Add(issue);

        public CapabilityCoverage ToCoverage(
            DateTimeOffset startedAt,
            DateTimeOffset completedAt) =>
            new()
            {
                CapabilityId = CapabilityId,
                ContractVersion = CapabilityContractCatalog.GetCurrentVersion(CapabilityId),
                Status = _issues.Count == 0 ? CapabilityStatus.Complete : CapabilityStatus.Partial,
                StartedAt = startedAt,
                CompletedAt = completedAt,
                ObservedItemCount = ObservedItemCount,
                Issues = _issues
                    .OrderBy(issue => issue.Code, StringComparer.Ordinal)
                    .ThenBy(issue => issue.Message, StringComparer.Ordinal)
                    .ToArray()
            };
    }
}
