using System.Globalization;
using DogfighterAD.Application.Analysis;
using DogfighterAD.Application.Analysis.Rules;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Analysis;

internal sealed class AnalysisFixture
{
    internal static readonly DateTimeOffset Now = new(2026, 9, 7, 12, 0, 0, TimeSpan.Zero);
    internal const string DomainSid = "S-1-5-21-1-2-3";
    internal static readonly AdDomain Domain = new()
    { Id = new(Guid.Parse("11111111-1111-1111-1111-111111111111")), DistinguishedName = "DC=review,DC=invalid", DnsName = "review.invalid", Sid = DomainSid };
    internal static readonly AdUser User = new()
    { Id = new(Guid.Parse("22222222-2222-2222-2222-222222222222")), DistinguishedName = "CN=User,DC=review,DC=invalid", Sid = DomainSid + "-1100", Name = "User" };
    internal static readonly AdComputer Computer = new()
    { Id = new(Guid.Parse("33333333-3333-3333-3333-333333333333")), DistinguishedName = "CN=Computer,DC=review,DC=invalid", Sid = DomainSid + "-1101", Name = "Computer" };
    internal static readonly AdGroup Group = new()
    { Id = new(Guid.Parse("44444444-4444-4444-4444-444444444444")), DistinguishedName = "CN=Domain Admins,DC=review,DC=invalid", Sid = DomainSid + "-512" };
    internal static readonly AdGroupPolicyObject Gpo = new()
    { Id = new(Guid.Parse("55555555-5555-5555-5555-555555555555")), GpoGuid = Guid.Parse("66666666-6666-6666-6666-666666666666"), DistinguishedName = "CN={66666666-6666-6666-6666-666666666666},CN=Policies,CN=System,DC=review,DC=invalid" };
    internal static readonly string[] Capabilities =
    [ CollectionCapabilities.DirectoryCore, CollectionCapabilities.DirectoryDomains, CollectionCapabilities.DirectoryUsers,
      CollectionCapabilities.DirectoryGroups, CollectionCapabilities.DirectoryComputers, CollectionCapabilities.DirectoryOrganizationalUnits,
      CollectionCapabilities.DirectoryMemberships, CollectionCapabilities.DirectoryAcls, CollectionCapabilities.DirectoryTrusts,
      CollectionCapabilities.GroupPolicyMetadata, CollectionCapabilities.GroupPolicyLinks, CollectionCapabilities.GroupPolicySysvol,
      CollectionCapabilities.DirectorySecurityPolicy ];
    internal SnapshotContent Content { get; set; } = new() { Domains = [Domain], Users = [User], Computers = [Computer], Groups = [Group], GroupPolicyObjects = [Gpo] };
    internal List<ObservedFact> Facts { get; } = [];
    internal List<CapabilityCoverage> Coverage { get; } = Capabilities.Select(cap => new CapabilityCoverage
    {
        CapabilityId = cap, ContractVersion = CapabilityContractCatalog.GetCurrentVersion(cap), Status = CapabilityStatus.Complete,
        StartedAt = Now.AddMinutes(-10), CompletedAt = Now, Collectors = [new("fixture", "1")]
    }).ToList();
    internal static string Subject(AdDirectoryObject item) => $"ad-object:{item.Id}";
    internal AnalysisFixture()
    {
        Add(CollectionCapabilities.DirectoryDomains, Subject(Domain), "domain.objectSid", DomainSid, FactValueKind.Sid);
        Add(CollectionCapabilities.DirectoryGroups, Subject(Group), "object.objectSid", Group.Sid!, FactValueKind.Sid);
        Add(CollectionCapabilities.DirectoryUsers, Subject(User), "object.objectSid", User.Sid!, FactValueKind.Sid);
        Add(CollectionCapabilities.DirectoryComputers, Subject(Computer), "object.objectSid", Computer.Sid!, FactValueKind.Sid);
    }
    internal void Add(string cap, string subject, string path, string value, FactValueKind kind = FactValueKind.Text) => Facts.Add(new()
    {
        FactId = FactIdFactory.Create(cap, subject, path, kind, value), CapabilityId = cap, SubjectId = subject,
        Path = path, Value = value, ValueKind = kind, Disposition = FactDisposition.Stored,
        ObservedAt = Now.AddMinutes(-1), Source = new()
        { CollectorId = "fixture", CollectorVersion = "1", SourceKind = cap == CollectionCapabilities.GroupPolicySysvol ? "sysvol" : "ldap", Endpoint = "review.invalid", Locator = "synthetic" }
    });
    internal void Integer(string cap, string subject, string path, long value) => Add(cap, subject, path, value.ToString(CultureInfo.InvariantCulture), FactValueKind.Integer);
    internal void Boolean(string cap, string subject, string path, bool value) => Add(cap, subject, path, value ? "true" : "false", FactValueKind.Boolean);
    internal void Remove(string cap, string subject, string path) => Facts.RemoveAll(f => f.CapabilityId == cap && f.SubjectId == subject && f.Path == path);
    internal void Uac(bool computer, long value)
    {
        var cap = computer ? CollectionCapabilities.DirectoryComputers : CollectionCapabilities.DirectoryUsers;
        var subject = Subject(computer ? Computer : User); var path = computer ? "computer.userAccountControl" : "user.userAccountControl";
        Remove(cap, subject, path); Integer(cap, subject, path, value);
    }
    internal void SetCoverage(string cap, CapabilityStatus status, int? version = null)
    {
        var index = Coverage.FindIndex(c => c.CapabilityId == cap);
        Coverage[index] = Coverage[index] with { Status = status, ContractVersion = version ?? Coverage[index].ContractVersion };
    }
    internal AdSnapshot Build()
    {
        var snapshot = new AdSnapshot
        {
        Metadata = new()
        {
            SnapshotId = Guid.Parse("77777777-7777-7777-7777-777777777777"), SchemaVersion = SnapshotSchema.CurrentVersion,
            ProductVersion = "test-rule-engine", StartedAt = Now.AddMinutes(-10), CompletedAt = Now,
            Target = new() { InitialTarget = "review.invalid" }, RequestedCapabilities = Coverage.Select(c => c.CapabilityId).ToArray(),
            Collectors = [new("fixture", "1")], CompletionStatus = SnapshotCompletionStatusCalculator.Calculate(Coverage.Select(c => c.CapabilityId), Coverage)
        }, Content = Content, Observations = Facts.ToArray(), Coverage = Coverage.ToArray()
        };
        return snapshot with { Coverage = snapshot.Coverage.Select(c => c with
        {
            ObservedItemCount = c.CapabilityId switch
            {
                CollectionCapabilities.DirectoryDomains => Content.Domains.Count,
                CollectionCapabilities.DirectoryUsers => Content.Users.Count,
                CollectionCapabilities.DirectoryComputers => Content.Computers.Count,
                CollectionCapabilities.DirectoryGroups => Content.Groups.Count,
                CollectionCapabilities.DirectoryOrganizationalUnits => Content.OrganizationalUnits.Count,
                CollectionCapabilities.DirectoryMemberships => Content.GroupMemberships.Count,
                CollectionCapabilities.DirectoryAcls => Content.SecurityDescriptors.Count,
                CollectionCapabilities.DirectoryTrusts => Content.Trusts.Count,
                CollectionCapabilities.GroupPolicyMetadata => Content.GroupPolicyObjects.Count,
                CollectionCapabilities.GroupPolicyLinks => Content.GroupPolicyLinks.Count,
                CollectionCapabilities.GroupPolicySysvol => Content.GroupPolicyFiles.Count,
                CollectionCapabilities.DirectorySecurityPolicy => Facts.Where(f => f.CapabilityId == c.CapabilityId && f.Path == "policy.kind").Select(f => f.SubjectId).Distinct().Count(),
                _ => c.ObservedItemCount
            }
        }).ToArray() };
    }
    internal AnalysisReport Run(params string[] ids) => new RuleEngine(BuiltInRulePack.Create(), BuiltInRulePack.Id, BuiltInRulePack.Version)
        .Analyze(Build(), new() { RuleIds = ids.ToHashSet(StringComparer.Ordinal) }, TestContext.Current.CancellationToken);
    internal RuleEvaluation Check(string id, AdDirectoryObject? subject = null, string? key = null) =>
        Assert.Single(Run(id).Evaluations.Where(e => e.Subject.StableId == Subject(subject ?? User) && (key is null || e.CheckKey == key)));
    internal void Policy(string field, string value, FactValueKind kind = FactValueKind.Integer, string? subject = null, string policyKind = "DefaultDomain")
    {
        const string cap = CollectionCapabilities.DirectorySecurityPolicy; subject ??= Subject(Domain);
        if (!Facts.Any(f => f.CapabilityId == cap && f.SubjectId == subject && f.Path == "policy.kind"))
        { Add(cap, subject, "policy.kind", policyKind); Add(cap, subject, "policy.distinguishedName", Domain.DistinguishedName, FactValueKind.DistinguishedName); }
        Add(cap, subject, "policy." + field, value, kind);
    }
    internal static string SettingPath(AdGpoSetting s)
    {
        var key = s.Key.Replace("\\", "/", StringComparison.Ordinal);
        return $"gpo.sysvol.setting.{s.SourceRelativePath}.{s.Sequence}.{key}";
    }
    internal AdGpoSetting Setting(string section, string key, string? value, FactValueKind kind = FactValueKind.Integer,
        GpoSettingKind settingKind = GpoSettingKind.RegistryPolicy, GpoPolicyScope scope = GpoPolicyScope.Machine,
        string? path = null, uint? registryType = 4, bool typeEvidence = true, FactDisposition disposition = FactDisposition.Stored)
    {
        var setting = new AdGpoSetting
        {
            GpoId = Gpo.Id, Scope = scope, SourceRelativePath = path ?? scope + "\\Registry.pol",
            Sequence = Content.GroupPolicySettings.Count + 1, Section = section, Key = key, Value = value,
            ValueKind = kind, Disposition = disposition, Kind = settingKind,
            RegistryValueType = settingKind == GpoSettingKind.RegistryPolicy ? registryType : null
        };
        Content = Content with { GroupPolicySettings = Content.GroupPolicySettings.Append(setting).ToArray() };
        if (value is not null) Add(CollectionCapabilities.GroupPolicySysvol, Subject(Gpo), SettingPath(setting), value, kind);
        if (setting.RegistryValueType.HasValue && typeEvidence)
            Integer(CollectionCapabilities.GroupPolicySysvol, Subject(Gpo), SettingPath(setting) + ".registryValueType", setting.RegistryValueType.Value);
        return setting;
    }
    internal void Acl(AdDirectoryObject target, uint mask, string? objectType = null, string access = "Allow", byte flags = 0,
        string trustee = "S-1-5-11", string state = "Present", bool complete = true)
    {
        const string cap = CollectionCapabilities.DirectoryAcls; var sub = Subject(target);
        var ace = new AdAce
        { TargetObjectId = target.Id, AceIndex = 0, TrusteeSid = trustee, AccessType = Enum.Parse<AdAccessControlType>(access),
          AccessMask = mask, AceFlags = flags, ObjectType = objectType is null ? null : Guid.Parse(objectType), IsInherited = (flags & 16) != 0 };
        Content = Content with { Aces = state == "Present" ? [ace] : [], SecurityDescriptors = [new() { TargetObjectId = target.Id, DaclState = Enum.Parse<AdDaclState>(state) }] };
        Add(cap, sub, "securityDescriptor.daclState", state);
        Boolean(cap, sub, "securityDescriptor.parseComplete", complete);
        Integer(cap, sub, "securityDescriptor.aceCount", state == "Present" ? 1 : 0);
        if (state != "Present") return;
        var p = "securityDescriptor.dacl.ace[0]";
        Add(cap, sub, p + ".accessType", access); Add(cap, sub, p + ".trusteeSid", trustee, FactValueKind.Sid);
        Integer(cap, sub, p + ".aceFlags", flags); Integer(cap, sub, p + ".accessMask", mask);
        Boolean(cap, sub, p + ".objectTypePresent", objectType is not null);
        Boolean(cap, sub, p + ".inheritedObjectTypePresent", false);
        if (objectType is not null) Add(cap, sub, p + ".objectType", objectType, FactValueKind.Guid);
    }
}
