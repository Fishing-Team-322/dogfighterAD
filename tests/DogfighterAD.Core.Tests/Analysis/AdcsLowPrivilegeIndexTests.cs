using System.Globalization;
using DogfighterAD.Application.Analysis;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Analysis;

public sealed class AdcsLowPrivilegeIndexTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 8, 10, 30, 0, TimeSpan.Zero);
    private const string DomainSid = "S-1-5-21-100-200-300";
    private const string EnrollGroupSid = DomainSid + "-2100";

    [Fact]
    public void NestedCustomGroup_WithEnabledNonPrivilegedUser_IsProvenLowPrivilege()
    {
        var snapshot = CreateSnapshot(privilegedUser: false);
        var index = new AdcsLowPrivilegeIndex(
            snapshot,
            new ObservationIndex(snapshot),
            TestContext.Current.CancellationToken);

        Assert.True(index.ScopeComplete);
        Assert.True(index.TryProveLowPrivilegeTrustee(EnrollGroupSid, out var evidence));
        Assert.Contains(evidence, item => item.Path == "group.member");
        Assert.Contains(evidence, item => item.Path == "user.userAccountControl");
    }

    [Fact]
    public void NestedCustomGroup_WithProvenPrivilegedUser_IsNotProvenLowPrivilege()
    {
        var snapshot = CreateSnapshot(privilegedUser: true);
        var index = new AdcsLowPrivilegeIndex(
            snapshot,
            new ObservationIndex(snapshot),
            TestContext.Current.CancellationToken);

        Assert.True(index.ScopeComplete);
        Assert.False(index.TryProveLowPrivilegeTrustee(EnrollGroupSid, out var evidence));
        Assert.Empty(evidence);
    }

    private static AdSnapshot CreateSnapshot(bool privilegedUser)
    {
        var domain = new AdDomain
        {
            Id = new AdObjectId(Guid.Parse("11111111-1111-1111-1111-111111111111")),
            DistinguishedName = "DC=review,DC=invalid",
            DnsName = "review.invalid",
            Sid = DomainSid
        };
        var user = new AdUser
        {
            Id = new AdObjectId(Guid.Parse("22222222-2222-2222-2222-222222222222")),
            DistinguishedName = "CN=Alice,OU=Users,DC=review,DC=invalid",
            Name = "Alice",
            Sid = DomainSid + "-1100",
            UserAccountControl = 512,
            PrimaryGroupId = 513
        };
        var domainUsers = new AdGroup
        {
            Id = new AdObjectId(Guid.Parse("33333333-3333-3333-3333-333333333333")),
            DistinguishedName = "CN=Domain Users,CN=Users,DC=review,DC=invalid",
            Name = "Domain Users",
            Sid = DomainSid + "-513"
        };
        var enrollGroup = new AdGroup
        {
            Id = new AdObjectId(Guid.Parse("44444444-4444-4444-4444-444444444444")),
            DistinguishedName = "CN=Certificate Enrollers,OU=Groups,DC=review,DC=invalid",
            Name = "Certificate Enrollers",
            Sid = EnrollGroupSid
        };
        var domainAdmins = new AdGroup
        {
            Id = new AdObjectId(Guid.Parse("55555555-5555-5555-5555-555555555555")),
            DistinguishedName = "CN=Domain Admins,CN=Users,DC=review,DC=invalid",
            Name = "Domain Admins",
            Sid = DomainSid + "-512"
        };

        var groups = privilegedUser
            ? new[] { domainUsers, enrollGroup, domainAdmins }
            : new[] { domainUsers, enrollGroup };
        var memberships = new List<AdGroupMembership>
        {
            new(domainUsers.Id, user.Id, MembershipSource.PrimaryGroup),
            new(enrollGroup.Id, user.Id, MembershipSource.Explicit)
        };
        if (privilegedUser)
            memberships.Add(new AdGroupMembership(domainAdmins.Id, user.Id, MembershipSource.Explicit));

        var facts = new List<ObservedFact>();
        Add(facts, CollectionCapabilities.DirectoryDomains, Subject(domain), "domain.objectSid", DomainSid, FactValueKind.Sid);
        Add(facts, CollectionCapabilities.DirectoryUsers, Subject(user), "object.objectSid", user.Sid!, FactValueKind.Sid);
        AddInteger(facts, CollectionCapabilities.DirectoryUsers, Subject(user), "user.userAccountControl", user.UserAccountControl);
        AddInteger(facts, CollectionCapabilities.DirectoryMemberships, Subject(user), "principal.primaryGroupId", 513);

        foreach (var group in groups)
            Add(facts, CollectionCapabilities.DirectoryGroups, Subject(group), "object.objectSid", group.Sid!, FactValueKind.Sid);

        AddMembershipBounds(facts, domainUsers, 0);
        AddMembershipBounds(facts, enrollGroup, 1);
        Add(facts, CollectionCapabilities.DirectoryMemberships, Subject(enrollGroup), "group.member", user.DistinguishedName, FactValueKind.DistinguishedName);
        if (privilegedUser)
        {
            AddMembershipBounds(facts, domainAdmins, 1);
            Add(facts, CollectionCapabilities.DirectoryMemberships, Subject(domainAdmins), "group.member", user.DistinguishedName, FactValueKind.DistinguishedName);
        }

        var content = new SnapshotContent
        {
            Domains = [domain],
            Users = [user],
            Groups = groups,
            GroupMemberships = memberships
        };
        var capabilities = new[]
        {
            CollectionCapabilities.DirectoryUsers,
            CollectionCapabilities.DirectoryGroups,
            CollectionCapabilities.DirectoryMemberships,
            CollectionCapabilities.DirectoryDomains
        };
        var coverage = capabilities.Select(capability => new CapabilityCoverage
        {
            CapabilityId = capability,
            ContractVersion = CapabilityContractCatalog.GetCurrentVersion(capability),
            Status = CapabilityStatus.Complete,
            StartedAt = Now.AddMinutes(-1),
            CompletedAt = Now,
            ObservedItemCount = capability switch
            {
                CollectionCapabilities.DirectoryUsers => 1,
                CollectionCapabilities.DirectoryGroups => groups.Length,
                CollectionCapabilities.DirectoryMemberships => memberships.Count,
                CollectionCapabilities.DirectoryDomains => 1,
                _ => 0
            },
            Collectors = [new CollectorIdentity("fixture", "1")]
        }).ToArray();

        return new AdSnapshot
        {
            Metadata = new SnapshotMetadata
            {
                SnapshotId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
                SchemaVersion = SnapshotSchema.CurrentVersion,
                ProductVersion = "adcs-membership-test",
                StartedAt = Now.AddMinutes(-1),
                CompletedAt = Now,
                CompletionStatus = SnapshotCompletionStatus.Complete,
                Target = new TargetIdentity
                {
                    InitialTarget = "review.invalid",
                    DomainDnsName = domain.DnsName,
                    DomainSid = DomainSid
                },
                RequestedCapabilities = capabilities,
                Collectors = [new CollectorIdentity("fixture", "1")]
            },
            Content = content,
            Coverage = coverage,
            Observations = facts
        };
    }

    private static void AddMembershipBounds(
        ICollection<ObservedFact> facts,
        AdGroup group,
        int count)
    {
        Add(facts, CollectionCapabilities.DirectoryMemberships, Subject(group), "group.memberReadComplete", "true", FactValueKind.Boolean);
        AddInteger(facts, CollectionCapabilities.DirectoryMemberships, Subject(group), "group.observedMemberCount", count);
    }

    private static string Subject(AdDirectoryObject value) => $"ad-object:{value.Id}";

    private static void AddInteger(
        ICollection<ObservedFact> facts,
        string capability,
        string subject,
        string path,
        long value) =>
        Add(facts, capability, subject, path, value.ToString(CultureInfo.InvariantCulture), FactValueKind.Integer);

    private static void Add(
        ICollection<ObservedFact> facts,
        string capability,
        string subject,
        string path,
        string value,
        FactValueKind kind)
    {
        facts.Add(new ObservedFact
        {
            FactId = FactIdFactory.Create(capability, subject, path, kind, value),
            CapabilityId = capability,
            SubjectId = subject,
            Path = path,
            Value = value,
            ValueKind = kind,
            ObservedAt = Now.AddSeconds(-15),
            Source = new ObservationSource
            {
                CollectorId = "fixture",
                CollectorVersion = "1",
                SourceKind = "ldap",
                Endpoint = "review.invalid",
                Locator = "synthetic"
            }
        });
    }
}
