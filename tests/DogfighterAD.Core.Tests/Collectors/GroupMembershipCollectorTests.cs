using System.Globalization;
using System.Runtime.CompilerServices;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class GroupMembershipCollectorTests
{
    private static readonly DateTimeOffset FixedNow =
        new(2026, 9, 5, 20, 15, 0, TimeSpan.Zero);

    private static readonly AdObjectId AliceId =
        new(Guid.Parse("11111111-1111-1111-1111-111111111111"));
    private static readonly AdObjectId WorkstationId =
        new(Guid.Parse("22222222-2222-2222-2222-222222222222"));
    private static readonly AdObjectId DomainUsersId =
        new(Guid.Parse("33333333-3333-3333-3333-333333333333"));
    private static readonly AdObjectId DomainComputersId =
        new(Guid.Parse("44444444-4444-4444-4444-444444444444"));
    private static readonly AdObjectId AuditGroupId =
        new(Guid.Parse("55555555-5555-5555-5555-555555555555"));
    private static readonly AdObjectId FspId =
        new(Guid.Parse("66666666-6666-6666-6666-666666666666"));

    private const string AliceDn = "CN=Alice,OU=Users,DC=mini,DC=lab";
    private const string WorkstationDn = "CN=WS01,OU=Computers,DC=mini,DC=lab";
    private const string DomainUsersDn = "CN=Domain Users,CN=Users,DC=mini,DC=lab";
    private const string DomainComputersDn = "CN=Domain Computers,CN=Users,DC=mini,DC=lab";
    private const string AuditGroupDn = "CN=Audit Team,OU=Groups,DC=mini,DC=lab";
    private const string FspDn = "CN=S-1-5-21-9-9-9-1001,CN=ForeignSecurityPrincipals,DC=mini,DC=lab";

    [Fact]
    public async Task CollectAsync_PreservesDirectNestedPrimaryAndForeignMemberships()
    {
        var client = new MembershipFakeClient(
            supportingEntries:
            [
                PrincipalEntry(AliceId, AliceDn, "S-1-5-21-1-2-3-1101", 513, "user"),
                PrincipalEntry(WorkstationId, WorkstationDn, "S-1-5-21-1-2-3-3101", 515, "computer"),
                ForeignSecurityPrincipalEntry()
            ],
            groupEntries:
            [
                GroupMemberEntry(DomainUsersId, DomainUsersDn),
                GroupMemberEntry(DomainComputersId, DomainComputersDn),
                GroupMemberEntry(
                    AuditGroupId,
                    AuditGroupDn,
                    AliceDn,
                    FspDn,
                    DomainUsersDn)
            ]);

        var collector = new GroupMembershipCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        Assert.Equal(2, client.StreamingRequests.Count);
        Assert.Equal(0, client.BaseSearchCount);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CollectionCapabilities.DirectoryMemberships, coverage.CapabilityId);
        Assert.Equal(CapabilityStatus.Complete, coverage.Status);
        Assert.Equal(1, coverage.ContractVersion);
        Assert.Empty(coverage.Issues);

        var memberships = result.Fragment.Content.GroupMemberships;
        Assert.Equal(5, memberships.Count);
        Assert.Contains(memberships, item =>
            item.GroupId == DomainUsersId &&
            item.MemberId == AliceId &&
            item.Source == MembershipSource.PrimaryGroup);
        Assert.Contains(memberships, item =>
            item.GroupId == DomainComputersId &&
            item.MemberId == WorkstationId &&
            item.Source == MembershipSource.PrimaryGroup);
        Assert.Contains(memberships, item =>
            item.GroupId == AuditGroupId &&
            item.MemberId == AliceId &&
            item.Source == MembershipSource.Explicit);
        Assert.Contains(memberships, item =>
            item.GroupId == AuditGroupId &&
            item.MemberId == FspId &&
            item.Source == MembershipSource.Explicit);
        Assert.Contains(memberships, item =>
            item.GroupId == AuditGroupId &&
            item.MemberId == DomainUsersId &&
            item.Source == MembershipSource.Explicit);

        var fsp = Assert.Single(result.Fragment.Content.ForeignSecurityPrincipals);
        Assert.Equal(FspId, fsp.Id);
        Assert.Equal("S-1-5-21-9-9-9-1001", fsp.Sid);

        Assert.Contains(result.Fragment.Observations, fact =>
            fact.Path == "principal.primaryGroupId" &&
            fact.SubjectId == $"ad-object:{AliceId}" &&
            fact.Value == "513");
        Assert.Contains(result.Fragment.Observations, fact =>
            fact.Path == "group.member" && fact.Value == FspDn);
    }

    [Fact]
    public async Task CollectAsync_UnresolvedMember_MakesCoveragePartial()
    {
        const string missingDn = "CN=Missing,OU=Users,DC=mini,DC=lab";
        var client = new MembershipFakeClient(
            supportingEntries: [],
            groupEntries:
            [
                GroupMemberEntry(DomainUsersId, DomainUsersDn),
                GroupMemberEntry(DomainComputersId, DomainComputersDn),
                GroupMemberEntry(AuditGroupId, AuditGroupDn, missingDn)
            ],
            baseResponses: new Dictionary<string, LdapSearchResult>(StringComparer.OrdinalIgnoreCase));

        var collector = new GroupMembershipCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Partial, coverage.Status);
        Assert.Contains(coverage.Issues, issue =>
            issue.Code == "collection.memberships.member-unresolved");
        Assert.Equal(1, client.BaseSearchCount);
    }

    private static CollectionContext CreateContext() =>
        new(
            Guid.Parse("acc4351a-7d6e-4611-a211-8305f76ac66a"),
            "dc01.mini.lab",
            new HashSet<string>(StringComparer.Ordinal)
            {
                CollectionCapabilities.DirectoryMemberships
            },
            new SnapshotFragment
            {
                Content = new SnapshotContent
                {
                    DirectoryEnvironment = new DirectoryEnvironment
                    {
                        DnsHostName = "dc01.mini.lab",
                        DefaultNamingContext = "DC=mini,DC=lab",
                        ConfigurationNamingContext = "CN=Configuration,DC=mini,DC=lab",
                        SchemaNamingContext = "CN=Schema,CN=Configuration,DC=mini,DC=lab",
                        RootDomainNamingContext = "DC=mini,DC=lab"
                    },
                    Users =
                    [
                        new AdUser
                        {
                            Id = AliceId,
                            DistinguishedName = AliceDn,
                            Sid = "S-1-5-21-1-2-3-1101",
                            SamAccountName = "alice",
                            UserAccountControl = 512,
                            PrimaryGroupId = 513
                        }
                    ],
                    Computers =
                    [
                        new AdComputer
                        {
                            Id = WorkstationId,
                            DistinguishedName = WorkstationDn,
                            Sid = "S-1-5-21-1-2-3-3101",
                            SamAccountName = "WS01$",
                            UserAccountControl = 4096
                        }
                    ],
                    Groups =
                    [
                        Group(DomainUsersId, DomainUsersDn, "S-1-5-21-1-2-3-513", "Domain Users"),
                        Group(DomainComputersId, DomainComputersDn, "S-1-5-21-1-2-3-515", "Domain Computers"),
                        Group(AuditGroupId, AuditGroupDn, "S-1-5-21-1-2-3-2101", "Audit Team")
                    ]
                }
            });

    private static AdGroup Group(
        AdObjectId id,
        string dn,
        string sid,
        string name) =>
        new()
        {
            Id = id,
            DistinguishedName = dn,
            Sid = sid,
            Name = name,
            SamAccountName = name,
            GroupType = -2147483646
        };

    private static LdapSearchEntry PrincipalEntry(
        AdObjectId id,
        string dn,
        string sid,
        int primaryGroupId,
        string mostSpecificClass) =>
        new()
        {
            DistinguishedName = dn,
            Attributes = Attributes(
                ("objectClass", Text("top", "person", "organizationalPerson", "user", mostSpecificClass)),
                ("objectGUID", Binary(id.Value.ToByteArray())),
                ("objectSid", Binary(CreateSidBytes(sid))),
                ("primaryGroupID", Text(primaryGroupId.ToString(CultureInfo.InvariantCulture))))
        };

    private static LdapSearchEntry ForeignSecurityPrincipalEntry() =>
        new()
        {
            DistinguishedName = FspDn,
            Attributes = Attributes(
                ("objectClass", Text("top", "foreignSecurityPrincipal")),
                ("objectGUID", Binary(FspId.Value.ToByteArray())),
                ("objectSid", Binary(CreateSidBytes("S-1-5-21-9-9-9-1001"))),
                ("name", Text("S-1-5-21-9-9-9-1001")))
        };

    private static LdapSearchEntry GroupMemberEntry(
        AdObjectId id,
        string dn,
        params string[] members)
    {
        var attributes = new List<(string Name, IReadOnlyList<LdapAttributeValue> Values)>
        {
            ("objectGUID", Binary(id.Value.ToByteArray()))
        };

        if (members.Length > 0)
        {
            attributes.Add(("member", Text(members)));
        }

        return new LdapSearchEntry
        {
            DistinguishedName = dn,
            Attributes = Attributes(attributes.ToArray())
        };
    }

    private static IReadOnlyDictionary<string, IReadOnlyList<LdapAttributeValue>> Attributes(
        params (string Name, IReadOnlyList<LdapAttributeValue> Values)[] attributes) =>
        attributes.ToDictionary(
            item => item.Name,
            item => item.Values,
            StringComparer.OrdinalIgnoreCase);

    private static IReadOnlyList<LdapAttributeValue> Text(params string[] values) =>
        values.Select(LdapAttributeValue.FromText).ToArray();

    private static IReadOnlyList<LdapAttributeValue> Binary(params byte[][] values) =>
        values.Select(LdapAttributeValue.FromBytes).ToArray();

    private static byte[] CreateSidBytes(string sid)
    {
        var parts = sid.Split('-');
        var revision = byte.Parse(parts[1], CultureInfo.InvariantCulture);
        var authority = ulong.Parse(parts[2], CultureInfo.InvariantCulture);
        var subAuthorities = parts.Skip(3)
            .Select(part => uint.Parse(part, CultureInfo.InvariantCulture))
            .ToArray();

        var result = new byte[8 + (subAuthorities.Length * 4)];
        result[0] = revision;
        result[1] = checked((byte)subAuthorities.Length);

        for (var index = 0; index < 6; index++)
        {
            result[7 - index] = (byte)(authority >> (index * 8));
        }

        for (var index = 0; index < subAuthorities.Length; index++)
        {
            var value = subAuthorities[index];
            var offset = 8 + (index * 4);
            result[offset] = (byte)value;
            result[offset + 1] = (byte)(value >> 8);
            result[offset + 2] = (byte)(value >> 16);
            result[offset + 3] = (byte)(value >> 24);
        }

        return result;
    }

    private sealed class FakeLdapClientFactory : IReadOnlyLdapClientFactory
    {
        private readonly IReadOnlyLdapClient _client;

        public FakeLdapClientFactory(IReadOnlyLdapClient client)
        {
            _client = client;
        }

        public ValueTask<IReadOnlyLdapClient> CreateAsync(
            string target,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(_client);
        }
    }

    private sealed class MembershipFakeClient : IReadOnlyLdapClient
    {
        private readonly IReadOnlyList<LdapSearchEntry> _supportingEntries;
        private readonly IReadOnlyList<LdapSearchEntry> _groupEntries;
        private readonly IReadOnlyDictionary<string, LdapSearchResult> _baseResponses;

        public MembershipFakeClient(
            IReadOnlyList<LdapSearchEntry> supportingEntries,
            IReadOnlyList<LdapSearchEntry> groupEntries,
            IReadOnlyDictionary<string, LdapSearchResult>? baseResponses = null)
        {
            _supportingEntries = supportingEntries;
            _groupEntries = groupEntries;
            _baseResponses = baseResponses ??
                new Dictionary<string, LdapSearchResult>(StringComparer.OrdinalIgnoreCase);
        }

        public List<LdapSearchRequest> StreamingRequests { get; } = [];
        public int BaseSearchCount { get; private set; }

        public Task<LdapSearchResult> SearchAsync(
            LdapSearchRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            BaseSearchCount++;
            return Task.FromResult(
                _baseResponses.TryGetValue(request.BaseDn, out var response)
                    ? response
                    : new LdapSearchResult([]));
        }

        public async IAsyncEnumerable<LdapSearchEntry> SearchEntriesAsync(
            LdapSearchRequest request,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            StreamingRequests.Add(request);
            var source = request.Filter.Contains("primaryGroupID", StringComparison.Ordinal)
                ? _supportingEntries
                : _groupEntries;

            foreach (var entry in source)
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return entry;
                await Task.Yield();
            }
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _utcNow;

        public FixedTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow() => _utcNow;
    }
}
