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
        Assert.Equal(CapabilityContractCatalog.GetCurrentVersion(CollectionCapabilities.DirectoryMemberships), coverage.ContractVersion);
        Assert.Equal(CapabilityStatus.Complete, coverage.Status);
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
            baseSearchResponses: []);

        var collector = new GroupMembershipCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Partial, coverage.Status);
        Assert.Contains(coverage.Issues, issue => issue.Code == CollectionIssueCode.UnresolvedReference);
    }

    [Fact]
    public async Task CollectAsync_BaseLookupResolvesMemberOutsideSupportingQuery()
    {
        const string movedUserDn = "CN=Moved,OU=Legacy,DC=mini,DC=lab";
        var movedUserId = new AdObjectId(Guid.Parse("77777777-7777-7777-7777-777777777777"));
        var client = new MembershipFakeClient(
            supportingEntries: [],
            groupEntries:
            [
                GroupMemberEntry(DomainUsersId, DomainUsersDn),
                GroupMemberEntry(DomainComputersId, DomainComputersDn),
                GroupMemberEntry(AuditGroupId, AuditGroupDn, movedUserDn)
            ],
            baseSearchResponses:
            [
                new LdapSearchResult
                {
                    Entries =
                    [
                        new LdapEntry
                        {
                            DistinguishedName = movedUserDn,
                            Attributes = new Dictionary<string, IReadOnlyList<LdapValue>>(StringComparer.OrdinalIgnoreCase)
                            {
                                ["objectGUID"] = [LdapValue.FromBytes(movedUserId.Value.ToByteArray())],
                                ["objectSid"] = [LdapValue.FromBytes(CreateSidBytes(21, 1, 2, 3, 2100))],
                                ["objectClass"] = [LdapValue.FromString("top"), LdapValue.FromString("person"), LdapValue.FromString("user")]
                            }
                        }
                    ]
                }
            ]);

        var collector = new GroupMembershipCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(CreateContext(), CancellationToken.None);

        Assert.Equal(1, client.BaseSearchCount);
        Assert.Contains(result.Fragment.Content.GroupMemberships, item =>
            item.GroupId == AuditGroupId &&
            item.MemberId == movedUserId &&
            item.Source == MembershipSource.Explicit);
    }

    [Fact]
    public async Task CollectAsync_BaseLookupFails_MakesCoveragePartial()
    {
        const string missingDn = "CN=Missing,OU=Legacy,DC=mini,DC=lab";
        var client = new MembershipFakeClient(
            supportingEntries: [],
            groupEntries:
            [
                GroupMemberEntry(DomainUsersId, DomainUsersDn),
                GroupMemberEntry(DomainComputersId, DomainComputersDn),
                GroupMemberEntry(AuditGroupId, AuditGroupDn, missingDn)
            ],
            baseSearchResponses: [new LdapSearchResult()]);

        var collector = new GroupMembershipCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(CreateContext(), CancellationToken.None);

        Assert.Equal(1, client.BaseSearchCount);
        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Partial, coverage.Status);
        Assert.Contains(coverage.Issues, issue => issue.Code == CollectionIssueCode.UnresolvedReference);
    }

    [Fact]
    public async Task CollectAsync_UnexpectedFailure_ReturnsFailedCoverage()
    {
        var client = new MembershipFakeClient(
            supportingEntries: [],
            groupEntries: [],
            failure: new LdapTransportException(LdapFailureKind.Protocol, "boom"));

        var collector = new GroupMembershipCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(CreateContext(), CancellationToken.None);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Failed, coverage.Status);
        Assert.Contains(coverage.Issues, issue => issue.Code == CollectionIssueCode.ProtocolError);
    }

    private static CollectionContext CreateContext() => new()
    {
        InitialTarget = "dc01.mini.lab",
        RequestedCapabilities = [CollectionCapabilities.DirectoryMemberships],
        Metadata = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [CollectionMetadataKeys.DefaultNamingContext] = "DC=mini,DC=lab"
        }
    };

    private static LdapEntry PrincipalEntry(
        AdObjectId id,
        string dn,
        string sid,
        int primaryGroupId,
        string objectClass) =>
        new()
        {
            DistinguishedName = dn,
            Attributes = new Dictionary<string, IReadOnlyList<LdapValue>>(StringComparer.OrdinalIgnoreCase)
            {
                ["objectGUID"] = [LdapValue.FromBytes(id.Value.ToByteArray())],
                ["objectSid"] = [LdapValue.FromBytes(CreateSidBytes(ParseSidSubAuthorities(sid)))],
                ["primaryGroupID"] = [LdapValue.FromString(primaryGroupId.ToString(CultureInfo.InvariantCulture))],
                ["objectClass"] = [LdapValue.FromString("top"), LdapValue.FromString(objectClass)]
            }
        };

    private static LdapEntry ForeignSecurityPrincipalEntry() =>
        new()
        {
            DistinguishedName = FspDn,
            Attributes = new Dictionary<string, IReadOnlyList<LdapValue>>(StringComparer.OrdinalIgnoreCase)
            {
                ["objectGUID"] = [LdapValue.FromBytes(FspId.Value.ToByteArray())],
                ["objectSid"] = [LdapValue.FromBytes(CreateSidBytes(21, 9, 9, 9, 1001))],
                ["objectClass"] = [LdapValue.FromString("top"), LdapValue.FromString("foreignSecurityPrincipal")]
            }
        };

    private static LdapEntry GroupMemberEntry(
        AdObjectId id,
        string dn,
        params string[] members) =>
        new()
        {
            DistinguishedName = dn,
            Attributes = new Dictionary<string, IReadOnlyList<LdapValue>>(StringComparer.OrdinalIgnoreCase)
            {
                ["objectGUID"] = [LdapValue.FromBytes(id.Value.ToByteArray())],
                ["member"] = members.Select(LdapValue.FromString).ToArray()
            }
        };

    private static byte[] CreateSidBytes(params uint[] subAuthorities)
    {
        var bytes = new byte[8 + (subAuthorities.Length * 4)];
        bytes[0] = 1;
        bytes[1] = checked((byte)subAuthorities.Length);
        bytes[7] = 5;

        for (var index = 0; index < subAuthorities.Length; index++)
        {
            var offset = 8 + (index * 4);
            var value = subAuthorities[index];
            bytes[offset] = (byte)(value & 0xFF);
            bytes[offset + 1] = (byte)((value >> 8) & 0xFF);
            bytes[offset + 2] = (byte)((value >> 16) & 0xFF);
            bytes[offset + 3] = (byte)((value >> 24) & 0xFF);
        }

        return bytes;
    }

    private static uint[] ParseSidSubAuthorities(string sid)
    {
        var parts = sid.Split('-');
        return parts.Skip(3).Select(part => uint.Parse(part, CultureInfo.InvariantCulture)).ToArray();
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class MembershipFakeClient : ILdapClient
    {
        private readonly IReadOnlyList<LdapEntry> _supportingEntries;
        private readonly IReadOnlyList<LdapEntry> _groupEntries;
        private readonly Queue<LdapSearchResult> _baseSearchResponses;
        private readonly Exception? _failure;

        public MembershipFakeClient(
            IReadOnlyList<LdapEntry> supportingEntries,
            IReadOnlyList<LdapEntry> groupEntries,
            IReadOnlyList<LdapSearchResult>? baseSearchResponses = null,
            Exception? failure = null)
        {
            _supportingEntries = supportingEntries;
            _groupEntries = groupEntries;
            _baseSearchResponses = new Queue<LdapSearchResult>(baseSearchResponses ?? []);
            _failure = failure;
        }

        public List<LdapSearchRequest> StreamingRequests { get; } = [];
        public int BaseSearchCount { get; private set; }

        public Task<LdapSearchResult> SearchAsync(LdapSearchRequest request, CancellationToken cancellationToken)
        {
            if (_failure is not null)
            {
                throw _failure;
            }

            if (request.Scope == LdapSearchScope.Base)
            {
                BaseSearchCount++;
                return Task.FromResult(_baseSearchResponses.Count > 0
                    ? _baseSearchResponses.Dequeue()
                    : new LdapSearchResult());
            }

            throw new InvalidOperationException("Unexpected non-streaming LDAP request in membership test.");
        }

        public async IAsyncEnumerable<LdapSearchPage> SearchPagesAsync(
            LdapSearchRequest request,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            StreamingRequests.Add(request);
            if (_failure is not null)
            {
                throw _failure;
            }

            var entries = request.Filter.Contains("objectCategory=group", StringComparison.OrdinalIgnoreCase)
                ? _groupEntries
                : _supportingEntries;

            await Task.Yield();
            yield return new LdapSearchPage { Entries = entries };
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
