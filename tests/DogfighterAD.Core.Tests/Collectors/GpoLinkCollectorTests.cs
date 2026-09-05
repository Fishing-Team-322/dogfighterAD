using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class GpoLinkCollectorTests
{
    private static readonly AdObjectId DomainId = new(Guid.Parse("11111111-1111-1111-1111-111111111111"));
    private static readonly AdObjectId OuId = new(Guid.Parse("22222222-2222-2222-2222-222222222222"));
    private static readonly AdObjectId FirstGpoId = new(Guid.Parse("33333333-3333-3333-3333-333333333333"));
    private static readonly AdObjectId SecondGpoId = new(Guid.Parse("44444444-4444-4444-4444-444444444444"));

    private const string DomainDn = "DC=mini,DC=lab";
    private const string OuDn = "OU=Servers,DC=mini,DC=lab";
    private const string FirstGpoDn = "CN={AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA},CN=Policies,CN=System,DC=mini,DC=lab";
    private const string SecondGpoDn = "CN={BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB},CN=Policies,CN=System,DC=mini,DC=lab";

    [Fact]
    public async Task CollectAsync_PreservesLinkOrderOptionsAndBlockInheritance()
    {
        var client = new FakeClient(
        [
            Entry(
                DomainId,
                DomainDn,
                ("gPLink", Text(
                    $"[LDAP://{FirstGpoDn};0][LDAP://{SecondGpoDn};3]")),
                ("gPOptions", Text("0"))),
            Entry(
                OuId,
                OuDn,
                ("gPLink", Text($"[LDAP://{SecondGpoDn};2]")),
                ("gPOptions", Text("1")))
        ]);

        var collector = new GpoLinkCollector(
            new FakeFactory(client),
            new FixedTimeProvider(new DateTimeOffset(2026, 9, 5, 20, 30, 0, TimeSpan.Zero)));

        var result = await collector.CollectAsync(CreateContext(), CancellationToken.None);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Complete, coverage.Status);
        Assert.Equal(3, coverage.ObservedItemCount);
        Assert.Empty(coverage.Issues);

        var links = result.Fragment.Content.GroupPolicyLinks;
        Assert.Equal(3, links.Count);

        var domainLinks = links.Where(link => link.ContainerId == DomainId).OrderBy(link => link.Order).ToArray();
        Assert.Equal(2, domainLinks.Length);
        Assert.Equal(FirstGpoId, domainLinks[0].GpoId);
        Assert.Equal(1, domainLinks[0].Order);
        Assert.True(domainLinks[0].Enabled);
        Assert.False(domainLinks[0].Enforced);
        Assert.Equal(0, domainLinks[0].RawOptions);

        Assert.Equal(SecondGpoId, domainLinks[1].GpoId);
        Assert.Equal(2, domainLinks[1].Order);
        Assert.False(domainLinks[1].Enabled);
        Assert.True(domainLinks[1].Enforced);
        Assert.Equal(3, domainLinks[1].RawOptions);

        var policies = result.Fragment.Content.GroupPolicyContainerPolicies;
        Assert.Equal(2, policies.Count);
        Assert.False(policies.Single(item => item.ContainerId == DomainId).BlockInheritance);
        Assert.True(policies.Single(item => item.ContainerId == OuId).BlockInheritance);
    }

    [Fact]
    public void ParseLinks_InvalidSyntaxIsRejected()
    {
        var result = GpoLinkCollector.ParseLinks("LDAP://CN=Broken;0");

        Assert.False(result.Success);
        Assert.Empty(result.Links);
        Assert.NotNull(result.Error);
    }

    private static CollectionContext CreateContext() =>
        new(
            Guid.Parse("55555555-5555-5555-5555-555555555555"),
            "dc01.mini.lab",
            new HashSet<string>(StringComparer.Ordinal)
            {
                CollectionCapabilities.GroupPolicyLinks
            },
            new SnapshotFragment
            {
                Content = new SnapshotContent
                {
                    DirectoryEnvironment = new DirectoryEnvironment
                    {
                        DnsHostName = "dc01.mini.lab",
                        DefaultNamingContext = DomainDn,
                        ConfigurationNamingContext = "CN=Configuration,DC=mini,DC=lab",
                        SchemaNamingContext = "CN=Schema,CN=Configuration,DC=mini,DC=lab",
                        RootDomainNamingContext = DomainDn
                    },
                    Domains =
                    [
                        new AdDomain
                        {
                            Id = DomainId,
                            DistinguishedName = DomainDn,
                            DnsName = "mini.lab"
                        }
                    ],
                    OrganizationalUnits =
                    [
                        new AdOrganizationalUnit
                        {
                            Id = OuId,
                            DistinguishedName = OuDn
                        }
                    ],
                    GroupPolicyObjects =
                    [
                        new AdGroupPolicyObject
                        {
                            Id = FirstGpoId,
                            DistinguishedName = FirstGpoDn,
                            GpoGuid = Guid.Parse("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")
                        },
                        new AdGroupPolicyObject
                        {
                            Id = SecondGpoId,
                            DistinguishedName = SecondGpoDn,
                            GpoGuid = Guid.Parse("BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")
                        }
                    ]
                }
            });

    private static LdapSearchEntry Entry(
        AdObjectId id,
        string dn,
        params (string Name, IReadOnlyList<LdapAttributeValue> Values)[] attributes)
    {
        var all = new List<(string Name, IReadOnlyList<LdapAttributeValue> Values)>
        {
            ("objectGUID", [LdapAttributeValue.FromBytes(id.Value.ToByteArray())])
        };
        all.AddRange(attributes);

        return new LdapSearchEntry
        {
            DistinguishedName = dn,
            Attributes = all.ToDictionary(
                item => item.Name,
                item => item.Values,
                StringComparer.OrdinalIgnoreCase)
        };
    }

    private static IReadOnlyList<LdapAttributeValue> Text(string value) =>
        [LdapAttributeValue.FromText(value)];

    private sealed class FakeFactory : IReadOnlyLdapClientFactory
    {
        private readonly IReadOnlyLdapClient _client;

        public FakeFactory(IReadOnlyLdapClient client)
        {
            _client = client;
        }

        public ValueTask<IReadOnlyLdapClient> CreateAsync(string target, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(_client);
        }
    }

    private sealed class FakeClient : IReadOnlyLdapClient
    {
        private readonly IReadOnlyList<LdapSearchEntry> _entries;

        public FakeClient(IReadOnlyList<LdapSearchEntry> entries)
        {
            _entries = entries;
        }

        public Task<LdapSearchResult> SearchAsync(
            LdapSearchRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new LdapSearchResult(_entries));
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
