using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class DomainMetadataCollectorTests
{
    private static readonly DateTimeOffset FixedNow =
        new(2026, 9, 5, 19, 40, 0, TimeSpan.Zero);

    private static readonly Guid DomainGuid =
        Guid.Parse("11111111-2222-3333-4444-555555555555");

    [Fact]
    public async Task CollectAsync_MapsDomainMetadataAndUsesDiscoveredNamingContext()
    {
        var client = new FakeLdapClient(CreateHealthyDomainResult());
        var collector = new DomainMetadataCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        var request = Assert.Single(client.Requests);
        Assert.Equal("DC=mini,DC=lab", request.BaseDn);
        Assert.Equal("(objectClass=domainDNS)", request.Filter);
        Assert.Equal(LdapSearchScope.Base, request.Scope);
        Assert.Contains("objectGUID", request.Attributes);
        Assert.Contains("objectSid", request.Attributes);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CollectionCapabilities.DirectoryDomains, coverage.CapabilityId);
        Assert.Equal(1, coverage.ContractVersion);
        Assert.Equal(CapabilityStatus.Complete, coverage.Status);
        Assert.Empty(coverage.Issues);

        var domain = Assert.Single(result.Fragment.Content.Domains);
        Assert.Equal(new AdObjectId(DomainGuid), domain.Id);
        Assert.Equal("DC=mini,DC=lab", domain.DistinguishedName);
        Assert.Equal("mini.lab", domain.DnsName);
        Assert.Equal("S-1-5-21-1-2-3", domain.Sid);
        Assert.Equal(7, domain.FunctionalLevel);
        Assert.Equal("mini", domain.Name);

        Assert.Contains(result.Fragment.Observations,
            fact => fact.Path == "domain.objectSid" && fact.Value == "S-1-5-21-1-2-3");
        Assert.Contains(result.Fragment.Observations,
            fact => fact.Path == "domain.functionalLevel" && fact.Value == "7");
    }

    [Fact]
    public async Task CollectAsync_MissingSid_IsPartialNotClean()
    {
        var healthy = Assert.Single(CreateHealthyDomainResult().Entries);
        var attributes = new Dictionary<string, IReadOnlyList<LdapAttributeValue>>(
            healthy.Attributes,
            StringComparer.OrdinalIgnoreCase);
        attributes.Remove("objectSid");

        var collector = new DomainMetadataCollector(
            new FakeLdapClientFactory(
                new FakeLdapClient(new LdapSearchResult([healthy with { Attributes = attributes }]))),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Partial, coverage.Status);
        Assert.Contains(coverage.Issues, issue => issue.Code == "collection.domain.sid-missing");
        Assert.Single(result.Fragment.Content.Domains);
    }

    [Fact]
    public async Task CollectAsync_MissingRootDseState_FailsWithoutLdapRequest()
    {
        var client = new FakeLdapClient(CreateHealthyDomainResult());
        var collector = new DomainMetadataCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var context = CreateContext() with
        {
            AvailableData = new SnapshotFragment()
        };

        var result = await collector.CollectAsync(context, CancellationToken.None);

        Assert.Empty(client.Requests);
        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Failed, coverage.Status);
        Assert.Equal(
            "collection.domain.default-naming-context-unavailable",
            Assert.Single(coverage.Issues).Code);
    }

    private static CollectionContext CreateContext() =>
        new(
            Guid.Parse("4a61f40d-8524-4a70-a8f6-9739e9658af2"),
            "dc01.mini.lab",
            new HashSet<string>(StringComparer.Ordinal)
            {
                CollectionCapabilities.DirectoryDomains
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
                    }
                },
                Coverage =
                [
                    new CapabilityCoverage
                    {
                        CapabilityId = CollectionCapabilities.DirectoryCore,
                        ContractVersion = 1,
                        Status = CapabilityStatus.Complete,
                        StartedAt = FixedNow,
                        CompletedAt = FixedNow
                    }
                ]
            });

    private static LdapSearchResult CreateHealthyDomainResult() =>
        new(
        [
            new LdapSearchEntry
            {
                DistinguishedName = "DC=mini,DC=lab",
                Attributes = new Dictionary<string, IReadOnlyList<LdapAttributeValue>>(
                    StringComparer.OrdinalIgnoreCase)
                {
                    ["objectGUID"] = Binary(DomainGuid.ToByteArray()),
                    ["objectSid"] = Binary(CreateSidBytes()),
                    ["name"] = Text("mini"),
                    ["msDS-Behavior-Version"] = Text("7"),
                    ["whenCreated"] = Text("20260101120000.0Z"),
                    ["whenChanged"] = Text("20260905180000.0Z")
                }
            }
        ]);

    private static byte[] CreateSidBytes() =>
    [
        1, 4,
        0, 0, 0, 0, 0, 5,
        21, 0, 0, 0,
        1, 0, 0, 0,
        2, 0, 0, 0,
        3, 0, 0, 0
    ];

    private static IReadOnlyList<LdapAttributeValue> Text(params string[] values) =>
        values.Select(LdapAttributeValue.FromText).ToArray();

    private static IReadOnlyList<LdapAttributeValue> Binary(params byte[][] values) =>
        values.Select(LdapAttributeValue.FromBytes).ToArray();

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

    private sealed class FakeLdapClient : IReadOnlyLdapClient
    {
        private readonly LdapSearchResult _result;

        public FakeLdapClient(LdapSearchResult result)
        {
            _result = result;
        }

        public List<LdapSearchRequest> Requests { get; } = [];

        public Task<LdapSearchResult> SearchAsync(
            LdapSearchRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(request);
            return Task.FromResult(_result);
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
