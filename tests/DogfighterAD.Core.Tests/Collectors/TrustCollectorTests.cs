using System.Globalization;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class TrustCollectorTests
{
    private static readonly DateTimeOffset FixedNow =
        new(2026, 9, 5, 20, 30, 0, TimeSpan.Zero);

    [Fact]
    public async Task CollectAsync_MapsTrustedDomainAndEvidence()
    {
        var client = new FakeLdapClient(
            new LdapSearchResult([HealthyTrustEntry()]));
        var collector = new TrustCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        var request = Assert.Single(client.Requests);
        Assert.Equal("DC=mini,DC=lab", request.BaseDn);
        Assert.Equal("(objectClass=trustedDomain)", request.Filter);
        Assert.Equal(LdapSearchScope.Subtree, request.Scope);
        Assert.Contains("trustPartner", request.Attributes);
        Assert.Contains("securityIdentifier", request.Attributes);
        Assert.Contains("trustAttributes", request.Attributes);

        var trust = Assert.Single(result.Fragment.Content.Trusts);
        Assert.Equal("mini.lab", trust.SourceDomainDnsName);
        Assert.Equal("partner.lab", trust.TargetDomainDnsName);
        Assert.Equal("S-1-5-21-9-8-7", trust.TargetDomainSid);
        Assert.Equal(3, trust.TrustDirection);
        Assert.Equal(2, trust.TrustType);
        Assert.Equal(8, trust.TrustAttributes);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CollectionCapabilities.DirectoryTrusts, coverage.CapabilityId);
        Assert.Equal(1, coverage.ContractVersion);
        Assert.Equal(CapabilityStatus.Complete, coverage.Status);
        Assert.Equal(1, coverage.ObservedItemCount);
        Assert.Empty(coverage.Issues);

        Assert.Contains(result.Fragment.Observations, fact =>
            fact.Path == "trust.partner" &&
            fact.Value == "partner.lab" &&
            fact.Source.CollectorId == TrustCollector.CollectorId);
        Assert.Contains(result.Fragment.Observations, fact =>
            fact.Path == "trust.targetSid" && fact.Value == "S-1-5-21-9-8-7");
    }

    [Fact]
    public async Task CollectAsync_NoTrustedDomains_IsCompleteWithZeroRelationships()
    {
        var client = new FakeLdapClient(new LdapSearchResult([]));
        var collector = new TrustCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        Assert.Empty(result.Fragment.Content.Trusts);
        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Complete, coverage.Status);
        Assert.Equal(0, coverage.ObservedItemCount);
        Assert.Empty(coverage.Issues);
    }

    [Fact]
    public async Task CollectAsync_InvalidRequiredTrustFields_MakesCoveragePartial()
    {
        var client = new FakeLdapClient(
            new LdapSearchResult(
            [
                new LdapSearchEntry
                {
                    DistinguishedName = "CN=Broken,CN=System,DC=mini,DC=lab",
                    Attributes = Attributes(
                        ("objectGUID", Binary(Guid.Parse("77777777-7777-7777-7777-777777777777").ToByteArray())),
                        ("trustDirection", Text("not-an-integer")),
                        ("trustType", Text("2")),
                        ("trustAttributes", Text("0")))
                }
            ]));

        var collector = new TrustCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        Assert.Empty(result.Fragment.Content.Trusts);
        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Partial, coverage.Status);
        Assert.Contains(coverage.Issues, issue =>
            issue.Code == "collection.trusts.partner-missing");
        Assert.Contains(coverage.Issues, issue =>
            issue.Code == "collection.trusts.direction-invalid");

        Assert.Contains(result.Fragment.Observations, fact =>
            fact.Path == "trust.direction" && fact.Value == "not-an-integer");
    }

    private static CollectionContext CreateContext() =>
        new(
            Guid.Parse("9a48f22d-f263-4f42-9252-a3b1cba92c48"),
            "dc01.mini.lab",
            new HashSet<string>(StringComparer.Ordinal)
            {
                CollectionCapabilities.DirectoryTrusts
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
                    Domains =
                    [
                        new AdDomain
                        {
                            Id = new AdObjectId(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")),
                            DistinguishedName = "DC=mini,DC=lab",
                            Sid = "S-1-5-21-1-2-3",
                            Name = "mini",
                            DnsName = "mini.lab",
                            FunctionalLevel = 7
                        }
                    ]
                }
            });

    private static LdapSearchEntry HealthyTrustEntry() =>
        new()
        {
            DistinguishedName = "CN=partner.lab,CN=System,DC=mini,DC=lab",
            Attributes = Attributes(
                ("objectGUID", Binary(Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").ToByteArray())),
                ("name", Text("partner.lab")),
                ("trustPartner", Text("partner.lab")),
                ("flatName", Text("PARTNER")),
                ("securityIdentifier", Binary(CreateSidBytes("S-1-5-21-9-8-7"))),
                ("trustDirection", Text("3")),
                ("trustType", Text("2")),
                ("trustAttributes", Text("8")),
                ("whenCreated", Text("20260905190000.0Z")),
                ("whenChanged", Text("20260905200000.0Z")))
        };

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
