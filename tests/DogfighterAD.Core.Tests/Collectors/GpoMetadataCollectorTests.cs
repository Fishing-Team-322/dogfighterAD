using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class GpoMetadataCollectorTests
{
    private static readonly DateTimeOffset FixedNow =
        new(2026, 9, 5, 21, 30, 0, TimeSpan.Zero);

    [Fact]
    public async Task CollectAsync_MapsGroupPolicyContainerMetadata()
    {
        var objectGuid = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var policyGuid = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var client = new FakeLdapClient(
            new LdapSearchResult(
            [
                new LdapSearchEntry
                {
                    DistinguishedName = $"CN={{{policyGuid:D}}},CN=Policies,CN=System,DC=mini,DC=lab",
                    Attributes = Attributes(
                        ("objectGUID", Binary(objectGuid.ToByteArray())),
                        ("name", Text($"{{{policyGuid:D}}}")),
                        ("displayName", Text("Workstation Baseline")),
                        ("gPCFileSysPath", Text($"\\\\mini.lab\\SYSVOL\\mini.lab\\Policies\\{{{policyGuid:D}}}")),
                        ("versionNumber", Text("65538")),
                        ("flags", Text("2")),
                        ("whenCreated", Text("20260905190000.0Z")),
                        ("whenChanged", Text("20260905200000.0Z")))
                }
            ]));
        var collector = new GpoMetadataCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        var request = Assert.Single(client.Requests);
        Assert.Equal("CN=Policies,CN=System,DC=mini,DC=lab", request.BaseDn);
        Assert.Equal("(objectClass=groupPolicyContainer)", request.Filter);
        Assert.Equal(LdapSearchScope.OneLevel, request.Scope);
        Assert.Equal(500, request.PageSize);

        var gpo = Assert.Single(result.Fragment.Content.GroupPolicyObjects);
        Assert.Equal(new AdObjectId(objectGuid), gpo.Id);
        Assert.Equal(policyGuid, gpo.GpoGuid);
        Assert.Equal("Workstation Baseline", gpo.DisplayName);
        Assert.Equal(65538, gpo.VersionNumber);
        Assert.Equal(2, gpo.Flags);
        Assert.Contains("SYSVOL", gpo.FileSystemPath, StringComparison.OrdinalIgnoreCase);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CollectionCapabilities.GroupPolicyMetadata, coverage.CapabilityId);
        Assert.Equal(CapabilityStatus.Complete, coverage.Status);
        Assert.Equal(1, coverage.ObservedItemCount);
        Assert.Empty(coverage.Issues);

        Assert.Contains(result.Fragment.Observations, fact =>
            fact.Path == "gpo.policyGuid" && fact.Value == policyGuid.ToString("D"));
        Assert.Contains(result.Fragment.Observations, fact =>
            fact.Path == "gpo.flags" && fact.Value == "2");
    }

    [Fact]
    public async Task CollectAsync_InvalidPolicyGuidName_IsPartial()
    {
        var client = new FakeLdapClient(
            new LdapSearchResult(
            [
                new LdapSearchEntry
                {
                    DistinguishedName = "CN=broken,CN=Policies,CN=System,DC=mini,DC=lab",
                    Attributes = Attributes(
                        ("objectGUID", Binary(Guid.Parse("33333333-3333-3333-3333-333333333333").ToByteArray())),
                        ("name", Text("not-a-guid")))
                }
            ]));
        var collector = new GpoMetadataCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        Assert.Empty(result.Fragment.Content.GroupPolicyObjects);
        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Partial, coverage.Status);
        Assert.Contains(coverage.Issues, issue =>
            issue.Code == "collection.gpo.metadata.identity-invalid");
    }

    [Fact]
    public async Task CollectAsync_NoGpos_IsCompleteWithZeroItems()
    {
        var collector = new GpoMetadataCollector(
            new FakeLdapClientFactory(new FakeLdapClient(new LdapSearchResult([]))),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Complete, coverage.Status);
        Assert.Equal(0, coverage.ObservedItemCount);
    }

    private static CollectionContext CreateContext() =>
        new(
            Guid.Parse("eb885b07-1e33-4501-bd16-6b57148445bc"),
            "dc01.mini.lab",
            new HashSet<string>(StringComparer.Ordinal)
            {
                CollectionCapabilities.GroupPolicyMetadata
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
                }
            });

    private static IReadOnlyDictionary<string, IReadOnlyList<LdapAttributeValue>> Attributes(
        params (string Name, IReadOnlyList<LdapAttributeValue> Values)[] values) =>
        values.ToDictionary(item => item.Name, item => item.Values, StringComparer.OrdinalIgnoreCase);

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
