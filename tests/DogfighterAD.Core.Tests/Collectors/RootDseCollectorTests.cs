using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class RootDseCollectorTests
{
    private static readonly DateTimeOffset FixedNow =
        new(2026, 9, 5, 19, 30, 0, TimeSpan.Zero);

    [Fact]
    public async Task CollectAsync_MapsDiscoveryAndEmitsCompleteCoverage()
    {
        var client = new FakeLdapClient(CreateHealthyRootDse());
        var factory = new FakeLdapClientFactory(client);
        var collector = new RootDseCollector(factory, new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        Assert.Equal(RootDseCollector.CollectorId, result.CollectorId);
        Assert.Equal(RootDseCollector.CollectorVersion, result.CollectorVersion);
        Assert.Equal("dc01.mini.lab", factory.Target);

        var request = Assert.Single(client.Requests);
        Assert.Equal(string.Empty, request.BaseDn);
        Assert.Equal("(objectClass=*)", request.Filter);
        Assert.Equal(LdapSearchScope.Base, request.Scope);
        Assert.Equal(0, request.PageSize);
        Assert.Contains("defaultNamingContext", request.Attributes);
        Assert.Contains("configurationNamingContext", request.Attributes);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CollectionCapabilities.DirectoryCore, coverage.CapabilityId);
        Assert.Equal(CapabilityStatus.Complete, coverage.Status);
        Assert.Empty(coverage.Issues);
        Assert.Equal(1, coverage.ObservedItemCount);

        Assert.NotNull(result.Fragment.Content.DirectoryEnvironment);
        var environment = result.Fragment.Content.DirectoryEnvironment!;
        Assert.Equal("dc01.mini.lab", environment.DnsHostName);
        Assert.Equal("DC=mini,DC=lab", environment.DefaultNamingContext);
        Assert.Equal("CN=Configuration,DC=mini,DC=lab", environment.ConfigurationNamingContext);
        Assert.Equal("CN=Schema,CN=Configuration,DC=mini,DC=lab", environment.SchemaNamingContext);
        Assert.Contains("DC=mini,DC=lab", environment.NamingContexts);
        Assert.Contains("1.2.840.113556.1.4.800", environment.SupportedCapabilities);

        var defaultNamingContextFact = result.Fragment.Observations.Single(
            fact => fact.Path == "rootDse.defaultNamingContext");

        Assert.Equal("DC=mini,DC=lab", defaultNamingContextFact.Value);
        Assert.Equal("ldap-rootdse:dc01.mini.lab", defaultNamingContextFact.SubjectId);
        Assert.Equal(FixedNow, defaultNamingContextFact.ObservedAt);
        Assert.Equal("ldap", defaultNamingContextFact.Source.SourceKind);
        Assert.Equal("dc01.mini.lab", defaultNamingContextFact.Source.Endpoint);
        Assert.StartsWith("fact:v1:", defaultNamingContextFact.FactId, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CollectAsync_MissingRequiredNamingContext_IsPartialNotClean()
    {
        var healthyResult = CreateHealthyRootDse();
        var rootDseEntry = Assert.Single(healthyResult.Entries);
        var attributes = new Dictionary<string, IReadOnlyList<LdapAttributeValue>>(
            rootDseEntry.Attributes,
            StringComparer.OrdinalIgnoreCase);
        attributes.Remove("configurationNamingContext");

        var client = new FakeLdapClient(
            new LdapSearchResult([rootDseEntry with { Attributes = attributes }]));
        var collector = new RootDseCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Partial, coverage.Status);

        var issue = Assert.Single(coverage.Issues);
        Assert.Equal("collection.rootdse.configuration-naming-context-missing", issue.Code);
        Assert.Equal(CollectionIssueSeverity.Error, issue.Severity);
    }

    [Fact]
    public async Task CollectAsync_UnexpectedEntryCount_IsFailed()
    {
        var client = new FakeLdapClient(
            new LdapSearchResult([]));
        var collector = new RootDseCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Failed, coverage.Status);
        Assert.Equal(0, coverage.ObservedItemCount);
        Assert.Null(result.Fragment.Content.DirectoryEnvironment);
        Assert.Equal("collection.rootdse.invalid-entry-count", Assert.Single(coverage.Issues).Code);
    }

    private static CollectionContext CreateContext() =>
        new(
            Guid.Parse("2f31e457-a961-4045-8357-c80a5bc5ef18"),
            "dc01.mini.lab",
            new HashSet<string>(StringComparer.Ordinal)
            {
                CollectionCapabilities.DirectoryCore
            },
            new SnapshotFragment());

    private static LdapSearchResult CreateHealthyRootDse() =>
        new(
        [
            new LdapSearchEntry
            {
                DistinguishedName = string.Empty,
                Attributes = new Dictionary<string, IReadOnlyList<LdapAttributeValue>>(
                    StringComparer.OrdinalIgnoreCase)
                {
                    ["dnsHostName"] = Text("dc01.mini.lab"),
                    ["defaultNamingContext"] = Text("DC=mini,DC=lab"),
                    ["configurationNamingContext"] = Text("CN=Configuration,DC=mini,DC=lab"),
                    ["schemaNamingContext"] = Text("CN=Schema,CN=Configuration,DC=mini,DC=lab"),
                    ["rootDomainNamingContext"] = Text("DC=mini,DC=lab"),
                    ["namingContexts"] = Text(
                        "CN=Configuration,DC=mini,DC=lab",
                        "DC=mini,DC=lab",
                        "CN=Schema,CN=Configuration,DC=mini,DC=lab"),
                    ["supportedCapabilities"] = Text("1.2.840.113556.1.4.800"),
                    ["supportedControl"] = Text("1.2.840.113556.1.4.319"),
                    ["supportedLDAPVersion"] = Text("3")
                }
            }
        ]);

    private static IReadOnlyList<LdapAttributeValue> Text(params string[] values) =>
        values.Select(LdapAttributeValue.FromText).ToArray();

    private sealed class FakeLdapClientFactory : IReadOnlyLdapClientFactory
    {
        private readonly IReadOnlyLdapClient _client;

        public FakeLdapClientFactory(IReadOnlyLdapClient client)
        {
            _client = client;
        }

        public string? Target { get; private set; }

        public ValueTask<IReadOnlyLdapClient> CreateAsync(
            string target,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Target = target;
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
