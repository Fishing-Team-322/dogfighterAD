using System.Runtime.CompilerServices;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class LdapTextSidRegressionTests
{
    private static readonly DateTimeOffset FixedNow =
        new(2026, 9, 6, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task DirectoryObjectsCollector_BuiltinGroupTextSid_IsNormalizedAndComplete()
    {
        var collector = new DirectoryObjectsCollector(
            new FakeLdapClientFactory(new FakeLdapClient([
                CreateBuiltinGroupEntry("S-1-5-32-544")
            ])),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        var group = Assert.Single(result.Fragment.Content.Groups);
        Assert.Equal("S-1-5-32-544", group.Sid);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CollectionCapabilities.DirectoryGroups, coverage.CapabilityId);
        Assert.Equal(CapabilityStatus.Complete, coverage.Status);
        Assert.Empty(coverage.Issues);
    }

    [Fact]
    public async Task DirectoryObjectsCollector_InvalidTextSid_RemainsPartial()
    {
        var collector = new DirectoryObjectsCollector(
            new FakeLdapClientFactory(new FakeLdapClient([
                CreateBuiltinGroupEntry("not-a-sid")
            ])),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        var group = Assert.Single(result.Fragment.Content.Groups);
        Assert.Null(group.Sid);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Partial, coverage.Status);
        Assert.Contains(coverage.Issues, issue =>
            issue.Code == "collection.directory.sid-missing");
    }

    private static CollectionContext CreateContext() =>
        new(
            Guid.Parse("39653114-3bad-45ae-9bd4-47065b887c43"),
            "dc01.mini.lab",
            new HashSet<string>(StringComparer.Ordinal)
            {
                CollectionCapabilities.DirectoryGroups
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

    private static LdapSearchEntry CreateBuiltinGroupEntry(string sid) =>
        new()
        {
            DistinguishedName = "CN=Administrators,CN=Builtin,DC=mini,DC=lab",
            Attributes = new Dictionary<string, IReadOnlyList<LdapAttributeValue>>(
                StringComparer.OrdinalIgnoreCase)
            {
                ["objectClass"] = Text("top", "group"),
                ["objectGUID"] = Binary(
                    Guid.Parse("55555555-5555-5555-5555-555555555555").ToByteArray()),
                ["objectSid"] = Text(sid),
                ["name"] = Text("Administrators"),
                ["sAMAccountName"] = Text("Administrators"),
                ["groupType"] = Text("-2147483644")
            }
        };

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
        private readonly IReadOnlyList<LdapSearchEntry> _entries;

        public FakeLdapClient(IReadOnlyList<LdapSearchEntry> entries)
        {
            _entries = entries;
        }

        public Task<LdapSearchResult> SearchAsync(
            LdapSearchRequest request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Regression fixture expects streaming search.");

        public async IAsyncEnumerable<LdapSearchEntry> SearchEntriesAsync(
            LdapSearchRequest request,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            foreach (var entry in _entries)
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
