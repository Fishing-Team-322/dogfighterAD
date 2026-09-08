using System.Globalization;
using System.Runtime.CompilerServices;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class DirectoryObjectsCollectorTests
{
    private static readonly DateTimeOffset FixedNow =
        new(2026, 9, 5, 20, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task CollectAsync_UsesOneStreamingSubtreePassForAllRequestedObjectTypes()
    {
        var passwordTimestamp = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        var client = new StreamingFakeLdapClient(
        [
            CreateUserEntry(passwordTimestamp.ToFileTimeUtc()),
            CreateGroupEntry(),
            CreateComputerEntry(passwordTimestamp.ToFileTimeUtc()),
            CreateOuEntry()
        ]);
        var collector = new DirectoryObjectsCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(
                CollectionCapabilities.DirectoryUsers,
                CollectionCapabilities.DirectoryGroups,
                CollectionCapabilities.DirectoryComputers,
                CollectionCapabilities.DirectoryOrganizationalUnits),
            CancellationToken.None);

        var request = Assert.Single(client.Requests);
        Assert.Equal("DC=mini,DC=lab", request.BaseDn);
        Assert.Equal(LdapSearchScope.Subtree, request.Scope);
        Assert.Equal(1000, request.PageSize);
        Assert.True(request.Filter.Contains("(objectCategory=person)", StringComparison.Ordinal));
        Assert.True(request.Filter.Contains("(objectCategory=group)", StringComparison.Ordinal));
        Assert.True(request.Filter.Contains("(objectCategory=computer)", StringComparison.Ordinal));
        Assert.True(request.Filter.Contains("(objectClass=organizationalUnit)", StringComparison.Ordinal));
        Assert.Contains("userAccountControl", request.Attributes);
        Assert.Contains("groupType", request.Attributes);
        Assert.Contains("operatingSystem", request.Attributes);
        Assert.Equal(0, client.BufferedSearchCount);

        Assert.Single(result.Fragment.Content.Users);
        Assert.Single(result.Fragment.Content.Groups);
        Assert.Single(result.Fragment.Content.Computers);
        Assert.Single(result.Fragment.Content.OrganizationalUnits);

        Assert.Equal(4, result.Fragment.Coverage.Count);
        Assert.All(result.Fragment.Coverage, coverage =>
        {
            Assert.Equal(CapabilityStatus.Complete, coverage.Status);
            Assert.Equal(CapabilityContractCatalog.GetCurrentVersion(coverage.CapabilityId), coverage.ContractVersion);
            Assert.Equal(1, coverage.ObservedItemCount);
            Assert.Empty(coverage.Issues);
        });

        var user = Assert.Single(result.Fragment.Content.Users);
        Assert.Equal("alice", user.SamAccountName);
        Assert.Equal(512, user.UserAccountControl);
        Assert.Equal(513, user.PrimaryGroupId);
        Assert.NotNull(user.PasswordLastSet);
        Assert.Equal(passwordTimestamp, user.PasswordLastSet.Value.UtcDateTime);
        Assert.True(user.PasswordMustChangeAtNextLogon is false);
        Assert.True(user.AccountNeverExpires is true);
        Assert.Null(user.AccountExpires);
        Assert.Contains("HTTP/app.mini.lab", user.ServicePrincipalNames);
        Assert.Contains("S-1-5-21-1-2-3-999", user.SidHistory);

        Assert.Contains(
            result.Fragment.Observations,
            fact => fact.Path == "user.accountExpires" &&
                    fact.Value == long.MaxValue.ToString(CultureInfo.InvariantCulture));
        Assert.Contains(
            result.Fragment.Observations,
            fact => fact.Path == "user.pwdLastSet" &&
                    fact.Value == passwordTimestamp.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture));
    }

    [Fact]
    public async Task CollectAsync_UserOnlyProfileAvoidsUnneededGroupAndComputerAttributes()
    {
        var client = new StreamingFakeLdapClient([CreateUserEntry(0)]);
        var collector = new DirectoryObjectsCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(CollectionCapabilities.DirectoryUsers),
            CancellationToken.None);

        var request = Assert.Single(client.Requests);
        Assert.Equal("(&(objectCategory=person)(objectClass=user))", request.Filter);
        Assert.Contains("userPrincipalName", request.Attributes);
        Assert.DoesNotContain("groupType", request.Attributes);
        Assert.DoesNotContain("operatingSystem", request.Attributes);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CollectionCapabilities.DirectoryUsers, coverage.CapabilityId);

        var user = Assert.Single(result.Fragment.Content.Users);
        Assert.True(user.PasswordMustChangeAtNextLogon is true);
    }

    [Fact]
    public async Task CollectAsync_MissingPrincipalSid_IsPartialButRetainsNormalizedObject()
    {
        var entry = CreateUserEntry(0);
        var attributes = new Dictionary<string, IReadOnlyList<LdapAttributeValue>>(
            entry.Attributes,
            StringComparer.OrdinalIgnoreCase);
        attributes.Remove("objectSid");

        var client = new StreamingFakeLdapClient([entry with { Attributes = attributes }]);
        var collector = new DirectoryObjectsCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(CollectionCapabilities.DirectoryUsers),
            CancellationToken.None);

        Assert.Single(result.Fragment.Content.Users);
        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Partial, coverage.Status);
        Assert.Contains(coverage.Issues, issue => issue.Code == "collection.directory.sid-missing");
    }

    private static CollectionContext CreateContext(params string[] capabilities) =>
        new(
            Guid.Parse("15d2b65c-3126-4aaa-9199-c0029e727a51"),
            "dc01.mini.lab",
            new HashSet<string>(capabilities, StringComparer.Ordinal),
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

    private static LdapSearchEntry CreateUserEntry(long passwordLastSet) =>
        new()
        {
            DistinguishedName = "CN=Alice,OU=Users,DC=mini,DC=lab",
            Attributes = Attributes(
                ("objectClass", Text("top", "person", "organizationalPerson", "user")),
                ("objectGUID", Binary(Guid.Parse("11111111-1111-1111-1111-111111111111").ToByteArray())),
                ("objectSid", Binary(CreateSidBytes(21, 1, 2, 3, 1101))),
                ("name", Text("Alice")),
                ("whenCreated", Text("20260101120000.0Z")),
                ("whenChanged", Text("20260901120000.0Z")),
                ("sAMAccountName", Text("alice")),
                ("userPrincipalName", Text("alice@mini.lab")),
                ("userAccountControl", Text("512")),
                ("primaryGroupID", Text("513")),
                ("pwdLastSet", Text(passwordLastSet.ToString(CultureInfo.InvariantCulture))),
                ("lastLogonTimestamp", Text("0")),
                ("accountExpires", Text(long.MaxValue.ToString(CultureInfo.InvariantCulture))),
                ("msDS-SupportedEncryptionTypes", Text("28")),
                ("servicePrincipalName", Text("HTTP/app.mini.lab")),
                ("sIDHistory", Binary(CreateSidBytes(21, 1, 2, 3, 999))),
                ("msDS-AllowedToDelegateTo", Text("cifs/fileserver.mini.lab")))
        };

    private static LdapSearchEntry CreateGroupEntry() =>
        new()
        {
            DistinguishedName = "CN=Audit Team,OU=Groups,DC=mini,DC=lab",
            Attributes = Attributes(
                ("objectClass", Text("top", "group")),
                ("objectGUID", Binary(Guid.Parse("22222222-2222-2222-2222-222222222222").ToByteArray())),
                ("objectSid", Binary(CreateSidBytes(21, 1, 2, 3, 2101))),
                ("name", Text("Audit Team")),
                ("sAMAccountName", Text("Audit Team")),
                ("groupType", Text("-2147483646")))
        };

    private static LdapSearchEntry CreateComputerEntry(long passwordLastSet) =>
        new()
        {
            DistinguishedName = "CN=WS01,OU=Computers,DC=mini,DC=lab",
            Attributes = Attributes(
                ("objectClass", Text("top", "person", "organizationalPerson", "user", "computer")),
                ("objectGUID", Binary(Guid.Parse("33333333-3333-3333-3333-333333333333").ToByteArray())),
                ("objectSid", Binary(CreateSidBytes(21, 1, 2, 3, 3101))),
                ("name", Text("WS01")),
                ("sAMAccountName", Text("WS01$")),
                ("dNSHostName", Text("ws01.mini.lab")),
                ("operatingSystem", Text("Windows 11 Enterprise")),
                ("operatingSystemVersion", Text("10.0")),
                ("userAccountControl", Text("4096")),
                ("pwdLastSet", Text(passwordLastSet.ToString(CultureInfo.InvariantCulture))),
                ("lastLogonTimestamp", Text("0")),
                ("msDS-SupportedEncryptionTypes", Text("28")),
                ("servicePrincipalName", Text("HOST/ws01.mini.lab")))
        };

    private static LdapSearchEntry CreateOuEntry() =>
        new()
        {
            DistinguishedName = "OU=Servers,DC=mini,DC=lab",
            Attributes = Attributes(
                ("objectClass", Text("top", "organizationalUnit")),
                ("objectGUID", Binary(Guid.Parse("44444444-4444-4444-4444-444444444444").ToByteArray())),
                ("name", Text("Servers")))
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

    private static byte[] CreateSidBytes(params uint[] subAuthorities)
    {
        var result = new byte[8 + (subAuthorities.Length * 4)];
        result[0] = 1;
        result[1] = checked((byte)subAuthorities.Length);
        result[7] = 5;

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

    private sealed class StreamingFakeLdapClient : IReadOnlyLdapClient
    {
        private readonly IReadOnlyList<LdapSearchEntry> _entries;

        public StreamingFakeLdapClient(IReadOnlyList<LdapSearchEntry> entries)
        {
            _entries = entries;
        }

        public List<LdapSearchRequest> Requests { get; } = [];
        public int BufferedSearchCount { get; private set; }

        public Task<LdapSearchResult> SearchAsync(
            LdapSearchRequest request,
            CancellationToken cancellationToken)
        {
            BufferedSearchCount++;
            throw new InvalidOperationException("The high-volume collector must use the streaming LDAP API.");
        }

        public async IAsyncEnumerable<LdapSearchEntry> SearchEntriesAsync(
            LdapSearchRequest request,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            Requests.Add(request);
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
