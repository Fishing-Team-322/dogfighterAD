using DogfighterAD.Collectors.ActiveDirectory.Ldap;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class LdapStreamingContractTests
{
    [Fact]
    public async Task DefaultStreamingFallback_EnumeratesBufferedSearchResult()
    {
        var fake = new BufferedOnlyFakeClient(
            new LdapSearchResult(
            [
                CreateEntry("CN=one,DC=mini,DC=lab"),
                CreateEntry("CN=two,DC=mini,DC=lab")
            ]));
        IReadOnlyLdapClient client = fake;

        var entries = new List<LdapSearchEntry>();
        await foreach (var entry in client.SearchEntriesAsync(
            new LdapSearchRequest
            {
                BaseDn = "DC=mini,DC=lab",
                Filter = "(objectClass=*)",
                Scope = LdapSearchScope.Subtree,
                PageSize = 1000
            },
            CancellationToken.None))
        {
            entries.Add(entry);
        }

        Assert.Equal(2, entries.Count);
        Assert.Equal("CN=one,DC=mini,DC=lab", entries[0].DistinguishedName);
        Assert.Equal("CN=two,DC=mini,DC=lab", entries[1].DistinguishedName);
        Assert.Equal(1, fake.SearchCount);
    }

    private static LdapSearchEntry CreateEntry(string distinguishedName) =>
        new()
        {
            DistinguishedName = distinguishedName,
            Attributes = new Dictionary<string, IReadOnlyList<LdapAttributeValue>>(
                StringComparer.OrdinalIgnoreCase)
        };

    private sealed class BufferedOnlyFakeClient : IReadOnlyLdapClient
    {
        private readonly LdapSearchResult _result;

        public BufferedOnlyFakeClient(LdapSearchResult result)
        {
            _result = result;
        }

        public int SearchCount { get; private set; }

        public Task<LdapSearchResult> SearchAsync(
            LdapSearchRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SearchCount++;
            return Task.FromResult(_result);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
