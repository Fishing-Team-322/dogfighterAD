using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class GroupMemberRangeReaderTests
{
    [Fact]
    public async Task ReadAsync_FollowsActiveDirectoryMemberRangesUntilTerminalChunk()
    {
        var groupDn = "CN=Big Group,OU=Groups,DC=mini,DC=lab";
        var initial = Entry(
            groupDn,
            ("member;range=0-1", Text(
                "CN=One,DC=mini,DC=lab",
                "CN=Two,DC=mini,DC=lab")));

        var client = new RangeFakeClient(
            Entry(
                groupDn,
                ("member;range=2-*", Text("CN=Three,DC=mini,DC=lab"))));

        var result = await new GroupMemberRangeReader().ReadAsync(
            client,
            initial,
            TestContext.Current.CancellationToken);

        Assert.True(result.Complete);
        Assert.Equal(3, result.Members.Count);
        Assert.Contains("CN=One,DC=mini,DC=lab", result.Members);
        Assert.Contains("CN=Two,DC=mini,DC=lab", result.Members);
        Assert.Contains("CN=Three,DC=mini,DC=lab", result.Members);

        var request = Assert.Single(client.Requests);
        Assert.Equal(groupDn, request.BaseDn);
        Assert.Equal(LdapSearchScope.Base, request.Scope);
        Assert.Equal(["member;range=2-*"], request.Attributes);
    }

    [Fact]
    public async Task ReadAsync_EmptyBaseAttributeDoesNotHidePopulatedRange()
    {
        var groupDn = "CN=Large Group,DC=mini,DC=lab";
        var initial = Entry(
            groupDn,
            ("member", Text()),
            ("member;range=0-1", Text(
                "CN=One,DC=mini,DC=lab",
                "CN=Two,DC=mini,DC=lab")));
        var client = new RangeFakeClient(
            Entry(
                groupDn,
                ("member;range=2-*", Text("CN=Three,DC=mini,DC=lab"))));

        var result = await new GroupMemberRangeReader().ReadAsync(
            client,
            initial,
            TestContext.Current.CancellationToken);

        Assert.True(result.Complete, result.Error);
        Assert.Equal(3, result.Members.Count);
        Assert.Contains("CN=Three,DC=mini,DC=lab", result.Members);
        var request = Assert.Single(client.Requests);
        Assert.Equal(["member;range=2-*"], request.Attributes);
    }

    [Fact]
    public async Task ReadAsync_EmptyRequestedPlaceholderDoesNotHideActualContinuationRange()
    {
        var groupDn = "CN=Large Group,DC=mini,DC=lab";
        var initial = Entry(
            groupDn,
            ("member;range=0-1", Text(
                "CN=One,DC=mini,DC=lab",
                "CN=Two,DC=mini,DC=lab")));
        var client = new RangeFakeClient(
            Entry(
                groupDn,
                ("member;range=2-*", Text()),
                ("member;range=2-3", Text(
                    "CN=Three,DC=mini,DC=lab",
                    "CN=Four,DC=mini,DC=lab"))),
            Entry(
                groupDn,
                ("member;range=4-*", Text("CN=Five,DC=mini,DC=lab"))));

        var result = await new GroupMemberRangeReader().ReadAsync(
            client,
            initial,
            TestContext.Current.CancellationToken);

        Assert.True(result.Complete, result.Error);
        Assert.Equal(5, result.Members.Count);
        Assert.Equal(2, client.Requests.Count);
        Assert.Equal(["member;range=2-*"], client.Requests[0].Attributes);
        Assert.Equal(["member;range=4-*"], client.Requests[1].Attributes);
    }

    [Fact]
    public async Task ReadAsync_GappedRangeIsReportedAsIncomplete()
    {
        var groupDn = "CN=Broken,DC=mini,DC=lab";
        var initial = Entry(
            groupDn,
            ("member;range=0-0", Text("CN=One,DC=mini,DC=lab")));
        var client = new RangeFakeClient(
            Entry(
                groupDn,
                ("member;range=2-*", Text("CN=Three,DC=mini,DC=lab"))));

        var result = await new GroupMemberRangeReader().ReadAsync(
            client,
            initial,
            TestContext.Current.CancellationToken);

        Assert.False(result.Complete);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public async Task ReadAsync_GroupWithNoMemberAttribute_IsCompleteAndEmpty()
    {
        var client = new RangeFakeClient();
        var result = await new GroupMemberRangeReader().ReadAsync(
            client,
            Entry("CN=Empty,DC=mini,DC=lab"),
            TestContext.Current.CancellationToken);

        Assert.True(result.Complete);
        Assert.Empty(result.Members);
        Assert.Empty(client.Requests);
    }

    [Fact]
    public async Task ReadAsync_NonAdvancingRange_IsReportedAsIncomplete()
    {
        var groupDn = "CN=Broken,DC=mini,DC=lab";
        var initial = Entry(
            groupDn,
            ("member;range=0-0", Text("CN=One,DC=mini,DC=lab")));
        var client = new RangeFakeClient(
            Entry(
                groupDn,
                ("member;range=0-*", Text("CN=One,DC=mini,DC=lab"))));

        var result = await new GroupMemberRangeReader().ReadAsync(
            client,
            initial,
            TestContext.Current.CancellationToken);

        Assert.False(result.Complete);
        Assert.NotNull(result.Error);
    }

    private static LdapSearchEntry Entry(
        string distinguishedName,
        params (string Name, IReadOnlyList<LdapAttributeValue> Values)[] attributes) =>
        new()
        {
            DistinguishedName = distinguishedName,
            Attributes = attributes.ToDictionary(
                item => item.Name,
                item => item.Values,
                StringComparer.OrdinalIgnoreCase)
        };

    private static IReadOnlyList<LdapAttributeValue> Text(params string[] values) =>
        values.Select(LdapAttributeValue.FromText).ToArray();

    private sealed class RangeFakeClient : IReadOnlyLdapClient
    {
        private readonly Queue<LdapSearchEntry> _responses;

        public RangeFakeClient(params LdapSearchEntry[] responses)
        {
            _responses = new Queue<LdapSearchEntry>(responses);
        }

        public List<LdapSearchRequest> Requests { get; } = [];

        public Task<LdapSearchResult> SearchAsync(
            LdapSearchRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(request);
            if (_responses.Count == 0)
            {
                return Task.FromResult(new LdapSearchResult([]));
            }

            return Task.FromResult(new LdapSearchResult([_responses.Dequeue()]));
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
