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
            CancellationToken.None);

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
    public async Task ReadAsync_GroupWithNoMemberAttribute_IsCompleteAndEmpty()
    {
        var client = new RangeFakeClient(null);
        var result = await new GroupMemberRangeReader().ReadAsync(
            client,
            Entry("CN=Empty,DC=mini,DC=lab"),
            CancellationToken.None);

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
            CancellationToken.None);

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
        private readonly LdapSearchEntry? _response;

        public RangeFakeClient(LdapSearchEntry? response)
        {
            _response = response;
        }

        public List<LdapSearchRequest> Requests { get; } = [];

        public Task<LdapSearchResult> SearchAsync(
            LdapSearchRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(request);
            return Task.FromResult(
                new LdapSearchResult(_response is null ? [] : [_response]));
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
