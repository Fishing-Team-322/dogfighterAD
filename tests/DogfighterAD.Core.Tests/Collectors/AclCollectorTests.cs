using System.Buffers.Binary;
using System.Globalization;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class AclCollectorTests
{
    private static readonly DateTimeOffset FixedNow =
        new(2026, 9, 5, 21, 0, 0, TimeSpan.Zero);

    private static readonly Guid DomainGuid =
        Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

    [Fact]
    public async Task CollectAsync_RequestsOnlyDaclAndMapsAceEvidence()
    {
        var descriptor = BuildDescriptor(
            [BuildStandardAce(0x00, 0x00, 0x00040000, CreateSidBytes("S-1-5-32-544"))]);
        var client = new FakeLdapClient(
            new LdapSearchResult([EntryWithDescriptor(descriptor)]));
        var collector = new AclCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        var request = Assert.Single(client.Requests);
        Assert.Equal("DC=mini,DC=lab", request.BaseDn);
        Assert.Equal(LdapSearchScope.Subtree, request.Scope);
        Assert.Equal(500, request.PageSize);
        Assert.Equal(LdapSecurityDescriptorSections.Dacl, request.SecurityDescriptorSections);
        Assert.Contains("nTSecurityDescriptor", request.Attributes);
        Assert.Contains("objectGUID", request.Attributes);

        var securityDescriptor = Assert.Single(result.Fragment.Content.SecurityDescriptors);
        Assert.Equal(new AdObjectId(DomainGuid), securityDescriptor.TargetObjectId);
        Assert.Equal(AdDaclState.Present, securityDescriptor.DaclState);

        var ace = Assert.Single(result.Fragment.Content.Aces);
        Assert.Equal("S-1-5-32-544", ace.TrusteeSid);
        Assert.Equal(AdAccessControlType.Allow, ace.AccessType);
        Assert.Equal((uint)0x00040000, ace.AccessMask);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CollectionCapabilities.DirectoryAcls, coverage.CapabilityId);
        Assert.Equal(CapabilityStatus.Complete, coverage.Status);
        Assert.Equal(1, coverage.ObservedItemCount);
        Assert.Empty(coverage.Issues);

        Assert.Contains(result.Fragment.Observations, fact =>
            fact.Path == "securityDescriptor.daclState" &&
            fact.Value == nameof(AdDaclState.Present));
        Assert.Contains(result.Fragment.Observations, fact =>
            fact.Path.EndsWith(".trusteeSid", StringComparison.Ordinal) &&
            fact.Value == "S-1-5-32-544");
    }

    [Fact]
    public async Task CollectAsync_MissingSecurityDescriptor_IsPartial()
    {
        var entry = new LdapSearchEntry
        {
            DistinguishedName = "DC=mini,DC=lab",
            Attributes = Attributes(
                ("objectGUID", Binary(DomainGuid.ToByteArray())))
        };
        var client = new FakeLdapClient(new LdapSearchResult([entry]));
        var collector = new AclCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        Assert.Empty(result.Fragment.Content.SecurityDescriptors);
        Assert.Empty(result.Fragment.Content.Aces);
        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Partial, coverage.Status);
        Assert.Contains(coverage.Issues, issue =>
            issue.Code == "collection.acls.security-descriptor-unavailable");
    }

    [Fact]
    public async Task CollectAsync_MissingExpectedTarget_IsPartial()
    {
        var client = new FakeLdapClient(new LdapSearchResult([]));
        var collector = new AclCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(),
            CancellationToken.None);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Partial, coverage.Status);
        Assert.Contains(coverage.Issues, issue =>
            issue.Code == "collection.acls.targets-missing" &&
            issue.Message.Contains("1 expected", StringComparison.Ordinal));
    }

    private static CollectionContext CreateContext() =>
        new(
            Guid.Parse("d95bf637-cab0-47d3-9da9-dddb4a08a9fd"),
            "dc01.mini.lab",
            new HashSet<string>(StringComparer.Ordinal)
            {
                CollectionCapabilities.DirectoryAcls
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
                            Id = new AdObjectId(DomainGuid),
                            DistinguishedName = "DC=mini,DC=lab",
                            Sid = "S-1-5-21-1-2-3",
                            DnsName = "mini.lab",
                            FunctionalLevel = 7
                        }
                    ]
                }
            });

    private static LdapSearchEntry EntryWithDescriptor(byte[] descriptor) =>
        new()
        {
            DistinguishedName = "DC=mini,DC=lab",
            Attributes = Attributes(
                ("objectGUID", Binary(DomainGuid.ToByteArray())),
                ("nTSecurityDescriptor", Binary(descriptor)))
        };

    private static IReadOnlyDictionary<string, IReadOnlyList<LdapAttributeValue>> Attributes(
        params (string Name, IReadOnlyList<LdapAttributeValue> Values)[] values) =>
        values.ToDictionary(
            item => item.Name,
            item => item.Values,
            StringComparer.OrdinalIgnoreCase);

    private static IReadOnlyList<LdapAttributeValue> Binary(params byte[][] values) =>
        values.Select(LdapAttributeValue.FromBytes).ToArray();

    private static byte[] BuildDescriptor(IReadOnlyList<byte[]> aces)
    {
        const ushort selfRelativeAndDaclPresent = 0x8004;
        var aclSize = 8 + aces.Sum(ace => ace.Length);
        var acl = new byte[aclSize];
        acl[0] = 4;
        BinaryPrimitives.WriteUInt16LittleEndian(acl.AsSpan(2, 2), checked((ushort)aclSize));
        BinaryPrimitives.WriteUInt16LittleEndian(acl.AsSpan(4, 2), checked((ushort)aces.Count));

        var cursor = 8;
        foreach (var ace in aces)
        {
            ace.CopyTo(acl, cursor);
            cursor += ace.Length;
        }

        var descriptor = new byte[20 + aclSize];
        descriptor[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(
            descriptor.AsSpan(2, 2),
            selfRelativeAndDaclPresent);
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(16, 4), 20);
        acl.CopyTo(descriptor, 20);
        return descriptor;
    }

    private static byte[] BuildStandardAce(
        byte aceType,
        byte aceFlags,
        uint accessMask,
        byte[] sid)
    {
        var ace = new byte[8 + sid.Length];
        ace[0] = aceType;
        ace[1] = aceFlags;
        BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2, 2), checked((ushort)ace.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(4, 4), accessMask);
        sid.CopyTo(ace, 8);
        return ace;
    }

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
            BinaryPrimitives.WriteUInt32LittleEndian(
                result.AsSpan(8 + (index * 4), 4),
                subAuthorities[index]);
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
