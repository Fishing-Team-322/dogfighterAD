using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class LdapAbsenceProofTests
{
    private static readonly ParsedDaclAce PublicRead = new("S-1-5-11", AdAccessControlType.Allow, 0x10, 0, null, null, false);
    private static ParsedDacl Dacl(params ParsedDaclAce[] aces) => ParsedDacl.Success(0x8004, AdDaclState.Present, aces);

    [Fact]
    public void PublicUnconditionalReadRequiresAuthentication()
    {
        Assert.True(LdapAttributeAbsenceProof.HasUnconditionalRead(Dacl(PublicRead), true));
        Assert.False(LdapAttributeAbsenceProof.HasUnconditionalRead(Dacl(PublicRead), false));
        Assert.True(LdapAttributeAbsenceProof.HasUnconditionalRead(Dacl(PublicRead with { TrusteeSid = "S-1-1-0" }), true));
    }

    [Theory]
    [InlineData(0x10u)]
    [InlineData(0x80000000u)]
    [InlineData(0x10000000u)]
    public void AnyPotentialReadDenyBlocksProof(uint mask)
    {
        var deny = PublicRead with { AccessType = AdAccessControlType.Deny, AccessMask = mask, TrusteeSid = "S-1-5-21-1-2-3-123", ObjectType = Guid.NewGuid() };
        Assert.False(LdapAttributeAbsenceProof.HasUnconditionalRead(Dacl(PublicRead, deny), true));
        Assert.False(LdapAttributeAbsenceProof.HasUnconditionalRead(Dacl(deny, PublicRead), true));
    }

    [Fact]
    public void UnrelatedDenyDoesNotRemoveReadGrant()
    {
        var deny = PublicRead with { AccessType = AdAccessControlType.Deny, AccessMask = 0x100 };
        Assert.True(LdapAttributeAbsenceProof.HasUnconditionalRead(Dacl(PublicRead, deny), true));
    }

    [Fact]
    public void ScopedInheritedOnlyPrivateOrMalformedGrantsAreUnknown()
    {
        foreach (var ace in new[] { PublicRead with { ObjectType = Guid.NewGuid() }, PublicRead with { AceFlags = 8 },
                     PublicRead with { TrusteeSid = "S-1-5-21-1-2-3-123" }, PublicRead with { AceFlags = 0x80 } })
            Assert.False(LdapAttributeAbsenceProof.HasUnconditionalRead(Dacl(ace), true));
        Assert.False(LdapAttributeAbsenceProof.HasUnconditionalRead(ParsedDacl.Failure(0x8004, AdDaclState.Present, true, "unsupported", [PublicRead]), true));
        Assert.False(LdapAttributeAbsenceProof.HasUnconditionalRead(ParsedDacl.Success(0x8004, AdDaclState.Empty, []), true));
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(128, false)]
    [InlineData(512, false)]
    [InlineData(1024, false)]
    [InlineData(-1, false)]
    public async Task SchemaFlagsGateActualAbsence(int flags, bool expected)
    {
        var client = new SchemaClient(flags.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var proof = await LdapAttributeAbsenceProof.CreateAsync(client, "CN=Schema,DC=test", TestContext.Current.CancellationToken);
        var entry = Entry();
        Assert.Equal(expected, proof.Confirm(entry, "servicePrincipalName") is not null);
    }

    [Fact]
    public async Task PresentMalformedAndRangedValuesNeverBecomeAbsent()
    {
        var proof = await LdapAttributeAbsenceProof.CreateAsync(new SchemaClient("0"), "CN=Schema,DC=test", TestContext.Current.CancellationToken);
        foreach (var name in new[] { "servicePrincipalName", "servicePrincipalName;range=0-*" })
        {
            var attributes = Entry().Attributes.ToDictionary(x => x.Key, x => x.Value);
            attributes[name] = [LdapAttributeValue.FromBytes([1])];
            Assert.Null(proof.Confirm(Entry() with { Attributes = attributes }, "servicePrincipalName"));
        }
        Assert.Null(proof.Confirm(Entry() with { Attributes = new Dictionary<string, IReadOnlyList<LdapAttributeValue>>() }, "servicePrincipalName"));
    }

    [Fact]
    public async Task MissingSchemaOrUnauthenticatedClientCannotProveAbsence()
    {
        foreach (var client in new[] { new SchemaClient(null), new SchemaClient("0", false) })
        {
            var proof = await LdapAttributeAbsenceProof.CreateAsync(client, "CN=Schema,DC=test", TestContext.Current.CancellationToken);
            Assert.Null(proof.Confirm(Entry(), "servicePrincipalName"));
        }
    }

    [Fact]
    public void ScopedReadNeedsMatchingObservedSchemaIdentity()
    {
        var attribute = Guid.NewGuid(); var propertySet = Guid.NewGuid();
        var scoped = PublicRead with { ObjectType = propertySet };
        Assert.True(LdapAttributeAbsenceProof.HasUnconditionalRead(Dacl(scoped), true, attribute, propertySet));
        Assert.False(LdapAttributeAbsenceProof.HasUnconditionalRead(Dacl(scoped), true, attribute, Guid.NewGuid()));
        Assert.True(LdapAttributeAbsenceProof.HasUnconditionalRead(Dacl(PublicRead with { ObjectType = attribute }), true, attribute));
        Assert.False(LdapAttributeAbsenceProof.HasUnconditionalRead(Dacl(scoped with { AceFlags = 8 }), true, attribute, propertySet));
    }
    private static LdapSearchEntry Entry()
    {
        // Self-relative descriptor with one unconditional READ_PROPERTY ACE for Authenticated Users.
        byte[] sd = [1,0,4,128, 0,0,0,0, 0,0,0,0, 0,0,0,0, 20,0,0,0,
            2,0,28,0,1,0,0,0, 0,0,20,0,16,0,0,0, 1,1,0,0,0,0,0,5,11,0,0,0];
        return new() { DistinguishedName = "CN=user,DC=test", Attributes = new Dictionary<string, IReadOnlyList<LdapAttributeValue>>
            { ["nTSecurityDescriptor"] = [LdapAttributeValue.FromBytes(sd)] } };
    }

    private sealed class SchemaClient(string? flags, bool authenticated = true) : IReadOnlyLdapClient
    {
        public bool IsAuthenticated => authenticated;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public Task<LdapSearchResult> SearchAsync(LdapSearchRequest request, CancellationToken cancellationToken)
        {
            Assert.Equal(LdapSearchScope.OneLevel, request.Scope);
            var attrs = new Dictionary<string, IReadOnlyList<LdapAttributeValue>> { ["lDAPDisplayName"] = [LdapAttributeValue.FromText("servicePrincipalName")] };
            attrs["schemaIDGUID"] = [LdapAttributeValue.FromBytes(Guid.Parse("11111111-1111-1111-1111-111111111111").ToByteArray())];
            if (flags is not null) attrs["searchFlags"] = [LdapAttributeValue.FromText(flags)];
            return Task.FromResult(new LdapSearchResult([new LdapSearchEntry { DistinguishedName = "CN=spn,CN=Schema,DC=test", Attributes = attrs }]));
        }
    }
}
