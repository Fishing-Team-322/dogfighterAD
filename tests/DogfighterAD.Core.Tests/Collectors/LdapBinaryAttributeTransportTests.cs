using System.DirectoryServices.Protocols;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class LdapBinaryAttributeTransportTests
{
    private static readonly byte[] BuiltinAdministratorsSid =
    [
        0x01, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        0x20, 0x00, 0x00, 0x00,
        0x20, 0x02, 0x00, 0x00
    ];

    [Theory]
    [InlineData("objectSid")]
    [InlineData("sIDHistory")]
    [InlineData("securityIdentifier")]
    [InlineData("objectGUID")]
    [InlineData("nTSecurityDescriptor")]
    [InlineData("cACertificate")]
    [InlineData("pKIExpirationPeriod")]
    [InlineData("pKIOverlapPeriod")]
    public void MapAttributeValues_KnownBinaryAttribute_PreservesWireBytes(string attributeName)
    {
        var attribute = new DirectoryAttribute(attributeName, BuiltinAdministratorsSid);

        var mapped = SystemLdapClient.MapAttributeValues(attributeName, attribute);

        var value = Assert.Single(mapped);
        Assert.True(value.IsBinary);
        Assert.Null(value.Text);
        Assert.Equal(BuiltinAdministratorsSid, value.Bytes);
    }

    [Fact]
    public void MapAttributeValues_BuiltinSid_RemainsUsableBySidNormalizer()
    {
        var attribute = new DirectoryAttribute("objectSid", BuiltinAdministratorsSid);
        var mapped = SystemLdapClient.MapAttributeValues("objectSid", attribute);
        var entry = new LdapSearchEntry
        {
            DistinguishedName = "CN=Administrators,CN=Builtin,DC=mini,DC=lab",
            Attributes = new Dictionary<string, IReadOnlyList<LdapAttributeValue>>(
                StringComparer.OrdinalIgnoreCase)
            {
                ["objectSid"] = mapped
            }
        };

        var sid = LdapValueConverters.GetSid(entry, "objectSid");

        Assert.Equal("S-1-5-32-544", sid);
    }

    [Fact]
    public void MapAttributeValues_TextAttribute_RemainsText()
    {
        var attribute = new DirectoryAttribute("name", "Administrators");

        var mapped = SystemLdapClient.MapAttributeValues("name", attribute);

        var value = Assert.Single(mapped);
        Assert.False(value.IsBinary);
        Assert.Equal("Administrators", value.Text);
        Assert.Null(value.Bytes);
    }
}
