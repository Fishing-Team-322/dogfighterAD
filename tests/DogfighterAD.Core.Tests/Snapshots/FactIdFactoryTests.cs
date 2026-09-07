using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Snapshots;

public sealed class FactIdFactoryTests
{
    [Fact]
    public void Create_ProducesStableGoldenVector()
    {
        var actual = FactIdFactory.Create(
            "directory.core",
            "ldap-rootdse:dc01.mini.lab",
            "rootDse.defaultNamingContext",
            FactValueKind.Text,
            "DC=mini,DC=lab");

        Assert.Equal(
            "fact:v1:ee34bc4cf866e72be29b5d7e288fc686dd93cbc946dec89adfe8f50e9611ea33",
            actual);
    }

    [Fact]
    public void Create_ChangesWhenObservedValueChanges()
    {
        var first = FactIdFactory.Create(
            "directory.users",
            "ad-object:6bc5b8df-999f-47df-9e76-664ad5ab2a58",
            "user.userAccountControl",
            FactValueKind.Integer,
            "512");

        var second = FactIdFactory.Create(
            "directory.users",
            "ad-object:6bc5b8df-999f-47df-9e76-664ad5ab2a58",
            "user.userAccountControl",
            FactValueKind.Integer,
            "514");

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Create_UsesUtf8ByteLengthsInCanonicalEncoding()
    {
        var unicode = FactIdFactory.Create(
            "directory.users",
            "subject:ёж",
            "path:имя",
            FactValueKind.Text,
            "значение");

        var ascii = FactIdFactory.Create(
            "directory.users",
            "subject:ezh",
            "path:imya",
            FactValueKind.Text,
            "znachenie");

        Assert.NotEqual(unicode, ascii);
        Assert.StartsWith("fact:v1:", unicode, StringComparison.Ordinal);
    }
}
