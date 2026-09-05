using System.Buffers.Binary;
using System.Globalization;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class SecurityDescriptorDaclParserTests
{
    [Fact]
    public void Parse_DistinguishesNotPresentNullAndEmptyDacl()
    {
        var parser = new SecurityDescriptorDaclParser();

        var notPresent = parser.Parse(BuildDescriptor(daclPresent: false, nullDacl: false, []));
        var nullDacl = parser.Parse(BuildDescriptor(daclPresent: true, nullDacl: true, []));
        var empty = parser.Parse(BuildDescriptor(daclPresent: true, nullDacl: false, []));

        Assert.True(notPresent.Complete);
        Assert.Equal(AdDaclState.NotPresent, notPresent.State);
        Assert.True(nullDacl.Complete);
        Assert.Equal(AdDaclState.Null, nullDacl.State);
        Assert.True(empty.Complete);
        Assert.Equal(AdDaclState.Empty, empty.State);
    }

    [Fact]
    public void Parse_PreservesStandardAndObjectAceSemantics()
    {
        var parser = new SecurityDescriptorDaclParser();
        var objectType = Guid.Parse("11111111-2222-3333-4444-555555555555");
        var inheritedObjectType = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

        var descriptor = BuildDescriptor(
            daclPresent: true,
            nullDacl: false,
            [
                BuildStandardAce(
                    aceType: 0x00,
                    aceFlags: 0x00,
                    accessMask: 0x00020000,
                    sid: CreateSidBytes("S-1-5-21-1-2-3-1001")),
                BuildObjectAce(
                    aceType: 0x06,
                    aceFlags: 0x10,
                    accessMask: 0x00040000,
                    objectType,
                    inheritedObjectType,
                    CreateSidBytes("S-1-5-32-544"))
            ]);

        var result = parser.Parse(descriptor);

        Assert.True(result.Complete, result.Error);
        Assert.Equal(AdDaclState.Present, result.State);
        Assert.Equal(2, result.Aces.Count);

        var allowed = result.Aces[0];
        Assert.Equal(AdAccessControlType.Allow, allowed.AccessType);
        Assert.Equal((uint)0x00020000, allowed.AccessMask);
        Assert.Equal("S-1-5-21-1-2-3-1001", allowed.TrusteeSid);
        Assert.Null(allowed.ObjectType);
        Assert.False(allowed.IsInherited);

        var deniedObject = result.Aces[1];
        Assert.Equal(AdAccessControlType.Deny, deniedObject.AccessType);
        Assert.Equal((uint)0x00040000, deniedObject.AccessMask);
        Assert.Equal("S-1-5-32-544", deniedObject.TrusteeSid);
        Assert.Equal(objectType, deniedObject.ObjectType);
        Assert.Equal(inheritedObjectType, deniedObject.InheritedObjectType);
        Assert.True(deniedObject.IsInherited);
        Assert.Equal((byte)0x10, deniedObject.AceFlags);
    }

    [Fact]
    public void Parse_UnsupportedAceType_IsExplicitFailure()
    {
        var parser = new SecurityDescriptorDaclParser();
        var descriptor = BuildDescriptor(
            daclPresent: true,
            nullDacl: false,
            [
                BuildStandardAce(
                    aceType: 0x09,
                    aceFlags: 0,
                    accessMask: 1,
                    sid: CreateSidBytes("S-1-5-18"))
            ]);

        var result = parser.Parse(descriptor);

        Assert.False(result.Complete);
        Assert.Equal(AdDaclState.Present, result.State);
        Assert.Contains("unsupported ACE type 0x09", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_TruncatedDescriptor_IsExplicitFailure()
    {
        var parser = new SecurityDescriptorDaclParser();

        var result = parser.Parse(new byte[12]);

        Assert.False(result.Complete);
        Assert.Contains("shorter", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    private static byte[] BuildDescriptor(
        bool daclPresent,
        bool nullDacl,
        IReadOnlyList<byte[]> aces)
    {
        const ushort selfRelative = 0x8000;
        const ushort daclPresentFlag = 0x0004;
        var control = (ushort)(selfRelative | (daclPresent ? daclPresentFlag : 0));

        if (!daclPresent || nullDacl)
        {
            var descriptorOnly = new byte[20];
            descriptorOnly[0] = 1;
            BinaryPrimitives.WriteUInt16LittleEndian(descriptorOnly.AsSpan(2, 2), control);
            return descriptorOnly;
        }

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

        var descriptor = new byte[20 + acl.Length];
        descriptor[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(descriptor.AsSpan(2, 2), control);
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

    private static byte[] BuildObjectAce(
        byte aceType,
        byte aceFlags,
        uint accessMask,
        Guid objectType,
        Guid inheritedObjectType,
        byte[] sid)
    {
        const uint objectTypePresent = 0x1;
        const uint inheritedObjectTypePresent = 0x2;
        var ace = new byte[12 + 16 + 16 + sid.Length];
        ace[0] = aceType;
        ace[1] = aceFlags;
        BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2, 2), checked((ushort)ace.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(4, 4), accessMask);
        BinaryPrimitives.WriteUInt32LittleEndian(
            ace.AsSpan(8, 4),
            objectTypePresent | inheritedObjectTypePresent);
        objectType.TryWriteBytes(ace.AsSpan(12, 16));
        inheritedObjectType.TryWriteBytes(ace.AsSpan(28, 16));
        sid.CopyTo(ace, 44);
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
            var value = subAuthorities[index];
            var offset = 8 + (index * 4);
            BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(offset, 4), value);
        }

        return result;
    }
}
