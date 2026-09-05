using System.Buffers.Binary;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Collectors.ActiveDirectory.Collectors;

internal sealed class SecurityDescriptorDaclParser
{
    private const ushort SeDaclPresent = 0x0004;
    private const ushort SeSelfRelative = 0x8000;
    private const byte InheritedAce = 0x10;
    private const uint AceObjectTypePresent = 0x00000001;
    private const uint AceInheritedObjectTypePresent = 0x00000002;

    private const byte AccessAllowedAceType = 0x00;
    private const byte AccessDeniedAceType = 0x01;
    private const byte AccessAllowedObjectAceType = 0x05;
    private const byte AccessDeniedObjectAceType = 0x06;

    public ParsedDacl Parse(ReadOnlySpan<byte> securityDescriptor)
    {
        if (securityDescriptor.Length < 20)
        {
            return ParsedDacl.Failure(0, AdDaclState.NotPresent, "Security descriptor is shorter than the self-relative header.");
        }

        if (securityDescriptor[0] != 1)
        {
            return ParsedDacl.Failure(0, AdDaclState.NotPresent, $"Unsupported security descriptor revision {securityDescriptor[0]}.");
        }

        var control = BinaryPrimitives.ReadUInt16LittleEndian(securityDescriptor.Slice(2, 2));
        if ((control & SeSelfRelative) == 0)
        {
            return ParsedDacl.Failure(control, AdDaclState.NotPresent, "Security descriptor is not self-relative.");
        }

        if ((control & SeDaclPresent) == 0)
        {
            return ParsedDacl.Success(control, AdDaclState.NotPresent, []);
        }

        var daclOffset = BinaryPrimitives.ReadUInt32LittleEndian(securityDescriptor.Slice(16, 4));
        if (daclOffset == 0)
        {
            return ParsedDacl.Success(control, AdDaclState.Null, []);
        }

        if (daclOffset > int.MaxValue || daclOffset + 8u > securityDescriptor.Length)
        {
            return ParsedDacl.Failure(control, AdDaclState.Present, "DACL offset points outside the security descriptor.");
        }

        var aclOffset = (int)daclOffset;
        var acl = securityDescriptor[aclOffset..];
        var aclRevision = acl[0];
        if (aclRevision is not 2 and not 4)
        {
            return ParsedDacl.Failure(control, AdDaclState.Present, $"Unsupported ACL revision {aclRevision}.");
        }

        var aclSize = BinaryPrimitives.ReadUInt16LittleEndian(acl.Slice(2, 2));
        var aceCount = BinaryPrimitives.ReadUInt16LittleEndian(acl.Slice(4, 2));
        if (aclSize < 8 || aclOffset + aclSize > securityDescriptor.Length)
        {
            return ParsedDacl.Failure(control, AdDaclState.Present, "DACL size points outside the security descriptor.");
        }

        if (aceCount == 0)
        {
            return ParsedDacl.Success(control, AdDaclState.Empty, []);
        }

        var aces = new List<ParsedDaclAce>(aceCount);
        var aceOffset = aclOffset + 8;
        var aclEnd = aclOffset + aclSize;

        for (var aceIndex = 0; aceIndex < aceCount; aceIndex++)
        {
            if (aceOffset + 4 > aclEnd)
            {
                return ParsedDacl.Failure(control, AdDaclState.Present, $"ACE {aceIndex} header exceeds DACL bounds.", aces);
            }

            var aceType = securityDescriptor[aceOffset];
            var aceFlags = securityDescriptor[aceOffset + 1];
            var aceSize = BinaryPrimitives.ReadUInt16LittleEndian(securityDescriptor.Slice(aceOffset + 2, 2));
            if (aceSize < 4 || aceOffset + aceSize > aclEnd)
            {
                return ParsedDacl.Failure(control, AdDaclState.Present, $"ACE {aceIndex} size exceeds DACL bounds.", aces);
            }

            if (!TryParseAce(
                    securityDescriptor.Slice(aceOffset, aceSize),
                    aceType,
                    aceFlags,
                    out var parsedAce,
                    out var error))
            {
                return ParsedDacl.Failure(
                    control,
                    AdDaclState.Present,
                    $"ACE {aceIndex}: {error}",
                    aces);
            }

            aces.Add(parsedAce!);
            aceOffset += aceSize;
        }

        return ParsedDacl.Success(control, AdDaclState.Present, aces);
    }

    private static bool TryParseAce(
        ReadOnlySpan<byte> ace,
        byte aceType,
        byte aceFlags,
        out ParsedDaclAce? result,
        out string? error)
    {
        result = null;
        error = null;

        var accessType = aceType switch
        {
            AccessAllowedAceType or AccessAllowedObjectAceType => AdAccessControlType.Allow,
            AccessDeniedAceType or AccessDeniedObjectAceType => AdAccessControlType.Deny,
            _ => AdAccessControlType.Unknown
        };

        if (accessType == AdAccessControlType.Unknown)
        {
            error = $"unsupported ACE type 0x{aceType:X2}.";
            return false;
        }

        var isObjectAce = aceType is AccessAllowedObjectAceType or AccessDeniedObjectAceType;
        var minimumSize = isObjectAce ? 20 : 16;
        if (ace.Length < minimumSize)
        {
            error = "ACE is shorter than its required fixed fields and minimum SID.";
            return false;
        }

        var accessMask = BinaryPrimitives.ReadUInt32LittleEndian(ace.Slice(4, 4));
        var cursor = 8;
        Guid? objectType = null;
        Guid? inheritedObjectType = null;

        if (isObjectAce)
        {
            var objectFlags = BinaryPrimitives.ReadUInt32LittleEndian(ace.Slice(8, 4));
            cursor = 12;

            if ((objectFlags & AceObjectTypePresent) != 0)
            {
                if (cursor + 16 > ace.Length)
                {
                    error = "object ACE declares ObjectType but does not contain the GUID.";
                    return false;
                }

                objectType = new Guid(ace.Slice(cursor, 16));
                cursor += 16;
            }

            if ((objectFlags & AceInheritedObjectTypePresent) != 0)
            {
                if (cursor + 16 > ace.Length)
                {
                    error = "object ACE declares InheritedObjectType but does not contain the GUID.";
                    return false;
                }

                inheritedObjectType = new Guid(ace.Slice(cursor, 16));
                cursor += 16;
            }
        }

        if (!TryReadSid(ace[cursor..], out var trusteeSid, out var sidLength))
        {
            error = "ACE trustee SID is missing or malformed.";
            return false;
        }

        if (cursor + sidLength > ace.Length)
        {
            error = "ACE trustee SID exceeds ACE bounds.";
            return false;
        }

        result = new ParsedDaclAce(
            trusteeSid!,
            accessType,
            accessMask,
            aceFlags,
            objectType,
            inheritedObjectType,
            (aceFlags & InheritedAce) != 0);
        return true;
    }

    private static bool TryReadSid(
        ReadOnlySpan<byte> data,
        out string? sid,
        out int length)
    {
        sid = null;
        length = 0;

        if (data.Length < 8)
        {
            return false;
        }

        var subAuthorityCount = data[1];
        length = 8 + (subAuthorityCount * 4);
        if (data.Length < length)
        {
            return false;
        }

        sid = LdapValueConverters.FormatSid(data[..length]);
        return sid is not null;
    }
}

internal sealed record ParsedDacl(
    ushort ControlFlags,
    AdDaclState State,
    IReadOnlyList<ParsedDaclAce> Aces,
    string? Error)
{
    public bool Complete => Error is null;

    public static ParsedDacl Success(
        ushort controlFlags,
        AdDaclState state,
        IReadOnlyList<ParsedDaclAce> aces) =>
        new(controlFlags, state, aces, null);

    public static ParsedDacl Failure(
        ushort controlFlags,
        AdDaclState state,
        string error,
        IReadOnlyList<ParsedDaclAce>? aces = null) =>
        new(controlFlags, state, aces ?? [], error);
}

internal sealed record ParsedDaclAce(
    string TrusteeSid,
    AdAccessControlType AccessType,
    uint AccessMask,
    byte AceFlags,
    Guid? ObjectType,
    Guid? InheritedObjectType,
    bool IsInherited);
