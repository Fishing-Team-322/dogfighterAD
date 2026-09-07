namespace DogfighterAD.Domain.Snapshots;

public readonly record struct AdObjectId(Guid Value)
{
    public override string ToString() => Value.ToString("D");
}

public abstract record AdDirectoryObject
{
    public required AdObjectId Id { get; init; }
    public required string DistinguishedName { get; init; }
    public string? Sid { get; init; }
    public string? Name { get; init; }
    public DateTimeOffset? WhenCreated { get; init; }
    public DateTimeOffset? WhenChanged { get; init; }
}

public sealed record AdDomain : AdDirectoryObject
{
    public required string DnsName { get; init; }
    public string? NetbiosName { get; init; }
    public int? FunctionalLevel { get; init; }
}

public sealed record AdUser : AdDirectoryObject
{
    public string? SamAccountName { get; init; }
    public string? UserPrincipalName { get; init; }
    public long UserAccountControl { get; init; }
    public int? AdminCount { get; init; }
    public int? PrimaryGroupId { get; init; }
    public DateTimeOffset? PasswordLastSet { get; init; }
    public bool? PasswordMustChangeAtNextLogon { get; init; }
    public DateTimeOffset? LastLogonTimestamp { get; init; }
    public DateTimeOffset? AccountExpires { get; init; }
    public bool? AccountNeverExpires { get; init; }
    public int? SupportedEncryptionTypes { get; init; }
    public IReadOnlyList<string> ServicePrincipalNames { get; init; } = [];
    public IReadOnlyList<string> SidHistory { get; init; } = [];
    public IReadOnlyList<string> AllowedToDelegateTo { get; init; } = [];
}

public sealed record AdGroup : AdDirectoryObject
{
    public string? SamAccountName { get; init; }
    public int? GroupType { get; init; }
    public int? AdminCount { get; init; }
}

public sealed record AdComputer : AdDirectoryObject
{
    public string? SamAccountName { get; init; }
    public string? DnsHostName { get; init; }
    public string? OperatingSystem { get; init; }
    public string? OperatingSystemVersion { get; init; }
    public long UserAccountControl { get; init; }
    public DateTimeOffset? PasswordLastSet { get; init; }
    public DateTimeOffset? LastLogonTimestamp { get; init; }
    public int? SupportedEncryptionTypes { get; init; }
    public IReadOnlyList<string> ServicePrincipalNames { get; init; } = [];
    public IReadOnlyList<string> AllowedToDelegateTo { get; init; } = [];
}

public sealed record AdOrganizationalUnit : AdDirectoryObject
{
    public bool? ProtectFromAccidentalDeletion { get; init; }
}

public sealed record AdGroupPolicyObject : AdDirectoryObject
{
    public required Guid GpoGuid { get; init; }
    public string? DisplayName { get; init; }
    public string? FileSystemPath { get; init; }
    public int? VersionNumber { get; init; }
    public int? Flags { get; init; }
}

public sealed record AdForeignSecurityPrincipal : AdDirectoryObject;

public sealed record AdGenericDirectoryObject : AdDirectoryObject
{
    public required string ObjectClass { get; init; }
}

public sealed record AdGroupMembership(
    AdObjectId GroupId,
    AdObjectId MemberId,
    MembershipSource Source);

public enum MembershipSource
{
    Explicit,
    PrimaryGroup
}

public sealed record AdGpoLink(
    AdObjectId ContainerId,
    AdObjectId GpoId,
    int Order,
    bool Enabled,
    bool Enforced)
{
    public int RawOptions { get; init; }
}

public sealed record AdGpoContainerPolicy(
    AdObjectId ContainerId,
    int RawOptions,
    bool BlockInheritance);

public sealed record AdTrust
{
    public required string SourceDomainDnsName { get; init; }
    public required string TargetDomainDnsName { get; init; }
    public string? TargetDomainSid { get; init; }
    public int TrustDirection { get; init; }
    public int TrustType { get; init; }
    public int TrustAttributes { get; init; }
}

public sealed record AdAce
{
    public required AdObjectId TargetObjectId { get; init; }

    /// <summary>
    /// Zero-based position of this ACE in the source DACL. The position is part of the typed
    /// snapshot representation because Windows access checks are order-sensitive and duplicate
    /// ACEs are meaningful source evidence.
    /// </summary>
    public int AceIndex { get; init; }

    public required string TrusteeSid { get; init; }
    public required AdAccessControlType AccessType { get; init; }
    public uint AccessMask { get; init; }
    public byte AceFlags { get; init; }
    public Guid? ObjectType { get; init; }
    public Guid? InheritedObjectType { get; init; }
    public bool IsInherited { get; init; }
}

public enum AdAccessControlType
{
    Unknown,
    Allow,
    Deny
}
