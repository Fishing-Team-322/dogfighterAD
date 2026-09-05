namespace DogfighterAD.Domain.Snapshots;

public sealed record AdSnapshot
{
    public required SnapshotMetadata Metadata { get; init; }
    public IReadOnlyList<AdDomain> Domains { get; init; } = [];
    public IReadOnlyList<AdUser> Users { get; init; } = [];
    public IReadOnlyList<AdGroup> Groups { get; init; } = [];
    public IReadOnlyList<AdComputer> Computers { get; init; } = [];
    public IReadOnlyList<AdTrust> Trusts { get; init; } = [];
    public IReadOnlyList<AdAce> Aces { get; init; } = [];
    public IReadOnlyList<CollectionCapability> Capabilities { get; init; } = [];
}

public sealed record SnapshotMetadata
{
    public required Guid SnapshotId { get; init; }
    public required int SchemaVersion { get; init; }
    public required string ProductVersion { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public required string Target { get; init; }
}

public sealed record AdDomain(
    string DistinguishedName,
    string DnsName,
    string? NetbiosName,
    string? DomainSid);

public sealed record AdUser(
    Guid ObjectGuid,
    string DistinguishedName,
    string? Sid,
    string? SamAccountName,
    string? UserPrincipalName,
    long UserAccountControl,
    DateTimeOffset? PasswordLastSet,
    DateTimeOffset? LastLogonTimestamp,
    IReadOnlyList<string> ServicePrincipalNames,
    IReadOnlyList<string> SidHistory);

public sealed record AdGroup(
    Guid ObjectGuid,
    string DistinguishedName,
    string? Sid,
    string? SamAccountName,
    IReadOnlyList<Guid> MemberObjectGuids);

public sealed record AdComputer(
    Guid ObjectGuid,
    string DistinguishedName,
    string? Sid,
    string? SamAccountName,
    string? DnsHostName,
    string? OperatingSystem,
    long UserAccountControl);

public sealed record AdTrust(
    string SourceDomain,
    string TargetDomain,
    int TrustDirection,
    int TrustType,
    int TrustAttributes);

public sealed record AdAce(
    Guid TargetObjectGuid,
    string TrusteeSid,
    string AccessType,
    uint AccessMask,
    Guid? ObjectType,
    Guid? InheritedObjectType,
    bool IsInherited);

public sealed record CollectionCapability(
    string Id,
    CapabilityStatus Status,
    string? Reason = null);

public enum CapabilityStatus
{
    NotRequested,
    Complete,
    Partial,
    Failed
}
