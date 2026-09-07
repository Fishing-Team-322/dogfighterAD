namespace DogfighterAD.Domain.Snapshots;

/// <summary>
/// Preserves security-descriptor state that cannot be reconstructed from ACE rows alone.
/// In particular, a null/absent DACL and an empty DACL have opposite authorization semantics.
/// </summary>
public sealed record AdSecurityDescriptor
{
    public required AdObjectId TargetObjectId { get; init; }
    public required AdDaclState DaclState { get; init; }
    public ushort ControlFlags { get; init; }
}

public enum AdDaclState
{
    NotPresent,
    Null,
    Empty,
    Present
}
