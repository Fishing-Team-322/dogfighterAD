namespace DogfighterAD.Domain.Snapshots;

public sealed record SnapshotContent
{
    public DirectoryEnvironment? DirectoryEnvironment { get; init; }
    public IReadOnlyList<AdDomain> Domains { get; init; } = [];
    public IReadOnlyList<AdUser> Users { get; init; } = [];
    public IReadOnlyList<AdGroup> Groups { get; init; } = [];
    public IReadOnlyList<AdComputer> Computers { get; init; } = [];
    public IReadOnlyList<AdOrganizationalUnit> OrganizationalUnits { get; init; } = [];
    public IReadOnlyList<AdGroupPolicyObject> GroupPolicyObjects { get; init; } = [];
    public IReadOnlyList<AdForeignSecurityPrincipal> ForeignSecurityPrincipals { get; init; } = [];
    public IReadOnlyList<AdGenericDirectoryObject> OtherDirectoryObjects { get; init; } = [];
    public IReadOnlyList<AdGroupMembership> GroupMemberships { get; init; } = [];
    public IReadOnlyList<AdGpoLink> GroupPolicyLinks { get; init; } = [];
    public IReadOnlyList<AdTrust> Trusts { get; init; } = [];
    public IReadOnlyList<AdSecurityDescriptor> SecurityDescriptors { get; init; } = [];
    public IReadOnlyList<AdAce> Aces { get; init; } = [];
}

public sealed record SnapshotFragment
{
    public SnapshotContent Content { get; init; } = new();
    public IReadOnlyList<CapabilityCoverage> Coverage { get; init; } = [];
    public IReadOnlyList<ObservedFact> Observations { get; init; } = [];
}
