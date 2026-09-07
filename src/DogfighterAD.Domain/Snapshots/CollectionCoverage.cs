namespace DogfighterAD.Domain.Snapshots;

public static class CollectionCapabilities
{
    public const string DirectoryCore = "directory.core";
    public const string DirectoryDomains = "directory.domains";
    public const string DirectoryUsers = "directory.users";
    public const string DirectoryGroups = "directory.groups";
    public const string DirectoryComputers = "directory.computers";
    public const string DirectoryOrganizationalUnits = "directory.ous";
    public const string DirectoryMemberships = "directory.memberships";
    public const string DirectoryAcls = "directory.acls";
    public const string DirectoryTrusts = "directory.trusts";
    public const string GroupPolicyMetadata = "gpo.metadata";
    public const string GroupPolicyLinks = "gpo.links";
    public const string GroupPolicySysvol = "gpo.sysvol";
    public const string AdcsDirectory = "adcs.directory";
}

public sealed record CapabilityCoverage
{
    public required string CapabilityId { get; init; }

    /// <summary>
    /// Version of the data contract that this coverage record satisfies.
    /// This is independent from collector and product versions and is persisted in snapshots.
    /// </summary>
    public int ContractVersion { get; init; } = 1;

    public required CapabilityStatus Status { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public int ObservedItemCount { get; init; }
    public IReadOnlyList<CollectorIdentity> Collectors { get; init; } = [];
    public IReadOnlyList<CollectionIssue> Issues { get; init; } = [];
}

public sealed record CollectionIssue
{
    public required string Code { get; init; }
    public required CollectionIssueSeverity Severity { get; init; }
    public required string Message { get; init; }
    public string? CapabilityId { get; init; }
    public string? CollectorId { get; init; }
    public string? Target { get; init; }
}

public enum CapabilityStatus
{
    NotRequested,
    Complete,
    Partial,
    Failed,
    Blocked,
    Unsupported,
    NotApplicable
}

public enum CollectionIssueSeverity
{
    Information,
    Warning,
    Error
}
