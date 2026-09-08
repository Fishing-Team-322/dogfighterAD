namespace DogfighterAD.Domain.Snapshots;

public static class CollectionCapabilities
{
    public const string DirectorySecurityPolicy = "directory.security-policy";
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

    // AD CS 0.3.2 deliberately uses narrow contracts so offline rules can distinguish exactly which
    // directory evidence exists. Runtime CA policy, RPC and web-enrollment posture will use separate
    // future capability IDs rather than overloading these directory-derived contracts.
    public const string AdcsAuthorities = "adcs.authorities";
    public const string AdcsTemplates = "adcs.templates";
    public const string AdcsPublication = "adcs.publication";
    public const string AdcsAcls = "adcs.acls";
    public const string AdcsTrust = "adcs.trust";

    // Retained as a legacy identifier so older custom profiles/code that referenced the pre-0.3.2
    // placeholder continue to deserialize. Built-in profiles and new rules do not request it.
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
