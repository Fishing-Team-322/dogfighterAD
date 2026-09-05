namespace DogfighterAD.Domain.Snapshots;

/// <summary>
/// Declares the minimum capability contract version required by an analyzer or rule.
/// Capability versions are monotonic: a newer version must preserve guarantees of older versions.
/// If a semantic break cannot preserve those guarantees, introduce a new capability id instead.
/// </summary>
public sealed record CapabilityRequirement(
    string CapabilityId,
    int MinimumContractVersion = 1);

/// <summary>
/// Central catalog for built-in capability contract versions.
/// Snapshots persist the version that was actually collected so later rule packs can decide
/// whether an old snapshot contains enough data for safe offline re-analysis.
/// </summary>
public static class CapabilityContractCatalog
{
    private static readonly IReadOnlyDictionary<string, int> CurrentVersions =
        new Dictionary<string, int>(StringComparer.Ordinal)
        {
            [CollectionCapabilities.DirectoryCore] = 1,
            [CollectionCapabilities.DirectoryDomains] = 1,
            [CollectionCapabilities.DirectoryUsers] = 1,
            [CollectionCapabilities.DirectoryGroups] = 1,
            [CollectionCapabilities.DirectoryComputers] = 1,
            [CollectionCapabilities.DirectoryOrganizationalUnits] = 1,
            [CollectionCapabilities.DirectoryMemberships] = 1,
            [CollectionCapabilities.DirectoryAcls] = 1,
            [CollectionCapabilities.DirectoryTrusts] = 1,
            [CollectionCapabilities.GroupPolicyMetadata] = 1,
            [CollectionCapabilities.GroupPolicyLinks] = 1,
            [CollectionCapabilities.GroupPolicySysvol] = 1,
            [CollectionCapabilities.AdcsDirectory] = 1
        };

    public static bool TryGetCurrentVersion(string capabilityId, out int version)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(capabilityId);
        return CurrentVersions.TryGetValue(capabilityId, out version);
    }

    public static int GetCurrentVersion(string capabilityId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(capabilityId);

        return CurrentVersions.TryGetValue(capabilityId, out var version)
            ? version
            : throw new KeyNotFoundException($"Capability '{capabilityId}' is not registered in the built-in contract catalog.");
    }

    public static bool IsSatisfied(
        CapabilityCoverage coverage,
        CapabilityRequirement requirement)
    {
        ArgumentNullException.ThrowIfNull(coverage);
        ArgumentNullException.ThrowIfNull(requirement);

        return StringComparer.Ordinal.Equals(coverage.CapabilityId, requirement.CapabilityId)
            && coverage.ContractVersion >= requirement.MinimumContractVersion
            && coverage.Status is CapabilityStatus.Complete or CapabilityStatus.NotApplicable;
    }
}
