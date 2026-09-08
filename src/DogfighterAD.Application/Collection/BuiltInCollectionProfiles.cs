using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Collection;

/// <summary>
/// Stable built-in collection profiles for common DogfighterAD scan modes.
/// Profiles intentionally list capabilities explicitly: adding a new collector/capability must not
/// silently make an existing profile heavier or change what an old command means.
/// </summary>
public static class BuiltInCollectionProfiles
{
    public const string MinimalName = "minimal";
    public const string AuditFullName = "audit-full";

    private static readonly IReadOnlyDictionary<string, Func<CollectionProfile>> Factories =
        new Dictionary<string, Func<CollectionProfile>>(StringComparer.OrdinalIgnoreCase)
        {
            [MinimalName] = CreateMinimal,
            [AuditFullName] = CreateAuditFull
        };

    public static IReadOnlyList<string> Names => Factories.Keys
        .OrderBy(name => name, StringComparer.Ordinal)
        .ToArray();

    public static bool TryGet(string name, out CollectionProfile profile)
    {
        if (string.IsNullOrWhiteSpace(name) || !Factories.TryGetValue(name, out var factory))
        {
            profile = null!;
            return false;
        }

        profile = factory();
        return true;
    }

    public static CollectionProfile Get(string name)
    {
        if (!TryGet(name, out var profile))
        {
            throw new KeyNotFoundException(
                $"Unknown collection profile '{name}'. Available profiles: {string.Join(", ", Names)}.");
        }

        return profile;
    }

    private static CollectionProfile CreateMinimal() => new()
    {
        Name = MinimalName,
        RequestedCapabilities = new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryCore,
            CollectionCapabilities.DirectoryDomains,
            CollectionCapabilities.DirectoryUsers,
            CollectionCapabilities.DirectoryGroups,
            CollectionCapabilities.DirectoryComputers,
            CollectionCapabilities.DirectoryOrganizationalUnits,
            CollectionCapabilities.DirectoryMemberships,
            CollectionCapabilities.DirectorySecurityPolicy,
            CollectionCapabilities.DirectoryTrusts
        },
        MaxConcurrency = 2,
        CollectorTimeout = TimeSpan.FromMinutes(2)
    };

    private static CollectionProfile CreateAuditFull() => new()
    {
        Name = AuditFullName,
        RequestedCapabilities = new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryCore,
            CollectionCapabilities.DirectoryDomains,
            CollectionCapabilities.DirectoryUsers,
            CollectionCapabilities.DirectoryGroups,
            CollectionCapabilities.DirectoryComputers,
            CollectionCapabilities.DirectoryOrganizationalUnits,
            CollectionCapabilities.DirectoryMemberships,
            CollectionCapabilities.DirectorySecurityPolicy,
            CollectionCapabilities.DirectoryTrusts,
            CollectionCapabilities.DirectoryAcls,
            CollectionCapabilities.GroupPolicyMetadata,
            CollectionCapabilities.GroupPolicyLinks,
            CollectionCapabilities.GroupPolicySysvol
        },
        MaxConcurrency = 4,
        CollectorTimeout = TimeSpan.FromMinutes(3)
    };
}
