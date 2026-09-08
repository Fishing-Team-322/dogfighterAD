using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis;

internal static class SnapshotInventory
{
    // These counts are explicitly defined by the built-in collection contracts. Unknown custom
    // capability inventories are not guessed. A complete count mismatch cannot certify emptiness.
    public static int? Count(AdSnapshot snapshot, string capability) => capability switch
    {
        CollectionCapabilities.DirectoryDomains => snapshot.Content.Domains.Count,
        CollectionCapabilities.DirectoryUsers => snapshot.Content.Users.Count,
        CollectionCapabilities.DirectoryGroups => snapshot.Content.Groups.Count,
        CollectionCapabilities.DirectoryComputers => snapshot.Content.Computers.Count,
        CollectionCapabilities.DirectoryOrganizationalUnits => snapshot.Content.OrganizationalUnits.Count,
        CollectionCapabilities.DirectoryMemberships => snapshot.Content.GroupMemberships.Count,
        CollectionCapabilities.DirectoryAcls => snapshot.Content.SecurityDescriptors.Count,
        CollectionCapabilities.DirectoryTrusts => snapshot.Content.Trusts.Count,
        CollectionCapabilities.GroupPolicyMetadata => snapshot.Content.GroupPolicyObjects.Count,
        CollectionCapabilities.GroupPolicyLinks => snapshot.Content.GroupPolicyLinks.Count,
        CollectionCapabilities.GroupPolicySysvol => snapshot.Content.GroupPolicyFiles.Count,
        CollectionCapabilities.AdcsAuthorities => snapshot.Content.CertificateServices?.Authorities.Count ?? 0,
        CollectionCapabilities.AdcsTemplates => snapshot.Content.CertificateServices?.Templates.Count ?? 0,
        CollectionCapabilities.AdcsPublication => snapshot.Content.CertificateServices?.Publications.Count ?? 0,
        CollectionCapabilities.AdcsAcls => snapshot.Content.CertificateServices?.SecurityDescriptors.Count ?? 0,
        CollectionCapabilities.AdcsTrust => snapshot.Content.CertificateServices?.Trust is null ? 0 : 1,
        CollectionCapabilities.DirectorySecurityPolicy => snapshot.Observations
            .Where(f => f.CapabilityId == capability && f.Path == "policy.kind")
            .Select(f => f.SubjectId).Distinct(StringComparer.Ordinal).Count(),
        _ => null
    };
}
