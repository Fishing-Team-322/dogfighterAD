using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Serialization;

public static class SnapshotCanonicalizer
{
    public static AdSnapshot Canonicalize(AdSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        return snapshot with
        {
            Metadata = snapshot.Metadata with
            {
                RequestedCapabilities = snapshot.Metadata.RequestedCapabilities
                    .OrderBy(value => value, StringComparer.Ordinal)
                    .ToArray(),
                Collectors = snapshot.Metadata.Collectors
                    .OrderBy(item => item.Id, StringComparer.Ordinal)
                    .ThenBy(item => item.Version, StringComparer.Ordinal)
                    .ToArray()
            },
            Content = CanonicalizeContent(snapshot.Content),
            Coverage = snapshot.Coverage
                .OrderBy(item => item.CapabilityId, StringComparer.Ordinal)
                .Select(item => item with
                {
                    Collectors = item.Collectors
                        .OrderBy(collector => collector.Id, StringComparer.Ordinal)
                        .ThenBy(collector => collector.Version, StringComparer.Ordinal)
                        .ToArray(),
                    Issues = item.Issues
                        .OrderBy(issue => issue.Code, StringComparer.Ordinal)
                        .ThenBy(issue => issue.Severity)
                        .ThenBy(issue => issue.CollectorId, StringComparer.Ordinal)
                        .ThenBy(issue => issue.Target, StringComparer.Ordinal)
                        .ThenBy(issue => issue.Message, StringComparer.Ordinal)
                        .ToArray()
                })
                .ToArray(),
            Observations = snapshot.Observations
                .OrderBy(item => item.FactId, StringComparer.Ordinal)
                .ToArray()
        };
    }

    private static SnapshotContent CanonicalizeContent(SnapshotContent content) =>
        content with
        {
            DirectoryEnvironment = content.DirectoryEnvironment is null
                ? null
                : content.DirectoryEnvironment with
                {
                    NamingContexts = SortIgnoreCase(content.DirectoryEnvironment.NamingContexts),
                    SupportedCapabilities = SortOrdinal(content.DirectoryEnvironment.SupportedCapabilities),
                    SupportedControls = SortOrdinal(content.DirectoryEnvironment.SupportedControls),
                    SupportedLdapVersions = SortOrdinal(content.DirectoryEnvironment.SupportedLdapVersions)
                },
            Domains = content.Domains.OrderBy(item => item.Id.Value).ToArray(),
            Users = content.Users
                .Select(item => item with
                {
                    ServicePrincipalNames = SortOrdinal(item.ServicePrincipalNames),
                    SidHistory = SortOrdinal(item.SidHistory),
                    AllowedToDelegateTo = SortIgnoreCase(item.AllowedToDelegateTo)
                })
                .OrderBy(item => item.Id.Value)
                .ToArray(),
            Groups = content.Groups.OrderBy(item => item.Id.Value).ToArray(),
            Computers = content.Computers
                .Select(item => item with
                {
                    ServicePrincipalNames = SortOrdinal(item.ServicePrincipalNames),
                    AllowedToDelegateTo = SortIgnoreCase(item.AllowedToDelegateTo)
                })
                .OrderBy(item => item.Id.Value)
                .ToArray(),
            OrganizationalUnits = content.OrganizationalUnits.OrderBy(item => item.Id.Value).ToArray(),
            GroupPolicyObjects = content.GroupPolicyObjects.OrderBy(item => item.Id.Value).ToArray(),
            ForeignSecurityPrincipals = content.ForeignSecurityPrincipals.OrderBy(item => item.Id.Value).ToArray(),
            OtherDirectoryObjects = content.OtherDirectoryObjects.OrderBy(item => item.Id.Value).ToArray(),
            GroupMemberships = content.GroupMemberships
                .OrderBy(item => item.GroupId.Value)
                .ThenBy(item => item.MemberId.Value)
                .ThenBy(item => item.Source)
                .ToArray(),
            GroupPolicyLinks = content.GroupPolicyLinks
                .OrderBy(item => item.ContainerId.Value)
                .ThenBy(item => item.Order)
                .ThenBy(item => item.GpoId.Value)
                .ThenBy(item => item.RawOptions)
                .ToArray(),
            GroupPolicyContainerPolicies = content.GroupPolicyContainerPolicies
                .OrderBy(item => item.ContainerId.Value)
                .ThenBy(item => item.RawOptions)
                .ToArray(),
            GroupPolicyFiles = content.GroupPolicyFiles
                .OrderBy(item => item.GpoId.Value)
                .ThenBy(item => item.RelativePath, StringComparer.OrdinalIgnoreCase)
                .ThenBy(item => item.RelativePath, StringComparer.Ordinal)
                .ToArray(),
            GroupPolicySettings = content.GroupPolicySettings
                .OrderBy(item => item.GpoId.Value)
                .ThenBy(item => item.SourceRelativePath, StringComparer.OrdinalIgnoreCase)
                .ThenBy(item => item.SourceRelativePath, StringComparer.Ordinal)
                .ThenBy(item => item.Sequence)
                .ThenBy(item => item.Kind)
                .ThenBy(item => item.Section, StringComparer.Ordinal)
                .ThenBy(item => item.Key, StringComparer.Ordinal)
                .ThenBy(item => item.Value, StringComparer.Ordinal)
                .ThenBy(item => item.Disposition)
                .ThenBy(item => item.DataLength)
                .ToArray(),
            Trusts = content.Trusts
                .OrderBy(item => item.SourceDomainDnsName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(item => item.SourceDomainDnsName, StringComparer.Ordinal)
                .ThenBy(item => item.TargetDomainDnsName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(item => item.TargetDomainDnsName, StringComparer.Ordinal)
                .ThenBy(item => item.TargetDomainSid, StringComparer.Ordinal)
                .ThenBy(item => item.TrustDirection)
                .ThenBy(item => item.TrustType)
                .ThenBy(item => item.TrustAttributes)
                .ToArray(),
            SecurityDescriptors = content.SecurityDescriptors
                .OrderBy(item => item.TargetObjectId.Value)
                .ThenBy(item => item.DaclState)
                .ThenBy(item => item.ControlFlags)
                .ToArray(),
            Aces = content.Aces
                .OrderBy(item => item.TargetObjectId.Value)
                .ThenBy(item => item.AceIndex)
                .ToArray()
        };

    private static IReadOnlyList<string> SortOrdinal(IEnumerable<string> values) =>
        values.OrderBy(value => value, StringComparer.Ordinal).ToArray();

    private static IReadOnlyList<string> SortIgnoreCase(IEnumerable<string> values) =>
        values
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ThenBy(value => value, StringComparer.Ordinal)
            .ToArray();
}
