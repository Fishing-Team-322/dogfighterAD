using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Snapshots;

public sealed class SnapshotFragmentMerger
{
    public SnapshotFragment Merge(IReadOnlyList<SnapshotFragment> fragments)
    {
        ArgumentNullException.ThrowIfNull(fragments);

        return new SnapshotFragment
        {
            Content = MergeContent(fragments),
            Coverage = MergeCoverage(fragments),
            Observations = MergeObservations(fragments)
        };
    }

    private static SnapshotContent MergeContent(IReadOnlyList<SnapshotFragment> fragments)
    {
        return new SnapshotContent
        {
            DirectoryEnvironment = MergeDirectoryEnvironment(fragments),
            Domains = MergeDirectoryObjects(fragments.SelectMany(x => x.Content.Domains), "domain"),
            Users = MergeDirectoryObjects(fragments.SelectMany(x => x.Content.Users), "user"),
            Groups = MergeDirectoryObjects(fragments.SelectMany(x => x.Content.Groups), "group"),
            Computers = MergeDirectoryObjects(fragments.SelectMany(x => x.Content.Computers), "computer"),
            OrganizationalUnits = MergeDirectoryObjects(
                fragments.SelectMany(x => x.Content.OrganizationalUnits),
                "organizational-unit"),
            GroupPolicyObjects = MergeDirectoryObjects(
                fragments.SelectMany(x => x.Content.GroupPolicyObjects),
                "group-policy-object"),
            ForeignSecurityPrincipals = MergeDirectoryObjects(
                fragments.SelectMany(x => x.Content.ForeignSecurityPrincipals),
                "foreign-security-principal"),
            OtherDirectoryObjects = MergeDirectoryObjects(
                fragments.SelectMany(x => x.Content.OtherDirectoryObjects),
                "generic-directory-object"),
            GroupMemberships = fragments
                .SelectMany(x => x.Content.GroupMemberships)
                .Distinct()
                .OrderBy(x => x.GroupId.Value)
                .ThenBy(x => x.MemberId.Value)
                .ThenBy(x => x.Source)
                .ToArray(),
            GroupPolicyLinks = fragments
                .SelectMany(x => x.Content.GroupPolicyLinks)
                .Distinct()
                .OrderBy(x => x.ContainerId.Value)
                .ThenBy(x => x.Order)
                .ThenBy(x => x.GpoId.Value)
                .ToArray(),
            GroupPolicyContainerPolicies = MergeGpoContainerPolicies(
                fragments.SelectMany(x => x.Content.GroupPolicyContainerPolicies)),
            GroupPolicyFiles = MergeGpoFiles(
                fragments.SelectMany(x => x.Content.GroupPolicyFiles)),
            GroupPolicySettings = fragments
                .SelectMany(x => x.Content.GroupPolicySettings)
                .Distinct()
                .OrderBy(x => x.GpoId.Value)
                .ThenBy(x => x.SourceRelativePath, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Sequence)
                .ThenBy(x => x.Key, StringComparer.Ordinal)
                .ToArray(),
            Trusts = fragments
                .SelectMany(x => x.Content.Trusts)
                .Distinct()
                .OrderBy(x => x.SourceDomainDnsName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.TargetDomainDnsName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.TrustDirection)
                .ThenBy(x => x.TrustType)
                .ToArray(),
            SecurityDescriptors = MergeSecurityDescriptors(
                fragments.SelectMany(x => x.Content.SecurityDescriptors)),
            Aces = fragments
                .SelectMany(x => x.Content.Aces)
                .Distinct()
                .OrderBy(x => x.TargetObjectId.Value)
                .ThenBy(x => x.TrusteeSid, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.AccessType)
                .ThenBy(x => x.AccessMask)
                .ThenBy(x => x.ObjectType)
                .ThenBy(x => x.InheritedObjectType)
                .ThenBy(x => x.AceFlags)
                .ToArray()
        };
    }

    private static DirectoryEnvironment? MergeDirectoryEnvironment(
        IReadOnlyList<SnapshotFragment> fragments)
    {
        var environments = fragments
            .Select(x => x.Content.DirectoryEnvironment)
            .Where(x => x is not null)
            .Cast<DirectoryEnvironment>()
            .ToArray();

        if (environments.Length == 0)
        {
            return null;
        }

        if (environments.Length > 1)
        {
            throw MergeError(
                "snapshot.fragment.duplicate-directory-environment",
                "Multiple collector fragments produced DirectoryEnvironment. " +
                "Discovery ownership must be resolved before snapshot assembly.");
        }

        var environment = environments[0];
        return environment with
        {
            NamingContexts = environment.NamingContexts
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            SupportedCapabilities = environment.SupportedCapabilities
                .Distinct(StringComparer.Ordinal)
                .OrderBy(x => x, StringComparer.Ordinal)
                .ToArray(),
            SupportedControls = environment.SupportedControls
                .Distinct(StringComparer.Ordinal)
                .OrderBy(x => x, StringComparer.Ordinal)
                .ToArray(),
            SupportedLdapVersions = environment.SupportedLdapVersions
                .Distinct(StringComparer.Ordinal)
                .OrderBy(x => x, StringComparer.Ordinal)
                .ToArray()
        };
    }

    private static IReadOnlyList<T> MergeDirectoryObjects<T>(
        IEnumerable<T> objects,
        string kind)
        where T : AdDirectoryObject
    {
        var result = new List<T>();
        var seen = new HashSet<AdObjectId>();

        foreach (var item in objects)
        {
            if (!seen.Add(item.Id))
            {
                throw MergeError(
                    "snapshot.fragment.duplicate-object",
                    $"Multiple collector fragments produced {kind} object {item.Id}. " +
                    "Collector ownership must be resolved before snapshot assembly.");
            }

            result.Add(item);
        }

        return result
            .OrderBy(x => x.Id.Value)
            .ToArray();
    }

    private static IReadOnlyList<AdSecurityDescriptor> MergeSecurityDescriptors(
        IEnumerable<AdSecurityDescriptor> descriptors)
    {
        var result = new List<AdSecurityDescriptor>();
        var seen = new HashSet<AdObjectId>();

        foreach (var descriptor in descriptors)
        {
            if (!seen.Add(descriptor.TargetObjectId))
            {
                throw MergeError(
                    "snapshot.fragment.duplicate-security-descriptor",
                    $"Multiple collector fragments produced a security descriptor for object {descriptor.TargetObjectId}.");
            }

            result.Add(descriptor);
        }

        return result
            .OrderBy(x => x.TargetObjectId.Value)
            .ToArray();
    }

    private static IReadOnlyList<AdGpoContainerPolicy> MergeGpoContainerPolicies(
        IEnumerable<AdGpoContainerPolicy> policies)
    {
        var result = new List<AdGpoContainerPolicy>();
        var seen = new HashSet<AdObjectId>();

        foreach (var policy in policies)
        {
            if (!seen.Add(policy.ContainerId))
            {
                throw MergeError(
                    "snapshot.fragment.duplicate-gpo-container-policy",
                    $"Multiple collector fragments produced GPO inheritance state for container {policy.ContainerId}.");
            }

            result.Add(policy);
        }

        return result
            .OrderBy(x => x.ContainerId.Value)
            .ToArray();
    }

    private static IReadOnlyList<AdGpoSysvolFile> MergeGpoFiles(
        IEnumerable<AdGpoSysvolFile> files)
    {
        var result = new List<AdGpoSysvolFile>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in files)
        {
            var key = $"{file.GpoId}|{file.RelativePath}";
            if (!seen.Add(key))
            {
                throw MergeError(
                    "snapshot.fragment.duplicate-gpo-sysvol-file",
                    $"Multiple collector fragments produced SYSVOL file '{file.RelativePath}' for GPO {file.GpoId}.");
            }

            result.Add(file);
        }

        return result
            .OrderBy(x => x.GpoId.Value)
            .ThenBy(x => x.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static IReadOnlyList<CapabilityCoverage> MergeCoverage(
        IReadOnlyList<SnapshotFragment> fragments)
    {
        return fragments
            .SelectMany(x => x.Coverage)
            .GroupBy(x => x.CapabilityId, StringComparer.Ordinal)
            .Select(group => new CapabilityCoverage
            {
                CapabilityId = group.Key,
                ContractVersion = group.Min(x => x.ContractVersion),
                Status = MergeCapabilityStatus(group.Select(x => x.Status)),
                StartedAt = group.Min(x => x.StartedAt),
                CompletedAt = group.Max(x => x.CompletedAt),
                ObservedItemCount = group.Max(x => x.ObservedItemCount),
                Collectors = group
                    .SelectMany(x => x.Collectors)
                    .Distinct()
                    .OrderBy(x => x.Id, StringComparer.Ordinal)
                    .ThenBy(x => x.Version, StringComparer.Ordinal)
                    .ToArray(),
                Issues = group
                    .SelectMany(x => x.Issues)
                    .OrderBy(x => x.Code, StringComparer.Ordinal)
                    .ThenBy(x => x.CollectorId, StringComparer.Ordinal)
                    .ThenBy(x => x.Target, StringComparer.Ordinal)
                    .ThenBy(x => x.Message, StringComparer.Ordinal)
                    .ToArray()
            })
            .OrderBy(x => x.CapabilityId, StringComparer.Ordinal)
            .ToArray();
    }

    private static IReadOnlyList<ObservedFact> MergeObservations(
        IReadOnlyList<SnapshotFragment> fragments)
    {
        var observations = fragments
            .SelectMany(x => x.Observations)
            .OrderBy(x => x.FactId, StringComparer.Ordinal)
            .ToArray();

        var duplicateFactId = observations
            .GroupBy(x => x.FactId, StringComparer.Ordinal)
            .FirstOrDefault(group => group.Count() > 1)?.Key;

        if (duplicateFactId is not null)
        {
            throw MergeError(
                "snapshot.fragment.duplicate-fact",
                $"Observed fact id '{duplicateFactId}' was produced more than once.");
        }

        return observations;
    }

    private static CapabilityStatus MergeCapabilityStatus(IEnumerable<CapabilityStatus> statuses)
    {
        var values = statuses.Distinct().ToArray();
        return values.Length == 1 ? values[0] : CapabilityStatus.Partial;
    }

    private static SnapshotMergeException MergeError(string code, string message) =>
        new(new SnapshotInvariantViolation(code, message));
}

public sealed class SnapshotMergeException : Exception
{
    public SnapshotMergeException(SnapshotInvariantViolation violation)
        : base($"{violation.Code}: {violation.Message}")
    {
        Violation = violation;
    }

    public SnapshotInvariantViolation Violation { get; }
}
