using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Snapshots;

public sealed class SnapshotAssembler
{
    public AdSnapshot Assemble(SnapshotAssemblyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var content = MergeContent(request.Fragments);
        var coverage = MergeCoverage(request.Fragments);
        var observations = request.Fragments
            .SelectMany(x => x.Observations)
            .OrderBy(x => x.FactId, StringComparer.Ordinal)
            .ToArray();

        var completionStatus = DetermineCompletionStatus(
            request.RequestedCapabilities,
            coverage);

        var collectors = request.Fragments
            .SelectMany(x => x.Coverage)
            .SelectMany(x => x.Collectors)
            .Distinct()
            .OrderBy(x => x.Id, StringComparer.Ordinal)
            .ThenBy(x => x.Version, StringComparer.Ordinal)
            .ToArray();

        var snapshot = new AdSnapshot
        {
            Metadata = new SnapshotMetadata
            {
                SnapshotId = request.SnapshotId,
                SchemaVersion = SnapshotSchema.CurrentVersion,
                ProductVersion = request.ProductVersion,
                StartedAt = request.StartedAt,
                CompletedAt = request.CompletedAt,
                CompletionStatus = completionStatus,
                Target = request.Target,
                CollectionProfile = request.CollectionProfile,
                RequestedCapabilities = request.RequestedCapabilities
                    .OrderBy(x => x, StringComparer.Ordinal)
                    .ToArray(),
                Collectors = collectors
            },
            Content = content,
            Coverage = coverage,
            Observations = observations
        };

        var violations = SnapshotInvariantValidator.Validate(snapshot);
        if (violations.Count > 0)
        {
            throw new SnapshotAssemblyException(violations);
        }

        return snapshot;
    }

    private static SnapshotContent MergeContent(IReadOnlyList<SnapshotFragment> fragments)
    {
        return new SnapshotContent
        {
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
                .ThenBy(x => x.GpoId.Value)
                .ThenBy(x => x.Order)
                .ToArray(),
            Trusts = fragments
                .SelectMany(x => x.Content.Trusts)
                .Distinct()
                .OrderBy(x => x.SourceDomainDnsName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.TargetDomainDnsName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.TrustDirection)
                .ThenBy(x => x.TrustType)
                .ToArray(),
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
                throw new SnapshotAssemblyException([
                    new SnapshotInvariantViolation(
                        "snapshot.fragment.duplicate-object",
                        $"Multiple collector fragments produced {kind} object {item.Id}. " +
                        "Collector ownership must be resolved before snapshot assembly.")
                ]);
            }

            result.Add(item);
        }

        return result
            .OrderBy(x => x.Id.Value)
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

    private static CapabilityStatus MergeCapabilityStatus(IEnumerable<CapabilityStatus> statuses)
    {
        var values = statuses.Distinct().ToArray();

        if (values.Length == 1)
        {
            return values[0];
        }

        return CapabilityStatus.Partial;
    }

    private static SnapshotCompletionStatus DetermineCompletionStatus(
        IReadOnlySet<string> requestedCapabilities,
        IReadOnlyList<CapabilityCoverage> coverage)
    {
        if (requestedCapabilities.Count == 0)
        {
            return SnapshotCompletionStatus.Complete;
        }

        var coverageByCapability = coverage.ToDictionary(
            x => x.CapabilityId,
            StringComparer.Ordinal);

        var statuses = requestedCapabilities
            .Select(capability => coverageByCapability.TryGetValue(capability, out var item)
                ? item.Status
                : CapabilityStatus.Failed)
            .ToArray();

        if (statuses.All(IsSatisfied))
        {
            return SnapshotCompletionStatus.Complete;
        }

        if (statuses.Any(x => x is CapabilityStatus.Complete or CapabilityStatus.Partial or CapabilityStatus.NotApplicable))
        {
            return SnapshotCompletionStatus.Partial;
        }

        return SnapshotCompletionStatus.Failed;
    }

    private static bool IsSatisfied(CapabilityStatus status) =>
        status is CapabilityStatus.Complete or CapabilityStatus.NotApplicable;
}

public sealed record SnapshotAssemblyRequest
{
    public required Guid SnapshotId { get; init; }
    public required string ProductVersion { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public required TargetIdentity Target { get; init; }
    public string? CollectionProfile { get; init; }
    public IReadOnlySet<string> RequestedCapabilities { get; init; } = new HashSet<string>();
    public IReadOnlyList<SnapshotFragment> Fragments { get; init; } = [];
}

public sealed class SnapshotAssemblyException : Exception
{
    public SnapshotAssemblyException(IReadOnlyList<SnapshotInvariantViolation> violations)
        : base(BuildMessage(violations))
    {
        Violations = violations;
    }

    public IReadOnlyList<SnapshotInvariantViolation> Violations { get; }

    private static string BuildMessage(IReadOnlyList<SnapshotInvariantViolation> violations) =>
        $"Snapshot assembly failed with {violations.Count} invariant violation(s): " +
        string.Join("; ", violations.Select(x => $"{x.Code}: {x.Message}"));
}
