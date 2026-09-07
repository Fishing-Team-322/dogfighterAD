namespace DogfighterAD.Domain.Snapshots;

public static class SnapshotCompletionStatusCalculator
{
    public static SnapshotCompletionStatus Calculate(
        IEnumerable<string> requestedCapabilities,
        IEnumerable<CapabilityCoverage> coverage)
    {
        ArgumentNullException.ThrowIfNull(requestedCapabilities);
        ArgumentNullException.ThrowIfNull(coverage);

        var requested = requestedCapabilities
            .Where(capability => !string.IsNullOrWhiteSpace(capability))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (requested.Length == 0)
        {
            return SnapshotCompletionStatus.Complete;
        }

        var coverageByCapability = coverage
            .Where(item => item is not null && !string.IsNullOrWhiteSpace(item.CapabilityId))
            .GroupBy(item => item.CapabilityId, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group.Count() == 1
                    ? group.Single().Status
                    : CapabilityStatus.Failed,
                StringComparer.Ordinal);

        var statuses = requested
            .Select(capability => coverageByCapability.TryGetValue(capability, out var status)
                ? status
                : CapabilityStatus.Failed)
            .ToArray();

        if (statuses.All(IsSatisfied))
        {
            return SnapshotCompletionStatus.Complete;
        }

        if (statuses.Any(status =>
                status is CapabilityStatus.Complete or
                    CapabilityStatus.Partial or
                    CapabilityStatus.NotApplicable))
        {
            return SnapshotCompletionStatus.Partial;
        }

        return SnapshotCompletionStatus.Failed;
    }

    private static bool IsSatisfied(CapabilityStatus status) =>
        status is CapabilityStatus.Complete or CapabilityStatus.NotApplicable;
}
