using DogfighterAD.Application.Contracts;

namespace DogfighterAD.Application.Collection;

public sealed class CollectionPlanner
{
    public CollectionPlan BuildPlan(
        CollectionProfile profile,
        IReadOnlyCollection<ICollector> availableCollectors)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(availableCollectors);

        ValidateProfile(profile);
        ValidateCollectorRegistry(availableCollectors);

        var providersByCapability = availableCollectors
            .SelectMany(collector => collector.ProvidesCapabilities.Select(capability => (capability, collector)))
            .GroupBy(x => x.capability, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group.Select(x => x.collector)
                    .OrderBy(x => x.Id, StringComparer.Ordinal)
                    .ThenBy(x => x.Version, StringComparer.Ordinal)
                    .ToArray(),
                StringComparer.Ordinal);

        var selectedByCapability = new Dictionary<string, ICollector>(StringComparer.Ordinal);
        var resolving = new HashSet<string>(StringComparer.Ordinal);
        var resolutionStack = new Stack<string>();

        foreach (var capability in profile.RequestedCapabilities.OrderBy(x => x, StringComparer.Ordinal))
        {
            ResolveCapability(
                capability,
                profile,
                providersByCapability,
                selectedByCapability,
                resolving,
                resolutionStack);
        }

        var selectedCollectors = selectedByCapability.Values
            .GroupBy(x => x.Id, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Single(), StringComparer.Ordinal);

        var selectedCapabilitiesByCollector = selectedByCapability
            .GroupBy(pair => pair.Value.Id, pair => pair.Key, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => (IReadOnlyList<string>)group.OrderBy(x => x, StringComparer.Ordinal).ToArray(),
                StringComparer.Ordinal);

        var dependencies = selectedCollectors.Values.ToDictionary(
            collector => collector.Id,
            collector => collector.RequiresCapabilities
                .Select(requiredCapability => selectedByCapability[requiredCapability].Id)
                .Where(providerId => !StringComparer.Ordinal.Equals(providerId, collector.Id))
                .ToHashSet(StringComparer.Ordinal),
            StringComparer.Ordinal);

        var stages = BuildStages(
            selectedCollectors,
            selectedCapabilitiesByCollector,
            dependencies);

        return new CollectionPlan
        {
            ProfileName = profile.Name,
            RequestedCapabilities = profile.RequestedCapabilities
                .OrderBy(x => x, StringComparer.Ordinal)
                .ToArray(),
            EffectiveCapabilities = selectedByCapability.Keys
                .OrderBy(x => x, StringComparer.Ordinal)
                .ToArray(),
            Stages = stages,
            ExecutionPolicy = new CollectionExecutionPolicy(
                profile.MaxConcurrency,
                profile.CollectorTimeout)
        };
    }

    private static ICollector ResolveCapability(
        string capability,
        CollectionProfile profile,
        IReadOnlyDictionary<string, ICollector[]> providersByCapability,
        IDictionary<string, ICollector> selectedByCapability,
        ISet<string> resolving,
        Stack<string> resolutionStack)
    {
        if (resolving.Contains(capability))
        {
            var chain = resolutionStack.Reverse().Append(capability);
            throw PlanningError(
                "collection.plan.capability-cycle",
                $"Capability dependency cycle detected: {string.Join(" -> ", chain)}.",
                capability);
        }

        if (selectedByCapability.TryGetValue(capability, out var alreadySelected))
        {
            return alreadySelected;
        }

        if (!providersByCapability.TryGetValue(capability, out var providers) || providers.Length == 0)
        {
            throw PlanningError(
                "collection.plan.provider-missing",
                $"No registered collector provides required capability '{capability}'.",
                capability);
        }

        ICollector selected;

        if (profile.PreferredCollectors.TryGetValue(capability, out var preferredCollectorId))
        {
            selected = providers.SingleOrDefault(
                x => StringComparer.Ordinal.Equals(x.Id, preferredCollectorId))
                ?? throw PlanningError(
                    "collection.plan.preferred-provider-invalid",
                    $"Preferred collector '{preferredCollectorId}' does not provide capability '{capability}'.",
                    capability,
                    preferredCollectorId);
        }
        else if (providers.Length == 1)
        {
            selected = providers[0];
        }
        else
        {
            throw PlanningError(
                "collection.plan.provider-ambiguous",
                $"Capability '{capability}' has multiple providers ({string.Join(", ", providers.Select(x => x.Id))}). " +
                "Choose one explicitly in the collection profile.",
                capability);
        }

        resolving.Add(capability);
        resolutionStack.Push(capability);
        selectedByCapability[capability] = selected;

        foreach (var dependency in selected.RequiresCapabilities.OrderBy(x => x, StringComparer.Ordinal))
        {
            ResolveCapability(
                dependency,
                profile,
                providersByCapability,
                selectedByCapability,
                resolving,
                resolutionStack);
        }

        resolutionStack.Pop();
        resolving.Remove(capability);

        return selected;
    }

    private static IReadOnlyList<CollectionStage> BuildStages(
        IReadOnlyDictionary<string, ICollector> selectedCollectors,
        IReadOnlyDictionary<string, IReadOnlyList<string>> selectedCapabilitiesByCollector,
        IReadOnlyDictionary<string, HashSet<string>> dependencies)
    {
        var remaining = dependencies.ToDictionary(
            pair => pair.Key,
            pair => new HashSet<string>(pair.Value, StringComparer.Ordinal),
            StringComparer.Ordinal);

        var stages = new List<CollectionStage>();
        var stageIndex = 0;

        while (remaining.Count > 0)
        {
            var readyIds = remaining
                .Where(pair => pair.Value.Count == 0)
                .Select(pair => pair.Key)
                .OrderBy(x => x, StringComparer.Ordinal)
                .ToArray();

            if (readyIds.Length == 0)
            {
                throw PlanningError(
                    "collection.plan.collector-cycle",
                    "Collector dependency graph contains a cycle.");
            }

            var stageCollectors = readyIds
                .Select(id => new PlannedCollector(
                    selectedCollectors[id],
                    selectedCapabilitiesByCollector[id]))
                .ToArray();

            stages.Add(new CollectionStage(stageIndex++, stageCollectors));

            foreach (var readyId in readyIds)
            {
                remaining.Remove(readyId);
            }

            foreach (var dependencySet in remaining.Values)
            {
                dependencySet.ExceptWith(readyIds);
            }
        }

        return stages;
    }

    private static void ValidateProfile(CollectionProfile profile)
    {
        if (string.IsNullOrWhiteSpace(profile.Name))
        {
            throw PlanningError(
                "collection.profile.name-missing",
                "Collection profile must have a name.");
        }

        if (profile.MaxConcurrency < 1)
        {
            throw PlanningError(
                "collection.profile.concurrency-invalid",
                "Collection profile MaxConcurrency must be at least 1.");
        }

        if (profile.CollectorTimeout <= TimeSpan.Zero)
        {
            throw PlanningError(
                "collection.profile.timeout-invalid",
                "Collection profile CollectorTimeout must be greater than zero.");
        }

        if (profile.RequestedCapabilities.Any(string.IsNullOrWhiteSpace))
        {
            throw PlanningError(
                "collection.profile.capability-invalid",
                "Collection profile contains an empty capability id.");
        }
    }

    private static void ValidateCollectorRegistry(IReadOnlyCollection<ICollector> collectors)
    {
        var duplicateIds = collectors
            .GroupBy(x => x.Id, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToArray();

        if (duplicateIds.Length > 0)
        {
            throw PlanningError(
                "collection.registry.duplicate-collector-id",
                $"Collector ids must be unique in one process. Duplicates: {string.Join(", ", duplicateIds)}.");
        }

        foreach (var collector in collectors)
        {
            if (string.IsNullOrWhiteSpace(collector.Id) || string.IsNullOrWhiteSpace(collector.Version))
            {
                throw PlanningError(
                    "collection.registry.collector-identity-invalid",
                    "Every collector must have a non-empty id and version.",
                    collectorId: collector.Id);
            }

            if (collector.ProvidesCapabilities.Count == 0)
            {
                throw PlanningError(
                    "collection.registry.collector-provides-nothing",
                    $"Collector '{collector.Id}' does not declare any provided capability.",
                    collectorId: collector.Id);
            }
        }
    }

    private static CollectionPlanningException PlanningError(
        string code,
        string message,
        string? capabilityId = null,
        string? collectorId = null) =>
        new(new CollectionPlanningIssue(code, message, capabilityId, collectorId));
}

public sealed record CollectionProfile
{
    public required string Name { get; init; }
    public IReadOnlySet<string> RequestedCapabilities { get; init; } = new HashSet<string>();
    public IReadOnlyDictionary<string, string> PreferredCollectors { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);
    public int MaxConcurrency { get; init; } = 4;
    public TimeSpan CollectorTimeout { get; init; } = TimeSpan.FromMinutes(2);
}

public sealed record CollectionPlan
{
    public required string ProfileName { get; init; }
    public required IReadOnlyList<string> RequestedCapabilities { get; init; }
    public required IReadOnlyList<string> EffectiveCapabilities { get; init; }
    public required IReadOnlyList<CollectionStage> Stages { get; init; }
    public required CollectionExecutionPolicy ExecutionPolicy { get; init; }
}

public sealed record CollectionStage(
    int Index,
    IReadOnlyList<PlannedCollector> Collectors);

public sealed record PlannedCollector(
    ICollector Collector,
    IReadOnlyList<string> SelectedCapabilities);

public sealed record CollectionExecutionPolicy(
    int MaxConcurrency,
    TimeSpan CollectorTimeout);

public sealed record CollectionPlanningIssue(
    string Code,
    string Message,
    string? CapabilityId = null,
    string? CollectorId = null);

public sealed class CollectionPlanningException : Exception
{
    public CollectionPlanningException(CollectionPlanningIssue issue)
        : base($"{issue.Code}: {issue.Message}")
    {
        Issue = issue;
    }

    public CollectionPlanningIssue Issue { get; }
}
