using DogfighterAD.Application.Collection;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collection;

public sealed class CollectionPlannerTests
{
    [Fact]
    public void BuildPlan_ExpandsDependenciesIntoOrderedStages()
    {
        var core = new StubCollector(
            "core",
            [CollectionCapabilities.DirectoryCore]);
        var users = new StubCollector(
            "users",
            [CollectionCapabilities.DirectoryUsers],
            [CollectionCapabilities.DirectoryCore]);

        var plan = new CollectionPlanner().BuildPlan(
            new CollectionProfile
            {
                Name = "users-only",
                RequestedCapabilities = new HashSet<string>(StringComparer.Ordinal)
                {
                    CollectionCapabilities.DirectoryUsers
                }
            },
            [users, core]);

        Assert.Equal(
            [CollectionCapabilities.DirectoryCore, CollectionCapabilities.DirectoryUsers],
            plan.EffectiveCapabilities);
        Assert.Equal(2, plan.Stages.Count);
        Assert.Equal("core", Assert.Single(plan.Stages[0].Collectors).Collector.Id);

        var usersPlan = Assert.Single(plan.Stages[1].Collectors);
        Assert.Equal("users", usersPlan.Collector.Id);
        Assert.Equal([CollectionCapabilities.DirectoryUsers], usersPlan.SelectedCapabilities);
    }

    [Fact]
    public void BuildPlan_MultipleProvidersRequireExplicitChoice()
    {
        var first = new StubCollector(
            "core-a",
            [CollectionCapabilities.DirectoryCore]);
        var second = new StubCollector(
            "core-b",
            [CollectionCapabilities.DirectoryCore]);

        var exception = Assert.Throws<CollectionPlanningException>(() =>
            new CollectionPlanner().BuildPlan(
                new CollectionProfile
                {
                    Name = "ambiguous",
                    RequestedCapabilities = new HashSet<string>(StringComparer.Ordinal)
                    {
                        CollectionCapabilities.DirectoryCore
                    }
                },
                [first, second]));

        Assert.Equal("collection.plan.provider-ambiguous", exception.Issue.Code);
    }

    [Fact]
    public void BuildPlan_PreferredProviderResolvesAmbiguityDeterministically()
    {
        var first = new StubCollector(
            "core-a",
            [CollectionCapabilities.DirectoryCore]);
        var second = new StubCollector(
            "core-b",
            [CollectionCapabilities.DirectoryCore]);

        var plan = new CollectionPlanner().BuildPlan(
            new CollectionProfile
            {
                Name = "preferred",
                RequestedCapabilities = new HashSet<string>(StringComparer.Ordinal)
                {
                    CollectionCapabilities.DirectoryCore
                },
                PreferredCollectors = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [CollectionCapabilities.DirectoryCore] = "core-b"
                }
            },
            [first, second]);

        Assert.Equal("core-b", Assert.Single(Assert.Single(plan.Stages).Collectors).Collector.Id);
    }

    [Fact]
    public void BuildPlan_CapabilityCycleFailsBeforeExecution()
    {
        const string capabilityA = "test.a";
        const string capabilityB = "test.b";

        var a = new StubCollector("a", [capabilityA], [capabilityB]);
        var b = new StubCollector("b", [capabilityB], [capabilityA]);

        var exception = Assert.Throws<CollectionPlanningException>(() =>
            new CollectionPlanner().BuildPlan(
                new CollectionProfile
                {
                    Name = "cycle",
                    RequestedCapabilities = new HashSet<string>(StringComparer.Ordinal)
                    {
                        capabilityA
                    }
                },
                [a, b]));

        Assert.Equal("collection.plan.capability-cycle", exception.Issue.Code);
    }

    [Fact]
    public void BuildPlan_DuplicateCollectorIdsAreRejected()
    {
        var first = new StubCollector("duplicate", ["test.a"]);
        var second = new StubCollector("duplicate", ["test.b"]);

        var exception = Assert.Throws<CollectionPlanningException>(() =>
            new CollectionPlanner().BuildPlan(
                new CollectionProfile
                {
                    Name = "duplicate-registry",
                    RequestedCapabilities = new HashSet<string>(StringComparer.Ordinal)
                    {
                        "test.a"
                    }
                },
                [first, second]));

        Assert.Equal("collection.registry.duplicate-collector-id", exception.Issue.Code);
    }

    private sealed class StubCollector : ICollector
    {
        public StubCollector(
            string id,
            IEnumerable<string> provides,
            IEnumerable<string>? requires = null)
        {
            Id = id;
            ProvidesCapabilities = provides.ToHashSet(StringComparer.Ordinal);
            RequiresCapabilities = (requires ?? []).ToHashSet(StringComparer.Ordinal);
        }

        public string Id { get; }
        public string Version => "test";
        public IReadOnlySet<string> ProvidesCapabilities { get; }
        public IReadOnlySet<string> RequiresCapabilities { get; }

        public Task<CollectorResult> CollectAsync(
            CollectionContext context,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException("Planner tests never execute collectors.");
    }
}
