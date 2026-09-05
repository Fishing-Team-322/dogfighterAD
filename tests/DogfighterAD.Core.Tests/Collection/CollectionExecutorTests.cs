using DogfighterAD.Application.Collection;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collection;

public sealed class CollectionExecutorTests
{
    [Fact]
    public async Task ExecuteAsync_PassesOnlyPreviousStageDataToDependentCollector()
    {
        var core = new RecordingCollector(
            "core",
            [CollectionCapabilities.DirectoryCore],
            [],
            status: CapabilityStatus.Complete);
        var users = new RecordingCollector(
            "users",
            [CollectionCapabilities.DirectoryUsers],
            [CollectionCapabilities.DirectoryCore],
            status: CapabilityStatus.Complete);

        var plan = CreatePlan(
            [CollectionCapabilities.DirectoryUsers],
            [users, core]);

        var result = await new CollectionExecutor().ExecuteAsync(
            plan,
            Guid.NewGuid(),
            "dc01.mini.lab",
            CancellationToken.None);

        Assert.Equal(1, core.ExecutionCount);
        Assert.Equal(1, users.ExecutionCount);
        Assert.Empty(Assert.Single(core.Contexts).AvailableData.Coverage);

        var usersContext = Assert.Single(users.Contexts);
        Assert.Equal(
            CapabilityStatus.Complete,
            usersContext.AvailableData.Coverage.Single(
                item => item.CapabilityId == CollectionCapabilities.DirectoryCore).Status);

        Assert.Equal(
            [CollectionCapabilities.DirectoryCore, CollectionCapabilities.DirectoryUsers],
            result.Data.Coverage.Select(x => x.CapabilityId).ToArray());
    }

    [Fact]
    public async Task ExecuteAsync_FailedDependencyBlocksDownstreamCollector()
    {
        var core = new RecordingCollector(
            "core",
            [CollectionCapabilities.DirectoryCore],
            [],
            status: CapabilityStatus.Failed);
        var users = new RecordingCollector(
            "users",
            [CollectionCapabilities.DirectoryUsers],
            [CollectionCapabilities.DirectoryCore],
            status: CapabilityStatus.Complete);

        var plan = CreatePlan(
            [CollectionCapabilities.DirectoryUsers],
            [users, core]);

        var result = await new CollectionExecutor().ExecuteAsync(
            plan,
            Guid.NewGuid(),
            "dc01.mini.lab",
            CancellationToken.None);

        Assert.Equal(1, core.ExecutionCount);
        Assert.Equal(0, users.ExecutionCount);

        var usersCoverage = result.Data.Coverage.Single(
            item => item.CapabilityId == CollectionCapabilities.DirectoryUsers);
        Assert.Equal(CapabilityStatus.Blocked, usersCoverage.Status);
        Assert.Equal("collection.collector.blocked", Assert.Single(usersCoverage.Issues).Code);

        var usersRecord = result.Collectors.Single(x => x.CollectorId == "users");
        Assert.Equal(CollectorExecutionStatus.Blocked, usersRecord.Status);
    }

    [Fact]
    public async Task ExecuteAsync_SameStageCollectorsSeeSamePriorState()
    {
        var first = new RecordingCollector(
            "first",
            ["test.first"],
            [],
            status: CapabilityStatus.Complete);
        var second = new RecordingCollector(
            "second",
            ["test.second"],
            [],
            status: CapabilityStatus.Complete);

        var plan = CreatePlan(
            ["test.first", "test.second"],
            [first, second]);

        await new CollectionExecutor().ExecuteAsync(
            plan,
            Guid.NewGuid(),
            "target",
            CancellationToken.None);

        Assert.Empty(Assert.Single(first.Contexts).AvailableData.Coverage);
        Assert.Empty(Assert.Single(second.Contexts).AvailableData.Coverage);
    }

    private static CollectionPlan CreatePlan(
        IEnumerable<string> requestedCapabilities,
        IReadOnlyCollection<ICollector> collectors) =>
        new CollectionPlanner().BuildPlan(
            new CollectionProfile
            {
                Name = "test",
                RequestedCapabilities = requestedCapabilities.ToHashSet(StringComparer.Ordinal),
                MaxConcurrency = 4,
                CollectorTimeout = TimeSpan.FromSeconds(5)
            },
            collectors);

    private sealed class RecordingCollector : ICollector
    {
        private readonly CapabilityStatus _status;

        public RecordingCollector(
            string id,
            IEnumerable<string> provides,
            IEnumerable<string> requires,
            CapabilityStatus status)
        {
            Id = id;
            ProvidesCapabilities = provides.ToHashSet(StringComparer.Ordinal);
            RequiresCapabilities = requires.ToHashSet(StringComparer.Ordinal);
            _status = status;
        }

        public string Id { get; }
        public string Version => "test";
        public IReadOnlySet<string> ProvidesCapabilities { get; }
        public IReadOnlySet<string> RequiresCapabilities { get; }
        public int ExecutionCount { get; private set; }
        public List<CollectionContext> Contexts { get; } = [];

        public Task<CollectorResult> CollectAsync(
            CollectionContext context,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ExecutionCount++;
            Contexts.Add(context);

            var now = DateTimeOffset.UtcNow;
            var coverage = context.RequestedCapabilities
                .OrderBy(x => x, StringComparer.Ordinal)
                .Select(capability => new CapabilityCoverage
                {
                    CapabilityId = capability,
                    Status = _status,
                    StartedAt = now,
                    CompletedAt = now,
                    ObservedItemCount = 0
                })
                .ToArray();

            return Task.FromResult(new CollectorResult(
                Id,
                Version,
                new SnapshotFragment
                {
                    Coverage = coverage
                }));
        }
    }
}
