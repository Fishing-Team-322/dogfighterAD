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
    public async Task ExecuteAsync_OperationalFailurePreservesSafeIssueOnly()
    {
        const string safeMessage = "LDAP authentication failed (code=49/InvalidCredentials).";
        var collector = new ThrowingCollector(
            "root",
            CollectionCapabilities.DirectoryCore,
            new CollectorOperationalException(
                "collection.ldap.authentication-failed",
                safeMessage,
                new InvalidOperationException("SECRET_CANARY")));
        var plan = CreatePlan(
            [CollectionCapabilities.DirectoryCore],
            [collector]);

        var result = await new CollectionExecutor().ExecuteAsync(
            plan,
            Guid.NewGuid(),
            "dc01.mini.lab",
            CancellationToken.None);

        var coverage = Assert.Single(result.Data.Coverage);
        Assert.Equal(CapabilityStatus.Failed, coverage.Status);
        var issue = Assert.Single(coverage.Issues);
        Assert.Equal("collection.ldap.authentication-failed", issue.Code);
        Assert.Equal(safeMessage, issue.Message);
        Assert.DoesNotContain("SECRET_CANARY", issue.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExecuteAsync_SynchronouslyBlockingCollectorCannotBypassTimeout()
    {
        using var started = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);
        var collector = new SynchronouslyBlockingCollector(started, release);
        var plan = CreatePlan(
            [CollectionCapabilities.DirectoryCore],
            [collector],
            TimeSpan.FromMilliseconds(250));

        try
        {
            var execution = new CollectionExecutor().ExecuteAsync(
                plan,
                Guid.NewGuid(),
                "dc01.mini.lab",
                CancellationToken.None);

            Assert.True(started.Wait(TimeSpan.FromSeconds(2)));
            var result = await execution.WaitAsync(TimeSpan.FromSeconds(3));

            var coverage = Assert.Single(result.Data.Coverage);
            Assert.Equal(CapabilityStatus.Failed, coverage.Status);
            Assert.Equal(
                "collection.collector.timeout",
                Assert.Single(coverage.Issues).Code);

            var record = Assert.Single(result.Collectors);
            Assert.Equal(CollectorExecutionStatus.TimedOut, record.Status);
        }
        finally
        {
            release.Set();
        }
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
        IReadOnlyCollection<ICollector> collectors,
        TimeSpan? collectorTimeout = null) =>
        new CollectionPlanner().BuildPlan(
            new CollectionProfile
            {
                Name = "test",
                RequestedCapabilities = requestedCapabilities.ToHashSet(StringComparer.Ordinal),
                MaxConcurrency = 4,
                CollectorTimeout = collectorTimeout ?? TimeSpan.FromSeconds(5)
            },
            collectors);

    private sealed class ThrowingCollector : ICollector
    {
        private readonly Exception _exception;

        public ThrowingCollector(string id, string capability, Exception exception)
        {
            Id = id;
            ProvidesCapabilities = new HashSet<string>(StringComparer.Ordinal) { capability };
            _exception = exception;
        }

        public string Id { get; }
        public string Version => "test";
        public IReadOnlySet<string> ProvidesCapabilities { get; }
        public IReadOnlySet<string> RequiresCapabilities { get; } =
            new HashSet<string>(StringComparer.Ordinal);

        public Task<CollectorResult> CollectAsync(
            CollectionContext context,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromException<CollectorResult>(_exception);
        }
    }

    private sealed class SynchronouslyBlockingCollector : ICollector
    {
        private readonly ManualResetEventSlim _started;
        private readonly ManualResetEventSlim _release;

        public SynchronouslyBlockingCollector(
            ManualResetEventSlim started,
            ManualResetEventSlim release)
        {
            _started = started;
            _release = release;
        }

        public string Id => "blocking";
        public string Version => "test";
        public IReadOnlySet<string> ProvidesCapabilities { get; } =
            new HashSet<string>(StringComparer.Ordinal)
            {
                CollectionCapabilities.DirectoryCore
            };
        public IReadOnlySet<string> RequiresCapabilities { get; } =
            new HashSet<string>(StringComparer.Ordinal);

        public Task<CollectorResult> CollectAsync(
            CollectionContext context,
            CancellationToken cancellationToken)
        {
            _started.Set();
            _release.Wait();

            var now = DateTimeOffset.UtcNow;
            return Task.FromResult(new CollectorResult(
                Id,
                Version,
                new SnapshotFragment
                {
                    Coverage =
                    [
                        new CapabilityCoverage
                        {
                            CapabilityId = CollectionCapabilities.DirectoryCore,
                            Status = CapabilityStatus.Complete,
                            StartedAt = now,
                            CompletedAt = now,
                            ObservedItemCount = 1
                        }
                    ]
                }));
        }
    }

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
