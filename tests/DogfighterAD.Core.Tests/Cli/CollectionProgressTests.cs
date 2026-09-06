using DogfighterAD.Application.Collection;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Cli;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Cli;

public sealed class CollectionProgressTests
{
    [Fact]
    public async Task Executor_ReportsCollectorStartAndCompletion()
    {
        var token = TestContext.Current.CancellationToken;
        var collector = new CompleteCollector();
        var profile = new CollectionProfile
        {
            Name = "progress-test",
            RequestedCapabilities = new HashSet<string>(StringComparer.Ordinal)
            {
                CollectionCapabilities.DirectoryCore
            },
            MaxConcurrency = 1,
            CollectorTimeout = TimeSpan.FromSeconds(5)
        };
        var plan = new CollectionPlanner().BuildPlan(profile, [collector]);
        var events = new List<CollectionProgressEvent>();

        await new CollectionExecutor().ExecuteAsync(
            plan,
            Guid.NewGuid(),
            "dc01.mini.lab",
            token,
            events.Add);

        Assert.Collection(
            events,
            started =>
            {
                Assert.Equal(CollectionProgressState.Started, started.State);
                Assert.Equal(collector.Id, started.CollectorId);
                Assert.Equal(profile.CollectorTimeout, started.Timeout);
                Assert.Null(started.IssueCode);
            },
            completed =>
            {
                Assert.Equal(CollectionProgressState.Completed, completed.State);
                Assert.Equal(collector.Id, completed.CollectorId);
                Assert.NotNull(completed.Elapsed);
                Assert.Null(completed.IssueCode);
            });
    }

    [Fact]
    public void Formatter_PrintsSafeFailureMetadataOnly()
    {
        var line = CliApplication.FormatCollectionProgress(new CollectionProgressEvent
        {
            CollectorId = "ad.ldap.rootdse",
            State = CollectionProgressState.Failed,
            Timestamp = DateTimeOffset.UtcNow,
            Elapsed = TimeSpan.FromSeconds(15),
            IssueCode = "collection.ldap.bind-timeout"
        });

        Assert.Contains("collector=ad.ldap.rootdse", line, StringComparison.Ordinal);
        Assert.Contains("issue=collection.ldap.bind-timeout", line, StringComparison.Ordinal);
        Assert.DoesNotContain("password", line, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class CompleteCollector : ICollector
    {
        public string Id => "progress.complete";
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
            cancellationToken.ThrowIfCancellationRequested();
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
                            ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                                CollectionCapabilities.DirectoryCore),
                            Status = CapabilityStatus.Complete,
                            StartedAt = now,
                            CompletedAt = now,
                            ObservedItemCount = 1
                        }
                    ]
                }));
        }
    }
}
