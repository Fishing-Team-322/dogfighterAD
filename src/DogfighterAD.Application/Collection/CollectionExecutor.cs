using DogfighterAD.Application.Contracts;
using DogfighterAD.Application.Snapshots;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Collection;

public sealed class CollectionExecutor
{
    private readonly SnapshotFragmentMerger _fragmentMerger;
    private readonly TimeProvider _timeProvider;

    public CollectionExecutor()
        : this(new SnapshotFragmentMerger(), TimeProvider.System)
    {
    }

    public CollectionExecutor(
        SnapshotFragmentMerger fragmentMerger,
        TimeProvider timeProvider)
    {
        _fragmentMerger = fragmentMerger ?? throw new ArgumentNullException(nameof(fragmentMerger));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public async Task<CollectionExecutionResult> ExecuteAsync(
        CollectionPlan plan,
        Guid scanId,
        string target,
        CancellationToken cancellationToken,
        Action<CollectionProgressEvent>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(plan);

        if (string.IsNullOrWhiteSpace(target))
        {
            throw new ArgumentException("Collection target must be provided.", nameof(target));
        }

        if (plan.ExecutionPolicy.MaxConcurrency < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(plan),
                "Collection plan MaxConcurrency must be at least 1.");
        }

        if (plan.ExecutionPolicy.CollectorTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(plan),
                "Collection plan CollectorTimeout must be greater than zero.");
        }

        var startedAt = _timeProvider.GetUtcNow();
        var fragments = new List<SnapshotFragment>();
        var executionRecords = new List<CollectorExecutionRecord>();

        foreach (var stage in plan.Stages.OrderBy(x => x.Index))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var availableData = _fragmentMerger.Merge(fragments);
            using var concurrencyGate = new SemaphoreSlim(plan.ExecutionPolicy.MaxConcurrency);

            var tasks = stage.Collectors.Select(async plannedCollector =>
            {
                await concurrencyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    return await ExecuteCollectorAsync(
                        plannedCollector,
                        plan.ExecutionPolicy,
                        scanId,
                        target,
                        availableData,
                        cancellationToken,
                        progress).ConfigureAwait(false);
                }
                finally
                {
                    concurrencyGate.Release();
                }
            }).ToArray();

            var stageResults = await Task.WhenAll(tasks).ConfigureAwait(false);

            foreach (var result in stageResults.OrderBy(x => x.Record.CollectorId, StringComparer.Ordinal))
            {
                fragments.Add(result.Fragment);
                executionRecords.Add(result.Record);
            }
        }

        var completedAt = _timeProvider.GetUtcNow();

        return new CollectionExecutionResult
        {
            ScanId = scanId,
            Target = target,
            StartedAt = startedAt,
            CompletedAt = completedAt,
            Data = _fragmentMerger.Merge(fragments),
            Collectors = executionRecords
                .OrderBy(x => x.StartedAt)
                .ThenBy(x => x.CollectorId, StringComparer.Ordinal)
                .ToArray()
        };
    }

    private async Task<CollectorExecutionResult> ExecuteCollectorAsync(
        PlannedCollector planned,
        CollectionExecutionPolicy policy,
        Guid scanId,
        string target,
        SnapshotFragment availableData,
        CancellationToken cancellationToken,
        Action<CollectionProgressEvent>? progress)
    {
        var collector = planned.Collector;

        if (planned.SelectedCapabilities.Any(
                capability => !collector.ProvidesCapabilities.Contains(capability)))
        {
            throw new InvalidOperationException(
                $"Collection plan assigns unsupported capabilities to collector '{collector.Id}'.");
        }

        var unsatisfiedDependencies = collector.RequiresCapabilities
            .Where(capability => !IsCapabilitySatisfied(availableData.Coverage, capability))
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToArray();

        if (unsatisfiedDependencies.Length > 0)
        {
            var timestamp = _timeProvider.GetUtcNow();
            const string issueCode = "collection.collector.blocked";
            var fragment = CreateFailureFragment(
                planned,
                target,
                CapabilityStatus.Blocked,
                issueCode,
                $"Collector was blocked because required capabilities were unavailable: {string.Join(", ", unsatisfiedDependencies)}.",
                timestamp,
                timestamp);

            ReportProgress(progress, new CollectionProgressEvent
            {
                CollectorId = collector.Id,
                State = CollectionProgressState.Blocked,
                Timestamp = timestamp,
                Elapsed = TimeSpan.Zero,
                IssueCode = issueCode
            });

            return new CollectorExecutionResult(
                fragment,
                new CollectorExecutionRecord
                {
                    CollectorId = collector.Id,
                    CollectorVersion = collector.Version,
                    SelectedCapabilities = planned.SelectedCapabilities,
                    Status = CollectorExecutionStatus.Blocked,
                    StartedAt = timestamp,
                    CompletedAt = timestamp
                });
        }

        var startedAt = _timeProvider.GetUtcNow();
        using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        linkedCancellation.CancelAfter(policy.CollectorTimeout);

        ReportProgress(progress, new CollectionProgressEvent
        {
            CollectorId = collector.Id,
            State = CollectionProgressState.Started,
            Timestamp = startedAt,
            Timeout = policy.CollectorTimeout
        });

        try
        {
            var context = new CollectionContext(
                scanId,
                target,
                planned.SelectedCapabilities.ToHashSet(StringComparer.Ordinal),
                availableData);

            // A collector is an extension boundary and may enter blocking native code before its
            // CollectAsync method returns a Task. Invoke it off the orchestration thread and apply
            // the linked timeout to the returned task so synchronous pre-await blocking cannot
            // bypass the collection timeout.
            var collectorTask = Task.Run(
                () => collector.CollectAsync(context, linkedCancellation.Token),
                CancellationToken.None);
            ObserveBackgroundFault(collectorTask);

            var result = await collectorTask
                .WaitAsync(linkedCancellation.Token)
                .ConfigureAwait(false);

            // A collector may return successfully after cancellation was requested.
            linkedCancellation.Token.ThrowIfCancellationRequested();
            var normalized = ValidateAndNormalizeResult(planned, result);
            var completedAt = _timeProvider.GetUtcNow();

            ReportProgress(progress, new CollectionProgressEvent
            {
                CollectorId = collector.Id,
                State = CollectionProgressState.Completed,
                Timestamp = completedAt,
                Elapsed = completedAt - startedAt
            });

            return new CollectorExecutionResult(
                normalized,
                new CollectorExecutionRecord
                {
                    CollectorId = collector.Id,
                    CollectorVersion = collector.Version,
                    SelectedCapabilities = planned.SelectedCapabilities,
                    Status = CollectorExecutionStatus.Completed,
                    StartedAt = startedAt,
                    CompletedAt = completedAt
                });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            var completedAt = _timeProvider.GetUtcNow();
            ReportProgress(progress, new CollectionProgressEvent
            {
                CollectorId = collector.Id,
                State = CollectionProgressState.Canceled,
                Timestamp = completedAt,
                Elapsed = completedAt - startedAt
            });
            throw;
        }
        catch (OperationCanceledException)
        {
            var completedAt = _timeProvider.GetUtcNow();
            const string issueCode = "collection.collector.timeout";
            var fragment = CreateFailureFragment(
                planned,
                target,
                CapabilityStatus.Failed,
                issueCode,
                $"Collector exceeded its timeout of {policy.CollectorTimeout}.",
                startedAt,
                completedAt);

            ReportProgress(progress, new CollectionProgressEvent
            {
                CollectorId = collector.Id,
                State = CollectionProgressState.TimedOut,
                Timestamp = completedAt,
                Elapsed = completedAt - startedAt,
                Timeout = policy.CollectorTimeout,
                IssueCode = issueCode
            });

            return new CollectorExecutionResult(
                fragment,
                new CollectorExecutionRecord
                {
                    CollectorId = collector.Id,
                    CollectorVersion = collector.Version,
                    SelectedCapabilities = planned.SelectedCapabilities,
                    Status = CollectorExecutionStatus.TimedOut,
                    StartedAt = startedAt,
                    CompletedAt = completedAt
                });
        }
        catch (CollectorOperationalException exception)
        {
            var completedAt = _timeProvider.GetUtcNow();
            var fragment = CreateFailureFragment(
                planned,
                target,
                CapabilityStatus.Failed,
                exception.IssueCode,
                exception.SafeMessage,
                startedAt,
                completedAt);

            ReportProgress(progress, new CollectionProgressEvent
            {
                CollectorId = collector.Id,
                State = CollectionProgressState.Failed,
                Timestamp = completedAt,
                Elapsed = completedAt - startedAt,
                IssueCode = exception.IssueCode
            });

            return new CollectorExecutionResult(
                fragment,
                new CollectorExecutionRecord
                {
                    CollectorId = collector.Id,
                    CollectorVersion = collector.Version,
                    SelectedCapabilities = planned.SelectedCapabilities,
                    Status = CollectorExecutionStatus.Failed,
                    StartedAt = startedAt,
                    CompletedAt = completedAt
                });
        }
        catch (CollectorContractException)
        {
            var completedAt = _timeProvider.GetUtcNow();
            const string issueCode = "collection.collector.contract-invalid";
            var fragment = CreateFailureFragment(
                planned,
                target,
                CapabilityStatus.Failed,
                issueCode,
                "Collector returned data that violates its declared capability contract.",
                startedAt,
                completedAt);

            ReportProgress(progress, new CollectionProgressEvent
            {
                CollectorId = collector.Id,
                State = CollectionProgressState.Failed,
                Timestamp = completedAt,
                Elapsed = completedAt - startedAt,
                IssueCode = issueCode
            });

            return new CollectorExecutionResult(
                fragment,
                new CollectorExecutionRecord
                {
                    CollectorId = collector.Id,
                    CollectorVersion = collector.Version,
                    SelectedCapabilities = planned.SelectedCapabilities,
                    Status = CollectorExecutionStatus.Failed,
                    StartedAt = startedAt,
                    CompletedAt = completedAt
                });
        }
        catch (Exception)
        {
            var completedAt = _timeProvider.GetUtcNow();
            const string issueCode = "collection.collector.failed";
            var fragment = CreateFailureFragment(
                planned,
                target,
                CapabilityStatus.Failed,
                issueCode,
                "Collector failed with an unexpected error. Detailed exception data is intentionally not stored in the snapshot.",
                startedAt,
                completedAt);

            ReportProgress(progress, new CollectionProgressEvent
            {
                CollectorId = collector.Id,
                State = CollectionProgressState.Failed,
                Timestamp = completedAt,
                Elapsed = completedAt - startedAt,
                IssueCode = issueCode
            });

            return new CollectorExecutionResult(
                fragment,
                new CollectorExecutionRecord
                {
                    CollectorId = collector.Id,
                    CollectorVersion = collector.Version,
                    SelectedCapabilities = planned.SelectedCapabilities,
                    Status = CollectorExecutionStatus.Failed,
                    StartedAt = startedAt,
                    CompletedAt = completedAt
                });
        }
    }

    private static void ReportProgress(
        Action<CollectionProgressEvent>? progress,
        CollectionProgressEvent progressEvent)
    {
        if (progress is null)
        {
            return;
        }

        try
        {
            progress(progressEvent);
        }
        catch (Exception)
        {
            // Runtime diagnostics are best-effort and must never change collection semantics.
        }
    }

    private static void ObserveBackgroundFault(Task task)
    {
        _ = task.ContinueWith(
            static completedTask => _ = completedTask.Exception,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously | TaskContinuationOptions.OnlyOnFaulted,
            TaskScheduler.Default);
    }

    private static SnapshotFragment ValidateAndNormalizeResult(
        PlannedCollector planned,
        CollectorResult? result)
    {
        var collector = planned.Collector;

        if (result is null ||
            !StringComparer.Ordinal.Equals(result.CollectorId, collector.Id) ||
            !StringComparer.Ordinal.Equals(result.CollectorVersion, collector.Version))
        {
            throw new CollectorContractException();
        }

        var duplicateCoverage = result.Fragment.Coverage
            .GroupBy(x => x.CapabilityId, StringComparer.Ordinal)
            .Any(group => group.Count() > 1);

        if (duplicateCoverage)
        {
            throw new CollectorContractException();
        }

        var returnedCapabilities = result.Fragment.Coverage
            .Select(x => x.CapabilityId)
            .ToHashSet(StringComparer.Ordinal);

        if (planned.SelectedCapabilities.Any(capability => !returnedCapabilities.Contains(capability)))
        {
            throw new CollectorContractException();
        }

        if (returnedCapabilities.Any(capability => !collector.ProvidesCapabilities.Contains(capability)))
        {
            throw new CollectorContractException();
        }

        if (result.Fragment.Coverage.Any(item =>
                planned.SelectedCapabilities.Contains(item.CapabilityId, StringComparer.Ordinal) &&
                item.Status == CapabilityStatus.NotRequested))
        {
            throw new CollectorContractException();
        }

        if (result.Fragment.Observations.Any(
                fact => !collector.ProvidesCapabilities.Contains(fact.CapabilityId)))
        {
            throw new CollectorContractException();
        }

        var identity = new CollectorIdentity(collector.Id, collector.Version);

        return result.Fragment with
        {
            Coverage = result.Fragment.Coverage
                .Select(item => item with
                {
                    Collectors = item.Collectors
                        .Append(identity)
                        .Distinct()
                        .OrderBy(x => x.Id, StringComparer.Ordinal)
                        .ThenBy(x => x.Version, StringComparer.Ordinal)
                        .ToArray(),
                    Issues = item.Issues
                        .Select(issue => issue with
                        {
                            CapabilityId = issue.CapabilityId ?? item.CapabilityId,
                            CollectorId = issue.CollectorId ?? collector.Id
                        })
                        .ToArray()
                })
                .ToArray(),
            Observations = result.Fragment.Observations
                .Select(fact => fact with
                {
                    Source = fact.Source with
                    {
                        CollectorId = collector.Id,
                        CollectorVersion = collector.Version
                    }
                })
                .ToArray()
        };
    }

    private static bool IsCapabilitySatisfied(
        IReadOnlyList<CapabilityCoverage> coverage,
        string capability)
    {
        var item = coverage.SingleOrDefault(
            x => StringComparer.Ordinal.Equals(x.CapabilityId, capability));

        return item?.Status is CapabilityStatus.Complete or CapabilityStatus.NotApplicable;
    }

    private static SnapshotFragment CreateFailureFragment(
        PlannedCollector planned,
        string target,
        CapabilityStatus status,
        string issueCode,
        string message,
        DateTimeOffset startedAt,
        DateTimeOffset completedAt)
    {
        var collector = planned.Collector;
        var identity = new CollectorIdentity(collector.Id, collector.Version);

        return new SnapshotFragment
        {
            Coverage = planned.SelectedCapabilities
                .OrderBy(x => x, StringComparer.Ordinal)
                .Select(capability => new CapabilityCoverage
                {
                    CapabilityId = capability,
                    Status = status,
                    StartedAt = startedAt,
                    CompletedAt = completedAt,
                    ObservedItemCount = 0,
                    Collectors = [identity],
                    Issues = [new CollectionIssue
                    {
                        Code = issueCode,
                        Severity = CollectionIssueSeverity.Error,
                        Message = message,
                        CapabilityId = capability,
                        CollectorId = collector.Id,
                        Target = target
                    }]
                })
                .ToArray()
        };
    }

    private sealed class CollectorContractException : Exception
    {
    }

    private sealed record CollectorExecutionResult(
        SnapshotFragment Fragment,
        CollectorExecutionRecord Record);
}

public sealed record CollectionExecutionResult
{
    public required Guid ScanId { get; init; }
    public required string Target { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public required SnapshotFragment Data { get; init; }
    public required IReadOnlyList<CollectorExecutionRecord> Collectors { get; init; }
}

public sealed record CollectorExecutionRecord
{
    public required string CollectorId { get; init; }
    public required string CollectorVersion { get; init; }
    public required IReadOnlyList<string> SelectedCapabilities { get; init; }
    public required CollectorExecutionStatus Status { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
}

public sealed record CollectionProgressEvent
{
    public required string CollectorId { get; init; }
    public required CollectionProgressState State { get; init; }
    public required DateTimeOffset Timestamp { get; init; }
    public TimeSpan? Elapsed { get; init; }
    public TimeSpan? Timeout { get; init; }
    public string? IssueCode { get; init; }
}

public enum CollectionProgressState
{
    Started,
    Completed,
    Failed,
    TimedOut,
    Blocked,
    Canceled
}

public enum CollectorExecutionStatus
{
    Completed,
    Failed,
    TimedOut,
    Blocked
}
