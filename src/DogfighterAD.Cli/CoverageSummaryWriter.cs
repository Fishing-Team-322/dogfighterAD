using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Cli;

internal static class CoverageSummaryWriter
{
    public static async Task WriteAsync(
        TextWriter writer,
        AdSnapshot snapshot,
        string? artifactPath = null)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(snapshot);

        await writer.WriteLineAsync($"Snapshot: {snapshot.Metadata.SnapshotId:D}").ConfigureAwait(false);
        await writer.WriteLineAsync($"Status: {snapshot.Metadata.CompletionStatus}").ConfigureAwait(false);
        await writer.WriteLineAsync($"Profile: {snapshot.Metadata.CollectionProfile ?? "(none)"}").ConfigureAwait(false);
        await writer.WriteLineAsync($"Target: {snapshot.Metadata.Target.InitialTarget}").ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(artifactPath))
        {
            await writer.WriteLineAsync($"Artifact: {Path.GetFullPath(artifactPath)}").ConfigureAwait(false);
        }

        await writer.WriteLineAsync(
                $"Objects: domains={snapshot.Content.Domains.Count} users={snapshot.Content.Users.Count} " +
                $"groups={snapshot.Content.Groups.Count} computers={snapshot.Content.Computers.Count} " +
                $"ous={snapshot.Content.OrganizationalUnits.Count} memberships={snapshot.Content.GroupMemberships.Count} " +
                $"gpos={snapshot.Content.GroupPolicyObjects.Count}")
            .ConfigureAwait(false);
        await writer.WriteLineAsync("Coverage:").ConfigureAwait(false);

        foreach (var item in snapshot.Coverage.OrderBy(x => x.CapabilityId, StringComparer.Ordinal))
        {
            await writer.WriteLineAsync(
                    $"  {item.CapabilityId,-26} {item.Status,-13} items={item.ObservedItemCount} issues={item.Issues.Count}")
                .ConfigureAwait(false);

            foreach (var issue in item.Issues
                         .OrderBy(x => x.Code, StringComparer.Ordinal)
                         .ThenBy(x => x.Message, StringComparer.Ordinal)
                         .ThenBy(x => x.Target, StringComparer.Ordinal))
            {
                await writer.WriteLineAsync(
                        $"    [{issue.Severity}] {issue.Code}: {issue.Message}")
                    .ConfigureAwait(false);
            }
        }
    }
}

internal static class CliExitCodes
{
    public const int Success = 0;
    public const int Partial = 2;
    public const int CollectionFailed = 3;
    public const int InvalidArguments = 64;
    public const int RuntimeFailure = 70;
    public const int Canceled = 130;

    public static int FromSnapshotStatus(SnapshotCompletionStatus status) => status switch
    {
        SnapshotCompletionStatus.Complete => Success,
        SnapshotCompletionStatus.Partial => Partial,
        SnapshotCompletionStatus.Failed => CollectionFailed,
        _ => RuntimeFailure
    };
}
