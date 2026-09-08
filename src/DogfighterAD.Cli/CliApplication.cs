using DogfighterAD.Application.Collection;
using DogfighterAD.Application.Analysis;
using System.Text.Json;
using DogfighterAD.Serialization;

namespace DogfighterAD.Cli;

internal static class CliApplication
{
    public static async Task<int> RunAsync(
        IReadOnlyList<string> args,
        string productVersion,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentException.ThrowIfNullOrWhiteSpace(productVersion);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        var parsed = CliArgumentParser.Parse(args);
        if (!parsed.Success)
        {
            await error.WriteLineAsync(parsed.Error).ConfigureAwait(false);
            await error.WriteLineAsync().ConfigureAwait(false);
            await WriteUsageAsync(error).ConfigureAwait(false);
            return CliExitCodes.InvalidArguments;
        }

        if (parsed.ShowHelp || parsed.Command is null)
        {
            await WriteUsageAsync(output).ConfigureAwait(false);
            return CliExitCodes.Success;
        }

        try
        {
            return parsed.Command switch
            {
                AnalyzeCommand analyze => await AnalysisCommands.AnalyzeAsync(analyze, output, error, cancellationToken).ConfigureAwait(false),
                RulesCommand rules => await AnalysisCommands.RulesAsync(rules, output, cancellationToken).ConfigureAwait(false),
                ScanCommand scan => await RunScanAsync(
                        scan,
                        productVersion,
                        output,
                        error,
                        cancellationToken)
                    .ConfigureAwait(false),
                InspectCommand inspect => await RunInspectAsync(
                        inspect,
                        output,
                        cancellationToken)
                    .ConfigureAwait(false),
                _ => CliExitCodes.InvalidArguments
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await error.WriteLineAsync("Operation canceled.").ConfigureAwait(false);
            return CliExitCodes.Canceled;
        }
        catch (DogadArtifactException exception)
        {
            // Stable domain codes are safe to print; arbitrary imported payload text is not.
            await error.WriteLineAsync($"Artifact operation failed ({exception.Code}).").ConfigureAwait(false);
            return CliExitCodes.RuntimeFailure;
        }
        catch (AnalysisLimitException)
        {
            await error.WriteLineAsync("Analysis evaluation budget exceeded. No truncated report was published.").ConfigureAwait(false);
            return CliExitCodes.RuntimeFailure;
        }
        catch (Exception exception) when (parsed.Command is AnalyzeCommand && (exception is ArgumentException or JsonException))
        {
            await error.WriteLineAsync("Invalid analysis options or policy; verify rule IDs, thresholds and the explicit analysis time.").ConfigureAwait(false);
            return CliExitCodes.InvalidArguments;
        }
        catch (Exception exception)
        {
            await error.WriteLineAsync(
                    $"Operation failed ({exception.GetType().Name}). No credentials or source payloads are printed by the default CLI error path.")
                .ConfigureAwait(false);
            return CliExitCodes.RuntimeFailure;
        }
    }

    private static async Task<int> RunScanAsync(
        ScanCommand command,
        string productVersion,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        if (!BuiltInCollectionProfiles.TryGet(command.Profile, out var profile))
        {
            await error.WriteLineAsync(
                    $"Unknown profile '{command.Profile}'. Available profiles: {string.Join(", ", BuiltInCollectionProfiles.Names)}.")
                .ConfigureAwait(false);
            return CliExitCodes.InvalidArguments;
        }

        using var ldapCredential = command.Username is null
            ? null
            : await ConsoleCredentialPrompt
                .ReadNetworkCredentialAsync(command.Username, error, cancellationToken)
                .ConfigureAwait(false);

        var ldapAuthMode = CollectionComposition.SelectAuthenticationMode(command);
        var namedServerBinding = CollectionComposition.UsesExplicitNamedServerBinding(ldapCredential?.Credential);
        var ldapProtection = command.UseLdaps ? "ldaps" : "sign-seal";
        var sysvolAuthentication = ldapCredential is null ? "os-context" : "portable-kerberos";
        await error.WriteLineAsync(
                $"Starting collection: target={command.Target} profile={profile.Name} " +
                $"ldap-auth={ldapAuthMode.ToString().ToLowerInvariant()} " +
                $"ldap-protection={ldapProtection} " +
                $"ldap-target-mode={(namedServerBinding ? "fqdn-server" : "discovery")} " +
                $"sysvol-auth={sysvolAuthentication} " +
                $"bind-timeout={CollectionComposition.LdapBindTimeout} " +
                $"request-timeout={CollectionComposition.LdapRequestTimeout} " +
                $"collector-timeout={profile.CollectorTimeout}.")
            .ConfigureAwait(false);

        var progressGate = new object();
        void WriteProgress(CollectionProgressEvent progressEvent)
        {
            lock (progressGate)
            {
                error.WriteLine(FormatCollectionProgress(progressEvent));
                error.Flush();
            }
        }

        var collectors = CollectionComposition.CreateCollectors(command, ldapCredential?.Credential);
        var workflow = new ScanWorkflow();
        var result = await workflow.ExecuteAsync(
                new ScanWorkflowRequest
                {
                    Target = command.Target,
                    OutputPath = command.OutputPath,
                    ProductVersion = productVersion,
                    Profile = profile,
                    Collectors = collectors,
                    Progress = WriteProgress,
                    ArtifactOptions = ArtifactBudgets.ForMiB(command.MaxSnapshotMiB)
                },
                cancellationToken)
            .ConfigureAwait(false);

        await CoverageSummaryWriter
            .WriteAsync(output, result.Snapshot, command.OutputPath)
            .ConfigureAwait(false);

        return CliExitCodes.FromSnapshotStatus(result.Snapshot.Metadata.CompletionStatus);
    }

    internal static string FormatCollectionProgress(CollectionProgressEvent progressEvent)
    {
        ArgumentNullException.ThrowIfNull(progressEvent);

        var elapsed = progressEvent.Elapsed is null
            ? string.Empty
            : $" elapsed={progressEvent.Elapsed.Value}";
        var timeout = progressEvent.Timeout is null
            ? string.Empty
            : $" timeout={progressEvent.Timeout.Value}";
        var issue = string.IsNullOrWhiteSpace(progressEvent.IssueCode)
            ? string.Empty
            : $" issue={progressEvent.IssueCode}";

        return progressEvent.State switch
        {
            CollectionProgressState.Started =>
                $"[collection] start collector={progressEvent.CollectorId}{timeout}",
            CollectionProgressState.Completed =>
                $"[collection] done collector={progressEvent.CollectorId}{elapsed}",
            CollectionProgressState.Failed =>
                $"[collection] failed collector={progressEvent.CollectorId}{issue}{elapsed}",
            CollectionProgressState.TimedOut =>
                $"[collection] timeout collector={progressEvent.CollectorId}{issue}{elapsed}{timeout}",
            CollectionProgressState.Blocked =>
                $"[collection] blocked collector={progressEvent.CollectorId}{issue}",
            CollectionProgressState.Canceled =>
                $"[collection] canceled collector={progressEvent.CollectorId}{elapsed}",
            _ => $"[collection] collector={progressEvent.CollectorId} state={progressEvent.State}"
        };
    }

    private static async Task<int> RunInspectAsync(
        InspectCommand command,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var serializer = new DogadArtifactSerializer();
        await using var source = new FileStream(
            command.SnapshotPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var snapshot = await serializer
            .ReadAsync(source, ArtifactBudgets.ForMiB(command.MaxSnapshotMiB).ToReadOptions(), cancellationToken)
            .ConfigureAwait(false);

        await CoverageSummaryWriter
            .WriteAsync(output, snapshot, command.SnapshotPath)
            .ConfigureAwait(false);
        return CliExitCodes.FromSnapshotStatus(snapshot.Metadata.CompletionStatus);
    }

    private static async Task WriteUsageAsync(TextWriter writer)
    {
        await writer.WriteLineAsync("DogfighterAD read-only collection CLI").ConfigureAwait(false);
        await writer.WriteLineAsync().ConfigureAwait(false);
        await writer.WriteLineAsync("Usage:").ConfigureAwait(false);
        await writer.WriteLineAsync("  dogfighter rules [--format json|text]").ConfigureAwait(false);
        await writer.WriteLineAsync("  dogfighter analyze --snapshot <input.dogad> --output <report.json|report.html> [--format json|html] [--policy <policy.json>] [--rule <ID>]... [--as-of <ISO-8601>] [--fail-on informational|low|medium|high|critical|none] [--max-snapshot-mib <1-1024>] [--max-evaluations <1-10000000>]").ConfigureAwait(false);
        await writer.WriteLineAsync("  Analysis is offline. Missing fields produce NotVerified, never inferred defaults. The default reference time is snapshot completion.").ConfigureAwait(false);
        await writer.WriteLineAsync(
                "  dogfighter scan --target <host-or-domain> --output <snapshot.dogad> [--profile minimal|audit-full] [--max-snapshot-mib <1-1024>] [-u <DOMAIN\\user|user@domain>] [--ldap-auth negotiate|ntlm] [--ldaps] [--ldap-port <1-65535>] [--sysvol-authority <host>]...")
            .ConfigureAwait(false);
        await writer.WriteLineAsync(
                "  dogfighter inspect --snapshot <snapshot.dogad> [--max-snapshot-mib <1-1024>]")
            .ConfigureAwait(false);
        await writer.WriteLineAsync().ConfigureAwait(false);
        await writer.WriteLineAsync(
                "Authentication: LDAP defaults to Negotiate. Supplying -u/--username opens a hidden password prompt; the explicit credential is reused for portable Kerberos SYSVOL access so audit-full does not depend on the host SMB logon context. Password command-line options are rejected.")
            .ConfigureAwait(false);
        await writer.WriteLineAsync(
                "NTLM is an explicit LDAP compatibility mode only: use --ldap-auth ntlm together with -u/--username. SYSVOL still uses Kerberos with the same explicit credential.")
            .ConfigureAwait(false);
        await writer.WriteLineAsync(
                "LDAP transport protection is mandatory: without --ldaps DogfighterAD requires LDAP signing and sealing before bind; with --ldaps normal server-certificate validation remains enabled. There is no silent unprotected downgrade.")
            .ConfigureAwait(false);
        await writer.WriteLineAsync(
                "Explicit credentials require a DNS hostname target rather than an IP address. Portable SYSVOL connects directly to that target over SMB and requires SMB signing.")
            .ConfigureAwait(false);
        await writer.WriteLineAsync(
                "Without -u/--username, SYSVOL uses the operating-system network security context for backward compatibility.")
            .ConfigureAwait(false);
        await writer.WriteLineAsync(
                "scan writes a temporary artifact, reads it back through the strict .dogad reader, and only then atomically replaces the requested output file.")
            .ConfigureAwait(false);
    }
}
