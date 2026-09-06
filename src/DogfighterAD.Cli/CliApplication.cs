using DogfighterAD.Application.Collection;
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

        var ldapCredential = command.Username is null
            ? null
            : ConsoleCredentialPrompt.ReadNetworkCredential(command.Username, error);
        var collectors = CollectionComposition.CreateCollectors(command, ldapCredential);
        var workflow = new ScanWorkflow();
        var result = await workflow.ExecuteAsync(
                new ScanWorkflowRequest
                {
                    Target = command.Target,
                    OutputPath = command.OutputPath,
                    ProductVersion = productVersion,
                    Profile = profile,
                    Collectors = collectors
                },
                cancellationToken)
            .ConfigureAwait(false);

        await CoverageSummaryWriter
            .WriteAsync(output, result.Snapshot, command.OutputPath)
            .ConfigureAwait(false);

        return CliExitCodes.FromSnapshotStatus(result.Snapshot.Metadata.CompletionStatus);
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
            .ReadAsync(source, cancellationToken: cancellationToken)
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
        await writer.WriteLineAsync(
                "  dogfighter scan --target <host-or-domain> --output <snapshot.dogad> [--profile minimal|audit-full] [-u <DOMAIN\\user|user@domain> -p] [--ldaps] [--ldap-port <1-65535>] [--sysvol-authority <host>]...")
            .ConfigureAwait(false);
        await writer.WriteLineAsync(
                "  dogfighter inspect --snapshot <snapshot.dogad>")
            .ConfigureAwait(false);
        await writer.WriteLineAsync().ConfigureAwait(false);
        await writer.WriteLineAsync(
                "Authentication: LDAP defaults to the current operating-system security context. -u/--username with -p/--password enables an explicit LDAP Negotiate credential; -p is a prompt switch and never accepts a password value in arguments.")
            .ConfigureAwait(false);
        await writer.WriteLineAsync(
                "SYSVOL/SMB still uses the operating-system network security context. Explicit LDAP credentials do not establish an SMB session or repair DNS/routing.")
            .ConfigureAwait(false);
        await writer.WriteLineAsync(
                "scan writes a temporary artifact, reads it back through the strict .dogad reader, and only then atomically replaces the requested output file.")
            .ConfigureAwait(false);
    }
}
