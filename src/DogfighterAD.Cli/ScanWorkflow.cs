using DogfighterAD.Application.Collection;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Application.Snapshots;
using DogfighterAD.Domain.Snapshots;
using DogfighterAD.Serialization;

namespace DogfighterAD.Cli;

internal sealed record ScanWorkflowRequest
{
    public required string Target { get; init; }
    public required string OutputPath { get; init; }
    public required string ProductVersion { get; init; }
    public required CollectionProfile Profile { get; init; }
    public required IReadOnlyCollection<ICollector> Collectors { get; init; }
    public Action<CollectionProgressEvent>? Progress { get; init; }
}

internal sealed record ScanWorkflowResult(
    AdSnapshot Snapshot,
    CollectionExecutionResult Execution);

internal sealed class ScanWorkflow
{
    private readonly CollectionPlanner _planner;
    private readonly CollectionExecutor _executor;
    private readonly SnapshotAssembler _assembler;
    private readonly DogadArtifactSerializer _serializer;

    public ScanWorkflow()
        : this(
            new CollectionPlanner(),
            new CollectionExecutor(),
            new SnapshotAssembler(),
            new DogadArtifactSerializer())
    {
    }

    public ScanWorkflow(
        CollectionPlanner planner,
        CollectionExecutor executor,
        SnapshotAssembler assembler,
        DogadArtifactSerializer serializer)
    {
        _planner = planner ?? throw new ArgumentNullException(nameof(planner));
        _executor = executor ?? throw new ArgumentNullException(nameof(executor));
        _assembler = assembler ?? throw new ArgumentNullException(nameof(assembler));
        _serializer = serializer ?? throw new ArgumentNullException(nameof(serializer));
    }

    public async Task<ScanWorkflowResult> ExecuteAsync(
        ScanWorkflowRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Target);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.OutputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.ProductVersion);

        var plan = _planner.BuildPlan(request.Profile, request.Collectors);
        var scanId = Guid.NewGuid();
        var execution = await _executor
            .ExecuteAsync(
                plan,
                scanId,
                request.Target,
                cancellationToken,
                request.Progress)
            .ConfigureAwait(false);

        var targetIdentity = BuildTargetIdentity(request.Target, execution.Data.Content);
        var snapshot = _assembler.Assemble(new SnapshotAssemblyRequest
        {
            SnapshotId = scanId,
            ProductVersion = request.ProductVersion,
            StartedAt = execution.StartedAt,
            CompletedAt = execution.CompletedAt,
            Target = targetIdentity,
            CollectionProfile = request.Profile.Name,
            RequestedCapabilities = request.Profile.RequestedCapabilities,
            Fragments = [execution.Data]
        });

        await WriteVerifiedArtifactAsync(
                snapshot,
                request.OutputPath,
                cancellationToken)
            .ConfigureAwait(false);

        return new ScanWorkflowResult(snapshot, execution);
    }

    private async Task WriteVerifiedArtifactAsync(
        AdSnapshot snapshot,
        string outputPath,
        CancellationToken cancellationToken)
    {
        var fullOutputPath = Path.GetFullPath(outputPath);
        var outputDirectory = Path.GetDirectoryName(fullOutputPath);
        if (!string.IsNullOrEmpty(outputDirectory))
        {
            Directory.CreateDirectory(outputDirectory);
        }

        var temporaryPath = fullOutputPath + $".tmp-{Guid.NewGuid():N}";
        try
        {
            await using (var destination = new FileStream(
                             temporaryPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             bufferSize: 64 * 1024,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await _serializer
                    .WriteAsync(snapshot, destination, cancellationToken)
                    .ConfigureAwait(false);
            }

            AdSnapshot verified;
            await using (var source = new FileStream(
                             temporaryPath,
                             FileMode.Open,
                             FileAccess.Read,
                             FileShare.Read,
                             bufferSize: 64 * 1024,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                verified = await _serializer
                    .ReadAsync(source, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
            }

            if (verified.Metadata.SnapshotId != snapshot.Metadata.SnapshotId ||
                verified.Metadata.CompletionStatus != snapshot.Metadata.CompletionStatus)
            {
                throw new InvalidDataException(
                    "The written .dogad artifact did not round-trip to the expected snapshot identity/status.");
            }

            File.Move(temporaryPath, fullOutputPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static TargetIdentity BuildTargetIdentity(
        string initialTarget,
        SnapshotContent content)
    {
        var environment = content.DirectoryEnvironment;
        var domain = content.Domains.FirstOrDefault();

        return new TargetIdentity
        {
            InitialTarget = initialTarget,
            ForestDnsName = NamingContextToDnsName(environment?.RootDomainNamingContext),
            DomainDnsName = domain?.DnsName,
            DomainSid = domain?.Sid,
            RootDseDnsHostName = environment?.DnsHostName
        };
    }

    private static string? NamingContextToDnsName(string? namingContext)
    {
        if (string.IsNullOrWhiteSpace(namingContext))
        {
            return null;
        }

        var labels = namingContext
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length == 0 || labels.Any(label =>
                !label.StartsWith("DC=", StringComparison.OrdinalIgnoreCase) ||
                label.Length <= 3))
        {
            return null;
        }

        return string.Join('.', labels.Select(label => label[3..]));
    }
}
