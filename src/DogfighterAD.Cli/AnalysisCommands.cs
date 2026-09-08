using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using DogfighterAD.Application.Analysis;
using DogfighterAD.Application.Analysis.Rules;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;
using DogfighterAD.Serialization;

namespace DogfighterAD.Cli;

internal sealed record AnalyzeCommand : CliCommand
{
    public required string SnapshotPath { get; init; }
    public required string OutputPath { get; init; }
    public string Format { get; init; } = "json";
    public string? PolicyPath { get; init; }
    public DateTimeOffset? AnalysisTime { get; init; }
    public IReadOnlySet<string>? RuleIds { get; init; }
    public int MaxSnapshotMiB { get; init; } = 512;
    public int MaxEvaluations { get; init; } = 2_000_000;
    public FindingSeverity? FailOn { get; init; } = FindingSeverity.Informational;
}
internal sealed record RulesCommand(bool Json = false) : CliCommand;

internal static class AnalysisArgumentParser
{
    public static CliParseResult ParseRules(IReadOnlyList<string> args)
    {
        if (args.Any(x => x is "--help" or "-h")) return new(null, true, null);
        if (args.Count == 0) return new(new RulesCommand(), false, null);
        if (args.Count == 2 && args[0] == "--format" && args[1] is "json" or "text")
            return new(new RulesCommand(args[1] == "json"), false, null);
        return new(null, false, "rules supports only --format json|text.");
    }
    public static CliParseResult ParseAnalyze(IReadOnlyList<string> args)
    {
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        var rules = new HashSet<string>(StringComparer.Ordinal);
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        { "--snapshot", "--output", "--format", "--policy", "--as-of", "--rule", "--max-snapshot-mib", "--max-evaluations", "--fail-on" };
        for (var i = 0; i < args.Count; i++)
        {
            var key = args[i];
            if (key is "--help" or "-h") return new(null, true, null);
            if (!allowed.Contains(key)) return new(null, false, "Unknown analyze option; use analyze --help.");
            if (++i >= args.Count || string.IsNullOrWhiteSpace(args[i]) || args[i].StartsWith('-'))
                return new(null, false, "An analyze option is missing its value.");
            if (key == "--rule") { rules.Add(args[i]); continue; }
            if (!options.TryAdd(key, args[i])) return new(null, false, "Duplicate analyze option.");
        }
        if (!options.TryGetValue("--snapshot", out var snapshot) || !options.TryGetValue("--output", out var output))
            return new(null, false, "analyze requires --snapshot <input.dogad> and --output <report.json|report.html>.");
        var format = options.GetValueOrDefault("--format", "json");
        if (format is not ("json" or "html")) return new(null, false, "Report format must be json or html.");
        if (!Path.GetExtension(output).Equals("." + format, StringComparison.OrdinalIgnoreCase))
            return new(null, false, "Report output extension must match its json/html format.");
        var budget = 512;
        if (options.TryGetValue("--max-snapshot-mib", out var size) &&
            (!int.TryParse(size, NumberStyles.None, CultureInfo.InvariantCulture, out budget) || budget is < 1 or > 1024))
            return new(null, false, "Snapshot budget must be 1 through 1024 MiB.");
        var evaluations = 2_000_000;
        if (options.TryGetValue("--max-evaluations", out var maximum) &&
            (!int.TryParse(maximum, NumberStyles.None, CultureInfo.InvariantCulture, out evaluations) || evaluations is < 1 or > 10_000_000))
            return new(null, false, "Evaluation budget must be 1 through 10000000.");
        DateTimeOffset? asOf = null;
        if (options.TryGetValue("--as-of", out var date))
        {
            if (!(date.EndsWith('Z') || (date.Length >= 6 && (date[^6] is '+' or '-') && date[^3] == ':')) ||
                !DateTimeOffset.TryParse(date, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
                return new(null, false, "--as-of requires an ISO 8601 timestamp with Z or an explicit timezone offset.");
            asOf = parsed.ToUniversalTime();
        }
        FindingSeverity? failOn = FindingSeverity.Informational;
        if (options.TryGetValue("--fail-on", out var threshold))
        {
            if (threshold == "none") failOn = null;
            else if (Enum.TryParse<FindingSeverity>(threshold, true, out var severity) && Enum.IsDefined(severity) && threshold.All(char.IsAsciiLetter))
                failOn = severity;
            else return new(null, false, "--fail-on must be informational, low, medium, high, critical or none.");
        }
        return new(new AnalyzeCommand { SnapshotPath = snapshot, OutputPath = output, Format = format,
            PolicyPath = options.GetValueOrDefault("--policy"), AnalysisTime = asOf, RuleIds = rules.Count == 0 ? null : rules,
            MaxSnapshotMiB = budget, MaxEvaluations = evaluations, FailOn = failOn }, false, null);
    }
}

internal static class AnalysisCommands
{
    public static async Task<int> RulesAsync(RulesCommand command, TextWriter output, CancellationToken token)
    {
        var catalog = BuiltInRulePack.Create().Select(r => r.Metadata).ToArray();
        token.ThrowIfCancellationRequested();
        if (command.Json)
            await output.WriteLineAsync(JsonSerializer.Serialize(catalog, AnalysisReportWriter.CreateJsonOptions())).ConfigureAwait(false);
        else
        {
            await output.WriteLineAsync($"{BuiltInRulePack.Id} {BuiltInRulePack.Version}: {catalog.Length} rules").ConfigureAwait(false);
            foreach (var rule in catalog)
                await output.WriteLineAsync($"{rule.Id} [{rule.DefaultSeverity}] {rule.Title}").ConfigureAwait(false);
        }
        return CliExitCodes.Success;
    }
    public static async Task<int> AnalyzeAsync(AnalyzeCommand command, TextWriter output, TextWriter error, CancellationToken token)
    {
        // No collector, LDAP factory, SYSVOL client or credential prompt is created by this path.
        var sourcePath = Path.GetFullPath(command.SnapshotPath);
        var outputPath = Path.GetFullPath(command.OutputPath);
        var comparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        if (comparer.Equals(sourcePath, outputPath)) throw new ArgumentException("Snapshot and report paths must differ.");
        if (command.PolicyPath is not null && comparer.Equals(Path.GetFullPath(command.PolicyPath), outputPath))
            throw new ArgumentException("Policy and report paths must differ.");
        var policy = command.PolicyPath is null ? new AnalysisPolicy() : await ReadPolicyAsync(command.PolicyPath, token).ConfigureAwait(false);
        var engine = new RuleEngine(BuiltInRulePack.Create(), BuiltInRulePack.Id, BuiltInRulePack.Version);
        if (command.RuleIds is not null && command.RuleIds.Any(id => !engine.Catalog.Any(r => r.Id == id)))
            throw new ArgumentException("Unknown rule ID.");
        var input = await ReadImmutableSnapshotAsync(sourcePath, command.MaxSnapshotMiB, token).ConfigureAwait(false);
        var report = engine.Analyze(input.Snapshot, new RuleEngineOptions { Policy = policy, AnalysisTime = command.AnalysisTime,
            RuleIds = command.RuleIds, MaxEvaluations = command.MaxEvaluations }, token) with { InputArtifactSha256 = input.Sha256 };
        var directory = Path.GetDirectoryName(outputPath)!;
        Directory.CreateDirectory(directory);
        var temporary = outputPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            var outputOptions = new FileStreamOptions
            { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, BufferSize = 64 * 1024, Options = FileOptions.Asynchronous };
            if (!OperatingSystem.IsWindows()) outputOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            await using (var destination = new FileStream(temporary, outputOptions))
            {
                if (command.Format == "html") await AnalysisReportWriter.WriteHtmlAsync(report, destination, token).ConfigureAwait(false);
                else await AnalysisReportWriter.WriteJsonAsync(report, destination, token).ConfigureAwait(false);
            }
            token.ThrowIfCancellationRequested();
            File.Move(temporary, outputPath, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
        await output.WriteLineAsync($"Analysis: {report.Completion}; rules={report.Rules.Count}; findings={report.Findings.Count}; " +
            $"not-verified={report.Evaluations.Count(x => x.Outcome == RuleOutcome.NotVerified)}; report={outputPath}").ConfigureAwait(false);
        if (report.Completion != AnalysisCompletion.Complete)
            await error.WriteLineAsync("Analysis is incomplete. Inspect missingData and rule errors; missing evidence was not treated as a clean result.").ConfigureAwait(false);
        foreach (var gap in report.Evaluations.Where(e => e.Outcome == RuleOutcome.NotVerified)
                     .SelectMany(e => e.MissingData.DistinctBy(g => (g.Code, g.Path)))
                     .GroupBy(g => (g.Code, g.Path)).OrderByDescending(g => g.Count())
                     .ThenBy(g => g.Key.Path, StringComparer.Ordinal).ThenBy(g => g.Key.Code, StringComparer.Ordinal))
            await error.WriteLineAsync($"  missing-data: evaluations={gap.Count()} code={gap.Key.Code} path={gap.Key.Path}").ConfigureAwait(false);
        if (report.Evaluations.Any(e => e.MissingData.Any(g => g.Code == "field.not-observed")))
            await error.WriteLineAsync("Omitted LDAP fields may be unset or unreadable; collection Complete does not prove attribute absence.").ConfigureAwait(false);
        if (report.Evaluations.Any(e => e.MissingData.Any(g => g.Code == "membership.proof-incomplete")))
            await error.WriteLineAsync("Membership negatives require explicit complete member enumeration, including empty groups and primary-group evidence.").ConfigureAwait(false);
        return ExitCode(report, command.FailOn);
    }
    private static async Task<(AdSnapshot Snapshot, string Sha256)> ReadImmutableSnapshotAsync(string path, int maximumMiB, CancellationToken token)
    {
        var budget = ArtifactBudgets.ForMiB(maximumMiB);
        var temporary = Path.Combine(Path.GetTempPath(), "dogfighter-analysis-" + Guid.NewGuid().ToString("N") + ".tmp");
        var fileOptions = new FileStreamOptions
        {
            Mode = FileMode.CreateNew, Access = FileAccess.ReadWrite, Share = FileShare.None,
            BufferSize = 64 * 1024, Options = FileOptions.Asynchronous | FileOptions.DeleteOnClose
        };
        if (!OperatingSystem.IsWindows()) fileOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        try
        {
            await using var copy = new FileStream(temporary, fileOptions);
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            await using (var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.Asynchronous))
            {
                var buffer = new byte[64 * 1024];
                long total = 0;
                while (true)
                {
                    var read = await source.ReadAsync(buffer, token).ConfigureAwait(false);
                    if (read == 0) break;
                    total += read;
                    if (total > budget.MaxContainerBytes)
                        throw new DogadArtifactException("dogad.container.too-large", "Input artifact exceeds its configured container budget.");
                    hasher.AppendData(buffer, 0, read);
                    await copy.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
                }
            }
            await copy.FlushAsync(token).ConfigureAwait(false);
            copy.Position = 0;
            var snapshot = await new DogadArtifactSerializer().ReadAsync(copy, budget.ToReadOptions(), token).ConfigureAwait(false);
            return (snapshot, Convert.ToHexStringLower(hasher.GetHashAndReset()));
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    internal static int ExitCode(AnalysisReport report, FindingSeverity? threshold) => report.Completion switch
    {
        AnalysisCompletion.Error => CliExitCodes.RuntimeFailure,
        AnalysisCompletion.Partial => CliExitCodes.Partial,
        _ => threshold.HasValue && report.Findings.Any(f => f.Severity >= threshold.Value) ? 1 : CliExitCodes.Success
    };
    internal static async Task<AnalysisPolicy> ReadPolicyAsync(string path, CancellationToken token)
    {
        const int maximum = 64 * 1024;
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
        var bytes = new byte[maximum + 1];
        var total = 0;
        while (total < bytes.Length)
        {
            var read = await stream.ReadAsync(bytes.AsMemory(total), token).ConfigureAwait(false);
            if (read == 0) break;
            total += read;
        }
        if (total > maximum) throw new ArgumentException("Analysis policy exceeds its read budget.");
        using (var document = JsonDocument.Parse(bytes.AsMemory(0, total)))
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw new JsonException("Policy must be an object.");
            var keys = new HashSet<string>(StringComparer.Ordinal);
            if (document.RootElement.EnumerateObject().Any(p => !keys.Add(p.Name))) throw new JsonException("Duplicate policy property.");
        }
        var policy = JsonSerializer.Deserialize<AnalysisPolicy>(bytes.AsSpan(0, total), AnalysisReportWriter.CreateJsonOptions())
            ?? throw new JsonException("Policy cannot be null.");
        policy.Validate();
        return policy;
    }
}
