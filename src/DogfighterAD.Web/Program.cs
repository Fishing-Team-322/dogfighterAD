using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using DogfighterAD.Application.Analysis;
using DogfighterAD.Application.Analysis.Rules;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Serialization;

if (!UiSettings.TryParse(args, out var settings, out var settingsError))
{
    Console.Error.WriteLine(settingsError);
    Console.Error.WriteLine("Usage: dogfighter-ui [--port <1-65535>] [--no-open]");
    return 64;
}

var url = $"http://127.0.0.1:{settings!.Port}";
var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
{
    Args = Array.Empty<string>(),
    ContentRootPath = AppContext.BaseDirectory
});
builder.WebHost.UseUrls(url);
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = DogadFormat.DefaultMaxContainerBytes + (1024L * 1024L);
});
builder.Services.AddSingleton<UiAnalysisStore>();

await using var app = builder.Build();
var jsonOptions = AnalysisReportWriter.CreateJsonOptions();

app.Use(async (context, next) =>
{
    context.Response.Headers.CacheControl = "no-store";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
    await next().ConfigureAwait(false);
});

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/status", () => Results.Json(new
{
    product = "DogfighterAD",
    uiVersion = "0.3.0",
    mode = "offline-first",
    bind = url,
    maxSnapshotBytes = DogadFormat.DefaultMaxContainerBytes
}, jsonOptions));

app.MapGet("/api/rules", () => Results.Json(
    BuiltInRulePack.Create().Select(rule => rule.Metadata).ToArray(),
    jsonOptions));

app.MapPost("/api/analyze", async (HttpRequest request, UiAnalysisStore store, CancellationToken cancellationToken) =>
{
    try
    {
        var report = await UiAnalysisService
            .AnalyzeAsync(request.Body, request.ContentLength, cancellationToken)
            .ConfigureAwait(false);
        var analysisId = store.Add(report);
        return Results.Json(new { analysisId, report }, jsonOptions);
    }
    catch (DogadArtifactException exception)
    {
        return Results.BadRequest(new { error = "invalid-artifact", code = exception.Code });
    }
    catch (AnalysisLimitException)
    {
        return Results.BadRequest(new { error = "analysis-limit" });
    }
    catch (ArgumentException)
    {
        return Results.BadRequest(new { error = "invalid-request" });
    }
});

app.MapGet("/api/analyses/{id:guid}", (Guid id, UiAnalysisStore store) =>
    store.TryGet(id, out var report)
        ? Results.Json(report, jsonOptions)
        : Results.NotFound(new { error = "analysis-not-found" }));

app.MapGet("/api/analyses/{id:guid}/json", (Guid id, UiAnalysisStore store) =>
{
    if (!store.TryGet(id, out var report))
        return Results.NotFound(new { error = "analysis-not-found" });

    var bytes = JsonSerializer.SerializeToUtf8Bytes(report, jsonOptions);
    return Results.File(bytes, "application/json", $"dogfighter-{report.SnapshotId:N}-analysis.json");
});

app.MapGet("/api/analyses/{id:guid}/html", async (Guid id, UiAnalysisStore store, CancellationToken cancellationToken) =>
{
    if (!store.TryGet(id, out var report))
        return Results.NotFound(new { error = "analysis-not-found" });

    await using var buffer = new MemoryStream();
    await AnalysisReportWriter.WriteHtmlAsync(report, buffer, cancellationToken).ConfigureAwait(false);
    return Results.File(
        buffer.ToArray(),
        "text/html; charset=utf-8",
        $"dogfighter-{report.SnapshotId:N}-analysis.html");
});

await app.StartAsync().ConfigureAwait(false);
Console.WriteLine($"DogfighterAD UI listening on {url}");
Console.WriteLine("The UI is loopback-only. Uploaded .dogad data and analysis reports remain in local process memory/temp storage.");

if (settings.OpenBrowser)
{
    try
    {
        Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
    }
    catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
    {
        Console.Error.WriteLine($"Could not open the default browser automatically. Open {url} manually.");
    }
}

await app.WaitForShutdownAsync().ConfigureAwait(false);
return 0;

internal sealed record UiSettings(int Port, bool OpenBrowser)
{
    public static bool TryParse(string[] args, out UiSettings? settings, out string? error)
    {
        var port = 51837;
        var openBrowser = true;

        for (var index = 0; index < args.Length; index++)
        {
            switch (args[index])
            {
                case "--port":
                    if (++index >= args.Length || !int.TryParse(args[index], out port) || port is < 1 or > 65535)
                    {
                        settings = null;
                        error = "--port requires a TCP port from 1 through 65535.";
                        return false;
                    }
                    break;

                case "--no-open":
                    openBrowser = false;
                    break;

                case "--help":
                case "-h":
                    settings = null;
                    error = "Usage requested.";
                    return false;

                default:
                    settings = null;
                    error = "Unknown UI option.";
                    return false;
            }
        }

        settings = new UiSettings(port, openBrowser);
        error = null;
        return true;
    }
}

internal static class UiAnalysisService
{
    public static async Task<AnalysisReport> AnalyzeAsync(
        Stream source,
        long? contentLength,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (contentLength is <= 0)
            throw new ArgumentException("Snapshot request body is empty.", nameof(contentLength));
        if (contentLength > DogadFormat.DefaultMaxContainerBytes)
            throw new DogadArtifactException("dogad.container.too-large", "Input artifact exceeds its configured container budget.");

        var temporary = Path.Combine(Path.GetTempPath(), "dogfighter-ui-" + Guid.NewGuid().ToString("N") + ".tmp");
        var fileOptions = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
            BufferSize = 64 * 1024,
            Options = FileOptions.Asynchronous | FileOptions.DeleteOnClose
        };
        if (!OperatingSystem.IsWindows())
            fileOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        try
        {
            await using var copy = new FileStream(temporary, fileOptions);
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[64 * 1024];
            long total = 0;

            while (true)
            {
                var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    break;

                total += read;
                if (total > DogadFormat.DefaultMaxContainerBytes)
                    throw new DogadArtifactException("dogad.container.too-large", "Input artifact exceeds its configured container budget.");

                hasher.AppendData(buffer, 0, read);
                await copy.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }

            if (total == 0)
                throw new ArgumentException("Snapshot request body is empty.", nameof(source));

            await copy.FlushAsync(cancellationToken).ConfigureAwait(false);
            copy.Position = 0;

            var snapshot = await new DogadArtifactSerializer()
                .ReadAsync(copy, new DogadReadOptions(), cancellationToken)
                .ConfigureAwait(false);

            var engine = new RuleEngine(BuiltInRulePack.Create(), BuiltInRulePack.Id, BuiltInRulePack.Version);
            return engine.Analyze(snapshot, new RuleEngineOptions
            {
                Policy = new AnalysisPolicy(),
                MaxEvaluations = 2_000_000
            }, cancellationToken) with
            {
                InputArtifactSha256 = Convert.ToHexStringLower(hasher.GetHashAndReset())
            };
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }
}

internal sealed class UiAnalysisStore
{
    private const int Capacity = 8;
    private readonly object gate = new();
    private readonly Dictionary<Guid, AnalysisReport> reports = [];
    private readonly Queue<Guid> insertionOrder = [];

    public Guid Add(AnalysisReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        lock (gate)
        {
            while (reports.Count >= Capacity && insertionOrder.Count > 0)
                reports.Remove(insertionOrder.Dequeue());

            var id = Guid.NewGuid();
            reports.Add(id, report);
            insertionOrder.Enqueue(id);
            return id;
        }
    }

    public bool TryGet(Guid id, out AnalysisReport report)
    {
        lock (gate)
            return reports.TryGetValue(id, out report!);
    }
}
