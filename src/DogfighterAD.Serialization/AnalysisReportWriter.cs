using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DogfighterAD.Domain.Analysis;

namespace DogfighterAD.Serialization;

public static class AnalysisReportWriter
{
    public static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true,
            PropertyNameCaseInsensitive = false, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            MaxDepth = 64
        };
        options.Converters.Add(new JsonStringEnumConverter(allowIntegerValues: false));
        return options;
    }
    public static Task WriteJsonAsync(AnalysisReport report, Stream destination, CancellationToken cancellationToken = default) =>
        JsonSerializer.SerializeAsync(destination, report, CreateJsonOptions(), cancellationToken);

    public static async Task WriteHtmlAsync(AnalysisReport report, Stream destination, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(destination);
        await using var writer = new StreamWriter(destination, new UTF8Encoding(false), 16 * 1024, leaveOpen: true);
        static string E(object? value) => WebUtility.HtmlEncode(value?.ToString() ?? "");
        async Task W(string value)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await writer.WriteAsync(value.AsMemory(), cancellationToken).ConfigureAwait(false);
        }
        await W("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">" +
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">" +
            "<title>DogfighterAD security findings</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;background:#f7f9fb;color:#17212b}" +
            "h1,h2,h3{line-height:1.2}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{text-align:left;vertical-align:top;padding:.5rem;border-bottom:1px solid #cbd5df;overflow-wrap:anywhere}" +
            "article,details{background:white;border:1px solid #cbd5df;padding:1rem;margin:1rem 0}code{overflow-wrap:anywhere}summary{cursor:pointer} .warning{border-left:5px solid #ad6500;padding:1rem;background:#fff4db}</style></head><body>");
        await W($"<h1>DogfighterAD security findings</h1><p>Snapshot <code>{E(report.SnapshotId)}</code> · collection completed {E(report.SnapshotCompletedAt.ToString("O"))}</p>" +
            $"<p>Rule pack {E(report.RulePackId)} {E(report.RulePackVersion)} · reference time {E(report.AnalysisTime.ToString("O"))} · completion <strong>{E(report.Completion)}</strong></p>" +
            $"<p>Input SHA-256: <code>{E(report.InputArtifactSha256)}</code><br>Policy SHA-256: <code>{E(report.PolicySha256)}</code></p>");
        await W("<p class=\"warning\">Offline configuration assessment, not live exploitation or a declaration of safety. NotVerified means missing or unusable evidence, never a clean result. " +
            "GPO/ACE candidates do not establish resultant policy or effective access. The artifact checksum is not a digital signature.</p>");
        await W("<h2>Rule coverage</h2><table><thead><tr><th>Rule</th><th>Present</th><th>Potential</th><th>Not detected</th><th>Not verified</th><th>Not applicable</th><th>Errors</th></tr></thead><tbody>");
        foreach (var rule in report.Rules)
            await W($"<tr><td><code>{E(rule.RuleId)}</code><br>{E(rule.Title)}</td><td>{rule.Present}</td><td>{rule.Potential}</td><td>{rule.NotDetected}</td><td>{rule.NotVerified}</td><td>{rule.NotApplicable}</td><td>{rule.Errors}</td></tr>");
        await W($"</tbody></table><h2>Findings ({report.Findings.Count})</h2>");
        foreach (var finding in report.Findings)
        {
            await W($"<article><h3>{E(finding.Severity)} · {E(finding.Title)}</h3><p><code>{E(finding.RuleId)}</code> · {E(finding.Status)} · {E(finding.Confidence)} confidence</p>" +
                $"<p>{E(finding.Description)}</p><p><strong>Risk:</strong> {E(finding.Risk)}</p><p><strong>Remediation:</strong> {E(finding.Remediation)}</p>");
            var ruleSummary = report.Rules.FirstOrDefault(r => r.RuleId == finding.RuleId);
            foreach (var reference in ruleSummary?.ReferenceUrls ?? [])
                if (Uri.TryCreate(reference, UriKind.Absolute, out var uri) && uri.Scheme is "https" or "http")
                    await W($"<p>Reference: <a href=\"{E(reference)}\" rel=\"noreferrer noopener\">{E(reference)}</a></p>");
            foreach (var subject in finding.AffectedObjects)
                await W($"<p><code>{E(subject.StableId)}</code> {E(subject.DistinguishedName)} {E(subject.DisplayName)}</p>");
            await W($"<details><summary>Evidence ({finding.Evidence.Count})</summary><table><tr><th>Fact</th><th>Value</th><th>Provenance</th></tr>");
            foreach (var evidence in finding.Evidence)
                await W($"<tr><td><code>{E(evidence.Path)}</code><br>{E(evidence.FactId)}</td><td>{E(evidence.Value)}</td><td>{E(evidence.Source)}<br>{E(evidence.CollectorId)} {E(evidence.CollectorVersion)}<br>{E(evidence.ObservedAt.ToString("O"))}</td></tr>");
            await W($"</table></details><p>Fingerprint: <code>{E(finding.Fingerprint)}</code></p></article>");
        }
        await W("<h2>Unverified checks and errors</h2>");
        foreach (var check in report.Evaluations.Where(e => e.Outcome is RuleOutcome.NotVerified or RuleOutcome.Error))
        {
            await W($"<details><summary>{E(check.RuleId)} · {E(check.Outcome)} · {E(check.Subject.StableId)}</summary><p>{E(check.Message)}</p>");
            foreach (var gap in check.MissingData)
                await W($"<p><code>{E(gap.CapabilityId)} / {E(gap.SubjectId)} / {E(gap.Path)}</code>: {E(gap.Code)}</p>");
            await W("</details>");
        }
        await W("</body></html>");
        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
