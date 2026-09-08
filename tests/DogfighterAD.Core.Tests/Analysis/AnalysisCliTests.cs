using System.Text.Json;
using DogfighterAD.Cli;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Serialization;

namespace DogfighterAD.Core.Tests.Analysis;

public sealed class AnalysisCliTests
{
    [Theory]
    [InlineData("json")] [InlineData("html")]
    public async Task AnalyzePublishesOfflineReportWithoutChangingInput(string format)
    {
        var root = Path.Combine(Path.GetTempPath(), "dogfighter-engine-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        try
        {
            var fixture = new AnalysisFixture(); fixture.Uac(false, 0x400200);
            var input = Path.Combine(root, "input.dogad"); var output = Path.Combine(root, "report." + format);
            await using (var stream = File.Create(input)) await new DogadArtifactSerializer().WriteAsync(fixture.Build(), stream, TestContext.Current.CancellationToken);
            var original = await File.ReadAllBytesAsync(input, TestContext.Current.CancellationToken);
            using var stdout = new StringWriter(); using var stderr = new StringWriter();
            var code = await CliApplication.RunAsync(["analyze", "--snapshot", input, "--output", output, "--format", format, "--rule", "AD.USER.PREAUTH_DISABLED"],
                "test", stdout, stderr, TestContext.Current.CancellationToken);
            Assert.Equal(1, code); Assert.True(File.Exists(output));
            Assert.Equal(original, await File.ReadAllBytesAsync(input, TestContext.Current.CancellationToken));
            if (format == "json")
            {
                await using var stream = File.OpenRead(output);
                var report = await JsonSerializer.DeserializeAsync<AnalysisReport>(stream, AnalysisReportWriter.CreateJsonOptions(), TestContext.Current.CancellationToken);
                Assert.NotNull(report); Assert.Single(report.Findings); Assert.Equal(AnalysisFixture.Now, report.AnalysisTime);
                Assert.Equal(64, report.InputArtifactSha256!.Length);
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }
    [Fact]
    public async Task InvalidInputPreservesAnExistingReport()
    {
        var root = Path.Combine(Path.GetTempPath(), "dogfighter-engine-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        try
        {
            var input = Path.Combine(root, "bad.dogad"); var output = Path.Combine(root, "report.json");
            await File.WriteAllTextAsync(input, "not a ZIP", TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(output, "previous", TestContext.Current.CancellationToken);
            using var stdout = new StringWriter(); using var stderr = new StringWriter();
            var code = await CliApplication.RunAsync(["analyze", "--snapshot", input, "--output", output], "test", stdout, stderr, TestContext.Current.CancellationToken);
            Assert.Equal(70, code); Assert.Equal("previous", await File.ReadAllTextAsync(output, TestContext.Current.CancellationToken));
        }
        finally { Directory.Delete(root, recursive: true); }
    }
    [Theory]
    [InlineData("{\"minimumPasswordLength\":0}")]
    [InlineData("{\"minimumPasswordLength\":14,\"minimumPasswordLength\":8}")]
    [InlineData("{\"unknownProperty\":1}")]
    public async Task InvalidAnalysisPolicyIsRejected(string json)
    {
        var path = Path.Combine(Path.GetTempPath(), "dogfighter-policy-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            await File.WriteAllTextAsync(path, json, TestContext.Current.CancellationToken);
            await Assert.ThrowsAnyAsync<Exception>(() => AnalysisCommands.ReadPolicyAsync(path, TestContext.Current.CancellationToken));
        }
        finally { File.Delete(path); }
    }
    [Fact]
    public async Task RulesCommandListsTheActualCatalog()
    {
        using var output = new StringWriter(); using var error = new StringWriter();
        var code = await CliApplication.RunAsync(["rules", "--format", "json"], "test", output, error, TestContext.Current.CancellationToken);
        Assert.Equal(0, code); using var json = JsonDocument.Parse(output.ToString()); Assert.Equal(88, json.RootElement.GetArrayLength());
    }
    [Theory]
    [InlineData("--as-of", "2026-09-07")]
    [InlineData("--max-evaluations", "0")]
    [InlineData("--max-snapshot-mib", "999999")]
    [InlineData("--fail-on", "-1")]
    public void InvalidOptionsAreNotAccepted(string option, string value)
    {
        Assert.False(CliArgumentParser.Parse(["analyze", "--snapshot", "test.dogad", "--output", "report.json", option, value]).Success);
    }
}
