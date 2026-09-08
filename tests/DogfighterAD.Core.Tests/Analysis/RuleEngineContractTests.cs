using System.Globalization;
using System.Text;
using System.Text.Json;
using DogfighterAD.Application.Analysis;
using DogfighterAD.Application.Analysis.Rules;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;
using DogfighterAD.Serialization;

namespace DogfighterAD.Core.Tests.Analysis;

public sealed class RuleEngineContractTests
{
    private const string Rule = "AD.USER.PREAUTH_DISABLED";
    [Fact]
    public void CatalogContainsEightyTwoUniqueDocumentedExecutableRules()
    {
        var pack = BuiltInRulePack.Create(); Assert.Equal(82, pack.Count);
        Assert.Equal(82, pack.Select(r => r.Metadata.Id).Distinct(StringComparer.Ordinal).Count());
        Assert.All(pack, r => { Assert.NotEmpty(r.Metadata.RequiredCapabilities); Assert.NotEmpty(r.Metadata.RequiredFields); Assert.NotEmpty(r.Metadata.References); });
        var report = new RuleEngine(pack).Analyze(new AnalysisFixture().Build(), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(82, report.Rules.Count); Assert.DoesNotContain(report.Evaluations, e => e.Outcome == RuleOutcome.Error);
        Assert.Empty(report.Findings); Assert.Equal(AnalysisCompletion.Partial, report.Completion);
    }
    [Theory]
    [InlineData(CapabilityStatus.Failed)] [InlineData(CapabilityStatus.Blocked)] [InlineData(CapabilityStatus.Unsupported)] [InlineData(CapabilityStatus.NotRequested)]
    public void UnavailableCapabilityNeverLooksClean(CapabilityStatus status)
    {
        var f = new AnalysisFixture(); f.Uac(false, 0x400200); f.SetCoverage(CollectionCapabilities.DirectoryUsers, status);
        var report = f.Run(Rule); Assert.Empty(report.Findings); Assert.Equal(RuleOutcome.NotVerified, Assert.Single(report.Evaluations).Outcome);
    }
    [Fact]
    public void PartialCoveragePreservesWitnessedFindingsButPreventsCompleteReport()
    {
        var f = new AnalysisFixture(); f.Uac(false, 0x400200); f.SetCoverage(CollectionCapabilities.DirectoryUsers, CapabilityStatus.Partial);
        var report = f.Run(Rule); Assert.Single(report.Findings); Assert.Contains(report.Evaluations, e => e.Outcome == RuleOutcome.NotVerified);
        Assert.Equal(AnalysisCompletion.Partial, report.Completion);
    }
    [Theory]
    [InlineData("missing")] [InlineData("redacted")] [InlineData("conflict")] [InlineData("wrong-kind")]
    [InlineData("bad-format")] [InlineData("wrong-id")] [InlineData("wrong-provenance")] [InlineData("future-observation")]
    public void UnusableOperandsNeverBecomeClrDefaults(string mode)
    {
        var f = new AnalysisFixture(); f.Uac(false, 512); var subject = AnalysisFixture.Subject(AnalysisFixture.User);
        var index = f.Facts.FindIndex(x => x.Path == "user.userAccountControl"); var original = f.Facts[index];
        switch (mode)
        {
            case "missing": f.Facts.RemoveAt(index); break;
            case "redacted": f.Facts[index] = original with { Disposition = FactDisposition.Redacted, Value = null }; break;
            case "conflict": f.Integer(CollectionCapabilities.DirectoryUsers, subject, original.Path, 514); break;
            case "wrong-kind": f.Facts[index] = original with { ValueKind = FactValueKind.Text }; break;
            case "bad-format": f.Facts.RemoveAt(index); f.Add(CollectionCapabilities.DirectoryUsers, subject, original.Path, "not-a-number", FactValueKind.Integer); break;
            case "wrong-id": f.Facts[index] = original with { FactId = "unverified-fixture-id" }; break;
            case "wrong-provenance": f.Facts[index] = original with { Source = original.Source with { CollectorVersion = "unrecorded" } }; break;
            case "future-observation": f.Facts[index] = original with { ObservedAt = AnalysisFixture.Now.AddDays(1) }; break;
        }
        var result = new ObservationIndex(f.Build()).Integer(CollectionCapabilities.DirectoryUsers, subject, original.Path);
        Assert.False(result.Known); Assert.NotNull(result.Code); Assert.Empty(result.Evidence);
    }
    [Fact]
    public void FingerprintsIgnoreSnapshotAndDisplayNamesButRetainSubjectIdentity()
    {
        var f = new AnalysisFixture(); f.Uac(false, 0x400200); var snapshot = f.Build();
        var engine = new RuleEngine(BuiltInRulePack.Create()); var options = new RuleEngineOptions { RuleIds = new HashSet<string> { Rule } };
        var first = engine.Analyze(snapshot, options, TestContext.Current.CancellationToken); var changed = snapshot with
        { Metadata = snapshot.Metadata with { SnapshotId = Guid.NewGuid() }, Content = snapshot.Content with { Users = [AnalysisFixture.User with { Name = "renamed" }] } };
        Assert.Equal(Assert.Single(first.Findings).Fingerprint, Assert.Single(engine.Analyze(changed, options, TestContext.Current.CancellationToken).Findings).Fingerprint);
        Assert.NotEqual(RuleEngine.Fingerprint("pack", Rule, "a", "b"), RuleEngine.Fingerprint("pack", Rule, "ab", ""));
    }
    [Fact]
    public void FindingsOnlyUseSourceFactIdsAndDoNotMutateSnapshot()
    {
        var f = new AnalysisFixture(); f.Uac(false, 0x400200); var snapshot = f.Build(); var before = JsonSerializer.Serialize(snapshot);
        var report = f.Run(Rule); var ids = snapshot.Observations.Select(x => x.FactId).ToHashSet();
        Assert.All(report.Findings.SelectMany(x => x.Evidence), e => Assert.Contains(e.FactId!, ids));
        Assert.Equal(before, JsonSerializer.Serialize(snapshot));
    }
    [Fact]
    public void RuleExceptionIsIsolatedWithoutEchoingPayload()
    {
        var good = BuiltInRulePack.Create().Single(x => x.Metadata.Id == Rule); var f = new AnalysisFixture(); f.Uac(false, 0x400200);
        var report = new RuleEngine([good, new BrokenRule()]).Analyze(f.Build(), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Single(report.Findings); Assert.Equal(AnalysisCompletion.Error, report.Completion);
        Assert.DoesNotContain("SECRET_CANARY", JsonSerializer.Serialize(report), StringComparison.Ordinal);
    }
    [Fact]
    public void CancellationAndBudgetsDoNotReturnTruncatedSuccess()
    {
        var f = new AnalysisFixture(); var engine = new RuleEngine(BuiltInRulePack.Create());
        using var cts = new CancellationTokenSource(); cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => engine.Analyze(f.Build(), cancellationToken: cts.Token));
        Assert.Throws<AnalysisLimitException>(() => engine.Analyze(f.Build(), new() { MaxEvaluations = 1 }, TestContext.Current.CancellationToken));
        Assert.Throws<ArgumentException>(() => engine.Analyze(f.Build(), new() { RuleIds = new HashSet<string> { "UNKNOWN" } }, TestContext.Current.CancellationToken));
        Assert.Throws<ArgumentOutOfRangeException>(() => engine.Analyze(f.Build(), new() { AnalysisTime = AnalysisFixture.Now.AddDays(-1) }, TestContext.Current.CancellationToken));
    }
    [Fact]
    public void ReportsAreDeterministicAcrossEnumerationAndCulture()
    {
        var f = new AnalysisFixture(); f.Uac(false, 0x400200); var first = JsonSerializer.Serialize(f.Run(Rule));
        f.Facts.Reverse(); f.Coverage.Reverse();
        var original = CultureInfo.CurrentCulture;
        try { CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR"); Assert.Equal(first, JsonSerializer.Serialize(f.Run(Rule))); }
        finally { CultureInfo.CurrentCulture = original; }
    }
    [Fact]
    public async Task HtmlEscapesSourceAndReportStrings()
    {
        var f = new AnalysisFixture(); f.Uac(false, 0x400200); var report = f.Run(Rule);
        report = report with { Findings = [report.Findings[0] with { Description = "<script>SECRET_CANARY</script>", Title = "<img src=x onerror=alert(1)>" }] };
        using var output = new MemoryStream(); await AnalysisReportWriter.WriteHtmlAsync(report, output, TestContext.Current.CancellationToken);
        var html = Encoding.UTF8.GetString(output.ToArray());
        Assert.DoesNotContain("<script>", html, StringComparison.Ordinal); Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
        Assert.Contains("Content-Security-Policy", html, StringComparison.Ordinal);
    }
    [Fact]
    public async Task OptionalRegistryTypeDoesNotBreakOldSchemaTwoCanonicalPayloads()
    {
        var f = new AnalysisFixture(); f.Setting("Software\\Policies\\Legacy", "Enabled", "1", registryType: null);
        var serializer = new DogadArtifactSerializer(); using var output = new MemoryStream();
        await serializer.WriteAsync(f.Build(), output, TestContext.Current.CancellationToken); output.Position = 0;
        var restored = await serializer.ReadAsync(output, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(Assert.Single(restored.Content.GroupPolicySettings).RegistryValueType);
        Assert.DoesNotContain("registryValueType", JsonSerializer.Serialize(restored), StringComparison.OrdinalIgnoreCase);
    }
    [Fact]
    public void CompleteCountMismatchDoesNotTurnMissingInventoryIntoNotApplicable()
    {
        var f = new AnalysisFixture(); var snapshot = f.Build();
        snapshot = snapshot with { Content = snapshot.Content with { Users = [] } };
        var report = new RuleEngine(BuiltInRulePack.Create()).Analyze(snapshot, new() { RuleIds = new HashSet<string> { Rule } }, TestContext.Current.CancellationToken);
        Assert.Equal(RuleOutcome.NotVerified, Assert.Single(report.Evaluations).Outcome);
        Assert.Empty(report.Findings);
    }
    private sealed class BrokenRule : IRule
    {
        public RuleMetadata Metadata { get; } = new()
        { Id = "TEST.BROKEN", Version = "1", Title = "test", Category = "test", DefaultSeverity = FindingSeverity.Low };
        public IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context) => throw new InvalidOperationException("SECRET_CANARY");
    }
}
