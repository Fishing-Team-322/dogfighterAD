using System.Globalization;
using DogfighterAD.Application.Analysis.Rules;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Analysis;

public sealed class AccountAndRegistryRuleTests
{
    public static IEnumerable<object[]> FlagCases()
    {
        foreach (var computer in new[] { false, true })
            foreach (var f in BuiltInRulePack.AccountFlags)
                foreach (var mode in new[] { "positive", "negative", "missing", "disabled" })
                    yield return [computer, f.Suffix, f.Mask, mode];
    }
    [Theory, MemberData(nameof(FlagCases))]
    public void FlagsRequireObservedUac(bool computer, string suffix, long mask, string mode)
    {
        var f = new AnalysisFixture();
        if (mode != "missing") f.Uac(computer, mode == "negative" ? 512L : mask | 512L | (mode == "disabled" ? 2L : 0L));
        var result = f.Check("AD." + (computer ? "COMPUTER." : "USER.") + suffix, computer ? AnalysisFixture.Computer : AnalysisFixture.User);
        Assert.Equal(mode switch { "positive" => RuleOutcome.Present, "negative" => RuleOutcome.NotDetected,
            "disabled" => RuleOutcome.NotApplicable, _ => RuleOutcome.NotVerified }, result.Outcome);
        if (mode == "missing") Assert.Contains(result.MissingData, g => g.Path.EndsWith(".userAccountControl", StringComparison.Ordinal));
        else Assert.NotEmpty(result.Evidence);
    }
    [Theory]
    [InlineData(8192)] [InlineData(67108864)]
    public void DelegationRuleExcludesExplicitDcRoles(long role)
    {
        var f = new AnalysisFixture(); f.Uac(true, role | 0x80000);
        Assert.Equal(RuleOutcome.NotApplicable, f.Check("AD.COMPUTER.UNCONSTRAINED_DELEGATION", AnalysisFixture.Computer).Outcome);
    }
    [Theory]
    [InlineData(0, RuleOutcome.NotVerified)] [InlineData(4, RuleOutcome.Present)]
    [InlineData(24, RuleOutcome.NotDetected)] [InlineData(-1, RuleOutcome.NotVerified)]
    public void Rc4IsNotGuessedFromAbsentOrZeroEncryptionMask(long mask, RuleOutcome expected)
    {
        var f = new AnalysisFixture(); f.Uac(false, 512);
        f.Integer(CollectionCapabilities.DirectoryUsers, AnalysisFixture.Subject(AnalysisFixture.User), "user.supportedEncryptionTypes", mask);
        Assert.Equal(expected, f.Check("AD.USER.EXPLICIT_RC4").Outcome);
    }
    [Theory]
    [InlineData("PASSWORD_AGE", "pwdLastSet", 400, RuleOutcome.Potential)]
    [InlineData("PASSWORD_AGE", "pwdLastSet", 10, RuleOutcome.NotDetected)]
    [InlineData("REPLICATED_LOGON_AGE", "lastLogonTimestamp", 120, RuleOutcome.Potential)]
    [InlineData("REPLICATED_LOGON_AGE", "lastLogonTimestamp", -1, RuleOutcome.NotVerified)]
    [InlineData("EXPIRED_ENABLED", "accountExpires", 1, RuleOutcome.Potential)]
    [InlineData("EXPIRED_ENABLED", "accountExpires", -1, RuleOutcome.NotDetected)]
    public void TimestampRulesUseExplicitReferenceAndSentinels(string suffix, string path, int days, RuleOutcome expected)
    {
        var f = new AnalysisFixture(); f.Uac(false, 512);
        f.Integer(CollectionCapabilities.DirectoryUsers, AnalysisFixture.Subject(AnalysisFixture.User), "user." + path, AnalysisFixture.Now.AddDays(-days).ToFileTime());
        Assert.Equal(expected, f.Check("AD.USER." + suffix).Outcome);
    }
    [Theory]
    [InlineData("PASSWORD_AGE", "pwdLastSet", RuleOutcome.NotVerified)]
    [InlineData("REPLICATED_LOGON_AGE", "lastLogonTimestamp", RuleOutcome.NotVerified)]
    [InlineData("EXPIRED_ENABLED", "accountExpires", RuleOutcome.NotDetected)]
    public void ZeroTimestampIsNotA1900YearOldEvent(string rule, string field, RuleOutcome expected)
    {
        var f = new AnalysisFixture(); f.Uac(false, 512);
        f.Integer(CollectionCapabilities.DirectoryUsers, AnalysisFixture.Subject(AnalysisFixture.User), "user." + field, 0);
        Assert.Equal(expected, f.Check("AD.USER." + rule).Outcome);
    }
    [Fact]
    public void NormallyDisabledKrbtgtStillReceivesAgeCheck()
    {
        var f = new AnalysisFixture(); f.Uac(false, 514);
        var subject = AnalysisFixture.Subject(AnalysisFixture.User);
        f.Remove(CollectionCapabilities.DirectoryUsers, subject, "object.objectSid");
        f.Add(CollectionCapabilities.DirectoryUsers, subject, "object.objectSid", AnalysisFixture.DomainSid + "-502", FactValueKind.Sid);
        f.Integer(CollectionCapabilities.DirectoryUsers, subject, "user.pwdLastSet", AnalysisFixture.Now.AddDays(-200).ToFileTime());
        Assert.Equal(RuleOutcome.Potential, f.Check("AD.USER.KRBTGT_PASSWORD_AGE").Outcome);
    }
    [Theory]
    [InlineData(false, RuleOutcome.NotVerified)] [InlineData(true, RuleOutcome.Potential)]
    public void MissingSpnIsNotAnExplicitEmptyAttribute(bool observed, RuleOutcome expected)
    {
        var f = new AnalysisFixture(); f.Uac(false, 512);
        if (observed) f.Add(CollectionCapabilities.DirectoryUsers, AnalysisFixture.Subject(AnalysisFixture.User), "user.servicePrincipalName", "HTTP/service.review.invalid");
        Assert.Equal(expected, f.Check("AD.USER.SPN_ACCOUNT").Outcome);
    }
    public static IEnumerable<object[]> RegistryCases()
    {
        foreach (var d in BuiltInRulePack.RegistryDefinitions)
            foreach (var mode in new[] { "positive", "negative", "missing", "type-missing", "wrong-type", "unsupported", "conflict", "directive" })
                yield return [d.Id, mode];
    }
    [Theory, MemberData(nameof(RegistryCases))]
    public void EveryRegistryRuleRequiresExactStoredDwordEvidence(string id, string mode)
    {
        var f = new AnalysisFixture(); var d = Assert.Single(BuiltInRulePack.RegistryDefinitions, x => x.Id == id);
        var positive = d.Comparison == NumericComparison.Equals ? d.Threshold : 0;
        var negative = d.Comparison == NumericComparison.Equals ? (d.Threshold == 0 ? 1u : 0u) : d.Threshold;
        var value = mode == "negative" ? negative : mode == "unsupported" ? d.MaximumSupportedValue + 1 : positive;
        if (mode != "missing") f.Setting(d.KeyPath, d.ValueName, value.ToString(CultureInfo.InvariantCulture),
            registryType: mode == "wrong-type" ? 11u : 4u, typeEvidence: mode != "type-missing");
        if (mode == "conflict") f.Setting(d.KeyPath, d.ValueName, negative.ToString(CultureInfo.InvariantCulture));
        if (mode == "directive") f.Setting(d.KeyPath, "**DeleteValues", null, FactValueKind.Text, registryType: 1, disposition: FactDisposition.MetadataOnly);
        var result = f.Check(id, AnalysisFixture.Gpo, "Machine");
        Assert.Equal(mode switch { "positive" => RuleOutcome.Potential, "negative" => RuleOutcome.NotDetected, _ => RuleOutcome.NotVerified }, result.Outcome);
        if (mode is "positive" or "negative") Assert.Contains(result.Evidence, e => e.Path!.EndsWith(".registryValueType", StringComparison.Ordinal) && e.Value == "4");
    }
    [Fact]
    public void AlwaysInstallElevatedDoesNotInferTheOtherSide()
    {
        var f = new AnalysisFixture(); var d = BuiltInRulePack.RegistryDefinitions[0]; f.Setting(d.KeyPath, d.ValueName, "1");
        var report = f.Run(d.Id);
        Assert.Equal(RuleOutcome.Potential, Assert.Single(report.Evaluations, e => e.CheckKey == "Machine").Outcome);
        Assert.Equal(RuleOutcome.NotVerified, Assert.Single(report.Evaluations, e => e.CheckKey == "User").Outcome);
        Assert.Equal(AnalysisCompletion.Partial, report.Completion);
    }
}
