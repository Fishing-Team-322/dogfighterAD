using DogfighterAD.Application.Analysis.Rules;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Analysis;

public sealed class PolicyAclAndTrustRuleTests
{
    public static IEnumerable<object[]> PolicyCases()
    {
        var cases = new (string Rule, string Field, string Bad, string Good, bool Boolean)[]
        {
            ("MINIMUM_LENGTH", "minimumPasswordLength", "8", "14", false),
            ("HISTORY", "passwordHistoryLength", "0", "24", false),
            ("COMPLEXITY", "complexityEnabled", "false", "true", true),
            ("REVERSIBLE_ENCRYPTION", "reversibleEncryptionEnabled", "true", "false", true),
            ("LOCKOUT_DISABLED", "lockoutThreshold", "0", "5", false),
            ("LOCKOUT_THRESHOLD", "lockoutThreshold", "20", "5", false),
            ("LOCKOUT_DURATION", "lockoutDurationTicks", "-600000000", "0", false),
            ("MACHINE_ACCOUNT_QUOTA", "machineAccountQuota", "10", "0", false)
        };
        foreach (var c in cases)
            foreach (var mode in new[] { "bad", "good", "missing" })
                yield return [c.Rule, c.Field, c.Bad, c.Good, c.Boolean, mode];
    }
    [Theory, MemberData(nameof(PolicyCases))]
    public void DomainPoliciesUseExplicitValues(string rule, string field, string bad, string good, bool boolean, string mode)
    {
        var f = new AnalysisFixture();
        if (mode != "missing") f.Policy(field, mode == "bad" ? bad : good, boolean ? FactValueKind.Boolean : FactValueKind.Integer);
        if (rule == "LOCKOUT_DURATION" && mode != "missing") f.Policy("lockoutThreshold", "5");
        var result = f.Check("AD.POLICY." + rule, AnalysisFixture.Domain);
        Assert.Equal(mode switch { "missing" => RuleOutcome.NotVerified, "good" => RuleOutcome.NotDetected,
            _ => rule == "REVERSIBLE_ENCRYPTION" ? RuleOutcome.Present : RuleOutcome.Potential }, result.Outcome);
    }
    [Fact]
    public void PsoNeverInheritsAMissingFieldFromDomainDefault()
    {
        var f = new AnalysisFixture(); f.Policy("minimumPasswordLength", "8");
        const string pso = "password-policy:88888888-8888-8888-8888-888888888888";
        f.Policy("passwordHistoryLength", "24", subject: pso, policyKind: "FineGrained");
        var report = f.Run("AD.POLICY.MINIMUM_LENGTH");
        Assert.Equal(RuleOutcome.Potential, Assert.Single(report.Evaluations.Where(e => e.Subject.StableId == AnalysisFixture.Subject(AnalysisFixture.Domain))).Outcome);
        Assert.Equal(RuleOutcome.NotVerified, Assert.Single(report.Evaluations.Where(e => e.Subject.StableId == pso)).Outcome);
    }
    public static IEnumerable<object[]> AclCases()
    {
        var cases = new (string Rule, uint Mask, string? Guid, bool Domain)[]
        {
            ("BROAD_GENERIC_ALL", 0x000F01FF, null, false), ("BROAD_WRITE", 0x20, null, false),
            ("BROAD_WRITE_DACL", 0x40000, null, false), ("BROAD_WRITE_OWNER", 0x80000, null, false),
            ("BROAD_RESET_PASSWORD", 0x100, "00299570-246d-11d0-a768-00aa006e0529", false),
            ("BROAD_REPLICATION_RIGHT", 0x100, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", true)
        };
        foreach (var c in cases)
            foreach (var mode in new[] { "allow", "deny", "inherit-only", "missing-type", "partial", "empty" })
                yield return [c.Rule, c.Mask, c.Guid ?? "", c.Domain, mode];
    }
    [Theory, MemberData(nameof(AclCases))]
    public void BroadAcesArePotentialNotEffectiveAccess(string rule, uint mask, string guid, bool domain, string mode)
    {
        var f = new AnalysisFixture(); var target = domain ? (AdDirectoryObject)AnalysisFixture.Domain : AnalysisFixture.User;
        f.Acl(target, mask, guid.Length == 0 ? null : guid, mode == "deny" ? "Deny" : "Allow",
            flags: mode == "inherit-only" ? (byte)8 : (byte)0, complete: mode != "partial", state: mode == "empty" ? "Empty" : "Present");
        if (mode == "missing-type") f.Remove(CollectionCapabilities.DirectoryAcls, AnalysisFixture.Subject(target), "securityDescriptor.dacl.ace[0].objectTypePresent");
        var result = f.Check("AD.ACL." + rule, target);
        Assert.Equal(mode switch { "allow" => RuleOutcome.Potential, "missing-type" or "partial" => RuleOutcome.NotVerified, _ => RuleOutcome.NotDetected }, result.Outcome);
    }
    [Theory]
    [InlineData("Null", RuleOutcome.Present)] [InlineData("NotPresent", RuleOutcome.Present)]
    [InlineData("Empty", RuleOutcome.NotDetected)] [InlineData("Present", RuleOutcome.NotDetected)]
    public void NullAndEmptyDaclRemainDistinct(string state, RuleOutcome expected)
    {
        var f = new AnalysisFixture(); f.Acl(AnalysisFixture.User, 0, state: state);
        Assert.Equal(expected, f.Check("AD.ACL.UNRESTRICTED_DACL").Outcome);
    }
    [Fact]
    public void OldAclContractCannotSupplyNewParseGuarantees()
    {
        var f = new AnalysisFixture(); f.Acl(AnalysisFixture.User, 0x40000);
        f.SetCoverage(CollectionCapabilities.DirectoryAcls, CapabilityStatus.Complete, 2);
        Assert.All(f.Run("AD.ACL.BROAD_WRITE_DACL").Evaluations, e => Assert.Equal(RuleOutcome.NotVerified, e.Outcome));
    }
    [Theory]
    [InlineData("SELECTIVE_AUTHENTICATION", 2, 2, 0, RuleOutcome.Potential)]
    [InlineData("SELECTIVE_AUTHENTICATION", 1, 2, 0, RuleOutcome.NotApplicable)]
    [InlineData("SELECTIVE_AUTHENTICATION", 2, 2, 16, RuleOutcome.NotDetected)]
    [InlineData("TREAT_AS_EXTERNAL", 3, 2, 72, RuleOutcome.Potential)]
    [InlineData("TREAT_AS_EXTERNAL", 3, 2, 8, RuleOutcome.NotDetected)]
    [InlineData("TGT_DELEGATION", 3, 2, 2048, RuleOutcome.Potential)]
    [InlineData("TGT_DELEGATION", 3, 2, 0, RuleOutcome.NotDetected)]
    [InlineData("LEGACY_TYPE", 3, 1, 0, RuleOutcome.Potential)]
    [InlineData("LEGACY_TYPE", 3, 2, 0, RuleOutcome.NotDetected)]
    public void TrustDirectionAndExplicitBitsMatter(string rule, int direction, int type, int attributes, RuleOutcome expected)
    {
        var f = new AnalysisFixture(); const string cap = CollectionCapabilities.DirectoryTrusts; const string sub = "ad-trust:review.invalid:partner.invalid";
        f.Content = f.Content with { Trusts = [new() { SourceDomainDnsName = "review.invalid", TargetDomainDnsName = "partner.invalid", TrustDirection = direction, TrustType = type, TrustAttributes = attributes }] };
        f.Add(cap, sub, "trust.partner", "partner.invalid"); f.Integer(cap, sub, "trust.direction", direction);
        f.Integer(cap, sub, "trust.type", type); f.Integer(cap, sub, "trust.attributes", attributes);
        Assert.Equal(expected, Assert.Single(f.Run("AD.TRUST." + rule).Evaluations).Outcome);
    }
    public static IEnumerable<object[]> PrivilegeCases() => BuiltInRulePack.Privileges.SelectMany(p => new[] { "broad", "empty", "missing", "name-not-sid" }.Select(m => new object[] { p, m }));
    [Theory, MemberData(nameof(PrivilegeCases))]
    public void EveryPrivilegeRuleNeedsStoredSidAssignment(string privilege, string mode)
    {
        var f = new AnalysisFixture();
        if (mode != "missing") f.Setting("Privilege Rights", privilege, mode == "empty" ? "" : mode == "broad" ? "*S-1-5-11" : "Domain Users",
            FactValueKind.Text, GpoSettingKind.SecurityTemplate, path: "Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf");
        Assert.Equal(mode switch { "broad" => RuleOutcome.Potential, "empty" => RuleOutcome.NotDetected, _ => RuleOutcome.NotVerified },
            f.Check("AD.GPO.PRIVILEGE." + privilege.ToUpperInvariant(), AnalysisFixture.Gpo).Outcome);
    }
    [Theory]
    [InlineData("true", RuleOutcome.Present)] [InlineData("false", RuleOutcome.NotDetected)] [InlineData(null, RuleOutcome.NotVerified)]
    public void CpasswordAbsenceRequiresExplicitParseSignal(string? value, RuleOutcome expected)
    {
        var f = new AnalysisFixture(); const string path = "Machine\\Preferences\\Groups\\Groups.xml";
        f.Content = f.Content with { GroupPolicyFiles = [new() { GpoId = AnalysisFixture.Gpo.Id, RelativePath = path, Kind = GpoSysvolFileKind.PreferencesXml, Length = 42 }] };
        if (value is not null) f.Setting("PreferencesXml", "cpassword-present", value, FactValueKind.Boolean, GpoSettingKind.PreferenceSignal, path: path);
        Assert.Equal(expected, f.Check("AD.GPO.GPP_CPASSWORD", AnalysisFixture.Gpo).Outcome);
    }
    [Theory]
    [InlineData("1", "2", RuleOutcome.Potential)] [InlineData("65537", "65537", RuleOutcome.NotDetected)]
    [InlineData("-1", "4294967295", RuleOutcome.NotDetected)] [InlineData("1", "wrong", RuleOutcome.NotVerified)]
    public void GpoVersionUsesUnsignedBitPattern(string ldap, string sysvol, RuleOutcome expected)
    {
        var f = new AnalysisFixture(); f.Add(CollectionCapabilities.GroupPolicyMetadata, AnalysisFixture.Subject(AnalysisFixture.Gpo), "gpo.versionNumber", ldap, FactValueKind.Integer);
        f.Setting("General", "Version", sysvol, FactValueKind.Text, GpoSettingKind.Ini, GpoPolicyScope.Common, "GPT.INI");
        Assert.Equal(expected, f.Check("AD.GPO.VERSION_MISMATCH", AnalysisFixture.Gpo).Outcome);
    }
}
