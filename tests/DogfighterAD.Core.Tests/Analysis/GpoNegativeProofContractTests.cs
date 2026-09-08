using DogfighterAD.Application.Analysis.Rules;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Analysis;

public sealed class GpoNegativeProofContractTests
{
    [Fact]
    public void MissingRegistryAssignmentNeedsSysvolV3CompleteCoverage()
    {
        var definition = BuiltInRulePack.RegistryDefinitions[1];
        var current = new AnalysisFixture();
        Assert.Equal(RuleOutcome.NotDetected,
            current.Check(definition.Id, AnalysisFixture.Gpo, "Machine").Outcome);

        var old = new AnalysisFixture();
        old.SetCoverage(CollectionCapabilities.GroupPolicySysvol, CapabilityStatus.Complete, 2);
        var result = old.Check(definition.Id, AnalysisFixture.Gpo, "Machine");
        Assert.Equal(RuleOutcome.NotVerified, result.Outcome);
        Assert.Contains(result.MissingData, gap => gap.Code == "capability.contract-too-old-for-negative-proof");
    }

    [Fact]
    public void MissingRegistryAssignmentStaysUnverifiedWhenSysvolIsPartial()
    {
        var definition = BuiltInRulePack.RegistryDefinitions[1];
        var fixture = new AnalysisFixture();
        fixture.SetCoverage(CollectionCapabilities.GroupPolicySysvol, CapabilityStatus.Partial);

        var result = fixture.Check(definition.Id, AnalysisFixture.Gpo, "Machine");
        Assert.Equal(RuleOutcome.NotVerified, result.Outcome);
        Assert.Contains(result.MissingData, gap => gap.Code == "capability.complete-inventory-required-for-negative-proof");
    }

    [Fact]
    public void MissingPrivilegeAssignmentUsesTheSameV3NegativeProofBoundary()
    {
        const string ruleId = "AD.GPO.PRIVILEGE.SEDEBUGPRIVILEGE";
        Assert.Equal(RuleOutcome.NotDetected,
            new AnalysisFixture().Check(ruleId, AnalysisFixture.Gpo).Outcome);

        var old = new AnalysisFixture();
        old.SetCoverage(CollectionCapabilities.GroupPolicySysvol, CapabilityStatus.Complete, 2);
        Assert.Equal(RuleOutcome.NotVerified, old.Check(ruleId, AnalysisFixture.Gpo).Outcome);
    }
}
