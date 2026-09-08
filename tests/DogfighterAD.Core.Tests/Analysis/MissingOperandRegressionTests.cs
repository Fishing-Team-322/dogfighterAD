using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Analysis;

public sealed class MissingOperandRegressionTests
{
    [Theory]
    [InlineData("AD.PRIVILEGED.PASSWORD_NEVER_EXPIRES", 512)]
    [InlineData("AD.PRIVILEGED.NOT_SENSITIVE", 1049088)]
    public void FalseAccountPredicateDoesNotNeedMembershipProof(string id, long uac)
    {
        var f = new AnalysisFixture();
        f.Uac(false, uac);
        // Complete capability, but no negative membership proof in the observations.
        var result = f.Check(id);
        Assert.Equal(RuleOutcome.NotDetected, result.Outcome);
        Assert.Empty(result.MissingData);
        Assert.Contains(result.Evidence, e => e.Path == "user.userAccountControl");
    }

    [Theory]
    [InlineData("AD.PRIVILEGED.PASSWORD_NEVER_EXPIRES", 66048)]
    [InlineData("AD.PRIVILEGED.NOT_SENSITIVE", 512)]
    public void TrueAccountPredicateStillRequiresMembership(string id, long uac)
    {
        var f = new AnalysisFixture(); f.Uac(false, uac);
        Assert.Equal(RuleOutcome.NotVerified, f.Check(id).Outcome);
    }

    [Theory]
    [InlineData("AD.USER.EXPLICIT_RC4")]
    [InlineData("AD.USER.EXPLICIT_DES")]
    public void MissingMaskDoesNotAlsoReportAnObservedInvalidMask(string id)
    {
        var f = new AnalysisFixture(); f.Uac(false, 512);
        var result = f.Check(id);
        Assert.Equal(RuleOutcome.NotVerified, result.Outcome);
        Assert.Equal("field.not-observed", Assert.Single(result.MissingData).Code);
        f.Integer(CollectionCapabilities.DirectoryUsers, AnalysisFixture.Subject(AnalysisFixture.User), "user.supportedEncryptionTypes", 0);
        Assert.Equal("field.zero-or-invalid-encryption-mask", Assert.Single(f.Check(id).MissingData).Code);
    }
}
