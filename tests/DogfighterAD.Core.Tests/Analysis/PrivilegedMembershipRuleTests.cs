using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Analysis;

public sealed class PrivilegedMembershipRuleTests
{
    [Theory]
    [InlineData("NOT_SENSITIVE", 512, null)]
    [InlineData("PASSWORD_NEVER_EXPIRES", 66048, null)]
    [InlineData("SPN_ACCOUNT", 512, "HTTP/service.review.invalid")]
    public void PrivilegedRulesRequireRealMembershipEvidence(string suffix, long uac, string? spn)
    {
        var f = new AnalysisFixture(); f.Uac(false, uac);
        f.Content = f.Content with { GroupMemberships = [new(AnalysisFixture.Group.Id, AnalysisFixture.User.Id, MembershipSource.Explicit)] };
        f.Add(CollectionCapabilities.DirectoryMemberships, AnalysisFixture.Subject(AnalysisFixture.Group), "group.member", AnalysisFixture.User.DistinguishedName, FactValueKind.DistinguishedName);
        if (spn is not null) f.Add(CollectionCapabilities.DirectoryUsers, AnalysisFixture.Subject(AnalysisFixture.User), "user.servicePrincipalName", spn);
        var positive = f.Check("AD.PRIVILEGED." + suffix);
        Assert.Equal(RuleOutcome.Potential, positive.Outcome);
        Assert.Contains(positive.Evidence, e => e.Path == "group.member");
        f.Remove(CollectionCapabilities.DirectoryMemberships, AnalysisFixture.Subject(AnalysisFixture.Group), "group.member");
        Assert.Equal(RuleOutcome.NotVerified, f.Check("AD.PRIVILEGED." + suffix).Outcome);
    }
    [Fact]
    public void AdminCountIsNeverProofOfPrivilege()
    {
        var f = new AnalysisFixture(); f.Uac(false, 512);
        f.Content = f.Content with { Users = [AnalysisFixture.User with { AdminCount = 1 }] };
        f.Integer(CollectionCapabilities.DirectoryUsers, AnalysisFixture.Subject(AnalysisFixture.User), "user.adminCount", 1);
        Assert.Empty(f.Run("AD.PRIVILEGED.NOT_SENSITIVE").Findings);
    }
    [Fact]
    public void NestedCyclesTerminateAndKeepTheFullWitnessPath()
    {
        var f = new AnalysisFixture(); f.Uac(false, 512);
        var nested = AnalysisFixture.Group with { Id = new(Guid.Parse("99999999-9999-9999-9999-999999999999")), DistinguishedName = "CN=Nested,DC=review,DC=invalid", Sid = AnalysisFixture.DomainSid + "-1102" };
        f.Content = f.Content with { Groups = [AnalysisFixture.Group, nested], GroupMemberships =
            [new(AnalysisFixture.Group.Id, nested.Id, MembershipSource.Explicit), new(nested.Id, AnalysisFixture.Group.Id, MembershipSource.Explicit), new(nested.Id, AnalysisFixture.User.Id, MembershipSource.Explicit)] };
        f.Add(CollectionCapabilities.DirectoryGroups, AnalysisFixture.Subject(nested), "object.objectSid", nested.Sid!, FactValueKind.Sid);
        f.Add(CollectionCapabilities.DirectoryMemberships, AnalysisFixture.Subject(AnalysisFixture.Group), "group.member", nested.DistinguishedName, FactValueKind.DistinguishedName);
        f.Add(CollectionCapabilities.DirectoryMemberships, AnalysisFixture.Subject(nested), "group.member", AnalysisFixture.Group.DistinguishedName, FactValueKind.DistinguishedName);
        f.Add(CollectionCapabilities.DirectoryMemberships, AnalysisFixture.Subject(nested), "group.member", AnalysisFixture.User.DistinguishedName, FactValueKind.DistinguishedName);
        var result = f.Check("AD.PRIVILEGED.NOT_SENSITIVE");
        Assert.Equal(RuleOutcome.Potential, result.Outcome);
        Assert.Equal(2, result.Evidence.Count(e => e.Path == "group.member"));
    }
    [Fact]
    public void PrimaryGroupUsesTheObservedDomainSidAndRid()
    {
        var f = new AnalysisFixture(); f.Uac(false, 512);
        f.Content = f.Content with { GroupMemberships = [new(AnalysisFixture.Group.Id, AnalysisFixture.User.Id, MembershipSource.PrimaryGroup)] };
        f.Integer(CollectionCapabilities.DirectoryMemberships, AnalysisFixture.Subject(AnalysisFixture.User), "principal.primaryGroupId", 512);
        Assert.Equal(RuleOutcome.Potential, f.Check("AD.PRIVILEGED.NOT_SENSITIVE").Outcome);
    }
}
