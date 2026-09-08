using DogfighterAD.Application.Analysis;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Analysis;

public sealed class AttributeAbsenceRuleTests
{
    private const string Cap = CollectionCapabilities.DirectoryUsers;
    private static void Proof(AnalysisFixture f, string path, string attribute)
    {
        var sub = AnalysisFixture.Subject(AnalysisFixture.User);
        f.Boolean(Cap, sub, path + ".absenceConfirmed", true);
        f.Add(Cap, sub, path + ".absenceProof", "authenticated-schema-read-v1");
        f.Add(Cap, sub, path + ".absenceAttribute", attribute);
        f.Integer(Cap, sub, path + ".absenceSearchFlags", 0);
        f.Add(Cap, sub, path + ".absenceDaclSha256", new string('a', 64));
        f.Add(Cap, sub, path + ".absenceSchemaId", "11111111-1111-1111-1111-111111111111", FactValueKind.Guid);
        f.Add(Cap, sub, path + ".absencePropertySetId", "");
    }

    [Theory]
    [InlineData("SPN_ACCOUNT", "servicePrincipalName", "servicePrincipalName", RuleOutcome.NotDetected)]
    [InlineData("SID_HISTORY", "sidHistory", "sIDHistory", RuleOutcome.NotDetected)]
    [InlineData("CONSTRAINED_DELEGATION", "allowedToDelegateTo", "msDS-AllowedToDelegateTo", RuleOutcome.NotDetected)]
    [InlineData("EXPLICIT_RC4", "supportedEncryptionTypes", "msDS-SupportedEncryptionTypes", RuleOutcome.NotApplicable)]
    [InlineData("EXPLICIT_DES", "supportedEncryptionTypes", "msDS-SupportedEncryptionTypes", RuleOutcome.NotApplicable)]
    [InlineData("REPLICATED_LOGON_AGE", "lastLogonTimestamp", "lastLogonTimestamp", RuleOutcome.NotApplicable)]
    public void OnlyProvenAbsenceEnablesAResult(string rule, string field, string attribute, RuleOutcome expected)
    {
        var f = new AnalysisFixture(); f.Uac(false, 512);
        Assert.Equal(RuleOutcome.NotVerified, f.Check("AD.USER." + rule).Outcome);
        Proof(f, "user." + field, attribute);
        var result = f.Check("AD.USER." + rule);
        Assert.Equal(expected, result.Outcome);
        Assert.Contains(result.Evidence, e => e.Path.EndsWith(".absenceConfirmed", StringComparison.Ordinal));
        f.SetCoverage(Cap, CapabilityStatus.Complete, 1);
        Assert.Equal(RuleOutcome.NotVerified, f.Check("AD.USER." + rule).Outcome);
    }

    [Theory]
    [InlineData("absenceConfirmed")]
    [InlineData("absenceProof")]
    [InlineData("absenceAttribute")]
    [InlineData("absenceSearchFlags")]
    [InlineData("absenceDaclSha256")]
    [InlineData("absenceSchemaId")]
    [InlineData("absencePropertySetId")]
    public void IncompleteProofNeverBecomesAnEmptySet(string part)
    {
        var f = new AnalysisFixture(); f.Uac(false, 512); Proof(f, "user.servicePrincipalName", "servicePrincipalName");
        f.Remove(Cap, AnalysisFixture.Subject(AnalysisFixture.User), "user.servicePrincipalName." + part);
        Assert.Equal(RuleOutcome.NotVerified, f.Check("AD.USER.SPN_ACCOUNT").Outcome);
    }

    [Fact]
    public void ConflictingValueAndAbsenceIsUnknown()
    {
        var f = new AnalysisFixture(); f.Uac(false, 512); Proof(f, "user.servicePrincipalName", "servicePrincipalName");
        f.Add(Cap, AnalysisFixture.Subject(AnalysisFixture.User), "user.servicePrincipalName", "HTTP/host.test");
        Assert.Equal(RuleOutcome.NotVerified, f.Check("AD.USER.SPN_ACCOUNT").Outcome);
    }

    [Theory]
    [InlineData("absenceProof", "untrusted-method")]
    [InlineData("absenceAttribute", "differentAttribute")]
    [InlineData("absenceDaclSha256", "invalid")]
    [InlineData("absencePropertySetId", "not-a-guid")]
    public void MalformedProofDoesNotProduceNegativeVerdict(string part, string value)
    {
        var f = new AnalysisFixture(); f.Uac(false, 512); Proof(f, "user.servicePrincipalName", "servicePrincipalName");
        var sub = AnalysisFixture.Subject(AnalysisFixture.User);
        f.Remove(Cap, sub, "user.servicePrincipalName." + part);
        f.Add(Cap, sub, "user.servicePrincipalName." + part, value);
        Assert.Equal(RuleOutcome.NotVerified, f.Check("AD.USER.SPN_ACCOUNT").Outcome);
    }

    [Fact]
    public void ConfidentialOrMixedSourceProofIsRejected()
    {
        var f = new AnalysisFixture(); f.Uac(false, 512); Proof(f, "user.servicePrincipalName", "servicePrincipalName");
        var sub = AnalysisFixture.Subject(AnalysisFixture.User);
        f.Remove(Cap, sub, "user.servicePrincipalName.absenceSearchFlags");
        f.Integer(Cap, sub, "user.servicePrincipalName.absenceSearchFlags", 128);
        Assert.Equal(RuleOutcome.NotVerified, f.Check("AD.USER.SPN_ACCOUNT").Outcome);
        f.Remove(Cap, sub, "user.servicePrincipalName.absenceSearchFlags");
        f.Integer(Cap, sub, "user.servicePrincipalName.absenceSearchFlags", 0);
        var i = f.Facts.FindIndex(x => x.Path.EndsWith(".absenceDaclSha256", StringComparison.Ordinal));
        f.Facts[i] = f.Facts[i] with { Source = f.Facts[i].Source with { Locator = "another-object" } };
        Assert.Equal(RuleOutcome.NotVerified, f.Check("AD.USER.SPN_ACCOUNT").Outcome);
    }

    [Fact]
    public void BrokenAbsenceCannotHideAnIncompletePrivilegeGraph()
    {
        var f = new AnalysisFixture(); f.Uac(false, 512);
        var normal = AnalysisFixture.Group with { Id = new(Guid.Parse("99999999-9999-9999-9999-999999999999")),
            DistinguishedName = "CN=Domain Users,DC=review,DC=invalid", Sid = AnalysisFixture.DomainSid + "-513" };
        f.Content = f.Content with { Computers = [], Groups = [AnalysisFixture.Group, normal],
            GroupMemberships = [new(normal.Id, AnalysisFixture.User.Id, MembershipSource.PrimaryGroup)] };
        f.Add(CollectionCapabilities.DirectoryGroups, AnalysisFixture.Subject(normal), "object.objectSid", normal.Sid!, FactValueKind.Sid);
        f.Integer(CollectionCapabilities.DirectoryMemberships, AnalysisFixture.Subject(AnalysisFixture.User), "principal.primaryGroupId", 513);
        foreach (var group in f.Content.Groups)
        {
            f.Boolean(CollectionCapabilities.DirectoryMemberships, AnalysisFixture.Subject(group), "group.memberReadComplete", true);
            f.Integer(CollectionCapabilities.DirectoryMemberships, AnalysisFixture.Subject(group), "group.observedMemberCount", 0);
        }
        Assert.Equal(RuleOutcome.NotApplicable, f.Check("AD.PRIVILEGED.NOT_SENSITIVE").Outcome);
        f.Boolean(CollectionCapabilities.DirectoryMemberships, AnalysisFixture.Subject(AnalysisFixture.Group), "group.member.absenceConfirmed", true);
        Assert.Equal(RuleOutcome.NotVerified, f.Check("AD.PRIVILEGED.NOT_SENSITIVE").Outcome);
    }
    [Fact]
    public void RedactionInvalidatesProof()
    {
        foreach (var part in new[] { "absenceProof", "absenceSearchFlags", "absenceConfirmed" })
        {
            var f = new AnalysisFixture(); f.Uac(false, 512); Proof(f, "user.servicePrincipalName", "servicePrincipalName");
            var index = f.Facts.FindIndex(x => x.Path == "user.servicePrincipalName." + part);
            f.Facts[index] = f.Facts[index] with { Disposition = FactDisposition.Redacted };
            Assert.False(new ObservationIndex(f.Build()).Values(Cap, AnalysisFixture.Subject(AnalysisFixture.User), "user.servicePrincipalName").Known);
        }
    }
}
