using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Web;

namespace DogfighterAD.Core.Tests;

public sealed class WebFindingPresentationTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 8, 12, 0, 0, TimeSpan.Zero);
    private const string TemplateId = "adcs-template:11111111-2222-3333-4444-555555555555";

    [Fact]
    public void Map_Esc1Candidate_UsesPotentialCopyKeyConditionsAndRuntimeBoundary()
    {
        var finding = FindingFor(
            "ADCS.TEMPLATE.ESC1_CANDIDATE",
            FindingSeverity.High,
            FindingStatus.Potential,
            TemplateId,
            "ESC1",
            Evidence("template.certificateNameFlags", "1"));
        var report = Report(finding, EvaluationFor(finding, RuleOutcome.Potential));
        var view = CertificateServicesView(new UiCertificateTemplateView
        {
            StableId = TemplateId,
            CommonName = "ESC1",
            DisplayName = "ESC1",
            DistinguishedName = "CN=ESC1,CN=Certificate Templates,DC=mini,DC=lab",
            CertificateNameFlags = 1,
            EnrollmentFlags = 0,
            RequiredAuthorizedSignatures = 0,
            ExtendedKeyUsages = ["1.3.6.1.5.5.7.3.2"],
            PublishedAuthorities = [new UiPublishedAuthority("ca-1", "MINILAB-CA", "ca01.mini.lab")],
            DirectAces = [Ace("S-1-5-11", "Enroll")]
        });

        var mapped = Assert.Single(UiFindingPresentationMapper.Map(report, view).Findings);

        Assert.Equal("Potential certificate impersonation risk", mapped.CustomerTitle);
        Assert.Equal("Potential", mapped.CustomerStatus);
        Assert.NotNull(mapped.StatusBoundary);
        Assert.Contains("directory-side conditions", mapped.StatusBoundary!);
        Assert.Contains(mapped.Conditions, item => item.Label == "Low-privileged enrollment" && item.Value == "Yes");
        Assert.Contains(mapped.Conditions, item => item.Label == "CA runtime conditions" && item.Value == "Not verified");
        Assert.Contains(mapped.KeyEvidence, item => item.Headline.Contains("Authenticated Users", StringComparison.Ordinal));
    }

    [Fact]
    public void Map_DangerousTemplateAcl_UsesFriendlyPrincipalAndRight()
    {
        const string domainUsers = "S-1-5-21-100-200-300-513";
        var finding = FindingFor(
            "ADCS.TEMPLATE.DANGEROUS_ACL",
            FindingSeverity.High,
            FindingStatus.Potential,
            TemplateId,
            "ESC4",
            Evidence("securityDescriptor.dacl.ace[4].accessMask", "1073741824"));
        var report = Report(finding, EvaluationFor(finding, RuleOutcome.Potential));
        var view = CertificateServicesView(new UiCertificateTemplateView
        {
            StableId = TemplateId,
            CommonName = "ESC4",
            DisplayName = "ESC4",
            DistinguishedName = "CN=ESC4,CN=Certificate Templates,DC=mini,DC=lab",
            DirectAces = [Ace(domainUsers, "GenericWrite", aceIndex: 4)]
        });

        var key = Assert.Single(Assert.Single(UiFindingPresentationMapper.Map(report, view).Findings).KeyEvidence);

        Assert.Equal("Domain Users", key.Principal);
        Assert.Equal(domainUsers, key.TechnicalPrincipal);
        Assert.Equal("Can modify this object", key.Right);
        Assert.Equal("GenericWrite", key.TechnicalRight);
        Assert.Equal("securityDescriptor.dacl.ace[4].accessMask", key.SourcePath);
    }

    [Fact]
    public void Map_BroadEnrollment_PreservesNestedMembershipEvidence()
    {
        var nested = Evidence("group.member", "CN=NormalUser,OU=Users,DC=mini,DC=lab");
        var finding = FindingFor(
            "ADCS.TEMPLATE.BROAD_ENROLLMENT",
            FindingSeverity.Medium,
            FindingStatus.Potential,
            TemplateId,
            "EnrollmentTemplate",
            nested);
        var report = Report(finding, EvaluationFor(finding, RuleOutcome.Potential));
        var view = CertificateServicesView(new UiCertificateTemplateView
        {
            StableId = TemplateId,
            CommonName = "EnrollmentTemplate",
            DistinguishedName = "CN=EnrollmentTemplate,CN=Certificate Templates,DC=mini,DC=lab",
            DirectAces = [Ace("S-1-5-21-100-200-300-1601", "Enroll")]
        });

        var mapped = Assert.Single(UiFindingPresentationMapper.Map(report, view).Findings);

        Assert.Contains(mapped.KeyEvidence, item =>
            item.Headline == "Nested membership evidence includes NormalUser" && item.SourcePath == "group.member");
    }

    [Fact]
    public void Map_NotVerified_ExplainsMissingAclAndNeverCallsItClean()
    {
        var evaluation = new RuleEvaluation
        {
            RuleId = "ADCS.TEMPLATE.DANGEROUS_ACL",
            RuleVersion = "1.0.0",
            Subject = new ObjectReference("certificate-template", TemplateId, DisplayName: "ESC4"),
            Outcome = RuleOutcome.NotVerified,
            Code = "analysis.required-data-unavailable",
            Message = "Required data is unavailable.",
            MissingData = [new DataGap("adcs.acls", TemplateId, "securityDescriptor", "descriptor.unavailable")]
        };
        var report = Report(null, evaluation, "ADCS.TEMPLATE.DANGEROUS_ACL", FindingSeverity.High);

        var mapped = Assert.Single(UiFindingPresentationMapper.Map(report, new UiCertificateServicesView { Available = false }).NotVerified);

        Assert.Equal("Could not verify", mapped.Status);
        Assert.Contains("should not be interpreted as a clean result", mapped.Caution, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("security descriptor", mapped.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(mapped.MissingEvidence, item => item.Contains("adcs.acls", StringComparison.Ordinal));
    }

    [Fact]
    public void Map_UnknownSid_FallsBackToSid()
    {
        const string unknownSid = "S-1-5-21-100-200-300-4242";
        var finding = FindingFor(
            "ADCS.TEMPLATE.DANGEROUS_ACL",
            FindingSeverity.High,
            FindingStatus.Potential,
            TemplateId,
            "UnknownPrincipalTemplate",
            Evidence("securityDescriptor.dacl.ace[0].accessMask", "262144"));
        var report = Report(finding, EvaluationFor(finding, RuleOutcome.Potential));
        var view = CertificateServicesView(new UiCertificateTemplateView
        {
            StableId = TemplateId,
            CommonName = "UnknownPrincipalTemplate",
            DistinguishedName = "CN=UnknownPrincipalTemplate,CN=Certificate Templates,DC=mini,DC=lab",
            DirectAces = [Ace(unknownSid, "WriteDacl")]
        });

        var key = Assert.Single(Assert.Single(UiFindingPresentationMapper.Map(report, view).Findings).KeyEvidence);

        Assert.Equal(unknownSid, key.Principal);
        Assert.Equal(unknownSid, key.TechnicalPrincipal);
    }

    [Fact]
    public void Map_SafeTemplate_DoesNotInventRiskPresentation()
    {
        var report = Report();
        var view = CertificateServicesView(new UiCertificateTemplateView
        {
            StableId = TemplateId,
            CommonName = "SafeTemplate",
            DisplayName = "Safe Template",
            DistinguishedName = "CN=SafeTemplate,CN=Certificate Templates,DC=mini,DC=lab"
        });

        var mapped = UiFindingPresentationMapper.Map(report, view);

        Assert.Empty(mapped.Findings);
        Assert.Equal("No findings emitted", mapped.Summary.OverallPosture);
    }

    [Fact]
    public void Map_RuleError_RemainsVisibleAndIsNotPresentedAsClean()
    {
        var evaluation = new RuleEvaluation
        {
            RuleId = "ADCS.TEMPLATE.BROAD_ENROLLMENT",
            RuleVersion = "1.0.0",
            Subject = new ObjectReference("certificate-template", TemplateId, DisplayName: "EnrollmentTemplate"),
            Outcome = RuleOutcome.Error,
            Code = "analysis.rule-error",
            Message = "The rule failed; no clean result was inferred."
        };
        var report = Report(null, evaluation, "ADCS.TEMPLATE.BROAD_ENROLLMENT", FindingSeverity.Medium);

        var mapped = Assert.Single(UiFindingPresentationMapper.Map(
            report,
            new UiCertificateServicesView { Available = false }).NotVerified);

        Assert.Equal("Check failed", mapped.Status);
        Assert.Equal("Error", mapped.TechnicalOutcome);
        Assert.Contains("clean result", mapped.Caution, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Map_LegacySnapshotMissingAdcs_RemainsNotVerified()
    {
        var evaluation = new RuleEvaluation
        {
            RuleId = "ADCS.TEMPLATE.ESC1_CANDIDATE",
            RuleVersion = "1.0.0",
            Subject = new ObjectReference("snapshot", "snapshot:legacy"),
            Outcome = RuleOutcome.NotVerified,
            Code = "analysis.required-data-unavailable",
            Message = "Required data is unavailable.",
            MissingData = [new DataGap("adcs.templates", "snapshot:legacy", "coverage", "capability.unavailable")]
        };
        var report = Report(null, evaluation, "ADCS.TEMPLATE.ESC1_CANDIDATE", FindingSeverity.High);

        var mapped = UiFindingPresentationMapper.Map(report, new UiCertificateServicesView { Available = false });

        Assert.Single(mapped.NotVerified);
        Assert.Equal("Needs attention", mapped.Summary.OverallPosture);
        Assert.Contains("Certificate Services evidence", mapped.NotVerified[0].MissingEvidence[0]);
    }

    private static AnalysisReport Report(
        Finding? finding = null,
        RuleEvaluation? evaluation = null,
        string? ruleId = null,
        FindingSeverity severity = FindingSeverity.Informational)
    {
        ruleId ??= finding?.RuleId ?? evaluation?.RuleId;
        IReadOnlyList<Finding> findings = finding is null ? [] : [finding];
        IReadOnlyList<RuleEvaluation> evaluations = evaluation is null ? [] : [evaluation];
        IReadOnlyList<RuleRunSummary> rules = ruleId is null
            ? []
            :
            [
                new RuleRunSummary
                {
                    RuleId = ruleId,
                    RuleVersion = "1.0.0",
                    Title = finding?.Title ?? ruleId,
                    Category = "Certificate Services",
                    Severity = finding?.Severity ?? severity,
                    Completion = evaluation?.Outcome == RuleOutcome.NotVerified ? AnalysisCompletion.Partial : AnalysisCompletion.Complete
                }
            ];

        return new AnalysisReport
        {
            EngineVersion = "test",
            RulePackId = "test.pack",
            RulePackVersion = "1.0.0",
            SnapshotId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            SnapshotSchemaVersion = 1,
            SnapshotCompletedAt = Now,
            AnalysisTime = Now,
            Policy = new AnalysisPolicy(),
            PolicySha256 = "test",
            Completion = evaluation?.Outcome == RuleOutcome.NotVerified ? AnalysisCompletion.Partial : AnalysisCompletion.Complete,
            Rules = rules,
            Evaluations = evaluations,
            Findings = findings
        };
    }

    private static RuleEvaluation EvaluationFor(Finding finding, RuleOutcome outcome) => new()
    {
        RuleId = finding.RuleId,
        RuleVersion = finding.RuleVersion,
        Subject = finding.AffectedObjects[0],
        Outcome = outcome,
        Code = "analysis.condition-observed",
        Message = finding.Description,
        Evidence = finding.Evidence
    };

    private static Finding FindingFor(
        string ruleId,
        FindingSeverity severity,
        FindingStatus status,
        string stableId,
        string displayName,
        params Evidence[] evidence) => new()
    {
        RuleId = ruleId,
        RuleVersion = "1.0.0",
        Fingerprint = "finding:v1:" + ruleId,
        Severity = severity,
        Status = status,
        Confidence = status == FindingStatus.Present ? FindingConfidence.High : FindingConfidence.Medium,
        Title = ruleId,
        Description = "test description",
        Risk = "test risk",
        Remediation = "test remediation",
        AffectedObjects = [new ObjectReference("certificate-template", stableId, DisplayName: displayName)],
        Evidence = evidence
    };

    private static Evidence Evidence(string path, string value) => new()
    {
        Kind = "observation",
        SubjectId = TemplateId,
        CapabilityId = "adcs.templates",
        FactId = "fact:" + path + ":" + value,
        Source = "ldap",
        Path = path,
        Value = value,
        ObservedAt = Now,
        CollectorId = "adcs-test",
        CollectorVersion = "1.0.0"
    };

    private static UiCertificateAceView Ace(string sid, string right, int aceIndex = 0) => new()
    {
        AceIndex = aceIndex,
        TrusteeSid = sid,
        AccessType = "Allow",
        AccessMask = "0x00000100",
        AceFlags = "0x00",
        IsInherited = false,
        Rights = [right]
    };

    private static UiCertificateServicesView CertificateServicesView(UiCertificateTemplateView template) => new()
    {
        Available = true,
        Templates = [template]
    };
}
