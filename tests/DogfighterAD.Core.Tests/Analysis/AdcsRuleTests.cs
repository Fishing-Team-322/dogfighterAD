using System.Globalization;
using DogfighterAD.Application.Analysis;
using DogfighterAD.Application.Analysis.Rules;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Analysis;

public sealed class AdcsRuleTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 8, 9, 0, 0, TimeSpan.Zero);
    private static readonly AdObjectId DomainId = new(Guid.Parse("11111111-aaaa-bbbb-cccc-111111111111"));
    private static readonly AdObjectId AuthorityId = new(Guid.Parse("22222222-aaaa-bbbb-cccc-222222222222"));
    private static readonly AdObjectId TemplateId = new(Guid.Parse("33333333-aaaa-bbbb-cccc-333333333333"));
    private const string DomainSid = "S-1-5-21-10-20-30";
    private const string AuthenticatedUsers = "S-1-5-11";
    private const string ClientAuthentication = "1.3.6.1.5.5.7.3.2";
    private const string EnrollGuid = "0e10c968-78fb-11d2-90d4-00c04f79dc55";

    [Fact]
    public void Esc1Candidate_CompleteDirectoryEvidence_IsPotentialNotPresent()
    {
        var report = Run(CreateSnapshot());
        var evaluation = Assert.Single(report.Evaluations, item => item.RuleId == "AD.ADCS.ESC1_CANDIDATE");

        Assert.Equal(RuleOutcome.Potential, evaluation.Outcome);
        Assert.Equal("esc1-candidate", evaluation.CheckKey);
        Assert.Contains("ESC1_CANDIDATE", evaluation.Message, StringComparison.Ordinal);
        var finding = Assert.Single(report.Findings, item => item.RuleId == "AD.ADCS.ESC1_CANDIDATE");
        Assert.Equal(DogfighterAD.Domain.Findings.FindingStatus.Potential, finding.Status);
    }

    [Fact]
    public void Esc1Candidate_ManagerApprovalObserved_IsNotDetected()
    {
        var report = Run(CreateSnapshot(enrollmentFlags: 2));
        var evaluation = Assert.Single(report.Evaluations, item => item.RuleId == "AD.ADCS.ESC1_CANDIDATE");

        Assert.Equal(RuleOutcome.NotDetected, evaluation.Outcome);
        Assert.Contains("approval", evaluation.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Esc1Candidate_AuthenticationPurposeNotObserved_IsNotVerified()
    {
        var report = Run(CreateSnapshot(includeAuthenticationPurpose: false));
        var evaluation = Assert.Single(report.Evaluations, item => item.RuleId == "AD.ADCS.ESC1_CANDIDATE");

        Assert.Equal(RuleOutcome.NotVerified, evaluation.Outcome);
        Assert.Contains(evaluation.MissingData, gap => gap.Code == "field.authentication-purpose-unavailable");
    }

    [Fact]
    public void Esc1Candidate_MultiplePublishingCas_UsesSetEvidence()
    {
        var secondAuthority = new CertificateAuthority
        {
            Id = new AdObjectId(Guid.Parse("44444444-aaaa-bbbb-cccc-444444444444")),
            DistinguishedName = "CN=CA2,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=review,DC=invalid",
            Name = "CA2",
            DnsHostName = "ca2.review.invalid"
        };
        var snapshot = CreateSnapshot(extraAuthority: secondAuthority);

        var evaluation = Assert.Single(Run(snapshot).Evaluations, item => item.RuleId == "AD.ADCS.ESC1_CANDIDATE");

        Assert.Equal(RuleOutcome.Potential, evaluation.Outcome);
    }

    [Fact]
    public void DangerousTemplateAcl_BroadGenericWrite_IsPotential()
    {
        var snapshot = CreateSnapshot(
            accessMask: 0x40000000,
            aceObjectType: null,
            includeAuthenticationPurpose: false);
        var report = Run(snapshot, "AD.ADCS.TEMPLATE_DANGEROUS_ACL");
        var evaluation = Assert.Single(report.Evaluations);

        Assert.Equal(RuleOutcome.Potential, evaluation.Outcome);
        Assert.Equal("dangerous-template-control", evaluation.CheckKey);
    }

    [Fact]
    public void Esc1Candidate_LegacySnapshotWithoutAdcsCoverage_IsNotVerified()
    {
        var snapshot = new AdSnapshot
        {
            Metadata = new SnapshotMetadata
            {
                SnapshotId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
                SchemaVersion = SnapshotSchema.CurrentVersion,
                ProductVersion = "legacy-test",
                StartedAt = Now.AddMinutes(-1),
                CompletedAt = Now,
                CompletionStatus = SnapshotCompletionStatus.Complete,
                Target = new TargetIdentity { InitialTarget = "review.invalid" },
                RequestedCapabilities = [],
                Collectors = []
            },
            Content = new SnapshotContent()
        };

        var evaluation = Assert.Single(Run(snapshot).Evaluations, item => item.RuleId == "AD.ADCS.ESC1_CANDIDATE");

        Assert.Equal(RuleOutcome.NotVerified, evaluation.Outcome);
        Assert.Contains(evaluation.MissingData, gap => gap.CapabilityId == CollectionCapabilities.AdcsTemplates);
    }

    private static AnalysisReport Run(AdSnapshot snapshot, params string[] ids)
    {
        var rules = AdcsRuleCatalog.Create();
        var selected = ids.Length == 0
            ? new HashSet<string>(["AD.ADCS.ESC1_CANDIDATE"], StringComparer.Ordinal)
            : ids.ToHashSet(StringComparer.Ordinal);
        return new RuleEngine(rules, "test.adcs", "1.0.0").Analyze(
            snapshot,
            new RuleEngineOptions { RuleIds = selected },
            TestContext.Current.CancellationToken);
    }

    private static AdSnapshot CreateSnapshot(
        int enrollmentFlags = 0,
        bool includeAuthenticationPurpose = true,
        uint accessMask = 0x00000100,
        string? aceObjectType = EnrollGuid,
        CertificateAuthority? extraAuthority = null)
    {
        var domain = new AdDomain
        {
            Id = DomainId,
            DistinguishedName = "DC=review,DC=invalid",
            DnsName = "review.invalid",
            Sid = DomainSid
        };
        var authority = new CertificateAuthority
        {
            Id = AuthorityId,
            DistinguishedName = "CN=CA1,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=review,DC=invalid",
            Name = "CA1",
            DnsHostName = "ca1.review.invalid"
        };
        var template = new CertificateTemplate
        {
            Id = TemplateId,
            DistinguishedName = "CN=ESC1,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=review,DC=invalid",
            Name = "ESC1",
            CommonName = "ESC1",
            CertificateNameFlags = 1,
            EnrollmentFlags = enrollmentFlags,
            PrivateKeyFlags = 0,
            RequiredAuthorizedSignatures = 0,
            ExpirationPeriodTicks = -31_536_000_000_000L,
            OverlapPeriodTicks = -6_048_000_000_000L,
            ExtendedKeyUsages = includeAuthenticationPurpose ? [ClientAuthentication] : []
        };
        var authorities = extraAuthority is null ? [authority] : new[] { authority, extraAuthority };
        var publications = authorities.Select(item => new CertificateTemplatePublication(item.Id, template.Id)).ToArray();
        var ace = new AdAce
        {
            TargetObjectId = template.Id,
            AceIndex = 0,
            TrusteeSid = AuthenticatedUsers,
            AccessType = AdAccessControlType.Allow,
            AccessMask = accessMask,
            AceFlags = 0,
            ObjectType = aceObjectType is null ? null : Guid.Parse(aceObjectType),
            IsInherited = false
        };
        var services = new CertificateServicesSnapshot
        {
            Authorities = authorities,
            Templates = [template],
            Publications = publications,
            SecurityDescriptors = [new AdSecurityDescriptor { TargetObjectId = template.Id, DaclState = AdDaclState.Present }],
            Aces = [ace],
            Trust = new CertificateServiceTrust { NtAuthObjectPresent = false }
        };

        var capabilities = new[]
        {
            CollectionCapabilities.AdcsTemplates,
            CollectionCapabilities.AdcsPublication,
            CollectionCapabilities.AdcsAcls,
            CollectionCapabilities.DirectoryUsers,
            CollectionCapabilities.DirectoryGroups,
            CollectionCapabilities.DirectoryMemberships,
            CollectionCapabilities.DirectoryDomains
        };
        var coverage = capabilities.Select(capability => new CapabilityCoverage
        {
            CapabilityId = capability,
            ContractVersion = CapabilityContractCatalog.GetCurrentVersion(capability),
            Status = CapabilityStatus.Complete,
            StartedAt = Now.AddMinutes(-2),
            CompletedAt = Now,
            ObservedItemCount = capability switch
            {
                CollectionCapabilities.AdcsTemplates => 1,
                CollectionCapabilities.AdcsPublication => publications.Length,
                CollectionCapabilities.AdcsAcls => 1,
                CollectionCapabilities.DirectoryDomains => 1,
                _ => 0
            },
            Collectors = [new CollectorIdentity("fixture", "1")]
        }).ToArray();

        var facts = new List<ObservedFact>();
        Add(facts, CollectionCapabilities.DirectoryDomains, $"ad-object:{domain.Id}", "domain.objectSid", DomainSid, FactValueKind.Sid);
        AddInteger(facts, CollectionCapabilities.AdcsTemplates, $"adcs-template:{template.Id}", "template.certificateNameFlags", 1);
        AddInteger(facts, CollectionCapabilities.AdcsTemplates, $"adcs-template:{template.Id}", "template.enrollmentFlags", enrollmentFlags);
        AddInteger(facts, CollectionCapabilities.AdcsTemplates, $"adcs-template:{template.Id}", "template.requiredAuthorizedSignatures", 0);
        if (includeAuthenticationPurpose)
            Add(facts, CollectionCapabilities.AdcsTemplates, $"adcs-template:{template.Id}", "template.eku", ClientAuthentication, FactValueKind.Text);
        foreach (var publication in publications)
            Add(facts, CollectionCapabilities.AdcsPublication, $"adcs-template:{template.Id}", "template.publishedOnCa", publication.AuthorityId.ToString(), FactValueKind.Guid);
        Add(facts, CollectionCapabilities.AdcsAcls, $"adcs-template:{template.Id}", "securityDescriptor.daclState", "Present", FactValueKind.Text);
        Add(facts, CollectionCapabilities.AdcsAcls, $"adcs-template:{template.Id}", "securityDescriptor.parseComplete", "true", FactValueKind.Boolean);
        AddInteger(facts, CollectionCapabilities.AdcsAcls, $"adcs-template:{template.Id}", "securityDescriptor.aceCount", 1);
        var prefix = "securityDescriptor.dacl.ace[0]";
        Add(facts, CollectionCapabilities.AdcsAcls, $"adcs-template:{template.Id}", prefix + ".accessType", "Allow", FactValueKind.Text);
        AddInteger(facts, CollectionCapabilities.AdcsAcls, $"adcs-template:{template.Id}", prefix + ".aceFlags", 0);
        AddInteger(facts, CollectionCapabilities.AdcsAcls, $"adcs-template:{template.Id}", prefix + ".accessMask", accessMask);
        Add(facts, CollectionCapabilities.AdcsAcls, $"adcs-template:{template.Id}", prefix + ".trusteeSid", AuthenticatedUsers, FactValueKind.Sid);
        Add(facts, CollectionCapabilities.AdcsAcls, $"adcs-template:{template.Id}", prefix + ".objectTypePresent", aceObjectType is null ? "false" : "true", FactValueKind.Boolean);
        if (aceObjectType is not null)
            Add(facts, CollectionCapabilities.AdcsAcls, $"adcs-template:{template.Id}", prefix + ".objectType", aceObjectType, FactValueKind.Guid);

        return new AdSnapshot
        {
            Metadata = new SnapshotMetadata
            {
                SnapshotId = Guid.Parse("99999999-aaaa-bbbb-cccc-999999999999"),
                SchemaVersion = SnapshotSchema.CurrentVersion,
                ProductVersion = "adcs-test",
                StartedAt = Now.AddMinutes(-2),
                CompletedAt = Now,
                CompletionStatus = SnapshotCompletionStatus.Complete,
                Target = new TargetIdentity { InitialTarget = "review.invalid", DomainDnsName = "review.invalid", DomainSid = DomainSid },
                RequestedCapabilities = capabilities,
                Collectors = [new CollectorIdentity("fixture", "1")]
            },
            Content = new SnapshotContent { Domains = [domain], CertificateServices = services },
            Coverage = coverage,
            Observations = facts
        };
    }

    private static void AddInteger(ICollection<ObservedFact> facts, string capability, string subject, string path, long value) =>
        Add(facts, capability, subject, path, value.ToString(CultureInfo.InvariantCulture), FactValueKind.Integer);

    private static void Add(ICollection<ObservedFact> facts, string capability, string subject, string path, string value, FactValueKind kind)
    {
        facts.Add(new ObservedFact
        {
            FactId = FactIdFactory.Create(capability, subject, path, kind, value),
            CapabilityId = capability,
            SubjectId = subject,
            Path = path,
            Value = value,
            ValueKind = kind,
            ObservedAt = Now.AddMinutes(-1),
            Source = new ObservationSource
            {
                CollectorId = "fixture",
                CollectorVersion = "1",
                SourceKind = "ldap",
                Endpoint = "review.invalid",
                Locator = "synthetic"
            }
        });
    }
}
