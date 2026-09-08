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
    private const string ServerAuthentication = "1.3.6.1.5.5.7.3.1";
    private const string EnrollGuid = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
    private const string AutoEnrollGuid = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";

    [Fact]
    public void RulePack_ContainsMilestoneContract()
    {
        var ids = CertificateServicesRulePack.Create().Select(rule => rule.Metadata.Id).ToHashSet(StringComparer.Ordinal);

        Assert.Equal(8, ids.Count);
        Assert.Contains("ADCS.TEMPLATE.ESC1_CANDIDATE", ids);
        Assert.Contains("ADCS.TEMPLATE.DANGEROUS_ACL", ids);
        Assert.Contains("ADCS.TEMPLATE.BROAD_ENROLLMENT", ids);
        Assert.Contains("ADCS.TEMPLATE.AUTHENTICATION_CAPABLE", ids);
        Assert.Contains("ADCS.TEMPLATE.ENROLLEE_SUPPLIES_SUBJECT", ids);
        Assert.Contains("ADCS.TEMPLATE.NO_APPROVAL", ids);
        Assert.Contains("ADCS.TEMPLATE.NO_AUTHORIZED_SIGNATURE", ids);
        Assert.Contains("ADCS.CA.DANGEROUS_DIRECTORY_ACL", ids);
    }

    [Fact]
    public void Esc1Candidate_CompleteDirectoryEvidence_IsPotentialNotPresent()
    {
        var evaluation = Evaluation(CreateSnapshot(), "ADCS.TEMPLATE.ESC1_CANDIDATE");

        Assert.Equal(RuleOutcome.Potential, evaluation.Outcome);
        Assert.Equal("esc1-candidate", evaluation.CheckKey);
        Assert.Contains("directory evidence proves", evaluation.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runtime", evaluation.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CleanTemplate_DoesNotProduceEsc1OrDangerousAclFalsePositive()
    {
        var snapshot = CreateSnapshot(new FixtureOptions
        {
            CertificateNameFlags = 0,
            TemplateDaclState = AdDaclState.Empty
        });

        Assert.Equal(RuleOutcome.NotDetected, Evaluation(snapshot, "ADCS.TEMPLATE.ESC1_CANDIDATE").Outcome);
        Assert.Equal(RuleOutcome.NotDetected, Evaluation(snapshot, "ADCS.TEMPLATE.BROAD_ENROLLMENT").Outcome);
        Assert.Equal(RuleOutcome.NotDetected, Evaluation(snapshot, "ADCS.TEMPLATE.DANGEROUS_ACL").Outcome);
    }

    [Fact]
    public void Esc1Candidate_ManagerApprovalEnabled_IsNotDetected()
    {
        var evaluation = Evaluation(
            CreateSnapshot(new FixtureOptions { EnrollmentFlags = 2 }),
            "ADCS.TEMPLATE.ESC1_CANDIDATE");

        Assert.Equal(RuleOutcome.NotDetected, evaluation.Outcome);
    }

    [Fact]
    public void Esc1Candidate_AuthorizedSignatureRequired_IsNotDetected()
    {
        var evaluation = Evaluation(
            CreateSnapshot(new FixtureOptions { RequiredAuthorizedSignatures = 1 }),
            "ADCS.TEMPLATE.ESC1_CANDIDATE");

        Assert.Equal(RuleOutcome.NotDetected, evaluation.Outcome);
    }

    [Fact]
    public void Esc1Candidate_EnrolleeCannotSupplySubject_IsNotDetected()
    {
        var evaluation = Evaluation(
            CreateSnapshot(new FixtureOptions { CertificateNameFlags = 0 }),
            "ADCS.TEMPLATE.ESC1_CANDIDATE");

        Assert.Equal(RuleOutcome.NotDetected, evaluation.Outcome);
    }

    [Fact]
    public void BroadEnrollmentWithoutAuthenticationPurpose_IsNotEsc1()
    {
        var snapshot = CreateSnapshot(new FixtureOptions { PurposeOid = ServerAuthentication });

        Assert.Equal(RuleOutcome.Potential, Evaluation(snapshot, "ADCS.TEMPLATE.BROAD_ENROLLMENT").Outcome);
        Assert.Equal(RuleOutcome.NotDetected, Evaluation(snapshot, "ADCS.TEMPLATE.AUTHENTICATION_CAPABLE").Outcome);
        Assert.Equal(RuleOutcome.NotDetected, Evaluation(snapshot, "ADCS.TEMPLATE.ESC1_CANDIDATE").Outcome);
    }

    [Fact]
    public void BroadAutoEnrollment_IsRecognizedAsBroadEnrollmentPosture()
    {
        var snapshot = CreateSnapshot(new FixtureOptions
        {
            TemplateAccessMask = 0x00000100,
            TemplateAceObjectType = AutoEnrollGuid
        });

        var evaluation = Evaluation(snapshot, "ADCS.TEMPLATE.BROAD_ENROLLMENT");

        Assert.Equal(RuleOutcome.Potential, evaluation.Outcome);
        Assert.Contains("AutoEnrollment", evaluation.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UnpublishedTemplate_IsNotApplicableToEsc1Candidate()
    {
        var evaluation = Evaluation(
            CreateSnapshot(new FixtureOptions { Published = false }),
            "ADCS.TEMPLATE.ESC1_CANDIDATE");

        Assert.Equal(RuleOutcome.NotApplicable, evaluation.Outcome);
    }

    [Fact]
    public void DangerousTemplateAcl_GenericWrite_IsPotential()
    {
        var evaluation = Evaluation(
            CreateSnapshot(new FixtureOptions
            {
                TemplateAccessMask = 0x40000000,
                TemplateAceObjectType = null
            }),
            "ADCS.TEMPLATE.DANGEROUS_ACL");

        Assert.Equal(RuleOutcome.Potential, evaluation.Outcome);
        Assert.Equal("dangerous-directory-control", evaluation.CheckKey);
    }

    [Fact]
    public void DangerousCaDirectoryAcl_WriteDacl_IsPotential()
    {
        var evaluation = Evaluation(
            CreateSnapshot(new FixtureOptions
            {
                CaDaclState = AdDaclState.Present,
                CaAccessMask = 0x00040000,
                CaAceObjectType = null
            }),
            "ADCS.CA.DANGEROUS_DIRECTORY_ACL");

        Assert.Equal(RuleOutcome.Potential, evaluation.Outcome);
        Assert.Equal("certificate-authority", evaluation.Subject.Kind);
    }

    [Fact]
    public void AtomicTemplatePostureRules_AreEvidenceBacked()
    {
        var snapshot = CreateSnapshot();

        Assert.Equal(RuleOutcome.Present, Evaluation(snapshot, "ADCS.TEMPLATE.AUTHENTICATION_CAPABLE").Outcome);
        Assert.Equal(RuleOutcome.Present, Evaluation(snapshot, "ADCS.TEMPLATE.ENROLLEE_SUPPLIES_SUBJECT").Outcome);
        Assert.Equal(RuleOutcome.Present, Evaluation(snapshot, "ADCS.TEMPLATE.NO_APPROVAL").Outcome);
        Assert.Equal(RuleOutcome.Present, Evaluation(snapshot, "ADCS.TEMPLATE.NO_AUTHORIZED_SIGNATURE").Outcome);
    }

    [Fact]
    public void MissingAuthenticationPurposeEvidence_IsNotVerified()
    {
        var snapshot = CreateSnapshot(new FixtureOptions { IncludePurposeEvidence = false, PurposeOid = null });

        var evaluation = Evaluation(snapshot, "ADCS.TEMPLATE.AUTHENTICATION_CAPABLE");

        Assert.Equal(RuleOutcome.NotVerified, evaluation.Outcome);
        Assert.Contains(evaluation.MissingData, gap => gap.Code == "field.authentication-purpose-unavailable");
    }

    [Fact]
    public void PartialAclCapability_AddsNotVerifiedCoverageEvaluation()
    {
        var snapshot = CreateSnapshot();
        snapshot = snapshot with
        {
            Coverage = snapshot.Coverage.Select(item =>
                item.CapabilityId == CollectionCapabilities.AdcsAcls
                    ? item with { Status = CapabilityStatus.Partial }
                    : item).ToArray()
        };

        var report = Run(snapshot, "ADCS.TEMPLATE.BROAD_ENROLLMENT");

        Assert.Contains(report.Evaluations, item =>
            item.RuleId == "ADCS.TEMPLATE.BROAD_ENROLLMENT" &&
            item.Outcome == RuleOutcome.NotVerified &&
            item.CheckKey == "coverage:adcs.acls");
    }

    [Fact]
    public void LegacySnapshotWithoutAdcsCoverage_IsNotVerified()
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

        var evaluation = Assert.Single(Run(snapshot, "ADCS.TEMPLATE.ESC1_CANDIDATE").Evaluations);

        Assert.Equal(RuleOutcome.NotVerified, evaluation.Outcome);
        Assert.Contains(evaluation.MissingData, gap => gap.CapabilityId == CollectionCapabilities.AdcsTemplates);
    }

    private static RuleEvaluation Evaluation(AdSnapshot snapshot, string id) =>
        Assert.Single(Run(snapshot, id).Evaluations, item => item.Subject.StableId != $"snapshot:{snapshot.Metadata.SnapshotId:D}");

    private static AnalysisReport Run(AdSnapshot snapshot, params string[] ids) =>
        new RuleEngine(CertificateServicesRulePack.Create(), "test.adcs", CertificateServicesRulePack.Version).Analyze(
            snapshot,
            new RuleEngineOptions
            {
                RuleIds = ids.Length == 0 ? null : ids.ToHashSet(StringComparer.Ordinal)
            },
            TestContext.Current.CancellationToken);

    private static AdSnapshot CreateSnapshot(FixtureOptions? options = null)
    {
        options ??= new FixtureOptions();
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
            DistinguishedName = "CN=Template1,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=review,DC=invalid",
            Name = "Template1",
            CommonName = "Template1",
            CertificateNameFlags = options.CertificateNameFlags,
            EnrollmentFlags = options.EnrollmentFlags,
            PrivateKeyFlags = 0,
            RequiredAuthorizedSignatures = options.RequiredAuthorizedSignatures,
            ExpirationPeriodTicks = -31_536_000_000_000L,
            OverlapPeriodTicks = -6_048_000_000_000L,
            ExtendedKeyUsages = options.PurposeOid is null ? [] : [options.PurposeOid]
        };

        var publications = options.Published
            ? new[] { new CertificateTemplatePublication(authority.Id, template.Id) }
            : [];
        var descriptors = new List<AdSecurityDescriptor>();
        var aces = new List<AdAce>();
        AddAclModel(descriptors, aces, template.Id, options.TemplateDaclState, options.TemplateAccessMask, options.TemplateAceObjectType);
        AddAclModel(descriptors, aces, authority.Id, options.CaDaclState, options.CaAccessMask, options.CaAceObjectType);

        var services = new CertificateServicesSnapshot
        {
            Authorities = [authority],
            Templates = [template],
            Publications = publications,
            SecurityDescriptors = descriptors,
            Aces = aces,
            Trust = new CertificateServiceTrust { NtAuthObjectPresent = false }
        };

        var capabilities = new[]
        {
            CollectionCapabilities.AdcsAuthorities,
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
                CollectionCapabilities.AdcsAuthorities => 1,
                CollectionCapabilities.AdcsTemplates => 1,
                CollectionCapabilities.AdcsPublication => publications.Length,
                CollectionCapabilities.AdcsAcls => descriptors.Count,
                CollectionCapabilities.DirectoryDomains => 1,
                _ => 0
            },
            Collectors = [new CollectorIdentity("fixture", "1")]
        }).ToArray();

        var facts = new List<ObservedFact>();
        Add(facts, CollectionCapabilities.DirectoryDomains, $"ad-object:{domain.Id}", "domain.objectSid", DomainSid, FactValueKind.Sid);
        Add(facts, CollectionCapabilities.AdcsAuthorities, $"adcs-ca:{authority.Id}", "authority.cn", "CA1", FactValueKind.Text);
        AddInteger(facts, CollectionCapabilities.AdcsTemplates, $"adcs-template:{template.Id}", "template.certificateNameFlags", options.CertificateNameFlags);
        AddInteger(facts, CollectionCapabilities.AdcsTemplates, $"adcs-template:{template.Id}", "template.enrollmentFlags", options.EnrollmentFlags);
        AddInteger(facts, CollectionCapabilities.AdcsTemplates, $"adcs-template:{template.Id}", "template.requiredAuthorizedSignatures", options.RequiredAuthorizedSignatures);
        if (options.IncludePurposeEvidence && options.PurposeOid is not null)
            Add(facts, CollectionCapabilities.AdcsTemplates, $"adcs-template:{template.Id}", "template.eku", options.PurposeOid, FactValueKind.Text);
        if (options.Published)
            Add(facts, CollectionCapabilities.AdcsPublication, $"adcs-template:{template.Id}", "template.publishedOnCa", authority.Id.ToString(), FactValueKind.Guid);
        AddAclFacts(facts, template, options.TemplateDaclState, options.TemplateAccessMask, options.TemplateAceObjectType);
        AddAclFacts(facts, authority, options.CaDaclState, options.CaAccessMask, options.CaAceObjectType);

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
                Target = new TargetIdentity
                {
                    InitialTarget = "review.invalid",
                    DomainDnsName = "review.invalid",
                    DomainSid = DomainSid
                },
                RequestedCapabilities = capabilities,
                Collectors = [new CollectorIdentity("fixture", "1")]
            },
            Content = new SnapshotContent
            {
                Domains = [domain],
                CertificateServices = services
            },
            Coverage = coverage,
            Observations = facts
        };
    }

    private static void AddAclModel(
        ICollection<AdSecurityDescriptor> descriptors,
        ICollection<AdAce> aces,
        AdObjectId targetId,
        AdDaclState state,
        uint accessMask,
        string? objectType)
    {
        descriptors.Add(new AdSecurityDescriptor { TargetObjectId = targetId, DaclState = state });
        if (state != AdDaclState.Present) return;
        aces.Add(new AdAce
        {
            TargetObjectId = targetId,
            AceIndex = 0,
            TrusteeSid = AuthenticatedUsers,
            AccessType = AdAccessControlType.Allow,
            AccessMask = accessMask,
            AceFlags = 0,
            ObjectType = objectType is null ? null : Guid.Parse(objectType),
            IsInherited = false
        });
    }

    private static void AddAclFacts(
        ICollection<ObservedFact> facts,
        AdDirectoryObject target,
        AdDaclState state,
        uint accessMask,
        string? objectType)
    {
        var subject = target is CertificateAuthority ? $"adcs-ca:{target.Id}" : $"adcs-template:{target.Id}";
        Add(facts, CollectionCapabilities.AdcsAcls, subject, "securityDescriptor.daclState", state.ToString(), FactValueKind.Text);
        Add(facts, CollectionCapabilities.AdcsAcls, subject, "securityDescriptor.parseComplete", "true", FactValueKind.Boolean);
        AddInteger(facts, CollectionCapabilities.AdcsAcls, subject, "securityDescriptor.aceCount", state == AdDaclState.Present ? 1 : 0);
        if (state != AdDaclState.Present) return;

        const string prefix = "securityDescriptor.dacl.ace[0]";
        Add(facts, CollectionCapabilities.AdcsAcls, subject, prefix + ".accessType", "Allow", FactValueKind.Text);
        AddInteger(facts, CollectionCapabilities.AdcsAcls, subject, prefix + ".aceFlags", 0);
        AddInteger(facts, CollectionCapabilities.AdcsAcls, subject, prefix + ".accessMask", accessMask);
        Add(facts, CollectionCapabilities.AdcsAcls, subject, prefix + ".trusteeSid", AuthenticatedUsers, FactValueKind.Sid);
        Add(facts, CollectionCapabilities.AdcsAcls, subject, prefix + ".objectTypePresent", objectType is null ? "false" : "true", FactValueKind.Boolean);
        if (objectType is not null)
            Add(facts, CollectionCapabilities.AdcsAcls, subject, prefix + ".objectType", objectType, FactValueKind.Guid);
    }

    private static void AddInteger(
        ICollection<ObservedFact> facts,
        string capability,
        string subject,
        string path,
        long value) =>
        Add(facts, capability, subject, path, value.ToString(CultureInfo.InvariantCulture), FactValueKind.Integer);

    private static void Add(
        ICollection<ObservedFact> facts,
        string capability,
        string subject,
        string path,
        string value,
        FactValueKind kind)
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

    private sealed record FixtureOptions
    {
        public bool Published { get; init; } = true;
        public int CertificateNameFlags { get; init; } = 1;
        public int EnrollmentFlags { get; init; }
        public int RequiredAuthorizedSignatures { get; init; }
        public string? PurposeOid { get; init; } = ClientAuthentication;
        public bool IncludePurposeEvidence { get; init; } = true;
        public AdDaclState TemplateDaclState { get; init; } = AdDaclState.Present;
        public uint TemplateAccessMask { get; init; } = 0x00000100;
        public string? TemplateAceObjectType { get; init; } = EnrollGuid;
        public AdDaclState CaDaclState { get; init; } = AdDaclState.Empty;
        public uint CaAccessMask { get; init; }
        public string? CaAceObjectType { get; init; }
    }
}
