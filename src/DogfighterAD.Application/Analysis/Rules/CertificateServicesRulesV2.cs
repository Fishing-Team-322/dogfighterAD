using DogfighterAD.Application.Contracts;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis.Rules;

internal static class CertificateServicesRuleCatalogV2
{
    private const string CertificateTemplateReference =
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/";

    public static IReadOnlyList<IRule> Create() =>
    [
        new AdcsEsc1CandidateRuleV2(Metadata(
            "ADCS.TEMPLATE.ESC1_CANDIDATE",
            "Published certificate template has an ESC1-like directory posture",
            FindingSeverity.High,
            TemplateRequirements(includePublication: true, includeAcl: true),
            ["template.publishedOnCa", "template.certificateNameFlags", "template.enrollmentFlags", "template.requiredAuthorizedSignatures", "template.eku or template.applicationPolicy", "securityDescriptor.dacl"],
            "A published template that combines low-privilege enrollment, an authentication-capable purpose, enrollee-supplied subject naming, and no directory-observed approval/signature gate can contribute to certificate-based privilege escalation. This is directory-derived evidence only and does not prove CA runtime policy or exploitability.")),

        new AdcsDangerousDirectoryAclRule(Metadata(
            "ADCS.TEMPLATE.DANGEROUS_ACL",
            "Low-privilege principal can potentially control a certificate template",
            FindingSeverity.High,
            TemplateRequirements(includePublication: false, includeAcl: true),
            ["securityDescriptor.parseComplete", "securityDescriptor.aceCount", "securityDescriptor.dacl.ace[*]"],
            "GenericAll, GenericWrite, WriteDacl, WriteOwner, or unrestricted WriteProperty on a certificate template can permit security-sensitive template changes. The rule intentionally reports a potential control path rather than claiming complete Windows effective access."),
            AdcsAclTarget.Template),

        new AdcsBroadEnrollmentRule(Metadata(
            "ADCS.TEMPLATE.BROAD_ENROLLMENT",
            "Low-privilege principal has an enrollment-capable grant on a certificate template",
            FindingSeverity.Medium,
            TemplateRequirements(includePublication: false, includeAcl: true),
            ["securityDescriptor.parseComplete", "securityDescriptor.aceCount", "Certificate-Enrollment or Certificate-AutoEnrollment"],
            "Broad enrollment or auto-enrollment rights increase the population that can request certificates from a template. This rule does not by itself claim privilege escalation.")),

        new AdcsTemplatePostureRule(Metadata(
            "ADCS.TEMPLATE.AUTHENTICATION_CAPABLE",
            "Certificate template has an authentication-capable purpose",
            FindingSeverity.Informational,
            [new(CollectionCapabilities.AdcsTemplates)],
            ["template.eku or template.applicationPolicy"],
            "Authentication-capable EKUs or application policies make the template relevant to authentication-path analysis, but are not independently a vulnerability."),
            AdcsTemplatePosture.AuthenticationCapable),

        new AdcsTemplatePostureRule(Metadata(
            "ADCS.TEMPLATE.ENROLLEE_SUPPLIES_SUBJECT",
            "Certificate template allows the enrollee to supply subject information",
            FindingSeverity.Low,
            [new(CollectionCapabilities.AdcsTemplates)],
            ["template.certificateNameFlags"],
            "Enrollee-supplied subject information can become security-sensitive when combined with authentication-capable issuance and broad enrollment."),
            AdcsTemplatePosture.EnrolleeSuppliesSubject),

        new AdcsTemplatePostureRule(Metadata(
            "ADCS.TEMPLATE.NO_APPROVAL",
            "Certificate template does not require manager approval",
            FindingSeverity.Informational,
            [new(CollectionCapabilities.AdcsTemplates)],
            ["template.enrollmentFlags"],
            "The absence of the pending/manager-approval flag removes one issuance gate. This is a posture fact, not a vulnerability by itself."),
            AdcsTemplatePosture.NoApproval),

        new AdcsTemplatePostureRule(Metadata(
            "ADCS.TEMPLATE.NO_AUTHORIZED_SIGNATURE",
            "Certificate template requires no authorized signatures",
            FindingSeverity.Informational,
            [new(CollectionCapabilities.AdcsTemplates)],
            ["template.requiredAuthorizedSignatures"],
            "A zero authorized-signature requirement removes one issuance gate. This is a posture fact, not a vulnerability by itself."),
            AdcsTemplatePosture.NoAuthorizedSignature),

        new AdcsDangerousDirectoryAclRule(Metadata(
            "ADCS.CA.DANGEROUS_DIRECTORY_ACL",
            "Low-privilege principal can potentially control an Enterprise CA directory object",
            FindingSeverity.High,
            AuthorityRequirements(includeAcl: true),
            ["securityDescriptor.parseComplete", "securityDescriptor.aceCount", "securityDescriptor.dacl.ace[*]"],
            "Broad write, ownership, or DACL-control rights on the pKIEnrollmentService directory object deserve review. This rule covers the directory object only; CA registry, service, RPC, and runtime permissions are outside this capability."),
            AdcsAclTarget.Authority)
    ];

    private static RuleMetadata Metadata(
        string id,
        string title,
        FindingSeverity severity,
        IReadOnlyList<CapabilityRequirement> requirements,
        IReadOnlyList<string> fields,
        string risk) => new()
    {
        Id = id,
        Version = "1.0.0",
        Title = title,
        Category = "Certificate Services",
        DefaultSeverity = severity,
        RequiredCapabilities = requirements,
        RequiredFields = fields,
        Risk = risk,
        Remediation = "Review the named AD CS object and its evidence. Apply the smallest approved directory change that removes unnecessary exposure, preserve required PKI administration, and validate the issuing CA separately when runtime behavior matters.",
        References =
        [
            new("Microsoft", "Certificate template protocol documentation", CertificateTemplateReference),
            new("Microsoft", "Active Directory access control", RuleSources.Acl),
            new("Microsoft", "Extended rights", RuleSources.ExtendedRights)
        ]
    };

    private static IReadOnlyList<CapabilityRequirement> TemplateRequirements(bool includePublication, bool includeAcl)
    {
        var result = new List<CapabilityRequirement> { new(CollectionCapabilities.AdcsTemplates) };
        if (includePublication) result.Add(new(CollectionCapabilities.AdcsPublication));
        if (includeAcl) AddPrincipalAndAclRequirements(result);
        return result;
    }

    private static IReadOnlyList<CapabilityRequirement> AuthorityRequirements(bool includeAcl)
    {
        var result = new List<CapabilityRequirement> { new(CollectionCapabilities.AdcsAuthorities) };
        if (includeAcl) AddPrincipalAndAclRequirements(result);
        return result;
    }

    private static void AddPrincipalAndAclRequirements(ICollection<CapabilityRequirement> result)
    {
        result.Add(new(CollectionCapabilities.AdcsAcls));
        result.Add(new(CollectionCapabilities.DirectoryUsers, 2));
        result.Add(new(CollectionCapabilities.DirectoryGroups));
        result.Add(new(CollectionCapabilities.DirectoryMemberships, 3));
        result.Add(new(CollectionCapabilities.DirectoryDomains));
    }
}

internal static class CertificateServicesProtocol
{
    public const uint ControlAccess = 0x00000100;
    public const uint WriteProperty = 0x00000020;
    public const uint WriteDacl = 0x00040000;
    public const uint WriteOwner = 0x00080000;
    public const uint GenericWrite = 0x40000000;
    public const uint GenericAll = 0x10000000;
    public const byte InheritOnlyAce = 0x08;
    public const int EnrolleeSuppliesSubject = 0x00000001;
    public const int PendAllRequests = 0x00000002;

    public static readonly Guid EnrollExtendedRight =
        Guid.Parse("0e10c968-78fb-11d2-90d4-00c04f79dc55");

    public static readonly Guid AutoEnrollExtendedRight =
        Guid.Parse("a05b8cc2-17bc-4802-a710-e7c15ab866a2");

    public static readonly IReadOnlySet<string> AuthenticationPurposeOids =
        new HashSet<string>(StringComparer.Ordinal)
        {
            "1.3.6.1.5.5.7.3.2",
            "1.3.6.1.4.1.311.20.2.2",
            "1.3.6.1.5.2.3.4",
            "2.5.29.37.0"
        };
}

internal enum AdcsTemplatePosture
{
    AuthenticationCapable,
    EnrolleeSuppliesSubject,
    NoApproval,
    NoAuthorizedSignature
}

internal sealed class AdcsTemplatePostureRule : RuleBase
{
    private readonly AdcsTemplatePosture posture;

    public AdcsTemplatePostureRule(RuleMetadata metadata, AdcsTemplatePosture posture) : base(metadata) =>
        this.posture = posture;

    public override IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context)
    {
        var services = snapshot.Content.CertificateServices;
        if (services is null)
        {
            yield return MissingPayload(context, CollectionCapabilities.AdcsTemplates);
            yield break;
        }

        foreach (var template in services.Templates.OrderBy(item => item.Id.Value))
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var check = Check(context, template);
            bool match;
            string presentMessage;
            string absentMessage;

            switch (posture)
            {
                case AdcsTemplatePosture.AuthenticationCapable:
                    match = AdcsTemplateEvidence.AuthenticationCapable(context, check, template);
                    presentMessage = "The collected EKU/application-policy evidence includes an authentication-capable purpose.";
                    absentMessage = "The collected EKU/application-policy evidence does not include an authentication-capable purpose used by this rule.";
                    break;
                case AdcsTemplatePosture.EnrolleeSuppliesSubject:
                {
                    var flags = AdcsTemplateEvidence.ReadScalar(check, template.CertificateNameFlags, "template.certificateNameFlags");
                    match = check.Known && (flags & CertificateServicesProtocol.EnrolleeSuppliesSubject) != 0;
                    presentMessage = "The enrollee-supplies-subject flag is set in the collected certificate-name flags.";
                    absentMessage = "The enrollee-supplies-subject flag is not set in the collected certificate-name flags.";
                    break;
                }
                case AdcsTemplatePosture.NoApproval:
                {
                    var flags = AdcsTemplateEvidence.ReadScalar(check, template.EnrollmentFlags, "template.enrollmentFlags");
                    match = check.Known && (flags & CertificateServicesProtocol.PendAllRequests) == 0;
                    presentMessage = "The collected enrollment flags do not require pending/manager approval.";
                    absentMessage = "The collected enrollment flags require pending/manager approval.";
                    break;
                }
                case AdcsTemplatePosture.NoAuthorizedSignature:
                {
                    var signatures = AdcsTemplateEvidence.ReadScalar(check, template.RequiredAuthorizedSignatures, "template.requiredAuthorizedSignatures", nonNegative: true);
                    match = check.Known && signatures == 0;
                    presentMessage = "The collected template requires zero authorized signatures.";
                    absentMessage = "The collected template requires one or more authorized signatures.";
                    break;
                }
                default:
                    throw new InvalidOperationException("Unknown AD CS template posture rule.");
            }

            yield return check.Known
                ? check.Verdict(match, match ? presentMessage : absentMessage, checkKey: posture.ToString())
                : check.Unknown();
        }
    }

    private RuleEvaluation MissingPayload(RuleContext context, string capability)
    {
        var check = Check(context, new ObjectReference("certificate-services", "adcs:snapshot"));
        check.Require(false, capability, "certificateServices", "field.certificate-services-payload-unavailable");
        return check.Unknown();
    }
}

internal sealed class AdcsBroadEnrollmentRule : RuleBase
{
    public AdcsBroadEnrollmentRule(RuleMetadata metadata) : base(metadata) { }

    public override IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context)
    {
        var services = snapshot.Content.CertificateServices;
        if (services is null)
        {
            yield return MissingPayload(context, CollectionCapabilities.AdcsTemplates);
            yield break;
        }

        var lowPrivilege = new AdcsLowPrivilegeIndex(snapshot, context.Facts, context.CancellationToken);
        var access = new CertificateServicesAccessAnalyzer(services);
        foreach (var template in services.Templates.OrderBy(item => item.Id.Value))
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var check = Check(context, template);
            var rights = access.Read(template, check, lowPrivilege);
            if (!check.Known)
            {
                yield return check.Unknown();
                continue;
            }

            var match = rights.Enroll || rights.AutoEnroll;
            var detail = rights.Enroll && rights.AutoEnroll
                ? "Enrollment and AutoEnrollment"
                : rights.Enroll ? "Enrollment" : "AutoEnrollment";
            yield return check.Verdict(
                match,
                match
                    ? $"A low-privilege trustee has a potential {detail} path from the collected DACL. Deny precedence and complete Windows token construction were not inferred."
                    : "No low-privilege Enrollment or AutoEnrollment grant was proven from the fully parsed DACL.",
                potential: match,
                checkKey: match ? "broad-enrollment" : "default");
        }
    }

    private RuleEvaluation MissingPayload(RuleContext context, string capability)
    {
        var check = Check(context, new ObjectReference("certificate-services", "adcs:snapshot"));
        check.Require(false, capability, "certificateServices", "field.certificate-services-payload-unavailable");
        return check.Unknown();
    }
}

internal enum AdcsAclTarget
{
    Template,
    Authority
}

internal sealed class AdcsDangerousDirectoryAclRule : RuleBase
{
    private readonly AdcsAclTarget target;

    public AdcsDangerousDirectoryAclRule(RuleMetadata metadata, AdcsAclTarget target) : base(metadata) =>
        this.target = target;

    public override IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context)
    {
        var services = snapshot.Content.CertificateServices;
        if (services is null)
        {
            var capability = target == AdcsAclTarget.Template
                ? CollectionCapabilities.AdcsTemplates
                : CollectionCapabilities.AdcsAuthorities;
            var missing = Check(context, new ObjectReference("certificate-services", "adcs:snapshot"));
            missing.Require(false, capability, "certificateServices", "field.certificate-services-payload-unavailable");
            yield return missing.Unknown();
            yield break;
        }

        var lowPrivilege = new AdcsLowPrivilegeIndex(snapshot, context.Facts, context.CancellationToken);
        var access = new CertificateServicesAccessAnalyzer(services);
        var subjects = target == AdcsAclTarget.Template
            ? services.Templates.Cast<AdDirectoryObject>()
            : services.Authorities.Cast<AdDirectoryObject>();

        foreach (var subject in subjects.OrderBy(item => item.Id.Value))
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var check = Check(context, subject);
            var rights = access.Read(subject, check, lowPrivilege);
            if (!check.Known)
            {
                yield return check.Unknown();
                continue;
            }

            var match = rights.DangerousControl;
            yield return check.Verdict(
                match,
                match
                    ? "A low-privilege trustee has a potential GenericAll, GenericWrite, WriteDacl, WriteOwner, or unrestricted WriteProperty control path on this AD CS directory object. Deny precedence and complete Windows effective access were not inferred."
                    : "No dangerous low-privilege directory-control grant was proven from the fully parsed DACL.",
                potential: match,
                checkKey: match ? "dangerous-directory-control" : "default");
        }
    }
}

internal sealed class AdcsEsc1CandidateRuleV2 : RuleBase
{
    public AdcsEsc1CandidateRuleV2(RuleMetadata metadata) : base(metadata) { }

    public override IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context)
    {
        var services = snapshot.Content.CertificateServices;
        if (services is null)
        {
            var missing = Check(context, new ObjectReference("certificate-services", "adcs:snapshot"));
            missing.Require(false, CollectionCapabilities.AdcsTemplates, "certificateServices", "field.certificate-services-payload-unavailable");
            yield return missing.Unknown();
            yield break;
        }

        var lowPrivilege = new AdcsLowPrivilegeIndex(snapshot, context.Facts, context.CancellationToken);
        var access = new CertificateServicesAccessAnalyzer(services);
        var publications = services.Publications
            .GroupBy(item => item.TemplateId)
            .ToDictionary(group => group.Key, group => group.OrderBy(item => item.AuthorityId.Value).ToArray());

        foreach (var template in services.Templates.OrderBy(item => item.Id.Value))
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var check = Check(context, template);

            if (!publications.TryGetValue(template.Id, out var publishedOn) || publishedOn.Length == 0)
            {
                yield return check.NotApplicable("The complete normalized publication inventory contains no publishing Enterprise CA for this template.");
                continue;
            }

            var observedPublication = check.Values(CollectionCapabilities.AdcsPublication, "template.publishedOnCa", FactValueKind.Guid);
            var typedPublication = publishedOn.Select(item => item.AuthorityId.ToString())
                .OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray();
            check.Require(
                observedPublication.OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
                    .SequenceEqual(typedPublication, StringComparer.OrdinalIgnoreCase),
                CollectionCapabilities.AdcsPublication,
                "template.publishedOnCa",
                "evidence.typed-content-conflict");

            var nameFlags = AdcsTemplateEvidence.ReadScalar(check, template.CertificateNameFlags, "template.certificateNameFlags");
            var enrollmentFlags = AdcsTemplateEvidence.ReadScalar(check, template.EnrollmentFlags, "template.enrollmentFlags");
            var signatures = AdcsTemplateEvidence.ReadScalar(check, template.RequiredAuthorizedSignatures, "template.requiredAuthorizedSignatures", nonNegative: true);
            var authenticationCapable = AdcsTemplateEvidence.AuthenticationCapable(context, check, template);
            var rights = access.Read(template, check, lowPrivilege);

            if (!check.Known)
            {
                yield return check.Unknown();
                continue;
            }

            var suppliesSubject = (nameFlags & CertificateServicesProtocol.EnrolleeSuppliesSubject) != 0;
            var noApproval = (enrollmentFlags & CertificateServicesProtocol.PendAllRequests) == 0;
            var noAuthorizedSignature = signatures == 0;
            var match = rights.Enroll && authenticationCapable && suppliesSubject && noApproval && noAuthorizedSignature;

            yield return check.Verdict(
                match,
                match
                    ? "ESC1_CANDIDATE: directory evidence proves publication, a low-privilege Enrollment path, an authentication-capable purpose, enrollee-supplied subject naming, no pending/manager-approval flag, and zero required authorized signatures. This remains a directory-derived candidate: CA registry/RPC policy, EDITF_ATTRIBUTESUBJECTALTNAME2, web enrollment, EPA/NTLM behavior, issuance behavior, deny precedence, and exploitability were not verified."
                    : "The collected directory evidence does not satisfy every ESC1 candidate prerequisite.",
                potential: match,
                checkKey: match ? "esc1-candidate" : "default");
        }
    }
}

internal static class AdcsTemplateEvidence
{
    public static long ReadScalar(RuleCheck check, int? typedValue, string path, bool nonNegative = false)
    {
        var observed = check.Integer(CollectionCapabilities.AdcsTemplates, path);
        check.Require(
            observed is >= int.MinValue and <= int.MaxValue &&
            typedValue.HasValue &&
            typedValue.Value == (int)observed &&
            (!nonNegative || observed >= 0),
            CollectionCapabilities.AdcsTemplates,
            path,
            "evidence.typed-content-conflict");
        return observed;
    }

    public static bool AuthenticationCapable(RuleContext context, RuleCheck check, CertificateTemplate template)
    {
        const string capability = CollectionCapabilities.AdcsTemplates;
        var subject = $"adcs-template:{template.Id}";
        var observedAny = false;
        var observed = new HashSet<string>(StringComparer.Ordinal);

        if (context.Facts.HasObservation(capability, subject, "template.eku"))
        {
            observedAny = true;
            foreach (var value in check.Values(capability, "template.eku")) observed.Add(value);
        }
        if (context.Facts.HasObservation(capability, subject, "template.applicationPolicy"))
        {
            observedAny = true;
            foreach (var value in check.Values(capability, "template.applicationPolicy")) observed.Add(value);
        }

        if (!observedAny)
        {
            check.Require(false, capability, "template.eku/applicationPolicy", "field.authentication-purpose-unavailable");
            return false;
        }

        var typed = template.ExtendedKeyUsages.Concat(template.ApplicationPolicies)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();
        check.Require(
            observed.OrderBy(value => value, StringComparer.Ordinal).SequenceEqual(typed, StringComparer.Ordinal),
            capability,
            "template.eku/applicationPolicy",
            "evidence.typed-content-conflict");
        return check.Known && observed.Any(CertificateServicesProtocol.AuthenticationPurposeOids.Contains);
    }
}

internal sealed record AdcsAccessResult(
    bool Enroll,
    bool AutoEnroll,
    bool GenericAll,
    bool GenericWrite,
    bool WriteDacl,
    bool WriteOwner,
    bool WriteProperty)
{
    public bool DangerousControl => GenericAll || GenericWrite || WriteDacl || WriteOwner || WriteProperty;
}

internal sealed class CertificateServicesAccessAnalyzer
{
    private readonly IReadOnlyDictionary<AdObjectId, AdSecurityDescriptor> descriptors;
    private readonly IReadOnlyDictionary<AdObjectId, AdAce[]> aces;

    public CertificateServicesAccessAnalyzer(CertificateServicesSnapshot services)
    {
        descriptors = services.SecurityDescriptors.ToDictionary(item => item.TargetObjectId);
        aces = services.Aces
            .GroupBy(item => item.TargetObjectId)
            .ToDictionary(group => group.Key, group => group.OrderBy(item => item.AceIndex).ToArray());
    }

    public AdcsAccessResult Read(AdDirectoryObject target, RuleCheck check, AdcsLowPrivilegeIndex lowPrivilege)
    {
        var targetAces = aces.TryGetValue(target.Id, out var found) ? found : [];
        if (!descriptors.TryGetValue(target.Id, out var descriptor))
        {
            check.Require(false, CollectionCapabilities.AdcsAcls, "securityDescriptor", "descriptor.unavailable");
            return Empty();
        }

        var state = check.Text(CollectionCapabilities.AdcsAcls, "securityDescriptor.daclState");
        var complete = check.Boolean(CollectionCapabilities.AdcsAcls, "securityDescriptor.parseComplete");
        var count = check.Integer(CollectionCapabilities.AdcsAcls, "securityDescriptor.aceCount");
        check.Require(
            Enum.TryParse<AdDaclState>(state, out var parsedState) && parsedState == descriptor.DaclState,
            CollectionCapabilities.AdcsAcls,
            "securityDescriptor.daclState",
            "evidence.typed-content-conflict");
        check.Require(
            complete && count >= 0 && count == targetAces.Length,
            CollectionCapabilities.AdcsAcls,
            "securityDescriptor.parseComplete/aceCount",
            "descriptor.incomplete-or-inconsistent");
        if (!check.Known) return Empty();

        if (descriptor.DaclState is AdDaclState.Null or AdDaclState.NotPresent)
            return new(true, true, true, true, true, true, true);
        if (descriptor.DaclState == AdDaclState.Empty)
            return Empty();

        var enroll = false;
        var autoEnroll = false;
        var genericAll = false;
        var genericWrite = false;
        var writeDacl = false;
        var writeOwner = false;
        var writeProperty = false;
        var unresolvedRelevantTrustee = false;

        foreach (var ace in targetAces)
        {
            if (!TryReadAce(check, ace, out var accessType, out var flags, out var mask, out var trustee, out var objectType))
                continue;
            if (accessType != AdAccessControlType.Allow || (flags & CertificateServicesProtocol.InheritOnlyAce) != 0)
                continue;

            var aceGenericAll = (mask & CertificateServicesProtocol.GenericAll) != 0;
            var aceGenericWrite = (mask & CertificateServicesProtocol.GenericWrite) != 0;
            var aceWriteDacl = (mask & CertificateServicesProtocol.WriteDacl) != 0;
            var aceWriteOwner = (mask & CertificateServicesProtocol.WriteOwner) != 0;
            var aceWriteProperty = (mask & CertificateServicesProtocol.WriteProperty) != 0 && !objectType.HasValue;
            var controlAccess = (mask & CertificateServicesProtocol.ControlAccess) != 0;
            var aceEnroll = aceGenericAll || (controlAccess &&
                (!objectType.HasValue || objectType.Value == CertificateServicesProtocol.EnrollExtendedRight));
            var aceAutoEnroll = aceGenericAll || (controlAccess &&
                (!objectType.HasValue || objectType.Value == CertificateServicesProtocol.AutoEnrollExtendedRight));
            var relevant = aceEnroll || aceAutoEnroll || aceGenericAll || aceGenericWrite || aceWriteDacl || aceWriteOwner || aceWriteProperty;
            if (!relevant) continue;

            if (!lowPrivilege.TryProveLowPrivilegeTrustee(trustee, out var proof))
            {
                unresolvedRelevantTrustee = true;
                continue;
            }

            check.AddEvidence(proof);
            enroll |= aceEnroll;
            autoEnroll |= aceAutoEnroll;
            genericAll |= aceGenericAll;
            genericWrite |= aceGenericWrite;
            writeDacl |= aceWriteDacl;
            writeOwner |= aceWriteOwner;
            writeProperty |= aceWriteProperty;
        }

        var provenRelevant = enroll || autoEnroll || genericAll || genericWrite || writeDacl || writeOwner || writeProperty;
        if (!provenRelevant && unresolvedRelevantTrustee && !lowPrivilege.ScopeComplete)
        {
            check.Require(
                false,
                CollectionCapabilities.DirectoryMemberships,
                "adcs.effective-rights-trustee",
                "membership.scope-incomplete");
        }

        return new(enroll, autoEnroll, genericAll, genericWrite, writeDacl, writeOwner, writeProperty);
    }

    private static bool TryReadAce(
        RuleCheck check,
        AdAce ace,
        out AdAccessControlType accessType,
        out byte flags,
        out uint mask,
        out string trustee,
        out Guid? objectType)
    {
        const string capability = CollectionCapabilities.AdcsAcls;
        var prefix = $"securityDescriptor.dacl.ace[{ace.AceIndex}]";
        var accessText = check.Text(capability, prefix + ".accessType");
        var flagsValue = check.Integer(capability, prefix + ".aceFlags");
        var maskValue = check.Integer(capability, prefix + ".accessMask");
        trustee = check.Text(capability, prefix + ".trusteeSid", FactValueKind.Sid);
        var objectTypePresent = check.Boolean(capability, prefix + ".objectTypePresent");
        objectType = null;
        if (objectTypePresent)
        {
            var value = check.Text(capability, prefix + ".objectType", FactValueKind.Guid);
            if (Guid.TryParse(value, out var parsed)) objectType = parsed;
            else check.Require(false, capability, prefix + ".objectType", "field.invalid-guid");
        }

        var accessParsed = Enum.TryParse(accessText, out accessType);
        check.Require(
            accessParsed &&
            flagsValue is >= byte.MinValue and <= byte.MaxValue &&
            maskValue is >= uint.MinValue and <= uint.MaxValue,
            capability,
            prefix,
            "field.invalid-ace");
        flags = flagsValue is >= byte.MinValue and <= byte.MaxValue ? (byte)flagsValue : (byte)0;
        mask = maskValue is >= uint.MinValue and <= uint.MaxValue ? (uint)maskValue : 0;
        check.Require(
            accessParsed &&
            ace.AccessType == accessType &&
            ace.AceFlags == flags &&
            ace.AccessMask == mask &&
            StringComparer.OrdinalIgnoreCase.Equals(ace.TrusteeSid, trustee) &&
            ace.ObjectType.HasValue == objectTypePresent &&
            (!objectTypePresent || ace.ObjectType == objectType),
            capability,
            prefix,
            "evidence.typed-content-conflict");
        return check.Known;
    }

    private static AdcsAccessResult Empty() => new(false, false, false, false, false, false, false);
}
