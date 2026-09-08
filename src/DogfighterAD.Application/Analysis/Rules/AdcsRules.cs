using DogfighterAD.Application.Contracts;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis.Rules;

internal static class AdcsRuleCatalog
{
    private const string ProtocolReference =
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/";

    public static IReadOnlyList<IRule> Create() =>
    [
        new AdcsEsc1CandidateRule(new RuleMetadata
        {
            Id = "AD.ADCS.ESC1_CANDIDATE",
            Version = "1.0.0",
            Title = "Published certificate template has an ESC1-like directory posture",
            Category = "Certificate Services",
            DefaultSeverity = FindingSeverity.High,
            RequiredCapabilities = CommonRequirements(includePublication: true),
            RequiredFields =
            [
                "template.certificateNameFlags",
                "template.enrollmentFlags",
                "template.requiredAuthorizedSignatures",
                "template.eku or template.applicationPolicy",
                "template.publishedOnCa",
                "securityDescriptor.parseComplete/aceCount/dacl"
            ],
            Risk = "A published template with enrollee-supplied subject names, an authentication-capable purpose, no directory-observed approval/signature gate, and low-privilege enrollment rights can contribute to certificate-based privilege escalation. Directory posture alone does not prove complete ESC1 exploitability or CA runtime behavior.",
            Remediation = "Review the template and issuing CA together. Remove unnecessary enrollee-supplied subject naming, authentication-capable purposes, broad enrollment grants, or add an approved issuance/signature control as appropriate. Validate effective permissions and CA runtime policy before and after changes.",
            References = [new("Microsoft", "Certificate template protocol documentation", ProtocolReference)]
        }),
        new AdcsDangerousTemplateAclRule(new RuleMetadata
        {
            Id = "AD.ADCS.TEMPLATE_DANGEROUS_ACL",
            Version = "1.0.0",
            Title = "Low-privilege principal can potentially modify a certificate template",
            Category = "Certificate Services",
            DefaultSeverity = FindingSeverity.High,
            RequiredCapabilities = CommonRequirements(includePublication: false),
            RequiredFields = ["securityDescriptor.parseComplete/aceCount/dacl"],
            Risk = "Write or ownership-control rights on a certificate template can permit a low-privilege principal to change security-sensitive template configuration. The rule reports a potential control path and does not claim full Windows effective access.",
            Remediation = "Review the template DACL and effective permissions. Remove unnecessary broad write, ownership, or DACL-control grants while preserving required PKI administration workflows.",
            References = [new("Microsoft", "Active Directory access control", RuleSources.Acl)]
        })
    ];

    private static IReadOnlyList<CapabilityRequirement> CommonRequirements(bool includePublication)
    {
        var result = new List<CapabilityRequirement>
        {
            new(CollectionCapabilities.AdcsTemplates),
            new(CollectionCapabilities.AdcsAcls),
            new(CollectionCapabilities.DirectoryUsers, 2),
            new(CollectionCapabilities.DirectoryGroups),
            new(CollectionCapabilities.DirectoryMemberships, 3),
            new(CollectionCapabilities.DirectoryDomains)
        };
        if (includePublication) result.Insert(1, new(CollectionCapabilities.AdcsPublication));
        return result;
    }
}

internal static class AdcsProtocolConstants
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

    public static readonly IReadOnlySet<string> AuthenticationPurposeOids =
        new HashSet<string>(StringComparer.Ordinal)
        {
            "1.3.6.1.5.5.7.3.2",       // Client Authentication
            "1.3.6.1.4.1.311.20.2.2",  // Smart Card Logon
            "1.3.6.1.5.2.3.4",         // PKINIT Client Authentication
            "2.5.29.37.0"               // Any Purpose
        };
}

internal sealed class AdcsEsc1CandidateRule : RuleBase
{
    public AdcsEsc1CandidateRule(RuleMetadata metadata) : base(metadata) { }

    public override IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context)
    {
        var services = snapshot.Content.CertificateServices;
        if (services is null)
        {
            yield return MissingPayload(context);
            yield break;
        }

        var lowPrivilege = new AdcsLowPrivilegeIndex(snapshot, context.Facts, context.CancellationToken);
        var publications = services.Publications.GroupBy(item => item.TemplateId)
            .ToDictionary(group => group.Key, group => group.OrderBy(item => item.AuthorityId.Value).ToArray());
        var acl = new AdcsAclInventory(services);

        foreach (var template in services.Templates.OrderBy(item => item.Id.Value))
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var check = Check(context, template);
            if (!publications.TryGetValue(template.Id, out var publishedOn) || publishedOn.Length == 0)
            {
                yield return check.NotApplicable("The template is not published by any collected Enterprise CA.");
                continue;
            }

            var nameFlags = check.Integer(CollectionCapabilities.AdcsTemplates, "template.certificateNameFlags");
            var enrollmentFlags = check.Integer(CollectionCapabilities.AdcsTemplates, "template.enrollmentFlags");
            var signatures = check.Integer(CollectionCapabilities.AdcsTemplates, "template.requiredAuthorizedSignatures");
            RequireTemplateScalar(check, template.CertificateNameFlags, nameFlags, "template.certificateNameFlags");
            RequireTemplateScalar(check, template.EnrollmentFlags, enrollmentFlags, "template.enrollmentFlags");
            RequireTemplateScalar(check, template.RequiredAuthorizedSignatures, signatures, "template.requiredAuthorizedSignatures", nonNegative: true);
            if (!check.Known) { yield return check.Unknown(); continue; }

            if ((nameFlags & AdcsProtocolConstants.EnrolleeSuppliesSubject) == 0)
            {
                yield return check.Verdict(false, "The template does not set the enrollee-supplies-subject flag.");
                continue;
            }
            if ((enrollmentFlags & AdcsProtocolConstants.PendAllRequests) != 0)
            {
                yield return check.Verdict(false, "The collected enrollment flags require pending/manager approval.");
                continue;
            }
            if (signatures != 0)
            {
                yield return check.Verdict(false, "The template requires one or more authorized signatures.");
                continue;
            }

            if (!ReadAuthenticationPurpose(context, check, template))
            {
                yield return check.Known
                    ? check.Verdict(false, "The collected EKU/application-policy values do not include an authentication-capable purpose used by this candidate rule.")
                    : check.Unknown();
                continue;
            }

            var publishedFacts = check.Values(CollectionCapabilities.AdcsPublication, "template.publishedOnCa", FactValueKind.Guid);
            var typedPublished = publishedOn.Select(item => item.AuthorityId.ToString())
                .OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray();
            check.Require(publishedFacts.OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
                    .SequenceEqual(typedPublished, StringComparer.OrdinalIgnoreCase),
                CollectionCapabilities.AdcsPublication, "template.publishedOnCa", "evidence.typed-content-conflict");
            if (!check.Known) { yield return check.Unknown(); continue; }

            var enrollment = acl.HasLowPrivilegeEnrollGrant(template, check, lowPrivilege);
            if (!check.Known) { yield return check.Unknown(); continue; }
            if (!enrollment)
            {
                yield return check.Verdict(false, "No low-privilege enrollment grant was proven from the fully parsed template DACL.");
                continue;
            }

            yield return check.Verdict(
                true,
                "ESC1_CANDIDATE: directory evidence shows a published template with enrollee-supplied subject naming, an authentication-capable purpose, no collected pending/signature gate, and a low-privilege enrollment path. This is a candidate only: CA runtime policy, deny precedence, complete token construction, issuance behavior, and exploitability were not proven.",
                potential: true,
                checkKey: "esc1-candidate");
        }
    }

    private RuleEvaluation MissingPayload(RuleContext context)
    {
        var check = Check(context, new ObjectReference("certificate-services", "adcs:snapshot"));
        check.Require(false, CollectionCapabilities.AdcsTemplates, "certificateServices", "field.certificate-services-payload-unavailable");
        return check.Unknown();
    }

    private static void RequireTemplateScalar(RuleCheck check, int? typed, long observed, string path, bool nonNegative = false)
    {
        check.Require(observed is >= int.MinValue and <= int.MaxValue && typed.HasValue && typed.Value == (int)observed && (!nonNegative || observed >= 0),
            CollectionCapabilities.AdcsTemplates, path, "evidence.typed-content-conflict");
    }

    private static bool ReadAuthenticationPurpose(RuleContext context, RuleCheck check, CertificateTemplate template)
    {
        const string capability = CollectionCapabilities.AdcsTemplates;
        var subject = $"adcs-template:{template.Id}";
        var observedAny = false;
        var values = new HashSet<string>(StringComparer.Ordinal);
        if (context.Facts.HasObservation(capability, subject, "template.eku"))
        {
            observedAny = true;
            foreach (var value in check.Values(capability, "template.eku")) values.Add(value);
        }
        if (context.Facts.HasObservation(capability, subject, "template.applicationPolicy"))
        {
            observedAny = true;
            foreach (var value in check.Values(capability, "template.applicationPolicy")) values.Add(value);
        }
        if (!observedAny)
        {
            check.Require(false, capability, "template.eku/applicationPolicy", "field.authentication-purpose-unavailable");
            return false;
        }

        var typed = template.ExtendedKeyUsages.Concat(template.ApplicationPolicies)
            .Distinct(StringComparer.Ordinal).OrderBy(value => value, StringComparer.Ordinal).ToArray();
        check.Require(values.OrderBy(value => value, StringComparer.Ordinal).SequenceEqual(typed, StringComparer.Ordinal),
            capability, "template.eku/applicationPolicy", "evidence.typed-content-conflict");
        return check.Known && values.Any(AdcsProtocolConstants.AuthenticationPurposeOids.Contains);
    }
}

internal sealed class AdcsDangerousTemplateAclRule : RuleBase
{
    public AdcsDangerousTemplateAclRule(RuleMetadata metadata) : base(metadata) { }

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
        var acl = new AdcsAclInventory(services);
        foreach (var template in services.Templates.OrderBy(item => item.Id.Value))
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var check = Check(context, template);
            var result = acl.HasLowPrivilegeDangerousControl(template, check, lowPrivilege);
            if (!check.Known) { yield return check.Unknown(); continue; }
            yield return check.Verdict(
                result,
                result
                    ? "A non-inherit-only Allow ACE gives a proven low-privilege trustee broad write, ownership, DACL-control, or unrestricted write-property rights on the certificate template. Deny precedence and complete Windows effective access are not inferred."
                    : "No dangerous low-privilege template-control Allow ACE was proven in the fully parsed DACL.",
                potential: result,
                checkKey: result ? "dangerous-template-control" : "default");
        }
    }
}

internal sealed class AdcsAclInventory
{
    private readonly IReadOnlyDictionary<AdObjectId, AdSecurityDescriptor> descriptors;
    private readonly IReadOnlyDictionary<AdObjectId, AdAce[]> aces;

    public AdcsAclInventory(CertificateServicesSnapshot services)
    {
        descriptors = services.SecurityDescriptors.ToDictionary(item => item.TargetObjectId);
        aces = services.Aces.GroupBy(item => item.TargetObjectId)
            .ToDictionary(group => group.Key, group => group.OrderBy(item => item.AceIndex).ToArray());
    }

    public bool HasLowPrivilegeEnrollGrant(CertificateTemplate template, RuleCheck check, AdcsLowPrivilegeIndex lowPrivilege)
    {
        if (!TryReadDescriptor(template, check, out var descriptor, out var targetAces)) return false;
        if (descriptor.DaclState is AdDaclState.Null or AdDaclState.NotPresent) return true;
        if (descriptor.DaclState == AdDaclState.Empty) return false;

        var unresolved = false;
        foreach (var ace in targetAces)
        {
            if (!TryReadAce(check, ace, out var access, out var flags, out var mask, out var trustee, out var objectType)) continue;
            if (access != AdAccessControlType.Allow || (flags & AdcsProtocolConstants.InheritOnlyAce) != 0) continue;
            var grantsEnroll = (mask & AdcsProtocolConstants.ControlAccess) != 0 &&
                               (!objectType.HasValue || objectType.Value == AdcsProtocolConstants.EnrollExtendedRight);
            if (!grantsEnroll) continue;
            if (lowPrivilege.TryProveLowPrivilegeTrustee(trustee, out var proof))
            {
                check.AddEvidence(proof);
                return true;
            }
            unresolved = true;
        }
        if (unresolved && !lowPrivilege.ScopeComplete)
            check.Require(false, CollectionCapabilities.DirectoryMemberships, "effective-enrollment-trustee", "membership.scope-incomplete");
        return false;
    }

    public bool HasLowPrivilegeDangerousControl(CertificateTemplate template, RuleCheck check, AdcsLowPrivilegeIndex lowPrivilege)
    {
        if (!TryReadDescriptor(template, check, out var descriptor, out var targetAces)) return false;
        if (descriptor.DaclState is AdDaclState.Null or AdDaclState.NotPresent) return true;
        if (descriptor.DaclState == AdDaclState.Empty) return false;

        var unresolved = false;
        foreach (var ace in targetAces)
        {
            if (!TryReadAce(check, ace, out var access, out var flags, out var mask, out var trustee, out var objectType)) continue;
            if (access != AdAccessControlType.Allow || (flags & AdcsProtocolConstants.InheritOnlyAce) != 0) continue;
            var dangerous = (mask & (AdcsProtocolConstants.GenericAll | AdcsProtocolConstants.GenericWrite |
                                      AdcsProtocolConstants.WriteDacl | AdcsProtocolConstants.WriteOwner)) != 0 ||
                            ((mask & AdcsProtocolConstants.WriteProperty) != 0 && !objectType.HasValue);
            if (!dangerous) continue;
            if (lowPrivilege.TryProveLowPrivilegeTrustee(trustee, out var proof))
            {
                check.AddEvidence(proof);
                return true;
            }
            unresolved = true;
        }
        if (unresolved && !lowPrivilege.ScopeComplete)
            check.Require(false, CollectionCapabilities.DirectoryMemberships, "dangerous-acl-trustee", "membership.scope-incomplete");
        return false;
    }

    private bool TryReadDescriptor(CertificateTemplate template, RuleCheck check, out AdSecurityDescriptor descriptor, out AdAce[] targetAces)
    {
        targetAces = aces.TryGetValue(template.Id, out var found) ? found : [];
        if (!descriptors.TryGetValue(template.Id, out descriptor!))
        {
            check.Require(false, CollectionCapabilities.AdcsAcls, "securityDescriptor", "descriptor.unavailable");
            return false;
        }

        var state = check.Text(CollectionCapabilities.AdcsAcls, "securityDescriptor.daclState");
        var complete = check.Boolean(CollectionCapabilities.AdcsAcls, "securityDescriptor.parseComplete");
        var count = check.Integer(CollectionCapabilities.AdcsAcls, "securityDescriptor.aceCount");
        check.Require(Enum.TryParse<AdDaclState>(state, out var parsedState) && parsedState == descriptor.DaclState,
            CollectionCapabilities.AdcsAcls, "securityDescriptor.daclState", "evidence.typed-content-conflict");
        check.Require(complete && count >= 0 && count == targetAces.Length,
            CollectionCapabilities.AdcsAcls, "securityDescriptor.parseComplete/aceCount", "descriptor.incomplete-or-inconsistent");
        return check.Known;
    }

    private static bool TryReadAce(RuleCheck check, AdAce ace, out AdAccessControlType access, out byte flags,
        out uint mask, out string trustee, out Guid? objectType)
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

        var accessParsed = Enum.TryParse(accessText, out access);
        check.Require(accessParsed && flagsValue is >= byte.MinValue and <= byte.MaxValue && maskValue is >= uint.MinValue and <= uint.MaxValue,
            capability, prefix, "field.invalid-ace");
        flags = flagsValue is >= byte.MinValue and <= byte.MaxValue ? (byte)flagsValue : (byte)0;
        mask = maskValue is >= uint.MinValue and <= uint.MaxValue ? (uint)maskValue : 0;
        check.Require(accessParsed && ace.AccessType == access && ace.AceFlags == flags && ace.AccessMask == mask &&
                      StringComparer.OrdinalIgnoreCase.Equals(ace.TrusteeSid, trustee) && ace.ObjectType.HasValue == objectTypePresent &&
                      (!objectTypePresent || ace.ObjectType == objectType),
            capability, prefix, "evidence.typed-content-conflict");
        return check.Known;
    }
}
