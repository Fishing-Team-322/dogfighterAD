using System.Globalization;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Findings;

namespace DogfighterAD.Web;

public sealed record UiFindingPresentationView
{
    public required UiExecutiveSummary Summary { get; init; }
    public IReadOnlyList<UiFindingPresentation> Findings { get; init; } = [];
    public IReadOnlyList<UiNotVerifiedPresentation> NotVerified { get; init; } = [];
}

public sealed record UiExecutiveSummary
{
    public required string OverallPosture { get; init; }
    public int Critical { get; init; }
    public int High { get; init; }
    public int Medium { get; init; }
    public int Low { get; init; }
    public int NotVerified { get; init; }
    public IReadOnlyList<string> TopPriorities { get; init; } = [];
}

public sealed record UiFindingPresentation
{
    public required string RuleId { get; init; }
    public required string Fingerprint { get; init; }
    public required string CustomerTitle { get; init; }
    public required string Severity { get; init; }
    public required string CustomerStatus { get; init; }
    public required string Summary { get; init; }
    public required string Impact { get; init; }
    public required string Recommendation { get; init; }
    public required string Confidence { get; init; }
    public string? StatusBoundary { get; init; }
    public required UiAffectedObjectPresentation AffectedObject { get; init; }
    public IReadOnlyList<UiConditionPresentation> Conditions { get; init; } = [];
    public IReadOnlyList<UiEvidencePresentation> KeyEvidence { get; init; } = [];
    public IReadOnlyList<UiEvidencePresentation> SupportingEvidence { get; init; } = [];
    public IReadOnlyList<UiEvidencePresentation> ContextEvidence { get; init; } = [];
}

public sealed record UiAffectedObjectPresentation(
    string DisplayName,
    string Type,
    string StableId,
    string? DistinguishedName);

public sealed record UiConditionPresentation(
    string Label,
    string Value,
    string? Detail,
    string State);

public sealed record UiEvidencePresentation
{
    public required string Classification { get; init; }
    public required string Headline { get; init; }
    public string? Principal { get; init; }
    public string? TechnicalPrincipal { get; init; }
    public string? Right { get; init; }
    public string? TechnicalRight { get; init; }
    public string? SourcePath { get; init; }
    public string? Value { get; init; }
}

public sealed record UiNotVerifiedPresentation
{
    public required string RuleId { get; init; }
    public required string CustomerTitle { get; init; }
    public required string Status { get; init; }
    public required string Subject { get; init; }
    public required string Reason { get; init; }
    public required string Caution { get; init; }
    public required string TechnicalOutcome { get; init; }
    public IReadOnlyList<string> MissingEvidence { get; init; } = [];
}

public static class UiFindingPresentationMapper
{
    private const string Esc1 = "ADCS.TEMPLATE.ESC1_CANDIDATE";
    private const string DangerousTemplateAcl = "ADCS.TEMPLATE.DANGEROUS_ACL";
    private const string BroadEnrollment = "ADCS.TEMPLATE.BROAD_ENROLLMENT";
    private const string DangerousCaAcl = "ADCS.CA.DANGEROUS_DIRECTORY_ACL";

    public static UiFindingPresentationView Map(
        AnalysisReport report,
        UiCertificateServicesView certificateServices)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(certificateServices);

        var findings = report.Findings
            .Select(finding => MapFinding(finding, certificateServices))
            .ToArray();
        var notVerified = report.Evaluations
            .Where(item => item.Outcome is RuleOutcome.NotVerified or RuleOutcome.Error)
            .Select(item => MapNotVerified(item, report))
            .ToArray();

        return new UiFindingPresentationView
        {
            Summary = BuildSummary(findings, notVerified),
            Findings = findings,
            NotVerified = notVerified
        };
    }

    private static UiExecutiveSummary BuildSummary(
        IReadOnlyList<UiFindingPresentation> findings,
        IReadOnlyList<UiNotVerifiedPresentation> notVerified)
    {
        var priorities = findings
            .OrderByDescending(item => SeverityRank(item.Severity))
            .ThenBy(item => item.CustomerTitle, StringComparer.Ordinal)
            .Select(item => PriorityText(item.RuleId, item.AffectedObject.DisplayName))
            .Distinct(StringComparer.Ordinal)
            .Take(3)
            .ToList();
        if (priorities.Count < 3 && notVerified.Count > 0)
            priorities.Add("Review checks that could not be verified");

        return new UiExecutiveSummary
        {
            OverallPosture = findings.Count > 0 || notVerified.Count > 0 ? "Needs attention" : "No findings emitted",
            Critical = findings.Count(item => item.Severity == "Critical"),
            High = findings.Count(item => item.Severity == "High"),
            Medium = findings.Count(item => item.Severity == "Medium"),
            Low = findings.Count(item => item.Severity == "Low"),
            NotVerified = notVerified.Count,
            TopPriorities = priorities.Take(3).ToArray()
        };
    }

    private static UiFindingPresentation MapFinding(
        Finding finding,
        UiCertificateServicesView certificateServices)
    {
        var affected = finding.AffectedObjects.FirstOrDefault()
            ?? new ObjectReference("snapshot", "snapshot");
        var template = certificateServices.Templates.FirstOrDefault(item => item.StableId == affected.StableId);
        var authority = certificateServices.Authorities.FirstOrDefault(item => item.StableId == affected.StableId);
        var presentation = Metadata(finding);
        var keyEvidence = BuildKeyEvidence(finding, template, authority);
        var keyPaths = keyEvidence
            .Where(item => !string.IsNullOrWhiteSpace(item.SourcePath))
            .Select(item => item.SourcePath!)
            .ToHashSet(StringComparer.Ordinal);
        var supporting = finding.Evidence
            .Where(item => !keyPaths.Contains(item.Path) && IsSupporting(item.Path))
            .Select(item => EvidenceRow("Supporting", item))
            .ToArray();
        var context = finding.Evidence
            .Where(item => !keyPaths.Contains(item.Path) && !IsSupporting(item.Path))
            .Select(item => EvidenceRow("Context", item))
            .ToArray();

        return new UiFindingPresentation
        {
            RuleId = finding.RuleId,
            Fingerprint = finding.Fingerprint,
            CustomerTitle = presentation.Title,
            Severity = finding.Severity.ToString(),
            CustomerStatus = CustomerStatus(finding.Status),
            Summary = presentation.Summary,
            Impact = presentation.Impact,
            Recommendation = presentation.Recommendation,
            Confidence = finding.Confidence.ToString(),
            StatusBoundary = finding.RuleId == Esc1 && finding.Status == FindingStatus.Potential
                ? "DogfighterAD verified the directory-side conditions only. CA runtime configuration and successful issuance were not verified."
                : finding.Status == FindingStatus.Potential
                    ? "This is a potential exposure based on the collected evidence. Complete Windows effective access or runtime exploitability was not asserted."
                    : null,
            AffectedObject = new UiAffectedObjectPresentation(
                affected.DisplayName ?? template?.DisplayName ?? template?.CommonName ?? authority?.Name ?? affected.StableId,
                ObjectType(affected.Kind),
                affected.StableId,
                affected.DistinguishedName),
            Conditions = BuildConditions(finding, template),
            KeyEvidence = keyEvidence,
            SupportingEvidence = supporting,
            ContextEvidence = context
        };
    }

    private static IReadOnlyList<UiConditionPresentation> BuildConditions(
        Finding finding,
        UiCertificateTemplateView? template)
    {
        if (finding.RuleId != Esc1)
            return [];

        var enrollment = FriendlyEnrollmentDetail(template);
        var purpose = template is null
            ? "Observed by the rule"
            : template.ExtendedKeyUsages.Concat(template.ApplicationPolicies).FirstOrDefault(FriendlyPurpose) is string oid
                ? FriendlyPurposeName(oid)
                : "Authentication-capable purpose observed";
        var publication = template?.PublishedAuthorities.FirstOrDefault()?.Name;

        return
        [
            new("Published on CA", "Yes", publication ?? "Proven by the matching rule evaluation", "Met"),
            new("Low-privileged enrollment", "Yes", enrollment, "Met"),
            new("Authentication capable", "Yes", purpose, "Met"),
            new("Requester supplies subject", "Yes", "ENROLLEE_SUPPLIES_SUBJECT is part of the proven match", "Met"),
            new("Manager approval required", "No", "The matching rule verified that the pending/approval gate is absent", "Met"),
            new("Authorized signatures required", "0", "The matching rule verified zero required authorized signatures", "Met"),
            new("CA runtime conditions", "Not verified", "Registry, RPC, web enrollment and successful issuance are outside this directory-derived rule", "NotVerified")
        ];
    }

    private static IReadOnlyList<UiEvidencePresentation> BuildKeyEvidence(
        Finding finding,
        UiCertificateTemplateView? template,
        UiCertificateAuthorityView? authority)
    {
        var result = new List<UiEvidencePresentation>();
        var aces = template?.DirectAces ?? authority?.DirectAces ?? [];

        if (finding.RuleId is DangerousTemplateAcl or DangerousCaAcl)
        {
            var candidate = FindProvableAce(finding, aces, DangerousRights);
            if (candidate is not null)
            {
                var technicalRight = candidate.Rights.First(DangerousRights.Contains);
                result.Add(AceEvidence(
                    finding.RuleId == DangerousCaAcl
                        ? $"{FriendlyPrincipal(candidate.TrusteeSid)} can change this CA directory object"
                        : $"{FriendlyPrincipal(candidate.TrusteeSid)} can modify this certificate template",
                    candidate,
                    technicalRight,
                    AceSourcePath(finding, candidate.AceIndex)));
            }
            else
            {
                result.Add(new UiEvidencePresentation
                {
                    Classification = "Key",
                    Headline = finding.RuleId == DangerousCaAcl
                        ? "A proven low-privilege path can change the Enterprise CA directory object"
                        : "A proven low-privilege path can modify this certificate template",
                    SourcePath = finding.Evidence.FirstOrDefault(item => item.Path.Contains("securityDescriptor.dacl", StringComparison.Ordinal))?.Path
                });
            }
        }
        else if (finding.RuleId is BroadEnrollment or Esc1)
        {
            var candidate = FindProvableAce(finding, aces, EnrollmentRights);
            if (candidate is not null)
            {
                var technicalRight = candidate.Rights.First(EnrollmentRights.Contains);
                result.Add(AceEvidence(
                    $"{FriendlyPrincipal(candidate.TrusteeSid)} can request certificates from this template",
                    candidate,
                    technicalRight,
                    AceSourcePath(finding, candidate.AceIndex)));
            }
            else
            {
                result.Add(new UiEvidencePresentation
                {
                    Classification = "Key",
                    Headline = "Low-privileged users have a proven certificate enrollment path",
                    SourcePath = finding.Evidence.FirstOrDefault(item => item.Path.Contains("securityDescriptor.dacl", StringComparison.Ordinal))?.Path
                });
            }

            foreach (var nested in finding.Evidence.Where(item => item.Path == "group.member" && !string.IsNullOrWhiteSpace(item.Value)))
            {
                result.Add(new UiEvidencePresentation
                {
                    Classification = "Key",
                    Headline = $"Nested membership evidence includes {CommonName(nested.Value!)}",
                    SourcePath = nested.Path,
                    Value = nested.Value
                });
            }
        }

        if (finding.RuleId == Esc1)
        {
            result.Add(new UiEvidencePresentation
            {
                Classification = "Key",
                Headline = "Requester can supply certificate subject information",
                Right = "ENROLLEE_SUPPLIES_SUBJECT",
                TechnicalRight = "certificateNameFlags bit 0x00000001",
                SourcePath = FindPath(finding, "template.certificateNameFlags")
            });
            result.Add(new UiEvidencePresentation
            {
                Classification = "Key",
                Headline = "Certificate usage is authentication-capable",
                Right = template is null ? "Authentication capable" : FriendlyAuthenticationPurpose(template),
                SourcePath = FindPath(finding, "template.eku") ?? FindPath(finding, "template.applicationPolicy")
            });
            result.Add(new UiEvidencePresentation
            {
                Classification = "Key",
                Headline = "Manager approval is not required",
                Right = "Approval disabled by collected template flags",
                SourcePath = FindPath(finding, "template.enrollmentFlags")
            });
            result.Add(new UiEvidencePresentation
            {
                Classification = "Key",
                Headline = "Authorized signatures are not required",
                Right = "0 required signatures",
                SourcePath = FindPath(finding, "template.requiredAuthorizedSignatures")
            });
        }

        return result;
    }

    private static UiCertificateAceView? FindProvableAce(
        Finding finding,
        IReadOnlyList<UiCertificateAceView> aces,
        IReadOnlySet<string> relevantRights)
    {
        var evidenceIndexes = finding.Evidence
            .Select(item => TryParseAceIndex(item.Path, out var index) ? index : (int?)null)
            .Where(item => item.HasValue)
            .Select(item => item!.Value)
            .ToHashSet();

        return aces
            .Where(item => evidenceIndexes.Contains(item.AceIndex))
            .Where(item => item.AccessType == "Allow")
            .Where(item => item.Rights.Any(relevantRights.Contains))
            .FirstOrDefault(item => IsBroadLowPrivilegeSid(item.TrusteeSid));
    }

    private static UiEvidencePresentation AceEvidence(
        string headline,
        UiCertificateAceView ace,
        string technicalRight,
        string? sourcePath) => new()
    {
        Classification = "Key",
        Headline = headline,
        Principal = FriendlyPrincipal(ace.TrusteeSid),
        TechnicalPrincipal = ace.TrusteeSid,
        Right = FriendlyRight(technicalRight),
        TechnicalRight = technicalRight,
        SourcePath = sourcePath
    };

    private static UiNotVerifiedPresentation MapNotVerified(
        RuleEvaluation evaluation,
        AnalysisReport report)
    {
        var title = report.Rules.FirstOrDefault(item => item.RuleId == evaluation.RuleId)?.Title
            ?? evaluation.RuleId;
        var missing = evaluation.MissingData.Select(MissingEvidenceText).ToArray();
        var reason = evaluation.Outcome == RuleOutcome.Error
            ? "The check failed before a trustworthy verdict could be produced."
            : MissingReason(evaluation.MissingData);

        return new UiNotVerifiedPresentation
        {
            RuleId = evaluation.RuleId,
            CustomerTitle = title,
            Status = evaluation.Outcome == RuleOutcome.Error ? "Check failed" : "Could not verify",
            Subject = evaluation.Subject.DisplayName ?? evaluation.Subject.DistinguishedName ?? evaluation.Subject.StableId,
            Reason = reason,
            Caution = evaluation.Outcome == RuleOutcome.Error
                ? "The rule failed; no clean result was inferred."
                : "DogfighterAD did not collect enough trustworthy evidence to determine whether this condition is secure or insecure. This should not be interpreted as a clean result.",
            TechnicalOutcome = evaluation.Outcome.ToString(),
            MissingEvidence = missing
        };
    }

    private static string MissingReason(IReadOnlyList<DataGap> gaps)
    {
        if (gaps.Any(item => item.CapabilityId == "adcs.acls" || item.Path.Contains("securityDescriptor", StringComparison.Ordinal)))
            return "The template or CA security descriptor could not be fully collected or verified.";
        if (gaps.Any(item => item.CapabilityId.StartsWith("adcs.", StringComparison.Ordinal)))
            return "Required Certificate Services directory evidence is missing, incomplete or unusable.";
        if (gaps.Any(item => item.Path == "coverage"))
            return "A required collection capability was unavailable or incomplete.";
        return "Required snapshot evidence is missing, conflicting or unusable.";
    }

    private static string MissingEvidenceText(DataGap gap)
    {
        var label = gap.CapabilityId.StartsWith("adcs.", StringComparison.Ordinal)
            ? "Certificate Services evidence"
            : "Missing evidence";
        return $"{label}: {gap.CapabilityId} · {gap.Path} · {gap.Code}";
    }

    private static (string Title, string Summary, string Impact, string Recommendation) Metadata(Finding finding) =>
        finding.RuleId switch
        {
            Esc1 => (
                "Potential certificate impersonation risk",
                "This certificate template combines a proven low-privilege enrollment path with requester-controlled identity information and authentication-capable certificate usage.",
                "If the remaining CA runtime conditions also permit it, a user may be able to obtain a certificate representing another account.",
                "Restrict enrollment permissions, prevent requester-supplied identity where it is not required, and review approval and signature requirements."),
            DangerousTemplateAcl => (
                "Certificate template permissions can be modified by low-privileged users",
                "Collected directory evidence proves a potential low-privilege path to security-sensitive template modification rights.",
                "A principal with these rights may be able to alter certificate template settings or permissions. Complete Windows effective access was not inferred.",
                "Remove unnecessary modification rights from low-privileged principals and retain only the minimum approved PKI administration permissions."),
            BroadEnrollment => (
                "Certificate enrollment is available to low-privileged users",
                "Collected directory evidence proves a low-privilege enrollment or auto-enrollment path for this template.",
                "A broader population can request certificates from this template. This finding alone does not claim privilege escalation.",
                "Restrict enrollment permissions to the users and groups that require this template and review nested group membership."),
            DangerousCaAcl => (
                "Enterprise CA directory permissions can be changed by low-privileged users",
                "Collected directory evidence proves a potential low-privilege path to security-sensitive permissions on the Enterprise CA directory object.",
                "A principal with these directory rights may be able to alter the CA object's permissions or properties. CA runtime permissions were not verified.",
                "Remove unnecessary write, ownership or permission-management rights from low-privileged principals on the Enterprise CA directory object."),
            _ => (finding.Title, finding.Description, finding.Risk, finding.Remediation)
        };

    private static UiEvidencePresentation EvidenceRow(string classification, Evidence evidence) => new()
    {
        Classification = classification,
        Headline = FriendlyEvidenceHeadline(evidence.Path),
        SourcePath = evidence.Path,
        Value = evidence.Value
    };

    private static bool IsSupporting(string path) =>
        path.Contains("publishedOnCa", StringComparison.Ordinal) ||
        path.Contains("certificateNameFlags", StringComparison.Ordinal) ||
        path.Contains("enrollmentFlags", StringComparison.Ordinal) ||
        path.Contains("requiredAuthorizedSignatures", StringComparison.Ordinal) ||
        path.Contains("template.eku", StringComparison.Ordinal) ||
        path.Contains("template.applicationPolicy", StringComparison.Ordinal) ||
        path.Contains("securityDescriptor.parseComplete", StringComparison.Ordinal) ||
        path.Contains("securityDescriptor.aceCount", StringComparison.Ordinal) ||
        path == "group.member";

    private static string FriendlyEvidenceHeadline(string path) => path switch
    {
        "template.publishedOnCa" => "Template publication",
        "template.certificateNameFlags" => "Certificate naming configuration",
        "template.enrollmentFlags" => "Enrollment approval configuration",
        "template.requiredAuthorizedSignatures" => "Authorized signature requirement",
        "template.eku" => "Extended key usage",
        "template.applicationPolicy" => "Application policy",
        "securityDescriptor.parseComplete" => "ACL parse completeness",
        "securityDescriptor.aceCount" => "ACL entry count",
        "group.member" => "Nested membership evidence",
        _ => path
    };

    private static string CustomerStatus(FindingStatus status) => status switch
    {
        FindingStatus.NotVerified => "Could not verify",
        _ => status.ToString()
    };

    private static string ObjectType(string kind) => kind switch
    {
        "certificate-template" => "Certificate Template",
        "certificate-authority" => "Enterprise CA",
        "user" => "User",
        "group" => "Group",
        "computer" => "Computer",
        _ => CultureInfo.InvariantCulture.TextInfo.ToTitleCase(kind.Replace('-', ' '))
    };

    private static string PriorityText(string ruleId, string subject) => ruleId switch
    {
        Esc1 => $"Review {subject} certificate template",
        DangerousTemplateAcl => $"Remove dangerous modification rights from {subject}",
        BroadEnrollment => $"Review broad certificate enrollment on {subject}",
        DangerousCaAcl => $"Review directory permissions on {subject}",
        _ => $"Review {subject}"
    };

    private static int SeverityRank(string severity) => severity switch
    {
        "Critical" => 5,
        "High" => 4,
        "Medium" => 3,
        "Low" => 2,
        _ => 1
    };

    private static readonly HashSet<string> DangerousRights = new(StringComparer.Ordinal)
    {
        "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "WriteProperty"
    };

    private static readonly HashSet<string> EnrollmentRights = new(StringComparer.Ordinal)
    {
        "Enroll", "AutoEnroll"
    };

    private static bool IsBroadLowPrivilegeSid(string sid) =>
        sid is "S-1-1-0" or "S-1-5-11" or "S-1-5-32-545" || sid.EndsWith("-513", StringComparison.Ordinal);

    private static string FriendlyPrincipal(string sid) => sid switch
    {
        "S-1-1-0" => "Everyone",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-32-545" => "Users",
        _ when sid.EndsWith("-513", StringComparison.Ordinal) => "Domain Users",
        _ => sid
    };

    private static string FriendlyRight(string right) => right switch
    {
        "GenericAll" => "Full control",
        "GenericWrite" => "Can modify this object",
        "WriteDacl" => "Can change permissions",
        "WriteOwner" => "Can take ownership",
        "WriteProperty" => "Can modify object properties",
        "Enroll" => "Can request certificates",
        "AutoEnroll" => "Can automatically enroll",
        _ => right
    };

    private static string? AceSourcePath(Finding finding, int aceIndex) =>
        finding.Evidence.FirstOrDefault(item => item.Path == $"securityDescriptor.dacl.ace[{aceIndex}].accessMask")?.Path
        ?? finding.Evidence.FirstOrDefault(item => item.Path.StartsWith($"securityDescriptor.dacl.ace[{aceIndex}]", StringComparison.Ordinal))?.Path;

    private static string? FindPath(Finding finding, string pathPrefix) =>
        finding.Evidence.FirstOrDefault(item => item.Path.StartsWith(pathPrefix, StringComparison.Ordinal))?.Path;

    private static bool TryParseAceIndex(string path, out int index)
    {
        const string marker = "securityDescriptor.dacl.ace[";
        var start = path.IndexOf(marker, StringComparison.Ordinal);
        if (start < 0)
        {
            index = -1;
            return false;
        }
        start += marker.Length;
        var end = path.IndexOf(']', start);
        return end > start && int.TryParse(path.AsSpan(start, end - start), NumberStyles.None, CultureInfo.InvariantCulture, out index);
    }

    private static string FriendlyEnrollmentDetail(UiCertificateTemplateView? template)
    {
        if (template is null)
            return "Proven by the matching rule evaluation";
        var ace = template.DirectAces.FirstOrDefault(item =>
            item.AccessType == "Allow" && item.Rights.Any(EnrollmentRights.Contains) && IsBroadLowPrivilegeSid(item.TrusteeSid));
        return ace is null
            ? "Proven through collected ACL and membership evidence"
            : $"{FriendlyPrincipal(ace.TrusteeSid)} · {FriendlyRight(ace.Rights.First(EnrollmentRights.Contains))}";
    }

    private static bool FriendlyPurpose(string oid) => oid is
        "1.3.6.1.5.5.7.3.2" or "1.3.6.1.4.1.311.20.2.2" or "1.3.6.1.5.2.3.4" or "2.5.29.37.0";

    private static string FriendlyPurposeName(string oid) => oid switch
    {
        "1.3.6.1.5.5.7.3.2" => "Client Authentication",
        "1.3.6.1.4.1.311.20.2.2" => "Smart Card Logon",
        "1.3.6.1.5.2.3.4" => "PKINIT Client Authentication",
        "2.5.29.37.0" => "Any Extended Key Usage",
        _ => oid
    };

    private static string FriendlyAuthenticationPurpose(UiCertificateTemplateView template) =>
        template.ExtendedKeyUsages.Concat(template.ApplicationPolicies)
            .Where(FriendlyPurpose)
            .Select(FriendlyPurposeName)
            .FirstOrDefault() ?? "Authentication capable";

    private static string CommonName(string distinguishedName)
    {
        const string prefix = "CN=";
        if (!distinguishedName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return distinguishedName;
        var end = distinguishedName.IndexOf(',');
        return end > prefix.Length ? distinguishedName[prefix.Length..end] : distinguishedName[prefix.Length..];
    }
}
