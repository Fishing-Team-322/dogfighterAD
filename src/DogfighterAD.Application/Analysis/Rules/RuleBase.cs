using DogfighterAD.Application.Contracts;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis.Rules;

public abstract class RuleBase : IRule
{
    protected RuleBase(RuleMetadata metadata) => Metadata = metadata;
    public RuleMetadata Metadata { get; }
    public abstract IEnumerable<RuleEvaluation> Evaluate(AdSnapshot snapshot, RuleContext context);
    protected RuleCheck Check(RuleContext context, AdDirectoryObject subject) => new(Metadata, context, AnalysisSubjects.For(subject));
    protected RuleCheck Check(RuleContext context, ObjectReference subject) => new(Metadata, context, subject);

    internal static RuleMetadata Describe(string id, string title, string category, FindingSeverity severity,
        string capability, IEnumerable<string> fields, string risk, string remediation, string reference,
        int contractVersion = 1) => new()
    {
        Id = id, Version = "1.0.0", Title = title, Category = category, DefaultSeverity = severity,
        RequiredCapabilities = [new(capability, contractVersion)], RequiredFields = fields.ToArray(),
        Risk = risk, Remediation = remediation, References = [new("Microsoft", "Protocol or setting documentation", reference)]
    };
}

public static class RuleSources
{
    public const string Uac = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties";
    public const string AccountPosture = "https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/accounts";
    public const string Encryption = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview";
    public const string PasswordPolicies = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/fine-grained-password-policies";
    public const string MachineQuota = "https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota";
    public const string Trusts = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c";
    public const string Acl = "https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl";
    public const string NullDacl = "https://learn.microsoft.com/en-us/windows/win32/ad/null-dacls-and-empty-dacls";
    public const string ExtendedRights = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb";
    public const string Ldap = "https://learn.microsoft.com/en-us/windows-server/identity/manage-ldap-signing-group-policy";
    public const string SecurityBaseline = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines";
}
