using DogfighterAD.Application.Contracts;
using DogfighterAD.Domain.Findings;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis.Rules;

public sealed record AccountFlagDefinition(string Suffix, string Title, long Mask, FindingSeverity Severity, bool ExcludeDomainControllers = false);

/// <summary>Versioned, deterministic built-in rules. This pack never performs network operations.</summary>
public static class BuiltInRulePack
{
    public const string Id = "dogfighterad.core";
    public const string Version = "1.2.0";
    public static IReadOnlyList<AccountFlagDefinition> AccountFlags { get; } = new AccountFlagDefinition[]
    {
        new("PREAUTH_DISABLED", "Kerberos preauthentication is disabled", 0x400000, FindingSeverity.High),
        new("PASSWORD_NOT_REQUIRED", "Password-not-required account flag is set", 0x20, FindingSeverity.High),
        new("REVERSIBLE_PASSWORD_ALLOWED", "Reversible password encryption is allowed", 0x80, FindingSeverity.High),
        new("DES_ONLY", "Account is restricted to DES keys", 0x200000, FindingSeverity.High),
        new("PASSWORD_NEVER_EXPIRES", "Password expiration is disabled on the account", 0x10000, FindingSeverity.Medium),
        new("UNCONSTRAINED_DELEGATION", "Unconstrained delegation is configured", 0x80000, FindingSeverity.High, true),
        new("PROTOCOL_TRANSITION", "Protocol-transition delegation is configured", 0x1000000, FindingSeverity.High)
    };
    public static IReadOnlyList<RegistryRuleDefinition> RegistryDefinitions { get; } = new RegistryRuleDefinition[]
    {
        new("AD.GPO.ALWAYS_INSTALL_ELEVATED", @"Software\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", NumericComparison.Equals, 1, FindingSeverity.High, "Windows Installer elevation policy is enabled", true),
        new("AD.GPO.UAC_DISABLED", @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", NumericComparison.Equals, 0, FindingSeverity.High, "GPO disables User Account Control", false),
        new("AD.GPO.LOCAL_ACCOUNT_TOKEN_FILTER", @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "LocalAccountTokenFilterPolicy", NumericComparison.Equals, 1, FindingSeverity.High, "GPO relaxes remote local-account token filtering", false),
        new("AD.GPO.WDIGEST_CACHING", @"System\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", NumericComparison.Equals, 1, FindingSeverity.High, "GPO enables WDigest logon-credential caching", false),
        new("AD.GPO.LSA_PROTECTION_DISABLED", @"System\CurrentControlSet\Control\Lsa", "RunAsPPL", NumericComparison.Equals, 0, FindingSeverity.Medium, "GPO disables configured LSA protected-process mode", false, 2),
        new("AD.GPO.LM_HASH_STORAGE", @"System\CurrentControlSet\Control\Lsa", "NoLMHash", NumericComparison.Equals, 0, FindingSeverity.High, "GPO permits legacy LM hash storage", false),
        new("AD.GPO.NTLM_COMPATIBILITY", @"System\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", NumericComparison.LessThan, 5, FindingSeverity.Medium, "GPO configures an NTLM compatibility level below 5", false, 5),
        new("AD.GPO.LDAP_SIGNING", @"System\CurrentControlSet\Services\NTDS\Parameters", "LDAPServerIntegrity", NumericComparison.LessThan, 2, FindingSeverity.High, "GPO does not require LDAP server signing in this legacy setting", false, 2),
        new("AD.GPO.LDAP_CHANNEL_BINDING", @"System\CurrentControlSet\Services\NTDS\Parameters", "LdapEnforceChannelBinding", NumericComparison.Equals, 0, FindingSeverity.Medium, "GPO explicitly disables LDAP channel-binding enforcement", false, 2),
        new("AD.GPO.SMB_SERVER_SIGNING", @"System\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature", NumericComparison.Equals, 0, FindingSeverity.High, "GPO does not require SMB server signing", false),
        new("AD.GPO.SMB_CLIENT_SIGNING", @"System\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature", NumericComparison.Equals, 0, FindingSeverity.High, "GPO does not require SMB client signing", false),
        new("AD.GPO.SMB1_ENABLED", @"System\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", NumericComparison.Equals, 1, FindingSeverity.High, "GPO enables SMB1 server configuration", false),
        new("AD.GPO.INSECURE_GUEST_LOGONS", @"Software\Policies\Microsoft\Windows\LanmanWorkstation", "AllowInsecureGuestAuth", NumericComparison.Equals, 1, FindingSeverity.Medium, "GPO allows insecure SMB guest logons", false),
        new("AD.GPO.RDP_NLA_DISABLED", @"Software\Policies\Microsoft\Windows NT\Terminal Services", "UserAuthentication", NumericComparison.Equals, 0, FindingSeverity.Medium, "GPO disables the RDP NLA requirement", false),
        new("AD.GPO.RDP_SECURITY_LAYER", @"Software\Policies\Microsoft\Windows NT\Terminal Services", "SecurityLayer", NumericComparison.LessThan, 2, FindingSeverity.Medium, "GPO does not require the RDP TLS security layer", false, 2),
        new("AD.GPO.WINRM_BASIC", @"Software\Policies\Microsoft\Windows\WinRM\Service", "AllowBasic", NumericComparison.Equals, 1, FindingSeverity.Medium, "GPO enables WinRM service Basic authentication", false),
        new("AD.GPO.WINRM_UNENCRYPTED", @"Software\Policies\Microsoft\Windows\WinRM\Service", "AllowUnencryptedTraffic", NumericComparison.Equals, 1, FindingSeverity.High, "GPO permits unencrypted WinRM service traffic", false),
        new("AD.GPO.CREDSSP_ORACLE", @"Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters", "AllowEncryptionOracle", NumericComparison.Equals, 2, FindingSeverity.High, "GPO selects the vulnerable CredSSP compatibility mode", false, 2),
        new("AD.GPO.DEFENDER_REALTIME_DISABLED", @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", NumericComparison.Equals, 1, FindingSeverity.High, "GPO requests disabling Defender real-time monitoring", false),
        new("AD.GPO.AUTOMATIC_UPDATES_DISABLED", @"Software\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", NumericComparison.Equals, 1, FindingSeverity.Low, "GPO disables automatic updates in this policy setting", false),
    };
    public static IReadOnlyList<string> Privileges { get; } = new[]
    { "SeDebugPrivilege", "SeImpersonatePrivilege", "SeTcbPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege" };

    public static IReadOnlyList<IRule> Create()
    {
        var rules = new List<IRule>();
        foreach (var computer in new[] { false, true })
        {
            var cap = computer ? CollectionCapabilities.DirectoryComputers : CollectionCapabilities.DirectoryUsers;
            var prefix = computer ? "computer" : "user";
            var idPrefix = computer ? "AD.COMPUTER." : "AD.USER.";
            RuleMetadata AccountMeta(string suffix, string title, FindingSeverity severity, params string[] fields) =>
                RuleBase.Describe(idPrefix + suffix, title, computer ? "Computer accounts" : "User accounts", severity, cap,
                    new[] { prefix + ".userAccountControl" }.Concat(fields),
                    "The observed account configuration can increase credential or delegation exposure. A configured flag does not prove an empty password, recoverable credentials, installed key types or successful compromise.",
                    "Review the account's purpose and dependencies. Remove unnecessary exposure using an approved change and service-account management plan; validate operational compatibility.", RuleSources.Uac);
            foreach (var flag in AccountFlags)
                rules.Add(new AccountRule(AccountMeta(flag.Suffix, flag.Title, flag.Severity), computer, AccountTest.Flag,
                    mask: flag.Mask, excludeDc: computer && flag.ExcludeDomainControllers));
            rules.Add(new AccountRule(AccountMeta("CONSTRAINED_DELEGATION", "Constrained-delegation targets are configured", FindingSeverity.Medium,
                prefix + ".allowedToDelegateTo"), computer, AccountTest.ValuesPresent, "allowedToDelegateTo"));
            rules.Add(new AccountRule(AccountMeta("EXPLICIT_DES", "DES encryption support is explicitly advertised", FindingSeverity.High,
                prefix + ".supportedEncryptionTypes"), computer, AccountTest.EncryptionBit, mask: 3));
            rules.Add(new AccountRule(AccountMeta("EXPLICIT_RC4", "RC4 encryption support is explicitly advertised", FindingSeverity.Medium,
                prefix + ".supportedEncryptionTypes"), computer, AccountTest.EncryptionBit, mask: 4));
            rules.Add(new AccountRule(AccountMeta("PASSWORD_AGE", "Password-change timestamp exceeds the review threshold", FindingSeverity.Medium,
                prefix + ".pwdLastSet"), computer, AccountTest.PasswordAge));
            rules.Add(new AccountRule(AccountMeta("REPLICATED_LOGON_AGE", "Replicated logon timestamp exceeds the review threshold", FindingSeverity.Low,
                prefix + ".lastLogonTimestamp"), computer, AccountTest.LogonAge));
            if (!computer)
            {
                rules.Add(new AccountRule(AccountMeta("SPN_ACCOUNT", "An enabled user account has a service principal name", FindingSeverity.Medium,
                    "user.servicePrincipalName"), false, AccountTest.ValuesPresent, "servicePrincipalName"));
                rules.Add(new AccountRule(AccountMeta("SID_HISTORY", "An enabled user has SID history", FindingSeverity.Medium,
                    "user.sidHistory"), false, AccountTest.ValuesPresent, "sidHistory", kind: FactValueKind.Sid));
                rules.Add(new AccountRule(AccountMeta("EXPIRED_ENABLED", "An enabled account has an elapsed expiration date", FindingSeverity.Low,
                    "user.accountExpires"), false, AccountTest.Expired));
                foreach (var special in new[] { ("GUEST_ENABLED", "The domain Guest account is enabled", AccountTest.GuestEnabled),
                                               ("KRBTGT_PASSWORD_AGE", "krbtgt password-change timestamp exceeds the review threshold", AccountTest.KrbtgtPasswordAge) })
                {
                    var meta = AccountMeta(special.Item1, special.Item2, FindingSeverity.High,
                        special.Item3 == AccountTest.GuestEnabled ? ["object.objectSid", "domain.objectSid"] : ["object.objectSid", "domain.objectSid", "user.pwdLastSet"]);
                    rules.Add(new AccountRule(meta with { RequiredCapabilities = [new(cap), new(CollectionCapabilities.DirectoryDomains)] }, false, special.Item3));
                }
            }
        }
        foreach (var (test, suffix, title) in new[]
        {
            (PrivilegedAccountTest.DelegationNotBlocked, "NOT_SENSITIVE", "Privileged account lacks the sensitive/not-delegated flag"),
            (PrivilegedAccountTest.ServicePrincipalName, "SPN_ACCOUNT", "Privileged account has a service principal name"),
            (PrivilegedAccountTest.PasswordNeverExpires, "PASSWORD_NEVER_EXPIRES", "Privileged account has password expiration disabled")
        })
        {
            var meta = RuleBase.Describe("AD.PRIVILEGED." + suffix, title, "Privileged accounts", FindingSeverity.High,
                CollectionCapabilities.DirectoryUsers, ["user.userAccountControl", "group.member or principal.primaryGroupId", "object.objectSid", "domain.objectSid"],
                "Credential exposure on an account with an evidence-backed path to an in-scope privileged group has elevated impact.",
                "Use dedicated privileged identities and managed service identities. Review delegation protections and service registration without relying on adminCount.", RuleSources.AccountPosture);
            rules.Add(new PrivilegedAccountRule(meta with { RequiredCapabilities = [new(CollectionCapabilities.DirectoryUsers), new(CollectionCapabilities.DirectoryGroups),
                new(CollectionCapabilities.DirectoryMemberships), new(CollectionCapabilities.DirectoryDomains)] }, test));
        }
        foreach (var (test, suffix, title, severity) in new[]
        {
            (PasswordPolicyTest.Length, "MINIMUM_LENGTH", "Password policy minimum length is below the configured baseline", FindingSeverity.Medium),
            (PasswordPolicyTest.History, "HISTORY", "Password history is below the configured baseline", FindingSeverity.Low),
            (PasswordPolicyTest.Complexity, "COMPLEXITY", "Password complexity is explicitly disabled", FindingSeverity.Medium),
            (PasswordPolicyTest.Reversible, "REVERSIBLE_ENCRYPTION", "Password policy enables reversible encryption", FindingSeverity.High),
            (PasswordPolicyTest.LockoutDisabled, "LOCKOUT_DISABLED", "Account lockout is explicitly disabled", FindingSeverity.Medium),
            (PasswordPolicyTest.LockoutHigh, "LOCKOUT_THRESHOLD", "Lockout threshold exceeds the configured baseline", FindingSeverity.Low),
            (PasswordPolicyTest.LockoutDuration, "LOCKOUT_DURATION", "Lockout duration is below the configured baseline", FindingSeverity.Low),
            (PasswordPolicyTest.MachineQuota, "MACHINE_ACCOUNT_QUOTA", "The domain permits a nonzero user machine-account quota", FindingSeverity.Medium)
        })
            rules.Add(new PasswordPolicyRule(RuleBase.Describe("AD.POLICY." + suffix, title, "Domain and fine-grained password policies", severity,
                CollectionCapabilities.DirectorySecurityPolicy, new[] { "policy.kind", "policy.distinguishedName", "policy." + (test switch
                {
                    PasswordPolicyTest.Length => "minimumPasswordLength", PasswordPolicyTest.History => "passwordHistoryLength",
                    PasswordPolicyTest.Complexity => "complexityEnabled", PasswordPolicyTest.Reversible => "reversibleEncryptionEnabled",
                    PasswordPolicyTest.LockoutDuration => "lockoutDurationTicks", PasswordPolicyTest.MachineQuota => "machineAccountQuota", _ => "lockoutThreshold"
                }) }.Concat(test == PasswordPolicyTest.LockoutDuration ? new[] { "policy.lockoutThreshold" } : Array.Empty<string>()),
                "The observed policy differs from the explicitly chosen review baseline or permits a known risky configuration. This is not a per-user resultant-policy calculation.",
                "Review domain defaults, PSO assignment and business requirements. Prefer long unique passwords and appropriate authentication protections; test lockout changes to avoid denial of service.",
                test == PasswordPolicyTest.MachineQuota ? RuleSources.MachineQuota : RuleSources.PasswordPolicies), test));
        foreach (var (test, suffix, title) in new[]
        {
            (TrustTest.ExternalWithoutSelectiveAuthentication, "SELECTIVE_AUTHENTICATION", "Outbound external trust lacks the selective-authentication flag"),
            (TrustTest.TreatAsExternal, "TREAT_AS_EXTERNAL", "Forest trust is configured to be treated as external for filtering"),
            (TrustTest.TgtDelegationEnabled, "TGT_DELEGATION", "Cross-organization TGT delegation is explicitly enabled"),
            (TrustTest.LegacyTrustType, "LEGACY_TYPE", "Legacy down-level trust type is configured")
        })
            rules.Add(new TrustRule(RuleBase.Describe("AD.TRUST." + suffix, title, "Trusts", FindingSeverity.Medium, CollectionCapabilities.DirectoryTrusts,
                ["trust.partner", "trust.direction", "trust.type", "trust.attributes"],
                "Cross-domain authentication expands a trust boundary. Local TDO flags alone do not prove a SID-filtering bypass or remote exposure.",
                "Review trust direction, scope, selective authentication and delegation with both domain owners; remove unnecessary trust relationships.", RuleSources.Trusts), test));
        foreach (var (test, suffix, title) in new[]
        {
            (AclTest.UnrestrictedDacl, "UNRESTRICTED_DACL", "An AD object has a null or absent DACL"),
            (AclTest.GenericAll, "BROAD_GENERIC_ALL", "A broad principal has an Allow ACE carrying full-control rights"),
            (AclTest.GenericWrite, "BROAD_WRITE", "A broad principal has an Allow ACE carrying write-property rights"),
            (AclTest.WriteDacl, "BROAD_WRITE_DACL", "A broad principal has an Allow ACE carrying WRITE_DAC"),
            (AclTest.WriteOwner, "BROAD_WRITE_OWNER", "A broad principal has an Allow ACE carrying WRITE_OWNER"),
            (AclTest.ResetPassword, "BROAD_RESET_PASSWORD", "A broad principal has an Allow ACE for password reset"),
            (AclTest.ReplicationRight, "BROAD_REPLICATION_RIGHT", "A broad principal has a replication-related Allow ACE on the domain")
        })
        {
            var min = test == AclTest.UnrestrictedDacl ? 1 : 3;
            var meta = RuleBase.Describe("AD.ACL." + suffix, title, "Directory ACLs", FindingSeverity.High, CollectionCapabilities.DirectoryAcls,
                test == AclTest.UnrestrictedDacl ? ["securityDescriptor.daclState"] : ["securityDescriptor.parseComplete", "securityDescriptor.aceCount", "securityDescriptor.dacl.ace[*].accessType/aceFlags/trusteeSid/accessMask/objectTypePresent"],
                "The recorded descriptor or Allow ACE deserves review. Effective access, deny order and token expansion are not inferred from a single ACE.",
                "Review the source DACL and effective permissions, remove unnecessary broad grants and preserve necessary inheritance and application access.",
                test == AclTest.UnrestrictedDacl ? RuleSources.NullDacl : RuleSources.Acl, min);
            if (test != AclTest.UnrestrictedDacl) meta = meta with { RequiredCapabilities = [new(CollectionCapabilities.DirectoryAcls, 3), new(CollectionCapabilities.DirectoryDomains)] };
            rules.Add(new AclRule(meta, test));
        }
        foreach (var definition in RegistryDefinitions)
        {
            var meta = GpoMeta(definition.Id, definition.Title, definition.Severity,
                [definition.KeyPath + "\\" + definition.ValueName]);
            rules.Add(new GpoRegistryRule(meta, definition));
        }
        rules.Add(new GppSecretRule(GpoMeta("AD.GPO.GPP_CPASSWORD", "GPP XML contains a nonempty legacy cpassword attribute", FindingSeverity.High,
            ["cpassword-present"]) with { RequiredCapabilities = [new(CollectionCapabilities.GroupPolicyMetadata), new(CollectionCapabilities.GroupPolicySysvol, 2)] }));
        foreach (var privilege in Privileges)
            rules.Add(new GpoPrivilegeRule(GpoMeta("AD.GPO.PRIVILEGE." + privilege.ToUpperInvariant(),
                "GPO assigns " + privilege + " to a broad principal", FindingSeverity.High, ["Privilege Rights/" + privilege]) with
                { RequiredCapabilities = [new(CollectionCapabilities.GroupPolicyMetadata), new(CollectionCapabilities.GroupPolicySysvol), new(CollectionCapabilities.DirectoryDomains)] }, privilege));
        rules.Add(new GpoVersionRule(GpoMeta("AD.GPO.VERSION_MISMATCH", "LDAP and SYSVOL GPO versions differ", FindingSeverity.Low,
            ["gpo.versionNumber", "GPT.INI/General/Version"])));
        rules.AddRange(CertificateServicesRulePack.Create());
        return rules.OrderBy(r => r.Metadata.Id, StringComparer.Ordinal).ToArray();
    }

    private static RuleMetadata GpoMeta(string id, string title, FindingSeverity severity, IReadOnlyList<string> fields) =>
        RuleBase.Describe(id, title, "Stored Group Policy configuration", severity, CollectionCapabilities.GroupPolicySysvol, fields,
            "The stored policy contains a potentially unsafe configuration. Policy application, filtering, precedence, OS-specific behavior and endpoint state require separate validation.",
            "Review the named policy and its scope. Apply the organization's tested security baseline, verify resultant policy on affected endpoints and rotate any exposed credentials.", RuleSources.SecurityBaseline) with
        { RequiredCapabilities = [new(CollectionCapabilities.GroupPolicyMetadata), new(CollectionCapabilities.GroupPolicySysvol)] };
}
