# Built-in rule catalog — dogfighterad.core 1.2.0

This catalog documents **88 rule IDs** implemented in `Application/Analysis/Rules`. Use `dogfighter rules --format json` for metadata emitted by the built executable. The tables are generated from source declarations; CI also executes a rule-catalog smoke check against the built CLI.

Required fields below are concise operand descriptions. All relevant observations must also pass provenance, disposition, type, identity, time and conflict checks. The complete runtime `requiredCapabilities`/`requiredFields` are included in report summaries. See [RULE_ENGINE.md](RULE_ENGINE.md) for status meanings and caveats.

**Important:** configured GPO values, ACEs, SPNs, trust flags, delegation, AD CS template flags and directory ACLs do not by themselves prove exploitability. Positive candidates are marked `Potential` where context is unresolved. A missing field is `NotVerified`, not a negative test. AD CS runtime-dependent conditions require separate future capabilities and are not inferred from Configuration-NC evidence.

## Users (17)

| ID | Severity | Capability | Required operands / condition | Description |
| --- | --- | --- | --- | --- |
| `AD.USER.CONSTRAINED_DELEGATION` | Medium | `directory.users` | `user.userAccountControl; user.allowedToDelegateTo` | Explicit constrained-delegation targets |
| `AD.USER.DES_ONLY` | High | `directory.users` | `user.userAccountControl & 0x200000` | Account is restricted to DES keys |
| `AD.USER.EXPIRED_ENABLED` | Low | `directory.users` | `user.userAccountControl; user.accountExpires` | Enabled account with elapsed explicit expiry |
| `AD.USER.EXPLICIT_DES` | High | `directory.users` | `user.userAccountControl; user.supportedEncryptionTypes` | Explicit DES advertisement (bits 0x3) |
| `AD.USER.EXPLICIT_RC4` | Medium | `directory.users` | `user.userAccountControl; user.supportedEncryptionTypes` | Explicit RC4 advertisement (bit 0x4) |
| `AD.USER.GUEST_ENABLED` | High | `directory.users + directory.domains` | `user.userAccountControl; object.objectSid + domain.objectSid` | Exact domain Guest SID is enabled |
| `AD.USER.KRBTGT_PASSWORD_AGE` | High | `directory.users + directory.domains` | `user.userAccountControl; object.objectSid + domain.objectSid + user.pwdLastSet` | Exact domain krbtgt password-event age; disabled UAC still evaluated |
| `AD.USER.PASSWORD_AGE` | Medium | `directory.users` | `user.userAccountControl; user.pwdLastSet` | Password-event age above configured review threshold |
| `AD.USER.PASSWORD_NEVER_EXPIRES` | Medium | `directory.users` | `user.userAccountControl & 0x10000` | Password expiration is disabled on the account |
| `AD.USER.PASSWORD_NOT_REQUIRED` | High | `directory.users` | `user.userAccountControl & 0x20` | Password-not-required account flag is set |
| `AD.USER.PREAUTH_DISABLED` | High | `directory.users` | `user.userAccountControl & 0x400000` | Kerberos preauthentication is disabled |
| `AD.USER.PROTOCOL_TRANSITION` | High | `directory.users` | `user.userAccountControl & 0x1000000` | Protocol-transition delegation is configured |
| `AD.USER.REPLICATED_LOGON_AGE` | Low | `directory.users` | `user.userAccountControl; user.lastLogonTimestamp` | Replicated logon-event age above configured review threshold |
| `AD.USER.REVERSIBLE_PASSWORD_ALLOWED` | High | `directory.users` | `user.userAccountControl & 0x80` | Reversible password encryption is allowed |
| `AD.USER.SID_HISTORY` | Medium | `directory.users` | `user.userAccountControl; user.sidHistory` | Enabled user has SID history |
| `AD.USER.SPN_ACCOUNT` | Medium | `directory.users` | `user.userAccountControl; user.servicePrincipalName` | Enabled user has SPN values |
| `AD.USER.UNCONSTRAINED_DELEGATION` | High | `directory.users` | `user.userAccountControl & 0x80000` | Unconstrained delegation is configured |

## Computers (12)

| ID | Severity | Capability | Required operands / condition | Description |
| --- | --- | --- | --- | --- |
| `AD.COMPUTER.CONSTRAINED_DELEGATION` | Medium | `directory.computers` | `computer.userAccountControl; computer.allowedToDelegateTo` | Explicit constrained-delegation targets |
| `AD.COMPUTER.DES_ONLY` | High | `directory.computers` | `computer.userAccountControl & 0x200000` | Account is restricted to DES keys |
| `AD.COMPUTER.EXPLICIT_DES` | High | `directory.computers` | `computer.userAccountControl; computer.supportedEncryptionTypes` | Explicit DES advertisement (bits 0x3) |
| `AD.COMPUTER.EXPLICIT_RC4` | Medium | `directory.computers` | `computer.userAccountControl; computer.supportedEncryptionTypes` | Explicit RC4 advertisement (bit 0x4) |
| `AD.COMPUTER.PASSWORD_AGE` | Medium | `directory.computers` | `computer.userAccountControl; computer.pwdLastSet` | Password-event age above configured review threshold |
| `AD.COMPUTER.PASSWORD_NEVER_EXPIRES` | Medium | `directory.computers` | `computer.userAccountControl & 0x10000` | Password expiration is disabled on the account |
| `AD.COMPUTER.PASSWORD_NOT_REQUIRED` | High | `directory.computers` | `computer.userAccountControl & 0x20` | Password-not-required account flag is set |
| `AD.COMPUTER.PREAUTH_DISABLED` | High | `directory.computers` | `computer.userAccountControl & 0x400000` | Kerberos preauthentication is disabled |
| `AD.COMPUTER.PROTOCOL_TRANSITION` | High | `directory.computers` | `computer.userAccountControl & 0x1000000` | Protocol-transition delegation is configured |
| `AD.COMPUTER.REPLICATED_LOGON_AGE` | Low | `directory.computers` | `computer.userAccountControl; computer.lastLogonTimestamp` | Replicated logon-event age above configured review threshold |
| `AD.COMPUTER.REVERSIBLE_PASSWORD_ALLOWED` | High | `directory.computers` | `computer.userAccountControl & 0x80` | Reversible password encryption is allowed |
| `AD.COMPUTER.UNCONSTRAINED_DELEGATION` | High | `directory.computers` | `computer.userAccountControl & 0x80000` | Unconstrained delegation is configured |

## Privileged users (3)

| ID | Severity | Capability | Required operands / condition | Description |
| --- | --- | --- | --- | --- |
| `AD.PRIVILEGED.NOT_SENSITIVE` | High | `directory.users + groups + memberships + domains` | `user.userAccountControl; witnessed SID-root membership path` | Privileged enabled user lacks the sensitive/not-delegated flag |
| `AD.PRIVILEGED.PASSWORD_NEVER_EXPIRES` | High | `directory.users + groups + memberships + domains` | `user.userAccountControl; witnessed SID-root membership path` | Privileged enabled user has password expiration disabled |
| `AD.PRIVILEGED.SPN_ACCOUNT` | High | `directory.users + groups + memberships + domains` | `user.servicePrincipalName; witnessed SID-root membership path` | Privileged enabled user has SPN values |

## Domain and fine-grained policy (8)

| ID | Severity | Capability | Required operands / condition | Description |
| --- | --- | --- | --- | --- |
| `AD.POLICY.COMPLEXITY` | Medium | `directory.security-policy v1` | `policy.kind; policy.distinguishedName; policy.complexityEnabled` | Password complexity is explicitly disabled |
| `AD.POLICY.HISTORY` | Low | `directory.security-policy v1` | `policy.kind; policy.distinguishedName; policy.passwordHistoryLength` | Password history is below the configured baseline |
| `AD.POLICY.LOCKOUT_DISABLED` | Medium | `directory.security-policy v1` | `policy.kind; policy.distinguishedName; policy.lockoutThreshold` | Account lockout is explicitly disabled |
| `AD.POLICY.LOCKOUT_DURATION` | Low | `directory.security-policy v1` | `policy.kind; policy.distinguishedName; policy.lockoutDurationTicks + policy.lockoutThreshold` | Lockout duration is below the configured baseline |
| `AD.POLICY.LOCKOUT_THRESHOLD` | Low | `directory.security-policy v1` | `policy.kind; policy.distinguishedName; policy.lockoutThreshold` | Lockout threshold exceeds the configured baseline |
| `AD.POLICY.MACHINE_ACCOUNT_QUOTA` | Medium | `directory.security-policy v1` | `policy.kind; policy.distinguishedName; policy.machineAccountQuota` | The domain permits a nonzero user machine-account quota |
| `AD.POLICY.MINIMUM_LENGTH` | Medium | `directory.security-policy v1` | `policy.kind; policy.distinguishedName; policy.minimumPasswordLength` | Password policy minimum length is below the configured baseline |
| `AD.POLICY.REVERSIBLE_ENCRYPTION` | High | `directory.security-policy v1` | `policy.kind; policy.distinguishedName; policy.reversibleEncryptionEnabled` | Password policy enables reversible encryption |

## Trust configuration (4)

| ID | Severity | Capability | Required operands / condition | Description |
| --- | --- | --- | --- | --- |
| `AD.TRUST.LEGACY_TYPE` | Medium | `directory.trusts` | `trust.partner/direction/type/attributes` | Legacy down-level trust type is configured |
| `AD.TRUST.SELECTIVE_AUTHENTICATION` | Medium | `directory.trusts` | `trust.partner/direction/type/attributes` | Outbound external trust lacks the selective-authentication flag |
| `AD.TRUST.TGT_DELEGATION` | Medium | `directory.trusts` | `trust.partner/direction/type/attributes` | Cross-organization TGT delegation is explicitly enabled |
| `AD.TRUST.TREAT_AS_EXTERNAL` | Medium | `directory.trusts` | `trust.partner/direction/type/attributes` | Forest trust is configured to be treated as external for filtering |

## Directory ACLs (7)

| ID | Severity | Capability | Required operands / condition | Description |
| --- | --- | --- | --- | --- |
| `AD.ACL.BROAD_GENERIC_ALL` | High | `directory.acls v3 + directory.domains` | `parseComplete, aceCount, ordered ACE operands/type-presence` | A broad principal has an Allow ACE carrying full-control rights |
| `AD.ACL.BROAD_REPLICATION_RIGHT` | High | `directory.acls v3 + directory.domains` | `parseComplete, aceCount, ordered ACE operands/type-presence` | A broad principal has a replication-related Allow ACE on the domain |
| `AD.ACL.BROAD_RESET_PASSWORD` | High | `directory.acls v3 + directory.domains` | `parseComplete, aceCount, ordered ACE operands/type-presence` | A broad principal has an Allow ACE for password reset |
| `AD.ACL.BROAD_WRITE` | High | `directory.acls v3 + directory.domains` | `parseComplete, aceCount, ordered ACE operands/type-presence` | A broad principal has an Allow ACE carrying write-property rights |
| `AD.ACL.BROAD_WRITE_DACL` | High | `directory.acls v3 + directory.domains` | `parseComplete, aceCount, ordered ACE operands/type-presence` | A broad principal has an Allow ACE carrying WRITE_DAC |
| `AD.ACL.BROAD_WRITE_OWNER` | High | `directory.acls v3 + directory.domains` | `parseComplete, aceCount, ordered ACE operands/type-presence` | A broad principal has an Allow ACE carrying WRITE_OWNER |
| `AD.ACL.UNRESTRICTED_DACL` | High | `directory.acls v1` | `securityDescriptor.daclState` | An AD object has a null or absent DACL |

## Stored Group Policy configuration (29)

| ID | Severity | Capability | Required operands / condition | Description |
| --- | --- | --- | --- | --- |
| `AD.GPO.ALWAYS_INSTALL_ELEVATED` | High | `gpo.metadata + gpo.sysvol` | `Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated; REG_DWORD=4; ==1` | Windows Installer elevation policy is enabled |
| `AD.GPO.AUTOMATIC_UPDATES_DISABLED` | Low | `gpo.metadata + gpo.sysvol` | `Software\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate; REG_DWORD=4; ==1` | GPO disables automatic updates in this policy setting |
| `AD.GPO.CREDSSP_ORACLE` | High | `gpo.metadata + gpo.sysvol` | `Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\AllowEncryptionOracle; REG_DWORD=4; ==2` | GPO selects the vulnerable CredSSP compatibility mode |
| `AD.GPO.DEFENDER_REALTIME_DISABLED` | High | `gpo.metadata + gpo.sysvol` | `Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring; REG_DWORD=4; ==1` | GPO requests disabling Defender real-time monitoring |
| `AD.GPO.GPP_CPASSWORD` | High | `gpo.metadata + gpo.sysvol v2+` | `cpassword-present` | Nonempty GPP cpassword signal, no secret export |
| `AD.GPO.INSECURE_GUEST_LOGONS` | Medium | `gpo.metadata + gpo.sysvol` | `Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth; REG_DWORD=4; ==1` | GPO allows insecure SMB guest logons |
| `AD.GPO.LDAP_CHANNEL_BINDING` | Medium | `gpo.metadata + gpo.sysvol` | `System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding; REG_DWORD=4; ==0` | GPO explicitly disables LDAP channel-binding enforcement |
| `AD.GPO.LDAP_SIGNING` | High | `gpo.metadata + gpo.sysvol` | `System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity; REG_DWORD=4; <2` | GPO does not require LDAP server signing in this legacy setting |
| `AD.GPO.LM_HASH_STORAGE` | High | `gpo.metadata + gpo.sysvol` | `System\CurrentControlSet\Control\Lsa\NoLMHash; REG_DWORD=4; ==0` | GPO permits legacy LM hash storage |
| `AD.GPO.LOCAL_ACCOUNT_TOKEN_FILTER` | High | `gpo.metadata + gpo.sysvol` | `Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy; REG_DWORD=4; ==1` | GPO relaxes remote local-account token filtering |
| `AD.GPO.LSA_PROTECTION_DISABLED` | Medium | `gpo.metadata + gpo.sysvol` | `System\CurrentControlSet\Control\Lsa\RunAsPPL; REG_DWORD=4; ==0` | GPO disables configured LSA protected-process mode |
| `AD.GPO.NTLM_COMPATIBILITY` | Medium | `gpo.metadata + gpo.sysvol` | `System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel; REG_DWORD=4; <5` | GPO configures an NTLM compatibility level below 5 |
| `AD.GPO.PRIVILEGE.SEBACKUPPRIVILEGE` | High | `gpo.metadata + gpo.sysvol + directory.domains` | `Privilege Rights/SeBackupPrivilege; stored SID list` | Broad-principal privilege assignment in stored GPO |
| `AD.GPO.PRIVILEGE.SEDEBUGPRIVILEGE` | High | `gpo.metadata + gpo.sysvol + directory.domains` | `Privilege Rights/SeDebugPrivilege; stored SID list` | Broad-principal privilege assignment in stored GPO |
| `AD.GPO.PRIVILEGE.SEIMPERSONATEPRIVILEGE` | High | `gpo.metadata + gpo.sysvol + directory.domains` | `Privilege Rights/SeImpersonatePrivilege; stored SID list` | Broad-principal privilege assignment in stored GPO |
| `AD.GPO.PRIVILEGE.SELOADDRIVERPRIVILEGE` | High | `gpo.metadata + gpo.sysvol + directory.domains` | `Privilege Rights/SeLoadDriverPrivilege; stored SID list` | Broad-principal privilege assignment in stored GPO |
| `AD.GPO.PRIVILEGE.SERESTOREPRIVILEGE` | High | `gpo.metadata + gpo.sysvol + directory.domains` | `Privilege Rights/SeRestorePrivilege; stored SID list` | Broad-principal privilege assignment in stored GPO |
| `AD.GPO.PRIVILEGE.SETAKEOWNERSHIPPRIVILEGE` | High | `gpo.metadata + gpo.sysvol + directory.domains` | `Privilege Rights/SeTakeOwnershipPrivilege; stored SID list` | Broad-principal privilege assignment in stored GPO |
| `AD.GPO.PRIVILEGE.SETCBPRIVILEGE` | High | `gpo.metadata + gpo.sysvol + directory.domains` | `Privilege Rights/SeTcbPrivilege; stored SID list` | Broad-principal privilege assignment in stored GPO |
| `AD.GPO.RDP_NLA_DISABLED` | Medium | `gpo.metadata + gpo.sysvol` | `Software\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication; REG_DWORD=4; ==0` | GPO disables the RDP NLA requirement |
| `AD.GPO.RDP_SECURITY_LAYER` | Medium | `gpo.metadata + gpo.sysvol` | `Software\Policies\Microsoft\Windows NT\Terminal Services\SecurityLayer; REG_DWORD=4; <2` | GPO does not require the RDP TLS security layer |
| `AD.GPO.SMB1_ENABLED` | High | `gpo.metadata + gpo.sysvol` | `System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1; REG_DWORD=4; ==1` | GPO enables SMB1 server configuration |
| `AD.GPO.SMB_CLIENT_SIGNING` | High | `gpo.metadata + gpo.sysvol` | `System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature; REG_DWORD=4; ==0` | GPO does not require SMB client signing |
| `AD.GPO.SMB_SERVER_SIGNING` | High | `gpo.metadata + gpo.sysvol` | `System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature; REG_DWORD=4; ==0` | GPO does not require SMB server signing |
| `AD.GPO.UAC_DISABLED` | High | `gpo.metadata + gpo.sysvol` | `Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA; REG_DWORD=4; ==0` | GPO disables User Account Control |
| `AD.GPO.VERSION_MISMATCH` | Low | `gpo.metadata + gpo.sysvol` | `gpo.versionNumber + GPT.INI/General/Version` | LDAP/SYSVOL version discrepancy; not tampering proof |
| `AD.GPO.WDIGEST_CACHING` | High | `gpo.metadata + gpo.sysvol` | `System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential; REG_DWORD=4; ==1` | GPO enables WDigest logon-credential caching |
| `AD.GPO.WINRM_BASIC` | Medium | `gpo.metadata + gpo.sysvol` | `Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic; REG_DWORD=4; ==1` | GPO enables WinRM service Basic authentication |
| `AD.GPO.WINRM_UNENCRYPTED` | High | `gpo.metadata + gpo.sysvol` | `Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic; REG_DWORD=4; ==1` | GPO permits unencrypted WinRM service traffic |

## Certificate Services / AD CS (8)

The 0.3.2 rules are **directory-posture rules**. The collector reads Configuration-NC objects and DACLs only. Runtime CA registry/RPC/web-enrollment/EPA/NTLM/issuance state is not part of these predicates.

| ID | Severity | Capability | Required operands / condition | Description |
| --- | --- | --- | --- | --- |
| `ADCS.TEMPLATE.ESC1_CANDIDATE` | High | `adcs.templates + adcs.publication + adcs.acls + directory.users v2 + groups + memberships v3 + domains` | published; low-priv Enrollment; authentication purpose; enrollee supplies subject; no approval; zero authorized signatures | **Potential** ESC1-like directory candidate; not runtime-verified ESC1 |
| `ADCS.TEMPLATE.DANGEROUS_ACL` | High | `adcs.templates + adcs.acls + directory users/groups/memberships/domains` | fully parsed DACL; low-priv GenericAll/GenericWrite/WriteDacl/WriteOwner/unrestricted WriteProperty | Potential low-priv template control path |
| `ADCS.TEMPLATE.BROAD_ENROLLMENT` | Medium | `adcs.templates + adcs.acls + directory users/groups/memberships/domains` | low-priv Enrollment or AutoEnrollment grant | Enrollment exposure posture; not privilege escalation by itself |
| `ADCS.TEMPLATE.AUTHENTICATION_CAPABLE` | Informational | `adcs.templates` | authentication-capable EKU/application policy | Authentication-relevant template purpose posture |
| `ADCS.TEMPLATE.ENROLLEE_SUPPLIES_SUBJECT` | Low | `adcs.templates` | `msPKI-Certificate-Name-Flag` enrollee-supplies-subject bit | Subject-name supply posture |
| `ADCS.TEMPLATE.NO_APPROVAL` | Informational | `adcs.templates` | `msPKI-Enrollment-Flag` lacks pending/manager-approval bit | No directory-observed manager-approval gate |
| `ADCS.TEMPLATE.NO_AUTHORIZED_SIGNATURE` | Informational | `adcs.templates` | `msPKI-RA-Signature == 0` | No authorized-signature gate |
| `ADCS.CA.DANGEROUS_DIRECTORY_ACL` | High | `adcs.authorities + adcs.acls + directory users/groups/memberships/domains` | fully parsed CA directory DACL; low-priv dangerous write/control grant | Potential control of the `pKIEnrollmentService` directory object only |

### Low-privilege trustee proof

The AD CS ACL rules do not equate every unknown SID with low privilege. Well-known broad principals are recognized, and custom group trustees require evidence-backed membership analysis. Nested group membership uses the existing membership proof engine; if the member scope is incomplete, a negative broad-enrollment/control conclusion is not manufactured. A custom enrollment group containing a proven privileged-only user is not treated as a low-privilege trustee merely because the group name looks generic.

### ESC1 candidate boundary

`ADCS.TEMPLATE.ESC1_CANDIDATE` requires all implemented directory prerequisites. A match is emitted as `Potential` with explicit text that CA runtime policy, `EDITF_ATTRIBUTESUBJECTALTNAME2`, RPC/service permissions, web enrollment, EPA/NTLM behavior, issuance behavior, deny precedence and exploitability were not verified. Those checks require separate future read-only capability IDs.

## Primary references

- [UserAccountControl flags](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties).
- [Fine-grained password policy properties](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adfinegrainedpasswordpolicy).
- [Machine-account quota schema](https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota).
- [Trust attributes — MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c).
- [ACE ordering](https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl) and [null versus empty DACL](https://learn.microsoft.com/en-us/windows/win32/ad/null-dacls-and-empty-dacls).
- [Security template registry values — MS-GPSB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/3a14ca47-a22f-43c5-b35e-6be791003ca7).
- [Certificate template protocol documentation — MS-CRTD](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/).
- [Active Directory extended rights](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights).

References describe platform semantics. This pack is not certified compliance with every current Microsoft/CIS baseline. Match the policy file and applicability to the actual environment.

## Proof-backed absence, pack 1.1.0+

Requested LDAP omissions remain `NotVerified` unless the collector persisted a validated read-access/absence proof. Confirmed empty SPN, SID history or delegation lists yield `NotDetected` for their presence predicates. Confirmed unset encryption configuration yields `NotApplicable` for explicit-mask rules; no effective cipher is inferred. Confirmed absent replicated-logon timestamps yield `NotApplicable` for age measurement, not a never-logged-on assertion. Membership v3 can certify an omitted `member` attribute as an empty direct-member set only when its proof is coherent. See RULE_ENGINE.md for the exact gates.

## AD CS addition, pack 1.2.0

Pack 1.2.0 adds the eight `ADCS.*` rules above and raises the built-in catalog from 80 to 88 IDs. The AD CS rule slice itself is exposed by `CertificateServicesRulePack` version `1.1.0`; the overall report still records the built-in pack as `dogfighterad.core/1.2.0`.
