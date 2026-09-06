# Workgroup workstation LDAP validation - 2026-09-06

Baseline: `f537c1c` from the user's `Z:\vs\dogfighterAD` checkout. Scanner host: Windows workstation outside MINILAB; target `dc.mini.lab` resolved to 192.168.57.30. Identity: MINILAB\alice, hidden CLI password prompt, NTLM, exact FQDN server binding. No credentials are included in this record.

## Observations

- TCP 389 and 445 were reachable. Direct native LDAP bind and RootDSE worked.
- The original published CLI reproduced setup timeouts: RootDSE completed, but directory-object/domain-metadata collectors timed out after 15 seconds. The user had also observed an earlier RootDSE setup timeout.
- A diagnostic build localized another stalled run to the directory search after successful binds. Increasing the timeout was not used as the remedy.
- Setting `LdapSessionOptions.ReferralChasing = None` before binding allowed the same CLI invocation to complete. The clean fixed build then passed three consecutive fresh-process minimal scans with identical counts and no coverage issues.
- For the later SYSVOL prerequisite check, the workstation used narrow hosts-file entries for `dc.mini.lab` and `mini.lab`, both mapped to `192.168.57.30`. This left the workstation's normal DNS server configuration unchanged.
- With that narrow name mapping, `mini.lab` resolved to `192.168.57.30` and TCP/445 succeeded from source `192.168.57.1` on the Host-Only adapter.
- `net use \\mini.lab\IPC$ /user:MINILAB\alice *` completed successfully, establishing an SMB IPC session without placing the password on the command line.
- `net view \\mini.lab` completed successfully and advertised both `NETLOGON` and `SYSVOL` shares.
- Before an explicit IPC session to the DC FQDN, `net view \\dc.mini.lab` returned system error 5 (`Access is denied`). An explicit `net use \\dc.mini.lab\IPC$ /user:MINILAB\alice *` then completed successfully.
- Despite successful IPC setup, `Get-ChildItem \\mini.lab\SYSVOL\mini.lab\Policies`, `Get-ChildItem \\dc.mini.lab\SYSVOL`, and `Get-ChildItem \\dc.mini.lab\SYSVOL\mini.lab\Policies` all returned `PathNotFound` / `ItemNotFoundException` on the primary workstation.
- The same SMB/SYSVOL checks were repeated from a separate ordinary Windows VM. On that VM, both `net view \\dc.mini.lab` and `net view \\mini.lab` advertised `NETLOGON` and `SYSVOL`; explicit IPC setup succeeded; both `\\dc.mini.lab\SYSVOL\mini.lab\Policies` and `\\mini.lab\SYSVOL\mini.lab\Policies` were readable; the two default GPO directories were present; and both GPO roots contained `MACHINE`, `USER`, and `GPT.INI`.
- This comparison confirms that the DC-side SYSVOL share, policy directories, domain-style SYSVOL authority, and Alice SMB access are functional from a suitable Windows client. The unresolved failure is specific to the primary workstation's Windows SMB/UNC client environment.
- No scanner fallback or SYSVOL scope relaxation is justified by this result: the primary workstation cannot open even the direct `\\dc.mini.lab\SYSVOL` share root, while the same path works from the VM.
- The primary workstation is a workgroup machine (`Name=MAIN`, `PartOfDomain=False`, `Domain=WORKGROUP`). The policy registry path `HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths` is absent.
- Absence of that registry path does **not** mean SYSVOL/NETLOGON UNC hardening is disabled. Microsoft documents that Windows 10 / Windows Server 2016 and later apply hardened UNC behavior for these shares by default; the registry values can be absent while the default hardening rules still apply. Microsoft also documents that UNC hardening for SYSVOL/NETLOGON requires SMB signing and mutual authentication such as Kerberos. See: https://learn.microsoft.com/en-us/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10 and https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview.
- `Get-SmbConnection` on MAIN showed IPC connections to both `dc.mini.lab` and `mini.lab` as `UserName=MAIN\del1m`, SMB dialect 3.1.1, signed and not encrypted, even after an explicit `net use ... /user:MINILAB\alice *` command reported success. This is evidence that the local SMB session/authentication context is not behaving like the successful VM path; it is not by itself proof of which Windows authentication mechanism is ultimately selected for every tree connect.
- An explicit tree connect `net use \\dc.mini.lab\SYSVOL /user:MINILAB\alice *` returned system error 5 (`Access is denied`). The equivalent `net use \\mini.lab\SYSVOL /user:MINILAB\alice *` returned system error 67 (`The network name cannot be found`).
- A fresh `runas /netonly /user:MINILAB\alice powershell.exe` session on MAIN still could not read either `\\dc.mini.lab\SYSVOL\mini.lab\Policies` or `\\mini.lab\SYSVOL\mini.lab\Policies`; both returned `PathNotFound`. Therefore merely moving the explicit domain identity into a network-only logon session did not satisfy the MAIN workstation's SYSVOL path requirements.
- In that network-only session, TCP/88 to `dc.mini.lab` succeeded from `192.168.57.1`, so the Kerberos service port itself was reachable. However, `klist` showed zero cached tickets and `klist get cifs/dc.mini.lab` failed (`LsaCallAuthenticationPackage` 0x51f; `klist` 0xc000005e), so MAIN did not obtain a CIFS service ticket for the DC.
- The comparison VM is domain joined: `Name=WS`, `PartOfDomain=True`, `Domain=mini.lab`. It is the same client on which both direct-DC and domain-style SYSVOL paths were readable.
- Taken together, the live comparison supports a client authentication-context split rather than a DC/SYSVOL defect: MAIN can reach LDAP/SMB/Kerberos ports and can use explicit NTLM for LDAP, but it lacks a usable Kerberos ticket context for the hardened SYSVOL access path; the domain-joined WS VM has the required domain context and reads SYSVOL successfully. TCP/88 reachability alone therefore does not make the workgroup `/netonly` session equivalent to a domain logon.
- Do not disable UNC hardening, weaken SMB signing, or relax scanner SYSVOL scope to make MAIN pass. The next product validation gate is `audit-full` from the domain-joined WS VM, where the manual SYSVOL prerequisite is already proven.

## Change and scope

The native LDAP client no longer follows referrals automatically. Existing collectors query the selected naming context on the selected server; implicit discovery/authentication to referral destinations is outside the present single-domain collection contract. Authentication mode, password prompting, TLS selection and existing timeouts are preserved.

This is a bounded collection policy, not a DNS rewrite, trust-policy relaxation or a claim of forest-wide coverage. Referrals and separate naming contexts will need an explicitly scoped collection design before multi-domain support is added. A Complete result describes the requested current capabilities in the selected context; it does not cover referred partitions. Explicit LDAP referral failures remain failures; no rule maps them to a clean security finding.

The exact named-server flag alone does not configure referral chasing. Microsoft's [LDAP hostname guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/ldap-session-takes-longer-target-host-names) covers avoiding initial locator lookups; this change separately controls follow-on referral behavior.

The evidence shows the referral policy change resolves the reproduced LDAP workstation workflow. It does not prove that every possible bind timeout, including unavailable servers or rejected identities, has the same cause.

## Results

| Data | Count |
| --- | ---: |
| Domains | 1 |
| Users | 8 |
| Groups | 50 |
| Computers | 2 |
| OUs | 1 |
| Memberships | 41 |
| Configured trusts | 0 |

All eight minimal capabilities: Complete, zero issues. Process exit: 0. Raw artifacts/logs remain local; they are not committed.

Two Windows-only tests verify the native session has referral chasing disabled before Bind for both configured TLS modes. They make no network requests and do not claim TLS endpoint validation. Linux CI skips these platform-specific checks while running the portable suite.

Only minimal was tested in this workstation run. Explicit `-u` credentials still apply to LDAP only; `audit-full` requires a suitable Windows SMB security context for SYSVOL, as documented in CLI.md. The ordinary VM has now passed the manual SYSVOL prerequisite for both the DC FQDN and domain-style UNC authorities; MAIN has not.
