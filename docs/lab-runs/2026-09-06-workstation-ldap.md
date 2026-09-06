# Workgroup workstation LDAP validation - 2026-09-06

Baseline: `f537c1c` from the user's `Z:\vs\dogfighterAD` checkout. Scanner host: Windows workstation outside MINILAB; target `dc.mini.lab` resolved to 192.168.57.30. Identity: MINILAB\alice, hidden CLI password prompt, NTLM, exact FQDN server binding. No credentials are included in this record.

## Observations

- TCP 389 and 445 were reachable. Direct native LDAP bind and RootDSE worked.
- The original published CLI reproduced setup timeouts: RootDSE completed, but directory-object/domain-metadata collectors timed out after 15 seconds. The user had also observed an earlier RootDSE setup timeout.
- A diagnostic build localized another stalled run to the directory search after successful binds. Increasing the timeout was not used as the remedy.
- Setting `LdapSessionOptions.ReferralChasing = None` before binding allowed the same CLI invocation to complete. The clean fixed build then passed three consecutive fresh-process minimal scans with identical counts and no coverage issues.
- For the later SYSVOL prerequisite check, the workstation used narrow hosts-file entries for `dc.mini.lab` and `mini.lab`, both mapped to `192.168.57.30`. This left the workstation's normal DNS server configuration unchanged.
- With that narrow name mapping, `mini.lab` resolved to `192.168.57.30` and TCP/445 succeeded from source `192.168.57.1` on the Host-Only adapter.
- `net use \\mini.lab\IPC$ /user:MINILAB\alice *` completed successfully, establishing an authenticated SMB session without placing the password on the command line.
- `net view \\mini.lab` completed successfully and advertised both `NETLOGON` and `SYSVOL` shares.
- Before an explicit IPC session to the DC FQDN, `net view \\dc.mini.lab` returned system error 5 (`Access is denied`). An explicit `net use \\dc.mini.lab\IPC$ /user:MINILAB\alice *` then completed successfully.
- Despite successful IPC authentication, `Get-ChildItem \\mini.lab\SYSVOL\mini.lab\Policies`, `Get-ChildItem \\dc.mini.lab\SYSVOL`, and `Get-ChildItem \\dc.mini.lab\SYSVOL\mini.lab\Policies` all returned `PathNotFound` / `ItemNotFoundException` on the workstation.
- Therefore SMB transport and credential acceptance are confirmed, but SYSVOL file-tree access is not. The current evidence does not yet distinguish client-side hardened-UNC behavior, server/share-name handling, or another SMB namespace condition. `audit-full` remains blocked until this is localized.

## Change and scope

The native LDAP client no longer follows referrals automatically. Existing collectors query their selected naming context on the selected server; implicit discovery/authentication to referral destinations is outside the present single-domain collection contract. Authentication mode, password prompting, TLS selection and existing timeouts are preserved.

This is a bounded collection policy, not a DNS rewrite, trust-policy relaxation or a claim of forest-wide coverage. Referrals and separate naming contexts will need an explicitly scoped collection design before multi-domain support is added. A Complete result describes the requested current capabilities in the selected context; it does not cover referred partitions. Explicit LDAP referral failures remain failures; no rule maps them to a clean security finding.

The exact named-server flag alone does not configure referral chasing. Microsoft's [LDAP hostname guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/ldap-session-takes-longer-target-host-names) covers avoiding initial locator lookups; this change separately controls follow-on referral behavior.

The evidence shows this policy change resolves the reproduced workstation workflow. It does not prove that every possible bind timeout, including unavailable servers or rejected identities, has the same cause.

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

Only minimal was tested in this workstation run. Explicit -u credentials still apply to LDAP only; audit-full requires a suitable Windows SMB security context for SYSVOL, as documented in CLI.md.
