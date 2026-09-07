# MINILAB readiness and live collection runs - 2026-09-06

## Build and fixture

- Branch: `foundation/snapshot-core`.
- Original readiness baseline: `07e8498bab081076c22c6a39ad13cca2449350bb`.
- GOAD source used for the lab: `992307adf944b934a3b76a2f56a637104c54b805`.
- Scanner development host: Windows 11, .NET SDK 10.0.400 / runtime 10.0.11.
- MINILAB DC Host-Only address observed during remote-workstation validation: `192.168.57.30/24`.
- No credential values are recorded in this document or committed to the repository.

This record is evidence-oriented. Unobserved process exit codes or successful states are not inferred from snapshot status.

## Initial readiness failure

Read-only inspection of the DC initially found computer name DC, domain WORKGROUP, `PartOfDomain=false`, `DomainRole=2`. AD-Domain-Services, DNS and RSAT-AD-PowerShell were not installed. NTDS/ADWS services were absent and `C:\Windows\SYSVOL\domain` did not exist. The earlier provisioning log had ended with the DC unreachable.

This was an unfinished-lab condition, not evidence about the security state of a functioning domain.

## Planner defect found before live collection

The original CLI exited before collection because `CollectionPlanner` grouped the capability-to-collector map by collector ID and called `Single` on each group. The directory-object collector legitimately provides multiple capabilities, so valid profiles contained repeated references to the same collector.

Commit `1b460ebe33bc45eb555780ecdfd56b741c959425` deduplicated those references while retaining duplicate registered-ID validation. Production-composition tests cover the real minimal and audit-full collector registries.

## Minimal negative-path run

Before AD provisioning was complete, a minimal run produced a valid Failed artifact:

```text
Target: 192.168.57.30
Exit: 3
Snapshot: a707c9c6-ce9d-44b9-8f2d-daf406416c36
Status: Failed
```

`directory.core` was Failed and all dependent minimal capabilities were Blocked. A separate `inspect` successfully reopened the artifact and preserved snapshot identity/status. This is negative-path evidence only.

## First functioning-domain minimal run

After the MINILAB domain became operational, the first real minimal collection reached LDAP and produced a verified artifact but correctly finished Partial:

```text
Snapshot: 24f8fc1b-a591-4b65-9d25-29b4314ff39f
Status: Partial
Exit: 2
Objects: domains=1 users=8 groups=50 computers=2 ous=1 memberships=0 gpos=0
```

| Capability | Status | Items | Issues |
| --- | --- | ---: | ---: |
| directory.computers | Complete | 2 | 0 |
| directory.core | Complete | 1 | 0 |
| directory.domains | Complete | 1 | 0 |
| directory.groups | Partial | 50 | 28 |
| directory.memberships | Blocked | 0 | 1 |
| directory.ous | Complete | 1 | 0 |
| directory.trusts | Complete | 0 | 0 |
| directory.users | Complete | 8 | 0 |

All 28 group issues corresponded to standard `CN=Builtin` groups. The first attempted normalization fix (`9af8b09df281a398894f634c97a396cdfeb90df0`) allowed textual SDDL-like SIDs, but a fresh live rerun still produced the same 28 issues. That disproved the stale-binary hypothesis.

The actual transport cause was `System.DirectoryServices.Protocols.DirectoryAttribute.Item[Int32]` coercing some binary SID values to strings. Commit `49699b7d050fb32f096f3809f19daca6fb7218b8` changed known binary LDAP attributes (`objectGUID`, `objectSid`, `sIDHistory`, `securityIdentifier`, `nTSecurityDescriptor`) to use `GetValues(typeof(byte[]))`.

## Completed MINILAB minimal baseline

A fresh live run after the binary LDAP transport fix completed all requested minimal capabilities:

```text
Snapshot: 063d8d70-b63b-47a1-8b5b-f4391f564aac
Status: Complete
Profile: minimal
Target: dc.mini.lab
Objects: domains=1 users=8 groups=50 computers=2 ous=1 memberships=41 gpos=0
```

| Capability | Status | Items | Issues |
| --- | --- | ---: | ---: |
| directory.computers | Complete | 2 | 0 |
| directory.core | Complete | 1 | 0 |
| directory.domains | Complete | 1 | 0 |
| directory.groups | Complete | 50 | 0 |
| directory.memberships | Complete | 41 | 0 |
| directory.ous | Complete | 1 | 0 |
| directory.trusts | Complete | 0 | 0 |
| directory.users | Complete | 8 | 0 |

`inspect` reopened the artifact with the same snapshot ID and status. The scan exit code was not captured immediately after this run and is therefore not recorded as an observed value.

This closes the live MINILAB `minimal` baseline for the current fixture.

## First audit-full live run

The first `audit-full` run produced:

```text
Snapshot: 7916c9f9-3293-4e65-ba15-10c1e7ddb905
Status: Partial
Profile: audit-full
Target: dc.mini.lab
Objects: domains=1 users=8 groups=50 computers=2 ous=1 memberships=41 gpos=2
```

| Capability | Status | Items | Issues |
| --- | --- | ---: | ---: |
| directory.acls | Partial | 62 | 2 |
| directory.computers | Complete | 2 | 0 |
| directory.core | Complete | 1 | 0 |
| directory.domains | Complete | 1 | 0 |
| directory.groups | Complete | 50 | 0 |
| directory.memberships | Complete | 41 | 0 |
| directory.ous | Complete | 1 | 0 |
| directory.trusts | Complete | 0 | 0 |
| directory.users | Complete | 8 | 0 |
| gpo.links | Partial | 2 | 2 |
| gpo.metadata | Complete | 2 | 0 |
| gpo.sysvol | Partial | 0 | 2 |

The scan exit code was not captured immediately after this run and is not inferred.

### Audit-full issues observed

`directory.acls` reported two `collection.acls.unexpected-target` issues for:

- `DC=DomainDnsZones,DC=mini,DC=lab`
- `DC=ForestDnsZones,DC=mini,DC=lab`

`gpo.links` reported two `collection.gpo.links.unknown-container` issues for the same DNS application partitions.

`gpo.sysvol` reported `collection.gpo.sysvol.enumeration-failed` / `IOException` for both default GPOs:

- `{31B2F340-016D-11D2-945F-00C04FB984F9}`
- `{6AC1786C-016F-11D2-945F-00C04FB984F9}`

The corresponding policy directories were directly enumerable on the DC, proving the observed SYSVOL failure was not simply a missing policy path.

### ACL/GPO scope fixes

The ACL and GPO-link collectors had subtree searches that matched every `domainDNS` object below the default naming context, including DNS application partitions that are not represented as the prerequisite snapshot domain.

The live fix pins the intended domain object by its already-collected `objectGUID` while retaining the required subtree object classes:

- `196077aba073e2c6128aaa6fe0577c62db99ac55` - LDAP GUID octet filter encoding.
- `21d7ea3913397654530755601ea639cfc518141b` - ACL domain scope pinned to snapshot domain GUID.
- `2fa3c8f24e32fee8f756fb070e1a89757ae8d5e9` - GPO-link domain scope pinned to snapshot domain GUID.
- `fa09ca2f0fa1af1826fbe896cc312c61c6ce907c` - regression coverage for the DNS application-partition scope issue.

### SYSVOL packaging defect and fix

Direct execution of the originally deployed worker on the DC failed because `DogfighterAD.SysvolWorker.dll` was absent. Direct `Get-ChildItem` against both GPO SYSVOL paths succeeded. This established a deployment/package defect rather than an SMB/path-access failure for that run.

Fixes:

- `0c37721a536f72da2e5a714fd33082509a6f86cb` publishes the SYSVOL worker into the CLI publish output with the same Configuration/RID/SelfContained settings.
- `bc0626a4866d287e03655bcf1baae83f755ffa97` adds a Windows self-contained publish smoke that verifies worker files and executes the worker with redirected empty stdin.

CI validated the self-contained Windows worker deployment. A fresh audit-full live rerun is still required before claiming the audit-full baseline is Complete.

## Remote workstation connectivity observations

The next validation moved scanner execution off the DC onto a Windows workstation.

Observed host-only path:

```text
Workstation: 192.168.57.1/24 (Ethernet 3)
DC:          192.168.57.30/24
TCP/389:     reachable
TCP/445:     reachable
Ping:        reachable
```

Direct DNS queries from the workstation to `192.168.57.30:53` timed out and TCP/53 was not reachable, while the DC itself successfully resolved `dc.mini.lab` through both `127.0.0.1` and `192.168.57.30`. The DC DNS answer contained both `192.168.57.30` and `10.0.2.15`, plus IPv6 addresses. UDP/53 was observed listening on `192.168.57.30` locally.

Narrow inbound DNS firewall rules were added on the isolated lab DC for `192.168.57.0/24`, but the workstation's direct DNS query still timed out. The underlying DNS/firewall/network-policy issue is therefore not recorded as resolved.

A controlled hosts-file entry for `dc.mini.lab -> 192.168.57.30` allowed the workstation to address the DC by FQDN for the subsequent LDAP test. The separate `mini.lab` SYSVOL/domain name still requires working resolution before a remote `audit-full` run can be considered valid.

## First explicit LDAP credential run from workstation

An initial explicit credential feature used `-u <user> -p`, where `-p` was only a hidden-prompt switch. The password itself was not supplied in CLI arguments and is not recorded.

Live command form:

```text
dogfighter scan --target dc.mini.lab --profile minimal -u MINILAB\alice -p ...
```

Observed result:

```text
Snapshot: 7a798436-f151-4d92-b421-0d6de0d1e56b
Status: Failed
Exit: 3
Objects: domains=0 users=0 groups=0 computers=0 ous=0 memberships=0 gpos=0
```

`directory.core` was Failed with one issue and all dependent capabilities were Blocked. At that revision the default summary only printed issue counts, while `CollectionExecutor` converted unexpected collector exceptions into generic `collection.collector.failed`. Therefore the live evidence does **not** establish whether this particular failure was bad credentials, Negotiate prerequisites, target/name behavior or another LDAP error. No cause is guessed here.

A follow-up explicit-credential attempt using the DC IP literal did not return promptly. No successful/failed snapshot result was captured for that attempt. This exposed two product problems relevant to live validation: ambiguous explicit Negotiate behavior by IP and insufficient timeout/diagnostic visibility.

## Explicit LDAP auth/diagnostic hardening after workstation run

The current branch now changes the explicit credential contract and diagnostics based on those observations:

- `-u/--username` automatically opens the hidden password prompt; `-p` has been removed as a supported flag.
- Password options and inline/following password values are rejected without echoing the value.
- Explicit Negotiate credentials require a DNS hostname target; an IP literal with `-u` is rejected before prompting/network collection.
- The hidden prompt is cancellation-aware instead of blocking permanently in `Console.ReadKey`.
- The LDAP connection now receives the configured 30-second `LdapConnection.Timeout` in addition to the existing request timeout and profile-level collector timeout.
- Exceptions from both `BeginSendRequest` and `EndSendRequest` are classified when they are LDAP/Directory operation failures.
- A safe operational-failure contract carries only a controlled issue code/message into snapshot coverage; raw inner exception/server text remains runtime-only.
- LDAP diagnostics classify authentication failures (including numeric code 49), connection/server unavailability, timeout, stronger-security requirements and generic LDAP failures.
- The CLI summary and offline `inspect` now print each snapshot issue's severity, code and message beneath the capability row, so a Failed RootDSE is diagnosable without opening internal exception data.
- Regression tests include password-canary non-leakage, IP-target rejection, safe LDAP failure classification, safe operational-failure propagation and CLI issue-detail rendering.

`docs/CLI.md` and `docs/MINILAB_RUNBOOK.md` contain the new invocation and diagnostic behavior.

## Current state and next live gate

The MINILAB minimal baseline on the DC is Complete. The first audit-full run exposed understood ACL/GPO scope and SYSVOL packaging defects; fixes are implemented and CI-covered, but the corrected audit-full live rerun has not yet been recorded.

The workstation explicit-credential path has one real Failed FQDN run from the pre-diagnostic revision and one non-returning IP attempt. The exact cause of the FQDN failure remains unknown until the current diagnostic build is rerun against the same authorized account.

The next remote-workstation gate is:

1. build/publish the current `foundation/snapshot-core` revision;
2. ensure `dc.mini.lab` resolves to the reachable lab DC address;
3. run `minimal` with `-u 'MINILAB\alice'` (no `-p`), capture the complete issue detail output and `$LASTEXITCODE` immediately;
4. do not use an IP literal with explicit credentials; the current parser must reject it;
5. if minimal succeeds, establish/verify an authorized OS-level SMB context and working resolution for `mini.lab`, then run corrected `audit-full` from the workstation;
6. record the fresh audit-full snapshot ID, exit, counts, issue codes/messages and offline inspect result before making any Complete claim.

No real/customer `.dogad` artifacts, passwords or credential values are committed to the repository.
