# MINILAB readiness and live minimal runs - 2026-09-06

## Build and fixture

- Baseline: `07e8498bab081076c22c6a39ad13cca2449350bb`, foundation/snapshot-core.
- Baseline CI: https://github.com/kusotsu/dogfighterAD/actions/runs/34015154932 (success).
- Planner-fix revision: `1b460ebe33bc45eb555780ecdfd56b741c959425`.
- Scanner: Windows 11, .NET SDK 10.0.400 / runtime 10.0.11; current local user context.
- GOAD source: `992307adf944b934a3b76a2f56a637104c54b805`.
- All three VirtualBox MINILAB machines were used during the readiness/live-validation sequence. Initial target was 192.168.57.30.

## Initial readiness failure

Read-only WinRM inspection of DC initially found computer name DC, domain WORKGROUP, PartOfDomain=false, DomainRole=2. AD-Domain-Services, DNS and RSAT-AD-PowerShell were not installed. NTDS/ADWS services were absent, and C:\Windows\SYSVOL\domain did not exist. Import-Module ActiveDirectory failed. The earlier provisioning log ended during ad-servers.yml with DC unreachable and a workstation reboot already in progress.

The workstation WinRM endpoint at 192.168.57.31 responded, but rejected the configured assessment credentials. Its domain state was not verified. No password guessing was performed.

This was an unfinished-lab condition, not evidence of a clean or vulnerable functioning domain. No AD/SYSVOL fixture changes or VM restarts were performed during that validation.

## Product defect found and fixed before live collection

The original CLI exited 70 with InvalidOperationException before collection. CollectionPlanner grouped the capability-to-collector map by collector ID and called Single on each group. The directory-object collector provides four capabilities, so legitimate profiles contained repeated references to the same collector and failed planning.

Commit `1b460ebe33bc45eb555780ecdfd56b741c959425` deduplicates those references before Single. Existing registry validation still rejects duplicate registered IDs. Production-composition regressions exercise the actual CLI collector registry for minimal (5 collectors / 8 capabilities) and audit-full (9 / 12), including the multi-capability collector. CI run `34029391724` passed on Windows and Ubuntu.

## Minimal negative-path run after planner fix

```text
dogfighter scan --target 192.168.57.30 --profile minimal --output minimal.dogad
Exit: 3
Snapshot: a707c9c6-ce9d-44b9-8f2d-daf406416c36
Completion: Failed
```

| Capability | Status | Items | Issues |
| --- | --- | ---: | ---: |
| directory.core | Failed | 0 | 1 |
| directory.domains | Blocked | 0 | 1 |
| directory.users | Blocked | 0 | 1 |
| directory.groups | Blocked | 0 | 1 |
| directory.computers | Blocked | 0 | 1 |
| directory.ous | Blocked | 0 | 1 |
| directory.memberships | Blocked | 0 | 1 |
| directory.trusts | Blocked | 0 | 1 |

A separate inspect invocation successfully opened the artifact and preserved the snapshot identity and Failed status. This was negative-path evidence only.

## First live-domain minimal run

After the MINILAB domain became operational, the first real `minimal` collection reached LDAP successfully and produced a verified artifact, but correctly finished `Partial` rather than hiding incomplete data.

```text
Snapshot: 24f8fc1b-a591-4b65-9d25-29b4314ff39f
Status: Partial
Exit: 2

Objects:
domains=1 users=8 groups=50 computers=2 ous=1 memberships=0 gpos=0
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

The local `.dogad` artifact was successfully reopened through `dogfighter inspect` with the same snapshot ID. Audit-full was intentionally not run because the minimal baseline was not Complete.

### Live defect diagnosis

All 28 group issues were standard `CN=Builtin` groups. Their `objectSid` values exist in AD; for example Administrators is `S-1-5-32-544`. On the Windows LDAP path used in this run, these SID values arrived as `System.String`, while domain-group SID values arrived as `byte[]`.

`SystemLdapClient` intentionally preserves the runtime value shape as text or binary. The defect was in normalization: `LdapValueConverters.GetSid/GetSids` only inspected binary values, so valid textual SIDs were treated as missing. This made `directory.groups` Partial and, by design, blocked `directory.memberships` because group coverage is a hard prerequisite.

## Text SID normalization fix

Commit `9af8b09df281a398894f634c97a396cdfeb90df0` fixes normalization without adding attribute-specific behavior to the LDAP transport:

- SID normalization now accepts both binary SID values and a conservative canonical decimal textual SID form;
- binary and text representations are normalized to the same `S-...` representation and deduplicated;
- malformed textual values are rejected and remain explicit Partial data rather than being trusted;
- the same normalization path also applies to multi-valued SID attributes such as `sIDHistory`;
- two no-network regressions reproduce a Builtin group with `objectSid = "S-1-5-32-544"` and verify that invalid text still produces Partial coverage.

GitHub Actions run `34036771409` passed build and unit tests on both Ubuntu and Windows.

## Current conclusion

This is the first real live-AD evidence for the collection path. RootDSE, default-domain metadata, users, groups, computers, OUs and trust enumeration reached a functioning domain, and `.dogad` offline readback worked. It is **not** yet a completed minimal validation because the run used the pre-fix text-SID normalization and therefore membership collection was blocked.

No claim is made yet for live memberships, ACLs, GPO metadata/links, SYSVOL, DFS/referrals or audit-full.

## Next steps

1. Build/pull revision `9af8b09df281a398894f634c97a396cdfeb90df0` or later and repeat `minimal` against the same unchanged fixture.
2. Require `directory.groups` to become Complete unless a different real issue is exposed; confirm `directory.memberships` actually executes instead of remaining Blocked.
3. Compare object and membership counts with the known MINILAB fixture and inspect the new `.dogad` offline.
4. Only after the corrected minimal baseline is understood, run `audit-full` and validate ACL/GPO/SYSVOL behavior.
5. Keep `.dogad` artifacts and raw lab logs local; do not commit credentials or real/customer snapshots.
