# MINILAB readiness and negative-path run - 2026-09-06

## Build and fixture

- Baseline: `07e8498bab081076c22c6a39ad13cca2449350bb`, foundation/snapshot-core.
- Baseline CI: https://github.com/kusotsu/dogfighterAD/actions/runs/34015154932 (success).
- Tested revision: baseline plus the planner fix and production-composition regression tests in this commit.
- Scanner: Windows 11, .NET SDK 10.0.400 / runtime 10.0.11; current local user context, not an established domain assessment identity.
- GOAD source: `992307adf944b934a3b76a2f56a637104c54b805`.
- All three VirtualBox MINILAB machines were running. Target: 192.168.57.30.

## Readiness failure

Read-only WinRM inspection of DC found computer name DC, domain WORKGROUP, PartOfDomain=false, DomainRole=2. AD-Domain-Services, DNS and RSAT-AD-PowerShell are not installed. NTDS/ADWS services were absent, and C:\Windows\SYSVOL\domain did not exist. Import-Module ActiveDirectory failed. The earlier provisioning log ended during ad-servers.yml with DC unreachable and a workstation reboot already in progress.

The workstation WinRM endpoint at 192.168.57.31 responded, but rejected the configured assessment credentials. Its domain state was not verified. No password guessing was performed.

This is an unfinished lab, not evidence of a clean or vulnerable functioning domain. No AD/SYSVOL fixture changes or VM restarts were performed during this validation.

## Product defect found and fixed

The original CLI exited 70 with InvalidOperationException before collection. CollectionPlanner grouped the capability-to-collector map by collector ID and called Single on each group. The directory-object collector provides four capabilities, so legitimate profiles contained repeated references to the same collector and failed planning.

The fix deduplicates those references before Single. Existing registry validation still rejects duplicate registered IDs. Two new no-network tests exercise the actual CLI collector registry for minimal (5 collectors / 8 capabilities) and audit-full (9 / 12), including the multi-capability collector.

Before fix: 122 tests, 2 failures. After fix: 122 passed, no failures or skips locally on Windows. Existing baseline was 120 passing tests, which did not cover planning the production registry.

## Minimal negative-path run after fix

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

A separate inspect invocation successfully opened the artifact and preserved the snapshot identity and Failed status (exit 3 intentionally describes snapshot completion, not a reader failure). This inspect ran in the restricted local context; VM adapters were not disconnected, so physical network-isolation testing is not claimed.

No expected-versus-actual domain count comparison is possible before provisioning. Audit-full was not run against the unfinished lab. This is negative-path evidence only, not completed MINILAB integration validation.

## Next steps

1. Complete GOAD provisioning and verify the DC role, DNS SRV records, SYSVOL, planted objects and workstation domain membership.
2. Establish an authorized domain security context for the scanner.
3. Repeat minimal, compare known fixtures, then audit-full and offline readback using MINILAB_RUNBOOK.md.
4. Continue with controlled partial-access cases and larger GOAD only after baseline is understood.

Artifacts and raw logs stay local under outputs/minilab-2026-09-06; no .dogad files or credential values are committed.
