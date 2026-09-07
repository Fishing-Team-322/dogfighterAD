# Live lab run record template

Copy this file to a dated/name-specific record such as `2026-09-06-minilab.md`. Do not put passwords, tickets, customer data or real secret values in the record.

## Build and fixture

```text
Date/time UTC:
DogfighterAD commit SHA:
CI run confirming build/tests:
.NET SDK/runtime:
Scanner host OS:
Lab name:
Lab version/commit/snapshot:
Collection identity (name only):
Target:
```

## Expected fixture facts

```text
Expected domains:
Expected users:
Expected groups:
Expected computers:
Expected OUs:
Expected memberships / special cases:
Expected configured trusts:
Expected GPOs/links:
Expected SYSVOL policy cases:
Expected ACL cases:
```

## Minimal run

```text
Command:
Exit code:
Snapshot ID:
Completion status:
Artifact path (lab-local only):
Offline inspect succeeded: yes/no
```

| Capability | Status | Items | Issues | Note |
| --- | --- | ---: | ---: | --- |
| directory.core |  |  |  |  |
| directory.domains |  |  |  |  |
| directory.users |  |  |  |  |
| directory.groups |  |  |  |  |
| directory.computers |  |  |  |  |
| directory.ous |  |  |  |  |
| directory.memberships |  |  |  |  |
| directory.trusts |  |  |  |  |

## Audit-full run

```text
Command:
Exit code:
Snapshot ID:
Completion status:
Artifact path (lab-local only):
Offline inspect succeeded: yes/no
Explicit additional SYSVOL authorities:
```

| Capability | Status | Items | Issues | Note |
| --- | --- | ---: | ---: | --- |
| directory.core |  |  |  |  |
| directory.domains |  |  |  |  |
| directory.users |  |  |  |  |
| directory.groups |  |  |  |  |
| directory.computers |  |  |  |  |
| directory.ous |  |  |  |  |
| directory.memberships |  |  |  |  |
| directory.trusts |  |  |  |  |
| directory.acls |  |  |  |  |
| gpo.metadata |  |  |  |  |
| gpo.links |  |  |  |  |
| gpo.sysvol |  |  |  |  |

## Expected vs actual counts

| Data | Expected | Actual | Explanation / discrepancy |
| --- | ---: | ---: | --- |
| Domains |  |  |  |
| Users |  |  |  |
| Groups |  |  |  |
| Computers |  |  |  |
| OUs |  |  |  |
| Memberships |  |  |  |
| Trusts |  |  |  |
| GPOs |  |  |  |
| GPO links |  |  |  |
| SYSVOL files |  |  |  |
| Supported GPO settings |  |  |  |
| Security descriptors / ACEs |  |  |  |

## Failure/partial fixtures

| Fixture | Expected behavior | Actual behavior | Issue code/status | Result |
| --- | --- | --- | --- | --- |
| Missing/inaccessible SYSVOL | Partial |  |  |  |
| Denied SYSVOL file | Partial |  |  |  |
| Out-of-scope GPO path | Reject before I/O |  |  |  |
| Blocked/slow SYSVOL | Deadline + worker termination |  |  |  |
| Insufficient ACL rights | Partial/Failed capability |  |  |  |
| Ranged membership | Complete members or explicit issue |  |  |  |
| Cancellation | No false Complete final artifact |  |  |  |
| Referral/inaccessible NC | Explicit incomplete behavior |  |  |  |

## Resource observations

```text
Minimal duration:
Audit-full duration:
Peak working set (when measured):
LDAP request count (when instrumented):
LDAP page count (when instrumented):
SYSVOL worker timeout observed/tested:
```

## Defects / unexplained differences

- 

## Read-only/security observations

```text
LDAP writes observed: yes/no
SYSVOL writes observed: yes/no
Credential/secret collection observed: yes/no
Unexpected remote/trust contact observed: yes/no
```

## Conclusion

```text
Collection path accepted for next stage: yes/no
Blocking issues:
Follow-up commits/issues:
```
