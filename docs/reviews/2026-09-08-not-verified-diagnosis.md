# MINILAB NotVerified diagnosis — 2026-09-08

Reviewed baseline: 87c3ae895744313ba774bc10abae02c799dee033, feature/rule-engine.
Input snapshot de2a4509-9c6c-406f-9496-60819e78d860 was supplied by the user.
The full collection is Complete, but analysis has 44 NotVerified evaluations,
22 findings and no rule errors. These are evaluations per object, not 44 distinct rules.

## Confirmed causes

- Optional user/computer SPN, SID history and delegation fields are not observed.
- Twelve encryption evaluations lack a mask; the old code additionally reported
  an invalid/zero mask because the failed read returned the CLR default zero.
- Two users lack a replicated logon timestamp; no event age can be computed.
- 37 groups explicitly record memberReadComplete=False and observedMemberCount=0.
  Thus the snapshot cannot prove negative privileged-membership reachability.

An empty typed CLR collection is not absence evidence. AD treats an attribute
hidden by access checks as nonexistent both in returned values and LDAP filters:
[MS-ADTS access checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8271b44d-a755-4872-a762-1ac57152099d).
A negative presence filter alone is therefore not an adequate fix.

## Changes

- Stop encryption evaluation after a missing/invalid operand, preserving its real
  cause instead of adding a spurious zero-mask gap.
- Evaluate false UAC predicates before demanding membership proof: a conjunction
  cannot match if its account condition is already false. Positive predicates
  still require membership proof. No privilege is inferred from adminCount.
- Print grouped missing-data reasons in analyze output.
- Version the changed account rules and rule pack as 1.0.1.

## Validation and limits

642 tests passed, including six new regression cases. Reanalysis of the unchanged
snapshot with its original analysis reference time still has 44 NotVerified and
22 findings; these changes do not claim to close the missing-evidence cases.
No live rescan or changes to the AD lab were needed or performed.

## Required next collection work

To close these cases safely, introduce explicit per-attribute observation states
and provenance-backed read-access/absence evidence, with denied-read fixtures.
Cover schema/property-set permissions and applicable extended access checks;
never interpret an ordinary omitted LDAP attribute as empty. For groups, persist
complete empty enumeration only when absence can actually be established.
Old snapshots remain unknown when they lack these proofs. Missing/zero encryption
configuration does not prove a negotiated cipher, and no replicated logon timestamp
does not prove that an account never logged on. These are collection-contract and
rule-semantics tasks, not timeout or VM-availability fixes.
