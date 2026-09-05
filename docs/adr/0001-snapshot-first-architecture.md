# ADR-0001: Snapshot-first architecture

Status: Accepted

## Context

DogfighterAD is intended to become an extensible Active Directory security assessment platform. The first product phase targets professional auditors and penetration testers. A later phase may add controlled validation/execution nodes, but active validation must not define or contaminate the initial collection architecture.

## Decision

DogfighterAD is snapshot-first and evidence-first.

1. Collection is separated from analysis.
2. The initial collection plane is read-only.
3. Collectors produce security-relevant facts and explicit capability/coverage results.
4. Facts are normalized into a versioned snapshot before rules or graph analysis run.
5. Rules never query Active Directory directly.
6. Graph analysis is a projection over snapshot data, not the canonical storage model.
7. Findings must reference evidence and stable object identities.
8. Incomplete collection must remain distinguishable from a clean result.
9. Snapshots must support offline re-analysis by later rule versions.
10. Reporting, persistence and user interfaces consume domain results and must not be coupled to collectors.
11. Future active validation is a separate execution plane consuming findings/paths through explicit contracts.
12. Validation code must never be required for read-only collection or offline analysis.

## Consequences

### Positive

- New rules can be added without modifying collectors when required data already exists.
- Old customer snapshots can be re-analyzed with new rule packs.
- Collection coverage and failures are auditable.
- Rules can be unit-tested with synthetic snapshots without a live domain.
- Storage and reporting formats can evolve independently from collection logic.
- A future validation node can use a different process, runtime or language without rewriting the core model.

### Costs

- Snapshot schema evolution requires explicit compatibility policy and migrations.
- Normalization adds engineering work before individual checks can be implemented.
- Collectors need provenance and coverage metadata instead of returning only raw values.

## Architectural invariants

The following are treated as architecture violations unless superseded by a later ADR:

- an `IRule` opening LDAP/SMB/RPC/network connections;
- an HTML/reporting component performing security analysis;
- persistence-specific types leaking into the domain model;
- treating failed or partial collection as "secure";
- changing the target environment during the snapshot-first phase;
- embedding future attack/validation execution into the snapshot collector.
