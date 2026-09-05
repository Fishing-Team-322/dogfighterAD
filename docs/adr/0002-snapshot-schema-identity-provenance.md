# ADR-0002: Snapshot schema, identity, provenance and coverage

Status: Accepted

## Context

DogfighterAD must support long-lived snapshots, offline re-analysis, deterministic findings and later comparison/retest workflows. The first prototype used flat snapshot records and a collector result containing `IReadOnlyList<object>`. That shape is too weak for a product expected to accumulate many collectors, rules and importers over time.

## Decision

### 1. The snapshot is a versioned immutable audit artifact

Every completed snapshot carries an explicit integer schema version that is independent from the DogfighterAD product version. Schema changes that break deserialization or semantic interpretation require an explicit migration or a new schema version. Product releases do not automatically increment the snapshot schema.

A completed snapshot is never mutated in place. Re-analysis produces new analysis results, not modified historical facts.

### 2. Distinguished names are locators, not identities

For Active Directory objects that expose `objectGUID`, DogfighterAD uses that GUID as the primary object identity inside a snapshot and across scans of the same object. A SID is preserved separately for security principals and authorization analysis, but not every directory object has a SID and SIDs must not be used as a universal object key.

A distinguished name may change when an object is moved or renamed, so it is stored as descriptive/locator data and must not be the sole basis for finding fingerprints.

### 3. Normalized content and observations are both first-class

The snapshot contains a normalized `SnapshotContent` model used by rules and graph projections. It also contains `ObservedFact` records that preserve evidence/provenance needed to explain where important values came from.

Rules should prefer normalized fields for stable semantics. Observations are the evidence and compatibility layer: they allow later rule versions to inspect already-collected security-relevant attributes that may not yet have had a dedicated normalized property at collection time.

The observation layer is not permission to persist arbitrary secrets. Collectors must explicitly mark values as stored, redacted or metadata-only. Secret material such as recoverable passwords, private keys or equivalent credentials is excluded from ordinary snapshots by default.

### 4. Coverage is part of correctness

Collection coverage is not a log message. Each capability has an explicit status such as complete, partial, failed, unsupported, not applicable or not requested, together with collector identity, item counts and structured issues.

A rule that requires a capability whose coverage is insufficient must not silently conclude that the target is safe. The analysis layer must be able to distinguish absence of a problem from absence of evidence.

### 5. Collectors return typed fragments

Collectors return `SnapshotFragment` rather than `object` bags. A later snapshot assembler will merge fragments, deduplicate objects, validate identity conflicts and derive the final snapshot completion status.

Collectors own acquisition and normalization of the facts they provide, but analysis remains forbidden inside collectors. If acquisition becomes complex, a collector may internally split protocol access and mapping into separate components without changing the application contract.

### 6. Capabilities are stable contracts

Capabilities use stable string identifiers such as `directory.users`, `directory.acls` or `gpo.sysvol`. Rules declare required capabilities and collectors declare provided capabilities. This lets a future collection planner request only the data required by a selected scan profile and lets reports state precisely what was and was not observed.

Capability identifiers are API surface. Renaming one requires compatibility handling rather than an ad-hoc string change.

### 7. Finding state and active validation state are separate

A passive analysis can establish that a dangerous configuration is present without proving exploitation. Therefore `FindingStatus` describes the analytical result while `ValidationStatus` is reserved for a future active validation plane.

The snapshot-first phase leaves validation as `NotRequested`/`NotSupported`; future validation workers may confirm or reject a specific hypothesis without changing the original snapshot.

## Consequences

### Positive

- rules and graph engines get typed, deterministic input;
- historical snapshots remain useful when rule packs evolve;
- evidence can be traced to collector/version/source;
- partial scans cannot masquerade as clean scans;
- object moves and renames do not automatically create unrelated finding identities;
- future importers can preserve their source provenance;
- an active validation node can be added later without contaminating read-only collection semantics.

### Costs

- snapshots contain some intentional duplication between normalized values and evidence observations;
- collectors must produce structured coverage and provenance instead of only data;
- schema compatibility and migrations become explicit engineering responsibilities;
- a snapshot assembler and validation layer are required before collection can be considered production-grade.

## Follow-up decisions

Before the first production collector is considered stable, DogfighterAD still needs ADRs for:

1. snapshot serialization/container format and integrity checks;
2. deterministic fact and finding fingerprint algorithms;
3. collection planner, timeout and resource-budget semantics;
4. credential/secrets boundary and least-privilege collection profiles;
5. schema migration/backwards-compatibility policy;
6. extension/import model for ADCS, host facts and third-party tool data.
