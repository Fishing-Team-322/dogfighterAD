# Development guide

This guide exists to keep DogfighterAD extensible as the number of collectors and rules grows.

## Before adding code

Ask which layer owns the behavior:

- protocol/network collection -> `DogfighterAD.Collectors.*`;
- orchestration/planning -> `DogfighterAD.Application`;
- canonical assessment data -> `DogfighterAD.Domain`;
- reporting/storage/UI -> separate modules later.

Do not bypass these boundaries for convenience.

## Adding a collector

A collector must:

1. have a stable collector `Id` and implementation `Version`;
2. declare provided and required capability IDs;
3. perform read-only collection during the snapshot-first phase;
4. consume upstream data through `CollectionContext.AvailableData` rather than re-running discovery unnecessarily;
5. return normalized `SnapshotFragment` data, not protocol-specific objects;
6. return one coverage record for every selected capability;
7. distinguish `Complete`, `Partial`, `Failed`, `Blocked`, `Unsupported` and `NotApplicable` correctly;
8. attach provenance to observed facts;
9. avoid persisting secrets that are not required for assessment;
10. support cancellation and respect collection timeouts;
11. have unit tests for mapping and contract behavior;
12. update `docs/ROADMAP.md` when implementation status changes.

### LDAP query shape

Small bounded lookups such as RootDSE or a single base object may use `SearchAsync`.

Large `Subtree`/paged scans should use `SearchEntriesAsync` so the production LDAP client can release each LDAP page instead of accumulating the complete server result before mapping begins. Do not convert a streaming search back into a giant intermediate list unless the algorithm genuinely requires the entire set at once.

Collectors may still build normalized snapshot collections in memory during the current foundation phase. Snapshot assembly/storage will later be benchmarked separately; the transport layer must not add a second avoidable full-result buffer.

### Capability contract versions

When a collector adds data that existing rules do not depend on, the capability version can normally remain unchanged.

Increment the capability contract version when a newer rule needs to distinguish snapshots that contain a newly guaranteed field/relationship from older snapshots that did not collect it.

A version increase must preserve older guarantees. If semantics are incompatible, create a new capability ID.

Never use collector version as a substitute for capability contract version: collectors can be refactored without changing the data contract.

## Adding a rule

The rule engine is not implemented yet, but the intended contract is already fixed:

- rules receive a snapshot, never LDAP/network clients;
- rule IDs are stable;
- rule versions change independently from product versions;
- required capabilities include minimum contract versions;
- unavailable/old/partial data produces `NotVerified`, not a clean result;
- findings reference evidence/facts;
- deterministic input should produce deterministic logical output.

A rule should be testable using a synthetic snapshot with no live domain.

## Evidence and facts

Keep these concepts separate:

- **Fact**: something observed from a source.
- **Finding**: an analytical conclusion derived from facts.
- **Potential path**: a calculated relationship/path that may enable abuse.
- **Validated condition/path**: a future active validation result.

Do not label a calculated possibility as actively confirmed.

## Testing expectations

For every new foundation behavior, prefer tests before broad feature expansion.

Current CI builds with warnings treated as errors and runs the core test suite on Windows and Linux/.NET 10. Use the executable test command documented in the [foundation review](reviews/2026-09-06-foundation-review.md). Protocol behavior that requires Windows or a real AD will get dedicated integration jobs later.

Planned test layers:

- unit tests for mappings and rules;
- golden snapshot/report tests;
- synthetic large snapshots for performance;
- clean-domain integration tests;
- GOAD/MINILAB integration tests;
- hidden mutations planted by another tester;
- false-positive regression corpus;
- resource/query-budget benchmarks.

## Documentation rule

A change is not considered complete when it materially changes architecture, capability semantics, security boundaries or roadmap status unless documentation is updated in the same branch.

Use an ADR under `docs/adr/` for decisions that would be expensive to reverse later.
