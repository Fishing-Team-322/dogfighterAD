# ADR-0003: Snapshot assembly and deterministic ordering

Status: Accepted

## Context

Collectors may execute concurrently and may complete in different orders on every scan. If final snapshot ordering depends on task scheduling, logically identical scans can serialize differently, produce noisy diffs and make reproducibility difficult. The application also needs one place where collector fragments become a trusted snapshot.

## Decision

1. Final snapshots are created through a dedicated snapshot assembler.
2. Collector output remains a `SnapshotFragment`; rules do not consume fragments directly.
3. The assembler merges typed content, coverage and observations, computes overall completion status and then runs snapshot invariant validation.
4. Duplicate ownership of the same normalized AD object across collector fragments is treated as an assembly error until an explicit merge policy exists for that object type.
5. Unknown but security-relevant directory objects are represented by a generic directory-object fallback rather than discarded. Specialized models may be introduced later without making the current collector blind to those objects.
6. Foreign security principals are represented explicitly because group and ACL analysis must tolerate principals outside the local domain.
7. Capability coverage from multiple contributors is merged conservatively. Conflicting statuses become `Partial`; the assembler must never upgrade uncertain coverage to `Complete` by guesswork.
8. Snapshot content is canonically ordered by stable identifiers/composite relationship keys. Observation records are ordered by fact id, coverage by capability id and collector identities by id/version.
9. Overall snapshot completion is derived from the capabilities requested by the scan profile. `Complete` means every requested capability was complete or explicitly not applicable. Missing, unsupported or failed requested capabilities cannot yield a complete snapshot.
10. A snapshot that violates identity, relationship, coverage or provenance invariants is rejected before persistence or analysis.

## Consequences

- collector concurrency cannot change the logical ordering of a snapshot;
- later serializers can produce deterministic output when they also use deterministic formatting;
- regression snapshots and golden tests become meaningful;
- incomplete collection is propagated instead of hidden;
- adding a new specialized object model does not require dropping unrecognized Configuration NC or extension objects today;
- collector ownership must be designed deliberately instead of allowing silent last-write-wins behavior.

## Future work

Before production-scale collection, add explicit tests for deterministic assembly, duplicate identity rejection, relationship integrity, coverage aggregation and generic-object preservation. A later ADR may define controlled merge semantics for object types intentionally enriched by more than one collector.
