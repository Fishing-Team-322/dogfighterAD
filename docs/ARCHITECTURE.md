# Architecture

DogfighterAD is a snapshot-first, evidence-first Active Directory security assessment platform. The current product phase is intentionally read-only.

## Core data flow

```text
Target AD / SYSVOL
  -> Collection Planner
  -> read-only Collectors
  -> Snapshot Fragments
  -> deterministic Snapshot assembly
  -> .dogad portable artifact
  -> offline Analysis / Rules / Graph projections
  -> Findings + Evidence
  -> Reports / API / UI

Future only:
Findings / Paths -> Validation Planner -> separate Validation Node
```

## Module boundaries

### `DogfighterAD.Domain`

Canonical security-assessment structures only: versioned snapshots, AD identities/relationships, GPO/SYSVOL normalized records, descriptors/ACEs, coverage/issues, observed facts/provenance, stable fact identity, findings/evidence and capability compatibility. It must not depend on LDAP, ZIP/JSON serialization, SQLite, HTML, CLI, network clients or UI frameworks.

### `DogfighterAD.Application`

Orchestration: collector contracts, capability-driven planning, built-in profiles, bounded staged execution, dependency blocking, timeout/cancellation, telemetry, fragment merge and snapshot assembly.

### `DogfighterAD.Collectors.ActiveDirectory`

Protocol/source-specific read-only collection: LDAP transport and paging, RootDSE/domain/users/groups/computers/OUs, range-aware memberships, trusts, DACL/ACE collection, GPO metadata/links, plus read-only SYSVOL enumeration and supported GPO policy parsers. It exposes no LDAP write API in the snapshot-first phase.

### `DogfighterAD.Serialization`

Outer portable-artifact layer. Depends on Domain only. Owns canonical snapshot ordering for external serialization, `.dogad` container/manifest versioning, deterministic ZIP/JSON representation, defensive read limits and integrity/canonicalization verification. See `DOGAD_FORMAT.md`.

## Non-negotiable invariants

1. Rules never query AD/SYSVOL directly.
2. Graph analysis is derived from snapshot data; graph is not canonical storage.
3. Missing/failed collection cannot be interpreted as a clean result.
4. Findings must be traceable to observed evidence.
5. Collector/protocol/serialization details do not leak into the Domain model.
6. Same logical inputs produce stable logical ordering and stable fact identities.
7. Secrets are not collected merely because readable; posture/access evidence is preferred.
8. Active validation is a future separate execution plane.
9. Large LDAP scans use streaming paging rather than avoidable whole-query buffers.
10. Capability contract versions are durable and never silently upgraded.
11. Collection stores direct relationships; transitive/path reasoning belongs to analysis.
12. A configured trust is not proof the remote side is reachable/usable.
13. Null/absent and empty DACLs remain distinguishable.
14. Unsupported/malformed security semantics make coverage incomplete instead of being silently discarded.
15. `.dogad` verifies payload integrity/schema/canonical representation, but SHA-256 is not an authenticity signature.

## Snapshot model

A snapshot has four major layers:

- `Metadata`: scan/target identity, product/schema versions and collector identities.
- `Content`: normalized AD objects, relationships, GPO/SYSVOL data, descriptor state and ACEs.
- `Coverage`: what was attempted, status, issues and capability contract version.
- `Observations`: evidence facts and provenance.

The snapshot is the durable logical audit record. `.dogad` is its portable deterministic outer artifact. Analysis should be repeatable offline without reconnecting to the customer when the required capability/version is present.

## Collection ownership and efficiency

Ownership follows source/query shape rather than UI feature names. Users/groups/computers/OUs share a one-pass directory collector; memberships are separate because ranged `member` and primary-group reconstruction have distinct semantics; trusts are separate because local configuration must not imply remote validation; ACLs are separate because SD controls and binary parsing are specialized; GPO metadata/links use LDAP while GPO template settings use a read-only SYSVOL boundary.

`gpo.sysvol v1` inventories/hash-evidences files but semantically normalizes only explicitly supported formats. It redacts/metadata-only handles potential secrets and never stores legacy `cpassword` values. Unknown files are not treated as understood policy.

## Portable artifact boundary

`.dogad v1` is a strict deterministic ZIP containing `manifest.json` and canonical `snapshot.json`. Container version, serialization ID, snapshot schema version and capability contract versions are intentionally independent compatibility axes. Unknown entries are rejected in v1. The current implementation buffers the JSON payload, so peak-memory benchmarking on large domains is pending.

## Current limitations

Collection Core now covers the default domain, core objects, memberships, local trust configuration, supported DACL semantics, GPO metadata/links/inheritance and supported read-only SYSVOL settings. It does not yet cover AD CS, full forest/multi-domain topology, all Group Policy extension semantics, every ACE family, endpoint RSoP/validation, LAPS/gMSA posture or broader host/protocol data.

`.dogad v1` exists and supports offline transport/integrity verification, but live end-to-end MINILAB/GOAD integration, LDAP request/page accounting and large-domain memory benchmarks are still pending. Persistent SQLite storage, Rule Engine, graph analysis, diff/retest and reporting are not yet implemented.

## Future Validation Plane

Validation/execution is not part of the snapshot collector. A future Validation Node will consume explicit finding/path jobs, may run in another process/host/OS/language, and must remain separately scoped, controlled and auditable.
