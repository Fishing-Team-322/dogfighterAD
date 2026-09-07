# Architecture

DogfighterAD is a snapshot-first, evidence-first Active Directory security assessment platform. The current product phase is intentionally read-only.

## Core data flow

```text
CLI / future API host
  -> Collection Planner
  -> read-only Collectors
       -> LDAP
       -> parent-validated SYSVOL scope -> disposable SysvolWorker filesystem I/O
  -> Snapshot Fragments
  -> deterministic Snapshot assembly
  -> .dogad portable artifact
  -> offline inspect / future Analysis / Rules / Graph projections
  -> Findings + Evidence
  -> Reports / API / UI

Future only:
Findings / Paths -> Validation Planner -> separate Validation Node
```

The CLI is a composition shell around the core. The durable product boundary is the snapshot/artifact, not the console process.

## Module boundaries

### `DogfighterAD.Domain`

Canonical security-assessment structures only: versioned snapshots, AD identities/relationships, GPO/SYSVOL normalized records, descriptors/ACEs, coverage/issues, observed facts/provenance, stable fact identity, findings/evidence and capability compatibility. It must not depend on LDAP, ZIP/JSON serialization, SQLite, HTML, CLI, network clients or UI frameworks.

### `DogfighterAD.Application`

Orchestration: collector contracts, capability-driven planning, built-in profiles, bounded staged execution, dependency blocking, timeout/cancellation, telemetry, fragment merge and snapshot assembly.

### `DogfighterAD.Collectors.ActiveDirectory`

Protocol/source-specific read-only collection: LDAP transport and paging, RootDSE/domain/users/groups/computers/OUs, range-aware memberships, trusts, DACL/ACE collection, GPO metadata/links, plus read-only SYSVOL enumeration and supported GPO policy parsers. It exposes no LDAP write API in the snapshot-first phase.

The parent collector owns SYSVOL scope policy and normalized assessment semantics. It validates approved roots/authorities and every enumerated child before requesting file content.

### `DogfighterAD.SysvolWorker`

Internal killable runtime helper for filesystem operations that can block inside SMB/DFS/OS code and may not observe managed cancellation. It performs directory enumeration, file metadata access and file reads on behalf of the parent through a private bounded protocol.

It is deliberately not a service, microservice, plugin host or security sandbox. It has no collection plan, capability semantics, normalization logic, findings, listener or persistent state. The parent keeps the policy decisions; the worker supplies a hard process-lifetime boundary so timeout/cancellation can terminate the process executing a stalled filesystem call. See ADR 0011.

### `DogfighterAD.Serialization`

Outer portable-artifact layer. Depends on Domain only. Owns canonical snapshot ordering for external serialization, `.dogad` container/manifest versioning, deterministic ZIP/JSON representation, defensive read limits and integrity/canonicalization verification. See `DOGAD_FORMAT.md`.

### `DogfighterAD.Cli`

Thin process composition/frontend layer. It selects a built-in profile, constructs production collector factories, invokes the Application planner/executor and SnapshotAssembler, writes/verifies `.dogad`, handles process cancellation/exit codes and prints bounded coverage summaries.

It does not own detection semantics and does not bypass collectors with direct AD queries. `inspect` opens only an existing artifact; the future `analyze` command will belong to the Analysis workflow once Rule Engine exists.

Production LDAP composition currently uses Negotiate/current operating-system security context. Credential values are intentionally not accepted as command-line options.

`scan` publishes the requested output only after a temporary `.dogad` has been read successfully through the strict artifact reader and its snapshot identity/status agree. This keeps a failed/canceled artifact write from intentionally appearing as the final requested scan result.

## Non-negotiable invariants

1. Rules never query AD/SYSVOL directly.
2. Graph analysis is derived from snapshot data; graph is not canonical storage.
3. Missing/failed collection cannot be interpreted as a clean result.
4. Findings must be traceable to observed evidence.
5. Collector/protocol/serialization/frontend details do not leak into the Domain model.
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
16. Filesystem/SMB operations known to be potentially uninterruptible do not run directly in the long-lived collector process; their process lifetime is bounded and drained before the operation slot is released.
17. Frontends may orchestrate core modules but must not become alternate sources of collection or analysis semantics.
18. A final `scan` artifact is published only after strict offline readback succeeds.

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

SYSVOL has two different containment layers. Parent-side path policy prevents out-of-scope reads/authentication attempts, while `DogfighterAD.SysvolWorker` bounds the lifetime of OS/filesystem operations after a path has been approved. Neither substitutes for the other.

## Portable artifact and process boundary

`.dogad v1` is a strict deterministic ZIP containing `manifest.json` and canonical `snapshot.json`. Container version, serialization ID, snapshot schema version and capability contract versions are intentionally independent compatibility axes. Unknown entries are rejected in v1. The current implementation buffers the JSON payload, so peak-memory benchmarking on large domains is pending.

The CLI is intentionally disposable: `scan` may run on a domain-connected assessment host, while later `inspect`/analysis can consume the resulting `.dogad` elsewhere without reconnecting to AD. This separation is central to reproducibility and retest/offline workflows.

## Current limitations

Collection Core now covers the default domain, core objects, memberships, local trust configuration, supported DACL semantics, GPO metadata/links/inheritance and supported read-only SYSVOL settings. It does not yet cover AD CS, full forest/multi-domain topology, all Group Policy extension semantics, every ACE family, endpoint RSoP/validation, LAPS/gMSA posture or broader host/protocol data.

A runnable `scan`/offline `inspect` composition exists and has a synthetic no-network end-to-end artifact round-trip test. That proves module composition and artifact readability, **not** correctness against a real Active Directory.

Live end-to-end MINILAB/GOAD integration, real DFS/referral behavior, LDAP request/page accounting and large-domain memory benchmarks are still pending. Persistent SQLite storage, Rule Engine, graph analysis, diff/retest and reporting are not yet implemented.

## Future Validation Plane

Validation/execution is not part of the snapshot collector. A future Validation Node will consume explicit finding/path jobs, may run in another process/host/OS/language, and must remain separately scoped, controlled and auditable.
