# Architecture

DogfighterAD is a snapshot-first, evidence-first Active Directory security assessment platform. The current product phase is intentionally read-only.

## Core data flow

```text
Target AD
  -> Collection Planner
  -> read-only Collectors
  -> Snapshot Fragments
  -> deterministic Snapshot assembly
  -> offline Analysis / Rules / Graph projections
  -> Findings + Evidence
  -> Reports / API / UI

Future only:
Findings / Paths -> Validation Planner -> separate Validation Node
```

## Module boundaries

### DogfighterAD.Domain
Owns canonical security-assessment data structures. It must not depend on LDAP, SQLite, HTML, CLI, network clients, or UI frameworks.

Current responsibilities:
- versioned snapshot schema;
- normalized AD object identities and relationships;
- collection coverage and issues;
- observed facts and provenance;
- stable fact identity;
- findings/evidence domain structures;
- capability contract compatibility.

### DogfighterAD.Application
Owns orchestration and contracts between the domain and infrastructure.

Current responsibilities:
- collector interface;
- capability-driven collection planning;
- staged execution with bounded concurrency;
- dependency blocking;
- timeout/cancellation handling;
- deterministic fragment merging and snapshot assembly.

### DogfighterAD.Collectors.ActiveDirectory
Owns Active Directory protocol-specific collection code.

Current responsibilities:
- read-only LDAP transport using `System.DirectoryServices.Protocols`;
- paged streaming enumeration for high-volume subtree scans;
- RootDSE discovery;
- default-domain metadata collection;
- one-pass collection of users, groups, computers and OUs;
- protocol-to-domain conversion for GUID, SID, generalized time and AD FileTime;
- mapping protocol data into snapshot fragments with per-capability coverage.

This project must not expose LDAP write operations to collectors. The snapshot-first phase does not modify target infrastructure.

## Architectural invariants

These are deliberate constraints, not style preferences:

1. Rules never query AD directly.
2. Graph analysis is derived from snapshot data; the graph is not canonical storage.
3. A collection failure or missing capability cannot be interpreted as a clean result.
4. Findings must be traceable to evidence/facts.
5. Collector/protocol details cannot leak into the domain model.
6. Same logical inputs must produce deterministic logical snapshot ordering and stable fact IDs.
7. Secrets are not collected merely because they are readable. The scanner targets security-relevant posture and access relationships.
8. Active validation is a future, separate execution plane.
9. Large LDAP subtree enumeration must not introduce an avoidable transport-level full-result buffer.
10. Capability contract versions are durable guarantees and must survive fragment merge/serialization unchanged or conservatively weakened, never silently upgraded.

## Snapshot model

A snapshot contains four major layers:

- `Metadata`: scan identity, target identity, product/schema versions and collector identities.
- `Content`: normalized AD objects and relationships.
- `Coverage`: what the scanner attempted, whether it succeeded, and the data-contract version collected.
- `Observations`: source facts with provenance used to support later findings.

The snapshot is the durable audit artifact. Analysis must be able to run again later without reconnecting to the customer's AD when the required data is present.

## Capability contracts

Capability IDs describe classes of collected data, for example:

- `directory.core`
- `directory.users`
- `directory.groups`
- `directory.memberships`
- `directory.acls`
- `directory.trusts`
- `gpo.metadata`
- `gpo.sysvol`
- `adcs.directory`

Every persisted coverage record contains a `ContractVersion`.

A rule declares a minimum required contract version. If a snapshot is older than the rule requirement, the rule must not report the environment as clean; it must be treated as not verifiable with that snapshot.

Capability versions are monotonic: version N+1 must preserve guarantees of version N. If semantics cannot remain compatible, introduce a new capability ID instead.

The concrete built-in guarantees are documented in [CAPABILITIES.md](CAPABILITIES.md).

## Collection ownership and query efficiency

Collector ownership is chosen by data source and query shape, not by UI feature names. The `ad.ldap.directory-objects` collector owns users, groups, computers and OUs because they can be retrieved safely in a single default-domain paged subtree pass. Each capability still receives independent coverage and can become `Partial` without contaminating unrelated capability results.

Memberships are deliberately separate because large group `member` attributes require range-aware collection and primary-group reconstruction. ACLs are separate because security descriptors require different controls/parsing. This keeps one-pass efficiency without creating one unmaintainable collector that owns all AD data.

## Stable identities and AD special values

AD objects use normalized stable identifiers rather than display names wherever possible. Facts use a versioned canonical hash algorithm so evidence identity is not coupled to collector implementation versions.

AD sentinel values are normalized explicitly. For example, `pwdLastSet=0` and `accountExpires=0/Int64.MaxValue` retain their security meaning in normalized fields while raw values remain available as source observations.

## Current limitations

The foundation is not yet a complete AD scanner. Current network collection covers RootDSE discovery, default-domain metadata, and users/groups/computers/OUs. Memberships, foreign security principals required by cross-domain group membership, trusts, ACLs, GPO data and ADCS collection are planned next.

Snapshot serialization (`.dogad`), persistent storage, rule execution, graph analysis and reporting are also not yet implemented.

## Future Validation Plane

Validation/execution is explicitly not part of the snapshot collector. A future Validation Node will consume findings or paths through explicit job contracts. It may run in another process, host, operating system or language without changing the snapshot and analysis core.
