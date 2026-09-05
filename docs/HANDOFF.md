# DogfighterAD development handoff

Last updated: 2026-09-05.

This file is the compact source of truth for continuing development in a new chat/session. Read `ARCHITECTURE.md`, `CAPABILITIES.md`, `ROADMAP.md`, `DEVELOPMENT.md`, `COLLECTION_PROFILES.md` and the ADRs for normative detail.

## Repository and branch

- Repository: `kusotsu/dogfighterAD`
- Default branch: `main`
- Active development branch: `foundation/snapshot-core`
- Do not assume `main` contains current implementation work. Continue from `foundation/snapshot-core` unless the user explicitly requests a merge/release.
- Before every write, fetch the current branch state and preserve existing files/commits.
- Keep CI green before moving to the next architectural layer.

## Product direction

DogfighterAD is being designed as a snapshot-first, evidence-first Active Directory security assessment platform.

Primary initial users are professional pentesters / red-team / AD auditors. Later the same core should support a simpler company/blue-team periodic assessment workflow.

The long-term product is not intended to be a BloodHound clone. BloodHound-style graph/path analysis is one analysis projection over DogfighterAD data, not the primary storage model. DogfighterAD's intended differentiators are reproducible snapshots, collection coverage, provenance/evidence, offline re-analysis, deterministic findings, diff/retest and eventually a separate controlled validation plane.

A future Validation/Execution Node may actively confirm selected conditions/paths, similar in product role to an automated validation node, but it must remain a separate execution plane. The current snapshot-first phase is read-only.

## Non-negotiable architectural rules

1. Collectors acquire facts. Rules/analyzers never query LDAP/SMB/RPC directly.
2. Collection, normalization, storage, analysis, graph projection, reporting and future validation remain separate responsibilities.
3. A failed/incomplete collection must never become a negative security result. Use `Partial`, `Failed`, `Blocked`, `Unsupported` or later `NotVerified` semantics.
4. Snapshot data and capability contracts are versioned for safe offline re-analysis by future rule packs.
5. Same logical input must produce deterministic logical ordering and stable fact identities.
6. Preserve evidence/provenance: what was observed, by which collector, where and when.
7. Do not collect secrets merely because they are readable. Prefer posture/access relationships (for example who can read LAPS/gMSA material) rather than secret values.
8. Snapshot-first collection is strictly read-only. LDAP write APIs are intentionally absent from collector contracts.
9. Avoid a monolithic collector. Ownership follows data source/query shape and capabilities/dependencies.
10. Avoid premature microservices, custom graph databases and runtime third-party DLL plugin systems.
11. Built-in profile capability sets change only deliberately; registering a new capability must not silently make an existing profile heavier.

## Technology baseline

- C# / .NET 10 LTS.
- `System.DirectoryServices.Protocols` isolated in the Active Directory collector project.
- xUnit v3 tests.
- GitHub Actions build/test CI.
- Planned local storage / portable artifact direction: SQLite plus deterministic portable `.dogad` snapshot representation; serialization is not implemented yet.

## Core architecture already implemented

The active branch contains:

- normalized/versioned snapshot model;
- `SnapshotMetadata`, target identity and schema foundation;
- stable `AdObjectId` based on AD object GUIDs;
- generic directory-object fallback for classes not yet specialized;
- observed facts with provenance/redaction disposition;
- versioned deterministic SHA-256 `FactId` generation;
- capability coverage with explicit statuses;
- monotonic capability contract versions and compatibility checks;
- deterministic `SnapshotFragmentMerger`;
- snapshot invariant validation;
- capability-driven collection planner with dependency-cycle/ambiguity checks;
- staged executor with bounded concurrency, cancellation and per-collector timeout;
- downstream blocking when prerequisite capabilities are unavailable;
- built-in `minimal` and `audit-full` collection profiles;
- deterministic execution telemetry for scan/collector durations and execution/capability status counts;
- read-only LDAP abstraction;
- paged streaming LDAP enumeration so large subtree scans are not fully buffered by the transport layer;
- portable GUID/SID/generalized-time/AD FileTime normalization;
- DACL-only security-descriptor request support and portable self-relative DACL parser.

Current telemetry intentionally does **not** claim LDAP request/page counts, peak memory or benchmark-derived resource budgets yet. Existing hard execution guardrails are `MaxConcurrency` and per-collector timeout. Query/resource instrumentation is a separate pending task.

## Built-in collection profiles

### `minimal`

A lighter inventory/topology profile. It currently requests:

- `directory.core`;
- `directory.domains`;
- `directory.users`;
- `directory.groups`;
- `directory.computers`;
- `directory.ous`;
- `directory.memberships`;
- `directory.trusts`.

It intentionally excludes DACL and GPO collection. Current guardrails: `MaxConcurrency=2`, per-collector timeout 2 minutes. These are conservative engineering defaults, not benchmark-proven production limits.

### `audit-full`

The broad built-in audit profile over all currently implemented read-only collection capabilities. It includes the minimal set plus:

- `directory.acls`;
- `gpo.metadata`;
- `gpo.links`.

It intentionally does not include planned capabilities such as `gpo.sysvol` or `adcs.directory` until those contracts are actually implemented/tested and the profile is deliberately revised. Current guardrails: `MaxConcurrency=4`, per-collector timeout 3 minutes.

## Implemented collection capabilities

### `directory.core v1`

RootDSE discovery. Provides naming contexts and LDAP environment metadata once for downstream collectors.

### `directory.domains v1`

Default domain object metadata including stable GUID/SID identity and functional level.

### `directory.users v1`

One-pass domain enumeration shared with groups/computers/OUs. Security-relevant fields include UAC, adminCount, primaryGroupID, password/logon/account-expiry timestamps, encryption types, SPNs, SIDHistory and constrained-delegation targets when present. AD sentinel FileTime values have explicit normalized semantics.

### `directory.groups v1`

Stable group identity, groupType, adminCount and common metadata. Membership is a separate capability.

### `directory.computers v1`

Stable computer identity, host/OS metadata, UAC, password/logon timestamps, encryption types, SPNs and constrained-delegation targets when present.

### `directory.ous v1`

Stable OU identity/common metadata. ACL-dependent protection semantics are intentionally not guessed here.

### `directory.memberships v1`

- direct group `member` relationships;
- range-safe `member;range=start-end` retrieval through terminal chunks;
- direct group-to-group edges (nested membership is not flattened at collection time);
- primary-group reconstruction;
- foreign security principal support;
- unresolved identities/range failures make coverage partial instead of silently truncating the graph.

### `directory.trusts v1`

Configured local `trustedDomain` relationships for the default domain. Does not contact or validate the remote side of a trust.

### `directory.acls v1`

DACL security descriptors for the normalized domain root/users/groups/computers/OUs. Preserves descriptor/DACL state, Allow/Deny standard ACEs, Allow/Deny object ACEs, trustee SID, access mask, ACE flags/inheritance, ObjectType and InheritedObjectType GUIDs. Unsupported/malformed ACE semantics cause partial coverage rather than silent omission. SACL, owner and group sections are intentionally outside v1.

### `gpo.metadata v1`

Group Policy Container metadata under `CN=Policies,CN=System,<domain>`, including stable AD/GPO identity, display name, file-system path, version, flags and timestamps when present. No SYSVOL parsing yet.

### `gpo.links v1`

- domain/OU `gPLink` enumeration;
- stable container→GPO edges;
- 1-based stored link order;
- raw link options plus normalized Enabled/Enforced flags;
- `gPOptions` and normalized Block Inheritance per domain/OU container;
- unknown targets/malformed syntax/unsupported option bits become partial coverage;
- snapshot invariants reject invalid GPO relationship references/order/inheritance state.

## Documentation already maintained

- `docs/ARCHITECTURE.md` — architectural boundaries and design.
- `docs/CAPABILITIES.md` — normative meaning of every built-in capability contract/version.
- `docs/ROADMAP.md` — conservative implementation status and next order of work.
- `docs/DEVELOPMENT.md` — rules for adding collectors/rules.
- `docs/COLLECTION_PROFILES.md` — built-in profile semantics and telemetry/guardrail status.
- `docs/adr/` — durable architectural decisions.
- `docs/HANDOFF.md` — this continuation summary.

When implementation changes a capability guarantee, update `CAPABILITIES.md` in the same development slice. When a milestone becomes actually implemented and tested, update `ROADMAP.md` only after CI succeeds.

## Immediate next work

Do not start a large rule library yet. Finish Collection Core v1 first.

Recommended order:

1. Design and implement `gpo.sysvol v1` as strictly read-only GPO settings/file collection with explicit per-file/per-setting coverage. Do not collect unrelated secrets from SYSVOL.
2. Instrument LDAP request/page counts and design benchmark-driven per-capability query/resource budgets. Add peak-memory measurement at benchmark/integration level rather than guessing thresholds.
3. Design deterministic snapshot serialization and the portable `.dogad` artifact, including integrity metadata and backwards-compatible schema/version handling.
4. Add real integration tests against MINILAB/GOAD, including clean and intentionally vulnerable fixtures, partial-access cases and larger membership/ACL examples.
5. Then implement the Rule Engine with capability-version prerequisite checks, stable finding fingerprints, evidence references, deterministic results and `NotVerified` behavior.
6. After that build the initial auditor-focused rule pack, diff/retest, JSON/HTML reporting and graph projection/path analysis.

## Later collection areas

After Collection Core v1 is stable, expand carefully into:

- broader Kerberos posture;
- delegation relationships/context;
- LAPS posture and who-can-read relationships without collecting managed passwords by default;
- gMSA posture/access relationships without collecting secret blobs by default;
- AD CS topology/security-relevant configuration;
- sites/subnets/forest topology and eventually multi-domain collection;
- additional ACE families based on real-world fixtures;
- improved referral/inaccessible-NC/mid-stream failure accounting.

## Testing philosophy

Every collector should have offline unit tests with fake protocol clients before relying on a live AD lab. Test both positive mapping and incomplete/malformed data behavior. A collector that silently skips data is more dangerous than one that reports `Partial`.

Required future test layers:

- unit/golden tests for normalization and rules;
- synthetic snapshots;
- contract/version compatibility tests;
- clean-domain false-positive regressions;
- GOAD/MINILAB integration tests;
- planted/hidden misconfiguration corpus;
- deterministic output tests;
- query-count, duration and peak-memory benchmarks;
- read-only/security tests for the scanner itself.

## Lab/product context

The user plans local AD lab testing with VirtualBox/GOAD MINILAB/GOAD-Light and may also have access to a fuller GOAD environment through a friend. Treat any historical transcript about local machine state as context only; do not claim current machine state without new evidence.

## Safety/product boundary

Current development is defensive/read-only AD collection and assessment. Do not add exploitation, credential dumping, destructive writes or automatic attack-path execution to the snapshot collector. Future active validation must be separately scoped, controlled, auditable and architecturally isolated.

## How to resume in a new chat

Tell the next assistant:

> Continue DogfighterAD from GitHub repository `kusotsu/dogfighterAD`, branch `foundation/snapshot-core`. Read `docs/HANDOFF.md`, `docs/ARCHITECTURE.md`, `docs/CAPABILITIES.md`, `docs/ROADMAP.md`, `docs/DEVELOPMENT.md`, `docs/COLLECTION_PROFILES.md` and ADRs first. Fetch current branch/CI before writing. Preserve the snapshot-first/read-only architecture. Continue from the immediate-next-work section; do not restart the project or rewrite working collectors without a concrete reason.
