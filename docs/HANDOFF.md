# DogfighterAD development handoff

Last updated: 2026-09-06.

This is the compact continuation source of truth. Read `ARCHITECTURE.md`, `CAPABILITIES.md`, `ROADMAP.md`, `DEVELOPMENT.md`, `COLLECTION_PROFILES.md`, `DOGAD_FORMAT.md`, `CLI.md`, `MINILAB_RUNBOOK.md` and ADRs before substantial changes.

## Repository

- repository: `kusotsu/dogfighterAD`
- default branch: `main`
- active development branch: `foundation/snapshot-core`
- continue from the active branch unless the user explicitly requests merge/release;
- fetch current HEAD/CI before every write and preserve existing work;
- keep CI green before advancing architectural layers.

## Product direction

DogfighterAD is a snapshot-first, evidence-first Active Directory assessment platform. Initial users are professional pentesters/red-team/AD auditors; later the same core should support simpler company/blue-team periodic assessment.

It is not intended to be a BloodHound clone. Graph/path analysis will be one projection over a richer reproducible snapshot. Differentiators are coverage/provenance, evidence-first findings, offline re-analysis, deterministic artifacts/results, diff/retest and eventually a separately controlled Validation Plane.

Current phase is defensive/read-only. Do not add exploitation, credential dumping, destructive writes or automatic attack-path execution to collection.

## Core rules

1. Collectors acquire facts; rules/analyzers never query LDAP/SMB/RPC/SYSVOL directly.
2. Collection, normalization, serialization/storage, analysis, graph, reporting and future validation are separate responsibilities.
3. Incomplete collection never means safe; preserve `Partial/Failed/Blocked/...` and later `NotVerified`.
4. Snapshot schema and capability contracts are versioned for safe future offline analysis.
5. Logical ordering/fact identities/artifacts should be deterministic where promised.
6. Preserve provenance; do not collect secrets merely because readable.
7. Built-in profile capability sets change only deliberately.

## Technology/modules

- C# / .NET 10 LTS
- xUnit v3 + GitHub Actions
- `DogfighterAD.Domain`: canonical model only
- `DogfighterAD.Application`: planning/execution/assembly/profiles/telemetry
- `DogfighterAD.Collectors.ActiveDirectory`: read-only LDAP + SYSVOL collection and parent-side scope/normalization policy
- `DogfighterAD.SysvolWorker`: internal disposable helper process for filesystem/SMB lifetime isolation; not a service and not a security sandbox
- `DogfighterAD.Serialization`: deterministic `.dogad` outer artifact
- `DogfighterAD.Cli`: thin composition host for `scan` and offline `inspect`; no detection semantics

## Implemented foundation

- versioned normalized snapshot and stable AD object IDs;
- observed facts/provenance/redaction + deterministic FactId;
- capability coverage and contract-version compatibility;
- deterministic fragment merger and invariant validation;
- capability planner and bounded staged executor with cancellation/timeout/dependency blocking;
- planner handles one collector providing multiple selected capabilities exactly once in the execution graph;
- `minimal` / `audit-full` profiles and execution status/duration telemetry;
- streaming paged read-only LDAP transport using current-security-context Negotiate auth;
- LDAP SID normalization accepts both binary values and validated canonical text values observed from the Windows LDAP API;
- DACL-only descriptor collection/parsing;
- read-only SYSVOL abstraction with source-scope validation, per-file/count limits and bounded maxBytes+1 streaming reads;
- blocking SYSVOL filesystem operations isolated in a disposable helper process with per-operation deadlines, forced process-tree termination and restart after timeout/cancellation;
- deterministic `.dogad v1` writer/reader with manifest, SHA-256, canonical JSON checks, size limits and strict entry allowlist;
- runnable `dogfighter scan` composition path and offline `dogfighter inspect` summary;
- atomic/verified scan artifact publication: temporary write -> strict `.dogad` readback -> snapshot identity/status verification -> final replace;
- CLI rejects credential command-line options and reports structured completion exit codes.

## Implemented capabilities

- `directory.core v1`
- `directory.domains v1`
- `directory.users v1`
- `directory.groups v1`
- `directory.computers v1`
- `directory.ous v1`
- `directory.memberships v1` — ranged members, direct nested edges, primary groups, FSP
- `directory.trusts v1` — local configured trust objects only
- `directory.acls v1` — supported DACL/ACE semantics; unsupported semantics => Partial
- `gpo.metadata v1`
- `gpo.links v1` — order/options/Enabled/Enforced/Block Inheritance
- `gpo.sysvol v1` — file inventory/hash + supported GPT.INI/GptTmpl.inf/Registry.pol normalization and safe legacy cpassword-presence signal

`gpo.sysvol` never persists cpassword itself. Arbitrary Registry.pol string/binary payloads are metadata-only; suspicious INI secret values are redacted. Unknown files are inventory/hash evidence, not assumed understood settings.

SYSVOL scope/resource hardening was closed in the offline/cross-platform regression layer by `946c864d8f7431a80fee315b95a05be2d64424d5`, `76def69e30c7330827c1a771ba7da7ceb40f5f1f` and `0e2490b3c2a0dd42f80b399c5c4de24ce57c7854`. ADR 0011 records the worker isolation decision. This is lifecycle isolation, not privilege sandboxing, and real DFS/referral behavior still requires live validation.

The CLI composition landed in `76034c859d4798fef551865d9ad36f72e1ca2da8`. Planner production-registry coverage and the multi-capability fix landed in `1b460ebe33bc45eb555780ecdfd56b741c959425`; CI run `34029391724` passed on Ubuntu and Windows. Textual LDAP SID normalization landed in `9af8b09df281a398894f634c97a396cdfeb90df0`; CI run `34036771409` passed on Ubuntu and Windows. The synthetic CLI workflow still exercises planner -> executor -> snapshot assembly -> `.dogad` write -> strict offline readback without contacting AD.

## Profiles

`minimal`: core/domains/users/groups/computers/OUs/memberships/trusts; concurrency 2; collector timeout 2 minutes.

`audit-full`: minimal + ACLs + GPO metadata + GPO links + GPO SYSVOL; concurrency 4; collector timeout 3 minutes. SYSVOL was added deliberately only after contract/tests existed.

## CLI

Production commands currently exposed:

```text
dogfighter scan --target <host-or-domain> --output <snapshot.dogad> [--profile minimal|audit-full] [--ldaps] [--ldap-port N] [--sysvol-authority host]...
dogfighter inspect --snapshot <snapshot.dogad>
```

Authentication uses the process/current OS security context via LDAP Negotiate. Password/user arguments are intentionally unsupported. `inspect` is not the future Rule Engine `analyze` command.

Exit status is meaningful: 0 Complete, 2 Partial, 3 Failed, 64 invalid arguments, 70 runtime failure, 130 cancellation.

See `CLI.md` for exact behavior and `MINILAB_RUNBOOK.md` for live validation.

## `.dogad v1`

Strict ZIP with exactly `manifest.json` and canonical `snapshot.json`. Format version, serialization ID (`canonical-json-v1`), snapshot schema version and capability contract versions are separate compatibility axes. Same logical tested snapshot ordering produces byte-identical artifact. Reader checks bounded sizes, payload length/SHA-256, manifest/payload identity, snapshot invariants and canonical bytes, and rejects unknown entries.

SHA-256 is integrity detection, not an authenticity signature. Current implementation buffers the JSON payload in memory; large-domain benchmark is pending.

## Still pending before auditor-facing Collection Core is trusted

- corrected live `minimal` baseline with memberships executing and expected-vs-actual fixture checks;
- live `audit-full -> AdSnapshot -> .dogad -> offline inspect` against MINILAB/GOAD;
- exact expected-vs-actual object/member/GPO/ACL/SYSVOL fixture validation;
- real DFS/referral/inaccessible LDAP/SYSVOL partial-result fixtures;
- LDAP request/page counting and query/resource benchmarks;
- peak-memory measurement, especially `.dogad` serialization;
- broader forest/multi-domain/ADCS/LAPS/gMSA/Kerberos areas later.

## Latest live validation

See [MINILAB readiness/live run](lab-runs/2026-09-06-minilab-readiness.md).

The first functioning-domain `minimal` run produced snapshot `24f8fc1b-a591-4b65-9d25-29b4314ff39f` with `Partial`/exit 2: domains=1, users=8, groups=50, computers=2, OUs=1, memberships=0. Core/domains/users/computers/OUs/trusts completed; groups were Partial with 28 issues and memberships were Blocked.

The 28 issues were localized to Builtin groups whose valid `objectSid` values were returned by the Windows LDAP API as text instead of binary. `LdapValueConverters` previously inspected only binary SID values. Commit `9af8b09df281a398894f634c97a396cdfeb90df0` now normalizes validated text and binary SID representations and includes regressions for `S-1-5-32-544` plus malformed text. CI run `34036771409` is green on both supported runners.

The artifact from the pre-fix live run reopened successfully through offline `inspect` with the same snapshot ID. Audit-full has not been run yet, by design.

## Immediate next work

0. Rebuild/pull `9af8b09df281a398894f634c97a396cdfeb90df0` or later and rerun the **same MINILAB minimal fixture**. Do not add new collection features before this comparison.
1. Confirm `directory.groups` is Complete unless a new real fixture issue is exposed, and confirm `directory.memberships` executes rather than being Blocked. Compare expected/actual group/member counts and reopen the new `.dogad` offline.
2. Only after corrected minimal is understood, run `audit-full` and fix/harden any ACL/GPO/SYSVOL/referral differences observed in the real lab. Incomplete data must remain explicit.
3. After the live path is understood, instrument LDAP request/page counts and benchmark query volume/duration/peak memory before setting resource budgets.
4. Repeat the same validated collection workflow on the fuller GOAD fixture.
5. Then implement Rule Engine: capability-version prerequisites, `NotVerified`, stable finding fingerprints, evidence references and deterministic rule-pack execution.
6. Add the initial high-value auditor rule pack, then diff/retest, JSON/HTML reporting and graph projection.

Do **not** start a broad rule library before the live collection/artifact integration path is validated.

## Testing philosophy

Collectors get offline fake-client tests first, then live lab tests. Silent omission is worse than explicit `Partial`. The current offline/cross-platform suite includes collection contracts, serializer boundaries, SYSVOL source/resource/lifecycle regressions, production-registry planner coverage, text/binary SID normalization regressions and a synthetic CLI end-to-end artifact round trip. Future layers include clean-domain false-positive regression, planted misconfigurations, synthetic/golden snapshots, query/memory benchmarks and scanner read-only/security tests.

## New-chat instruction

> Continue DogfighterAD from GitHub repository `kusotsu/dogfighterAD`, branch `foundation/snapshot-core`. First read `docs/HANDOFF.md`, `docs/ARCHITECTURE.md`, `docs/CAPABILITIES.md`, `docs/ROADMAP.md`, `docs/DEVELOPMENT.md`, `docs/COLLECTION_PROFILES.md`, `docs/DOGAD_FORMAT.md`, `docs/CLI.md`, `docs/MINILAB_RUNBOOK.md` and ADRs. Fetch current branch and CI before writing. Preserve the snapshot-first/evidence-first/read-only architecture. Continue from `Immediate next work`; do not restart or rewrite green collectors without a concrete reason.
