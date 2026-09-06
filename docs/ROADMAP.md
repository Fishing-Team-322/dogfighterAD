# Roadmap and implementation status

This document tracks what is actually implemented in the repository. An item is marked complete only when code and automated checks exist.

## Foundation — current branch

- [x] .NET 10 LTS baseline, warnings as errors and deterministic builds.
- [x] Snapshot-first/read-only architecture ADRs.
- [x] Versioned normalized snapshot schema and generic directory-object fallback.
- [x] Observed facts, provenance/redaction disposition and stable versioned `FactId` generation.
- [x] Capability coverage plus monotonic contract versions for offline compatibility checks.
- [x] Deterministic fragment merge/assembly and snapshot invariant validation.
- [x] Capability-driven collection planner with cycle/provider validation.
- [x] Staged executor with bounded concurrency, cancellation, timeout and dependency blocking.
- [x] Built-in `minimal` and `audit-full` profiles with explicit capability sets.
- [x] Execution duration/status telemetry.
- [x] Read-only LDAP transport, paged streaming enumeration and binary attributes.
- [x] DACL-only SD requests plus portable v1 DACL parser.
- [x] Read-only SYSVOL transport boundary with approved-source/root/child validation plus file-count/file-size guardrails.
- [x] Bounded SYSVOL file streaming that stops after maxBytes+1 detection instead of buffering unbounded growth.
- [x] Hard lifecycle/deadline boundary for blocking SYSVOL filesystem operations via a disposable helper process with forced termination/restart.
- [x] Portable deterministic `.dogad` artifact serializer/reader in a separate module.
- [x] `.dogad` manifest/payload integrity checks, canonical representation checks and strict v1 entry allowlist.
- [x] Thin read-only CLI composition layer with `scan` and offline `inspect`.
- [x] Verified artifact publication: temporary write -> strict `.dogad` readback -> final replace.
- [x] CLI credential-argument rejection, Ctrl+C cancellation and structured completion exit codes.
- [x] GitHub Actions build/test pipeline and core unit-test suite.
- [x] Living architecture/capability/profile/format/CLI/handoff documentation.

## Collection Core v1

- [x] RootDSE discovery / `directory.core`.
- [x] Default-domain metadata / `directory.domains`.
- [x] Users, groups, computers and OUs in one paged subtree pass.
- [x] Range-safe memberships, nested direct edges, primary groups and FSP support.
- [x] Local configured trusts.
- [x] DACL/security descriptors and supported ACEs.
- [x] GPO metadata.
- [x] GPO links/order/options and Block Inheritance.
- [x] Read-only SYSVOL file inventory and supported GPO setting normalization.
- [x] SYSVOL root/child scope rejection before reads, with explicit alternate-authority configuration.
- [x] Blocking SYSVOL filesystem operations isolated from the long-lived scanner process and terminated on operation timeout/cancellation.
- [x] `minimal` / `audit-full` profiles; `audit-full` deliberately includes `gpo.sysvol`.
- [x] Deterministic portable `.dogad v1` artifact.
- [x] SHA-256 payload integrity metadata and strict artifact reader.
- [x] Runnable composition path from profile -> collectors -> `AdSnapshot` -> `.dogad` -> offline readback in synthetic tests.
- [ ] LDAP request/page counting and per-capability query budgets.
- [ ] Peak-memory/resource telemetry and benchmark-derived thresholds.
- [ ] Live end-to-end validation against MINILAB/GOAD.
- [ ] Better partial-result accounting based on real referral/inaccessible-NC/SYSVOL failure fixtures.

## Collection Core v1.1

- [ ] Broader Kerberos-relevant account posture beyond fields already captured in v1.
- [ ] Additional delegation relationships and host/protocol context.
- [ ] LAPS posture and who-can-read relationships without collecting managed passwords by default.
- [ ] gMSA posture/access relationships without collecting secret blobs by default.
- [ ] AD CS directory topology/security configuration.
- [ ] Sites/subnets/forest topology and multi-domain collection.
- [ ] Additional conditional/callback ACE families when justified by real fixtures.

## Analysis Core

- [ ] Rule engine with capability/version prerequisite checks and explicit `NotVerified`.
- [ ] Stable finding fingerprints.
- [ ] Evidence references back to snapshot observations.
- [ ] Deterministic rule-pack execution and metadata/versioning.
- [ ] Finding lifecycle: new / existing / resolved.
- [ ] Initial auditor-focused AD rule pack.
- [ ] Graph projection/path analysis as a separate analysis module.

## Audit workflow

- [x] CLI `scan` producing a verified `.dogad` artifact.
- [x] Offline `inspect` loading `.dogad` without reconnecting to AD and showing coverage/count summary.
- [ ] Offline `analyze` loading `.dogad` without reconnecting to AD; blocked on Rule Engine.
- [ ] Snapshot diff / retest workflow.
- [ ] JSON export and HTML audit report.
- [ ] Machine-readable coverage report beyond the current console summary.
- [ ] Suppression / accepted-risk model with audit trail.

## Later product layers

- [ ] Company-friendly UX over the same core.
- [ ] Scheduled/continuous assessment mode.
- [ ] External-data import adapters where technically/legal appropriate.
- [ ] Separate Validation Plane / Validation Node contracts.
- [ ] Controlled active validation only after read-only assessment is mature and measurable.

## Explicitly not doing yet

- Microservices.
- Runtime arbitrary third-party DLL loading.
- Automatic exploitation or credential dumping.
- Collecting secrets merely because they are readable.
- A custom graph database before measurements justify it.
- Reimplementing every existing AD security tool instead of building a coherent assessment workflow.

## Immediate next stopping-point tasks

0. Execute and record the first MINILAB validation using `docs/MINILAB_RUNBOOK.md`: `minimal` first, then `audit-full`, with exact commit SHA, lab fixture state, expected/actual counts, coverage statuses and offline `inspect` readback. Store the record under `docs/lab-runs/` using the template; do not commit real/customer `.dogad` artifacts.
1. Fix/harden any collector, referral, inaccessible LDAP/SYSVOL or partial-coverage differences observed in the real lab. Incomplete data must remain explicit.
2. After the live path is understood, instrument LDAP request/page counts and measure query volume, duration and peak memory before setting budgets.
3. Repeat the same validated workflow on the fuller GOAD fixture.
4. Then implement the Rule Engine with capability-version prerequisites, stable finding fingerprints, evidence references, deterministic results and explicit `NotVerified` semantics.
5. Build the first high-value auditor rule pack, then diff/retest, JSON/HTML reporting and graph projection.

The CLI composition landed in commit `76034c859d4798fef551865d9ad36f72e1ca2da8`. CI run `34014916366` passed on Linux and Windows; the Linux execution reported 120 tests with no errors, failures or skips. This proves the synthetic/offline composition and artifact round trip, **not** live AD correctness.

SYSVOL scope, bounded streaming and blocking-I/O lifecycle blockers from the 2026-09-06 foundation review are closed in the offline/cross-platform regression layer. Real AD/SMB/DFS semantics remain live integration questions.

## Quality gates before first auditor-facing build

1. Clean and intentionally vulnerable AD fixtures exist.
2. Collection failures cannot silently become negative findings.
3. `.dogad` is reproducible, integrity-checked and can be consumed offline.
4. Core collectors have live lab integration coverage.
5. Planted misconfigurations have expected findings plus clean-state false-positive regressions.
6. Collection time, LDAP query/page count and peak memory are measured on multiple directory sizes.
7. Every finding explains the fact/evidence that caused it.
8. The read-only claim is validated by code review and integration tests.
