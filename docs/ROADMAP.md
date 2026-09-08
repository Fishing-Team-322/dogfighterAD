# Roadmap and implementation status

This document tracks the current repository state after the validated Rule Engine 0.2.x milestone. An item is marked complete only when code and automated checks exist; live-lab claims are called out separately.

## Foundation — validated baseline

- [x] .NET 10 baseline, warnings as errors and deterministic builds.
- [x] Snapshot-first/read-only architecture ADRs.
- [x] Versioned normalized snapshot schema and generic directory-object fallback.
- [x] Observed facts, provenance/redaction disposition and stable versioned `FactId` generation.
- [x] Capability coverage plus monotonic contract versions for offline compatibility checks.
- [x] Deterministic fragment merge/assembly and snapshot invariant validation.
- [x] Capability-driven collection planner with cycle/provider validation.
- [x] Staged executor with bounded concurrency, cancellation, timeout and dependency blocking.
- [x] Built-in `minimal` and `audit-full` profiles.
- [x] Read-only paged/streaming LDAP transport and DACL-only security-descriptor reads.
- [x] Read-only SYSVOL scope enforcement, byte/file limits and isolated worker lifecycle.
- [x] Portable explicit-credential Kerberos + SMB 3.1.1 SYSVOL transport with required signing.
- [x] Deterministic portable `.dogad` artifact with strict integrity/readback validation.
- [x] Thin CLI composition for `scan`, `inspect`, `rules`, and offline `analyze`.
- [x] GitHub Actions build/test pipeline on Windows and Ubuntu plus Windows self-contained publish smoke.

## Collection Core v1

- [x] RootDSE / `directory.core`.
- [x] Domain metadata / `directory.domains`.
- [x] Users, groups, computers and OUs.
- [x] Range-safe memberships, primary groups and FSP support.
- [x] Local configured trusts.
- [x] DACL/security descriptors and supported ACEs.
- [x] GPO metadata and links.
- [x] Read-only SYSVOL inventory and supported GPO setting normalization.
- [x] Domain password/lockout defaults, machine-account quota and PSO collection for offline rules.
- [x] Complete `audit-full` live validation from a non-domain/WORKGROUP Windows workstation using explicit credentials and portable Kerberos SYSVOL.
- [ ] Live Linux Kerberos/SMB SYSVOL validation.
- [ ] LDAP request/page counting and per-capability query budgets.
- [ ] Peak-memory/resource telemetry and benchmark-derived thresholds.
- [ ] Fuller GOAD live end-to-end validation.
- [ ] Better partial-result accounting based on real referral/inaccessible-NC/SYSVOL failure fixtures.

## Analysis Core

- [x] Offline Rule Engine with capability/version prerequisites and explicit `NotVerified`.
- [x] Stable finding fingerprints.
- [x] Evidence references back to snapshot observations.
- [x] Deterministic rule-pack execution and metadata/versioning.
- [x] Initial auditor-focused built-in pack with 80 rule IDs.
- [x] JSON and HTML report generation.
- [x] Safe handling of missing/omitted LDAP fields without substituting CLR defaults.
- [ ] Finding lifecycle: `new` / `existing` / `resolved`.
- [ ] Snapshot diff/retest engine.
- [ ] Accepted-risk / suppression model with audit trail.
- [ ] Graph projection/path analysis as a separate analysis module.

## Audit workflow

- [x] `scan` producing a verified `.dogad` artifact.
- [x] Offline `inspect` showing snapshot/coverage/object summary.
- [x] Offline `rules` catalog command.
- [x] Offline `analyze` loading `.dogad` without reconnecting to AD.
- [x] Machine-readable JSON analysis report.
- [x] Human-readable HTML analysis report.
- [x] Explicit analysis exit semantics for complete, partial, threshold-triggered and error outcomes.
- [ ] Snapshot diff / retest workflow.
- [ ] Finding lifecycle across repeated assessments.
- [ ] Suppression / accepted-risk model with audit trail.
- [ ] Historical assessment store.

## Product/UI layer

### 0.2.1 — contract/documentation stabilization

- [x] Rule Engine and report schema exist as a stable offline integration surface.
- [ ] Keep README/CLI/roadmap/validation docs synchronized with the validated baseline.
- [ ] Add/maintain deterministic sample reports for UI fixtures (`Complete`, `Partial/NotVerified`, findings-heavy).
- [ ] Expose UI-facing Application services so the UI does not shell out to the CLI for core operations.

### 0.3.0 — local web UI, offline-first

- [ ] Local HTTP host backed by the existing .NET Application/Analysis core.
- [ ] Open/import `.dogad` snapshot.
- [ ] Run offline analysis.
- [ ] Dashboard with assessment completion, coverage and severity summary.
- [ ] Findings list with severity/category/outcome filters.
- [ ] Finding detail with affected subject, evidence and missing-data explanation.
- [ ] Coverage/capability view.
- [ ] Snapshot metadata view.
- [ ] JSON/HTML export from the same analysis model.

The first UI milestone is intentionally **not graph-dependent**. A graph visualization will only be added after graph projection/path-analysis semantics are implemented and validated. DogfighterAD will not introduce a graph database or graph UI solely to imitate another product.

### 0.3.1 — collection UX

- [ ] Scan wizard for target/profile/authentication selection.
- [ ] Hidden interactive credential entry; no password argv/environment persistence.
- [ ] Collector progress and cancellation.
- [ ] Live coverage/issues display.
- [ ] Save `.dogad` then analyze through the same core services.

### 0.4.0 — retest and lifecycle

- [ ] Snapshot/report comparison.
- [ ] `new` / `existing` / `resolved` finding states using stable fingerprints.
- [ ] Accepted-risk/suppression records with audit history.
- [ ] Historical trend views in the UI.

## Collection Core v1.1 / later analysis

- [ ] Broader Kerberos-relevant account posture.
- [ ] Additional delegation relationships and host/protocol context.
- [ ] LAPS posture and who-can-read relationships without collecting managed passwords by default.
- [ ] gMSA posture/access relationships without collecting secret blobs by default.
- [ ] AD CS directory topology/security configuration.
- [ ] Sites/subnets/forest topology and multi-domain collection.
- [ ] Additional conditional/callback ACE families when justified by real fixtures.
- [ ] Graph projection/path analysis once evidence semantics are defined.

## Explicitly not doing yet

- Microservices.
- Runtime arbitrary third-party DLL loading.
- Automatic exploitation or credential dumping.
- Collecting secrets merely because they are readable.
- A custom graph database before measurements and analysis semantics justify it.
- Graph visualization without a validated graph-analysis model behind it.
- Reimplementing every existing AD security tool instead of building a coherent assessment workflow.

## Quality gates before the first auditor-facing UI build

1. Collection failures cannot silently become negative findings.
2. `.dogad` remains reproducible, integrity-checked and consumable offline.
3. Core collectors and Rule Engine remain covered by Windows/Ubuntu CI.
4. MINILAB live acceptance remains reproducible and documented.
5. Every finding can explain the fact/evidence that caused it.
6. Partial/missing evidence remains visible as `NotVerified`, never a false clean result.
7. UI uses the same core analysis/collection services as CLI rather than duplicating security logic.
8. Credentials and sensitive transport material never enter browser storage, argv, logs or persisted UI state.
