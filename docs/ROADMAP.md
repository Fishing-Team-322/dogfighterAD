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
- [x] Keep README/CLI/roadmap/validation docs synchronized with the validated baseline.
- [ ] Add/maintain deterministic sample reports for UI fixtures (`Complete`, `Partial/NotVerified`, findings-heavy).
- [ ] Expose UI-facing Application services so the UI does not shell out to the CLI for core operations.

### 0.3.0 — local web UI, offline-first

- [ ] Local loopback HTTP host backed by the existing .NET Application/Analysis core.
- [ ] Open/import `.dogad` snapshot.
- [ ] Run offline analysis without reconnecting to AD.
- [ ] Dashboard with assessment completion, coverage and severity summary.
- [ ] Findings list with severity/search filters.
- [ ] Finding detail with affected subject, risk, remediation and evidence provenance.
- [ ] Coverage/capability view.
- [ ] Explicit `NotVerified`/missing-data view.
- [ ] Snapshot metadata view.
- [ ] JSON/HTML export from the same in-memory analysis model.
- [ ] Package the UI into the normal distributable workflow after the first functional host is validated.

The first UI milestone is intentionally **not graph-dependent**. A graph visualization will only be added after graph projection/path-analysis semantics are implemented and validated. DogfighterAD will not introduce a graph database or graph UI solely to imitate another product.

### 0.3.1 — collection UX

- [ ] Scan wizard for target/profile/authentication selection.
- [ ] Hidden interactive credential entry; no password argv/environment/browser-storage persistence.
- [ ] Collector progress and cancellation.
- [ ] Live coverage/issues display.
- [ ] Save `.dogad` then analyze through the same core services.

### 0.3.2 — AD CS directory posture and certificate templates

This milestone follows the first usable UI foundation and is intentionally split between directory evidence and CA runtime evidence. Missing CA-side runtime configuration must remain `NotVerified`; DogfighterAD will not infer an ESC condition from data it did not collect.

- [ ] Add read-only Configuration NC collection for `CN=Public Key Services,CN=Services,CN=Configuration,...`.
- [ ] Collect Enterprise CA / Enrollment Services objects and stable CA identities.
- [ ] Collect certificate templates, including display name, template OID, schema/version and publication state.
- [ ] Collect template EKUs / application policies and authentication-relevant purpose information.
- [ ] Collect `msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`, `msPKI-Private-Key-Flag`, `msPKI-RA-Signature`, validity and renewal periods, and other reviewed template-security operands.
- [ ] Collect CA-to-template publication relationships.
- [ ] Collect `NTAuthCertificates` directory posture where relevant to authentication trust decisions.
- [ ] Collect DACLs on certificate templates and CA directory objects with evidence/provenance.
- [ ] Normalize enrollment/auto-enrollment and dangerous control relationships such as `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner` and security-relevant `WriteProperty` candidates.
- [ ] Add conservative template-focused findings/ESC candidates where directory evidence is sufficient, including dangerous template ACLs, broad enrollment plus authentication-capable template combinations, and subject-name supply conditions.
- [ ] Keep ESC checks that depend on CA registry/RPC/web-enrollment/runtime state explicitly `NotVerified` until those inputs have their own read-only collectors/contracts.
- [ ] Add a `Certificate Services` UI area showing CAs, templates, publication, enrollment principals, template flags and ACLs even when no finding is present.
- [ ] Add contextual relationship visualization only where useful (for example principal -> group -> Enroll -> template -> published CA); no graph database is required for this milestone.
- [ ] Validate planted vulnerable and clean AD CS fixtures so template findings have both positive and false-positive regression coverage.

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
- [ ] AD CS directory topology/security configuration and certificate templates — tracked in the dedicated 0.3.2 milestone above.
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
