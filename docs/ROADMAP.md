# Roadmap and implementation status

This document tracks the current repository state through the 0.3.2 AD CS directory-posture milestone. An item is marked complete only when code and automated checks exist; live-lab claims are called out separately.

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
- [x] GitHub Actions build/test pipeline on Windows and Ubuntu plus web/JS/rule-catalog smoke and Windows self-contained publish smoke.

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
- [x] Complete pre-AD-CS `audit-full` live validation from a non-domain/WORKGROUP Windows workstation using explicit credentials and portable Kerberos SYSVOL.
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
- [x] Auditor-focused built-in pack `dogfighterad.core/1.2.0` with 88 rule IDs.
- [x] JSON and HTML report generation.
- [x] Safe handling of missing/omitted LDAP fields without substituting CLR defaults.
- [x] Evidence-backed nested group membership reused by AD CS enrollment-principal analysis.
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

### 0.3.0 — local web UI, offline-first

- [x] Local loopback HTTP host backed by the existing .NET Application/Analysis core.
- [x] Open/import `.dogad` snapshot.
- [x] Run offline analysis without reconnecting to AD.
- [x] Dashboard with assessment completion, coverage and severity summary.
- [x] Findings list with severity/search filters.
- [x] Finding detail with affected subject, risk, remediation and evidence provenance.
- [x] Coverage/capability view.
- [x] Explicit `NotVerified`/missing-data view.
- [x] Basic snapshot/report metadata view.
- [x] JSON/HTML export from the same in-memory analysis model.
- [ ] Package the UI into the normal distributable workflow after live UI acceptance.

The first UI milestone is intentionally **not graph-dependent**. A graph visualization will only be added after graph projection/path-analysis semantics are implemented and validated.

### 0.3.1 — integrated assessment workflow

- [x] `New assessment` workflow for target/profile/authentication selection.
- [x] Current-OS-context and explicit username/password collection paths.
- [x] Password input is not persisted in browser storage/argv/environment/report state and is cleared after request construction.
- [x] LDAP Negotiate/NTLM compatibility selection, optional LDAPS/port and approved SYSVOL authorities.
- [x] Live collector progress with state/elapsed/issue display.
- [x] Cancellation while collection or analysis is active.
- [x] Save a verified `.dogad` into the current user's local assessment-data directory.
- [x] Download the generated `.dogad` from the loopback UI.
- [x] Automatically analyze the completed snapshot and open findings/coverage/NotVerified workspace.
- [x] Keep `Open existing snapshot` as a separate offline-only workflow.
- [ ] Persist assessment metadata/report history across UI process restarts.

The integrated workflow preserves the snapshot boundary: `UI -> collectors -> verified .dogad -> offline Rule Engine -> findings`. The browser is only a controller/view; LDAP/SYSVOL/AD CS collection remains in the local .NET host.

### 0.3.2 — AD CS directory posture and certificate templates

This milestone deliberately separates directory evidence from CA runtime evidence. Directory-only evidence can produce narrow posture findings and **Potential** ESC candidates; it cannot prove CA runtime configuration or exploitability.

- [x] Add read-only Configuration NC collection for `CN=Public Key Services,CN=Services,CN=Configuration,...`.
- [x] Collect Enterprise CA / Enrollment Services objects and stable CA identities.
- [x] Collect certificate templates, including display name, template OID, schema/version and publication state.
- [x] Collect template EKUs / application policies and authentication-relevant purpose information.
- [x] Collect `msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`, `msPKI-Private-Key-Flag`, `msPKI-RA-Signature`, validity and renewal periods.
- [x] Collect CA-to-template publication relationships.
- [x] Collect `NTAuthCertificates` directory posture and certificate fingerprints.
- [x] Collect DACLs on certificate templates and CA directory objects with evidence/provenance.
- [x] Normalize Enrollment/AutoEnrollment plus dangerous direct directory-control candidates such as `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner` and unrestricted `WriteProperty`.
- [x] Add 8 evidence-first `ADCS.*` rules, including `ADCS.TEMPLATE.ESC1_CANDIDATE` as a directory-derived `Potential` candidate.
- [x] Keep CA registry/RPC/web-enrollment/runtime-dependent checks outside the 0.3.2 contracts; missing runtime evidence is never inferred from directory data.
- [x] Add a `Certificate Services` UI area showing CAs, templates, publication, enrollment principals, template flags, ACLs, findings and evidence even when no finding is present.
- [x] Reuse the existing membership proof engine for custom/nested enrollment groups rather than hardcoding only well-known broad SIDs.
- [x] Validate synthetic planted vulnerable and clean AD CS fixtures, including approval/signature gates, unpublished templates, non-authentication EKU, AutoEnroll, dangerous CA/template ACLs, partial/legacy evidence and nested low-privilege membership.
- [x] Windows/Ubuntu CI: build, unit tests, web asset smoke, JavaScript syntax and offline rule catalog; Windows self-contained publish smoke.
- [ ] Live MINILAB/GOAD AD CS acceptance with a real Enterprise CA and certificate-template inventory.
- [ ] Optional relationship/path visualization only after a concrete UI need and semantics justify it; no graph database is required.

### 0.4.0 — retest and lifecycle

- [ ] Snapshot/report comparison.
- [ ] `new` / `existing` / `resolved` finding states using stable fingerprints.
- [ ] Accepted-risk/suppression records with audit history.
- [ ] Historical trend views in the UI.

## Collection Core v1.1 / later analysis

- [ ] Read-only CA runtime evidence under separate capability IDs when justified (registry/RPC/service/web enrollment/EPA/NTLM).
- [ ] Broader Kerberos-relevant account posture.
- [ ] Additional delegation relationships and host/protocol context.
- [ ] LAPS posture and who-can-read relationships without collecting managed passwords by default.
- [ ] gMSA posture/access relationships without collecting secret blobs by default.
- [ ] Sites/subnets/forest topology and multi-domain collection.
- [ ] Additional conditional/callback ACE families when justified by real fixtures.
- [ ] Graph projection/path analysis once evidence semantics are defined.

## Explicitly not doing yet

- Microservices.
- Runtime arbitrary third-party DLL loading.
- Automatic exploitation or credential dumping.
- Collecting secrets merely because they are readable.
- Treating directory-derived AD CS posture as proof of runtime CA exploitability.
- A custom graph database before measurements and analysis semantics justify it.
- Graph visualization without a validated graph-analysis model behind it.

## Quality gates before promotion

1. Collection failures cannot silently become negative findings.
2. `.dogad` remains reproducible, integrity-checked and consumable offline.
3. Core collectors and Rule Engine remain covered by Windows/Ubuntu CI.
4. Live-lab acceptance claims are reproducible and documented separately from synthetic CI.
5. Every finding can explain the fact/evidence that caused it.
6. Partial/missing evidence remains visible as `NotVerified`, never a false clean result.
7. UI uses the same core analysis/collection services as CLI rather than duplicating security logic.
8. Credentials and sensitive transport material never enter browser storage, argv, logs or persisted UI state.
9. A UI-created assessment writes and verifies its `.dogad` before the snapshot is treated as a saved assessment artifact.
10. AD CS runtime-dependent conditions require separate runtime evidence and are never inferred from Configuration-NC data.
