# Roadmap and implementation status

This document tracks what is actually implemented in the repository and what is planned next. It is intentionally conservative: an item is marked complete only when code and automated checks exist.

## Foundation — current branch

- [x] .NET 10 LTS baseline with warnings as errors and deterministic builds.
- [x] Snapshot-first architecture ADR.
- [x] Read-only collection boundary ADR.
- [x] Versioned snapshot schema foundation.
- [x] Normalized domain objects and relationship containers.
- [x] Generic directory-object fallback for not-yet-specialized object classes.
- [x] Observed facts with provenance and redaction disposition.
- [x] Stable versioned `FactId` generation.
- [x] Capability coverage with explicit failure/partial/blocked states.
- [x] Capability contract versions for future offline compatibility checks.
- [x] Capability contract versions preserved conservatively during fragment merging.
- [x] Deterministic snapshot fragment merging/assembly.
- [x] Capability-driven collection planner with dependency-cycle detection.
- [x] Staged collection executor with bounded concurrency, cancellation and timeouts.
- [x] Dependency failure propagation: downstream collectors are blocked instead of producing misleading clean data.
- [x] Read-only LDAP adapter with paging and binary attribute support.
- [x] Streaming paged LDAP entry API for large directory scans without transport-level full-result buffering.
- [x] RootDSE discovery collector.
- [x] Domain metadata collector using upstream RootDSE state.
- [x] One-pass directory object collector for users, groups, computers and OUs.
- [x] Portable GUID/SID/generalized-time/AD FileTime conversion helpers for LDAP normalization.
- [x] GitHub Actions build/test pipeline.
- [x] Core unit tests for fact IDs, capability compatibility, snapshot invariants, fragment merging, collection planning/execution and LDAP collector mapping.
- [x] Living architecture, roadmap, capability-contract and development documentation.

## Collection Core v1

Order matters. We build broad reliable collection before a large rule library.

- [x] Domain object collector: default domain metadata.
- [x] Directory users collector/capability.
- [x] Directory groups collector/capability.
- [x] Directory computers collector/capability.
- [x] Organizational units collector/capability.
- [ ] Group membership collector with nested relationship preservation, primary groups and foreign security principals.
- [ ] Trust collector.
- [ ] Security descriptor / ACL collector with correct object/inherited object GUID handling.
- [ ] GPO metadata and link collection from LDAP.
- [ ] SYSVOL read-only GPO settings collection.
- [ ] Collection profiles (`minimal`, `audit-full`, later custom profiles).
- [ ] Per-capability query budgets and collection telemetry.
- [ ] Snapshot serializer and portable `.dogad` artifact.
- [ ] Integrity metadata for portable snapshots.

## Collection Core v1.1

- [ ] Broader Kerberos-relevant account posture beyond the fields already captured in directory object v1.
- [ ] Additional delegation relationships and host/protocol context.
- [ ] LAPS posture and who-can-read relationships without collecting managed passwords by default.
- [ ] gMSA posture and access relationships without collecting secret blobs by default.
- [ ] AD CS directory topology and security-relevant configuration.
- [ ] Sites/subnets and forest topology where needed for assessment logic.
- [ ] Better partial-result accounting for referrals, inaccessible naming contexts and mid-stream LDAP failures.

## Analysis Core

- [ ] Rule engine with prerequisite/capability-version checks.
- [ ] Stable finding fingerprints.
- [ ] Finding lifecycle: new / existing / resolved.
- [ ] Evidence references back to snapshot observations.
- [ ] Deterministic analysis results.
- [ ] Rule metadata and rule-pack versioning.
- [ ] Initial high-value AD audit rule pack.
- [ ] Graph projection and path analysis as a separate analysis module.

## Audit workflow

- [ ] CLI scan command.
- [ ] Offline analyze command.
- [ ] Snapshot diff / retest workflow.
- [ ] JSON export.
- [ ] HTML audit report.
- [ ] Machine-readable coverage report showing what could and could not be verified.
- [ ] Suppression / accepted-risk model with audit trail.

## Later product layers

- [ ] Local/company-friendly UX over the same core engine.
- [ ] Scheduled/continuous assessment mode.
- [ ] Optional external-data import adapters where technically and legally appropriate.
- [ ] Separate Validation Plane and Validation Node contracts.
- [ ] Controlled active validation only after read-only assessment is mature and measurable.

## Explicitly not doing yet

- Microservices.
- Runtime third-party DLL plugin loading.
- Automatic exploitation.
- Credential dumping or collection of secrets simply because the account can read them.
- A custom graph database before measurement proves it is necessary.
- Reimplementing every existing AD security tool instead of focusing on a coherent audit workflow.

## Quality gates before first auditor-facing build

The first build intended for real auditors should not be released until:

1. clean AD and intentionally vulnerable AD fixtures both exist;
2. collection failures cannot silently become negative findings;
3. snapshots are reproducible and can be analyzed offline;
4. core collectors have integration tests against a lab domain;
5. known planted misconfigurations have expected findings and clean-state regression tests;
6. collection time, LDAP query count and peak memory are measured on multiple directory sizes;
7. every finding can explain what fact/evidence caused it;
8. the read-only claim has been validated by code review and integration tests.
