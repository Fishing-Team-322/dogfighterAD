# DogfighterAD

DogfighterAD is a snapshot-first, evidence-first Active Directory security assessment platform.

The project is built around a strict separation between collection, normalization, analysis, evidence, storage, and reporting. The first development phase is read-only: collect security-relevant Active Directory facts into a versioned snapshot that can be analyzed and re-analyzed offline.

## Current direction

- read-only collection first;
- immutable, versioned snapshots;
- provenance and collection coverage as first-class data;
- versioned capability data contracts for safe offline re-analysis;
- independent rule and graph analysis over snapshots;
- deterministic findings with evidence and stable identities;
- offline re-analysis and retest/diff support;
- future validation/execution nodes remain a separate plane and are intentionally out of scope for the first phase.

## Current implementation

The foundation branch currently contains the snapshot/domain model, deterministic fragment assembly, capability-driven collection planning/execution, read-only paged/streaming LDAP transport, RootDSE discovery, default-domain metadata, one-pass collection of users/groups/computers/OUs, range-safe group membership collection with direct nested-group edges, primary groups and foreign security principals, and local trust relationship collection from `trustedDomain` objects. Stable fact identity, capability-version compatibility, core tests, and GitHub Actions CI are also in place.

A full AD assessment is **not implemented yet**. The next collection milestones are ACLs/security descriptors, GPO data, SYSVOL settings and portable snapshot serialization.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Capability contracts](docs/CAPABILITIES.md)
- [Roadmap and implementation status](docs/ROADMAP.md)
- [Development guide](docs/DEVELOPMENT.md)
- [Architecture Decision Records](docs/adr/)

Development continues in `foundation/snapshot-core` before the first release is merged into `main`.
