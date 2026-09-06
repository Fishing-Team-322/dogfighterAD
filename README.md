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

The foundation branch contains the snapshot/domain model, deterministic fragment assembly, capability-driven collection planning/execution, read-only paged/streaming LDAP transport, RootDSE discovery, default-domain metadata, users/groups/computers/OUs, range-safe memberships, local configured trusts, DACL/ACE collection, GPO metadata/links and supported SYSVOL normalization. Stable fact identity, capability-version compatibility, core tests and cross-platform GitHub Actions CI are in place.

SYSVOL path scope and streaming byte limits are enforced before/while I/O. Potentially blocking SYSVOL filesystem calls are isolated in the disposable `DogfighterAD.SysvolWorker` helper process with per-operation deadlines and forced termination/restart.

A thin runnable CLI now composes the existing Collection Core:

```powershell
dogfighter scan --target dc01.mini.lab --profile minimal --output .\mini.dogad
dogfighter inspect --snapshot .\mini.dogad
```

`scan` uses the current OS security context for LDAP Negotiate authentication, writes a temporary deterministic `.dogad`, reads it back through the strict artifact reader, and only then replaces the requested output file. Password/username command-line options are intentionally unsupported. `inspect` is offline and prints snapshot/coverage/count summaries.

The CLI and offline synthetic round trip are covered by CI, but **no live AD/MINILAB/GOAD validation has yet been recorded**. Analysis rules, reports, diff/retest and graph analysis are not implemented yet.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [CLI](docs/CLI.md)
- [MINILAB / GOAD runbook](docs/MINILAB_RUNBOOK.md)
- [Capability contracts](docs/CAPABILITIES.md)
- [Roadmap and implementation status](docs/ROADMAP.md)
- [Development guide](docs/DEVELOPMENT.md)
- [Architecture Decision Records](docs/adr/)
- [Live lab run template](docs/lab-runs/TEMPLATE.md)

Development continues in `foundation/snapshot-core` before the first release is merged into `main`.
