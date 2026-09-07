# DogfighterAD

> Review-fix source package: see [PATCH_NOTES_RU.md](PATCH_NOTES_RU.md) for the exact baseline, fixes, compatibility limits and validation status. Run `scripts/verify.sh` or `scripts/verify.ps1` with .NET 10 before deployment.

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

SYSVOL path scope and streaming byte limits are enforced before/while I/O. Potentially blocking SYSVOL work is isolated in the disposable `DogfighterAD.SysvolWorker` helper process with per-operation deadlines and forced termination/restart. With explicit `-u/--username` credentials, the worker uses DogfighterAD-owned Kerberos + SMB 3.1.1 with required signing against the named DC instead of depending on the host OS SMB redirector. Without `-u`, the existing operating-system network security context path remains available.

A thin runnable CLI now composes the existing Collection Core:

```powershell
dogfighter scan --target dc01.mini.lab --profile minimal --output .\mini.dogad
dogfighter inspect --snapshot .\mini.dogad
```

`scan` uses the current OS security context for LDAP Negotiate authentication when no explicit identity is supplied. Explicit usernames are accepted with `-u`; passwords are read only from the hidden prompt and are reused for both LDAP and portable Kerberos SYSVOL on `audit-full`. NTLM is an explicit LDAP compatibility mode only and requires `--ldap-auth ntlm`. Non-TLS LDAP requires signing and sealing; `--ldaps` keeps platform certificate validation. Explicit credentials require a resolvable DC DNS hostname/FQDN rather than an IP literal. `inspect` is offline and prints snapshot/coverage/count summaries.

MINILAB live validation now includes a complete `audit-full` run from a non-domain/WORKGROUP Windows workstation using explicit credentials and portable Kerberos SYSVOL: all directory/GPO/SYSVOL capabilities completed with zero issues, and strict offline `.dogad` readback reproduced the same snapshot ID and coverage. Linux build/tests are green in CI; Linux live SYSVOL validation remains a later acceptance gate. Analysis rules, reports, diff/retest and graph analysis are not implemented yet.

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
