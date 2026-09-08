# DogfighterAD

DogfighterAD is a snapshot-first, evidence-first Active Directory security assessment platform. The current validated baseline is read-only: collect security-relevant AD facts into a versioned `.dogad` snapshot, analyze that snapshot offline, and preserve provenance/coverage so missing evidence cannot silently become a clean result.

## Current validated baseline

The current source includes:

- read-only `minimal` and `audit-full` AD collection;
- users, groups, computers, OUs, memberships, trusts, ACLs, GPO metadata/links, SYSVOL-normalized policy data and domain security-policy facts;
- portable explicit-credential Kerberos + SMB SYSVOL access from a non-domain Windows workstation;
- deterministic schema-2 `.dogad` snapshots with integrity validation and strict offline readback;
- an offline Rule Engine (`dogfighterad.core/1.0.0`) with 80 rule IDs;
- explicit analysis outcomes: `Present`, `Potential`, `NotDetected`, `NotVerified`, `NotApplicable`, `Error`;
- deterministic findings with evidence references, missing-data records and stable fingerprints;
- JSON and HTML analysis reports;
- a local loopback web UI for both end-to-end assessments and offline snapshot analysis;
- Windows/Ubuntu CI for build, tests and rule-catalog smoke, plus Windows self-contained publish smoke.

The CLI remains available for automation and troubleshooting:

```powershell
dogfighter scan --target dc.mini.lab --profile audit-full -u 'MINILAB\alice' --output .\audit.dogad
dogfighter inspect --snapshot .\audit.dogad
dogfighter rules
dogfighter analyze --snapshot .\audit.dogad --output .\findings.json --fail-on none
dogfighter analyze --snapshot .\audit.dogad --output .\findings.html --format html --fail-on none
```

The primary interactive workflow under development is the local web UI:

```powershell
dotnet run --project src/DogfighterAD.Web/DogfighterAD.Web.csproj -c Release
```

From the UI, **New assessment** performs collection, writes and verifies the `.dogad`, then automatically runs offline analysis and opens the findings dashboard. **Open existing snapshot** keeps the original offline-only workflow for previously collected artifacts. See [Local Web UI](docs/UI.md).

## Validation status

The Rule Engine milestone is no longer static-only. It has been compiled and tested on .NET 10, exercised against MINILAB, and promoted to `main` after CI.

The latest live Rule Engine acceptance on the non-domain/WORKGROUP Windows workstation completed `audit-full` with all requested capabilities `Complete`, zero collection issues, and exit code `0`. Offline analysis evaluated all 80 rules, produced 22 findings, and retained only two intentional `NotVerified` evaluations where `user.lastLogonTimestamp` was genuinely not observed. Local verification completed 678 tests with zero failures. The corresponding GitHub Windows/Ubuntu CI and Windows self-contained publish smoke also completed successfully.

Linux build/tests are green in CI. Live Linux Kerberos/SMB SYSVOL validation remains a separate acceptance item. The integrated UI assessment path is still a feature-branch milestone until it is live-validated end-to-end and promoted through the normal PR/CI flow.

See [Rule Engine](docs/RULE_ENGINE.md), [80-rule catalog](docs/RULES.md), [validation status](VALIDATION_RULE_ENGINE.md), [CLI](docs/CLI.md), [Local Web UI](docs/UI.md), and [roadmap](docs/ROADMAP.md).

## Product direction

The local web UI is the intended primary interactive surface. The browser is a controller/view over the local .NET host; LDAP, SYSVOL, snapshot validation and rule execution remain in the existing core services. The normal user workflow is:

```text
New assessment -> scan -> verified .dogad -> offline analyze -> findings
```

The snapshot boundary is not removed just because the UI automates the steps. A saved assessment still has a deterministic `.dogad` artifact that can be re-opened and re-analyzed offline.

Graph visualization is intentionally **not a requirement for the first UI milestones**. A graph view only becomes a first-class feature after DogfighterAD has a real graph projection/path-analysis module with defined semantics. The project will not add a graph database or graph visualization merely to imitate other AD tools.

The next collector/product milestone after the integrated assessment workflow is **AD CS / Certificate Services**: Enterprise CA objects, certificate templates, publication relationships, template/CA ACLs, enrollment posture and conservative ESC candidates where directory evidence is sufficient. CA runtime-dependent ESC checks remain `NotVerified` until their own read-only evidence exists.

Near-term workflow work after that includes snapshot diff/retest, finding lifecycle (`new` / `existing` / `resolved`), and accepted-risk/suppression with an audit trail.

## Architecture principles

- read-only collection first;
- immutable, versioned snapshots;
- provenance and collection coverage as first-class data;
- versioned capability contracts for safe offline re-analysis;
- deterministic analysis and report output;
- no automatic exploitation or credential dumping;
- no collection of secrets merely because they are readable;
- validation/execution remains a separate future plane.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [CLI](docs/CLI.md)
- [Local Web UI](docs/UI.md)
- [MINILAB / GOAD runbook](docs/MINILAB_RUNBOOK.md)
- [Capability contracts](docs/CAPABILITIES.md)
- [Rule Engine](docs/RULE_ENGINE.md)
- [Rule catalog](docs/RULES.md)
- [Roadmap and implementation status](docs/ROADMAP.md)
- [Development guide](docs/DEVELOPMENT.md)
- [Architecture Decision Records](docs/adr/)
- [Live lab run template](docs/lab-runs/TEMPLATE.md)

`main` tracks the validated baseline. Ongoing development continues on `foundation/snapshot-core` and short-lived feature branches, merged back only after review and validation.
