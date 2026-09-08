# DogfighterAD

DogfighterAD is a snapshot-first, evidence-first Active Directory security assessment platform. The validated architecture is read-only: collect security-relevant AD facts into a versioned `.dogad` snapshot, analyze that snapshot offline, and preserve provenance/coverage so missing evidence cannot silently become a clean result.

## Current source baseline — 0.3.2 AD CS directory slice

The current source includes:

- read-only `minimal` and `audit-full` AD collection;
- users, groups, computers, OUs, memberships, trusts, ACLs, GPO metadata/links, SYSVOL-normalized policy data and domain security-policy facts;
- read-only AD CS Configuration-NC collection for Enterprise CAs, certificate templates, CA↔template publication, template/CA DACLs and NTAuth directory posture;
- portable explicit-credential Kerberos + SMB SYSVOL access from a non-domain Windows workstation;
- deterministic schema-2 `.dogad` snapshots with integrity validation and strict offline readback;
- an offline Rule Engine (`dogfighterad.core/1.2.0`) with **88 rule IDs**, including 8 evidence-first `ADCS.*` rules;
- explicit analysis outcomes: `Present`, `Potential`, `NotDetected`, `NotVerified`, `NotApplicable`, `Error`;
- deterministic findings with evidence references, missing-data records and stable fingerprints;
- JSON and HTML analysis reports;
- a local loopback web UI for both end-to-end assessments and offline snapshot analysis;
- a dedicated **Certificate Services** UI with CAs, templates and AD CS findings;
- Windows/Ubuntu CI for build, tests, web static-asset smoke, JavaScript syntax and rule-catalog smoke, plus Windows self-contained publish smoke.

The CLI remains available for automation and troubleshooting:

```powershell
dogfighter scan --target dc.mini.lab --profile audit-full -u 'MINILAB\alice' --output .\audit.dogad
dogfighter inspect --snapshot .\audit.dogad
dogfighter rules
dogfighter analyze --snapshot .\audit.dogad --output .\findings.json --fail-on none
dogfighter analyze --snapshot .\audit.dogad --output .\findings.html --format html --fail-on none
```

The local web UI is the intended primary interactive workflow:

```powershell
dotnet run --project src/DogfighterAD.Web/DogfighterAD.Web.csproj -c Release
```

From the UI, **New assessment** performs collection, writes and verifies the `.dogad`, then automatically runs offline analysis and opens the findings dashboard. **Open existing snapshot** keeps the offline-only workflow for previously collected artifacts. `audit-full` also requests the AD CS directory capabilities used by the Certificate Services workspace. See [Local Web UI](docs/UI.md).

## AD CS 0.3.2 scope

The production `CertificateServicesCollector` reads only the Configuration NC under `CN=Public Key Services,CN=Services,...`. It provides five narrow contracts:

- `adcs.authorities`;
- `adcs.templates`;
- `adcs.publication`;
- `adcs.acls`;
- `adcs.trust`.

The built-in pack adds:

- `ADCS.TEMPLATE.ESC1_CANDIDATE`;
- `ADCS.TEMPLATE.DANGEROUS_ACL`;
- `ADCS.TEMPLATE.BROAD_ENROLLMENT`;
- `ADCS.TEMPLATE.AUTHENTICATION_CAPABLE`;
- `ADCS.TEMPLATE.ENROLLEE_SUPPLIES_SUBJECT`;
- `ADCS.TEMPLATE.NO_APPROVAL`;
- `ADCS.TEMPLATE.NO_AUTHORIZED_SIGNATURE`;
- `ADCS.CA.DANGEROUS_DIRECTORY_ACL`.

`ADCS.TEMPLATE.ESC1_CANDIDATE` is deliberately a **Potential directory-derived candidate**, not a runtime-verified ESC1 claim. CA registry/RPC/service permissions, `EDITF_ATTRIBUTESUBJECTALTNAME2`, web enrollment, EPA/channel binding, NTLM behavior, issuance behavior and exploitability are outside the 0.3.2 capability set and must not be inferred from directory evidence.

The AD CS fixture matrix covers clean and positive templates, manager approval/signature gates, unpublished templates, broad enrollment without authentication purpose, dangerous template/CA ACLs, AutoEnroll, partial/legacy evidence, and nested custom-group enrollment where low privilege is proven through the normal membership engine.

## Validation status

The pre-AD-CS collection/Rule Engine baseline has live MINILAB acceptance from a non-domain/WORKGROUP Windows workstation, including complete `audit-full`, portable Kerberos SYSVOL and offline readback.

For the 0.3.2 AD CS branch, Windows and Ubuntu CI currently pass build, unit tests, web asset smoke, JavaScript syntax and rule-catalog smoke; Windows also passes the self-contained publish smoke. This is automated/synthetic validation. **Live MINILAB/GOAD AD CS acceptance is still pending** and must be recorded separately before claiming live CA/template coverage for a lab environment.

Linux build/tests are green in CI. Live Linux Kerberos/SMB SYSVOL validation remains a separate acceptance item.

See [Rule Engine](docs/RULE_ENGINE.md), [rule catalog](docs/RULES.md), [capability contracts](docs/CAPABILITIES.md), [Local Web UI](docs/UI.md), [MINILAB runbook](docs/MINILAB_RUNBOOK.md), and [roadmap](docs/ROADMAP.md).

## Product direction

The local web UI is the intended primary interactive surface. The browser is a controller/view over the local .NET host; LDAP, SYSVOL, snapshot validation and rule execution remain in existing core services. The normal user workflow is:

```text
New assessment -> scan -> verified .dogad -> offline analyze -> findings
```

The snapshot boundary is not removed just because the UI automates the steps. A saved assessment still has a deterministic `.dogad` artifact that can be re-opened and re-analyzed offline.

Graph visualization is intentionally **not a requirement for the first UI milestones**. A graph view only becomes a first-class feature after DogfighterAD has a real graph projection/path-analysis module with defined semantics.

Near-term work after the AD CS directory slice includes live AD CS validation, separate read-only CA runtime evidence where justified, snapshot diff/retest, finding lifecycle (`new` / `existing` / `resolved`), and accepted-risk/suppression with an audit trail.

## Architecture principles

- read-only collection first;
- immutable, versioned snapshots;
- provenance and collection coverage as first-class data;
- versioned capability contracts for safe offline re-analysis;
- deterministic analysis and report output;
- no automatic exploitation or credential dumping;
- no collection of secrets merely because they are readable;
- runtime/validation evidence remains a separate capability plane.

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

`main` tracks the validated baseline. Ongoing development uses short-lived feature branches and is merged only after review and validation.
