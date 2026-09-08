# Local Web UI

DogfighterAD's primary interactive workflow is a local web application backed by the same .NET collection and analysis core as the CLI. The UI is intentionally functionality-first: a user can start an assessment, watch collection progress, receive a verified `.dogad`, and inspect the resulting findings without manually chaining separate CLI commands.

## Run from source

```powershell
dotnet run --project src/DogfighterAD.Web/DogfighterAD.Web.csproj -c Release
```

The host binds only to loopback by default:

```text
http://127.0.0.1:51837
```

The default browser is opened automatically. To choose another local port or avoid automatic browser launch:

```powershell
dotnet run --project src/DogfighterAD.Web/DogfighterAD.Web.csproj -c Release -- --port 51900 --no-open
```

## Primary workflow: New assessment

1. Open the local UI.
2. Enter a DC/domain target.
3. Choose `audit-full` or `minimal`.
4. Choose the current OS context or explicit username/password authentication.
5. Optionally select LDAPS, a custom LDAP port, LDAP NTLM compatibility mode, or additional approved SYSVOL authorities.
6. Click **Start assessment**.
7. Watch collector progress and cancel if needed.
8. DogfighterAD writes the result to a private local assessment directory as a verified `.dogad` artifact.
9. After collection succeeds, the same local host automatically runs the offline Rule Engine over that snapshot.
10. The findings dashboard opens with severity summary, evidence, coverage and `NotVerified` explanations.
11. Download the `.dogad` or export the in-memory analysis as JSON/HTML.

The intended user experience is therefore:

```text
UI -> scan -> verified .dogad -> offline analyze -> findings
```

The snapshot boundary remains explicit even though the UI automates the transitions. Collection results are not analyzed directly as an unverified transient object: the workflow writes and round-trips the `.dogad` before it is exposed as the saved assessment artifact.

## Secondary workflow: Open existing snapshot

The original offline workflow remains available:

1. Choose an existing `.dogad`.
2. Click **Analyze snapshot**.
3. Review findings, coverage and missing evidence.
4. Export JSON or HTML.

This path never reconnects to LDAP or SYSVOL.

## What the UI currently shows

- assessment state and collector progress;
- cancellation while collection/analysis is active;
- saved snapshot status and a `.dogad` download;
- analysis completion state;
- Critical/High/Medium/Low severity summary;
- finding search and severity filters;
- finding description, risk and remediation;
- affected AD objects;
- evidence paths, observed values and collector/source provenance;
- capability coverage and collection issues;
- explicit `NotVerified` / error evaluations;
- JSON and HTML report export.

## Credential and local-data boundaries

- HTTP binds to `127.0.0.1` only.
- No scan target, password or snapshot is sent to an external service by the UI.
- Passwords are not written to browser storage, command-line arguments, environment variables, reports or logs by this workflow.
- The browser password field is cleared immediately after the start request is constructed.
- Explicit credentials are converted to the same `NetworkCredential`/secure-string form used by production LDAP/SYSVOL clients and disposed when the scan task finishes.
- The current host does not persist passwords or reusable credentials between assessments.
- Verified snapshots created by the UI are stored below the current user's local application-data directory in `DogfighterAD/Assessments`.
- On Unix, assessment directories/files are restricted to the current user where the platform file-mode APIs are available.
- Analysis reports remain in a bounded in-process store for this milestone; persisted assessment/report history is a later feature.
- Uploaded existing snapshots are processed through bounded temporary files and the strict existing `.dogad` reader.
- Responses use `no-store`, CSP, no-referrer and content-type hardening headers.

Loopback HTTP is a local process boundary, not transport security for a remote deployment. The current UI must not be exposed on a non-loopback interface. A future remotely hosted/multi-user mode would require a separate authentication, authorization and TLS design rather than changing the bind address.

## Collection behavior

The web assessment path composes the same production collectors used by the CLI:

- RootDSE;
- domain metadata;
- domain security policy / PSO;
- users, groups, computers and OUs;
- memberships;
- trusts;
- ACLs;
- GPO metadata and links;
- SYSVOL GPO collection.

Explicit credentials retain the existing security behavior: LDAP defaults to Negotiate, optional NTLM is LDAP-only compatibility mode, and SYSVOL uses portable Kerberos with the same credential. Explicit credentials require a DNS hostname target. LDAP signing/sealing remains the default when LDAPS is not selected.

## Not yet implemented

- persisted recent-assessment/history browser;
- retest/diff lifecycle and finding states;
- accepted-risk/suppression workflow;
- AD CS/certificate-template collection and `Certificate Services` UI;
- graph/path analysis;
- polished distributable packaging/live UI acceptance beyond source execution.

AD CS and certificate templates are tracked as the dedicated 0.3.2 milestone in `ROADMAP.md`.
