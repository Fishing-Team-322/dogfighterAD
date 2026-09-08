# Local Web UI

The first DogfighterAD UI milestone is an offline-first local web application. It is intentionally functional before it is visually elaborate.

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

## First workflow

1. Open the local UI.
2. Select an existing `.dogad` snapshot.
3. Click **Analyze snapshot**.
4. Review severity summary and completion state.
5. Filter/search findings and select one to see description, risk, remediation, affected objects and evidence provenance.
6. Review **Coverage** for collector capability status.
7. Review **Not verified** for checks that could not reach a trustworthy verdict.
8. Export the same in-memory analysis as JSON or HTML.

The UI uses the existing strict `.dogad` reader and the same built-in Rule Engine as the CLI. It does not shell out to `dogfighter analyze` and it does not reconnect to LDAP/SYSVOL while analyzing an imported snapshot.

## Security boundaries

- HTTP binds to `127.0.0.1` only.
- Snapshot uploads are processed locally.
- The current UI does not persist snapshots or reports in browser storage.
- The server keeps only a bounded set of recent reports in process memory.
- Temporary snapshot copies use the existing artifact size boundary and are deleted after analysis.
- Responses use `no-store`, CSP, no-referrer and content-type hardening headers.
- This milestone does not accept AD credentials. Credential entry belongs to the later scan-wizard milestone and must never persist passwords in browser storage, argv, environment variables or logs.

## Current scope

Implemented in the foundation UI:

- local `.dogad` import;
- offline analysis;
- assessment completion and severity summary;
- finding search/severity filter;
- finding detail, affected objects and evidence;
- capability coverage;
- explicit `NotVerified` / error checks;
- JSON/HTML export.

Not yet implemented:

- scan wizard/live collector progress;
- persisted assessment history;
- retest/diff lifecycle;
- AD CS/certificate-template collection and UI;
- graph/path analysis.

AD CS and certificate templates are tracked as the dedicated 0.3.2 milestone in `ROADMAP.md`.
