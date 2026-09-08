# DogfighterAD CLI

The CLI is a thin composition layer over collection, snapshot serialization and offline analysis. It does not duplicate collector or rule logic.

## Build

```powershell
dotnet build src/DogfighterAD.Cli/DogfighterAD.Cli.csproj -c Release
```

The build also produces/copies `DogfighterAD.SysvolWorker` beside the CLI output. `audit-full` requires the worker because potentially blocking SYSVOL operations execute outside the long-lived scanner process and are terminated/restarted on timeout or cancellation.

Standalone Windows publish:

```powershell
dotnet publish src/DogfighterAD.Cli/DogfighterAD.Cli.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -o C:\DogfighterBuild
```

The publish output must contain the CLI and complete `DogfighterAD.SysvolWorker` runtime set, including Kerberos/SMB dependencies.

## Authentication model

### No explicit username

Without `-u/--username`, LDAP uses the current OS security context with Negotiate. SYSVOL uses the OS network security context through the isolated worker.

### Explicit username

Supplying `-u/--username` opens a hidden interactive password prompt:

```powershell
./dogfighter scan `
  --target dc.mini.lab `
  --profile audit-full `
  -u 'MINILAB\alice' `
  --output .\artifacts\mini-audit-full.dogad
```

The password is never accepted on the command line. Password-like CLI options are intentionally rejected.

The same prompted credential is used for:

- LDAP authentication to the exact named DC; and
- portable Kerberos SYSVOL authentication when `audit-full` reaches `gpo.sysvol`.

LDAP defaults to Negotiate regardless of whether the username is `DOMAIN\user` or `user@domain`. NTLM is an explicit LDAP-only compatibility mode:

```text
--ldap-auth ntlm
```

`--ldap-auth ntlm` requires `-u/--username`. Username syntax never silently selects NTLM.

Explicit credentials require a resolvable DC DNS hostname/FQDN. IP literals are rejected before prompting/collection. The named host is used as the exact LDAP server and Kerberos/SMB server identity for SYSVOL.

Without `--ldaps`, LDAP signing and sealing are mandatory. With `--ldaps`, normal platform certificate validation remains enabled. There is no silent unprotected downgrade.

## Portable SYSVOL with explicit credentials

When `-u` is supplied, `gpo.sysvol` does not depend on the Windows UNC redirector or a pre-existing OS SMB session. The isolated worker owns the network path:

1. obtain Kerberos credentials for the prompted identity;
2. request `cifs/<target>` for the exact approved server;
3. connect directly to TCP/445;
4. negotiate SMB 3.1.1;
5. require SMB signing;
6. connect to `SYSVOL`;
7. enumerate/read only paths that passed the collector SYSVOL scope policy.

Credentials, Kerberos tickets/session keys and SMB security blobs are not persisted in argv, environment variables, logs or `.dogad` artifacts.

The startup marker identifies the selected mode, for example:

```text
Starting collection: target=dc.mini.lab profile=audit-full ldap-auth=negotiate ldap-protection=sign-seal ldap-target-mode=fqdn-server sysvol-auth=portable-kerberos bind-timeout=00:00:15 request-timeout=00:00:30 collector-timeout=00:03:00.
```

## Current timeout boundaries

- LDAP connection/authentication setup: 15 seconds;
- each LDAP request: 30 seconds;
- collector timeout: 2 minutes for `minimal`, 3 minutes for `audit-full`;
- isolated SYSVOL worker operation deadline: 30 seconds.

Automatic native LDAP referral chasing is disabled. Current collectors assess the selected naming context on the selected server; referred partitions/servers are not implicitly assessed.

## `scan`

Minimal collection using current OS context:

```powershell
./dogfighter scan `
  --target dc01.mini.lab `
  --profile minimal `
  --output .\artifacts\mini-minimal.dogad
```

Full collection using explicit credentials and portable SYSVOL:

```powershell
./dogfighter scan `
  --target dc.mini.lab `
  --profile audit-full `
  -u 'MINILAB\alice' `
  --output .\artifacts\mini-audit-full.dogad
```

Optional LDAPS:

```powershell
./dogfighter scan `
  --target dc01.mini.lab `
  --profile minimal `
  --ldaps `
  --ldap-port 636 `
  --output .\artifacts\mini-ldaps.dogad
```

`--ldap-port` defaults to `389`, or `636` with `--ldaps`.

### Explicit SYSVOL authorities

Parent-side scope validation automatically permits the GPO domain DFS authority and current collection target when the normalized GPO path matches the expected `SYSVOL/<domain>/Policies/{GPO-GUID}` root.

A controlled alternate authority can be approved explicitly:

```text
--sysvol-authority dc02.mini.lab
```

The option is repeatable. It is a path-policy approval mechanism, not a wildcard and not permission to contact arbitrary hosts. Portable explicit-credential operation still connects to the exact scan target DC for Kerberos/SMB.

## Collection progress and safe diagnostics

The CLI prints per-collector progress:

```text
[collection] start collector=ad.sysvol.gpo-settings timeout=00:03:00
[collection] done collector=ad.sysvol.gpo-settings elapsed=00:00:11.7
```

Collector failures are evidence-first and sanitized. Passwords, tickets/session keys and arbitrary server payloads are not printed by the normal CLI path.

Known LDAP issue codes include:

- `collection.ldap.authentication-failed`
- `collection.ldap.bind-timeout`
- `collection.ldap.server-unavailable`
- `collection.ldap.timeout`
- `collection.ldap.security-required`
- `collection.ldap.failed`

## Artifact publication

`scan` does not stream directly into the requested final filename. It:

1. executes the capability plan;
2. assembles the canonical `AdSnapshot`;
3. writes a temporary `.dogad` artifact;
4. re-opens it through the strict reader;
5. verifies snapshot identity/status agreement;
6. atomically replaces the requested output path.

A failed/cancelled write or failed readback is not intentionally published as the requested final artifact.

## `inspect`

`inspect` is fully offline and opens only the supplied `.dogad`:

```powershell
./dogfighter inspect --snapshot .\artifacts\mini-audit-full.dogad
```

It prints snapshot metadata, object counts, capability coverage and sanitized collection issues.

## `rules`

List the built-in offline rule catalog:

```powershell
./dogfighter rules
./dogfighter rules --format json
```

The current built-in pack is `dogfighterad.core/1.0.0` with 80 rule IDs.

## `analyze`

`analyze` is fully offline. It accepts a validated `.dogad` snapshot and does not create LDAP, SYSVOL, endpoint or external rule-service connections.

JSON report:

```powershell
./dogfighter analyze `
  --snapshot .\artifacts\mini-audit-full.dogad `
  --output .\artifacts\analysis.json `
  --fail-on none
```

HTML report:

```powershell
./dogfighter analyze `
  --snapshot .\artifacts\mini-audit-full.dogad `
  --output .\artifacts\analysis.html `
  --format html `
  --fail-on none
```

Useful analysis options:

- `--snapshot <path>` — input `.dogad` artifact;
- `--output <path>` — output report path;
- `--format json|html` — report format;
- `--policy <path>` — analysis policy JSON;
- repeatable `--rule <rule-id>` — evaluate selected rule IDs;
- `--as-of <ISO-8601-with-timezone>` — deterministic reference time; cannot precede snapshot completion;
- `--fail-on informational|low|medium|high|critical|none` — exit threshold only; does not hide findings or missing-data outcomes;
- `--max-snapshot-mib 1..1024`;
- `--max-evaluations 1..10000000`.

The report extension must match the requested format.

### Analysis outcomes

Each evaluation is one of:

- `Present`
- `Potential`
- `NotDetected`
- `NotVerified`
- `NotApplicable`
- `Error`

`findings` contains `Present` and `Potential`. `evaluations` contains all outcomes.

Overall report completion is:

- `Error` if any rule evaluation errors;
- `Partial` if any required evidence is not verified;
- `Complete` otherwise.

`Complete` does **not** mean “no findings”. Missing evidence is never silently converted into a clean result.

### Analysis exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Complete analysis and no finding at/above threshold, or `--fail-on none` |
| `1` | Complete analysis with finding at/above configured threshold |
| `2` | Partial analysis / missing required evidence; takes precedence over finding threshold |
| `64` | invalid arguments/policy/rule/reference time |
| `70` | invalid artifact, rule/runtime/evaluation-limit/I/O failure |
| `130` | cancellation |

## Collection command exit codes

| Code | Meaning |
| ---: | --- |
| `0` | snapshot status `Complete` / command succeeded |
| `2` | snapshot status `Partial` |
| `3` | snapshot status `Failed` |
| `64` | invalid command/arguments/profile |
| `70` | runtime failure before a valid final result |
| `130` | caller cancellation / Ctrl+C |

## Validation status and current limitations

The current Rule Engine baseline has been compiled/tested and live-validated on MINILAB. A non-domain/WORKGROUP Windows workstation completed `audit-full` with explicit credentials and portable Kerberos SYSVOL, all requested capabilities `Complete`, zero collection issues and exit `0`. Offline analysis evaluated all 80 rules and retained only two intentional `NotVerified` evaluations for genuinely unobserved `user.lastLogonTimestamp` values. Local `verify.ps1` completed 678 tests with zero failures, and GitHub Windows/Ubuntu CI plus Windows self-contained publish smoke passed before promotion to `main`.

Linux live Kerberos/SMB SYSVOL validation is still pending.

Other current limitations:

- collection is primarily default-domain scoped; broader forest/multi-domain work is later;
- LDAP request/page counters and peak-memory telemetry remain pending;
- snapshot diff/retest and finding lifecycle are not implemented yet;
- suppression/accepted-risk workflow is not implemented yet;
- graph projection/path analysis is not implemented yet;
- per-user resultant PSO, AD CS, RBCD, LAPS and full RSoP/effective-rights analysis are outside the current milestone.

See [`RULE_ENGINE.md`](RULE_ENGINE.md) for exact analysis semantics and `MINILAB_RUNBOOK.md` for live validation workflow.
