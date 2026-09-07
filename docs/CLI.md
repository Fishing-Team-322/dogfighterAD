# DogfighterAD CLI

The CLI is a thin composition layer over the collection, snapshot and serialization modules. It does not contain AD detection rules or duplicate collector logic.

## Build

```powershell
dotnet build src/DogfighterAD.Cli/DogfighterAD.Cli.csproj -c Release
```

The build also produces/copies `DogfighterAD.SysvolWorker` beside the CLI output. `audit-full` requires the worker because potentially blocking SYSVOL operations execute outside the long-lived scanner process and are terminated/restarted on timeout or cancellation.

For a standalone Windows deployment without a preinstalled .NET runtime:

```powershell
dotnet publish src/DogfighterAD.Cli/DogfighterAD.Cli.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -o C:\DogfighterBuild
```

The publish path must contain the CLI and the complete `DogfighterAD.SysvolWorker` runtime set, including its Kerberos/SMB dependencies.

## Authentication model

### No explicit username

Without `-u/--username`, LDAP uses the current operating-system security context with Negotiate. SYSVOL uses the operating-system network security context through the isolated worker.

### Explicit username

Supplying `-u/--username` opens a hidden interactive password prompt:

```powershell
./dogfighter scan `
  --target dc.mini.lab `
  --profile audit-full `
  -u 'MINILAB\alice' `
  --output .\artifacts\mini-audit-full.dogad
```

The password is not accepted on the command line. `-p`, `--password`, `--passwd`, `--credential`, inline password forms and equivalent options are intentionally rejected.

The same prompted credential is used for:

- LDAP authentication to the explicitly named DC; and
- portable Kerberos SYSVOL authentication when `audit-full` reaches `gpo.sysvol`.

LDAP defaults to Negotiate regardless of whether the username is written as `DOMAIN\user` or `user@domain`. NTLM is an explicit LDAP compatibility mode only:

```powershell
--ldap-auth ntlm
```

`--ldap-auth ntlm` requires `-u/--username`. Username syntax does not silently select NTLM.

Explicit credentials require a resolvable DC DNS hostname/FQDN. IP literals are rejected before prompting/collection. The named host is used as the exact LDAP server and as the Kerberos/SMB server identity for SYSVOL.

Without `--ldaps`, LDAP signing and sealing are mandatory. With `--ldaps`, normal platform certificate validation remains enabled. There is no silent unprotected downgrade.

## Portable SYSVOL with explicit credentials

When `-u` is supplied, `gpo.sysvol` does not depend on the Windows UNC redirector or a pre-established OS SMB logon. The isolated worker owns the network authentication path:

1. obtain Kerberos credentials for the prompted identity;
2. request the CIFS service ticket for the exact approved server (`cifs/<target>`);
3. connect directly to TCP/445;
4. negotiate SMB 3.1.1;
5. require SMB signing;
6. connect to `SYSVOL`;
7. enumerate/read only paths that have already passed the collector's SYSVOL scope policy.

The SMB SessionKey is normalized to the 16-byte value expected by the SMB client implementation before signing-key derivation. This behavior is covered by tests and by MINILAB live validation.

Credentials are not placed in argv, environment variables, logs or `.dogad` artifacts. The parent sends the worker request through redirected stdin. The parent still owns the per-operation timeout and terminates the worker process tree if an operation stalls.

The startup marker identifies the selected safe mode. With explicit credentials it includes:

```text
sysvol-auth=portable-kerberos
```

Without explicit credentials it reports the OS-context path instead.

## LDAP referral and timeout boundaries

Automatic native LDAP referral chasing is disabled. Current collectors query the selected naming context on the selected server; referred partitions/servers are not implicitly assessed.

Current production limits are:

- LDAP connection/authentication setup: 15 seconds;
- each LDAP request: 30 seconds;
- profile collector timeout: 2 minutes for `minimal`, 3 minutes for `audit-full`;
- isolated SYSVOL operation deadline: 30 seconds per worker operation.

The collector timeout is an outer orchestration boundary in addition to LDAP/SYSVOL transport deadlines.

A scan prints the selected runtime mode and deadlines after any credential prompt, for example:

```text
Starting collection: target=dc.mini.lab profile=audit-full ldap-auth=negotiate ldap-protection=sign-seal ldap-target-mode=fqdn-server sysvol-auth=portable-kerberos bind-timeout=00:00:15 request-timeout=00:00:30 collector-timeout=00:03:00.
```

No password value is included in this marker.

## `scan`

Minimal collection using the current OS context:

```powershell
./dogfighter scan `
  --target dc01.mini.lab `
  --profile minimal `
  --output .\artifacts\mini-minimal.dogad
```

Minimal collection using an explicit prompted identity:

```powershell
./dogfighter scan `
  --target dc.mini.lab `
  --profile minimal `
  -u 'MINILAB\alice' `
  --output .\artifacts\mini-minimal-explicit.dogad
```

Full Collection Core from a non-domain workstation with portable SYSVOL authentication:

```powershell
./dogfighter scan `
  --target dc.mini.lab `
  --profile audit-full `
  -u 'MINILAB\alice' `
  --output .\artifacts\mini-audit-full.dogad
```

Optional LDAPS selection:

```powershell
./dogfighter scan `
  --target dc01.mini.lab `
  --profile minimal `
  --ldaps `
  --ldap-port 636 `
  --output .\artifacts\mini-ldaps.dogad
```

`--ldap-port` defaults to `389`, or `636` when `--ldaps` is supplied.

### Explicit SYSVOL authorities

Parent-side scope validation automatically permits the GPO domain DFS authority and the current collection target when the normalized GPO path matches the expected `SYSVOL/<domain>/Policies/{GPO-GUID}` root.

If a controlled environment intentionally returns another DC/authority, approve only that authority explicitly:

```powershell
--sysvol-authority dc02.mini.lab
```

`--sysvol-authority` is repeatable. It is not a wildcard or a scope-disable switch.

Portable explicit-credential operation still connects to the exact scan target DC for Kerberos/SMB. Alternate authorities are a path-policy approval mechanism, not permission to contact arbitrary hosts.

## Safe failure diagnostics

Collector failures are evidence-first and do not persist raw exception/server text. Known LDAP operational failures include:

- `collection.ldap.authentication-failed`
- `collection.ldap.bind-timeout`
- `collection.ldap.server-unavailable`
- `collection.ldap.timeout`
- `collection.ldap.security-required`
- `collection.ldap.failed`

SYSVOL failures are surfaced through sanitized capability issues such as missing paths, denied access, file/read failures, size limits and operation timeout. Passwords, Kerberos tickets/session keys, SMB security blobs and arbitrary server payloads are not printed by the default CLI path.

The CLI also prints per-collector progress:

```text
[collection] start collector=ad.sysvol.gpo-settings timeout=00:03:00
[collection] done collector=ad.sysvol.gpo-settings elapsed=00:00:11.7
```

## Artifact commit behavior

`scan` does not stream directly into the requested final filename. It:

1. executes the capability plan;
2. assembles the canonical `AdSnapshot`;
3. writes a temporary `.dogad` artifact;
4. re-opens the temporary artifact through the strict reader;
5. verifies snapshot identity/status agreement;
6. only then atomically replaces the requested output path.

A failed/canceled write or failed readback is not intentionally published as the requested final artifact.

## `inspect`

`inspect` is offline. It opens only the supplied `.dogad`; it does not create LDAP or SYSVOL clients.

```powershell
./dogfighter inspect --snapshot .\artifacts\mini-audit-full.dogad
```

The summary prints metadata, object counts, capability coverage and sanitized collection issue details.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | snapshot status `Complete` / command succeeded |
| `2` | snapshot status `Partial` |
| `3` | snapshot status `Failed` |
| `64` | invalid command/arguments/profile |
| `70` | runtime failure before a valid final result |
| `130` | caller cancellation / Ctrl+C |

A `Partial` exit is deliberately non-zero.

## Validation status and current limitations

MINILAB live validation includes a successful `audit-full` collection from a non-domain/WORKGROUP Windows workstation using `-u 'MINILAB\alice'` and automatic portable Kerberos SYSVOL. The run completed all directory, ACL, GPO metadata/link and SYSVOL capabilities with zero issues, produced two GPOs / four SYSVOL inventory items, returned exit code `0`, and strict offline `inspect` reproduced the same snapshot ID and coverage. See `docs/lab-runs/2026-09-07-workgroup-portable-sysvol-audit-full.md`.

Cross-platform build/tests are green on Windows and Ubuntu CI. Linux live Kerberos/SMB SYSVOL validation is still pending.

Other current limitations:

- current collection is primarily default-domain scoped; broader forest/multi-domain work is later;
- native LDAP setup cancellation is containment-based: the scanner stops waiting at the deadline, but an OS native call may remain on its isolated task until the OS returns it;
- `inspect` is not the future `analyze` command; there is no Rule Engine yet;
- analysis rules, reports, graph analysis and diff/retest are not implemented yet;
- LDAP request/page counters and peak-memory telemetry remain pending.

Use `MINILAB_RUNBOOK.md` for the live validation sequence.
