# DogfighterAD CLI

The current CLI is a thin composition layer over the existing collection, snapshot and serialization modules. It does not contain AD detection rules or duplicate collector logic.

## Build

```powershell
dotnet build src/DogfighterAD.Cli/DogfighterAD.Cli.csproj -c Release
```

The build also produces/copies `DogfighterAD.SysvolWorker` beside the CLI output. `audit-full` requires that worker because potentially blocking SYSVOL filesystem calls execute outside the long-lived scanner process.

For a standalone Windows deployment without a preinstalled .NET runtime:

```powershell
dotnet publish src/DogfighterAD.Cli/DogfighterAD.Cli.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -o C:\DogfighterBuild
```

The publish path must contain both the CLI and the complete `DogfighterAD.SysvolWorker` runtime set.

## Authentication model

LDAP always uses `AuthType.Negotiate`.

By default DogfighterAD uses the current operating-system security context. For a controlled lab or assessment where the scanner host is not logged on with the AD identity, `scan` supports an explicit LDAP username with a **hidden interactive password prompt**:

```powershell
./dogfighter scan `
  --target dc.mini.lab `
  --profile minimal `
  -u 'MINILAB\alice' `
  --output .\artifacts\mini-minimal.dogad
```

`-u` is an alias for `--username`. Supplying it automatically opens the password prompt:

```text
LDAP password for MINILAB\alice:
```

The entered characters are not echoed. There is deliberately no `-p` password flag. Password options/values such as `-p`, `-p secret`, `--password secret`, `--password=secret`, or `--passwd=secret` are rejected without reproducing a following/supplied secret in the parser error.

This preserves the project invariant that credential secrets must not appear in command-line arguments, process listings, artifacts or default logs. The prompted credential exists only in runtime memory and is supplied to the LDAP connection.

`DOMAIN\user` and UPN-style `user@domain` names are supported. For `DOMAIN\user`, the CLI separates the domain and account name before constructing the LDAP network credential.

Explicit LDAP Negotiate credentials require a **DNS hostname target**. An IP literal together with `-u` is rejected before prompting/collection. This avoids ambiguous Kerberos/NTLM fallback behavior and the live-observed case where an explicit Negotiate scan by IP did not return promptly. Use a resolvable DC FQDN (for example `dc.mini.lab`).

### LDAP bind and timeout boundaries

`System.DirectoryServices.Protocols` can enter a synchronous native Negotiate bind before an asynchronous LDAP request is available to await. DogfighterAD therefore disables LDAP auto-bind and performs an explicit bind on an isolated worker task. The bind has the configured LDAP timeout (currently 30 seconds) as an external boundary. A bind that does not complete in that interval returns a sanitized `collection.ldap.bind-timeout` issue to the scan rather than holding the orchestration path indefinitely.

LDAP requests retain their own configured request timeout. In addition, the collection executor invokes collectors outside the orchestration thread and waits with the profile-level collector timeout. That outer boundary covers collectors that block synchronously before returning their `Task`, not only well-behaved asynchronous collectors.

A native Windows LDAP call that ignores cancellation may continue on its isolated background thread until the OS call itself returns; the scan orchestration no longer waits indefinitely for that call. Cleanup of the affected LDAP connection is deferred until the native operation finishes.

After the hidden password prompt completes, `scan` prints a start marker such as:

```text
Starting collection: target=dc.mini.lab profile=minimal collector-timeout=00:02:00.
```

This distinguishes a prompt/input problem from a later collection/bind problem.

### Important SYSVOL distinction

The explicit `-u` credential currently applies to **LDAP only**. `gpo.sysvol` runs through the isolated worker and Windows filesystem/SMB APIs, so SYSVOL still uses the operating-system network security context.

Therefore an `audit-full` scan from a non-domain workstation needs both:

- working DNS/routing to the target domain/DC; and
- an OS-level SMB security context authorized to read the returned `\\domain\SYSVOL\...` paths, for example a controlled `runas /netonly` session or another pre-established Windows network logon context.

Explicit LDAP credentials do not repair DNS, routing or SMB authentication. A `minimal` profile can be used first to validate LDAP separately.

## `scan`

Minimal read-only collection using the current OS context:

```powershell
./dogfighter scan `
  --target dc01.mini.lab `
  --profile minimal `
  --output .\artifacts\mini-minimal.dogad
```

Minimal read-only collection using a prompted explicit LDAP credential:

```powershell
./dogfighter scan `
  --target dc.mini.lab `
  --profile minimal `
  -u 'MINILAB\alice' `
  --output .\artifacts\mini-minimal-explicit-ldap.dogad
```

Full current Collection Core:

```powershell
./dogfighter scan `
  --target dc01.mini.lab `
  --profile audit-full `
  --output .\artifacts\mini-audit-full.dogad
```

Optional LDAP transport selection:

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

If a controlled environment intentionally returns another DC/authority, approve it explicitly and narrowly:

```powershell
./dogfighter scan `
  --target dc01.mini.lab `
  --profile audit-full `
  --sysvol-authority dc02.mini.lab `
  --output .\artifacts\mini-audit-full.dogad
```

`--sysvol-authority` is repeatable. It is not a wildcard/disable-scope switch.

## Safe failure diagnostics

Collector failures are still evidence-first and do not persist raw exception/server text. Known operational failures may emit a sanitized issue code/message, for example:

```text
  directory.core             Failed        items=0 issues=1
    [Error] collection.ldap.authentication-failed: LDAP authentication failed (code=49/InvalidCredentials). Verify the supplied username/password and Negotiate prerequisites.
```

LDAP diagnostics distinguish at least:

- `collection.ldap.authentication-failed`
- `collection.ldap.bind-timeout`
- `collection.ldap.server-unavailable`
- `collection.ldap.timeout`
- `collection.ldap.security-required`
- `collection.ldap.failed`

Numeric LDAP/result codes are retained when safe. Raw `LdapException`/server error text and credential material are intentionally omitted. Unknown exceptions still fall back to `collection.collector.failed` rather than serializing arbitrary exception details.

The profile-level `collection.collector.timeout` remains a separate outer failure when any collector exceeds its profile budget, including synchronous pre-await blocking.

## Artifact commit behavior

`scan` does not directly stream into the final filename. It:

1. executes the capability plan;
2. assembles the canonical `AdSnapshot`;
3. writes a temporary `.dogad` artifact;
4. re-opens that temporary artifact through the strict `DogadArtifactSerializer.ReadAsync` path;
5. verifies snapshot identity/status agreement;
6. only then atomically replaces the requested output path.

A failed/canceled write or failed readback is not intentionally published as the requested final artifact.

## `inspect`

`inspect` is offline. It opens only the supplied `.dogad`; it does not create LDAP or SYSVOL clients.

```powershell
./dogfighter inspect --snapshot .\artifacts\mini-audit-full.dogad
```

The summary prints metadata, object counts, capability coverage and sanitized collection issue details. It does not print raw AD source payloads or credential values.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | snapshot status `Complete` / command succeeded |
| `2` | snapshot status `Partial` |
| `3` | snapshot status `Failed` |
| `64` | invalid command/arguments/profile |
| `70` | runtime failure before a valid final result |
| `130` | caller cancellation / Ctrl+C |

A `Partial` exit is deliberately non-zero. Incomplete collection must not be silently treated as a clean/successful audit.

## Default output summary

The CLI prints:

- collection start marker after any credential prompt;
- snapshot ID;
- completion status;
- profile;
- initial target;
- artifact path;
- counts for domains/users/groups/computers/OUs/memberships/GPOs;
- each capability's status, observed item count and issue count;
- each collection issue's severity, code and sanitized message.

It does not print credential values or arbitrary exception/source payloads on the default error path.

## Current limitations

- The MINILAB minimal profile has been validated live and completed with the corrected binary SID transport; `audit-full` validation is continuing against observed ACL/GPO/SYSVOL issues.
- Explicit `-u` credentials currently authenticate LDAP only; SYSVOL/SMB still uses the OS network security context.
- Explicit Negotiate authentication requires a hostname target; IP literals with `-u` are rejected.
- Native LDAP bind cancellation is containment-based: the scanner can stop waiting at the configured timeout, but a native OS call may remain on its isolated thread until the OS returns it.
- Current collection is primarily default-domain scoped; broader forest/multi-domain work is later.
- `inspect` is not the future `analyze` command. There is no Rule Engine yet.
- LDAP request/page counters and peak-memory telemetry are still pending.

Use `MINILAB_RUNBOOK.md` for the live validation sequence.
