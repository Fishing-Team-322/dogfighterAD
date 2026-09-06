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

By default DogfighterAD uses the current operating-system security context. For a controlled lab or assessment where the scanner host is not logged on with the AD identity, `scan` also supports an explicit LDAP username with a **hidden interactive password prompt**:

```powershell
./dogfighter scan `
  --target dc.mini.lab `
  --profile minimal `
  -u 'MINILAB\alice' `
  -p `
  --output .\artifacts\mini-minimal.dogad
```

`-u` is an alias for `--username`. `-p` is an alias for `--password`, but it is deliberately a **prompt switch**, not a password-value option. The CLI then prompts:

```text
LDAP password for MINILAB\alice:
```

The entered characters are not echoed. Password values such as `-p secret`, `--password secret`, `--password=secret`, or `--passwd=secret` are rejected without reproducing the supplied value in the parser error.

This preserves the project invariant that credential secrets must not appear in command-line arguments, process listings, artifacts or default logs. The prompted credential exists only in runtime memory and is supplied to the LDAP connection.

`DOMAIN\user` and UPN-style `user@domain` names are supported. For `DOMAIN\user`, the CLI separates the domain and account name before constructing the LDAP network credential.

### Important SYSVOL distinction

The explicit `-u ... -p` credential currently applies to **LDAP only**. `gpo.sysvol` runs through the isolated worker and Windows filesystem/SMB APIs, so SYSVOL still uses the operating-system network security context.

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
  -p `
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

The default summary intentionally prints metadata, object counts and capability coverage rather than raw AD object attributes or evidence payloads.

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

- snapshot ID;
- completion status;
- profile;
- initial target;
- artifact path;
- counts for domains/users/groups/computers/OUs/memberships/GPOs;
- each capability's status, observed item count and issue count.

It does not print credential values or arbitrary source payloads on the default exception path.

## Current limitations

- The MINILAB minimal profile has been validated live and completed with the corrected binary SID transport; `audit-full` validation is continuing against observed ACL/GPO/SYSVOL issues.
- Explicit `-u ... -p` credentials currently authenticate LDAP only; SYSVOL/SMB still uses the OS network security context.
- Current collection is primarily default-domain scoped; broader forest/multi-domain work is later.
- `inspect` is not the future `analyze` command. There is no Rule Engine yet.
- LDAP request/page counters and peak-memory telemetry are still pending.

Use `MINILAB_RUNBOOK.md` for the live validation sequence.
