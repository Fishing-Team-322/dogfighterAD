# DogfighterAD CLI

The current CLI is a thin composition layer over the existing collection, snapshot and serialization modules. It does not contain AD detection rules or duplicate collector logic.

## Build

```powershell
dotnet build src/DogfighterAD.Cli/DogfighterAD.Cli.csproj -c Release
```

The build also produces/copies `DogfighterAD.SysvolWorker` beside the CLI output. `audit-full` requires that worker because potentially blocking SYSVOL filesystem calls execute outside the long-lived scanner process.

## Authentication model

LDAP uses `AuthType.Negotiate` and the current operating-system security context. The CLI intentionally does **not** accept username/password/credential values as command-line options.

Run DogfighterAD under an identity that is authorized for the assessment. How that identity is established is an operating-system/environment concern; credentials must not be placed in DogfighterAD arguments, artifacts or logs.

## `scan`

Minimal read-only collection:

```powershell
./dogfighter scan `
  --target dc01.mini.lab `
  --profile minimal `
  --output .\artifacts\mini-minimal.dogad
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

- The CLI has cross-platform build/offline tests, but no live AD/MINILAB/GOAD result has yet been recorded in the repository.
- Current collection is primarily default-domain scoped; broader forest/multi-domain work is later.
- `inspect` is not the future `analyze` command. There is no Rule Engine yet.
- LDAP request/page counters and peak-memory telemetry are still pending.
- `audit-full` SYSVOL DFS/referral behavior needs real lab validation even though scope, byte-budget and blocked-I/O lifetime boundaries have offline regression coverage.

Use `MINILAB_RUNBOOK.md` for the first live validation sequence.
