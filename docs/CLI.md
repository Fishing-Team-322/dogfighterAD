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

LDAP authentication depends on how the identity is supplied:

- no `-u`: current operating-system security context with `AuthType.Negotiate`;
- explicit `DOMAIN\user`: `AuthType.Ntlm` challenge/response to the explicitly named DC;
- explicit UPN-style `user@domain`: `AuthType.Negotiate`.

The explicit down-level `DOMAIN\user` path uses NTLM deliberately for the remote non-domain-workstation case. It avoids making the scanner depend on Kerberos KDC/SPN discovery when the operator has already named the DC and only the DC hostname is resolvable. It does not introduce Basic authentication and does not put the password on the command line.

For a controlled lab or assessment where the scanner host is not logged on with the AD identity, `scan` supports an explicit LDAP username with a **hidden interactive password prompt**:

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

Explicit LDAP credentials require a **DNS hostname target**. An IP literal together with `-u` is rejected before prompting/collection. Use a resolvable DC FQDN (for example `dc.mini.lab`).

For the explicit-credential path, DogfighterAD also marks that FQDN as the **exact named LDAP server** when constructing `LdapDirectoryIdentifier` (`fullyQualifiedDnsHostName: true`, TCP/connectionless false). This is intentional: Windows LDAP otherwise may treat a supplied host-like name as something to rediscover and perform extra locator/name-resolution work before connecting. The current-OS-context path retains the older discovery-capable identifier semantics because `--target` may legitimately be a domain rather than a specific DC.

### LDAP setup and timeout boundaries

`System.DirectoryServices.Protocols` can enter synchronous native Windows LDAP code while creating/configuring the connection or performing authentication, before an asynchronous request is available to await. DogfighterAD therefore places the **complete native LDAP connection/setup/bind boundary** on an isolated task and applies a separate external bind/setup deadline.

Current production limits are:

- LDAP connection/authentication setup: 15 seconds;
- each LDAP request: 30 seconds;
- profile collector timeout: 2 minutes for `minimal`, 3 minutes for `audit-full`.

If the native connection/authentication setup does not complete within 15 seconds, the scan receives sanitized `collection.ldap.bind-timeout` evidence rather than intentionally waiting for that native call indefinitely. A native Windows call may still continue on its isolated background task until the OS returns it; any connection returned after the deadline is disposed instead of being reused.

An explicit credential used by the isolated native setup is cloned into an operation-owned runtime credential lease before WLDAP32 is entered. This prevents a timed-out native setup task from depending on the shorter prompt-owned `SecureString` lifetime. The clone is disposed with the live LDAP client, or after a timed-out native setup eventually returns. This is a lifetime/cleanup guarantee only; it is not a claim that managed or native credential memory can be made universally non-copyable.

LDAP requests retain their own request timeout. In addition, the collection executor invokes collectors outside the orchestration thread and waits with the profile-level collector timeout. That outer boundary covers collectors that block synchronously before returning their `Task`, not only well-behaved asynchronous collectors.

After the hidden password prompt completes, `scan` prints the selected safe runtime mode and deadlines, for example:

```text
Starting collection: target=dc.mini.lab profile=minimal ldap-auth=ntlm bind-timeout=00:00:15 request-timeout=00:00:30 collector-timeout=00:02:00.
```

No username/password value is added to that marker. The marker distinguishes prompt/input problems from later LDAP collection problems and makes the expected timeout boundaries visible during live validation.

The scanner also prints safe per-collector progress so a live wait has an exact boundary instead of appearing as an undifferentiated hang:

```text
[collection] start collector=ad.ldap.rootdse timeout=00:02:00
[collection] failed collector=ad.ldap.rootdse issue=collection.ldap.bind-timeout elapsed=00:00:15.0
```

Progress lines contain only stable collector IDs, state, timeout/elapsed values and sanitized issue codes. They do not print credential values, LDAP source payloads or raw exception/server text. The final snapshot summary remains the authoritative place for capability status and the sanitized issue message.

### Important SYSVOL distinction

The explicit `-u` credential currently applies to **LDAP only**. `gpo.sysvol` runs through the isolated worker and Windows filesystem/SMB APIs, so SYSVOL still uses the operating-system network security context.

Therefore an `audit-full` scan from a non-domain workstation needs both:

- working name resolution/routing to the required domain/DC names; and
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

Collector failures are evidence-first and do not persist raw exception/server text. Known operational failures may emit a sanitized issue code/message, for example:

```text
  directory.core             Failed        items=0 issues=1
    [Error] collection.ldap.authentication-failed: LDAP authentication failed (code=49/InvalidCredentials). Verify the supplied username/password and authentication prerequisites.
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

- collection start marker after any credential prompt, including selected auth mode and timeout boundaries;
- safe per-collector runtime progress (`start`, `done`, `failed`, `timeout`, `blocked`, `canceled`);
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
- Explicit credentials require a hostname target; IP literals with `-u` are rejected.
- Down-level `DOMAIN\user` explicit credentials currently use NTLM to avoid Kerberos/DC-locator dependency on a non-domain workstation; UPN and current-context paths retain Negotiate.
- Native LDAP setup cancellation is containment-based: the scanner stops waiting at the configured setup deadline, but a native OS call may remain on its isolated task until the OS returns it.
- Current collection is primarily default-domain scoped; broader forest/multi-domain work is later.
- `inspect` is not the future `analyze` command. There is no Rule Engine yet.
- LDAP request/page counters and peak-memory telemetry are still pending.

Use `MINILAB_RUNBOOK.md` for the live validation sequence.
