# MINILAB / GOAD live collection runbook

This runbook is the live validation path for the current Collection Core. A successful process exit is not enough: record the exact build, lab state, expected facts, actual counts, capability coverage and artifact readback result.

Do not introduce broad detection rules until this collection path is understood and reproducible.

## 1. Preconditions

Use an assessment identity authorized for read-only directory/SYSVOL access. DogfighterAD must not place passwords in CLI arguments, scripts committed to the repository, `.dogad` artifacts or logs.

Current authentication behavior:

- no `-u`: LDAP uses the current operating-system security context with Negotiate; SYSVOL uses the operating-system network security context;
- with `-u/--username`: the CLI opens a hidden password prompt, LDAP defaults to Negotiate against the named DC, and `audit-full` automatically reuses the same credential for DogfighterAD-owned portable Kerberos/SMB SYSVOL authentication;
- `--ldap-auth ntlm` is an explicit LDAP compatibility mode only and requires `-u`; username syntax does not silently select NTLM.

There is no `-p` password flag. Password command-line options/values are intentionally rejected.

When `-u` is used, `--target` must be a resolvable DC DNS hostname/FQDN. An IP literal is rejected before prompting. The exact target is used for LDAP server identity and for the `cifs/<target>` Kerberos service identity used by portable SYSVOL.

The portable SYSVOL path requires SMB 3.1.1 with signing and runs inside the isolated SYSVOL worker. It does not require a domain-joined scanner host or a pre-established Windows UNC/SMB logon context.

Record before running:

```text
Date/time UTC:
DogfighterAD commit SHA:
.NET SDK/runtime:
Host OS:
Domain-joined? yes/no
Lab: MINILAB / GOAD
Lab version/commit/snapshot:
Collection identity (name only, no credential material):
Target DC/domain:
Known DNS/domain/forest names:
Known expected object counts or planted objects:
Known expected GPOs/trusts/memberships:
```

### Network preflight

For a workstation outside the MINILAB domain, prove naming and required transports before interpreting collection failures:

```powershell
Resolve-DnsName dc.mini.lab
Test-NetConnection dc.mini.lab -Port 389
Test-NetConnection dc.mini.lab -Port 445
Test-NetConnection dc.mini.lab -Port 88
```

Use port 636 instead of 389 when validating LDAPS.

A credential cannot repair DNS or routing. If DNS resolution fails, fix the scanner's route/name-resolution path to the isolated lab first.

Manual UNC access is useful for comparing OS redirector behavior, but it is **not a prerequisite** for explicit-credential portable SYSVOL. A WORKGROUP host may fail:

```powershell
Get-ChildItem '\\mini.lab\SYSVOL\mini.lab\Policies'
```

while DogfighterAD `audit-full -u ...` succeeds through its own Kerberos/SMB worker. Record that distinction instead of weakening UNC hardening, SMB signing or scanner scope controls.

## 2. Build the exact commit

```powershell
git rev-parse HEAD
dotnet restore src/DogfighterAD.Cli/DogfighterAD.Cli.csproj
dotnet build src/DogfighterAD.Cli/DogfighterAD.Cli.csproj -c Release --no-restore
```

Use the executable from `src/DogfighterAD.Cli/bin/Release/net10.0/`. Confirm `DogfighterAD.SysvolWorker` and its runtime dependencies are present beside the CLI before `audit-full`.

For a self-contained Windows deployment:

```powershell
dotnet publish src/DogfighterAD.Cli/DogfighterAD.Cli.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -o C:\DogfighterBuild
```

The publish output must contain the complete worker runtime set, not only the worker executable.

## 3. Minimal collection first

Using current OS context:

```powershell
./dogfighter scan `
  --target dc.mini.lab `
  --profile minimal `
  --output .\lab-artifacts\mini-minimal.dogad
```

Using an explicit read-only identity from a non-domain host:

```powershell
./dogfighter scan `
  --target dc.mini.lab `
  --profile minimal `
  -u 'MINILAB\alice' `
  --output .\lab-artifacts\mini-minimal-explicit.dogad
```

The password prompt is automatic after `-u`. Do not add a password option/value.

Expected minimal capabilities:

- `directory.core`
- `directory.domains`
- `directory.users`
- `directory.groups`
- `directory.computers`
- `directory.ous`
- `directory.memberships`
- `directory.trusts`

With explicit credentials the startup marker should contain values equivalent to:

```text
ldap-auth=negotiate
ldap-protection=sign-seal
ldap-target-mode=fqdn-server
sysvol-auth=portable-kerberos
bind-timeout=00:00:15
request-timeout=00:00:30
collector-timeout=00:02:00
```

`sysvol-auth=portable-kerberos` describes what `audit-full` will use; the minimal profile itself does not request `gpo.sysvol`.

Record the process exit code and every capability status. A `Partial` or `Failed` result is a validation finding to investigate.

## 4. Offline readback

Use a new CLI invocation:

```powershell
./dogfighter inspect --snapshot .\lab-artifacts\mini-minimal.dogad
```

Record:

```text
Snapshot ID from scan:
Snapshot ID from inspect:
Completion status from scan:
Completion status from inspect:
Artifact opened after network isolation/disconnect? yes/no
```

The IDs and status must agree. `inspect` is offline and should continue to work after lab network access is removed.

## 5. Validate known counts/facts

Compare CLI counts and snapshot contents against the known fixture, not assumptions.

| Data | Expected | Actual | Result / note |
| --- | ---: | ---: | --- |
| Domains |  |  |  |
| Users |  |  |  |
| Groups |  |  |  |
| Computers |  |  |  |
| OUs |  |  |  |
| Direct/primary memberships |  |  |  |
| Configured trusts |  |  |  |

For memberships, include a nested group, a primary-group relationship and any foreign-security-principal case present in the fixture.

## 6. Audit-full collection

For a non-domain workstation using explicit credentials, the normal command is now:

```powershell
./dogfighter scan `
  --target dc.mini.lab `
  --profile audit-full `
  -u 'MINILAB\alice' `
  --output .\lab-artifacts\mini-audit-full.dogad
```

No extra SYSVOL transport flag or separate OS SMB logon is required.

Audit-full additionally validates:

- `directory.acls`
- `gpo.metadata`
- `gpo.links`
- `gpo.sysvol`

For explicit credentials, `gpo.sysvol` uses the isolated portable Kerberos/SMB worker. The worker connects to the exact target DC, requires SMB signing, and only reads paths that pass the existing SYSVOL scope policy.

If the lab intentionally returns another approved authority in GPO metadata, scope can be extended narrowly:

```powershell
--sysvol-authority dc02.mini.lab
```

Do not add wildcard authority bypasses. Portable authentication still targets the explicitly named scan DC; this option is a path-policy approval, not permission to contact arbitrary servers.

Record at minimum:

| Data | Expected | Actual | Result / note |
| --- | ---: | ---: | --- |
| Security descriptors / supported ACEs |  |  |  |
| GPO objects |  |  |  |
| GPO links |  |  |  |
| SYSVOL inventoried files |  |  |  |
| Normalized supported GPO settings |  |  |  |

Check known `GPT.INI`, `GptTmpl.inf`, `Registry.pol` and Preferences XML cases when present. Legacy `cpassword` must be represented only as the safe presence signal; the value itself must not enter snapshot observations/settings.

### Current MINILAB reference result

A Windows WORKGROUP live run on 2026-09-07 completed successfully with explicit `MINILAB\alice` credentials and automatic portable SYSVOL:

```text
Status: Complete
Profile: audit-full
Objects: domains=1 users=8 groups=50 computers=2 ous=1 memberships=41 gpos=2

directory.acls             Complete      items=62 issues=0
gpo.links                  Complete      items=2 issues=0
gpo.metadata               Complete      items=2 issues=0
gpo.sysvol                 Complete      items=4 issues=0
```

Scan exit code was `0`; offline `inspect` reproduced the same snapshot ID and coverage with exit code `0`. See `docs/lab-runs/2026-09-07-workgroup-portable-sysvol-audit-full.md`.

## 7. Explicit failure/partial cases

After a successful baseline, exercise controlled failures one at a time.

Recommended cases:

1. wrong explicit password -> sanitized LDAP/Kerberos authentication failure; no credential text in output/artifact;
2. explicit identity with an IP-literal target -> parser rejection before prompting/collection;
3. DNS failure for the target DC -> fail/partial with transport classification rather than a misleading clean result;
4. unreachable TCP/88 -> portable Kerberos SYSVOL must fail/partial rather than silently falling back to NTLM;
5. unreachable TCP/445 -> `gpo.sysvol` incomplete; no indefinite hang;
6. inaccessible or missing GPO path -> `gpo.sysvol` incomplete with an issue;
7. denied SYSVOL file read -> incomplete coverage; no silent omission;
8. mutated/out-of-scope `gPCFileSysPath` -> reject before SMB file access;
9. `..`, device-style UNC or alternate-share path injection -> scope rejection;
10. oversized SYSVOL file -> bounded read failure / `file-too-large`, no over-budget payload;
11. slow/stalled SMB operation -> worker timeout/termination; scanner must not hang indefinitely;
12. insufficient ACL rights -> `directory.acls` incomplete rather than clean;
13. large/ranged membership -> verify final count and range retrieval;
14. Ctrl+C during prompt/LDAP/SYSVOL -> cancellation and no successful final artifact;
15. stalled native LDAP setup -> `collection.ldap.bind-timeout` at the setup boundary;
16. explicit `--ldap-auth ntlm` -> only LDAP changes auth mode; portable SYSVOL remains Kerberos and must not silently downgrade.

For every case record capability status and issue code/message, not only the process exit.

## 8. Read-only validation

Verify DogfighterAD does not:

- issue LDAP modify/add/delete requests;
- write/create/delete/rename SYSVOL files;
- change GPOs;
- dump credentials, Kerberos tickets/session keys or SMB security blobs;
- execute attack paths;
- contact configured trust partners merely because a trust object exists.

Portable SYSVOL opens only read/list operations required for inventory and supported-file normalization.

## 9. Artifact retention

`.dogad` contains sensitive AD assessment data even without passwords. Store lab artifacts in an access-controlled local path. Do not commit live/customer `.dogad` files.

For reproducible synthetic fixtures, create sanitized fixtures separately and document their generation.

## 10. Result record

Create a dated record under `docs/lab-runs/` including:

- exact `git rev-parse HEAD`;
- lab fixture/version/state;
- host/domain-join state;
- commands and exit codes;
- selected LDAP/SYSVOL auth markers;
- expected vs actual counts;
- capability coverage/statuses;
- issue codes/messages for incomplete capabilities;
- whether `.dogad` offline readback succeeded;
- measured duration;
- explicit statement that no real/customer credential material was committed.

Repeat the same process on the larger GOAD fixture before using the collection baseline as the foundation for Rule Engine work.
