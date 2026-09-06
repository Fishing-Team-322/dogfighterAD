# MINILAB / GOAD live collection runbook

This runbook is the first live validation path for the current Collection Core. It is deliberately evidence-oriented: a successful process exit is not enough. Record the exact build, lab state, expected facts, actual counts, coverage and artifact readback result.

Do not introduce broad detection rules until this path has been completed and discrepancies have been understood.

## 1. Preconditions

Use an assessment identity authorized for read-only directory/SYSVOL access. DogfighterAD must not place passwords in CLI arguments, scripts committed to the repository, `.dogad` artifacts or logs.

LDAP authentication has these current execution paths:

- no `-u`: current operating-system security context with Negotiate;
- explicit `DOMAIN\user`: hidden password prompt followed by NTLM challenge/response to the named DC;
- explicit `user@domain`: hidden password prompt followed by Negotiate.

The down-level `DOMAIN\user` path uses NTLM deliberately for the remote non-domain-workstation case so the scanner does not require Kerberos KDC/SPN discovery merely to authenticate to an explicitly named DC. There is no Basic-auth fallback.

There is no `-p` password flag. Password command-line options/values are intentionally rejected.

Explicit CLI credentials currently apply to LDAP only. SYSVOL/SMB still uses the operating-system network security context because the isolated worker uses Windows filesystem/SMB APIs.

When `-u` is used, the LDAP target must be a DNS hostname/FQDN. An IP literal is rejected before prompting. Use the DC FQDN rather than an IP workaround so target identity, AD naming and later SYSVOL validation remain explicit.

Prefer a Windows test host for the first `audit-full` run because SYSVOL/SMB behavior is a primary validation target. The collection code itself remains cross-platform tested where practical.

Record before running:

```text
Date/time UTC:
DogfighterAD commit SHA:
.NET SDK/runtime:
Host OS:
Lab: MINILAB / GOAD
Lab version/commit/snapshot:
Collection identity (name only, no credential material):
Target DC/domain:
Known DNS/domain/forest names:
Known expected object counts or planted objects:
Known expected GPOs/trusts/memberships:
```

### Remote Windows workstation preflight

When DogfighterAD runs on a workstation outside the MINILAB domain, prove network naming and transport before interpreting collection failures:

```powershell
Resolve-DnsName dc.mini.lab
Test-NetConnection dc.mini.lab -Port 389
Test-NetConnection dc.mini.lab -Port 445
```

A credential cannot repair DNS or routing. If `Resolve-DnsName` fails, fix the workstation's path to the lab DNS/DC first (or use a controlled temporary name-resolution configuration appropriate to the isolated lab).

For `audit-full`, also prove the exact SYSVOL authority returned by AD is reachable through the same OS network context:

```powershell
Get-ChildItem '\\mini.lab\sysvol\mini.lab\Policies' |
  Select-Object -First 5 Name
```

If LDAP credentials are needed from the workstation, use the hidden prompt form:

```powershell
./dogfighter scan `
  --target dc.mini.lab `
  --profile minimal `
  -u 'MINILAB\alice' `
  --output .\lab-artifacts\mini-minimal-remote.dogad
```

The password prompt is automatic after `-u`. Do not add `-p`, `--password` or any password value to the command line.

For this exact `DOMAIN\user` form, the current CLI should print a marker like:

```text
Starting collection: target=dc.mini.lab profile=minimal ldap-auth=ntlm bind-timeout=00:00:15 request-timeout=00:00:30 collector-timeout=00:02:00.
```

If this marker never appears, investigate console/prompt handling. If it appears and the scan then waits, use the displayed deadlines when judging whether the transport returned normally. A `DOMAIN\user` run that prints `ldap-auth=negotiate` is the wrong build/configuration for the current remote-workstation path.

For an `audit-full` remote run, the LDAP prompt does not create the SMB session. Establish the authorized Windows network context separately (for example a controlled `runas /netonly` shell or an explicit Windows SMB session appropriate to the isolated lab) and then run DogfighterAD from that context.

### Interpreting collection failures

The CLI prints sanitized issue details beneath affected capability rows. Record the issue **code and message**, not only `Failed`/`Partial`.

Known LDAP operational failures include:

- `collection.ldap.authentication-failed`
- `collection.ldap.bind-timeout`
- `collection.ldap.server-unavailable`
- `collection.ldap.timeout`
- `collection.ldap.security-required`
- `collection.ldap.failed`

Numeric LDAP/result codes may be included in the safe message. Do not infer a bad password from a generic collector failure; use the actual emitted issue classification.

The production LDAP factory isolates the complete native connection/configuration/authentication setup, not only the explicit `Bind()` call. DogfighterAD stops waiting for that setup after 15 seconds and reports `collection.ldap.bind-timeout` if Windows has not returned. LDAP requests retain a separate 30-second timeout.

The profile collector timeout is an additional outer boundary. Collection execution is isolated so even a collector that blocks synchronously before returning a `Task` cannot hold the orchestration thread past that boundary. A native OS LDAP call may remain on its isolated background task until Windows itself returns it; this is containment rather than a claim that WLDAP32 native calls are forcibly cancellable. A connection returned after its setup deadline is disposed and not reused.

A scan that still does not return beyond these documented boundaries is a new live defect and must be recorded with the exact build and last visible output.

## 2. Build the exact commit

```powershell
git rev-parse HEAD
dotnet restore src/DogfighterAD.Cli/DogfighterAD.Cli.csproj
dotnet build src/DogfighterAD.Cli/DogfighterAD.Cli.csproj -c Release --no-restore
```

Use the executable from the `Release/net10.0` CLI output. Confirm `DogfighterAD.SysvolWorker` and its runtime files are present beside it before `audit-full`.

For a self-contained Windows deployment, use:

```powershell
dotnet publish src/DogfighterAD.Cli/DogfighterAD.Cli.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -o C:\DogfighterBuild
```

The publish output must contain the complete worker runtime set, not only `DogfighterAD.SysvolWorker.exe`.

## 3. Minimal collection first

Run the lighter profile before touching SYSVOL/ACL collection:

```powershell
./dogfighter scan `
  --target dc01.mini.lab `
  --profile minimal `
  --output .\lab-artifacts\mini-minimal.dogad
```

Expected capability set:

- `directory.core`
- `directory.domains`
- `directory.users`
- `directory.groups`
- `directory.computers`
- `directory.ous`
- `directory.memberships`
- `directory.trusts`

Record the command exit code and every capability status. A `Partial` or `Failed` result is a validation finding to investigate, not something to normalize away. Also record every printed issue code/message for non-Complete capabilities.

## 4. Offline readback

Use a new CLI invocation to prove the artifact can be consumed without an AD connection:

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

The IDs and status must agree. For a stronger offline proof, disconnect/block access to the lab after collection and run `inspect` again; `inspect` should still work because it only opens the artifact.

## 5. Validate known counts/facts

Compare the CLI counts and snapshot contents against the known lab fixture, not against assumptions.

Record at least:

| Data | Expected | Actual | Result / note |
| --- | ---: | ---: | --- |
| Domains |  |  |  |
| Users |  |  |  |
| Groups |  |  |  |
| Computers |  |  |  |
| OUs |  |  |  |
| Direct/primary memberships |  |  |  |
| Configured trusts |  |  |  |

For memberships, explicitly include at least one nested group, one primary-group relationship and any foreign-security-principal case present in the fixture.

Do not treat a count mismatch as a harmless cosmetic difference until the source is understood (system objects, filtering semantics, disabled/deleted objects, range retrieval, fixture drift, etc.).

## 6. Audit-full collection

After minimal is understood, run:

```powershell
./dogfighter scan `
  --target dc01.mini.lab `
  --profile audit-full `
  --output .\lab-artifacts\mini-audit-full.dogad
```

If the lab intentionally returns SYSVOL paths through another DC that is not the GPO domain DFS authority or the initial target, approve only that authority explicitly:

```powershell
  --sysvol-authority dc02.mini.lab
```

Do not add broad/wildcard authority bypasses.

Audit-full additionally validates:

- `directory.acls`
- `gpo.metadata`
- `gpo.links`
- `gpo.sysvol`

Record at minimum:

| Data | Expected | Actual | Result / note |
| --- | ---: | ---: | --- |
| Security descriptors / supported ACEs |  |  |  |
| GPO objects |  |  |  |
| GPO links |  |  |  |
| SYSVOL inventoried files |  |  |  |
| Normalized supported GPO settings |  |  |  |

Check at least one known GPT.INI, GptTmpl.inf, Registry.pol and Preferences XML case when the fixture contains them. Confirm legacy `cpassword` is represented only as the safe presence signal and that the value itself is absent from snapshot observations/settings.

## 7. Explicit failure/partial cases

After a successful baseline, exercise controlled failure cases one at a time. Restore the lab between cases when necessary.

Recommended cases:

1. Inaccessible or missing SYSVOL policy directory -> `gpo.sysvol` must become incomplete with an issue.
2. Denied SYSVOL file read -> incomplete coverage; no silent omission.
3. Out-of-scope/mutated `gPCFileSysPath` fixture -> reject before filesystem access.
4. Unavailable/slow SYSVOL operation -> worker timeout/termination must not hang the scan indefinitely.
5. Insufficient ACL read permissions -> `directory.acls` must be incomplete rather than clean.
6. Large/ranged group membership -> verify range retrieval and final member count.
7. LDAP cancellation (Ctrl+C), including during the hidden password prompt -> no successful final artifact should be published as if complete.
8. Referral/inaccessible naming-context fixture when available -> capture actual current behavior before hardening it.
9. Remote workstation DNS failure -> collection must fail/partial rather than being misdiagnosed as an authentication problem.
10. Explicit LDAP username with no SMB network context -> minimal may succeed while `gpo.sysvol` remains incomplete; record the distinction.
11. Explicit LDAP username with an IP-literal target -> parser must reject it immediately with an invalid-arguments result instead of entering LDAP collection.
12. Wrong explicit LDAP credential in the lab -> expect a sanitized authentication issue (typically `collection.ldap.authentication-failed`) and no credential text in output/artifact.
13. Stalled native LDAP connection/authentication setup -> expect `collection.ldap.bind-timeout` at the 15-second setup boundary instead of an indefinitely silent scan.
14. Synthetic collector that blocks synchronously before returning its Task -> executor regression must produce `collection.collector.timeout` at the profile boundary.
15. Remote `DOMAIN\user` explicit credential -> start marker must show `ldap-auth=ntlm`; a UPN/current-context run should show Negotiate.

For every case record the capability status and issue code/message, not just the process exit or generic console text.

## 8. Read-only validation

The current claim is read-only collection, not exploitation/validation.

During the lab run, verify by code review and environment observation that DogfighterAD does not:

- issue LDAP modify/add/delete requests;
- write SYSVOL files;
- change GPOs;
- dump credentials/secrets;
- execute attack paths;
- contact configured trust partners merely because a trust object exists.

A configured trust is collected from local `trustedDomain` metadata only; remote reachability is not implied.

## 9. Artifact retention

`.dogad` contains sensitive AD assessment data even without passwords. Store lab artifacts in an access-controlled local path. Do not commit real/customer `.dogad` files into the source repository.

For reproducible synthetic fixtures, create intentionally sanitized fixtures separately and document their generation.

## 10. Result record

Create a dated record under `docs/lab-runs/` using the template in that directory. The record should include:

- exact commit SHA;
- lab fixture/version/state;
- commands and exit codes;
- expected vs actual counts;
- capability coverage/statuses;
- issue codes/messages for incomplete capabilities;
- observed defects or unexplained differences;
- whether `.dogad` offline readback succeeded;
- measured duration and, once telemetry exists, LDAP request/page counts and peak memory;
- explicit statement that no customer/real credentials or secrets were committed.

Only after this record is understood should the same process be repeated on the larger GOAD fixture and then used as the basis for Rule Engine work.
