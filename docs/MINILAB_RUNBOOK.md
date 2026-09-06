# MINILAB / GOAD live collection runbook

This runbook is the first live validation path for the current Collection Core. It is deliberately evidence-oriented: a successful process exit is not enough. Record the exact build, lab state, expected facts, actual counts, coverage and artifact readback result.

Do not introduce broad detection rules until this path has been completed and discrepancies have been understood.

## 1. Preconditions

Use an assessment identity authorized for read-only directory/SYSVOL access. DogfighterAD uses the current operating-system security context; do not place passwords in CLI arguments, scripts committed to the repository, `.dogad` artifacts or logs.

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

## 2. Build the exact commit

```powershell
git rev-parse HEAD
dotnet restore src/DogfighterAD.Cli/DogfighterAD.Cli.csproj
dotnet build src/DogfighterAD.Cli/DogfighterAD.Cli.csproj -c Release --no-restore
```

Use the executable from the `Release/net10.0` CLI output. Confirm `DogfighterAD.SysvolWorker` and its runtime files are present beside it before `audit-full`.

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

Record the command exit code and every capability status. A `Partial` or `Failed` result is a validation finding to investigate, not something to normalize away.

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
7. LDAP cancellation (Ctrl+C) -> no successful final artifact should be published as if complete.
8. Referral/inaccessible naming-context fixture when available -> capture actual current behavior before hardening it.

For every case record the capability status and issue code, not just console text.

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
- observed defects or unexplained differences;
- whether `.dogad` offline readback succeeded;
- measured duration and, once telemetry exists, LDAP request/page counts and peak memory;
- explicit statement that no customer/real credentials or secrets were committed.

Only after this record is understood should the same process be repeated on the larger GOAD fixture and then used as the basis for Rule Engine work.
