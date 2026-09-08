# MINILAB / GOAD live collection runbook

This runbook is the live validation path for DogfighterAD collection and offline analysis. A successful process exit is not enough: record the exact build, lab state, expected facts, actual counts, capability coverage and artifact readback result.

Automated CI and synthetic fixtures are prerequisites, not substitutes for this record. In particular, the 0.3.2 AD CS branch must not be described as live-validated until the AD CS section below is completed against a lab with a real Enterprise CA.

## 1. Preconditions

Use an assessment identity authorized for read-only directory/SYSVOL/Configuration-NC access. DogfighterAD must not place passwords in CLI arguments, committed scripts, `.dogad` artifacts or logs.

Current authentication behavior:

- no `-u`: LDAP uses current OS security context with Negotiate; SYSVOL uses the OS network context;
- with `-u/--username`: the CLI opens a hidden password prompt, LDAP defaults to Negotiate, and `audit-full` reuses the credential for DogfighterAD-owned portable Kerberos/SMB SYSVOL;
- `--ldap-auth ntlm` is an explicit LDAP compatibility mode only and requires `-u`.

There is no `-p` password flag. With explicit credentials, `--target` must be a resolvable DC DNS hostname/FQDN.

Record before running:

```text
Date/time UTC:
DogfighterAD commit SHA:
.NET SDK/runtime:
Host OS:
Domain-joined? yes/no
Lab: MINILAB / GOAD
Lab version/commit/snapshot:
Collection identity (name only):
Target DC/domain:
Known DNS/domain/forest names:
Enterprise CA expected? yes/no
Expected CA names:
Expected certificate-template count or planted template names:
Expected vulnerable/clean AD CS fixtures:
```

### Network preflight

For a workstation outside the lab domain:

```powershell
Resolve-DnsName dc.mini.lab
Test-NetConnection dc.mini.lab -Port 389
Test-NetConnection dc.mini.lab -Port 445
Test-NetConnection dc.mini.lab -Port 88
```

Use 636 instead of 389 for LDAPS. AD CS 0.3.2 itself uses LDAP Configuration-NC data only and does not require CA RPC/HTTP connectivity.

## 2. Build the exact commit

```powershell
git rev-parse HEAD
dotnet restore tests/DogfighterAD.Core.Tests/DogfighterAD.Core.Tests.csproj
dotnet build tests/DogfighterAD.Core.Tests/DogfighterAD.Core.Tests.csproj -c Release --no-restore
dotnet run --project tests/DogfighterAD.Core.Tests/DogfighterAD.Core.Tests.csproj -c Release --no-build
```

Before live testing, the same commit should be green in the repository CI matrix, including web/JavaScript/rule-catalog smoke and Windows publish smoke.

For a self-contained Windows deployment:

```powershell
dotnet publish src/DogfighterAD.Cli/DogfighterAD.Cli.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -o C:\DogfighterBuild
```

## 3. Minimal collection first

```powershell
./dogfighter scan `
  --target dc.mini.lab `
  --profile minimal `
  -u 'MINILAB\alice' `
  --output .\lab-artifacts\mini-minimal.dogad
```

Expected minimal capabilities include directory core/domains/users/groups/computers/OUs/memberships/security-policy/trusts. AD CS capabilities are **not** requested by `minimal`.

Record process exit code and every capability status. A `Partial`/`Failed` result is a validation finding to investigate.

## 4. Offline readback

Use a new CLI invocation:

```powershell
./dogfighter inspect --snapshot .\lab-artifacts\mini-minimal.dogad
```

Record snapshot ID/status from scan and inspect. They must agree. `inspect` is offline and should continue to work after lab network access is removed.

## 5. Audit-full collection

```powershell
./dogfighter scan `
  --target dc.mini.lab `
  --profile audit-full `
  -u 'MINILAB\alice' `
  --output .\lab-artifacts\mini-audit-full.dogad
```

`audit-full` additionally requests ACL/GPO/SYSVOL and the 0.3.2 AD CS directory capabilities:

```text
adcs.authorities
adcs.templates
adcs.publication
adcs.acls
adcs.trust
```

The AD CS collector reads only `CN=Public Key Services,CN=Services,<configurationNamingContext>` with LDAP and DACL-only security-descriptor reads. It must not contact CA registry/RPC/service/web enrollment endpoints.

If the lab has no Enterprise CA, all five AD CS capabilities should be `NotApplicable` after a successful search. If a CA is expected but collection is blocked/partial/failed, do not reinterpret that as “no AD CS risk”.

## 6. Record normal inventory

Record at minimum:

| Data | Expected | Actual | Result / note |
| --- | ---: | ---: | --- |
| Domains |  |  |  |
| Users |  |  |  |
| Groups |  |  |  |
| Computers |  |  |  |
| OUs |  |  |  |
| Direct/primary memberships |  |  |  |
| Configured trusts |  |  |  |
| Security descriptors / supported ACEs |  |  |  |
| GPO objects |  |  |  |
| GPO links |  |  |  |
| SYSVOL inventoried files |  |  |  |
| Enterprise CAs |  |  |  |
| Certificate templates |  |  |  |
| CA→template publication edges |  |  |  |
| AD CS descriptors |  |  |  |
| NTAuth object/certificates |  |  |  |

For memberships, include a nested group, a primary-group relationship and any FSP case present in the fixture.

## 7. AD CS 0.3.2 live acceptance

This section is required before claiming live AD CS validation.

### 7.1 Capability coverage

For a lab with an Enterprise CA, record:

```text
adcs.authorities   status=_____ items=_____ issues=_____
adcs.templates     status=_____ items=_____ issues=_____
adcs.publication   status=_____ items=_____ issues=_____
adcs.acls          status=_____ items=_____ issues=_____
adcs.trust         status=_____ items=_____ issues=_____
```

Expected successful baseline is `Complete` for all five unless the lab deliberately exercises a partial case.

### 7.2 CA inventory

For each expected Enterprise CA verify:

- stable CA directory object identity/DN;
- `cn` and DNS hostname when configured;
- CA certificate metadata/fingerprint when `cACertificate` is present;
- published template names/edges;
- CA directory DACL state and parsed supported ACEs.

Compare CA/template publication edges against the lab configuration, not only object counts.

### 7.3 Template inventory

For planted templates verify the snapshot contains the expected values for:

- common/display name and template OID/version where present;
- EKUs/application policies;
- `msPKI-Certificate-Name-Flag`;
- `msPKI-Enrollment-Flag`;
- `msPKI-Private-Key-Flag`;
- `msPKI-RA-Signature`;
- validity/overlap periods;
- direct DACL/ACE evidence;
- publication on expected CA(s).

Missing/malformed required security operands should make coverage incomplete rather than becoming zero/default values.

### 7.4 NTAuth directory posture

Record whether `CN=NTAuthCertificates` exists and the certificate fingerprints collected from it. A CA certificate matching NTAuth directory data is only a **directory trust match**. Do not claim endpoint-chain validation or live authentication acceptance from this evidence.

### 7.5 Offline AD CS rules

Run after collection, then disconnect from the lab network if practical:

```powershell
./dogfighter analyze `
  --snapshot .\lab-artifacts\mini-audit-full.dogad `
  --output .\lab-artifacts\mini-adcs.json `
  --rule ADCS.TEMPLATE.ESC1_CANDIDATE `
  --rule ADCS.TEMPLATE.DANGEROUS_ACL `
  --rule ADCS.TEMPLATE.BROAD_ENROLLMENT `
  --rule ADCS.TEMPLATE.AUTHENTICATION_CAPABLE `
  --rule ADCS.TEMPLATE.ENROLLEE_SUPPLIES_SUBJECT `
  --rule ADCS.TEMPLATE.NO_APPROVAL `
  --rule ADCS.TEMPLATE.NO_AUTHORIZED_SIGNATURE `
  --rule ADCS.CA.DANGEROUS_DIRECTORY_ACL `
  --fail-on none
```

Record evaluation outcome for every planted template/CA, not only findings.

Recommended fixture matrix:

1. **clean template** — no ESC1 candidate and no dangerous ACL;
2. **ESC1-like directory candidate** — published, low-priv Enrollment, authentication purpose, enrollee-supplies-subject, no approval, zero authorized signatures -> `ADCS.TEMPLATE.ESC1_CANDIDATE = Potential`;
3. same template with manager approval -> ESC1 candidate false;
4. same template with one authorized signature -> ESC1 candidate false;
5. broad enrollment but server-auth-only/non-authentication purpose -> `BROAD_ENROLLMENT` may match but ESC1 candidate false;
6. unpublished vulnerable-looking template -> ESC1 candidate `NotApplicable` for publication;
7. low-priv GenericWrite/WriteDacl/WriteOwner/GenericAll on a template -> dangerous template ACL candidate;
8. dangerous low-priv directory control on CA object -> `ADCS.CA.DANGEROUS_DIRECTORY_ACL = Potential`;
9. custom enrollment group containing a normal enabled user through nested membership -> broad enrollment can be proven via membership evidence;
10. comparable custom group whose witnessed member is privileged -> must not be treated as low privilege merely from group name/SID unfamiliarity.

### 7.6 Runtime boundary assertion

The live report/UI must **not** claim that 0.3.2 verified:

- CA registry policy;
- `EDITF_ATTRIBUTESUBJECTALTNAME2`;
- CA RPC/DCOM/service permissions;
- web enrollment;
- EPA/channel-binding/NTLM behavior;
- successful issuance;
- certificate impersonation/exploitability;
- complete Windows effective-access/deny precedence.

A matched `ADCS.TEMPLATE.ESC1_CANDIDATE` must remain `Potential` and describe itself as directory-derived.

## 8. Local UI acceptance

Run the loopback UI from the same build and start an `audit-full` assessment.

Verify:

- collection progress includes `ad.ldap.adcs`;
- completed live assessment opens the Certificate Services workspace (not only uploaded snapshots);
- CAs view shows CA metadata/certificates/publications/DACL/findings;
- Templates view shows safe templates as well as risky ones;
- template detail shows EKU/policies, flags, approval/signature posture, validity, publication, enrollment trustees, ACLs, findings and evidence;
- Findings view contains the `ADCS.*` subset from the same offline report;
- legacy/unavailable AD CS data is not shown as a clean empty environment;
- all-five-`NotApplicable` state is displayed as no Enterprise AD CS directory posture found, not as a runtime security verdict.

## 9. Controlled failure cases

After a successful baseline, exercise controlled failures one at a time where practical:

1. wrong explicit password -> sanitized auth failure, no credential text;
2. DNS/transport failures -> fail/partial, no misleading clean result;
3. unavailable SYSVOL/Kerberos/SMB -> `gpo.sysvol` incomplete;
4. insufficient domain ACL rights -> `directory.acls` incomplete;
5. insufficient Configuration-NC/template descriptor rights -> affected `adcs.*` capability incomplete;
6. malformed/unsupported AD CS certificate/DACL/template operand fixture -> issue + incomplete capability, not fabricated defaults;
7. Ctrl+C during collection -> cancellation and no successful final artifact.

For every case record capability status and issue code/message, not only process exit.

## 10. Read-only validation

Verify DogfighterAD does not:

- issue LDAP modify/add/delete requests;
- write/create/delete/rename SYSVOL files;
- modify templates/CAs/GPOs;
- invoke certificate enrollment or CA management actions;
- contact CA registry/RPC/web endpoints in the 0.3.2 AD CS collector;
- dump credentials, Kerberos tickets/session keys or SMB security blobs;
- execute attack paths.

## 11. Artifact retention

`.dogad` contains sensitive AD/PKI assessment data even without passwords. Store lab artifacts in an access-controlled local path. Do not commit live/customer `.dogad` files.

## 12. Result record

Create a dated record under `docs/lab-runs/` including:

- exact `git rev-parse HEAD`;
- lab fixture/version/state;
- host/domain-join state;
- commands and exit codes;
- selected LDAP/SYSVOL auth markers;
- expected vs actual core + AD CS counts;
- all capability statuses/issues;
- expected vs actual `ADCS.*` outcomes for planted fixtures;
- UI Certificate Services acceptance result;
- `.dogad` offline readback result;
- measured duration;
- explicit statement that no real/customer credential material was committed;
- explicit statement that runtime CA conditions were not claimed unless separately collected by a future capability.
