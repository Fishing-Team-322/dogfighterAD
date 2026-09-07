# 2026-09-07 WORKGROUP portable SYSVOL audit-full validation

## Scope

Authorized MINILAB validation of the production portable Kerberos/SMB SYSVOL integration on a non-domain Windows workstation.

Branch under test: `feature/portable-sysvol-transport`.

The exact local `git rev-parse HEAD` was not pasted into the chat transcript, so runtime provenance is recorded against the branch/test behavior rather than asserted as an exact local commit SHA. The branch head immediately before the run was `5cbd8530af4eaf43b54579d95cfa88f12835c2d9`.

## Environment

- Target DC: `dc.mini.lab`
- Explicit identity: `MINILAB\alice`
- Host context: non-domain / WORKGROUP Windows workstation
- Profile: `audit-full`
- LDAP auth: Negotiate
- LDAP protection: signing/sealing
- SYSVOL auth: portable Kerberos
- Password supplied only through the hidden interactive prompt; no secret value was captured in the transcript.

## Command

```powershell
.\src\DogfighterAD.Cli\bin\Release\net10.0\dogfighter.exe scan `
  --target dc.mini.lab `
  --profile audit-full `
  -u 'MINILAB\alice' `
  --output .\lab-artifacts\mini-audit-full-portable.dogad
```

Startup marker confirmed the intended credential path:

```text
ldap-auth=negotiate
ldap-protection=sign-seal
ldap-target-mode=fqdn-server
sysvol-auth=portable-kerberos
```

## Result

Collection completed successfully.

```text
Snapshot: 8b8be944-e95e-4a63-9321-c39b41ff8344
Status: Complete
Profile: audit-full
Target: dc.mini.lab
Objects: domains=1 users=8 groups=50 computers=2 ous=1 memberships=41 gpos=2
```

Coverage:

```text
directory.acls             Complete      items=62 issues=0
directory.computers        Complete      items=2 issues=0
directory.core             Complete      items=1 issues=0
directory.domains          Complete      items=1 issues=0
directory.groups           Complete      items=50 issues=0
directory.memberships      Complete      items=41 issues=0
directory.ous              Complete      items=1 issues=0
directory.trusts           Complete      items=0 issues=0
directory.users            Complete      items=8 issues=0
gpo.links                  Complete      items=2 issues=0
gpo.metadata               Complete      items=2 issues=0
gpo.sysvol                 Complete      items=4 issues=0
```

`ad.sysvol.gpo-settings` completed in approximately 11.76 seconds and reported no issues.

Exit code:

```text
0
```

## Offline artifact verification

The generated artifact was inspected using the offline `inspect` command:

```powershell
.\src\DogfighterAD.Cli\bin\Release\net10.0\dogfighter.exe inspect `
  --snapshot .\lab-artifacts\mini-audit-full-portable.dogad
```

The readback produced the same snapshot ID, completion status, object counts, and coverage summary:

```text
Snapshot: 8b8be944-e95e-4a63-9321-c39b41ff8344
Status: Complete
Profile: audit-full
Target: dc.mini.lab
```

`inspect` exit code:

```text
0
```

## Acceptance conclusion

The production portable SYSVOL integration passed its Windows WORKGROUP acceptance gate for this MINILAB fixture:

- explicit LDAP credentials were reused for portable Kerberos SYSVOL without an additional transport flag;
- the non-domain Windows host no longer depended on the OS SMB redirector for audit-full SYSVOL collection;
- GPO metadata, links, ACLs and SYSVOL collection all completed with zero issues;
- the resulting `.dogad` artifact passed strict offline readback and preserved the same snapshot identity and coverage.

Linux live validation remains a later acceptance gate. CI build/tests on Ubuntu are still required before merge.
