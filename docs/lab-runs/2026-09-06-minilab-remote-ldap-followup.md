# MINILAB remote LDAP follow-up - 2026-09-06

This note extends `2026-09-06-minilab-readiness.md` with the repeated remote-workstation explicit-credential observations. No password or credential value is recorded.

## Environment already established

- Scanner host: Windows workstation outside the MINILAB domain.
- Workstation Host-Only address: `192.168.57.1/24`.
- DC Host-Only address: `192.168.57.30/24`.
- TCP/389 and TCP/445 from workstation to the DC were observed reachable.
- Direct workstation DNS queries to the DC on port 53 remained unavailable.
- A controlled hosts-file entry allowed `dc.mini.lab` to resolve to `192.168.57.30` for LDAP testing.
- Resolution/access for the separate `mini.lab` SYSVOL authority is not yet considered solved.

## Repeated FQDN explicit-credential stall

A fresh self-contained build from commit:

```text
0e7494ac26368a7e92673ecbb59ab3c2790260ec
```

was run from the workstation with this command shape:

```powershell
dogfighter scan `
  --target dc.mini.lab `
  --profile minimal `
  -u 'MINILAB\alice' `
  --output C:\DogfighterLab\minimal-from-workstation-auth-v3.dogad
```

The hidden prompt accepted input and the scanner printed:

```text
Starting collection: target=dc.mini.lab profile=minimal collector-timeout=00:02:00.
```

No subsequent snapshot summary or exit code was captured in the reported run; the scanner again appeared non-returning after collection started. Therefore this run is recorded only as a **non-returning observation**. It is not evidence of an invalid password, successful authentication, or any particular LDAP server result.

## Review findings after the non-returning run

The previous hardening isolated `Bind()` itself, but the complete Windows LDAP setup path still mixed several concerns:

1. native WLDAP32 connection/configuration/authentication can block before or around the explicit bind boundary;
2. a down-level explicit identity such as `MINILAB\alice` was still using `AuthType.Negotiate` on a workstation whose lab DNS/Kerberos discovery path was known to be incomplete;
3. the scanner only printed a scan-level start marker, so a live stall could not identify the exact collector boundary; and
4. after an external timeout, an isolated native setup task could outlive the prompt-owned credential scope. The native task therefore must not retain the prompt-owned `SecureString` directly.

The next hardening made these boundaries explicit instead of relying on implicit Negotiate/fallback and object-lifetime behavior.

## Explicit NTLM + hard-boundary live result

A later fresh build used explicit `DOMAIN\user -> AuthType.Ntlm`, a 15-second native setup deadline, operation-owned credential lifetime, and per-collector progress output.

Observed command shape:

```powershell
dogfighter scan `
  --target dc.mini.lab `
  --profile minimal `
  -u 'MINILAB\alice' `
  --output C:\DogfighterLab\minimal-from-workstation-auth-v4.dogad
```

Observed start/progress:

```text
Starting collection: target=dc.mini.lab profile=minimal ldap-auth=ntlm bind-timeout=00:00:15 request-timeout=00:00:30 collector-timeout=00:02:00.
[collection] start collector=ad.ldap.rootdse timeout=00:02:00
[collection] failed collector=ad.ldap.rootdse issue=collection.ldap.bind-timeout elapsed=00:00:15.0142585
```

Observed result:

```text
Snapshot: 87b7e118-2ec7-4559-9809-88c2ab23a926
Status: Failed
Exit: 3
Objects: domains=0 users=0 groups=0 computers=0 ous=0 memberships=0 gpos=0
```

`directory.core` was `Failed` with:

```text
collection.ldap.bind-timeout
```

All minimal capabilities that depend on `directory.core` were `Blocked`. This run proves that the scanner no longer waits indefinitely and that safe live diagnostics/exit behavior work. It does **not** prove invalid credentials: no server authentication result was received before the local setup deadline.

## Additional code-review finding from the v4 timeout

The Windows LDAP identifier was still being created with the two-argument constructor:

```text
LdapDirectoryIdentifier(target, port)
```

That constructor leaves `FullyQualifiedDnsHostName` false. For the explicit-credential path, however, the CLI contract already requires `--target` to be the exact resolvable DC FQDN. Windows LDAP can otherwise treat a supplied host-like name as something that may require locator/name-resolution work before establishing the server session.

The current correction therefore makes the explicit server intent unambiguous:

- explicit credential -> `LdapDirectoryIdentifier(target, port, fullyQualifiedDnsHostName: true, connectionless: false)`;
- current OS context keeps discovery-capable identifier semantics because `--target` may still be a domain rather than a specific DC;
- regression coverage checks the FQDN/server and TCP identifier flags;
- the 15-second setup deadline remains in place, so a failed correction still produces bounded evidence rather than another indefinite wait.

This is a code-level defect found from the live v4 result. A fresh live rerun is required before claiming that the FQDN/server-binding correction resolves the workstation LDAP path.

## Current corrective behavior awaiting the next live rerun

The branch now applies these rules:

- current OS security context -> `Negotiate`;
- explicit `DOMAIN\user` -> `Ntlm` challenge/response to the explicitly named DC;
- explicit `user@domain` -> `Negotiate`;
- no Basic-auth fallback is introduced;
- explicit credentials require a named DNS DC target and mark it as a fully-qualified server in `LdapDirectoryIdentifier`;
- the complete native LDAP connection/configuration/authentication setup runs behind a 15-second external deadline;
- LDAP requests retain a 30-second request timeout;
- profile-level collector timeout remains the outer collection boundary;
- the CLI start marker prints the selected auth mode and all three timeout boundaries without printing credential values;
- each collector emits safe runtime progress (`start`, `done`, `failed`, `timeout`, `blocked`, `canceled`) containing collector ID, elapsed/timeout values and sanitized issue code only;
- every native setup operation receives its own cloned runtime credential lease. A setup that outlives the scan does not depend on the prompt-owned `SecureString`; the cloned credential is disposed with the live LDAP client or, for a timed-out setup, when the native setup finally returns.

The next remote-workstation evidence required is the full fresh start/progress output, final snapshot status/counts/issues and `$LASTEXITCODE`. If the exact FQDN server-binding build still times out, the next investigation should verify the actual AD NetBIOS/UPN identity and Windows authentication evidence on the DC rather than inferring a bad password from `bind-timeout`.

`audit-full` remains blocked on successful `minimal` plus separately validated SMB/SYSVOL name resolution and network security context.
