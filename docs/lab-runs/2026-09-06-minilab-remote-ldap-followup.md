# MINILAB remote LDAP follow-up - 2026-09-06

This note extends `2026-09-06-minilab-readiness.md` with the repeated remote-workstation explicit-credential observation. No password or credential value is recorded.

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

## Review finding

The previous hardening isolated `Bind()` itself, but the complete Windows LDAP setup path still mixed two concerns:

1. native WLDAP32 connection/configuration/authentication can block before or around the explicit bind boundary; and
2. a down-level explicit identity such as `MINILAB\alice` was still using `AuthType.Negotiate` on a workstation whose lab DNS/Kerberos discovery path was known to be incomplete.

Microsoft's `System.DirectoryServices.Protocols.AuthType` supports both `Negotiate` and `Ntlm`. The current fix therefore makes the remote down-level credential path explicit instead of relying on Negotiate/Kerberos fallback behavior.

## Current corrective behavior awaiting live rerun

The current branch now applies these rules:

- current OS security context -> `Negotiate`;
- explicit `DOMAIN\user` -> `Ntlm` challenge/response to the explicitly named DC;
- explicit `user@domain` -> `Negotiate`;
- no Basic-auth fallback is introduced;
- explicit credentials still require a DNS hostname target;
- the complete native LDAP connection/configuration/authentication setup runs behind a 15-second external deadline;
- LDAP requests retain a 30-second request timeout;
- profile-level collector timeout remains the outer collection boundary;
- the CLI start marker prints the selected auth mode and all three timeout boundaries without printing credential values.

For the exact MINILAB command using `MINILAB\alice`, the fresh build should therefore show:

```text
ldap-auth=ntlm bind-timeout=00:00:15 request-timeout=00:00:30
```

before collection proceeds.

A fresh live run is required before claiming that this change fixes the workstation path. The required evidence is the full start marker, final snapshot status/counts/issues, and `$LASTEXITCODE`. `audit-full` remains blocked on successful `minimal` plus separately validated SMB/SYSVOL name resolution and network security context.
