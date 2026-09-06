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

## Review findings

The previous hardening isolated `Bind()` itself, but the complete Windows LDAP setup path still mixed several concerns:

1. native WLDAP32 connection/configuration/authentication can block before or around the explicit bind boundary;
2. a down-level explicit identity such as `MINILAB\alice` was still using `AuthType.Negotiate` on a workstation whose lab DNS/Kerberos discovery path was known to be incomplete;
3. the scanner only printed a scan-level start marker, so a live stall could not identify the exact collector boundary; and
4. after an external timeout, an isolated native setup task could outlive the prompt-owned credential scope. The native task therefore must not retain the prompt-owned `SecureString` directly.

The current fix makes these boundaries explicit instead of relying on implicit Negotiate/fallback and object-lifetime behavior.

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
- the CLI start marker prints the selected auth mode and all three timeout boundaries without printing credential values;
- each collector emits safe runtime progress (`start`, `done`, `failed`, `timeout`, `blocked`, `canceled`) containing collector ID, elapsed/timeout values and sanitized issue code only;
- every native setup operation receives its own cloned runtime credential lease. A setup that outlives the scan does not depend on the prompt-owned `SecureString`; the cloned credential is disposed with the live LDAP client or, for a timed-out setup, when the native setup finally returns.

For the exact MINILAB command using `MINILAB\alice`, the fresh build should therefore begin with lines shaped like:

```text
Starting collection: target=dc.mini.lab profile=minimal ldap-auth=ntlm bind-timeout=00:00:15 request-timeout=00:00:30 collector-timeout=00:02:00.
[collection] start collector=ad.ldap.rootdse timeout=00:02:00
```

If native LDAP setup exceeds its 15-second deadline, the expected diagnostic shape is:

```text
[collection] failed collector=ad.ldap.rootdse issue=collection.ldap.bind-timeout elapsed=...
```

followed by the normal Failed snapshot summary and sanitized issue message. This is expected behavior to validate, not a claim that it has already been observed.

A fresh live run is required before claiming that these changes fix the workstation path. The required evidence is the full start marker, the last per-collector progress line, final snapshot status/counts/issues, and `$LASTEXITCODE`. `audit-full` remains blocked on successful `minimal` plus separately validated SMB/SYSVOL name resolution and network security context.
