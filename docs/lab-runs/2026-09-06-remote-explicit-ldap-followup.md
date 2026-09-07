# Remote explicit-LDAP follow-up - 2026-09-06

## Scope

This record continues the MINILAB remote-workstation validation after the earlier explicit-credential Failed snapshot. It records only observed behavior and the code changes made in response. No password or credential value is recorded.

Branch: `foundation/snapshot-core`.

## Second FQDN explicit-credential attempt

The workstation ran the updated CLI using the DC FQDN, `minimal` profile and an explicit LDAP username. The `-p` flag had already been removed; `-u` opened the hidden password prompt automatically.

Command shape:

```powershell
dogfighter scan `
  --target dc.mini.lab `
  --profile minimal `
  -u 'MINILAB\alice' `
  --output C:\DogfighterLab\minimal-from-workstation-auth-v2.dogad
```

Observed console state:

```text
LDAP password for MINILAB\alice:
```

The password was entered. The process then produced no further visible output and did not promptly return. No snapshot ID, final status or exit code was captured for this attempt, so none is inferred here.

This observation disproved the narrower assumption that only an IP-literal explicit Negotiate target could trigger the non-returning behavior. The FQDN path could also stall after the interactive prompt.

## Code review finding

The collection timeout was not a complete safety boundary for synchronous pre-await blocking.

`CollectionExecutor` created a linked cancellation token and called `collector.CollectAsync(...)` directly. A collector could therefore enter blocking native code before its method returned a `Task`; in that state `CancelAfter` existed but the orchestration thread had not yet reached an awaitable operation that could observe it.

The LDAP transport had the same structural problem at a lower layer. `System.DirectoryServices.Protocols` could enter a synchronous Negotiate bind in the auto-bind path before `BeginSendRequest` returned its asynchronous result. A configured request timeout therefore did not guarantee that the scanner would regain control if the native bind itself stalled.

The exact external MINILAB reason for the stalled Negotiate bind (for example name/SPN/authentication environment) is still not claimed from this run because the stalled revision did not return an LDAP result/error. The product bug was that such a native stall could bypass the intended timeout/diagnostic boundaries.

## Fixes

The following changes were made on `foundation/snapshot-core`:

- `b8d9ea4a51f3caccc8540eb3bb9ea1242629a193` - invoke collectors off the orchestration thread and apply the linked profile timeout with `WaitAsync`, so synchronous collector entry cannot hold collection orchestration indefinitely.
- `a40dc26390338aaa1c47b4908598b852b0c292a5` - regression for a collector that blocks synchronously before returning its `Task`.
- `3a0a56cb8c22b9e1025ba711bd6148c65ef2748e` - disable LDAP auto-bind and run explicit synchronous `LdapConnection.Bind()` on an isolated task with the configured LDAP timeout as an external boundary. A stalled bind is classified as `collection.ldap.bind-timeout`.
- `37f40c30f6245964c8f86ce664d8a63d0a745ca3` - print a `Starting collection: ...` marker immediately after the credential prompt so prompt completion is distinguishable from transport collection.
- `318277d85d61b35a08c7c5acefe18ac019792400` - make the blocking-timeout regression responsive to the xUnit test cancellation token after the first CI analyzer failure.

CI run `34044823910` for `318277d85d61b35a08c7c5acefe18ac019792400` completed successfully on Ubuntu and Windows; the Windows self-contained publish smoke also completed successfully.

## Containment semantics

The scanner now stops waiting for an explicit Negotiate bind after the configured LDAP timeout (currently 30 seconds) and can return a sanitized Failed result rather than remaining indefinitely silent. The profile collector timeout remains an additional outer boundary.

This does not claim that a native WLDAP32 call can always be forcibly cancelled. If Windows itself keeps a native bind call blocked, that call may continue on its isolated background thread until the OS returns it. The scanner no longer waits indefinitely for that thread, and connection cleanup is deferred until the native operation completes.

## Next live gate

Build and publish the latest branch revision, then repeat the same FQDN `minimal` explicit-credential command. Record:

- whether the `Starting collection:` marker appears after the password prompt;
- elapsed time until result;
- snapshot ID/status and process exit when present;
- every issue code/message shown for `directory.core` or other incomplete capabilities.

If the Negotiate bind still stalls, the expected product behavior is a `collection.ldap.bind-timeout` result around the configured LDAP timeout rather than an indefinitely non-returning scan. This is an expected behavior checkpoint, not a claim about the next live result.

Do not proceed to remote `audit-full` until the explicit LDAP `minimal` path is understood. SYSVOL/SMB remains a separate OS-network-context requirement.
