# Portable SYSVOL authentication prototype - 2026-09-06

Status: approved spike; not production behavior.

## Question

Can DogfighterAD, using explicit user credentials, authenticate to the selected AD controller and read one known GPO `GPT.INI` from SYSVOL on both a non-domain Windows host and Linux without relying on a pre-existing OS SMB session or a domain join?

The spike exists to answer that question only. It must not be used to justify broader collection claims until both platforms pass live validation.

## Known live baseline

- `minimal` LDAP collection from the non-domain Windows workstation is Complete after disabling implicit LDAP referral chasing.
- The non-domain workstation can reach the DC on TCP/88, 389 and 445, but its tested Windows logon/session path did not obtain a `cifs/dc.mini.lab` service ticket and could not open SYSVOL.
- A separate domain-joined Windows VM can read both `\\dc.mini.lab\SYSVOL\mini.lab\Policies` and `\\mini.lab\SYSVOL\mini.lab\Policies` and both default GPO roots.
- Workgroup membership is not treated as the root cause by itself. The exact ticket acquisition failure on MAIN remains an environmental/authentication fact to preserve, not a universal Kerberos rule.

## Prototype scope

Use a single selected DC (`dc.mini.lab`) and one known policy file, for example:

`SYSVOL/mini.lab/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI`

The prototype should:

1. Accept the same explicit identity form used by the CLI, with the password supplied interactively or through an in-process test harness, never argv.
2. Acquire Kerberos credentials explicitly enough to request a service ticket for the selected SMB server identity (expected SPN shape: `cifs/dc.mini.lab`).
3. Connect directly to the selected DC on SMB over TCP/445 using SMB2/3 only.
4. Require the security properties needed for the tested SYSVOL path rather than disabling signing or server-authentication checks to make the test pass.
5. Tree-connect only to `SYSVOL` and open only the validated `mini.lab/Policies/<known-guid>/GPT.INI` path.
6. Read the file under a small byte limit and hard operation deadline.
7. Emit safe stage/result diagnostics such as Kerberos acquisition, service-ticket acquisition, SMB negotiate, authentication, tree connect and file read. Do not emit secrets or raw authentication blobs.
8. Run unchanged in principle on non-domain Windows and Linux.

## Candidate libraries

`SMBLibrary` and `Kerberos.NET` are candidates for the spike, not selected production dependencies. Their repositories indicate that SMBLibrary provides a cross-platform SMB client implementation and Kerberos.NET provides a managed Kerberos client, but the combination must be proven against this AD fixture before integration. The spike must also record dependency license/packaging implications and the exact negotiated authentication/signing behavior.

A failed combination is a useful result. Do not add silent NTLM downgrade, disable signing, relax server identity, or broaden the approved SYSVOL path just to obtain a green prototype.

## Success criteria

The spike passes only when all of the following are observed on both target clients:

- non-domain Windows MAIN reads the selected `GPT.INI` through the application-owned transport;
- Linux reads the same `GPT.INI` through the same logical transport design;
- the selected server identity and service principal are explicit and recorded safely;
- SMB signing/integrity state is observed and meets the prototype requirement;
- no password appears in argv, environment variables, logs or temporary files;
- path validation, byte limit and timeout are enforced before/around the read;
- the file bytes match the control read from the domain-joined Windows VM for the same fixture.

## Failure criteria and diagnostics

A prototype failure must identify the narrow stage reached, for example:

- KDC unreachable;
- Kerberos credential/TGT acquisition rejected;
- `cifs/<dc>` service ticket acquisition rejected;
- SMB negotiate failed;
- SMB authentication failed;
- signing/security requirement not met;
- `SYSVOL` tree connect failed;
- approved path not found/access denied;
- read exceeded byte/time budget.

Do not collapse these into a generic `IOException` in the spike report.

## Integration decision

Only after both platforms pass should the transport be integrated behind the existing `IReadOnlySysvolClient` and helper-process isolation boundary. The existing GPO path-policy validation, evidence/provenance model, timeout/kill semantics and coverage rules remain requirements. Production integration should be a separate reviewed change from the prototype itself.

## 2026-09-07: SMB SessionKey length correction

Baseline b9f10d6 timed out at tree-connect after successful Kerberos login.
The adapter passed the entire Kerberos key to SMBLibrary's key derivation.
Normalize it to 16 bytes before deriving SMB signing/encryption material:
truncate longer keys, right-pad shorter keys with zero bytes, reject empty keys.
See [MS-SMB2 3.2.5.3.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7fd079ca-17e6-4f02-8449-46b606ea289c).

Validation on non-domain Windows MAIN: Release build succeeded; 222 executable
core tests passed, including four normalization cases. The corrected prototype
read 22 bytes from the selected default-domain-policy GPT.INI on dc.mini.lab
using SMB311 with required signing, in 11.335 seconds overall, with the original
20-second deadline. No signing bypass or authentication fallback was introduced.

This narrowly fixes the reproduced key-length defect and preserves the existing
prototype ticket-key selection. General GSS context/subkey/AP-REP handling,
Linux validation, a trusted control-file comparison, and cleanup/deadline
isolation remain follow-up work. Successful session setup alone still must not
be treated as proof of a complete secure transport implementation.
