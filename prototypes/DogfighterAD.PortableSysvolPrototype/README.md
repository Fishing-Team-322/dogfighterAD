# Portable SYSVOL prototype

This is a deliberately narrow proof of concept. It does **not** replace the production `DogfighterAD.SysvolWorker` or `gpo.sysvol` transport.

The only successful operation implemented by this executable is:

1. acquire a Kerberos TGT for an explicitly supplied account;
2. acquire a service ticket for exactly `cifs/<server>`;
3. establish an SMB 3.1.1 session to that explicitly named server over TCP/445;
4. fail closed unless SMB signing is required by the negotiated session;
5. tree-connect only to the `SYSVOL` share;
6. open only `<domain>\Policies\{GPO-GUID}\GPT.INI`;
7. read at most the configured byte budget;
8. print only status, byte count and SHA-256, not file contents, credentials, tickets or session keys.

The whole blocking Kerberos/SMB operation is contained behind an outer deadline. Cancellation stops the caller from waiting; as with other blocking/native boundaries, that is a containment guarantee rather than a claim that every library/internal network call can be forcibly aborted at an arbitrary instruction.

## Dependencies

The prototype pins these candidate libraries so behavior can be validated against a known build:

- `SMBLibrary` 1.5.7.1 (LGPL-3.0-or-later)
- `Kerberos.NET` 4.6.168 (MIT)

Their presence here is an evaluation choice, not a production dependency decision.

## Build

```powershell
dotnet restore prototypes/DogfighterAD.PortableSysvolPrototype/DogfighterAD.PortableSysvolPrototype.csproj
dotnet build prototypes/DogfighterAD.PortableSysvolPrototype/DogfighterAD.PortableSysvolPrototype.csproj -c Release --no-restore
```

The same project is compiled by CI on Windows and Linux.

## MINILAB test

First select one GPO GUID from a host that can already read MINILAB SYSVOL:

```powershell
Get-ChildItem '\\dc.mini.lab\SYSVOL\mini.lab\Policies' |
    Select-Object -First 1 -ExpandProperty Name
```

Then run the prototype on the non-domain Windows scanner:

```powershell
dotnet run --project prototypes/DogfighterAD.PortableSysvolPrototype -c Release --no-build -- `
  --server dc.mini.lab `
  --kdc dc.mini.lab `
  --domain mini.lab `
  --realm MINI.LAB `
  --user alice `
  --gpo '{PUT-GPO-GUID-HERE}'
```

The password is requested by a hidden interactive prompt. There is intentionally no password command-line option.

Run the equivalent command on Linux after confirming that `dc.mini.lab` resolves to the intended lab DC and TCP/88 and TCP/445 are reachable.

## Success criteria

A successful probe exits `0` and prints fields similar to:

```text
kerberos: success
smb-session: success
smb-dialect: SMB311
smb-signing: required-and-verified-by-client
tree-connect: SYSVOL success
path-scope: accepted mini.lab\Policies\{...}\GPT.INI
read: <n> bytes
sha256: <hex>
elapsed: <duration>
```

The Windows and Linux runs should read the same known `GPT.INI` and therefore produce the same SHA-256 when the file has not changed between tests.

## Failure interpretation

A failure is reported by stage and a sanitized code. Do not reduce every failure to a transport defect. DNS, KDC/realm discovery/configuration, Kerberos account state, SPN availability, SMB authorization, SYSVOL permissions, server behavior and lab state can all affect the result.

In particular, a non-domain-joined Windows host is not by itself proof that Kerberos cannot work. The relevant evidence is the concrete Kerberos/KDC failure reported by this explicit credential path.

## Security boundaries

Do not loosen these boundaries merely to make the prototype pass:

- explicit DNS server target; IP literals are rejected;
- exact `cifs/<server>` SPN only;
- no SMB redirect/referral authentication to another SPN;
- SMB 3.1.1 and required signing;
- `SYSVOL` share only;
- one derived GPO `GPT.INI` path only;
- read-only SMB access;
- bounded file size;
- outer operation deadline and Ctrl+C handling;
- password not present in argv or normal output.

Only after the same bounded operation succeeds on the target non-domain Windows host and Linux should a production transport design be proposed.
