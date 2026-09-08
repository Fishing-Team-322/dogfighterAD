# Capability contracts

> **Rule Engine 0.2.0 update:** see [RULE_ENGINE.md](RULE_ENGINE.md) for the implemented offline engine, 80 rules, expanded collection contracts, schema-2 compatibility and exact CLI/verification semantics. Historical checkpoints below are retained as history.

Capability contracts define what data a snapshot is guaranteed to contain when a coverage record is marked `Complete` for a given contract version.

This document is normative for built-in collectors. It must change together with `CapabilityContractCatalog` when a contract version changes.

## Versioning rules

- Versions are positive integers.
- Versions are monotonic: v2 preserves every guarantee of v1 and may add new guarantees.
- A collector implementation version is not a capability contract version.
- New optional data that no rule relies on does not automatically require a capability version bump.
- Increase the contract version when newer analysis needs to distinguish snapshots that guarantee new data from older snapshots that did not collect it.
- If semantics cannot stay backward-compatible, create a new capability ID.

## Current built-in contracts

### `directory.core` v1

Owner: `ad.ldap.rootdse`

`Complete` guarantees that RootDSE discovery succeeded and the normalized `DirectoryEnvironment` contains at least `defaultNamingContext`, `configurationNamingContext` and `schemaNamingContext`. Available DNS host name, root domain naming context, naming contexts, supported LDAP versions, controls and capabilities are retained when present.

### `directory.domains` v1

Owner: `ad.ldap.domain-metadata`

`Complete` guarantees one normalized domain object for the discovered default naming context with stable `objectGUID`, domain `objectSid`, distinguished name, derived DNS domain name and domain functional level. Name and creation/change timestamps are collected when available. NetBIOS naming is outside v1.

### `directory.users` v1

Owner: `ad.ldap.directory-objects`

`Complete` guarantees successful default-domain user enumeration and usable stable `objectGUID`, DN, SID, parseable `userAccountControl` and `primaryGroupID` for every retained user. The collector also requests/normalizes, when present, `sAMAccountName`, UPN, `adminCount`, `pwdLastSet`, `lastLogonTimestamp`, `accountExpires`, `msDS-SupportedEncryptionTypes`, SPNs, `sIDHistory`, `msDS-AllowedToDelegateTo` and timestamps.

AD FileTime sentinels retain explicit meaning: `pwdLastSet=0` becomes `PasswordMustChangeAtNextLogon=true`; `accountExpires=0` or `Int64.MaxValue` becomes `AccountNeverExpires=true`. Raw values remain evidence facts.

### `directory.groups` v1

Owner: `ad.ldap.directory-objects`

`Complete` guarantees successful default-domain group enumeration and stable GUID/DN/SID identity plus parseable `groupType`. `sAMAccountName`, `adminCount`, name and timestamps are retained when present. Membership is a separate capability.

### `directory.computers` v1

Owner: `ad.ldap.directory-objects`

`Complete` guarantees successful default-domain computer enumeration and stable GUID/DN/SID identity plus parseable `userAccountControl`. Host/OS metadata, password/logon timestamps, encryption types, SPNs and constrained-delegation targets are retained when present.

### `directory.ous` v1

Owner: `ad.ldap.directory-objects`

`Complete` guarantees successful default-domain OU enumeration and stable GUID/DN identity. Name and timestamps are retained when present. ACL-derived protection semantics are intentionally outside this capability.

### `directory.memberships` v1

Owner: `ad.ldap.group-memberships`

Depends on complete `directory.core`, `directory.users`, `directory.groups` and `directory.computers` data.

`Complete` guarantees direct `member` relationships, full AD ranged-member retrieval through terminal ranges, direct group-to-group edges, reconstructed primary-group edges, stable member identity resolution, supporting FSP/generic objects when required, and source observations. Transitive membership is deliberately not precomputed. Incomplete ranges or unresolved identities produce `Partial`.

### `directory.trusts` v1

Owner: `ad.ldap.trusts`

Depends on `directory.core` and `directory.domains`. `Complete` guarantees local `trustedDomain` enumeration with normalized source domain, `trustPartner`, parseable direction/type/attributes and target SID when available. Zero trusts can legitimately be complete. The remote side is not contacted or validated.

### `directory.acls` v1

Owner: `ad.ldap.acls`

Depends on complete core/domain/users/groups/computers/OUs data. v1 covers the normalized default-domain root, users, groups, computers and OUs.

The collector requests only the DACL section of `nTSecurityDescriptor`. `Complete` preserves descriptor control flags; DACL state (`NotPresent`, `Null`, `Empty`, `Present`); Allow/Deny standard ACEs; Allow/Deny object ACEs; trustee SID; access mask; ACE flags/inheritance; and object/inherited-object GUIDs. Unsupported/malformed ACE semantics, missing descriptors or target inconsistencies produce `Partial`. Raw descriptor bytes are not persisted by default.

### `gpo.metadata` v1

Owner: `ad.ldap.gpo-metadata`

Depends on `directory.core`. Reads Group Policy Container objects from `CN=Policies,CN=System,<defaultNamingContext>`.

`Complete` guarantees successful GPC enumeration and stable AD `objectGUID`/DN plus a parseable unique policy GUID from the GPC `name`. `displayName`, `gPCFileSysPath`, `versionNumber`, GPO flags and timestamps are retained when present. A domain with no GPOs may be complete with zero items.

### `gpo.links` v1

Owner: `ad.ldap.gpo-links`

Depends on complete `directory.core`, `directory.domains`, `directory.ous` and `gpo.metadata`.

`Complete` guarantees:

- every prerequisite domain/OU container was returned by link enumeration;
- each `gPLink` entry was normalized into a stable container→GPO edge;
- 1-based stored link order follows AD `gPLink` sequence;
- raw link options plus normalized `Enabled` and `Enforced` are preserved (`0x1` disabled, `0x2` enforced);
- `gPOptions` plus normalized Block Inheritance are retained per domain/OU;
- linked GPO DNs resolve to collected GPO identities;
- source evidence retains LDAP provenance.

Malformed syntax, unknown targets, missing containers, invalid/unsupported options or duplicate container results produce `Partial`. This capability does not calculate RSoP/effective policy.

### `gpo.sysvol` v1

Owner: `ad.sysvol.gpo-settings`

Depends on complete `gpo.metadata`. It is a strictly read-only Group Policy Template collector using each GPO's `gPCFileSysPath`.

`Complete` guarantees that every known GPO with a usable SYSVOL path was recursively enumerated within configured file-count/read-size limits and that:

- every enumerated file has stable GPO identity, normalized relative path, byte length and file classification;
- every readable file within the configured size limit has SHA-256 inventory evidence;
- root `GPT.INI` is normalized as INI settings;
- `GptTmpl.inf` is normalized as security-template settings;
- `Machine\\Registry.pol` and `User\\Registry.pol` are parsed as v1 PReg policy records;
- DWORD/QWORD registry data is retained as normalized numeric values;
- arbitrary registry string, multi-string and binary payloads are retained as metadata-only records rather than blindly persisted;
- Preferences XML is parsed with DTD resolution disabled and records only the presence/count signal of legacy `cpassword` attributes; the `cpassword` value itself is never persisted;
- INI-like values with secret-like keys are redacted unless the key is an explicitly recognized password-policy setting;
- unknown policy files remain useful as inventory/hash evidence even when DogfighterAD does not yet understand their semantics.

A missing/unreadable GPO path, denied file/directory access, configured file-count/size limit hit, malformed supported policy file or unsupported Registry.pol semantic makes coverage `Partial`; such data is never silently treated as absent/safe.

v1 does **not** promise semantic parsing of every Group Policy extension, compute effective/RSoP policy, validate endpoint application, modify SYSVOL, or collect arbitrary file contents as a generic text archive.

### `adcs.directory` v1

Status: planned.

## Analysis compatibility

A rule declares a minimum capability contract, for example `directory.users >= 2`. A snapshot with `directory.users v1 = Complete` is insufficient for that rule and must result in `NotVerified`/insufficient data, not a negative finding. A snapshot with v3 may satisfy a rule requiring v2 because versions are monotonic.
