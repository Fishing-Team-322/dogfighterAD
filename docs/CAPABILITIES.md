# Capability contracts

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

`Complete` guarantees that RootDSE discovery succeeded and the normalized `DirectoryEnvironment` contains at least:

- `defaultNamingContext`;
- `configurationNamingContext`;
- `schemaNamingContext`.

The collector also records available RootDSE metadata such as DNS host name, root domain naming context, naming contexts, supported LDAP versions, controls and capabilities.

### `directory.domains` v1

Owner: `ad.ldap.domain-metadata`

`Complete` guarantees one normalized domain object for the discovered default naming context with stable `objectGUID`, domain `objectSid`, distinguished name, derived DNS domain name and domain functional level. Name and creation/change timestamps are collected when available. NetBIOS domain naming is intentionally not part of v1 because it requires configuration-partition cross-reference collection.

### `directory.users` v1

Owner: `ad.ldap.directory-objects`

`Complete` guarantees that the requested default-domain subtree enumeration for user objects completed and every retained user has a usable stable `objectGUID`, distinguished name, `objectSid`, parseable `userAccountControl` and `primaryGroupID`.

The collector requests and normalizes, when present: `sAMAccountName`, `userPrincipalName`, `adminCount`, `pwdLastSet`, `lastLogonTimestamp`, `accountExpires`, `msDS-SupportedEncryptionTypes`, `servicePrincipalName`, `sIDHistory`, `msDS-AllowedToDelegateTo` and object timestamps.

Special AD FileTime values are not silently discarded. `pwdLastSet=0` is normalized as `PasswordMustChangeAtNextLogon=true`; `accountExpires=0` or `Int64.MaxValue` is normalized as `AccountNeverExpires=true`. Raw LDAP integer values remain available as observed facts.

### `directory.groups` v1

Owner: `ad.ldap.directory-objects`

`Complete` guarantees successful default-domain group enumeration and stable GUID/DN/SID identity for retained groups plus a parseable `groupType`. `sAMAccountName`, `adminCount`, name and timestamps are collected when present. Membership is intentionally not part of this capability.

### `directory.computers` v1

Owner: `ad.ldap.directory-objects`

`Complete` guarantees successful default-domain computer enumeration and stable GUID/DN/SID identity plus parseable `userAccountControl` for retained computers. Host identity, OS metadata, password/logon timestamps, encryption types, SPNs and constrained-delegation targets are collected when present.

### `directory.ous` v1

Owner: `ad.ldap.directory-objects`

`Complete` guarantees successful default-domain OU enumeration and stable GUID/distinguished-name identity for retained OUs. Name and creation/change timestamps are collected when present. `ProtectFromAccidentalDeletion` is intentionally not guaranteed by v1 because reliable evaluation belongs with security-descriptor/ACL collection.

### `directory.memberships` v1

Owner: `ad.ldap.group-memberships`

This capability depends on complete `directory.core`, `directory.users`, `directory.groups` and `directory.computers` data.

`Complete` guarantees direct group `member` relationships, full AD ranged-member retrieval, direct group-to-group edges, reconstructed `primaryGroupID` edges, stable member identity resolution, supporting foreign security principals/generic objects when required, and source observations. Transitive membership is deliberately not precomputed; analysis traverses the direct graph. Incomplete ranges or unresolved identities produce `Partial` rather than a misleading clean result.

### `directory.trusts` v1

Owner: `ad.ldap.trusts`

This capability depends on `directory.core` and the normalized default `directory.domains` identity. `Complete` guarantees local `trustedDomain` enumeration with normalized source domain, `trustPartner`, parseable direction/type/attributes and target SID when available. A local domain with no trust objects can legitimately be `Complete` with zero relationships. This capability does not contact or validate the remote side of a trust.

### `directory.acls` v1

Owner: `ad.ldap.acls`

This capability depends on complete `directory.core`, `directory.domains`, `directory.users`, `directory.groups`, `directory.computers` and `directory.ous` data. v1 covers the normalized default-domain root, user, group, computer and OU objects already present in the prerequisite snapshot.

The LDAP request asks only for the DACL section of `nTSecurityDescriptor`; SACL, owner and group sections are outside v1. `Complete` preserves security-descriptor control flags, DACL state (`NotPresent`, `Null`, `Empty`, `Present`), Allow/Deny standard ACEs, Allow/Deny object ACEs, trustee SID, access mask, ACE flags/inheritance and object/inherited-object GUIDs. Unsupported or malformed ACE semantics, missing descriptors or target inconsistencies produce `Partial`. Raw descriptor bytes are not persisted by default.

### `gpo.metadata` v1

Owner: `ad.ldap.gpo-metadata`

This capability depends on `directory.core`. It reads Group Policy Container objects from `CN=Policies,CN=System,<defaultNamingContext>` and does not read SYSVOL file contents.

`Complete` guarantees that GPO container enumeration completed and every retained GPO has:

- stable AD `objectGUID` and distinguished name;
- a parseable policy GUID from the GPC `name` value (`{GUID}`);
- a unique policy GUID within the collected default-domain policy container.

The collector also normalizes, when present:

- `displayName`;
- `gPCFileSysPath`;
- `versionNumber`;
- GPO `flags`;
- creation/change timestamps.

These values are retained as evidence facts with LDAP provenance. Optional metadata is not replaced with guessed defaults. A domain with no GPOs may legitimately produce `Complete` coverage with zero items. An unusable/duplicate GPO identity produces `Partial` coverage.

`gpo.metadata` describes directory metadata only. Policy-file contents and settings under SYSVOL belong to `gpo.sysvol`.

### `gpo.links` v1

Owner: `ad.ldap.gpo-links`

This capability depends on complete `directory.core`, `directory.domains`, `directory.ous` and `gpo.metadata` data. It enumerates the default domain root and all known OUs in one paged LDAP subtree query and reads `gPLink` plus `gPOptions`.

`Complete` guarantees that:

- every prerequisite domain/OU container was returned by link enumeration;
- each `gPLink` entry was parsed into a stable container→GPO relationship;
- link order is retained as a 1-based order matching the sequence stored in the AD `gPLink` attribute;
- raw link options are preserved together with normalized `Enabled` and `Enforced` flags (`0x1` disabled, `0x2` enforced);
- each domain/OU has normalized container policy state from `gPOptions`, including Block Inheritance (`gPOptions` bit/value `1`);
- linked GPO DNs resolve to GPO identities collected by `gpo.metadata`;
- raw options and target-DN evidence retain LDAP provenance.

Malformed link syntax, unknown linked GPOs, missing expected containers, invalid options, duplicate container results, or unsupported option bits produce `Partial` rather than silently dropping semantics.

This capability does not read policy files from SYSVOL, calculate effective/RSoP policy, or actively validate whether a policy setting took effect on an endpoint.

### `gpo.sysvol` v1

Status: planned.

### `adcs.directory` v1

Status: planned.

## Analysis compatibility

A rule declares a minimum contract, for example:

```text
directory.users >= 2
```

A snapshot with `directory.users v1 = Complete` is not sufficient for that rule. The correct result is `NotVerified`/insufficient data, not a negative finding. A snapshot with `directory.users v3 = Complete` may satisfy a rule requiring v2 because capability versions are monotonic.
