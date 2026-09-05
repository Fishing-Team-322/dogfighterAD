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

`Complete` guarantees one normalized domain object for the discovered default naming context with:

- stable `objectGUID`;
- domain `objectSid`;
- distinguished name;
- derived DNS domain name;
- domain functional level.

Name and creation/change timestamps are collected when available. NetBIOS domain naming is intentionally not part of v1 because it requires configuration-partition cross-reference collection.

### `directory.users` v1

Owner: `ad.ldap.directory-objects`

`Complete` guarantees that the requested default-domain subtree enumeration for user objects completed and every retained user has a usable stable `objectGUID`, distinguished name, `objectSid`, parseable `userAccountControl` and `primaryGroupID`.

The collector requests and normalizes, when present:

- `sAMAccountName`, `userPrincipalName`;
- `adminCount`;
- `pwdLastSet`, `lastLogonTimestamp`, `accountExpires`;
- `msDS-SupportedEncryptionTypes`;
- `servicePrincipalName`;
- `sIDHistory`;
- `msDS-AllowedToDelegateTo`;
- object creation/change timestamps.

Special AD FileTime values are not silently discarded. `pwdLastSet=0` is normalized as `PasswordMustChangeAtNextLogon=true`; `accountExpires=0` or `Int64.MaxValue` is normalized as `AccountNeverExpires=true`. Raw LDAP integer values remain available as observed facts for evidence/re-analysis.

### `directory.groups` v1

Owner: `ad.ldap.directory-objects`

`Complete` guarantees successful default-domain group enumeration and stable GUID/DN/SID identity for retained groups plus a parseable `groupType`. `sAMAccountName`, `adminCount`, name and timestamps are collected when present.

Membership is intentionally **not** part of this capability; it belongs to `directory.memberships` so large/ranged `member` attributes can have their own collection logic and coverage.

### `directory.computers` v1

Owner: `ad.ldap.directory-objects`

`Complete` guarantees successful default-domain computer enumeration and stable GUID/DN/SID identity plus parseable `userAccountControl` for retained computers.

The collector requests and normalizes, when present:

- `sAMAccountName`, `dNSHostName`;
- operating system/version;
- `pwdLastSet`, `lastLogonTimestamp`;
- `msDS-SupportedEncryptionTypes`;
- `servicePrincipalName`;
- `msDS-AllowedToDelegateTo`;
- name and creation/change timestamps.

### `directory.ous` v1

Owner: `ad.ldap.directory-objects`

`Complete` guarantees successful default-domain OU enumeration and stable GUID/distinguished-name identity for retained OUs. Name and creation/change timestamps are collected when present.

`ProtectFromAccidentalDeletion` is intentionally not guaranteed by v1 because reliable evaluation belongs with security-descriptor/ACL collection rather than a guessed standalone value.

### `directory.memberships` v1

Owner: `ad.ldap.group-memberships`

This capability depends on complete `directory.core`, `directory.users`, `directory.groups` and `directory.computers` data. A downstream membership scan is blocked rather than treated as clean when those prerequisites are unavailable.

`Complete` guarantees that:

- direct `member` relationships were enumerated for the default domain's groups;
- Active Directory ranged `member;range=start-end` responses were followed until a terminal range was reached;
- direct group-to-group relationships are preserved as edges, so nested membership can be evaluated later without flattening source evidence;
- `primaryGroupID` relationships observed for principals are reconstructed against the corresponding group SID and stored as `MembershipSource.PrimaryGroup` edges;
- direct member DNs are resolved to stable snapshot object identities;
- foreign security principals and other otherwise-unmodeled directory objects needed to keep membership references resolvable are materialized as supporting snapshot objects;
- source observations retain direct member DNs and primary-group values with LDAP provenance.

The collector deliberately does **not** precompute transitive group membership. Analysis code should traverse the direct group-to-group graph when transitive membership is required. This keeps the snapshot evidence-oriented and prevents multiplicative relationship expansion during collection.

An incomplete AD member range, an unresolved member DN, an unusable supporting identity, a missing referenced group, or a primary group that cannot be resolved prevents `Complete` coverage and produces `Partial`/failure evidence instead of a misleading clean result.

### `directory.trusts` v1

Owner: `ad.ldap.trusts`

This capability depends on `directory.core` and the normalized default `directory.domains` identity.

`Complete` guarantees that the local default-domain LDAP query for `trustedDomain` objects completed and every retained trust relationship has:

- the normalized source domain DNS name;
- `trustPartner` as the target domain/partner identity;
- parseable `trustDirection`;
- parseable `trustType`;
- parseable `trustAttributes`.

The trusted-domain `securityIdentifier` is normalized to a SID when it is available. Evidence also retains local trust-object metadata such as `objectGUID`, `flatName`, timestamps and raw trust integer values when returned by LDAP.

A local domain with no `trustedDomain` objects may legitimately produce `Complete` coverage with zero trust relationships. Missing/invalid required trust fields produce `Partial` coverage rather than silently substituting zero/default semantics.

This capability describes **configured local trust objects only**. It does not contact the remote domain, validate that the remote side is reachable, authenticate across the trust, or prove that a configured trust is operational. Those would require separate data/validation contracts.

### `directory.acls` v1

Owner: `ad.ldap.acls`

This capability depends on complete `directory.core`, `directory.domains`, `directory.users`, `directory.groups`, `directory.computers` and `directory.ous` data. v1 covers the normalized default-domain root, user, group, computer and OU objects already present in the prerequisite snapshot.

The LDAP request explicitly asks only for the DACL section of `nTSecurityDescriptor`. It does not request SACL data and does not require SACL-reading privileges. Owner/group sections are also outside the v1 contract.

`Complete` guarantees that every expected v1 target returned a usable DACL security descriptor and that DogfighterAD preserved:

- security-descriptor control flags;
- DACL state as `NotPresent`, `Null`, `Empty` or `Present` so zero ACEs cannot erase important authorization semantics;
- Allow and Deny standard ACEs;
- Allow and Deny object ACEs;
- trustee SID;
- raw access mask;
- ACE flags and inherited status;
- `ObjectType` GUID when present;
- `InheritedObjectType` GUID when present;
- evidence facts tied back to the target object and LDAP source.

v1 fully normalizes ACE types `ACCESS_ALLOWED_ACE`, `ACCESS_DENIED_ACE`, `ACCESS_ALLOWED_OBJECT_ACE` and `ACCESS_DENIED_OBJECT_ACE`. If a descriptor contains an unsupported ACE type, malformed SID/GUID layout, invalid bounds, a missing descriptor, an unexpected target or an expected target omitted by LDAP, coverage becomes `Partial` instead of silently dropping security semantics.

The full raw binary security descriptor is not persisted as a fact by default; normalized descriptor state and ACE evidence are retained instead.

### `gpo.metadata` v1

Status: planned.

### `gpo.links` v1

Status: planned.

### `gpo.sysvol` v1

Status: planned.

### `adcs.directory` v1

Status: planned.

## Analysis compatibility

A rule declares a minimum contract, for example:

```text
directory.users >= 2
```

A snapshot with `directory.users v1 = Complete` is not sufficient for that rule. The correct result is `NotVerified`/insufficient data, not a negative finding.

A snapshot with `directory.users v3 = Complete` may satisfy a rule requiring v2 because capability versions are monotonic.
