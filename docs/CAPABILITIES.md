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

Status: planned.

The exact v1 guarantees will be fixed before the collector is merged. The current domain model already reserves common security-relevant fields such as UAC, `adminCount`, password/logon timestamps, SPNs, SID history, encryption types and delegation targets.

### `directory.groups` v1

Status: planned.

### `directory.computers` v1

Status: planned.

### `directory.ous` v1

Status: planned.

### `directory.memberships` v1

Status: planned. This capability will preserve explicit and primary-group membership as relationships rather than only materializing flattened group membership.

### `directory.acls` v1

Status: planned. This capability will preserve raw security-relevant ACE semantics required for later rights/path analysis, including object type and inherited object type GUIDs.

### `directory.trusts` v1

Status: planned.

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
