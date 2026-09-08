# Capability contracts

> **0.3.2 update:** the current built-in pack is `dogfighterad.core/1.2.0` with 88 rules. AD CS directory posture is implemented through five narrow v1 contracts: `adcs.authorities`, `adcs.templates`, `adcs.publication`, `adcs.acls`, and `adcs.trust`. The older `adcs.directory` identifier is retained only for compatibility and is not requested by built-in profiles or current AD CS rules.

Capability contracts define what data a snapshot is guaranteed to contain when a coverage record is marked `Complete` for a given contract version.

This document is normative for built-in collectors. It must change together with `CapabilityContractCatalog` when a contract version changes.

## Versioning rules

- Versions are positive integers.
- Versions are monotonic: v2 preserves every guarantee of v1 and may add new guarantees.
- A collector implementation version is not a capability contract version.
- New optional data that no rule relies on does not automatically require a capability version bump.
- Increase the contract version when newer analysis needs to distinguish snapshots that guarantee new data from older snapshots that did not collect it.
- If semantics cannot stay backward-compatible, create a new capability ID.

## Attribute-read proof extension (2026-09-08)

Users/computers v2 and memberships v3 preserve prior positive observations and add optional, provenance-backed absence proofs. Complete inventory does not guarantee read access to every field. The exact proof gates and persisted proof fields are normatively defined in [RULE_ENGINE.md, Attribute absence proofs](RULE_ENGINE.md#attribute-absence-proofs-rule-pack-110). Missing proof remains unknown. Membership v3 accepts proven empty groups without inventing member edges. No snapshot schema bump is needed: all additions use existing `ObservedFact` records.

## Current built-in contracts

### `directory.core` v1

Owner: `ad.ldap.rootdse`

`Complete` guarantees that RootDSE discovery succeeded and the normalized `DirectoryEnvironment` contains at least `defaultNamingContext`, `configurationNamingContext` and `schemaNamingContext`. Available DNS host name, root domain naming context, naming contexts, supported LDAP versions, controls and capabilities are retained when present.

### `directory.domains` v1

Owner: `ad.ldap.domain-metadata`

`Complete` guarantees one normalized domain object for the discovered default naming context with stable `objectGUID`, domain `objectSid`, distinguished name, derived DNS domain name and domain functional level. Name and creation/change timestamps are collected when available. NetBIOS naming is outside v1.

### `directory.users` v2

Owner: `ad.ldap.directory-objects`

`Complete` guarantees successful default-domain user enumeration and usable stable `objectGUID`, DN, SID, parseable `userAccountControl` and `primaryGroupID` for every retained user. The collector also requests/normalizes, when present, `sAMAccountName`, UPN, `adminCount`, `pwdLastSet`, `lastLogonTimestamp`, `accountExpires`, `msDS-SupportedEncryptionTypes`, SPNs, `sIDHistory`, `msDS-AllowedToDelegateTo` and timestamps. v2 additionally permits conservative absence proofs for reviewed requested attributes; missing or contradictory proof remains unknown.

AD FileTime sentinels retain explicit meaning: `pwdLastSet=0` becomes `PasswordMustChangeAtNextLogon=true`; `accountExpires=0` or `Int64.MaxValue` becomes `AccountNeverExpires=true`. Raw values remain evidence facts.

### `directory.groups` v1

Owner: `ad.ldap.directory-objects`

`Complete` guarantees successful default-domain group enumeration and stable GUID/DN/SID identity plus parseable `groupType`. `sAMAccountName`, `adminCount`, name and timestamps are retained when present. Membership is a separate capability.

### `directory.computers` v2

Owner: `ad.ldap.directory-objects`

`Complete` guarantees successful default-domain computer enumeration and stable GUID/DN/SID identity plus parseable `userAccountControl`. Host/OS metadata, password/logon timestamps, encryption types, SPNs and constrained-delegation targets are retained when present. v2 follows the same conservative reviewed-attribute absence-proof model as users.

### `directory.ous` v1

Owner: `ad.ldap.directory-objects`

`Complete` guarantees successful default-domain OU enumeration and stable GUID/DN identity. Name and timestamps are retained when present. ACL-derived protection semantics are intentionally outside this capability.

### `directory.memberships` v3

Owner: `ad.ldap.group-memberships`

Depends on complete `directory.core`, `directory.users`, `directory.groups` and `directory.computers` data.

`Complete` guarantees direct `member` relationships, full AD ranged-member retrieval through terminal ranges, direct group-to-group edges, reconstructed primary-group edges, stable member identity resolution, supporting FSP/generic objects when required, and source observations. v2 added per-group `group.memberReadComplete` / `group.observedMemberCount` boundaries. v3 permits a missing `member` attribute to certify an empty direct-member set only when the reviewed absence proof is present and coherent. Transitive membership is deliberately not precomputed. Incomplete ranges, unresolved identities or invalid absence proof produce incomplete/unknown analysis rather than a negative membership assertion.

### `directory.trusts` v1

Owner: `ad.ldap.trusts`

Depends on `directory.core` and `directory.domains`. `Complete` guarantees local `trustedDomain` enumeration with normalized source domain, `trustPartner`, parseable direction/type/attributes and target SID when available. Zero trusts can legitimately be complete. The remote side is not contacted or validated.

### `directory.acls` v3

Owner: `ad.ldap.acls`

Depends on complete core/domain/users/groups/computers/OUs data. The collector requests only the DACL section of `nTSecurityDescriptor` for the normalized default-domain root, users, groups, computers and OUs.

`Complete` preserves descriptor control flags; DACL state (`NotPresent`, `Null`, `Empty`, `Present`); Allow/Deny standard ACEs; Allow/Deny object ACEs; trustee SID; access mask; ACE flags/inheritance; and object/inherited-object GUIDs. v3 additionally guarantees explicit descriptor parse-completeness/ACE-count operands and object-type presence operands used by offline ACL rules. Unsupported/malformed ACE semantics, missing descriptors or target inconsistencies produce `Partial`. Raw descriptor bytes are not persisted by default.

### `gpo.metadata` v1

Owner: `ad.ldap.gpo-metadata`

Depends on `directory.core`. Reads Group Policy Container objects from `CN=Policies,CN=System,<defaultNamingContext>`.

`Complete` guarantees successful GPC enumeration and stable AD `objectGUID`/DN plus a parseable unique policy GUID from the GPC `name`. `displayName`, `gPCFileSysPath`, `versionNumber`, GPO flags and timestamps are retained when present. A domain with no GPOs may be complete with zero items.

### `gpo.links` v1

Owner: `ad.ldap.gpo-links`

Depends on complete `directory.core`, `directory.domains`, `directory.ous` and `gpo.metadata`.

`Complete` guarantees every prerequisite domain/OU container was returned by link enumeration; each `gPLink` entry was normalized into a stable container→GPO edge; link order follows AD sequence; raw link options plus normalized `Enabled`/`Enforced` are retained; `gPOptions` plus normalized Block Inheritance are retained; linked GPO DNs resolve to collected GPO identities; and source evidence retains LDAP provenance. Malformed syntax, unknown targets, missing containers, invalid/unsupported options or duplicate container results produce `Partial`. This capability does not calculate RSoP/effective policy.

### `gpo.sysvol` v3

Owner: `ad.sysvol.gpo-settings`

Depends on complete `gpo.metadata`. It is a strictly read-only Group Policy Template collector using each GPO's `gPCFileSysPath`.

`Complete` preserves bounded file inventory/hashes and reviewed normalization for `GPT.INI`, `GptTmpl.inf`, Registry.pol and Preferences XML. Later contract versions add evidence required by the current Rule Engine, including original registry value type, reviewed security-template registry normalization, and explicit safe GPP `cpassword` presence/absence semantics. Secret values are not persisted. A missing/unreadable GPO path, denied access, configured budget hit, malformed supported policy file or unsupported required semantic makes coverage incomplete; such data is never silently treated as absent/safe.

This capability does **not** promise semantic parsing of every Group Policy extension, compute effective/RSoP policy, validate endpoint application, modify SYSVOL, or collect arbitrary file contents as a generic text archive.

## AD CS 0.3.2 directory contracts

Owner for all five contracts: `ad.ldap.adcs` collector version `0.3.2`.

The collector reads only `CN=Public Key Services,CN=Services,<configurationNamingContext>` using LDAP and a DACL-only security-descriptor request. It does **not** contact CA RPC endpoints, CA registry, HTTP(S)/web enrollment, certificate enrollment services, or any other runtime surface. If no Enterprise CA (`pKIEnrollmentService`) is found after a successful search, all five capabilities are `NotApplicable` rather than a clean runtime-CA verdict.

### `adcs.authorities` v1

`Complete` guarantees stable Enterprise CA directory identities (`objectGUID`/DN), available `cn`/DNS host metadata and parsed `cACertificate` metadata/fingerprints for collected `pKIEnrollmentService` objects. Publication names are collected but normalized CA↔template edges belong to `adcs.publication`.

### `adcs.templates` v1

`Complete` guarantees stable certificate-template identities and the reviewed directory operands used by current rules/UI: common/display name, template OID/schema/minor version when present, EKUs, application policies, `msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`, `msPKI-Private-Key-Flag`, `msPKI-RA-Signature`, validity period and overlap period. Missing or malformed required security operands produce collection issues/incomplete coverage; they are not converted to zero/defaults.

### `adcs.publication` v1

`Complete` guarantees normalized Enterprise CA → certificate-template publication relationships derived from `certificateTemplates`, with stable CA/template IDs and provenance-backed `template.publishedOnCa` evidence. Unresolvable published template names make the capability incomplete rather than silently dropping the edge.

### `adcs.acls` v1

`Complete` guarantees DACL state plus a fully parsed, ordered set of supported direct ACEs for collected Enterprise CA and certificate-template directory objects, including trustee SID, access type/mask, ACE flags, inheritance and object/inherited-object GUIDs where present. Current rules use this evidence for conservative Enrollment/AutoEnrollment and dangerous-directory-control candidates. Deny precedence and full Windows token/effective-access calculation are **not** claimed.

### `adcs.trust` v1

`Complete` guarantees the directory posture of `CN=NTAuthCertificates` when present and parsed certificate metadata/fingerprints for its `cACertificate` values. This is directory trust-store evidence only; it does not prove endpoint certificate-chain behavior or live authentication acceptance.

### Legacy `adcs.directory` v1

This identifier is retained in `CapabilityContractCatalog` so older custom profiles/code can deserialize/refer to the pre-0.3.2 placeholder. Built-in profiles and the current AD CS rule pack do not request it. New functionality must use the narrow contracts above or introduce separate future runtime capability IDs.

## Analysis compatibility

A rule declares a minimum capability contract, for example `directory.users >= 2`. A snapshot with `directory.users v1 = Complete` is insufficient for that rule and must result in `NotVerified`/insufficient data, not a negative finding. A snapshot with v3 may satisfy a rule requiring v2 because versions are monotonic.

AD CS runtime-dependent checks must require their own future capability IDs. Directory evidence from `adcs.*` v1 cannot be reinterpreted as proof of CA registry/RPC/web-enrollment/EPA/NTLM/issuance behavior.
