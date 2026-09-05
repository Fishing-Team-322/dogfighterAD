# `.dogad` portable snapshot format

`.dogad` is the portable offline audit artifact for DogfighterAD snapshots. It is implemented by `DogfighterAD.Serialization`, which depends on the Domain model but keeps ZIP/JSON concerns outside `DogfighterAD.Domain`.

## Version 1 identifiers

- artifact type: `dogfighterad.snapshot`
- container format version: `1`
- serialization ID: `canonical-json-v1`
- snapshot schema version: stored independently as `snapshotSchemaVersion`

These versions have different responsibilities:

- change `.dogad` container/layout semantics -> bump `formatVersion`;
- change canonical JSON representation -> introduce a new `serializationId` and, when required, a new container version;
- change normalized snapshot data schema -> bump snapshot schema version;
- change guarantees of collected data -> bump the relevant capability `ContractVersion`.

## Container layout

v1 is a strict ZIP archive with exactly two entries:

```text
manifest.json
snapshot.json
```

Unexpected entries are rejected. v1 deliberately does not allow arbitrary attachments because an audit artifact should not become an uncontrolled place to hide unrelated or sensitive data. Future extensions require an explicit format decision.

Entries are currently written with no ZIP compression, a fixed ZIP timestamp (`1980-01-01T00:00:00Z`) and stable ordering to make artifacts byte-for-byte reproducible for the same logical snapshot.

## Manifest

`manifest.json` contains:

- `artifactType`
- `formatVersion`
- `serializationId`
- `snapshotSchemaVersion`
- `snapshotId`
- `productVersion`
- `snapshotCompletedAt`
- `payloadPath`
- `payloadLength`
- `payloadSha256`

The payload path in v1 must be `snapshot.json`.

## Canonical snapshot JSON

`snapshot.json` uses compact camelCase JSON and string enum names. Before serialization, snapshot collections and nested security-relevant arrays are canonically ordered, including object lists, SPNs/delegation arrays, memberships, GPO relations/files/settings, trusts, descriptors/ACEs, coverage/issues/collectors and observations.

The writer test suite verifies that logically equivalent snapshots with deliberately reversed collection order produce the same `.dogad` bytes. A read→write round trip must also be byte-for-byte stable.

## Integrity and reader validation

The v1 reader validates, in order where applicable:

- strict container entry allowlist and uniqueness;
- manifest size and snapshot size limits;
- supported artifact/container/serialization/schema identifiers;
- payload path and declared length;
- SHA-256 of the exact `snapshot.json` bytes;
- manifest snapshot identity/schema/product metadata against the payload;
- snapshot domain invariants;
- byte-for-byte equality with the expected `canonical-json-v1` representation.

Default read limits are 1 MiB for the manifest and 512 MiB for the snapshot payload. Limits exist as defensive parsing boundaries and can be configured explicitly.

Tests include same-length payload tampering that reaches and fails the SHA-256 check, unsupported format versions and rejection of unexpected ZIP entries.

## Integrity is not authenticity

`payloadSha256` detects corruption or accidental/unsynchronized modification. It is **not a digital signature**. An attacker who can rewrite both `snapshot.json` and `manifest.json` can recompute SHA-256.

If signed/customer-verifiable artifacts become a product requirement, signing must be added as a separate authenticity design with key management, signature scope, rotation and verification policy; do not misrepresent the v1 hash as a signature.

## Current performance limitation

The current v1 writer serializes canonical `snapshot.json` to an in-memory byte array before hashing/writing, and the reader buffers the bounded snapshot payload before verification/deserialization. This keeps determinism/integrity simple while the data model is stabilizing, but large-domain benchmarks must measure peak memory. If this becomes material, a later implementation may use deterministic streaming or staged files without changing semantic guarantees casually.

## Security/data boundary

`.dogad` contains the normalized `AdSnapshot`: content, coverage and observations already admitted by collectors. It is not a raw file dump. SYSVOL collector secret-handling/redaction rules apply before data reaches the artifact. Executor-only `CollectionTelemetry` is not yet persisted in v1 unless represented in the snapshot model itself.
