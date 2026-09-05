# ADR-0010: Portable deterministic `.dogad` artifact

Status: Accepted

Date: 2026-09-05

## Context

DogfighterAD's product model requires a collector to leave the customer's environment while preserving enough evidence for deterministic offline re-analysis by later rule packs. The portable artifact therefore needs reproducible representation, explicit compatibility axes and defensive integrity checks without coupling serialization technology to the Domain model.

## Decision

1. Implement portable artifacts in a separate `DogfighterAD.Serialization` module that depends on Domain; Domain does not depend on JSON/ZIP.
2. `.dogad v1` is a strict ZIP containing exactly `manifest.json` and canonical `snapshot.json`.
3. v1 writes entries without compression, with fixed timestamp and stable order for byte reproducibility.
4. Keep `formatVersion`, `serializationId`, snapshot schema version and capability contract versions independent.
5. `manifest.json` binds snapshot identity/schema/product metadata to payload length and SHA-256.
6. Reader enforces size limits, entry allowlist/uniqueness, supported versions, SHA-256, metadata agreement, snapshot invariants and canonical byte representation.
7. Unknown ZIP entries are rejected in v1 rather than silently accepted as attachments.
8. SHA-256 is integrity checking only. v1 does not claim cryptographic authenticity/signing.
9. The initial implementation may buffer canonical JSON in memory; benchmark before redesigning for streaming.

## Consequences

Positive:

- auditors can preserve/re-analyze one collection offline;
- same logical snapshot has a stable portable representation;
- corruption/tampering that does not also rewrite the manifest is detected;
- compatibility decisions are explicit instead of overloading one product version;
- serialization technology remains replaceable without contaminating core AD models.

Costs/limitations:

- no-compression v1 artifacts can be larger;
- current writer/reader add bounded memory pressure from the full JSON payload;
- SHA-256 does not prove who produced the artifact;
- adding attachments or new container entries requires an explicit format evolution decision.

## Future work

Measure real MINILAB/GOAD and larger-domain artifact sizes/peak memory. If authenticity is required, design signing/key management separately. If streaming becomes necessary, preserve canonical/integrity semantics through an explicit compatible implementation or new serialization identifier.
