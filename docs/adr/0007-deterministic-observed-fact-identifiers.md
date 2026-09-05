# ADR-0007: Deterministic observed-fact identifiers

Status: Accepted

## Context

Observed facts are the evidence/provenance layer beneath findings. If collectors invent identifiers independently or include transient values such as task order or collector version, the same fact cannot be referenced reliably by later rule packs, diff logic or imported reports.

## Decision

DogfighterAD uses a centralized, versioned `FactIdFactory`.

A fact id is a SHA-256 digest over a length-prefixed canonical sequence containing:

1. fact-id algorithm version;
2. capability id;
3. stable subject id;
4. fact path;
5. value kind;
6. normalized stored value (or an empty value for redacted/metadata-only facts).

Collector id/version and observation timestamp are deliberately excluded. They are provenance, not identity of the observed fact.

The textual id is prefixed with `fact:v<version>:` so a future normalization/hash change can coexist with historical snapshots.

## Consequences

- identical logical observations can retain stable references across scans and collector updates when their canonical representation is unchanged;
- evidence may point to facts without coupling to a particular collector release;
- changing value normalization is a compatibility event and requires a new fact-id algorithm version;
- collectors must use shared fact-id generation instead of ad-hoc GUIDs/random ids;
- secret/redacted values must not be fed into the id factory merely to make an id stable. Metadata-only identity must use non-secret canonical inputs.

## Follow-up

Define canonical subject-id helpers for AD object GUIDs, SIDs, hosts and imported sources, and add golden vectors so the fact-id algorithm cannot change accidentally.
