# ADR-0003: Version capability data contracts independently from collector versions

Status: Accepted

## Context

DogfighterAD is designed to support offline re-analysis of historical snapshots with newer rule packs.

A simple capability state such as `directory.users = Complete` is not sufficient. A future collector may guarantee additional fields that older snapshots did not contain. Without a persisted data-contract version, a new rule could incorrectly treat an old snapshot as complete for data that was never collected and produce a false negative.

Collector implementation versions cannot solve this problem because collector code may change without changing the shape or guarantees of the data it produces.

## Decision

Every persisted `CapabilityCoverage` includes an integer `ContractVersion`.

Rules declare `CapabilityRequirement` values with a minimum contract version.

A rule may evaluate only when:

1. the required capability ID is present;
2. coverage status is complete or explicitly not applicable where that semantic is valid;
3. the persisted capability contract version is at least the rule's minimum version.

If those conditions are not met, analysis must not interpret absence of a finding as proof that the environment is safe.

Built-in current contract versions are recorded in `CapabilityContractCatalog`.

## Versioning policy

Capability contract versions are monotonic.

Version N+1 must preserve the guarantees of version N. This allows a rule requiring v1 to operate on a v2 snapshot.

If a future data model changes semantics in a way that cannot preserve old guarantees, a new capability ID must be introduced instead of reusing the existing ID with incompatible meaning.

## Example

A snapshot collected in 2026 may contain:

```text
directory.users contract v1 = Complete
```

A rule introduced later may require:

```text
directory.users >= v2
```

That rule must report itself as not verifiable against the old snapshot rather than returning a clean result.

## Consequences

### Positive

- offline re-analysis can distinguish old-but-complete data from sufficiently rich data;
- new rules can safely specify their data prerequisites;
- collector refactoring does not unnecessarily invalidate snapshots;
- false negatives caused by historical schema gaps are reduced.

### Cost

- capability contracts need deliberate version management;
- rule authors must declare minimum versions;
- snapshot importers and future plugins must preserve capability-version provenance.
