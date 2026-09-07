# ADR-0009: Core test foundation and deterministic regression gates

Status: Accepted

## Context

DogfighterAD's value depends on trustworthy collection semantics, reproducible snapshots and stable evidence identities. Waiting for a full AD lab to test every change would make regressions expensive and would encourage protocol behavior, analysis logic and environment assumptions to become coupled.

## Decision

1. Core unit/contract tests run without a live Active Directory environment.
2. The initial test project uses xUnit.net v3 on the same .NET 10 runtime baseline as production code.
3. LDAP-dependent collectors are tested through the Dogfighter-owned `IReadOnlyLdapClient` abstraction with deterministic fake responses. Unit tests do not mock `System.DirectoryServices.Protocols` directly.
4. Stable hash/fingerprint algorithms require golden vectors. A release cannot silently change a golden vector; any intended algorithm change requires a new explicit algorithm version and compatibility decision.
5. Snapshot fragment merging and final assembly require deterministic-order tests so collector completion/order cannot alter logical output.
6. Planner tests cover dependency expansion, ambiguity, cycles and invalid registries before network collection begins.
7. Executor tests cover dependency failure propagation and stage isolation. Timeout/cancellation/concurrency-budget tests are required before those behaviors are considered release-ready.
8. CI restores, builds and executes the core test project on every branch change currently used for foundation work and on pull requests.
9. Test runner telemetry is disabled in CI.
10. Live AD tests are a separate integration tier. GOAD/MINILAB must not replace unit/contract tests; they validate real protocol acquisition and environment interpretation.

## Future test tiers

- **Unit/contract:** pure rule/domain/planner/collector mapping tests using synthetic data.
- **Golden snapshot:** serialized snapshot compatibility, deterministic content and report baselines.
- **Integration clean AD:** expected low/no findings and collection completeness to detect false positives.
- **Integration vulnerable AD/GOAD:** known seeded weaknesses and relationships.
- **Hidden mutation corpus:** changes unknown to rule/collector authors to reduce overfitting to GOAD defaults.
- **Scale/performance:** synthetic and real-like object counts with memory, query and duration budgets.
- **Security:** secrets redaction, malformed LDAP/import data, untrusted snapshot/report inputs and privilege boundaries.

## Consequences

- most architectural regressions can be found without booting virtual machines;
- collector mapping can evolve while the network adapter remains independently testable;
- future GOAD results can be compared against deterministic lower-level behavior;
- adding a collector or rule carries an expectation of focused tests rather than only a successful manual run.
