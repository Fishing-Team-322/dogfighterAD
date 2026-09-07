# ADR-0005: Collection execution, failure propagation and stage isolation

Status: Accepted

## Context

Capability planning defines which collectors are required and in what dependency order they may run. Execution still needs explicit semantics for concurrency, timeouts, dependency failures and the data visible to downstream collectors. These semantics directly affect correctness: a failed dependency must never be interpreted as a clean result.

## Decision

1. Collection executes stage by stage according to the planner's DAG.
2. Every collector in one stage receives the same immutable merged state produced by all previous stages. Collectors in the same stage do not observe each other's in-flight or newly completed data. This removes scheduling-dependent behavior.
3. Independent collectors in the same stage may run concurrently, bounded by the profile's global `MaxConcurrency` value.
4. Each collector has a bounded execution timeout supplied by the collection profile.
5. A collector is not executed when one of its hard required capabilities is unavailable. Its selected capabilities receive `Blocked` coverage with a structured dependency issue.
6. A timeout or unhandled collector exception becomes `Failed` coverage for the capabilities that collector was selected to provide. Other independent collectors continue.
7. Global caller cancellation is different from collector failure: cancellation propagates immediately and aborts the scan instead of being converted into ordinary failed coverage.
8. Downstream collectors may run only when their required capabilities are `Complete` or explicitly `NotApplicable`. `Partial`, `Failed`, `Blocked`, `Unsupported` and missing coverage do not satisfy a hard dependency.
9. Collector results are contract-checked before they enter shared collection state. Collector id/version must match the registered implementation, every selected capability must have a coverage record, returned capabilities/observations must be declared by the collector and selected capabilities may not be reported as `NotRequested`.
10. The executor stamps collector identity into coverage and observation provenance so an implementation cannot accidentally emit stale identity metadata.
11. Detailed exception messages and stack traces are not persisted into snapshot coverage by default. Snapshots receive stable sanitized issue codes/messages; a later diagnostic logging subsystem may retain richer local diagnostics under separate retention/security controls.
12. There are no automatic retries in the first execution model. Retry policy requires a separate decision because repeated network/security queries may be expensive, non-idempotent at the protocol level or may distort benchmark/audit timing.

## Consequences

- partial failure does not destroy unrelated collection results;
- dependency failures propagate explicitly instead of generating false negatives;
- collector scheduling order cannot change downstream inputs;
- collection profiles can tune resource pressure without collector-specific concurrency code;
- snapshot issue data remains safer to share with reports than arbitrary exception text;
- later retry/backoff behavior can be introduced deliberately with transient-error classification and per-protocol budgets.

## Follow-up

Add structured local logging, per-endpoint request/rate budgets, retry classification, execution metrics and tests for timeout, blocked dependencies, cancellation and same-stage isolation before large-scale collectors are enabled.
