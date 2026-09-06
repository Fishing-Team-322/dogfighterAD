# Collection profiles and execution telemetry

Built-in profiles are explicit product contracts. Registering a new collector/capability must not silently make an existing profile heavier. Profile expansion requires a deliberate code/documentation/test change.

## `minimal`

Purpose: lighter read-only inventory/topology collection.

Capabilities:

- `directory.core`
- `directory.domains`
- `directory.users`
- `directory.groups`
- `directory.computers`
- `directory.ous`
- `directory.memberships`
- `directory.trusts`

Defaults: `MaxConcurrency=2`, per-collector timeout 2 minutes.

It intentionally excludes DACL and all GPO collection.

## `audit-full`

Purpose: broad auditor-oriented scan over every read-only capability that is currently implemented and intentionally approved for the built-in full profile.

Capabilities:

- everything in `minimal`
- `directory.acls`
- `gpo.metadata`
- `gpo.links`
- `gpo.sysvol`

Defaults: `MaxConcurrency=4`, per-collector timeout 3 minutes.

`gpo.sysvol` was added deliberately only after its read-only contract, secret-handling rules and tests existed. This profile therefore includes filesystem/SMB-backed SYSVOL workload in addition to LDAP workload. Planned capabilities such as `adcs.directory` remain excluded until explicitly reviewed and added.

## Current guardrails

`CollectionProfile` feeds the planner/executor with requested capabilities, optional preferred provider mapping, max concurrency and per-collector cooperative timeout. Collectors that observe cancellation, including immediately after returning, become failed coverage and downstream dependencies are blocked; incomplete collection is never converted into a clean result.

The current concurrency/timeouts are engineering defaults, not benchmark-derived production limits. Blocking filesystem operations can still exceed the timeout; the executor does not terminate a stuck collector. See the [review](reviews/2026-09-06-foundation-review.md) for open SYSVOL scope and resource-boundary issues.

## Current telemetry

`CollectionTelemetry.Build(CollectionExecutionResult)` provides deterministic:

- overall duration;
- collector count;
- completed/failed/timed-out/blocked counts;
- coverage counts by `CapabilityStatus`;
- per-collector identity, duration, status and selected capabilities.

Still pending:

- native LDAP request/page counts;
- entries/bytes per request;
- per-capability query budgets;
- peak managed/process memory;
- benchmark-derived thresholds;
- persistence of executor telemetry itself into `.dogad` (the current artifact serializes `AdSnapshot`, not `CollectionTelemetry`).

## Future custom profiles

A CLI/config layer may later support include/exclude capability IDs, provider selection, concurrency, timeout and benchmark-informed budgets, but custom configuration must still compile to `CollectionProfile` and pass through normal dependency planning/coverage semantics.
