# Collection profiles and execution telemetry

This document defines the built-in DogfighterAD collection profiles and the current operational guardrails around collection execution.

Profiles are intentionally explicit. Adding a new capability or collector must not silently make an existing built-in profile heavier. A profile changes only through a deliberate code/documentation change with tests.

## `minimal`

Purpose: a lighter read-only inventory/topology pass suitable for quick AD discovery and for environments where DACL/GPO collection is intentionally deferred.

Requested capabilities:

- `directory.core`
- `directory.domains`
- `directory.users`
- `directory.groups`
- `directory.computers`
- `directory.ous`
- `directory.memberships`
- `directory.trusts`

Execution defaults:

- `MaxConcurrency = 2`
- per-collector timeout = 2 minutes

The profile intentionally excludes `directory.acls`, `gpo.metadata`, `gpo.links`, planned `gpo.sysvol` and planned AD CS collection.

## `audit-full`

Purpose: the broad built-in auditor-oriented scan over every read-only capability that is currently implemented and tested.

Requested capabilities:

- everything in `minimal`
- `directory.acls`
- `gpo.metadata`
- `gpo.links`

Execution defaults:

- `MaxConcurrency = 4`
- per-collector timeout = 3 minutes

Planned capabilities are not added automatically. For example, `gpo.sysvol` and `adcs.directory` remain excluded until their contracts, collectors and tests actually exist and `audit-full` is deliberately revised.

## Why profiles are explicit

Collector registration is an implementation detail. Profile semantics must remain reproducible across versions.

Without explicit capability sets, adding a new collector could unexpectedly increase LDAP traffic, permissions required, runtime or collected data for an old command. DogfighterAD avoids that behavior: a built-in profile is a reviewed product contract, not `all currently registered collectors`.

## Current execution guardrails

`CollectionProfile` already feeds `CollectionPlanner` / `CollectionExecutor` with:

- maximum collector concurrency;
- per-collector hard timeout;
- requested capability set;
- optional preferred collector mapping for ambiguous providers.

A timed-out collector produces failed capability coverage. Downstream collectors depending on unavailable capability coverage are blocked rather than executed against incomplete prerequisites.

The default concurrency/timeout values are conservative engineering defaults. They are **not** yet benchmark-derived production limits and should be tuned only after MINILAB/GOAD and larger-directory measurements exist.

## Current execution telemetry

`CollectionTelemetry.Build(CollectionExecutionResult)` produces a deterministic summary containing:

- overall scan duration;
- collector count;
- completed / failed / timed-out / blocked collector counts;
- capability coverage counts by `CapabilityStatus`;
- per-collector duration, status and selected capabilities.

Collector telemetry is sorted by stable collector identity so presentation does not depend on the timing/order of concurrent task completion.

Telemetry is observational. It must never reinterpret incomplete collection as a clean security result.

## Not implemented yet

The following are deliberately still open work:

- native LDAP request count;
- paged-request/page count;
- entries/bytes transferred per LDAP request;
- per-capability query budgets;
- peak managed/process memory telemetry;
- benchmark-derived warning/error thresholds;
- persistence of scan telemetry in the portable `.dogad` artifact.

These should be added as instrumentation layers rather than by coupling rule logic to protocol clients.

## Future custom profiles

A later CLI/config layer may permit custom profiles, but custom profiles should still compile into the same `CollectionProfile` contract and pass through `CollectionPlanner` validation.

Expected future options include:

- include/exclude capability IDs;
- preferred collector provider;
- concurrency;
- collector timeout;
- benchmark-informed resource/query budgets.

Custom configuration must not bypass dependency planning or coverage semantics.
