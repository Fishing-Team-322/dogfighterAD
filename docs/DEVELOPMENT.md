# Development guide

This guide exists to keep DogfighterAD extensible as the number of collectors, frontends and rules grows.

## Before adding code

Ask which layer owns the behavior:

- protocol/network collection -> `DogfighterAD.Collectors.*`;
- orchestration/planning -> `DogfighterAD.Application`;
- canonical assessment data -> `DogfighterAD.Domain`;
- portable artifact encoding/validation -> `DogfighterAD.Serialization`;
- process composition/console UX -> `DogfighterAD.Cli`;
- reporting/storage/UI -> separate modules later.

Do not bypass these boundaries for convenience.

## Adding a collector

A collector must:

1. have a stable collector `Id` and implementation `Version`;
2. declare provided and required capability IDs;
3. perform read-only collection during the snapshot-first phase;
4. consume upstream data through `CollectionContext.AvailableData` rather than re-running discovery unnecessarily;
5. return normalized `SnapshotFragment` data, not protocol-specific objects;
6. return one coverage record for every selected capability;
7. distinguish `Complete`, `Partial`, `Failed`, `Blocked`, `Unsupported` and `NotApplicable` correctly;
8. attach provenance to observed facts;
9. avoid persisting secrets that are not required for assessment;
10. support cancellation and respect collection timeouts;
11. have unit tests for mapping and contract behavior;
12. update `docs/ROADMAP.md` when implementation status changes.

### LDAP query shape

Small bounded lookups such as RootDSE or a single base object may use `SearchAsync`.

Large `Subtree`/paged scans should use `SearchEntriesAsync` so the production LDAP client can release each LDAP page instead of accumulating the complete server result before mapping begins. Do not convert a streaming search back into a giant intermediate list unless the algorithm genuinely requires the entire set at once.

Collectors may still build normalized snapshot collections in memory during the current foundation phase. Snapshot assembly/storage will later be benchmarked separately; the transport layer must not add a second avoidable full-result buffer.

### SYSVOL filesystem lifetime boundary

Production SYSVOL collection has two separate safety boundaries and both must remain intact:

1. The parent collector validates the approved GPO root/authority and validates every enumerated child before asking for file content. Scope policy belongs in `DogfighterAD.Collectors.ActiveDirectory`, not in the helper process.
2. Filesystem primitives that may block in SMB/DFS/OS code execute in `DogfighterAD.SysvolWorker`, a disposable helper process. Do not move recursive enumeration, `FileInfo` access or file opening back into the long-lived scanner process merely to reduce IPC/process overhead.

`DogfighterAD.SysvolWorker` is an internal runtime component, not a microservice and not a security sandbox. It should contain filesystem mechanics only. It must not acquire planning, capability, normalization, finding or report responsibilities.

The parent/worker protocol should remain private, bounded and diagnostic-safe: bounded frame sizes, bounded file content, generic error codes, no raw filesystem exception/source text crossing into persisted collection issues. On timeout or caller cancellation the parent terminates the worker process tree and waits for cleanup before releasing the operation slot. A later operation may start a fresh worker.

Hosts using `SystemSysvolClientFactory` must deploy `DogfighterAD.SysvolWorker` beside the host executable or explicitly supply the worker executable path. The CLI/test projects build and copy the worker so the process boundary is exercised on Windows and Linux. See ADR `0011-isolate-blocking-sysvol-filesystem-io.md`.

### Capability contract versions

When a collector adds data that existing rules do not depend on, the capability version can normally remain unchanged.

Increment the capability contract version when a newer rule needs to distinguish snapshots that contain a newly guaranteed field/relationship from older snapshots that did not collect it.

A version increase must preserve older guarantees. If semantics are incompatible, create a new capability ID.

Never use collector version as a substitute for capability contract version: collectors can be refactored without changing the data contract.

## CLI / composition rules

`DogfighterAD.Cli` is intentionally thin. It may:

- parse process arguments;
- choose stable built-in collection profiles;
- configure production collector factories/transports;
- invoke planner/executor/snapshot assembly/serialization;
- control Ctrl+C cancellation and process exit codes;
- print bounded metadata/coverage summaries;
- open an existing `.dogad` for offline inspection.

It must **not**:

- contain AD detection semantics or duplicate a collector parser;
- make direct LDAP/SYSVOL queries that bypass collectors;
- reinterpret `Partial`/`Failed` as success;
- accept passwords/credential material in command-line arguments;
- print raw source payloads or credentials in the default exception path;
- mutate the canonical snapshot after assembly.

`scan` currently commits an artifact using `temporary write -> strict Dogad readback -> identity/status check -> final replace`. Preserve that property when adding future output options: the requested final filename should not intentionally contain a half-written or unreadable `.dogad` after a failed/canceled scan.

`inspect` is deliberately offline and is **not** a placeholder for rule semantics. The future `analyze` command should call Analysis Core over a snapshot; do not grow `inspect` into an ad-hoc rule engine.

Current LDAP production composition uses Negotiate/current OS security context. If an explicit credential workflow is later required, design a secure input/provider abstraction; do not add `--password` or persist a credential into logs/config/snapshot.

See `CLI.md` and `MINILAB_RUNBOOK.md`.

## Adding a rule

The rule engine is not implemented yet, but the intended contract is already fixed:

- rules receive a snapshot, never LDAP/network clients;
- rule IDs are stable;
- rule versions change independently from product versions;
- required capabilities include minimum contract versions;
- unavailable/old/partial data produces `NotVerified`, not a clean result;
- findings reference evidence/facts;
- deterministic input should produce deterministic logical output.

A rule should be testable using a synthetic snapshot with no live domain.

## Evidence and facts

Keep these concepts separate:

- **Fact**: something observed from a source.
- **Finding**: an analytical conclusion derived from facts.
- **Potential path**: a calculated relationship/path that may enable abuse.
- **Validated condition/path**: a future active validation result.

Do not label a calculated possibility as actively confirmed.

## Testing expectations

For every new foundation behavior, prefer tests before broad feature expansion.

Current CI builds with warnings treated as errors and runs the core test suite on Windows and Linux/.NET 10. Use the executable test command documented in the [foundation review](reviews/2026-09-06-foundation-review.md). Protocol behavior that requires Windows or a real AD still needs dedicated live integration evidence.

The SYSVOL worker regression layer intentionally includes a deterministic blocked-operation fixture. It proves timeout -> worker termination -> subsequent worker restart without requiring a real stalled SMB server. This does not replace live DFS/referral/inaccessible-share tests.

The CLI regression layer includes a no-network synthetic end-to-end test through planner -> executor -> snapshot assembly -> `.dogad` write -> strict readback and tests argument/exit-code behavior. This proves composition, not live AD mapping correctness.

Planned/current test layers:

- unit tests for mappings/contracts/CLI behavior;
- synthetic collection/artifact round trips;
- golden snapshot/report tests;
- synthetic large snapshots for performance;
- clean-domain integration tests;
- GOAD/MINILAB integration tests;
- hidden mutations planted by another tester;
- false-positive regression corpus;
- resource/query-budget benchmarks.

Live runs should create a dated record under `docs/lab-runs/` using `TEMPLATE.md`; do not commit real/customer `.dogad` artifacts.

## Documentation rule

A change is not considered complete when it materially changes architecture, capability semantics, security boundaries, process UX or roadmap status unless documentation is updated in the same branch.

Use an ADR under `docs/adr/` for decisions that would be expensive to reverse later.
