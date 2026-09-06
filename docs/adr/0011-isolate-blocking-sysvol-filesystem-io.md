# ADR 0011: Isolate blocking SYSVOL filesystem I/O in a disposable worker process

- Status: Accepted
- Date: 2026-09-06

## Context

DogfighterAD gives collectors cooperative cancellation and collector-level timeouts, but several filesystem primitives used for SYSVOL are not reliably interruptible by `CancellationToken`. In particular, recursive directory enumeration, `FileInfo` metadata access and opening a `FileStream` over SMB/DFS can block inside the operating system before managed code regains control.

A timeout implemented only as a race against a timer would let the blocked filesystem operation continue in the scanner process. That would create an untracked background operation, retain resources and potentially violate the executor's concurrency guarantees. Source-scope validation and bounded file reads solve different problems; neither establishes a hard lifetime boundary for a stalled OS/filesystem call.

## Decision

Potentially blocking SYSVOL filesystem primitives run in an internal disposable helper process, `DogfighterAD.SysvolWorker`.

The parent collector remains authoritative for assessment semantics and scope:

1. `GpoSysvolCollector` validates the GPO SYSVOL root before creating/using the worker-backed client.
2. Enumerated child paths are validated again by the parent before any file read is requested.
3. The worker receives only the already approved filesystem path needed for one enumeration or read operation. It does not own collection planning, capability semantics, normalization or findings.
4. Parent and worker communicate through a private bounded framed protocol. Enumeration entries and file bytes are bounded; worker errors are returned as generic error codes rather than raw exception text.
5. Operations are serialized per SYSVOL client. Enumeration is exposed to the collector through a bounded channel so a producer cannot create an unbounded in-process queue.
6. Each worker operation has a finite deadline. The current default is 30 seconds with a 2-second process-termination grace period.
7. On timeout or caller cancellation, the parent kills the worker process tree and waits for termination. A later operation creates a fresh worker.
8. The worker is a packaged runtime component, not a service or microservice. It has no listener, scheduler, persistent state or independent product API.

This boundary is for lifecycle isolation, not privilege isolation or sandboxing. The helper process executes under the scanner's operating-system security context; no claim is made that it is a security sandbox.

## Consequences

### Positive

- A blocked SMB/filesystem call cannot indefinitely occupy a managed collector task in the long-lived scanner process.
- Timeout/cancellation has a resource-lifecycle action: the process executing the blocking call is terminated and drained.
- The scanner can restart the helper and continue later operations after a forced termination.
- Scope policy remains in the parent collector rather than being duplicated inside a filesystem helper.
- The approach is small and local to SYSVOL rather than introducing a service fleet or new distributed architecture.

### Costs and limitations

- The worker executable must be built and deployed with a host that uses the production SYSVOL client.
- Process startup and IPC add overhead. Defaults must be validated against real lab/production-sized SYSVOL workloads before being treated as final budgets.
- Process isolation does not prove correct DFS/referral behavior, permissions or real-domain semantics. Those still require MINILAB/GOAD integration tests.
- This does not establish a total scan-time or total-byte budget; those belong to later resource telemetry/benchmark work.

## Verification

A deterministic test-only worker fixture blocks a requested synthetic path. The parent operation reaches its deadline, terminates the worker and then successfully performs a normal read through a newly started worker. The worker-backed static file-size boundary tests also exercise the packaged process path.

GitHub Actions run `34014520656` passed the resulting build and 111-test suite on both Ubuntu and Windows for commit `0e2490b3c2a0dd42f80b399c5c4de24ce57c7854`.
