# ADR-0004: Capability-driven collection planning

Status: Accepted

## Context

DogfighterAD is expected to grow from LDAP directory collection into GPO/SYSVOL, ADCS, host and later imported/external evidence. A single collector that always gathers everything would become hard to test, hard to privilege-minimize and impossible to tune for different audit profiles.

## Decision

1. Collectors declare stable `ProvidesCapabilities` and `RequiresCapabilities` sets.
2. A collection profile requests capabilities, not concrete implementation classes.
3. A `CollectionPlanner` resolves required capabilities to collectors before any collection begins.
4. Collector dependencies form a directed acyclic graph. The planner topologically groups collectors into stages; collectors in the same stage may later execute concurrently within a configured budget.
5. Missing providers, cycles and invalid collector registrations are planning errors and must fail before touching the target environment.
6. If more than one collector provides the same capability, DogfighterAD does not choose one by hidden priority or registration order. The profile must explicitly select a preferred provider for that capability.
7. Capability dependencies are included in the effective collection plan even when they were not directly requested by the user.
8. The plan carries execution policy such as maximum concurrency and collector timeout, but collectors themselves do not decide global concurrency.
9. A collector should own a well-defined normalized output surface. It must not silently duplicate normalized objects owned by another selected collector; cross-cutting enrichment should prefer observations until an explicit merge policy exists.
10. Capability names are compatibility surface. New collectors may replace implementations without changing rule requirements when they provide semantically equivalent capability contracts.

## Why this matters

A future `audit-full` profile may request users, groups, ACLs, trusts, GPO/SYSVOL and ADCS. A lighter company profile may request only low-impact directory and policy capabilities. Both use the same core engine while the planner selects the minimum collector graph required for the requested profile.

This also creates a clean boundary for future privilege-aware planning: capabilities can later advertise required privileges, protocols, network reachability and safety/resource cost without changing rule code.

## Consequences

- the first LDAP implementation can be split into focused collectors instead of becoming a permanent monolith;
- collection can become incremental and profile-driven later;
- concurrency is controlled centrally;
- alternate/import collectors can coexist safely when provider choice is explicit;
- plan construction can be unit-tested without a live domain;
- future execution/validation nodes can reuse the capability-planning concept without sharing collection implementations.

## Follow-up

Before production collection, define execution semantics for cancellation, retries, per-target rate limits, transient vs permanent failures and capability coverage propagation from collector results.
