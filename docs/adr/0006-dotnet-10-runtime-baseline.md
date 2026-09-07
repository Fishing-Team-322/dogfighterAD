# ADR-0006: .NET 10 LTS runtime baseline

Status: Accepted

## Context

The repository was initially bootstrapped on .NET 8. Development started in September 2026, while Microsoft support for .NET 8 ends in November 2026. Building a new security product on a runtime approaching end of support would force an almost immediate runtime migration and shorten the security servicing window.

## Decision

DogfighterAD targets .NET 10 LTS as its runtime baseline.

The runtime baseline is chosen for support lifetime and maintainability, not for speculative performance gains. Performance-sensitive components must still be benchmarked before considering native code or a second language.

Package versions should be pinned and kept on supported servicing lines. Preview runtimes/packages are not used for the production foundation unless a later ADR documents a specific requirement.

## Consequences

- the initial product baseline remains supported through November 2028;
- collectors can use the current .NET runtime and BCL APIs without planning an immediate .NET 8-to-10 migration;
- contributors/build agents require a .NET 10 SDK;
- deployment on systems that cannot host .NET 10 must use a self-contained build or a separately justified compatibility strategy;
- future runtime upgrades remain explicit engineering decisions rather than silent CI changes.
