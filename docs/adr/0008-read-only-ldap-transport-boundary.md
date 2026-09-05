# ADR-0008: Read-only LDAP transport boundary

Status: Accepted

## Context

The first production-facing collection capability needs LDAP, but protocol implementation details must not leak into the domain/application layers and the snapshot-first phase must remain technically read-only. Future deployment modes will also need different authentication, TLS and credential-delivery strategies without rewriting individual collectors.

## Decision

1. `System.DirectoryServices.Protocols` is isolated in `DogfighterAD.Collectors.ActiveDirectory`. Domain and Application projects do not reference it.
2. Collectors consume a Dogfighter-owned `IReadOnlyLdapClient` abstraction. The abstraction exposes search only; it has no add, modify, delete, extended write or password-operation methods.
3. The first system adapter authenticates with the running process identity through `AuthType.Negotiate`. Usernames/passwords are not added to `CollectionContext`, snapshot models or collector configuration in this phase.
4. A later explicit-credential mode must use a dedicated credential/secret provider whose values remain outside snapshots, reports and ordinary logs. Adding that mode must not change rule or snapshot contracts.
5. LDAP v3 is required. LDAPS may be enabled by configuration, but the adapter does not install certificate-validation bypass callbacks. Trust failures remain failures.
6. Per-request timeout and caller cancellation are both supported. The S.DS.Protocols asynchronous request API is used so cancellation can abort an in-flight LDAP request rather than waiting indefinitely for a synchronous call to return.
7. LDAP paging is implemented in the transport adapter because large directories must not force every collector to reimplement paging controls.
8. Attribute values preserve binary data. Collectors decide how binary values such as object GUIDs, SIDs and security descriptors are normalized; the transport must not stringify or discard them.
9. RootDSE discovery is owned by one collector (`ad.ldap.rootdse`). Downstream collectors consume its typed `DirectoryEnvironment` from previous collection stages instead of repeating discovery requests.
10. RootDSE and other collectors produce provenance-backed observations in addition to normalized structures where those observations are useful for later evidence/offline analysis.
11. The transport does not automatically retry requests in the first implementation. Retry/backoff requires transient-error classification and query budgets before it is enabled.
12. The transport boundary is intentionally narrower than the underlying LDAP library. Future active validation/write functionality, if ever needed, belongs to the separate Validation Plane and must not expand this read-only interface.

## Consequences

- accidental target modification is harder to introduce into snapshot collectors;
- protocol/library replacement does not affect snapshot/rule contracts;
- test collectors can use an in-memory/fake `IReadOnlyLdapClient` without a live domain;
- credentials have a clear future extension point without becoming serializable application state;
- binary/security-descriptor collection remains possible;
- LDAPS security is not weakened for convenience;
- the first deployment assumes an identity that can authenticate to the target AD, while richer credential workflows are deferred deliberately.

## Follow-up

Add explicit endpoint discovery/selection, connection-security metadata, request metrics, test doubles and eventually a non-serializable credential provider. StartTLS support should be considered separately from LDAPS and must preserve certificate validation.
