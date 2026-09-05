# DogfighterAD

DogfighterAD is a snapshot-first, evidence-first Active Directory security assessment platform.

The project is being built around a strict separation between collection, normalization, analysis, evidence, storage, and reporting. The first development phase is read-only: collect security-relevant Active Directory facts into a versioned snapshot that can be analyzed and re-analyzed offline.

## Current direction

- read-only collection first;
- immutable, versioned snapshots;
- provenance and collection coverage as first-class data;
- independent rule and graph analysis over snapshots;
- deterministic findings with evidence and stable identities;
- offline re-analysis and retest/diff support;
- future validation/execution nodes remain a separate plane and are intentionally out of scope for the first phase.

Development starts in a dedicated foundation branch before the first release is merged into `main`.
