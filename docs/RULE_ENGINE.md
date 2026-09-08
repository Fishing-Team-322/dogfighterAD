# Offline Rule Engine — version 0.2.0

## Scope

The engine evaluates a validated `.dogad` snapshot without connecting to LDAP, SYSVOL, an endpoint, a domain controller or an external rule service. The built-in pack `dogfighterad.core` version `1.0.0` contains **80 rule IDs**. See [RULES.md](RULES.md) for the catalog. A rule can produce multiple object/ACE/file/scope evaluations, so the finding count is not the rule count.

The engine is a functioning implementation of the offline assessment stage, not an exploitation/validation subsystem. It does not calculate effective Windows access, Resultant Set of Policy, a user's resultant PSO, graph attack paths across an entire forest, AD CS ESC conditions, RBCD, LAPS deployment, credential strength, certificate trust on live endpoints, or vulnerability patch state. No placeholder rules claim to evaluate those conditions.

## Pipeline and modules

```text
analyze
  -> bounded private copy of input bytes + SHA-256 of those same bytes
  -> existing strict DogadArtifactSerializer.ReadAsync
  -> SnapshotInvariantValidator
  -> ObservationIndex (capability / subject / path)
  -> RuleEngine: prerequisites, evaluations, evidence, deterministic findings
  -> JSON or escaped, script-free HTML
  -> atomic publication of a separate report
```

`DogfighterAD.Domain/Analysis` contains results and policy contracts. `DogfighterAD.Application/Analysis` contains the engine, observation access, proof graph and built-in rules. The application engine has no filesystem or network dependency. CLI owns input/output and policy parsing. `DogfighterAD.Serialization/AnalysisReportWriter` renders reports. Collectors remain separate and are never instantiated by `analyze`.

### API

```csharp
using DogfighterAD.Application.Analysis;
using DogfighterAD.Application.Analysis.Rules;

var engine = new RuleEngine(BuiltInRulePack.Create());
var report = engine.Analyze(snapshot, new RuleEngineOptions
{
    Policy = new(),
    RuleIds = new HashSet<string>(StringComparer.Ordinal)
    {
        "AD.USER.PREAUTH_DISABLED", "AD.POLICY.REVERSIBLE_ENCRYPTION"
    }
}, cancellationToken);
```

`IRule.Evaluate` now returns `IEnumerable<RuleEvaluation>`, not the previously unimplemented `IEnumerable<Finding>` contract. This is an intentional source-level API change in 0.2.0. Custom rule implementations must migrate. Use `RuleCheck` to acquire operands; its missing-data accumulator prevents a condition from producing a verdict after an unsuccessful read. Rule packs are trusted in-process code, not sandboxed plugins: exception isolation cannot stop arbitrary malicious code or a rule that ignores cancellation forever. Built-in loops observe cancellation; custom rules must do the same.

## No inferred field values

Complete built-in inventory counts must agree with `ObservedItemCount`, and applicable coverage must identify its collector. A missing inventory cannot silently become `NotApplicable` when the coverage claims objects were collected. These are consistency checks, not proof against a dishonest producer.

Typed objects provide inventory and relationship identity. Security predicates use persisted `ObservedFact` operands. For example, a typed `AdUser.UserAccountControl == 0` is not evidence that its LDAP attribute was collected. Likewise, an empty list is not automatically evidence of an empty LDAP multivalue attribute.

An operand is usable only if its disposition is `Stored`, the value and kind are valid, its fact ID recomputes correctly, its collector/version occurs in capability coverage, and its observation time lies inside the collection window. Missing, redacted, metadata-only, null, wrong-kind, malformed, conflicting or unverifiable observations produce `NotVerified` with `missingData` entries. For scalar values multiple distinct observations are a conflict; the engine never picks the first one. Evidence contains the fact ID, capability, subject, field path, observed value, collector version, source locator and observation time.

These consistency checks do **not** authenticate the source of a snapshot. SHA-256 is an integrity checksum, not a signature. A producer able to rewrite the entire artifact can rewrite observations and their hashes. Use trusted collection and secure artifact custody.

### Explicit special cases

* `accountExpires = 0` or `Int64.MaxValue` explicitly encodes no expiration; a missing attribute does not.
* `pwdLastSet = 0`, `lastLogonTimestamp = 0`, invalid timestamps and impossible future event timestamps are not converted into ancient events. Replicated logon age is only an approximate review signal, never proof of inactivity.
* Missing or explicit-zero `msDS-SupportedEncryptionTypes` is not assumed to mean RC4 or AES. Explicit advertised bits do not prove negotiated encryption or available keys.
* Guest/krbtgt use observed domain SID plus the exact well-known RID, not names or RID suffixes alone. The krbtgt age rule evaluates the normally disabled account too.
* `adminCount = 1` never proves current privilege. Privileged-user rules require a witnessed membership path. Every traversed edge has evidence. Missing per-group/member enumeration boundaries prevent a negative membership assertion; cycles terminate and a depth limit of 64 makes unproved paths unknown.
* Null/absent DACL is distinct from empty DACL. ACE candidate findings are `Potential`, not proof of effective control or DCSync. Deny order, property scope and token expansion are not calculated.
* Registry rules require explicit `REG_DWORD` type **4** in both normalized content and observations. `ValueKind.Integer` alone is insufficient. Conflicting assignments, unsupported values and unresolved `**` operations are not guessed.
* GPO settings are evaluated as **stored configuration**, not effective machine/user settings. Link precedence, filtering, enforced/disabled sections, loopback, OS-specific defaults and runtime protection are not inferred. `AlwaysInstallElevated` checks each side independently and explicitly states that one side is not proof of the combined elevation condition.
* A parsed GPP file emits `cpassword-present = true` only for a **nonempty** attribute, or an explicit `false` after successful parsing. The value is never persisted or decrypted. Presence is not proof that a password is valid or recoverable.
* Domain defaults and PSO configurations are separate subjects. A missing PSO field never falls back to the domain policy. Applies-to/precedence effects on individual users are not calculated.

## Result states

| Outcome | Meaning |
| --- | --- |
| `Present` | The narrowly stated configuration condition is explicitly evidenced. Not live exploitation. |
| `Potential` | The witnessed configuration is a review/exposure candidate; applicability or impact requires context. |
| `NotDetected` | The particular predicate is false for the evaluated subject and evidence. Not `Safe` or `Resolved`. |
| `NotVerified` | Required data or collection guarantees are unavailable. Never a clean result. |
| `NotApplicable` | Explicit evidence excludes the subject, or a completely collected scope has no applicable inventory. |
| `Error` | Evaluation failed. Exception payloads are not echoed; no clean result is inferred. |

`findings` contains `Present`/`Potential`. All other outcomes remain visible in `evaluations` and per-rule summaries. The overall report is `Error` if any rule errors, otherwise `Partial` if any check is unverified, otherwise `Complete`. `Complete` does not mean no findings. `ValidationStatus` stays `NotRequested` because no live validation occurred.

Missing/failed/blocked/unsupported/not-requested required capabilities and old minimum contract versions block evaluation with `NotVerified`. A partial capability can still provide valid positive evidence, but the engine adds a snapshot-scope `NotVerified` marker for its incomplete inventory. It never promotes the overall report to `Complete` merely because the known objects passed. Explicit `NotApplicable` prerequisite coverage is respected.

Capability versions use the repository's existing **monotonic backward-compatible** contract: versions at least as new as the required minimum satisfy its version requirement. Semantic breaks require a new capability ID, not reuse of a version number with a changed meaning.

## Collector extensions and compatibility

The artifact format stays v1 and the snapshot schema stays **2**. Already-readable schema-2 snapshots remain readable. Schema 1 was unsupported by the uploaded baseline and is not silently migrated here.

| Capability | Contract | Added collection |
| --- | --- | --- |
| `directory.security-policy` | new v1 | Domain password/lockout defaults, machine-account quota, individual PSO configurations; missing/invalid fields get `.readState` and no invented operand. |
| `directory.acls` | v2 → v3 | `securityDescriptor.parseComplete`, `securityDescriptor.aceCount`, per-ACE `objectTypePresent` and `inheritedObjectTypePresent`. |
| `directory.memberships` | v1 → v2 | Per-group `group.memberReadComplete` and `group.observedMemberCount`. An omitted `member` attribute is not certified as an explicit empty set for offline negative proofs. |
| `gpo.sysvol` | v1 → v2 | Explicit GPP nonempty-secret signal including negative observations; original registry value type; normalized allowlisted security-template DWORDs. |

Both built-in collection profiles now request `directory.security-policy`; `audit-full` remains needed for ACL/GPO/SYSVOL checks. The new collector queries the selected domain and `CN=Password Settings Container,CN=System,<domainDN>` only. It does not request passwords, hashes or managed-password blobs.

Domain attributes: `minPwdLength`, `pwdHistoryLength`, `pwdProperties`, `lockoutThreshold`, `lockoutDuration`, `lockOutObservationWindow`, `minPwdAge`, `maxPwdAge`, `ms-DS-MachineAccountQuota` plus identity. PSO attributes: `msDS-MinimumPasswordLength`, `msDS-PasswordHistoryLength`, `msDS-LockoutThreshold`, `msDS-LockoutDuration`, `msDS-LockoutObservationWindow`, `msDS-MinimumPasswordAge`, `msDS-MaximumPasswordAge`, `msDS-PasswordSettingsPrecedence`, `msDS-PasswordComplexityEnabled`, `msDS-PasswordReversibleEncryptionEnabled` plus identity. Stored durations are signed 100-nanosecond ticks as returned; no wall-clock conversion or default inference is used.

`AdGpoSetting.RegistryValueType` is an additive nullable property omitted from JSON when null. Therefore old canonical schema-2 payloads do not gain an unexpected null field on readback. New snapshots include the original type and a companion `<setting-fact-path>.registryValueType` integer fact. Old snapshots missing this evidence yield `NotVerified` for registry rules; a rescan is required, not fabricated backfilling. Only 20 reviewed DWORD keys in `SecurityRegistryCatalog` are exported from `[Registry Values]`; unknown or string/binary template values retain redaction/metadata-only handling.

## Determinism, identifiers and limits

Default reference time is the **snapshot's collection completion time**. No rule consults `DateTimeOffset.UtcNow`. `--as-of` is an explicit alternative, recorded in the report and required to be no earlier than collection completion. It reinterprets old evidence at a later reference time; it does not make that evidence current.

Same snapshot, pack, selection, policy and reference time produce deterministic sorted output. Findings use versioned SHA-256 fingerprints over length-prefixed UTF-8 pack ID, rule ID, subject ID and check key. Snapshot ID, display name, observation time and rule implementation version are deliberately excluded from that fingerprint; report metadata still records the pack and rule versions. Stable fingerprints are groundwork for a future retest/diff layer, not an implementation of one.

The default organizational thresholds are in [../samples/analysis-policy.json](../samples/analysis-policy.json). They are explicit review choices, not a claim about an AD default or a universal compliance standard. A policy file may override known properties; omitted threshold properties use the documented analysis defaults, not guessed snapshot values. Unknown/duplicate properties, nonintegers, excessive size and out-of-range thresholds are rejected.

Input budgets reuse the strict artifact reader. CLI first makes a private bounded temporary copy and hashes the exact bytes being analyzed, preventing an input-change/hash race. Reports are written to a temporary sibling and atomically renamed; invalid input, cancellation and budget failure do not replace an existing output. File contents remain sensitive audit data; protect source/output directories and permissions.

The default evaluation budget is 2,000,000, configurable from 1 to 10,000,000. Exceeding it aborts without publishing a truncated report. Membership reachability is capped at 1,000,000 nodes and depth 64. The engine and report model retain results/evidence in memory: these limits are not a total-process memory guarantee. Very large ACL-heavy environments require measurement and possibly rule selection or a future streaming result store.

## CLI

```sh
# Review the exact active catalog.
dogfighter rules
dogfighter rules --format json

# Collect fresh inputs for the expanded rules.
dogfighter scan --target dc01.example.test --profile audit-full --ldaps --output new.dogad

# Both commands are entirely offline after the .dogad exists.
dogfighter analyze --snapshot new.dogad --output findings.json
dogfighter analyze --snapshot new.dogad --output findings.html --format html

# Explicit baseline / time / selection.
dogfighter analyze --snapshot new.dogad --output selected.json --policy samples/analysis-policy.json \
  --rule AD.USER.PREAUTH_DISABLED --rule AD.POLICY.REVERSIBLE_ENCRYPTION --fail-on high
```

Available options: `--snapshot`, `--output`, `--format json|html`, `--policy`, repeatable `--rule`, `--as-of` (ISO 8601 with timezone), `--fail-on informational|low|medium|high|critical|none`, `--max-snapshot-mib 1..1024`, `--max-evaluations 1..10000000`. The report extension must match its format. No credentials or targets are accepted by `analyze`.

| Exit | Meaning for `analyze` |
| --- | --- |
| 0 | Complete analysis; no finding at or above the chosen failure threshold (or `--fail-on none`). |
| 1 | Complete analysis with a finding at/above threshold. |
| 2 | Partial analysis, including missing evidence; takes precedence over findings. |
| 64 | Invalid arguments, policy, rule selection or reference time. |
| 70 | Invalid artifact, rule error, evaluation limit or runtime/I/O failure. |
| 130 | Caller cancellation. |

`--fail-on` changes the exit code threshold only; it does not hide findings or unknown checks. JSON is the complete machine-readable report. HTML lists rule coverage, findings, evidence, reference links, unknowns and errors; all source strings are HTML-escaped, and no scripts, external fonts or analytics are loaded.

## Verification

Run the existing xUnit v3 executable runner (not an assumed legacy `dotnet test --filter` workflow):

```sh
dotnet restore tests/DogfighterAD.Core.Tests/DogfighterAD.Core.Tests.csproj
dotnet build tests/DogfighterAD.Core.Tests/DogfighterAD.Core.Tests.csproj -c Release --no-restore
dotnet run --project tests/DogfighterAD.Core.Tests/DogfighterAD.Core.Tests.csproj -c Release --no-build
```

`scripts/verify.sh` / `scripts/verify.ps1` invoke this sequence. CI retains Windows/Linux coverage and adds a real CLI catalog smoke step. New tests under `tests/DogfighterAD.Core.Tests/Analysis` exercise all rule families, field absence/redaction/conflicts, capability boundaries, group cycles, primary groups, default/PSO separation, old optional-field compatibility, deterministic output, safe HTML and CLI round trips. These tests use synthetic data and do not contact a live directory.

**Build and xUnit were not executed in the implementation environment because the .NET SDK is absent.** See [../VALIDATION_RULE_ENGINE.md](../VALIDATION_RULE_ENGINE.md) for the checks that actually ran. Live AD/SMB and empirical memory/performance validation remain deployment acceptance steps.

## Attribute absence proofs (rule pack 1.1.0)

`directory.users` and `directory.computers` v2 and `directory.memberships` v3
add conservative proofs for requested but omitted LDAP fields. Collectors request
DACL-only nTSecurityDescriptor together with the attributes and query the schema
once per participating collector. Their additional facts use the original field
path plus `.absenceConfirmed`, `.absenceProof`, `.absenceAttribute`,
`.absenceSearchFlags`, `.absenceDaclSha256`, `.absenceSchemaId`, and
`.absencePropertySetId`. These are observations with collector, endpoint, DN and
timestamp provenance; hashes bind diagnostics to the descriptor read but are not
signatures or offline re-execution of the access check.

The `authenticated-schema-read-v1` method is a sufficient proof, not a full token
access-check implementation. It requires a successfully authenticated LDAP client,
an allowlisted attribute with explicit ordinary schema searchFlags and schemaIDGUID,
and a fully parsed DACL. A read grant must apply to Everyone or Authenticated Users,
with no ObjectType restriction or one matching the observed attribute/property-set
GUID. Inherit-only ACEs do not grant access to the current object. Any potentially
applicable read deny (regardless of trustee or object scope), unsupported ACE,
missing DACL/schema, or uncertain authentication prevents the proof. A returned
attribute, including ranged, binary or malformed values, is never relabeled absent.
A null DACL permits read; an empty/unknown DACL does not. Confidential, RODC-filtered
and unfamiliar search flags are excluded. The whitelist excludes attributes with
other special read requirements. Broader allow ACEs for private groups/SELF are
not resolved; such objects may legitimately retain NotVerified.

Only a complete, coherent proof with the appropriate capability version enables
an empty-set operand. Missing, old, redacted or contradictory proof remains unknown.
Positive values and absence evidence together are a conflict. Scalar absence is
never converted to numeric zero. An explicitly proven unset encryption attribute
makes explicit-mask rules NotApplicable (not proof of AES/RC4 or KDC defaults).
A proven absent replicated-logon timestamp makes that age test NotApplicable,
not proof that the account never logged on. Ordinary missing values stay NotVerified.

`group.memberReadComplete` can now be true for an omitted member attribute only
when its absence is proved. Invalid absence evidence prevents negative privilege
proof even if a complete boolean was also persisted. Existing returned-member and
primary-group requirements remain in force. Original snapshots are never backfilled.

See [MS-ADTS access checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8271b44d-a755-4872-a762-1ac57152099d)
and [object-specific access](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3da5080d-de25-4ac8-9f2b-982709253dfb).
