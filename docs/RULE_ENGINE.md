# Offline Rule Engine — 0.3.2 source baseline

## Scope

The engine evaluates a validated `.dogad` snapshot without connecting to LDAP, SYSVOL, an endpoint, a domain controller, a CA runtime endpoint, or an external rule service. The built-in pack is `dogfighterad.core/1.2.0` and contains **88 rule IDs**. See [RULES.md](RULES.md) for the catalog. A rule can produce multiple object/ACE/file/scope evaluations, so finding count is not rule count.

The engine is an offline assessment stage, not an exploitation/validation subsystem. It does not perform credential attacks, live certificate enrollment, live CA RPC/registry inspection, RSoP, full Windows effective-access calculation, graph attack-path execution, endpoint vulnerability scanning or automatic exploitation.

0.3.2 adds directory-derived AD CS analysis. The distinction is strict:

```text
Configuration-NC evidence -> normalized adcs.* snapshot capabilities -> offline ADCS.* rules

NOT:
Configuration-NC evidence -> inferred CA registry/RPC/web/issuance behavior
```

`ADCS.TEMPLATE.ESC1_CANDIDATE` is therefore a `Potential` directory candidate, never a claim that runtime ESC1 exploitability has been verified.

## Pipeline and modules

```text
scan / UI assessment
  -> production read-only collectors
  -> deterministic SnapshotFragment merge
  -> verified .dogad round-trip

analyze
  -> bounded private copy of input bytes + SHA-256 of those same bytes
  -> strict DogadArtifactSerializer.ReadAsync
  -> snapshot invariant validation
  -> ObservationIndex (capability / subject / path)
  -> RuleEngine: prerequisites, evaluations, evidence, deterministic findings
  -> JSON or escaped, script-free HTML
  -> atomic publication of a separate report
```

The local UI automates the first and second stages but preserves the same snapshot boundary. The browser does not contain a second rule implementation.

`DogfighterAD.Domain/Analysis` contains result/policy contracts. `DogfighterAD.Application/Analysis` contains the engine, observation access, membership proof graph and built-in rules. Collectors remain separate and are never instantiated by offline `analyze`.

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
        "AD.USER.PREAUTH_DISABLED",
        "ADCS.TEMPLATE.ESC1_CANDIDATE"
    }
}, cancellationToken);
```

`IRule.Evaluate` returns `IEnumerable<RuleEvaluation>`. Use `RuleCheck` to acquire operands; its missing-data accumulator prevents a condition from producing a verdict after an unsuccessful read. Rule packs are trusted in-process code, not sandboxed plugins. Built-in loops observe cancellation; custom rules must do the same.

## Evidence-first operand model

Complete inventory is not a substitute for a field observation. Typed snapshot objects provide normalized inventory/relationships, while security predicates require persisted `ObservedFact` operands.

An operand is usable only if its disposition is `Stored`, its value/kind is valid, its `FactId` recomputes correctly, its collector/version occurs in relevant capability coverage, and its observation time is coherent with collection. Missing, redacted, metadata-only, wrong-kind, malformed, conflicting or unverifiable observations produce `NotVerified` with `missingData`; the engine does not choose an arbitrary value.

Typed content and observations are cross-checked for security-relevant fields. A typed `0`, empty list or default CLR value is never silently converted into proof that LDAP returned zero/empty.

These consistency checks do not cryptographically authenticate a snapshot producer. SHA-256 protects artifact integrity/readback; it is not a signature. Use trusted collection and protect artifact custody.

## Result states

| Outcome | Meaning |
| --- | --- |
| `Present` | The narrowly stated configuration condition is explicitly evidenced. Not live exploitation. |
| `Potential` | A witnessed review/exposure candidate; applicability or impact still requires context. |
| `NotDetected` | The particular predicate is false for the evaluated subject and usable evidence. Not `Safe`. |
| `NotVerified` | Required data or collection guarantees are unavailable/unusable. Never a clean result. |
| `NotApplicable` | Explicit evidence excludes the subject, or completely collected scope proves no applicable inventory. |
| `Error` | Evaluation failed. No clean result is inferred. |

`findings` contains `Present`/`Potential`. Other outcomes remain in `evaluations` and rule summaries. Overall completion is `Error` if a rule errors, otherwise `Partial` if any check is unverified, otherwise `Complete`. `Complete` does not mean no findings.

Missing/failed/blocked/unsupported/not-requested capabilities and too-old minimum contract versions block required rules with `NotVerified`. Partial coverage can retain witnessed positive findings while adding snapshot-scope `NotVerified`; partial inventory never becomes a complete clean report.

## Capability compatibility

Capability versions are monotonic and backward-compatible. A rule declares a minimum version; newer compatible versions satisfy it. Semantic breaks require a new capability ID.

Current security-relevant versions include:

- `directory.users` v2;
- `directory.computers` v2;
- `directory.memberships` v3;
- `directory.acls` v3;
- `gpo.sysvol` v3;
- AD CS directory contracts `adcs.authorities/templates/publication/acls/trust` v1.

The pre-0.3.2 placeholder `adcs.directory` remains a legacy catalog ID only. Built-in profiles/rules do not use it.

## AD CS rule plane — pack 1.2.0

`CertificateServicesRulePack` version `1.1.0` contributes eight rules to `dogfighterad.core/1.2.0`:

- `ADCS.TEMPLATE.ESC1_CANDIDATE`;
- `ADCS.TEMPLATE.DANGEROUS_ACL`;
- `ADCS.TEMPLATE.BROAD_ENROLLMENT`;
- `ADCS.TEMPLATE.AUTHENTICATION_CAPABLE`;
- `ADCS.TEMPLATE.ENROLLEE_SUPPLIES_SUBJECT`;
- `ADCS.TEMPLATE.NO_APPROVAL`;
- `ADCS.TEMPLATE.NO_AUTHORIZED_SIGNATURE`;
- `ADCS.CA.DANGEROUS_DIRECTORY_ACL`.

### ESC1 candidate prerequisites

The composite ESC1 candidate requires all implemented directory evidence for the same template:

1. template is published by at least one collected Enterprise CA;
2. a low-privilege trustee has an evidence-backed Enrollment path from the collected template DACL;
3. an authentication-capable EKU/application policy is present;
4. enrollee-supplies-subject is set;
5. pending/manager approval is not required by collected enrollment flags;
6. required authorized signatures equals zero.

If a prerequisite is false, the candidate is not detected. If a required operand/scope cannot be proven, the result is `NotVerified`. If the template is not published in a complete publication inventory, the rule is `NotApplicable` for that template.

A match is `Potential`. The evaluation explicitly says that the following are **not verified** by 0.3.2: CA registry/RPC policy, `EDITF_ATTRIBUTESUBJECTALTNAME2`, service permissions, web enrollment, EPA/channel binding, NTLM behavior, live issuance behavior, deny precedence/full Windows effective access and exploitability.

### Low-privilege enrollment/control proof

AD CS ACL analysis reuses the normal directory user/group/membership/domain evidence. It does not treat every custom trustee SID as broad merely because the SID is unfamiliar.

- Well-known broad principals can be recognized directly where appropriate.
- A custom group can be treated as low privilege when collected nested membership proves an enabled non-privileged user path.
- A custom group whose witnessed member is privileged is not automatically treated as low privilege.
- Incomplete group-member boundaries prevent a negative proof; unknown scope stays `NotVerified` where relevant.
- DACL rules report candidate direct control/enrollment paths and do not claim full effective-access resolution.

## AD CS collector/runtime boundary

The 0.3.2 collector reads `CN=Public Key Services,CN=Services,<configurationNamingContext>` by LDAP and requests DACL-only `nTSecurityDescriptor`. It collects Enterprise CAs, templates, publication edges, CA/template DACLs and NTAuth directory certificate posture.

It deliberately does not contact:

- CA registry;
- CA RPC/DCOM/service APIs;
- HTTP(S) or web enrollment;
- live certificate enrollment endpoints;
- endpoint certificate stores or authentication services.

Future runtime checks must use separate capability IDs. Existing `adcs.*` directory v1 evidence cannot satisfy them by implication.

If a successful Configuration-NC search finds no Enterprise CA, all five AD CS capabilities are `NotApplicable`. If collection is partial/failed, rules remain unknown as required; a missing AD CS payload is not interpreted as “no CA risk”.

## Explicit special cases

- `accountExpires = 0` or `Int64.MaxValue` explicitly encodes no expiration; a missing attribute does not.
- `pwdLastSet = 0`, `lastLogonTimestamp = 0`, invalid timestamps and impossible future timestamps are not converted into ancient events.
- Missing or explicit-zero `msDS-SupportedEncryptionTypes` is not assumed to mean RC4/AES. Explicit bits do not prove negotiated encryption or keys.
- Guest/krbtgt use observed domain SID plus exact well-known RID, not names/RID suffixes alone.
- `adminCount = 1` never proves current privilege. Privileged-user and AD CS custom-group reasoning use witnessed membership paths.
- Null/absent DACL is distinct from empty DACL. Candidate ACE findings remain `Potential` where effective access is unresolved.
- Registry rules require explicit reviewed value type/operands; unsupported or conflicting assignments are not guessed.
- GPO settings are stored configuration, not effective RSoP.
- GPP `cpassword` stores only the reviewed presence signal; the secret value is not persisted/decrypted.
- Domain defaults and PSOs are separate subjects; no missing PSO field falls back to domain policy.

## Attribute absence proofs (rule pack 1.1.0+)

`directory.users` / `directory.computers` v2 and `directory.memberships` v3 support conservative proofs for requested-but-omitted reviewed LDAP fields. Proof facts bind the decision to collector/endpoint/DN/time/schema and DACL diagnostics. This is a sufficient proof model, not full token-access emulation.

A proof is accepted only when its reviewed gates are coherent. A returned attribute is never relabeled absent. Potentially applicable denies, unsupported ACE semantics, unknown/confidential schema behavior or incomplete DACL/schema evidence prevent an absence proof. Missing/old/redacted/contradictory proof stays unknown.

For group membership, `group.memberReadComplete` plus observed count and proof semantics establish the direct-member enumeration boundary required for negative membership reasoning. Positive returned-member and primary-group evidence remains explicit.

## Determinism and limits

Default analysis reference time is snapshot collection completion. Rules do not consult the current wall clock unless the caller explicitly supplies a permitted `--as-of` reference.

Same snapshot, pack, selection, policy and reference time produce deterministic sorted output. Finding fingerprints are stable SHA-256 identifiers over pack/rule/subject/check identity rather than display names.

The default evaluation budget is 2,000,000 (configurable up to 10,000,000). Membership reachability is capped at 1,000,000 nodes and depth 64. Exceeding a hard analysis budget aborts rather than publishing a truncated successful report.

## CLI

```sh
dogfighter rules
dogfighter rules --format json

dogfighter scan --target dc01.example.test --profile audit-full --ldaps --output new.dogad

dogfighter analyze --snapshot new.dogad --output findings.json
dogfighter analyze --snapshot new.dogad --output findings.html --format html

dogfighter analyze --snapshot new.dogad --output adcs.json \
  --rule ADCS.TEMPLATE.ESC1_CANDIDATE --rule ADCS.TEMPLATE.DANGEROUS_ACL \
  --fail-on none
```

`analyze` remains offline after the `.dogad` exists and accepts no LDAP/CA credentials or live target.

| Exit | Meaning for `analyze` |
| --- | --- |
| 0 | Complete analysis; no finding at/above failure threshold (or `--fail-on none`). |
| 1 | Complete analysis with a finding at/above threshold. |
| 2 | Partial analysis, including missing evidence; takes precedence over findings. |
| 64 | Invalid arguments/policy/rule selection/reference time. |
| 70 | Invalid artifact, rule error, evaluation limit or runtime/I/O failure. |
| 130 | Caller cancellation. |

## Verification

The repository's CI matrix currently runs on Ubuntu and Windows and covers:

- restore/build with warnings as errors;
- local web static-asset smoke including Certificate Services assets/tab;
- JavaScript syntax checks for `app.js` and `certificate-services.js`;
- the xUnit v3 executable test suite;
- offline CLI rule-catalog smoke;
- Windows self-contained publish smoke.

AD CS tests include clean/positive template fixtures, approval/signature gates, unpublished templates, broad enrollment without authentication purpose, AutoEnroll, dangerous template/CA directory ACLs, legacy/partial evidence, web view projection and nested custom enrollment-group membership through the public Rule Engine.

These are automated/synthetic checks. Live MINILAB/GOAD AD CS acceptance remains a separate validation record and must not be inferred from green CI.
