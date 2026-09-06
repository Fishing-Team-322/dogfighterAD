# Foundation review and MINILAB readiness - 2026-09-06

## Verdict

The repository has a substantial collection/serialization foundation, but no runnable scan CLI or live integration harness. It is suitable for continuing implementation and offline testing, not yet a validated AD assessment product. The review does not establish correctness of every collector against a real directory.

Reviewed baseline: `abb9aaf2b3edd3718b9fd6fe88678c02e4f45238`, branch `foundation/snapshot-core`. Baseline GitHub CI run [33992211384](https://github.com/kusotsu/dogfighterAD/actions/runs/33992211384) succeeded. Local Windows/.NET SDK 10.0.400 verification passed all 67 existing tests. No VMs were started or scanned during this review.

## Added regression coverage

`tests/DogfighterAD.Core.Tests/BoundaryRegressionTests.cs` adds 33 executable cases:

- 5 INI encoding cases (UTF-8 with/without BOM, UTF-16 LE with/without BOM, UTF-16 BE);
- 3 malformed/DTD XML cases checking source-content omission;
- 7 INI secret-key redaction cases;
- 13 malformed or inconsistent manifest cases;
- 4 real temporary-file size boundary cases;
- 1 deterministic collector cancellation race case.

Before fixes: 100 tests, 6 failures. After fixes: 100 tests, no failures or skips on local Windows. CI now runs the suite on both Windows and Linux with a 15-minute job limit. Synthetic test fixtures do not contact AD, SMB servers or external XML entities. The suite does not claim exhaustive secret detection or real AD integration coverage.

Reproduce with .NET 10:

```sh
dotnet restore tests/DogfighterAD.Core.Tests/DogfighterAD.Core.Tests.csproj
dotnet build tests/DogfighterAD.Core.Tests/DogfighterAD.Core.Tests.csproj -c Release --no-restore
dotnet run --project tests/DogfighterAD.Core.Tests/DogfighterAD.Core.Tests.csproj -c Release --no-build
```

The project uses the xUnit v3 executable runner; these are the CI commands.

## Confirmed defects addressed in this change

### XML error text could expose source fragments

`SysvolPolicyParsers.ScanPreferencesXml` included `XmlException.Message` in parser errors, which the collector persists in coverage issues. A malformed cpassword attribute containing an undefined entity named `SECRET_CANARY` reproduced source text in the error. This is a diagnostic-channel leak; it does not mean valid cpassword values were normally stored. XML errors now use a fixed message without parser-supplied content. DTD processing remains prohibited.

### UTF-8 BOM caused valid INI headers to fail

`DecodeText` retained the UTF-8 BOM as a character, causing `[General]` on line one to be rejected. The BOM is now stripped while preserving existing decoding fallbacks. Equivalent supported encodings have regression coverage.

### Malformed manifest hash caused NullReferenceException

An explicit JSON null for `payloadSha256` bypassed C# required-member expectations and was dereferenced. It now produces a controlled `DogadArtifactException`. Invalid values, unsupported identifiers and path/length mutations have additional rejection coverage.

### Manifest completion time was not checked against the snapshot

Changing only `snapshotCompletedAt` to a different date was accepted. Reader metadata agreement now includes completion time. This concerns internal consistency, not authenticity: SHA-256 is still not a signature.

### Late collector success overrode cancellation

A collector returning a successful result after its timeout token was canceled was recorded as Completed. The executor now checks the linked token before accepting returned data. The regression waits for cancellation through a token registration rather than relying on a particular scheduler delay. This fixes status handling; it does NOT forcibly interrupt a blocked collector.

## Open blockers and limitations

### P1: enforce the SYSVOL source boundary before network/file access

Locations: `Collectors/GpoSysvolCollector.cs` and `Sysvol/SysvolContracts.cs` in `DogfighterAD.Collectors.ActiveDirectory`.

The collector trusts `gPCFileSysPath` and passes it directly to filesystem enumeration. An offline probe pointing a GPO at an ordinary local temporary directory collected its GPT.INI with Complete coverage. No target/domain/share validation currently prevents a different UNC server from being used. An untrusted path may therefore cause out-of-scope reads or Windows network authentication. External-server authentication was not exercised in this review.

Required next change: explicit approved SYSVOL authorities/domains and policy-root validation before any I/O, with an intentional model for domain DFS and approved DCs. Reject local/device paths, traversal and unrelated shares; validate resolved child paths as well. Test rejection with a recording fake client that proves no I/O occurred. Keep any local fixture adapter explicit and test-only. A textual host comparison alone is not a complete DFS/referral policy.

Until implemented, audit-full needs a controlled lab and independently verified GPO paths. Do not describe the current collector as enforcing scan scope.

### P1: blocking filesystem operations lack a hard deadline

`CollectionExecutor` cancellation is cooperative. `Directory.EnumerateFiles`, FileInfo access and FileStream opening contain synchronous filesystem work. A stalled operation can prevent token observation and hold a stage indefinitely. A synthetic collector ignoring cancellation returned after approximately 186 ms despite a 25 ms timeout; before the status fix it was also recorded Completed.

Required next change: define how outstanding I/O is bounded, canceled and drained. Simply racing a Task against a timer can leave background work running and exceed concurrency limits. Consider an isolated worker for operations that cannot be reliably interrupted; prove termination and resource cleanup with controlled blocked-I/O fixtures. Do not add a fleet of services for this purpose.

### P2: file-size limit is not enforced during streaming

`SystemSysvolClient.ReadFileAsync` checks length before and after `CopyToAsync`, with FileShare.ReadWrite enabled. A growing file can exceed the intended allocation limit before rejection. This is a source-inspection finding; concurrent growth was not reproduced deterministically. Existing/new size-boundary tests cover static files only.

Required next change: bounded chunked reads that stop after at most maxBytes plus one detection byte; add a deterministic growing-stream fixture and cancellation tests. Add total scan/file budgets after measurement.

### Additional live-test gaps

- LDAP referrals, inaccessible naming contexts and partial paging need fixtures; page/request telemetry is absent.
- Effective GPO settings, all ACE families and forest-wide correctness are not established by the current normalized models.
- Reader/writer memory use needs large-artifact measurements; entry limits do not establish a total-process memory bound.
- Secret-key heuristics are not a complete secret classifier. Test more real formats before making stronger claims.

## Recommended development sequence

1. Close the SYSVOL scope and I/O-budget items above with regression tests.
2. Add a small CLI composition layer: target/profile/output, explicit scope, running-identity authentication, cancellation, structured exit statuses and coverage summary. Keep credentials out of arguments and artifacts.
3. In MINILAB, run minimal first, then audit-full, assemble a snapshot, write .dogad and read it back offline. Check known object/member/GPO counts and explicit failure coverage. Record the exact build and fixture state.
4. Measure LDAP requests/pages, duration and peak working set. Try unavailable SYSVOL, denied reads, paging/ranged groups and cancellation. Record failures as incomplete, never safe.
5. Repeat on the full GOAD fixture prepared by the tester; compare expected planted configuration with collected facts before introducing a broad rule pack.
6. Add a small evidence-backed rule engine, capability prerequisites/NotVerified, JSON/HTML reporting and retest diff. Add graph projection when it answers a concrete audit question.

Keep C#/.NET and the current module boundaries. There is no benchmark evidence that changing language or buying a powerful server would solve the present gaps. Measure directory I/O, normalization and artifact allocations before adding parallelism or a database. The first useful product milestone is a reproducible, scoped collection plus a few reliable findings, not feature parity with a large commercial platform.
