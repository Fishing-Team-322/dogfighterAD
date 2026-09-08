using System.Net;
using System.Security;
using System.Security.Cryptography;
using DogfighterAD.Application.Analysis;
using DogfighterAD.Application.Analysis.Rules;
using DogfighterAD.Application.Collection;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Application.Snapshots;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Collectors.ActiveDirectory.Sysvol;
using DogfighterAD.Domain.Analysis;
using DogfighterAD.Domain.Snapshots;
using DogfighterAD.Serialization;

internal sealed class UiStartAssessmentRequest
{
    public string? Target { get; set; }
    public string Profile { get; set; } = "audit-full";
    public string Authentication { get; set; } = "os-context";
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string LdapAuth { get; set; } = "negotiate";
    public bool UseLdaps { get; set; }
    public int? LdapPort { get; set; }
    public IReadOnlyList<string> SysvolAuthorities { get; set; } = [];
}

internal sealed record UiAssessmentStatus
{
    public required Guid AssessmentId { get; init; }
    public required string State { get; init; }
    public required string Target { get; init; }
    public required string Profile { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset? CompletedAt { get; init; }
    public required bool CanCancel { get; init; }
    public string? Error { get; init; }
    public string? SnapshotPath { get; init; }
    public string? SnapshotFileName { get; init; }
    public string? SnapshotStatus { get; init; }
    public Guid? SnapshotId { get; init; }
    public Guid? AnalysisId { get; init; }
    public IReadOnlyList<UiCollectorProgress> Progress { get; init; } = [];
}

internal sealed record UiCollectorProgress
{
    public required string CollectorId { get; init; }
    public required string State { get; init; }
    public required DateTimeOffset Timestamp { get; init; }
    public TimeSpan? Elapsed { get; init; }
    public TimeSpan? Timeout { get; init; }
    public string? IssueCode { get; init; }
}

internal sealed class UiAssessmentStore
{
    private readonly object gate = new();
    private readonly Dictionary<Guid, UiAssessmentSession> sessions = [];
    private readonly string rootDirectory;

    public UiAssessmentStore()
    {
        rootDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DogfighterAD",
            "Assessments");
        EnsurePrivateDirectory(rootDirectory);
    }

    public UiAssessmentStatus Start(UiStartAssessmentRequest request, string productVersion, UiAnalysisStore analyses)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(productVersion);
        ArgumentNullException.ThrowIfNull(analyses);

        var prepared = UiPreparedAssessment.Create(request);
        var assessmentId = Guid.NewGuid();
        var directory = Path.Combine(rootDirectory, $"{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}-{assessmentId:N}");
        EnsurePrivateDirectory(directory);
        var snapshotPath = Path.Combine(directory, "snapshot.dogad");
        var session = new UiAssessmentSession(assessmentId, prepared.Target, prepared.Profile.Name, snapshotPath);

        lock (gate)
            sessions.Add(assessmentId, session);

        _ = Task.Run(() => RunAsync(session, prepared, productVersion, analyses), CancellationToken.None);
        return session.GetStatus();
    }

    public bool TryGet(Guid assessmentId, out UiAssessmentStatus status)
    {
        UiAssessmentSession? session;
        lock (gate)
            sessions.TryGetValue(assessmentId, out session);

        if (session is null)
        {
            status = null!;
            return false;
        }

        status = session.GetStatus();
        return true;
    }

    public bool Cancel(Guid assessmentId)
    {
        UiAssessmentSession? session;
        lock (gate)
            sessions.TryGetValue(assessmentId, out session);
        return session?.Cancel() == true;
    }

    public bool TryGetSnapshot(Guid assessmentId, out string path, out string fileName)
    {
        UiAssessmentSession? session;
        lock (gate)
            sessions.TryGetValue(assessmentId, out session);

        if (session is null || !session.TryGetSnapshot(out path))
        {
            path = string.Empty;
            fileName = string.Empty;
            return false;
        }

        fileName = $"dogfighter-{assessmentId:N}.dogad";
        return true;
    }

    private static async Task RunAsync(UiAssessmentSession session, UiPreparedAssessment prepared, string productVersion, UiAnalysisStore analyses)
    {
        using (prepared)
        {
            try
            {
                session.SetState("collecting");
                var collectors = UiCollectionComposition.CreateCollectors(prepared);
                var scan = await UiScanWorkflow.ExecuteAsync(
                        prepared.Target,
                        session.SnapshotPath,
                        productVersion,
                        prepared.Profile,
                        collectors,
                        session.RecordProgress,
                        session.CancellationToken)
                    .ConfigureAwait(false);

                session.SetSnapshot(scan.Snapshot.Metadata.SnapshotId, scan.Snapshot.Metadata.CompletionStatus.ToString());
                session.SetState("analyzing");

                var sha256 = await HashFileAsync(session.SnapshotPath, session.CancellationToken).ConfigureAwait(false);
                var engine = new RuleEngine(BuiltInRulePack.Create(), BuiltInRulePack.Id, BuiltInRulePack.Version);
                var report = engine.Analyze(
                    scan.Snapshot,
                    new RuleEngineOptions { Policy = new AnalysisPolicy(), MaxEvaluations = 2_000_000 },
                    session.CancellationToken) with
                {
                    InputArtifactSha256 = sha256
                };

                var analysisId = analyses.Add(report);
                session.Complete(analysisId, report.SnapshotId);
            }
            catch (OperationCanceledException) when (session.CancellationToken.IsCancellationRequested)
            {
                session.MarkCanceled();
            }
            catch (DogadArtifactException exception)
            {
                session.Fail($"artifact:{exception.Code}");
            }
            catch (Exception exception)
            {
                session.Fail(exception.GetType().Name);
            }
        }
    }

    private static async Task<string> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        await using var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
                break;
            hasher.AppendData(buffer, 0, read);
        }
        return Convert.ToHexStringLower(hasher.GetHashAndReset());
    }

    private static void EnsurePrivateDirectory(string path)
    {
        Directory.CreateDirectory(path);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
}

internal sealed class UiAssessmentSession
{
    private readonly object gate = new();
    private readonly CancellationTokenSource cancellation = new();
    private readonly Dictionary<string, UiCollectorProgress> progress = new(StringComparer.Ordinal);
    private readonly List<string> progressOrder = [];
    private string state = "queued";
    private string? error;
    private DateTimeOffset? completedAt;
    private Guid? snapshotId;
    private string? snapshotStatus;
    private Guid? analysisId;

    public UiAssessmentSession(Guid id, string target, string profile, string snapshotPath)
    {
        AssessmentId = id;
        Target = target;
        Profile = profile;
        SnapshotPath = snapshotPath;
        StartedAt = DateTimeOffset.UtcNow;
    }

    public Guid AssessmentId { get; }
    public string Target { get; }
    public string Profile { get; }
    public string SnapshotPath { get; }
    public DateTimeOffset StartedAt { get; }
    public CancellationToken CancellationToken => cancellation.Token;

    public void RecordProgress(CollectionProgressEvent progressEvent)
    {
        ArgumentNullException.ThrowIfNull(progressEvent);
        lock (gate)
        {
            if (!progress.ContainsKey(progressEvent.CollectorId))
                progressOrder.Add(progressEvent.CollectorId);
            progress[progressEvent.CollectorId] = new UiCollectorProgress
            {
                CollectorId = progressEvent.CollectorId,
                State = progressEvent.State.ToString(),
                Timestamp = progressEvent.Timestamp,
                Elapsed = progressEvent.Elapsed,
                Timeout = progressEvent.Timeout,
                IssueCode = progressEvent.IssueCode
            };
        }
    }

    public void SetState(string value)
    {
        lock (gate)
            state = value;
    }

    public void SetSnapshot(Guid id, string status)
    {
        lock (gate)
        {
            snapshotId = id;
            snapshotStatus = status;
        }
    }

    public void Complete(Guid completedAnalysisId, Guid completedSnapshotId)
    {
        lock (gate)
        {
            analysisId = completedAnalysisId;
            snapshotId = completedSnapshotId;
            state = "complete";
            completedAt = DateTimeOffset.UtcNow;
        }
    }

    public void Fail(string code)
    {
        lock (gate)
        {
            error = code;
            state = "failed";
            completedAt = DateTimeOffset.UtcNow;
        }
    }

    public void MarkCanceled()
    {
        lock (gate)
        {
            state = "canceled";
            completedAt = DateTimeOffset.UtcNow;
        }
    }

    public bool Cancel()
    {
        lock (gate)
        {
            if (state is "complete" or "failed" or "canceled")
                return false;
            cancellation.Cancel();
            return true;
        }
    }

    public bool TryGetSnapshot(out string path)
    {
        lock (gate)
        {
            if (!File.Exists(SnapshotPath))
            {
                path = string.Empty;
                return false;
            }
            path = SnapshotPath;
            return true;
        }
    }

    public UiAssessmentStatus GetStatus()
    {
        lock (gate)
        {
            var snapshotExists = File.Exists(SnapshotPath);
            return new UiAssessmentStatus
            {
                AssessmentId = AssessmentId,
                State = state,
                Target = Target,
                Profile = Profile,
                StartedAt = StartedAt,
                CompletedAt = completedAt,
                CanCancel = state is "queued" or "collecting" or "analyzing",
                Error = error,
                SnapshotPath = snapshotExists ? SnapshotPath : null,
                SnapshotFileName = snapshotExists ? Path.GetFileName(SnapshotPath) : null,
                SnapshotStatus = snapshotStatus,
                SnapshotId = snapshotId,
                AnalysisId = analysisId,
                Progress = progressOrder.Where(progress.ContainsKey).Select(id => progress[id]).ToArray()
            };
        }
    }
}

internal sealed class UiPreparedAssessment : IDisposable
{
    private UiPreparedAssessment(string target, CollectionProfile profile, bool useLdaps, int? ldapPort, LdapAuthenticationMode ldapAuthenticationMode, IReadOnlySet<string> approvedSysvolAuthorities, UiNetworkCredential? credential)
    {
        Target = target;
        Profile = profile;
        UseLdaps = useLdaps;
        LdapPort = ldapPort;
        LdapAuthenticationMode = ldapAuthenticationMode;
        ApprovedSysvolAuthorities = approvedSysvolAuthorities;
        Credential = credential;
    }

    public string Target { get; }
    public CollectionProfile Profile { get; }
    public bool UseLdaps { get; }
    public int? LdapPort { get; }
    public LdapAuthenticationMode LdapAuthenticationMode { get; }
    public IReadOnlySet<string> ApprovedSysvolAuthorities { get; }
    public UiNetworkCredential? Credential { get; }
    public NetworkCredential? NetworkCredential => Credential?.Credential;

    public static UiPreparedAssessment Create(UiStartAssessmentRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var target = request.Target?.Trim();
        if (string.IsNullOrWhiteSpace(target))
            throw new ArgumentException("Assessment target is required.");

        if (string.IsNullOrWhiteSpace(request.Profile) || !BuiltInCollectionProfiles.TryGet(request.Profile, out var profile))
            throw new ArgumentException("Unknown collection profile.");

        var authentication = request.Authentication?.Trim().ToLowerInvariant() ?? string.Empty;
        if (authentication is not ("os-context" or "explicit"))
            throw new ArgumentException("Authentication must be os-context or explicit.");

        var ldapAuth = request.LdapAuth?.Trim().ToLowerInvariant() switch
        {
            "negotiate" => LdapAuthenticationMode.Negotiate,
            "ntlm" => LdapAuthenticationMode.Ntlm,
            _ => throw new ArgumentException("LDAP authentication must be negotiate or ntlm.")
        };

        if (request.LdapPort is < 1 or > 65535)
            throw new ArgumentException("LDAP port is outside the supported range.");

        UiNetworkCredential? credential = null;
        try
        {
            if (authentication == "explicit")
            {
                if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrEmpty(request.Password))
                    throw new ArgumentException("Explicit authentication requires username and password.");
                if (IPAddress.TryParse(target, out _))
                    throw new ArgumentException("Explicit credentials require a DNS hostname target.");
                credential = UiNetworkCredential.Create(request.Username.Trim(), request.Password);
            }
            else if (ldapAuth == LdapAuthenticationMode.Ntlm)
            {
                throw new ArgumentException("Explicit LDAP NTLM mode requires explicit credentials.");
            }

            var authorities = (request.SysvolAuthorities ?? [])
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value.Trim())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            return new UiPreparedAssessment(target, profile, request.UseLdaps, request.LdapPort, ldapAuth, authorities, credential);
        }
        catch
        {
            credential?.Dispose();
            throw;
        }
        finally
        {
            request.Password = null;
        }
    }

    public void Dispose() => Credential?.Dispose();
}

internal sealed class UiNetworkCredential : IDisposable
{
    private readonly SecureString password;
    private bool disposed;

    private UiNetworkCredential(NetworkCredential credential, SecureString password)
    {
        Credential = credential;
        this.password = password;
    }

    public NetworkCredential Credential { get; }

    public static UiNetworkCredential Create(string username, string plainTextPassword)
    {
        var secure = new SecureString();
        try
        {
            foreach (var character in plainTextPassword)
                secure.AppendChar(character);
            secure.MakeReadOnly();

            var separator = username.IndexOf('\\');
            var credential = separator > 0 && separator < username.Length - 1
                ? new NetworkCredential(username[(separator + 1)..], secure, username[..separator])
                : new NetworkCredential(username, secure);
            return new UiNetworkCredential(credential, secure);
        }
        catch
        {
            secure.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        if (disposed)
            return;
        password.Dispose();
        disposed = true;
    }
}

internal static class UiCollectionComposition
{
    private static readonly TimeSpan LdapBindTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan LdapRequestTimeout = TimeSpan.FromSeconds(30);

    public static IReadOnlyCollection<ICollector> CreateCollectors(UiPreparedAssessment assessment)
    {
        ArgumentNullException.ThrowIfNull(assessment);
        var credential = assessment.NetworkCredential;
        var ldapFactory = new SystemLdapClientFactory(new LdapClientOptions
        {
            Port = assessment.LdapPort ?? (assessment.UseLdaps ? 636 : 389),
            UseLdaps = assessment.UseLdaps,
            BindTimeout = LdapBindTimeout,
            RequestTimeout = LdapRequestTimeout,
            AuthenticationMode = assessment.LdapAuthenticationMode,
            TreatTargetAsFullyQualifiedDnsHostName = credential is not null,
            Credential = credential
        });

        IReadOnlySysvolClientFactory sysvolFactory = credential is null
            ? new SystemSysvolClientFactory()
            : new PortableKerberosSysvolClientFactory(credential, assessment.Target);
        var sysvolOptions = new SysvolClientOptions { ApprovedAuthorities = assessment.ApprovedSysvolAuthorities };

        return
        [
            new RootDseCollector(ldapFactory),
            new DomainMetadataCollector(ldapFactory),
            new SecurityPolicyCollector(ldapFactory),
            new DirectoryObjectsCollector(ldapFactory),
            new GroupMembershipCollector(ldapFactory),
            new TrustCollector(ldapFactory),
            new AclCollector(ldapFactory),
            new GpoMetadataCollector(ldapFactory),
            new GpoLinkCollector(ldapFactory),
            new GpoSysvolCollector(sysvolFactory, sysvolOptions)
        ];
    }
}

internal sealed record UiScanResult(AdSnapshot Snapshot, CollectionExecutionResult Execution);

internal static class UiScanWorkflow
{
    public static async Task<UiScanResult> ExecuteAsync(string target, string outputPath, string productVersion, CollectionProfile profile, IReadOnlyCollection<ICollector> collectors, Action<CollectionProgressEvent>? progress, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(productVersion);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(collectors);

        var planner = new CollectionPlanner();
        var executor = new CollectionExecutor();
        var assembler = new SnapshotAssembler();
        var serializer = new DogadArtifactSerializer();
        var plan = planner.BuildPlan(profile, collectors);
        var scanId = Guid.NewGuid();
        var execution = await executor.ExecuteAsync(plan, scanId, target, cancellationToken, progress).ConfigureAwait(false);

        var snapshot = assembler.Assemble(new SnapshotAssemblyRequest
        {
            SnapshotId = scanId,
            ProductVersion = productVersion,
            StartedAt = execution.StartedAt,
            CompletedAt = execution.CompletedAt,
            Target = BuildTargetIdentity(target, execution.Data.Content),
            CollectionProfile = profile.Name,
            RequestedCapabilities = profile.RequestedCapabilities,
            Fragments = [execution.Data]
        });

        await WriteVerifiedArtifactAsync(snapshot, outputPath, serializer, cancellationToken).ConfigureAwait(false);
        return new UiScanResult(snapshot, execution);
    }

    private static async Task WriteVerifiedArtifactAsync(AdSnapshot snapshot, string outputPath, DogadArtifactSerializer serializer, CancellationToken cancellationToken)
    {
        var fullOutputPath = Path.GetFullPath(outputPath);
        var directory = Path.GetDirectoryName(fullOutputPath)!;
        Directory.CreateDirectory(directory);
        var temporaryPath = fullOutputPath + $".tmp-{Guid.NewGuid():N}";
        var options = new DogadWriteOptions();

        try
        {
            var fileOptions = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                BufferSize = 64 * 1024,
                Options = FileOptions.Asynchronous | FileOptions.SequentialScan
            };
            if (!OperatingSystem.IsWindows())
                fileOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

            await using (var destination = new FileStream(temporaryPath, fileOptions))
                await serializer.WriteAsync(snapshot, destination, options, cancellationToken).ConfigureAwait(false);

            AdSnapshot verified;
            await using (var source = new FileStream(temporaryPath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
                verified = await serializer.ReadAsync(source, options.ToReadOptions(), cancellationToken).ConfigureAwait(false);

            if (verified.Metadata.SnapshotId != snapshot.Metadata.SnapshotId || verified.Metadata.CompletionStatus != snapshot.Metadata.CompletionStatus)
                throw new InvalidDataException("The written .dogad artifact failed verified round-trip.");

            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporaryPath, fullOutputPath, overwrite: false);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(fullOutputPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        finally
        {
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
        }
    }

    private static TargetIdentity BuildTargetIdentity(string initialTarget, SnapshotContent content)
    {
        var environment = content.DirectoryEnvironment;
        var domain = content.Domains.FirstOrDefault();
        return new TargetIdentity
        {
            InitialTarget = initialTarget,
            ForestDnsName = NamingContextToDnsName(environment?.RootDomainNamingContext),
            DomainDnsName = domain?.DnsName,
            DomainSid = domain?.Sid,
            RootDseDnsHostName = environment?.DnsHostName
        };
    }

    private static string? NamingContextToDnsName(string? namingContext)
    {
        if (string.IsNullOrWhiteSpace(namingContext))
            return null;
        var labels = namingContext.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length == 0 || labels.Any(label => !label.StartsWith("DC=", StringComparison.OrdinalIgnoreCase) || label.Length <= 3))
            return null;
        return string.Join('.', labels.Select(label => label[3..]));
    }
}
