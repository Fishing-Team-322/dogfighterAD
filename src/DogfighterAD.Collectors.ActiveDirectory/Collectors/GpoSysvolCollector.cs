using System.Globalization;
using System.Security.Cryptography;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Sysvol;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Collectors.ActiveDirectory.Collectors;

/// <summary>
/// Reads Group Policy Templates from SYSVOL without modifying or locking policy files.
/// v1 inventories every file and normalizes only explicitly supported policy formats.
/// </summary>
public sealed class GpoSysvolCollector : ICollector
{
    public const string CollectorId = "ad.sysvol.gpo-settings";
    public const string CollectorVersion = "0.1.0";

    private static readonly IReadOnlySet<string> ProvidedCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.GroupPolicySysvol
        };

    private static readonly IReadOnlySet<string> RequiredCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.GroupPolicyMetadata
        };

    private readonly IReadOnlySysvolClientFactory _clientFactory;
    private readonly SysvolClientOptions _options;
    private readonly TimeProvider _timeProvider;

    public GpoSysvolCollector(
        IReadOnlySysvolClientFactory clientFactory,
        SysvolClientOptions? options = null,
        TimeProvider? timeProvider = null)
    {
        _clientFactory = clientFactory ?? throw new ArgumentNullException(nameof(clientFactory));
        _options = options ?? new SysvolClientOptions();
        _timeProvider = timeProvider ?? TimeProvider.System;

        if (_options.MaxFileBytes < 1 || _options.MaxFilesPerGpo < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "SYSVOL limits must be positive.");
        }

        if (_options.ApprovedAuthorities is null ||
            _options.ApprovedAuthorities.Any(authority => !SysvolPathPolicy.IsValidAuthority(authority)))
        {
            throw new ArgumentException(
                "Approved SYSVOL authorities must be simple host/domain names without path or port components.",
                nameof(options));
        }
    }

    public string Id => CollectorId;
    public string Version => CollectorVersion;
    public IReadOnlySet<string> ProvidesCapabilities => ProvidedCapabilities;
    public IReadOnlySet<string> RequiresCapabilities => RequiredCapabilities;

    public async Task<CollectorResult> CollectAsync(
        CollectionContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var startedAt = _timeProvider.GetUtcNow();
        var files = new List<AdGpoSysvolFile>();
        var settings = new List<AdGpoSetting>();
        var observations = new List<ObservedFact>();
        var issues = new List<CollectionIssue>();
        IReadOnlySysvolClient? client = null;

        try
        {
            foreach (var gpo in context.AvailableData.Content.GroupPolicyObjects
                         .OrderBy(item => item.GpoGuid))
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (string.IsNullOrWhiteSpace(gpo.FileSystemPath))
                {
                    issues.Add(Issue(
                        "collection.gpo.sysvol.path-missing",
                        $"GPO {gpo.GpoGuid:D} has no gPCFileSysPath and cannot be read from SYSVOL.",
                        context.Target));
                    continue;
                }

                if (!SysvolPathPolicy.TryValidateGpoRoot(
                        gpo.FileSystemPath,
                        gpo.DistinguishedName,
                        gpo.GpoGuid,
                        context.Target,
                        _options.ApprovedAuthorities,
                        out var sysvolScope))
                {
                    issues.Add(Issue(
                        "collection.gpo.sysvol.path-out-of-scope",
                        $"GPO {gpo.GpoGuid:D} gPCFileSysPath is outside the approved SYSVOL scope.",
                        context.Target));
                    continue;
                }

                client ??= await _clientFactory
                    .CreateAsync(cancellationToken)
                    .ConfigureAwait(false);

                try
                {
                    // The isolated SYSVOL client intentionally serializes worker operations. Do not
                    // attempt a file read while its enumeration operation still owns that operation
                    // slot: the worker may be blocked writing its bounded enumeration channel while
                    // the consumer waits for ReadFileAsync to acquire the same slot. Materialize only
                    // validated metadata first, within MaxFilesPerGpo, then read after enumeration has
                    // completed and released the worker operation boundary.
                    var enumeratedFiles = new List<(SysvolFileEntry File, string RelativePath)>();
                    var count = 0;
                    await foreach (var file in client.EnumerateFilesAsync(sysvolScope.RootPath, cancellationToken))
                    {
                        count++;
                        if (count > _options.MaxFilesPerGpo)
                        {
                            issues.Add(Issue(
                                "collection.gpo.sysvol.file-count-limit",
                                $"GPO {gpo.GpoGuid:D} exceeded the {_options.MaxFilesPerGpo} file inventory limit.",
                                context.Target));
                            break;
                        }

                        if (!SysvolPathPolicy.TryValidateFile(sysvolScope, file, out var relativePath))
                        {
                            issues.Add(Issue(
                                "collection.gpo.sysvol.file-out-of-scope",
                                $"GPO {gpo.GpoGuid:D} enumeration returned a file outside the approved policy root.",
                                context.Target));
                            continue;
                        }

                        enumeratedFiles.Add((file, relativePath));
                    }

                    foreach (var (file, relativePath) in enumeratedFiles)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var kind = Classify(relativePath);
                        byte[] content;

                        try
                        {
                            content = await client
                                .ReadFileAsync(file.FullPath, _options.MaxFileBytes, cancellationToken)
                                .ConfigureAwait(false);
                        }
                        catch (SysvolFileTooLargeException)
                        {
                            files.Add(new AdGpoSysvolFile
                            {
                                GpoId = gpo.Id,
                                RelativePath = relativePath,
                                Length = file.Length,
                                LastWriteTimeUtc = file.LastWriteTimeUtc,
                                Kind = kind
                            });
                            issues.Add(Issue(
                                "collection.gpo.sysvol.file-too-large",
                                $"GPO {gpo.GpoGuid:D} file '{relativePath}' exceeds the {_options.MaxFileBytes} byte read limit.",
                                context.Target));
                            continue;
                        }
                        catch (IOException exception)
                        {
                            issues.Add(Issue(
                                "collection.gpo.sysvol.file-read-failed",
                                $"GPO {gpo.GpoGuid:D} file '{relativePath}' could not be read: {exception.GetType().Name}.",
                                context.Target));
                            continue;
                        }
                        catch (UnauthorizedAccessException)
                        {
                            issues.Add(Issue(
                                "collection.gpo.sysvol.file-access-denied",
                                $"Access to GPO {gpo.GpoGuid:D} file '{relativePath}' was denied.",
                                context.Target));
                            continue;
                        }

                        var hash = Convert.ToHexStringLower(SHA256.HashData(content));
                        files.Add(new AdGpoSysvolFile
                        {
                            GpoId = gpo.Id,
                            RelativePath = relativePath,
                            Length = content.LongLength,
                            Sha256 = hash,
                            LastWriteTimeUtc = file.LastWriteTimeUtc,
                            Kind = kind
                        });

                        AddFileFacts(
                            observations,
                            gpo,
                            relativePath,
                            content.LongLength,
                            hash,
                            context.Target,
                            file.FullPath,
                            _timeProvider.GetUtcNow());

                        var parsed = ParseSupportedFile(kind, relativePath, content);
                        if (!parsed.Success)
                        {
                            issues.Add(Issue(
                                "collection.gpo.sysvol.parse-failed",
                                $"GPO {gpo.GpoGuid:D} file '{relativePath}' could not be normalized: {parsed.Error}",
                                context.Target));
                            continue;
                        }

                        foreach (var parsedSetting in parsed.Settings)
                        {
                            var setting = new AdGpoSetting
                            {
                                GpoId = gpo.Id,
                                Scope = parsedSetting.Scope,
                                SourceRelativePath = parsedSetting.SourceRelativePath,
                                Sequence = parsedSetting.Sequence,
                                Kind = parsedSetting.Kind,
                                Section = parsedSetting.Section,
                                Key = parsedSetting.Key,
                                Value = parsedSetting.Value,
                                ValueKind = parsedSetting.ValueKind,
                                Disposition = parsedSetting.Disposition,
                                DataLength = parsedSetting.DataLength
                            };
                            settings.Add(setting);
                            AddSettingFact(
                                observations,
                                gpo,
                                setting,
                                context.Target,
                                file.FullPath,
                                _timeProvider.GetUtcNow());
                        }
                    }
                }
                catch (DirectoryNotFoundException)
                {
                    issues.Add(Issue(
                        "collection.gpo.sysvol.directory-not-found",
                        $"SYSVOL directory for GPO {gpo.GpoGuid:D} was not found.",
                        context.Target));
                }
                catch (UnauthorizedAccessException)
                {
                    issues.Add(Issue(
                        "collection.gpo.sysvol.directory-access-denied",
                        $"Access to the SYSVOL directory for GPO {gpo.GpoGuid:D} was denied.",
                        context.Target));
                }
                catch (IOException exception)
                {
                    issues.Add(Issue(
                        "collection.gpo.sysvol.enumeration-failed",
                        $"SYSVOL enumeration for GPO {gpo.GpoGuid:D} failed: {exception.GetType().Name}.",
                        context.Target));
                }
            }
        }
        finally
        {
            if (client is not null)
            {
                await client.DisposeAsync().ConfigureAwait(false);
            }
        }

        var completedAt = _timeProvider.GetUtcNow();
        var orderedFiles = files
            .OrderBy(item => item.GpoId.Value)
            .ThenBy(item => item.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var orderedSettings = settings
            .OrderBy(item => item.GpoId.Value)
            .ThenBy(item => item.SourceRelativePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Sequence)
            .ThenBy(item => item.Key, StringComparer.Ordinal)
            .ToArray();

        return new CollectorResult(
            CollectorId,
            CollectorVersion,
            new SnapshotFragment
            {
                Content = new SnapshotContent
                {
                    GroupPolicyFiles = orderedFiles,
                    GroupPolicySettings = orderedSettings
                },
                Coverage =
                [
                    new CapabilityCoverage
                    {
                        CapabilityId = CollectionCapabilities.GroupPolicySysvol,
                        ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                            CollectionCapabilities.GroupPolicySysvol),
                        Status = issues.Count == 0
                            ? CapabilityStatus.Complete
                            : CapabilityStatus.Partial,
                        StartedAt = startedAt,
                        CompletedAt = completedAt,
                        ObservedItemCount = orderedFiles.Length,
                        Issues = issues
                            .OrderBy(issue => issue.Code, StringComparer.Ordinal)
                            .ThenBy(issue => issue.Message, StringComparer.Ordinal)
                            .ToArray()
                    }
                ],
                Observations = observations
                    .DistinctBy(fact => fact.FactId, StringComparer.Ordinal)
                    .OrderBy(fact => fact.FactId, StringComparer.Ordinal)
                    .ToArray()
            });
    }

    private static ParsedSettingsResult ParseSupportedFile(
        GpoSysvolFileKind kind,
        string relativePath,
        byte[] content) => kind switch
    {
        GpoSysvolFileKind.GptIni => SysvolPolicyParsers.ParseGptIni(content, relativePath),
        GpoSysvolFileKind.SecurityTemplate => SysvolPolicyParsers.ParseSecurityTemplate(content, relativePath),
        GpoSysvolFileKind.RegistryPolicy => SysvolPolicyParsers.ParseRegistryPolicy(
            content,
            relativePath,
            SysvolPolicyParsers.ScopeFromRelativePath(relativePath)),
        GpoSysvolFileKind.PreferencesXml => SysvolPolicyParsers.ScanPreferencesXml(content, relativePath),
        _ => ParsedSettingsResult.Succeeded([])
    };

    private static GpoSysvolFileKind Classify(string relativePath)
    {
        if (relativePath.Equals("GPT.INI", StringComparison.OrdinalIgnoreCase))
        {
            return GpoSysvolFileKind.GptIni;
        }

        if (relativePath.EndsWith("\\GptTmpl.inf", StringComparison.OrdinalIgnoreCase))
        {
            return GpoSysvolFileKind.SecurityTemplate;
        }

        if (relativePath.Equals("Machine\\Registry.pol", StringComparison.OrdinalIgnoreCase) ||
            relativePath.Equals("User\\Registry.pol", StringComparison.OrdinalIgnoreCase))
        {
            return GpoSysvolFileKind.RegistryPolicy;
        }

        if ((relativePath.StartsWith("Machine\\Preferences\\", StringComparison.OrdinalIgnoreCase) ||
             relativePath.StartsWith("User\\Preferences\\", StringComparison.OrdinalIgnoreCase)) &&
            relativePath.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
        {
            return GpoSysvolFileKind.PreferencesXml;
        }

        return GpoSysvolFileKind.Other;
    }

    private static void AddFileFacts(
        ICollection<ObservedFact> facts,
        AdGroupPolicyObject gpo,
        string relativePath,
        long length,
        string hash,
        string endpoint,
        string locator,
        DateTimeOffset observedAt)
    {
        var subjectId = $"ad-object:{gpo.Id}";
        AddFact(
            facts,
            subjectId,
            $"gpo.sysvol.file.{relativePath}.sha256",
            hash,
            FactValueKind.Text,
            FactDisposition.Stored,
            endpoint,
            locator,
            observedAt);
        AddFact(
            facts,
            subjectId,
            $"gpo.sysvol.file.{relativePath}.length",
            length.ToString(CultureInfo.InvariantCulture),
            FactValueKind.Integer,
            FactDisposition.Stored,
            endpoint,
            locator,
            observedAt);
    }

    private static void AddSettingFact(
        ICollection<ObservedFact> facts,
        AdGroupPolicyObject gpo,
        AdGpoSetting setting,
        string endpoint,
        string locator,
        DateTimeOffset observedAt)
    {
        var subjectId = $"ad-object:{gpo.Id}";
        var safeKey = setting.Key.Replace("\\", "/", StringComparison.Ordinal);
        var path = $"gpo.sysvol.setting.{setting.SourceRelativePath}.{setting.Sequence}.{safeKey}";
        AddFact(
            facts,
            subjectId,
            path,
            setting.Value,
            setting.ValueKind,
            setting.Disposition,
            endpoint,
            locator,
            observedAt);
    }

    private static void AddFact(
        ICollection<ObservedFact> facts,
        string subjectId,
        string path,
        string? value,
        FactValueKind valueKind,
        FactDisposition disposition,
        string endpoint,
        string locator,
        DateTimeOffset observedAt)
    {
        facts.Add(new ObservedFact
        {
            FactId = FactIdFactory.Create(
                CollectionCapabilities.GroupPolicySysvol,
                subjectId,
                path,
                valueKind,
                value),
            CapabilityId = CollectionCapabilities.GroupPolicySysvol,
            SubjectId = subjectId,
            Path = path,
            Value = disposition == FactDisposition.Stored ? value : null,
            ValueKind = valueKind,
            Disposition = disposition,
            Source = new ObservationSource
            {
                CollectorId = CollectorId,
                CollectorVersion = CollectorVersion,
                SourceKind = "sysvol",
                Endpoint = endpoint,
                Locator = locator
            },
            ObservedAt = observedAt
        });
    }

    private static CollectionIssue Issue(string code, string message, string target) =>
        new()
        {
            Code = code,
            Severity = CollectionIssueSeverity.Error,
            Message = message,
            CapabilityId = CollectionCapabilities.GroupPolicySysvol,
            CollectorId = CollectorId,
            Target = target
        };
}
