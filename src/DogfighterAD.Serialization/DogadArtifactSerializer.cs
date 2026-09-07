using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Serialization;

public sealed class DogadArtifactSerializer
{
    private static readonly DateTimeOffset StableZipTimestamp =
        new(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public Task WriteAsync(
        AdSnapshot snapshot,
        Stream destination,
        CancellationToken cancellationToken = default) =>
        WriteAsync(snapshot, destination, new DogadWriteOptions(), cancellationToken);

    public async Task WriteAsync(
        AdSnapshot snapshot,
        Stream destination,
        DogadWriteOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(options);
        if (!destination.CanWrite)
        {
            throw new ArgumentException("Destination stream must be writable.", nameof(destination));
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (destination.CanSeek && (destination.Position != 0 || destination.Length != 0))
            throw new ArgumentException("Destination must be an empty stream at position zero.", nameof(destination));
        ValidateWriteOptions(options);

        var violations = SnapshotInvariantValidator.Validate(snapshot);
        if (violations.Count > 0)
        {
            throw DogadArtifactException.InvalidSnapshot(violations);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var canonical = SnapshotCanonicalizer.Canonicalize(snapshot);
        using var payloadBuffer = new MemoryStream();
        using (var boundedPayload = new BudgetWriteStream(
                   payloadBuffer, options.MaxSnapshotBytes, "dogad.payload.write-limit-exceeded"))
        {
            await JsonSerializer.SerializeAsync(boundedPayload, canonical, JsonOptions, cancellationToken)
                .ConfigureAwait(false);
        }
        var payload = payloadBuffer.GetBuffer().AsMemory(0, checked((int)payloadBuffer.Length));
        cancellationToken.ThrowIfCancellationRequested();

        if (payload.Length > options.MaxSnapshotBytes)
        {
            throw new DogadArtifactException(
                "dogad.payload.write-limit-exceeded",
                $"Canonical snapshot payload is {payload.Length} bytes and exceeds the configured write limit of {options.MaxSnapshotBytes} bytes.");
        }

        var manifest = new DogadManifest
        {
            ArtifactType = DogadFormat.ArtifactType,
            FormatVersion = DogadFormat.CurrentVersion,
            SerializationId = DogadFormat.SerializationId,
            SnapshotSchemaVersion = canonical.Metadata.SchemaVersion,
            SnapshotId = canonical.Metadata.SnapshotId,
            ProductVersion = canonical.Metadata.ProductVersion,
            SnapshotCompletedAt = canonical.Metadata.CompletedAt,
            PayloadPath = DogadFormat.SnapshotEntryName,
            PayloadLength = payload.Length,
            PayloadSha256 = Convert.ToHexStringLower(SHA256.HashData(payload.Span))
        };
        using var manifestBuffer = new MemoryStream();
        using (var boundedManifest = new BudgetWriteStream(
                   manifestBuffer, options.MaxManifestBytes, "dogad.manifest.write-limit-exceeded"))
        {
            await JsonSerializer.SerializeAsync(boundedManifest, manifest, JsonOptions, cancellationToken)
                .ConfigureAwait(false);
        }
        var manifestBytes = manifestBuffer.ToArray();
        using var boundedDestination = new BudgetWriteStream(
            destination, options.MaxContainerBytes, "dogad.container.write-limit-exceeded");
        using var archive = new ZipArchive(boundedDestination, ZipArchiveMode.Create, leaveOpen: true);
        await WriteEntryAsync(
            archive,
            DogadFormat.ManifestEntryName,
            manifestBytes,
            cancellationToken).ConfigureAwait(false);
        await WriteEntryAsync(
            archive,
            DogadFormat.SnapshotEntryName,
            payload,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<AdSnapshot> ReadAsync(
        Stream source,
        DogadReadOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (!source.CanRead)
        {
            throw new ArgumentException("Source stream must be readable.", nameof(source));
        }

        var limits = options ?? new DogadReadOptions();
        ValidateReadOptions(limits);

        FileStream? boundedCopy = null;
        try
        {
            Stream archiveSource;
            if (source.CanSeek)
            {
                ValidateSeekableContainerLength(source, limits.MaxContainerBytes);
                archiveSource = source;
            }
            else
            {
                boundedCopy = await CopyNonSeekableContainerAsync(
                    source,
                    limits.MaxContainerBytes,
                    cancellationToken).ConfigureAwait(false);
                archiveSource = boundedCopy;
            }

            await ZipContainerPreflight.ValidateAsync(archiveSource, limits, cancellationToken).ConfigureAwait(false);
            using var archive = new ZipArchive(archiveSource, ZipArchiveMode.Read, leaveOpen: true);
            ValidateContainerEntries(archive, limits);
            var manifestEntry = GetRequiredUniqueEntry(archive, DogadFormat.ManifestEntryName);
            var payloadEntry = GetRequiredUniqueEntry(archive, DogadFormat.SnapshotEntryName);

            var manifestBytes = await ReadEntryBoundedAsync(
                manifestEntry,
                limits.MaxManifestBytes,
                cancellationToken).ConfigureAwait(false);
            var manifest = DeserializeManifest(manifestBytes);
            ValidateManifest(manifest);

            if (!StringComparer.Ordinal.Equals(manifest.PayloadPath, DogadFormat.SnapshotEntryName))
            {
                throw new DogadArtifactException(
                    "dogad.manifest.payload-path-invalid",
                    $"Manifest payload path '{manifest.PayloadPath}' is not supported by format v{DogadFormat.CurrentVersion}.");
            }

            if (manifest.PayloadLength < 0 || manifest.PayloadLength > limits.MaxSnapshotBytes)
            {
                throw new DogadArtifactException(
                    "dogad.payload.length-invalid",
                    $"Manifest payload length {manifest.PayloadLength} is outside the configured read limit.");
            }

            var payload = await ReadEntryBoundedAsync(
                payloadEntry,
                limits.MaxSnapshotBytes,
                cancellationToken).ConfigureAwait(false);
            if (payload.LongLength != manifest.PayloadLength)
            {
                throw new DogadArtifactException(
                    "dogad.payload.length-mismatch",
                    $"Snapshot payload length {payload.LongLength} does not match manifest length {manifest.PayloadLength}.");
            }

            var actualHash = Convert.ToHexStringLower(SHA256.HashData(payload));
            if (!StringComparer.OrdinalIgnoreCase.Equals(actualHash, manifest.PayloadSha256))
            {
                throw new DogadArtifactException(
                    "dogad.payload.hash-mismatch",
                    "Snapshot payload SHA-256 does not match the manifest.");
            }

            AdSnapshot snapshot;
            try
            {
                snapshot = JsonSerializer.Deserialize<AdSnapshot>(payload, JsonOptions)
                    ?? throw new JsonException("Snapshot payload deserialized to null.");
            }
            catch (JsonException exception)
            {
                throw new DogadArtifactException(
                    "dogad.snapshot.json-invalid",
                    "Snapshot payload is not valid DogfighterAD snapshot JSON.",
                    exception);
            }

            if (snapshot.Metadata is null ||
                snapshot.Metadata.CompletedAt != manifest.SnapshotCompletedAt ||
                snapshot.Metadata.SnapshotId != manifest.SnapshotId ||
                snapshot.Metadata.SchemaVersion != manifest.SnapshotSchemaVersion ||
                !StringComparer.Ordinal.Equals(snapshot.Metadata.ProductVersion, manifest.ProductVersion))
            {
                throw new DogadArtifactException(
                    "dogad.manifest.snapshot-mismatch",
                    "Manifest identity/schema/product/completion metadata does not match snapshot payload metadata.");
            }

            var violations = SnapshotInvariantValidator.Validate(snapshot);
            if (violations.Count > 0)
            {
                throw DogadArtifactException.InvalidSnapshot(violations);
            }

            var canonical = SnapshotCanonicalizer.Canonicalize(snapshot);
            using var comparison = new CanonicalComparisonStream(payload);
            await JsonSerializer.SerializeAsync(comparison, canonical, JsonOptions, cancellationToken).ConfigureAwait(false);
            comparison.ValidateComplete();

            return canonical;
        }
        catch (DogadArtifactException)
        {
            throw;
        }
        catch (EndOfStreamException exception)
        {
            throw new DogadArtifactException("dogad.container.invalid", "The .dogad container is truncated.", exception);
        }
        catch (InvalidDataException exception)
        {
            throw new DogadArtifactException(
                "dogad.container.invalid",
                "The .dogad container is not a readable ZIP artifact.",
                exception);
        }
        finally
        {
            boundedCopy?.Dispose();
        }
    }

    internal static byte[] SerializeCanonicalSnapshot(AdSnapshot snapshot) =>
        JsonSerializer.SerializeToUtf8Bytes(SnapshotCanonicalizer.Canonicalize(snapshot), JsonOptions);

    private static async Task WriteEntryAsync(
        ZipArchive archive,
        string name,
        ReadOnlyMemory<byte> bytes,
        CancellationToken cancellationToken)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
        entry.LastWriteTime = StableZipTimestamp;
        entry.ExternalAttributes = 0;
        await using var stream = entry.Open();
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
    }

    private static void ValidateSeekableContainerLength(Stream source, long maxContainerBytes)
    {
        if (source.Position != 0)
        {
            throw new DogadArtifactException("dogad.container.position-invalid", "A seekable .dogad stream must start at position zero.");
        }
        if (source.Length < 0 || source.Length > maxContainerBytes)
        {
            throw new DogadArtifactException("dogad.container.too-large", "The complete .dogad container exceeds the configured input budget.");
        }
    }

    private static async Task<FileStream> CopyNonSeekableContainerAsync(
        Stream source,
        long maxContainerBytes,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var path = Path.Combine(Path.GetTempPath(), $"dogad-input-{Guid.NewGuid():N}.tmp");
        var fileOptions = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
            Options = FileOptions.Asynchronous | FileOptions.DeleteOnClose,
            BufferSize = 64 * 1024
        };
        if (!OperatingSystem.IsWindows())
            fileOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        var output = new FileStream(path, fileOptions);
        var buffer = new byte[64 * 1024];
        long total = 0;
        try
        {
            while (true)
            {
                var requested = (int)Math.Min(buffer.Length, maxContainerBytes - total + 1);
                var read = await source.ReadAsync(buffer.AsMemory(0, requested), cancellationToken).ConfigureAwait(false);
                if (read == 0) break;
                total += read;
                if (total > maxContainerBytes)
                    throw new DogadArtifactException("dogad.container.too-large", "Non-seekable .dogad input exceeded its byte budget.");
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            output.Position = 0;
            return output;
        }
        catch
        {
            await output.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static void ValidateContainerEntries(ZipArchive archive, DogadReadOptions options)
    {
        if (archive.Entries.Count > options.MaxEntryCount)
        {
            throw new DogadArtifactException(
                "dogad.container.entry-count-invalid",
                $".dogad container has {archive.Entries.Count} entries and exceeds the configured limit of {options.MaxEntryCount}.");
        }

        foreach (var entry in archive.Entries)
        {
            if (entry.FullName.Length > options.MaxEntryNameChars)
            {
                throw new DogadArtifactException(
                    "dogad.container.entry-name-too-long",
                    $".dogad contains an entry name longer than the configured {options.MaxEntryNameChars}-character limit.");
            }
        }

        var unexpected = archive.Entries.FirstOrDefault(entry =>
            !StringComparer.Ordinal.Equals(entry.FullName, DogadFormat.ManifestEntryName) &&
            !StringComparer.Ordinal.Equals(entry.FullName, DogadFormat.SnapshotEntryName));

        if (unexpected is not null)
        {
            throw new DogadArtifactException(
                "dogad.container.entry-unexpected",
                $".dogad format v{DogadFormat.CurrentVersion} does not allow entry '{TruncateEntryName(unexpected.FullName)}'.");
        }
    }

    private static string TruncateEntryName(string name)
    {
        const int diagnosticLimit = 80;
        return name.Length <= diagnosticLimit
            ? name
            : name[..diagnosticLimit] + "...";
    }

    private static ZipArchiveEntry GetRequiredUniqueEntry(ZipArchive archive, string name)
    {
        var matches = archive.Entries
            .Where(entry => StringComparer.Ordinal.Equals(entry.FullName, name))
            .ToArray();
        return matches.Length switch
        {
            1 => matches[0],
            0 => throw new DogadArtifactException(
                "dogad.container.entry-missing",
                $"Required .dogad entry '{name}' is missing."),
            _ => throw new DogadArtifactException(
                "dogad.container.entry-duplicate",
                $"Required .dogad entry '{name}' appears more than once.")
        };
    }

    private static async Task<byte[]> ReadEntryBoundedAsync(
        ZipArchiveEntry entry,
        long maxBytes,
        CancellationToken cancellationToken)
    {
        if (entry.Length > maxBytes)
        {
            throw new DogadArtifactException(
                "dogad.container.entry-too-large",
                $"Entry '{entry.FullName}' is {entry.Length} bytes and exceeds the configured limit of {maxBytes} bytes.");
        }

        await using var input = entry.Open();
        // The ZIP header is untrusted. Do not allocate its declared expanded size up front.
        using var output = new MemoryStream((int)Math.Min(entry.Length, 64 * 1024));
        var effectiveLimit = Math.Min(entry.Length, maxBytes);
        var buffer = new byte[64 * 1024];
        long total = 0;
        while (true)
        {
            var requested = (int)Math.Min(buffer.Length, effectiveLimit - total + 1);
            var read = await input.ReadAsync(buffer.AsMemory(0, requested), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
            if (total > effectiveLimit)
            {
                throw new DogadArtifactException(
                    "dogad.container.entry-too-large",
                    $"Entry '{entry.FullName}' exceeded the configured limit while reading.");
            }

            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        return output.ToArray();
    }

    private static DogadManifest DeserializeManifest(byte[] bytes)
    {
        try
        {
            return JsonSerializer.Deserialize<DogadManifest>(bytes, JsonOptions)
                ?? throw new JsonException("Manifest deserialized to null.");
        }
        catch (JsonException exception)
        {
            throw new DogadArtifactException(
                "dogad.manifest.json-invalid",
                "The .dogad manifest is invalid JSON.",
                exception);
        }
    }

    private static void ValidateManifest(DogadManifest manifest)
    {
        if (!StringComparer.Ordinal.Equals(manifest.ArtifactType, DogadFormat.ArtifactType))
        {
            throw new DogadArtifactException(
                "dogad.manifest.artifact-type-unsupported",
                $"Artifact type '{manifest.ArtifactType}' is not supported.");
        }

        if (manifest.FormatVersion != DogadFormat.CurrentVersion)
        {
            throw new DogadArtifactException(
                "dogad.manifest.format-version-unsupported",
                $".dogad format version {manifest.FormatVersion} is not supported; expected {DogadFormat.CurrentVersion}.");
        }

        if (!StringComparer.Ordinal.Equals(manifest.SerializationId, DogadFormat.SerializationId))
        {
            throw new DogadArtifactException(
                "dogad.manifest.serialization-unsupported",
                $"Serialization '{manifest.SerializationId}' is not supported.");
        }

        if (manifest.SnapshotSchemaVersion != SnapshotSchema.CurrentVersion)
        {
            throw new DogadArtifactException(
                "dogad.manifest.snapshot-schema-unsupported",
                $"Snapshot schema {manifest.SnapshotSchemaVersion} is not supported; expected {SnapshotSchema.CurrentVersion}.");
        }

        if (string.IsNullOrWhiteSpace(manifest.ProductVersion) ||
            string.IsNullOrWhiteSpace(manifest.PayloadPath) ||
            string.IsNullOrWhiteSpace(manifest.PayloadSha256) ||
            manifest.PayloadSha256.Length != 64 ||
            manifest.PayloadSha256.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new DogadArtifactException(
                "dogad.manifest.invalid",
                "The .dogad manifest contains invalid required fields.");
        }
    }

    private static void ValidateWriteOptions(DogadWriteOptions options)
    {
        if (options.MaxSnapshotBytes < 1 || options.MaxSnapshotBytes > int.MaxValue ||
            options.MaxManifestBytes < 1 || options.MaxContainerBytes < 1 || options.MaxContainerBytes >= uint.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(options), ".dogad write payload limit must be positive.");
        }
    }

    private static void ValidateReadOptions(DogadReadOptions options)
    {
        if (options.MaxManifestBytes < 1 ||
            options.MaxSnapshotBytes < 1 || options.MaxSnapshotBytes > int.MaxValue ||
            options.MaxContainerBytes < 1 || options.MaxContainerBytes >= uint.MaxValue ||
            options.MaxCentralDirectoryBytes < 1 ||
            options.MaxEntryCount < 2 ||
            options.MaxEntryNameChars < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(options), ".dogad read limits must be positive and allow the two required entries.");
        }
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = false,
            WriteIndented = false,
            AllowTrailingCommas = false,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 128,
            RespectNullableAnnotations = true
        };
        options.Converters.Add(new JsonStringEnumConverter(allowIntegerValues: false));
        return options;
    }
}

public sealed class DogadArtifactException : IOException
{
    public DogadArtifactException(string code, string message, Exception? innerException = null)
        : base($"{code}: {message}", innerException)
    {
        Code = code;
    }

    public string Code { get; }

    internal static DogadArtifactException InvalidSnapshot(
        IReadOnlyList<SnapshotInvariantViolation> violations) =>
        new(
            "dogad.snapshot.invariant-invalid",
            $"Snapshot violates {violations.Count} invariant(s): " +
            string.Join("; ", violations.Select(item => $"{item.Code}: {item.Message}")));
}
