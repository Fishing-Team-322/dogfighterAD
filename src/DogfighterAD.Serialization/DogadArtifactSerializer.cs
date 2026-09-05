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

    public async Task WriteAsync(
        AdSnapshot snapshot,
        Stream destination,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(destination);
        if (!destination.CanWrite)
        {
            throw new ArgumentException("Destination stream must be writable.", nameof(destination));
        }

        var violations = SnapshotInvariantValidator.Validate(snapshot);
        if (violations.Count > 0)
        {
            throw DogadArtifactException.InvalidSnapshot(violations);
        }

        var canonical = SnapshotCanonicalizer.Canonicalize(snapshot);
        var payload = JsonSerializer.SerializeToUtf8Bytes(canonical, JsonOptions);
        cancellationToken.ThrowIfCancellationRequested();

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
            PayloadLength = payload.LongLength,
            PayloadSha256 = Convert.ToHexStringLower(SHA256.HashData(payload))
        };
        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);

        using var archive = new ZipArchive(destination, ZipArchiveMode.Create, leaveOpen: true);
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

        try
        {
            using var archive = new ZipArchive(source, ZipArchiveMode.Read, leaveOpen: true);
            ValidateContainerEntries(archive);
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

            if (snapshot.Metadata.SnapshotId != manifest.SnapshotId ||
                snapshot.Metadata.SchemaVersion != manifest.SnapshotSchemaVersion ||
                !StringComparer.Ordinal.Equals(snapshot.Metadata.ProductVersion, manifest.ProductVersion))
            {
                throw new DogadArtifactException(
                    "dogad.manifest.snapshot-mismatch",
                    "Manifest identity/schema/product metadata does not match snapshot payload metadata.");
            }

            var violations = SnapshotInvariantValidator.Validate(snapshot);
            if (violations.Count > 0)
            {
                throw DogadArtifactException.InvalidSnapshot(violations);
            }

            var canonical = SnapshotCanonicalizer.Canonicalize(snapshot);
            var canonicalPayload = JsonSerializer.SerializeToUtf8Bytes(canonical, JsonOptions);
            if (!payload.AsSpan().SequenceEqual(canonicalPayload))
            {
                throw new DogadArtifactException(
                    "dogad.payload.noncanonical",
                    $"Snapshot payload does not match serialization '{DogadFormat.SerializationId}'.");
            }

            return canonical;
        }
        catch (DogadArtifactException)
        {
            throw;
        }
        catch (InvalidDataException exception)
        {
            throw new DogadArtifactException(
                "dogad.container.invalid",
                "The .dogad container is not a readable ZIP artifact.",
                exception);
        }
    }

    internal static byte[] SerializeCanonicalSnapshot(AdSnapshot snapshot) =>
        JsonSerializer.SerializeToUtf8Bytes(SnapshotCanonicalizer.Canonicalize(snapshot), JsonOptions);

    private static async Task WriteEntryAsync(
        ZipArchive archive,
        string name,
        byte[] bytes,
        CancellationToken cancellationToken)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
        entry.LastWriteTime = StableZipTimestamp;
        entry.ExternalAttributes = 0;
        await using var stream = entry.Open();
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
    }

    private static void ValidateContainerEntries(ZipArchive archive)
    {
        var unexpected = archive.Entries
            .Where(entry =>
                !StringComparer.Ordinal.Equals(entry.FullName, DogadFormat.ManifestEntryName) &&
                !StringComparer.Ordinal.Equals(entry.FullName, DogadFormat.SnapshotEntryName))
            .Select(entry => entry.FullName)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        if (unexpected.Length > 0)
        {
            throw new DogadArtifactException(
                "dogad.container.entry-unexpected",
                $".dogad format v{DogadFormat.CurrentVersion} does not allow unexpected entries: {string.Join(", ", unexpected)}.");
        }
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
        using var output = entry.Length <= int.MaxValue
            ? new MemoryStream((int)entry.Length)
            : new MemoryStream();
        var buffer = new byte[64 * 1024];
        long total = 0;
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
            if (total > maxBytes)
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
            manifest.PayloadSha256.Length != 64 ||
            manifest.PayloadSha256.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new DogadArtifactException(
                "dogad.manifest.invalid",
                "The .dogad manifest contains invalid required fields.");
        }
    }

    private static void ValidateReadOptions(DogadReadOptions options)
    {
        if (options.MaxManifestBytes < 1 || options.MaxSnapshotBytes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(options), ".dogad read limits must be positive.");
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
            MaxDepth = 128
        };
        options.Converters.Add(new JsonStringEnumConverter());
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
