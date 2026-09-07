namespace DogfighterAD.Serialization;

public static class DogadFormat
{
    public const string ArtifactType = "dogfighterad.snapshot";
    public const int CurrentVersion = 1;
    public const string SerializationId = "canonical-json-v1";
    public const string ManifestEntryName = "manifest.json";
    public const string SnapshotEntryName = "snapshot.json";

    public const int DefaultMaxManifestBytes = 1024 * 1024;
    public const long DefaultMaxSnapshotBytes = 512L * 1024 * 1024;
    public const long DefaultMaxContainerBytes = 576L * 1024 * 1024;
}

public sealed record DogadManifest
{
    public required string ArtifactType { get; init; }
    public required int FormatVersion { get; init; }
    public required string SerializationId { get; init; }
    public required int SnapshotSchemaVersion { get; init; }
    public required Guid SnapshotId { get; init; }
    public required string ProductVersion { get; init; }
    public required DateTimeOffset SnapshotCompletedAt { get; init; }
    public required string PayloadPath { get; init; }
    public required long PayloadLength { get; init; }
    public required string PayloadSha256 { get; init; }
}

public sealed record DogadWriteOptions
{
    /// <summary>
    /// Maximum canonical snapshot JSON payload that the writer is allowed to publish. The default
    /// intentionally matches the strict reader payload budget used by CLI verified readback.
    /// </summary>
    public long MaxSnapshotBytes { get; init; } = DogadFormat.DefaultMaxSnapshotBytes;
}

public sealed record DogadReadOptions
{
    public int MaxManifestBytes { get; init; } = DogadFormat.DefaultMaxManifestBytes;
    public long MaxSnapshotBytes { get; init; } = DogadFormat.DefaultMaxSnapshotBytes;

    /// <summary>
    /// Maximum bytes accepted for the complete ZIP container before ZipArchive is constructed.
    /// Non-seekable inputs are copied with this bound and cancellation into a seekable buffer first.
    /// </summary>
    public long MaxContainerBytes { get; init; } = DogadFormat.DefaultMaxContainerBytes;

    public int MaxEntryCount { get; init; } = 2;
    public int MaxEntryNameChars { get; init; } = 128;
}
