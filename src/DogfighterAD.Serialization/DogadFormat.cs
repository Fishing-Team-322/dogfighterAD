namespace DogfighterAD.Serialization;

public static class DogadFormat
{
    public const string ArtifactType = "dogfighterad.snapshot";
    public const int CurrentVersion = 1;
    public const string SerializationId = "canonical-json-v1";
    public const string ManifestEntryName = "manifest.json";
    public const string SnapshotEntryName = "snapshot.json";
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

public sealed record DogadReadOptions
{
    public int MaxManifestBytes { get; init; } = 1024 * 1024;
    public long MaxSnapshotBytes { get; init; } = 512L * 1024 * 1024;
}
