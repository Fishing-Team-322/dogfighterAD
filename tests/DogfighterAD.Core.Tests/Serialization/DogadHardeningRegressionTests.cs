using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using DogfighterAD.Domain.Snapshots;
using DogfighterAD.Serialization;

namespace DogfighterAD.Core.Tests.Serialization;

public sealed class DogadHardeningRegressionTests
{
    private static readonly DateTimeOffset FixedNow =
        new(2026, 9, 7, 12, 30, 0, TimeSpan.Zero);

    private static readonly JsonSerializerOptions ManifestJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    [Fact]
    public async Task Write_RejectsPayloadBeyondConfiguredWriterBudget()
    {
        var serializer = new DogadArtifactSerializer();
        await using var destination = new MemoryStream();

        var exception = await Assert.ThrowsAsync<DogadArtifactException>(() =>
            serializer.WriteAsync(
                Snapshot(),
                destination,
                new DogadWriteOptions { MaxSnapshotBytes = 32 },
                TestContext.Current.CancellationToken));

        Assert.Equal("dogad.payload.write-limit-exceeded", exception.Code);
        Assert.Equal(0, destination.Length);
    }

    [Theory]
    [InlineData("metadata.target")]
    [InlineData("content")]
    [InlineData("content.users")]
    [InlineData("content.users[0]")]
    [InlineData("observations[0]")]
    public async Task Read_NestedNullsFailAsControlledArtifactErrors(string mutation)
    {
        var serializer = new DogadArtifactSerializer();
        var artifact = await WriteArtifactAsync(serializer, Snapshot());
        var mutated = await MutateSnapshotAsync(artifact, root => ApplyNullMutation(root, mutation));
        await using var input = new MemoryStream(mutated, writable: false);

        var exception = await Assert.ThrowsAsync<DogadArtifactException>(() =>
            serializer.ReadAsync(input, cancellationToken: TestContext.Current.CancellationToken));

        Assert.False(string.IsNullOrWhiteSpace(exception.Code));
        Assert.IsNotType<NullReferenceException>(exception.InnerException);
    }

    [Fact]
    public async Task Read_CompletionStatusContradictingCoverageIsRejected()
    {
        const string capability = CollectionCapabilities.DirectoryUsers;
        var valid = Snapshot() with
        {
            Metadata = Snapshot().Metadata with
            {
                RequestedCapabilities = [capability],
                CompletionStatus = SnapshotCompletionStatus.Failed
            },
            Coverage =
            [
                new CapabilityCoverage
                {
                    CapabilityId = capability,
                    Status = CapabilityStatus.Failed,
                    StartedAt = FixedNow,
                    CompletedAt = FixedNow
                }
            ]
        };
        var serializer = new DogadArtifactSerializer();
        var artifact = await WriteArtifactAsync(serializer, valid);
        var mutated = await MutateSnapshotAsync(artifact, root =>
        {
            var metadata = root["metadata"]!.AsObject();
            metadata["completionStatus"] = "Complete";
        });
        await using var input = new MemoryStream(mutated, writable: false);

        var exception = await Assert.ThrowsAsync<DogadArtifactException>(() =>
            serializer.ReadAsync(input, cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal("dogad.snapshot.invariant-invalid", exception.Code);
        Assert.Contains("snapshot.completion-status.inconsistent", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Read_NonSeekableInputIsBoundedBeforeZipArchiveConstruction()
    {
        var serializer = new DogadArtifactSerializer();
        var artifact = await WriteArtifactAsync(serializer, Snapshot());
        await using var input = new NonSeekableReadStream(artifact);

        var exception = await Assert.ThrowsAsync<DogadArtifactException>(() =>
            serializer.ReadAsync(
                input,
                new DogadReadOptions
                {
                    MaxContainerBytes = artifact.Length - 1,
                    MaxSnapshotBytes = DogadFormat.DefaultMaxSnapshotBytes,
                    MaxManifestBytes = DogadFormat.DefaultMaxManifestBytes,
                    MaxEntryCount = 2,
                    MaxEntryNameChars = 128
                },
                TestContext.Current.CancellationToken));

        Assert.Equal("dogad.container.too-large", exception.Code);
    }

    [Fact]
    public async Task Read_EntryCountBudgetRejectsMetadataFloodWithoutListingNames()
    {
        await using var zip = new MemoryStream();
        using (var archive = new ZipArchive(zip, ZipArchiveMode.Create, leaveOpen: true))
        {
            for (var index = 0; index < 12; index++)
            {
                archive.CreateEntry($"entry-{index:D2}");
            }
        }

        zip.Position = 0;
        var serializer = new DogadArtifactSerializer();
        var exception = await Assert.ThrowsAsync<DogadArtifactException>(() =>
            serializer.ReadAsync(
                zip,
                new DogadReadOptions
                {
                    MaxContainerBytes = 1024 * 1024,
                    MaxSnapshotBytes = 1024,
                    MaxManifestBytes = 1024,
                    MaxEntryCount = 4,
                    MaxEntryNameChars = 128
                },
                TestContext.Current.CancellationToken));

        Assert.Equal("dogad.container.entry-count-invalid", exception.Code);
        Assert.DoesNotContain("entry-11", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Read_EntryNameBudgetRejectsLongNameWithoutEchoingIt()
    {
        var longName = new string('x', 300);
        await using var zip = new MemoryStream();
        using (var archive = new ZipArchive(zip, ZipArchiveMode.Create, leaveOpen: true))
        {
            archive.CreateEntry(DogadFormat.ManifestEntryName);
            archive.CreateEntry(longName);
        }

        zip.Position = 0;
        var serializer = new DogadArtifactSerializer();
        var exception = await Assert.ThrowsAsync<DogadArtifactException>(() =>
            serializer.ReadAsync(
                zip,
                new DogadReadOptions
                {
                    MaxContainerBytes = 1024 * 1024,
                    MaxSnapshotBytes = 1024,
                    MaxManifestBytes = 1024,
                    MaxEntryCount = 2,
                    MaxEntryNameChars = 64
                },
                TestContext.Current.CancellationToken));

        Assert.Equal("dogad.container.entry-name-too-long", exception.Code);
        Assert.DoesNotContain(longName, exception.Message, StringComparison.Ordinal);
    }

    private static void ApplyNullMutation(JsonObject root, string mutation)
    {
        switch (mutation)
        {
            case "metadata.target":
                root["metadata"]!.AsObject()["target"] = null;
                break;
            case "content":
                root["content"] = null;
                break;
            case "content.users":
                root["content"]!.AsObject()["users"] = null;
                break;
            case "content.users[0]":
                root["content"]!.AsObject()["users"] = new JsonArray((JsonNode?)null);
                break;
            case "observations[0]":
                root["observations"] = new JsonArray((JsonNode?)null);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mutation));
        }
    }

    private static async Task<byte[]> WriteArtifactAsync(
        DogadArtifactSerializer serializer,
        AdSnapshot snapshot)
    {
        await using var stream = new MemoryStream();
        await serializer.WriteAsync(snapshot, stream, TestContext.Current.CancellationToken);
        return stream.ToArray();
    }

    private static async Task<byte[]> MutateSnapshotAsync(
        byte[] artifact,
        Action<JsonObject> mutation)
    {
        byte[] payload;
        DogadManifest manifest;
        await using (var source = new MemoryStream(artifact, writable: false))
        using (var archive = new ZipArchive(source, ZipArchiveMode.Read, leaveOpen: true))
        {
            await using var payloadStream = archive.GetEntry(DogadFormat.SnapshotEntryName)!.Open();
            using var payloadBuffer = new MemoryStream();
            await payloadStream.CopyToAsync(payloadBuffer, TestContext.Current.CancellationToken);
            payload = payloadBuffer.ToArray();

            await using var manifestStream = archive.GetEntry(DogadFormat.ManifestEntryName)!.Open();
            manifest = await JsonSerializer.DeserializeAsync<DogadManifest>(
                manifestStream,
                ManifestJson,
                TestContext.Current.CancellationToken)
                ?? throw new InvalidOperationException("Test manifest could not be deserialized.");
        }

        var root = JsonNode.Parse(payload)?.AsObject()
            ?? throw new InvalidOperationException("Test payload could not be parsed.");
        mutation(root);
        payload = JsonSerializer.SerializeToUtf8Bytes(root, ManifestJson);
        manifest = manifest with
        {
            PayloadLength = payload.LongLength,
            PayloadSha256 = Convert.ToHexStringLower(SHA256.HashData(payload))
        };
        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, ManifestJson);

        await using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            await WriteZipEntryAsync(archive, DogadFormat.ManifestEntryName, manifestBytes);
            await WriteZipEntryAsync(archive, DogadFormat.SnapshotEntryName, payload);
        }

        return output.ToArray();
    }

    private static async Task WriteZipEntryAsync(
        ZipArchive archive,
        string name,
        byte[] bytes)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
        entry.LastWriteTime = new DateTimeOffset(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);
        await using var stream = entry.Open();
        await stream.WriteAsync(bytes, TestContext.Current.CancellationToken);
    }

    private static AdSnapshot Snapshot() =>
        new()
        {
            Metadata = new SnapshotMetadata
            {
                SnapshotId = Guid.Parse("f3a8d611-37e2-49a0-a916-3945f27e42b4"),
                SchemaVersion = SnapshotSchema.CurrentVersion,
                ProductVersion = "review-regression",
                StartedAt = FixedNow,
                CompletedAt = FixedNow,
                CompletionStatus = SnapshotCompletionStatus.Complete,
                Target = new TargetIdentity { InitialTarget = "dc.mini.lab" },
                RequestedCapabilities = [],
                Collectors = []
            },
            Content = new SnapshotContent
            {
                Users =
                [
                    new AdUser
                    {
                        Id = new AdObjectId(Guid.Parse("6a1bfd24-b70b-492e-8e64-71d39f6ca455")),
                        DistinguishedName = "CN=Alice,DC=mini,DC=lab",
                        UserAccountControl = 512
                    }
                ]
            }
        };

    private sealed class NonSeekableReadStream : Stream
    {
        private readonly MemoryStream _inner;

        public NonSeekableReadStream(byte[] bytes)
        {
            _inner = new MemoryStream(bytes, writable: false);
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) =>
            _inner.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            _inner.ReadAsync(buffer, cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await _inner.DisposeAsync();
            await base.DisposeAsync();
        }
    }
}
