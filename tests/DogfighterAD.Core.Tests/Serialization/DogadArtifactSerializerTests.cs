using System.IO.Compression;
using System.Text;
using System.Text.Json;
using DogfighterAD.Domain.Snapshots;
using DogfighterAD.Serialization;

namespace DogfighterAD.Core.Tests.Serialization;

public sealed class DogadArtifactSerializerTests
{
    private static readonly DateTimeOffset FixedNow =
        new(2026, 9, 5, 22, 15, 0, TimeSpan.Zero);

    [Fact]
    public async Task WriteThenReadThenWrite_IsByteForByteStable()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var serializer = new DogadArtifactSerializer();
        var snapshot = CreateSnapshot(reverseCollections: false);

        var first = await WriteAsync(serializer, snapshot, cancellationToken);
        await using var input = new MemoryStream(first, writable: false);
        var restored = await serializer.ReadAsync(input, cancellationToken: cancellationToken);
        var second = await WriteAsync(serializer, restored, cancellationToken);

        Assert.Equal(first, second);
        Assert.Equal(snapshot.Metadata.SnapshotId, restored.Metadata.SnapshotId);
        Assert.Contains(restored.Content.GroupPolicySettings, setting =>
            setting.Disposition == FactDisposition.MetadataOnly && setting.Value is null);
    }

    [Fact]
    public async Task Write_LogicalCollectionOrderDoesNotChangeArtifactBytes()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var serializer = new DogadArtifactSerializer();

        var normal = await WriteAsync(
            serializer,
            CreateSnapshot(reverseCollections: false),
            cancellationToken);
        var reversed = await WriteAsync(
            serializer,
            CreateSnapshot(reverseCollections: true),
            cancellationToken);

        Assert.Equal(normal, reversed);
    }

    [Fact]
    public async Task Read_TamperedPayloadFailsHashValidation()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var serializer = new DogadArtifactSerializer();
        var artifact = await WriteAsync(serializer, CreateSnapshot(false), cancellationToken);
        using var mutable = new MemoryStream(artifact.ToArray());
        using (var archive = new ZipArchive(mutable, ZipArchiveMode.Update, leaveOpen: true))
        {
            archive.GetEntry(DogadFormat.SnapshotEntryName)!.Delete();
            var replacement = archive.CreateEntry(DogadFormat.SnapshotEntryName, CompressionLevel.NoCompression);
            replacement.LastWriteTime = new DateTimeOffset(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);
            await using var stream = replacement.Open();
            await stream.WriteAsync(Encoding.UTF8.GetBytes("{}"), cancellationToken);
        }

        mutable.Position = 0;
        var exception = await Assert.ThrowsAsync<DogadArtifactException>(() =>
            serializer.ReadAsync(mutable, cancellationToken: cancellationToken));

        Assert.Equal("dogad.payload.length-mismatch", exception.Code);
    }

    [Fact]
    public async Task Read_UnsupportedFormatVersionFailsBeforeSnapshotUse()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var serializer = new DogadArtifactSerializer();
        var artifact = await WriteAsync(serializer, CreateSnapshot(false), cancellationToken);
        using var mutable = new MemoryStream(artifact.ToArray());
        using (var archive = new ZipArchive(mutable, ZipArchiveMode.Update, leaveOpen: true))
        {
            var entry = archive.GetEntry(DogadFormat.ManifestEntryName)!;
            DogadManifest manifest;
            await using (var readStream = entry.Open())
            {
                manifest = await JsonSerializer.DeserializeAsync<DogadManifest>(
                    readStream,
                    cancellationToken: cancellationToken)
                    ?? throw new InvalidOperationException("Test manifest failed to deserialize.");
            }

            entry.Delete();
            var replacement = archive.CreateEntry(DogadFormat.ManifestEntryName, CompressionLevel.NoCompression);
            replacement.LastWriteTime = new DateTimeOffset(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);
            await using var writeStream = replacement.Open();
            await JsonSerializer.SerializeAsync(
                writeStream,
                manifest with { FormatVersion = 999 },
                cancellationToken: cancellationToken);
        }

        mutable.Position = 0;
        var exception = await Assert.ThrowsAsync<DogadArtifactException>(() =>
            serializer.ReadAsync(mutable, cancellationToken: cancellationToken));

        Assert.Equal("dogad.manifest.format-version-unsupported", exception.Code);
    }

    private static async Task<byte[]> WriteAsync(
        DogadArtifactSerializer serializer,
        AdSnapshot snapshot,
        CancellationToken cancellationToken)
    {
        await using var stream = new MemoryStream();
        await serializer.WriteAsync(snapshot, stream, cancellationToken);
        return stream.ToArray();
    }

    private static AdSnapshot CreateSnapshot(bool reverseCollections)
    {
        var firstUser = new AdUser
        {
            Id = new AdObjectId(Guid.Parse("11111111-1111-1111-1111-111111111111")),
            DistinguishedName = "CN=Alice,DC=mini,DC=lab",
            Sid = "S-1-5-21-1-1-1-1101",
            SamAccountName = "alice",
            UserAccountControl = 512,
            ServicePrincipalNames = reverseCollections
                ? ["HTTP/z.mini.lab", "HTTP/a.mini.lab"]
                : ["HTTP/a.mini.lab", "HTTP/z.mini.lab"]
        };
        var secondUser = new AdUser
        {
            Id = new AdObjectId(Guid.Parse("22222222-2222-2222-2222-222222222222")),
            DistinguishedName = "CN=Bob,DC=mini,DC=lab",
            Sid = "S-1-5-21-1-1-1-1102",
            SamAccountName = "bob",
            UserAccountControl = 514
        };
        var gpo = new AdGroupPolicyObject
        {
            Id = new AdObjectId(Guid.Parse("33333333-3333-3333-3333-333333333333")),
            DistinguishedName = "CN={44444444-4444-4444-4444-444444444444},CN=Policies,CN=System,DC=mini,DC=lab",
            GpoGuid = Guid.Parse("44444444-4444-4444-4444-444444444444"),
            Name = "{44444444-4444-4444-4444-444444444444}"
        };
        var users = reverseCollections ? [secondUser, firstUser] : new[] { firstUser, secondUser };
        var files = new[]
        {
            new AdGpoSysvolFile
            {
                GpoId = gpo.Id,
                RelativePath = "Machine\\Registry.pol",
                Length = 20,
                Sha256 = new string('a', 64),
                Kind = GpoSysvolFileKind.RegistryPolicy
            },
            new AdGpoSysvolFile
            {
                GpoId = gpo.Id,
                RelativePath = "GPT.INI",
                Length = 12,
                Sha256 = new string('b', 64),
                Kind = GpoSysvolFileKind.GptIni
            }
        };

        return new AdSnapshot
        {
            Metadata = new SnapshotMetadata
            {
                SnapshotId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                SchemaVersion = SnapshotSchema.CurrentVersion,
                ProductVersion = "0.1-test",
                StartedAt = FixedNow.AddMinutes(-1),
                CompletedAt = FixedNow,
                CompletionStatus = SnapshotCompletionStatus.Complete,
                Target = new TargetIdentity
                {
                    InitialTarget = "dc01.mini.lab",
                    DomainDnsName = "mini.lab"
                },
                RequestedCapabilities = [],
                Collectors = reverseCollections
                    ? [new CollectorIdentity("z", "1"), new CollectorIdentity("a", "1")]
                    : [new CollectorIdentity("a", "1"), new CollectorIdentity("z", "1")]
            },
            Content = new SnapshotContent
            {
                Users = users,
                GroupPolicyObjects = [gpo],
                GroupPolicyFiles = reverseCollections ? files.Reverse().ToArray() : files,
                GroupPolicySettings =
                [
                    new AdGpoSetting
                    {
                        GpoId = gpo.Id,
                        Scope = GpoPolicyScope.Machine,
                        SourceRelativePath = "Machine\\Registry.pol",
                        Sequence = 1,
                        Kind = GpoSettingKind.RegistryPolicy,
                        Section = "Software\\Policies\\Example",
                        Key = "Endpoint",
                        ValueKind = FactValueKind.Text,
                        Disposition = FactDisposition.MetadataOnly,
                        DataLength = 24
                    }
                ]
            }
        };
    }
}
