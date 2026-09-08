using System.IO.Compression;
using System.Text;
using DogfighterAD.Domain.Snapshots;
using DogfighterAD.Serialization;

namespace DogfighterAD.Core.Tests.Serialization;

public sealed class AdcsBackwardCompatibilityTests
{
    [Fact]
    public async Task LegacySchemaV2Snapshot_WithoutAdcs_OmitsCertificateServicesAndRoundTrips()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var snapshot = new AdSnapshot
        {
            Metadata = new SnapshotMetadata
            {
                SnapshotId = Guid.Parse("c31ef3fe-d024-4aab-8209-15e15b7ea7a7"),
                SchemaVersion = SnapshotSchema.CurrentVersion,
                ProductVersion = "0.3.1-test",
                StartedAt = new DateTimeOffset(2026, 9, 8, 11, 59, 0, TimeSpan.Zero),
                CompletedAt = new DateTimeOffset(2026, 9, 8, 12, 0, 0, TimeSpan.Zero),
                CompletionStatus = SnapshotCompletionStatus.Complete,
                Target = new TargetIdentity
                {
                    InitialTarget = "dc01.mini.lab",
                    DomainDnsName = "mini.lab"
                },
                RequestedCapabilities = []
            }
        };
        var serializer = new DogadArtifactSerializer();

        byte[] artifact;
        await using (var output = new MemoryStream())
        {
            await serializer.WriteAsync(snapshot, output, cancellationToken);
            artifact = output.ToArray();
        }

        using (var archiveStream = new MemoryStream(artifact, writable: false))
        using (var archive = new ZipArchive(archiveStream, ZipArchiveMode.Read, leaveOpen: false))
        {
            var payload = archive.GetEntry(DogadFormat.SnapshotEntryName)
                ?? throw new InvalidOperationException("snapshot payload missing");
            await using var payloadStream = payload.Open();
            using var reader = new StreamReader(payloadStream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false);
            var json = await reader.ReadToEndAsync(cancellationToken);
            Assert.DoesNotContain("certificateServices", json, StringComparison.Ordinal);
        }

        await using var input = new MemoryStream(artifact, writable: false);
        var restored = await serializer.ReadAsync(input, cancellationToken: cancellationToken);

        Assert.Null(restored.Content.CertificateServices);
        Assert.DoesNotContain(restored.Coverage, item =>
            item.CapabilityId.StartsWith("adcs.", StringComparison.Ordinal));
    }
}
