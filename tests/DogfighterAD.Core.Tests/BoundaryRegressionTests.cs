using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using DogfighterAD.Application.Collection;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Sysvol;
using DogfighterAD.Domain.Snapshots;
using DogfighterAD.Serialization;

namespace DogfighterAD.Core.Tests;

public sealed class BoundaryRegressionTests
{
    [Theory]
    [InlineData("utf8")]
    [InlineData("utf8-bom")]
    [InlineData("utf16-le")]
    [InlineData("utf16-be")]
    [InlineData("utf16-le-no-bom")]
    public void Ini_RecognizesSupportedEncodings(string name)
    {
        Encoding encoding = name switch
        {
            "utf8" => new UTF8Encoding(false),
            "utf8-bom" => new UTF8Encoding(true),
            "utf16-le-no-bom" => new UnicodeEncoding(false, false),
            "utf16-be" => Encoding.BigEndianUnicode,
            _ => Encoding.Unicode
        };
        var bytes = encoding.GetPreamble().Concat(encoding.GetBytes("[General]\r\nVersion=1\r\n")).ToArray();
        var result = SysvolPolicyParsers.ParseGptIni(bytes, "GPT.INI");
        Assert.True(result.Success, result.Error);
        Assert.Equal("1", Assert.Single(result.Settings).Value);
    }

    [Theory]
    [InlineData("<Groups cpassword='&SECRET_CANARY;' />")]
    [InlineData("<SECRET_CANARY></Other>")]
    [InlineData("<!DOCTYPE Groups [<!ENTITY x SYSTEM 'file:///SECRET_CANARY'>]><Groups>&x;</Groups>")]
    public void MalformedXml_DoesNotExposeInputInErrors(string xml)
    {
        var result = SysvolPolicyParsers.ScanPreferencesXml(Encoding.UTF8.GetBytes(xml), "Machine\\Preferences\\Groups\\Groups.xml");
        Assert.False(result.Success);
        Assert.DoesNotContain("SECRET_CANARY", result.Error ?? "");
    }

    [Theory]
    [InlineData("password")]
    [InlineData("passwd")]
    [InlineData("pwd")]
    [InlineData("secret")]
    [InlineData("credentials")]
    [InlineData("cpassword")]
    [InlineData("ServicePassword")]
    public void Ini_SecretValuesAreRedacted(string key)
    {
        var result = SysvolPolicyParsers.ParseSecurityTemplate(Encoding.UTF8.GetBytes($"[Service]\n{key}=SECRET_CANARY\n"), "GptTmpl.inf");
        Assert.True(result.Success, result.Error);
        var setting = Assert.Single(result.Settings);
        Assert.NotEqual("SECRET_CANARY", setting.Value);
        Assert.Equal(FactDisposition.Redacted, setting.Disposition);
    }

    [Theory]
    [InlineData("payloadSha256", "null")]
    [InlineData("payloadSha256", "\"short\"")]
    [InlineData("payloadSha256", "\"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"")]
    [InlineData("productVersion", "null")]
    [InlineData("payloadPath", "null")]
    [InlineData("artifactType", "null")]
    [InlineData("serializationId", "null")]
    [InlineData("formatVersion", "999")]
    [InlineData("snapshotSchemaVersion", "999")]
    [InlineData("payloadLength", "-1")]
    [InlineData("payloadPath", "\"../snapshot.json\"")]
    [InlineData("snapshotCompletedAt", "\"2035-01-01T00:00:00Z\"")]
    [InlineData("snapshotId", "\"00000000-0000-0000-0000-000000000000\"")]
    public async Task InvalidManifest_IsRejectedWithDomainException(string field, string value)
    {
        var token = TestContext.Current.CancellationToken;
        var serializer = new DogadArtifactSerializer();
        using var artifact = new MemoryStream();
        await serializer.WriteAsync(CreateSnapshot(), artifact, token);
        artifact.Position = 0;
        using (var zip = new ZipArchive(artifact, ZipArchiveMode.Update, true))
        {
            var entry = zip.GetEntry("manifest.json")!;
            JsonNode manifest;
            using (var reader = new StreamReader(entry.Open()))
                manifest = JsonNode.Parse(await reader.ReadToEndAsync(token))!;
            manifest[field] = JsonNode.Parse(value);
            entry.Delete();
            using var writer = new StreamWriter(zip.CreateEntry("manifest.json").Open());
            await writer.WriteAsync(manifest.ToJsonString().AsMemory(), token);
        }
        artifact.Position = 0;
        await Assert.ThrowsAsync<DogadArtifactException>(() => serializer.ReadAsync(artifact, cancellationToken: token));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    public async Task SysvolRead_EnforcesFileSizeBoundary(int size)
    {
        var token = TestContext.Current.CancellationToken;
        var path = Path.Combine(Path.GetTempPath(), $"dogad-{Guid.NewGuid():N}.tmp");
        try
        {
            await File.WriteAllBytesAsync(path, new byte[size], token);
            await using var client = await new SystemSysvolClientFactory().CreateAsync(token);
            if (size > 16)
                await Assert.ThrowsAsync<SysvolFileTooLargeException>(() => client.ReadFileAsync(path, 16, token));
            else
                Assert.Equal(size, (await client.ReadFileAsync(path, 16, token)).Length);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task SysvolRead_StopsAtMaxPlusOneWhenStreamLengthUnderreports()
    {
        var token = TestContext.Current.CancellationToken;
        using var stream = new UnderreportedLengthStream(new byte[128], reportedLength: 16);

        await Assert.ThrowsAsync<SysvolFileTooLargeException>(() =>
            SysvolBoundedReader.ReadAsync(stream, "synthetic", 16, token));

        Assert.Equal(17, stream.BytesRead);
    }

    [Fact]
    public async Task SysvolRead_ObservesCancellationBeforeStreaming()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        using var stream = new UnderreportedLengthStream(new byte[1], reportedLength: 1);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            SysvolBoundedReader.ReadAsync(stream, "synthetic", 16, cts.Token));

        Assert.Equal(0, stream.BytesRead);
    }

    [Fact]
    public async Task Collector_ReturningAfterCancellation_IsTimedOut()
    {
        var token = TestContext.Current.CancellationToken;
        var collector = new ReturnsAfterCancellationCollector();
        var plan = new CollectionPlanner().BuildPlan(new CollectionProfile
        {
            Name = "regression", RequestedCapabilities = new HashSet<string> { "probe" },
            MaxConcurrency = 1, CollectorTimeout = TimeSpan.FromMilliseconds(25)
        }, [collector]);
        var result = await new CollectionExecutor().ExecuteAsync(plan, Guid.NewGuid(), "synthetic", token);
        Assert.Equal(CollectorExecutionStatus.TimedOut, Assert.Single(result.Collectors).Status);
        Assert.Equal(CapabilityStatus.Failed, Assert.Single(result.Data.Coverage).Status);
    }

    private static AdSnapshot CreateSnapshot()
    {
        var now = new DateTimeOffset(2026, 9, 6, 0, 0, 0, TimeSpan.Zero);
        return new AdSnapshot
        {
            Metadata = new SnapshotMetadata
            {
                SnapshotId = Guid.Parse("01234567-89ab-cdef-0123-456789abcdef"),
                SchemaVersion = SnapshotSchema.CurrentVersion, ProductVersion = "regression",
                StartedAt = now, CompletedAt = now, CompletionStatus = SnapshotCompletionStatus.Complete,
                Target = new TargetIdentity { InitialTarget = "synthetic" }, RequestedCapabilities = [], Collectors = []
            }, Content = new SnapshotContent()
        };
    }

    private sealed class ReturnsAfterCancellationCollector : ICollector
    {
        public string Id => "probe";
        public string Version => "1";
        public IReadOnlySet<string> ProvidesCapabilities { get; } = new HashSet<string> { "probe" };
        public IReadOnlySet<string> RequiresCapabilities { get; } = new HashSet<string>();
        public async Task<CollectorResult> CollectAsync(CollectionContext context, CancellationToken token)
        {
            var canceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var registration = token.Register(() => canceled.TrySetResult());
            await canceled.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            var now = DateTimeOffset.UtcNow;
            return new(Id, Version, new SnapshotFragment { Coverage = [new CapabilityCoverage
            {
                CapabilityId = "probe", Status = CapabilityStatus.Complete,
                StartedAt = now, CompletedAt = now, ObservedItemCount = 0
            }] });
        }
    }

    private sealed class UnderreportedLengthStream : Stream
    {
        private readonly byte[] _content;
        private readonly long _reportedLength;
        private int _position;

        public UnderreportedLengthStream(byte[] content, long reportedLength)
        {
            _content = content;
            _reportedLength = reportedLength;
        }

        public int BytesRead => _position;
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _reportedLength;
        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var remaining = _content.Length - _position;
            if (remaining <= 0)
            {
                return 0;
            }

            var read = Math.Min(count, remaining);
            _content.AsSpan(_position, read).CopyTo(buffer.AsSpan(offset, read));
            _position += read;
            return read;
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var remaining = _content.Length - _position;
            if (remaining <= 0)
            {
                return ValueTask.FromResult(0);
            }

            var read = Math.Min(buffer.Length, remaining);
            _content.AsMemory(_position, read).CopyTo(buffer);
            _position += read;
            return ValueTask.FromResult(read);
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
