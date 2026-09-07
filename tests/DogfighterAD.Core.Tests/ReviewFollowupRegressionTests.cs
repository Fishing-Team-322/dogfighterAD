using System.Buffers.Binary;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Text;
using DogfighterAD.Application.Collection;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Cli;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Collectors.ActiveDirectory.Sysvol;
using DogfighterAD.Domain.Snapshots;
using DogfighterAD.Serialization;

namespace DogfighterAD.Core.Tests;

public sealed class ReviewFollowupRegressionTests
{
    [Theory]
    [InlineData("member;range=0-2147483647")]
    [InlineData("member;range=+0-0")]
    [InlineData("member;range=0-+1")]
    public async Task InvalidRangeIndicesProduceIncompleteResultNotOverflow(string name)
    {
        await using var client = new RangeClient();
        var entry = Entry((name, Text("CN=One,DC=review,DC=invalid")));
        var result = await new GroupMemberRangeReader().ReadAsync(client, entry, TestContext.Current.CancellationToken);
        Assert.False(result.Complete);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public async Task EmptyBaseAttributeOnContinuationDoesNotDeclareCompletion()
    {
        await using var client = new RangeClient(Entry(("member", Text())));
        var result = await new GroupMemberRangeReader().ReadAsync(
            client, Entry(("member;range=0-0", Text("CN=One,DC=review,DC=invalid"))),
            TestContext.Current.CancellationToken);
        Assert.False(result.Complete);
        Assert.Single(result.Members);
    }

    [Fact]
    public async Task BinaryMemberIsNotSilentlyDiscarded()
    {
        await using var client = new RangeClient();
        var result = await new GroupMemberRangeReader().ReadAsync(
            client, Entry(("member;range=0-*", new[] { LdapAttributeValue.FromBytes([1]) })),
            TestContext.Current.CancellationToken);
        Assert.False(result.Complete);
    }

    [Theory]
    [InlineData("Event Audit", "Unclassified")]
    [InlineData("Kerberos Policy", "Unclassified")]
    [InlineData("Privilege Rights", "Unclassified")]
    [InlineData("Group Membership", "Unclassified")]
    [InlineData("Version", "Unclassified")]
    [InlineData("System Access", "MinimumPasswordLength")]
    public void ApprovedSectionDoesNotApproveArbitrarySecretValues(string section, string key)
    {
        var parsed = SysvolPolicyParsers.ParseSecurityTemplate(
            Encoding.UTF8.GetBytes($"[{section}]\n{key}=SECRET_CANARY\n"), "GptTmpl.inf");
        Assert.True(parsed.Success, parsed.Error);
        var setting = Assert.Single(parsed.Settings);
        Assert.NotEqual(FactDisposition.Stored, setting.Disposition);
        Assert.Null(setting.Value);
    }

    [Fact]
    public void GptVersionKeyInWrongSectionIsMetadataOnly()
    {
        var parsed = SysvolPolicyParsers.ParseGptIni(Encoding.UTF8.GetBytes("[Service]\nVersion=SECRET_CANARY\n"), "GPT.INI");
        Assert.True(parsed.Success, parsed.Error);
        Assert.Equal(FactDisposition.MetadataOnly, Assert.Single(parsed.Settings).Disposition);
    }

    [Theory]
    [InlineData("Privilege Rights", "SeBackupPrivilege", "*S-1-5-32-544")]
    [InlineData("Event Audit", "AuditLogonEvents", "3")]
    [InlineData("Kerberos Policy", "MaxTicketAge", "10")]
    public void KnownSecuritySettingsRemainAvailable(string section, string key, string value)
    {
        var parsed = SysvolPolicyParsers.ParseSecurityTemplate(
            Encoding.UTF8.GetBytes($"[{section}]\n{key}={value}\n"), "GptTmpl.inf");
        Assert.True(parsed.Success, parsed.Error);
        Assert.Equal(value, Assert.Single(parsed.Settings).Value);
    }

    [Fact]
    public async Task SeekPositionCannotBypassContainerBudget()
    {
        using var input = await Artifact();
        input.Position = input.Length - 1;
        var error = await Assert.ThrowsAsync<DogadArtifactException>(() =>
            new DogadArtifactSerializer().ReadAsync(input, new DogadReadOptions { MaxContainerBytes = 1 },
                TestContext.Current.CancellationToken));
        Assert.Equal("dogad.container.position-invalid", error.Code);
    }

    [Fact]
    public async Task CentralDirectoryBudgetIsCheckedBeforeZipEntryLoading()
    {
        using var input = await Artifact();
        var error = await Assert.ThrowsAsync<DogadArtifactException>(() =>
            new DogadArtifactSerializer().ReadAsync(input, new DogadReadOptions { MaxCentralDirectoryBytes = 16 },
                TestContext.Current.CancellationToken));
        Assert.Equal("dogad.container.metadata-too-large", error.Code);
    }

    [Fact]
    public async Task ForgedEocdCountCannotHideActualExcessEntries()
    {
        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            zip.CreateEntry("manifest.json");
            zip.CreateEntry("snapshot.json");
            zip.CreateEntry("snapshot.json");
        }
        var bytes = output.ToArray();
        var end = bytes.Length - 22;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(end + 8, 2), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(end + 10, 2), 2);
        using var input = new MemoryStream(bytes);
        var error = await Assert.ThrowsAsync<DogadArtifactException>(() =>
            new DogadArtifactSerializer().ReadAsync(input, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal("dogad.container.entry-count-invalid", error.Code);
    }

    [Fact]
    public async Task NonSeekableInputReadsAtMostBudgetPlusOneDetectionByte()
    {
        using var input = new NonSeekableStream(new byte[1024]);
        var error = await Assert.ThrowsAsync<DogadArtifactException>(() =>
            new DogadArtifactSerializer().ReadAsync(input, new DogadReadOptions { MaxContainerBytes = 16 },
                TestContext.Current.CancellationToken));
        Assert.Equal("dogad.container.too-large", error.Code);
        Assert.Equal(17, input.BytesRead);
    }

    [Fact]
    public async Task ValidNonSeekableArtifactRoundTripsThroughPrivateSpool()
    {
        using var artifact = await Artifact();
        using var input = new NonSeekableStream(artifact.ToArray());
        var result = await new DogadArtifactSerializer().ReadAsync(input, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(Snapshot().Metadata.SnapshotId, result.Metadata.SnapshotId);
    }

    [Fact]
    public async Task ManifestWriterBudgetRejectsBeforePublishingZip()
    {
        using var output = new MemoryStream();
        var error = await Assert.ThrowsAsync<DogadArtifactException>(() =>
            new DogadArtifactSerializer().WriteAsync(Snapshot(), output,
                new DogadWriteOptions { MaxManifestBytes = 16 }, TestContext.Current.CancellationToken));
        Assert.Equal("dogad.manifest.write-limit-exceeded", error.Code);
        Assert.Equal(0, output.Length);
    }

    [Fact]
    public void UndefinedEnumCannotBypassProgrammaticValidation()
    {
        var invalid = Snapshot() with
        {
            Coverage = [new CapabilityCoverage
            {
                CapabilityId = "probe", Status = (CapabilityStatus)999,
                StartedAt = DateTimeOffset.UnixEpoch, CompletedAt = DateTimeOffset.UnixEpoch
            }]
        };
        Assert.Contains(SnapshotInvariantValidator.Validate(invalid), item => item.Code == "snapshot.coverage.invalid");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(512)]
    [InlineData(1024)]
    public void CliScanAndInspectUseIdenticalExplicitBudgets(int mib)
    {
        var text = mib.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var scan = CliArgumentParser.Parse(["scan", "--target", "dc.review.invalid", "--output", "out.dogad", "--max-snapshot-mib", text]);
        var inspect = CliArgumentParser.Parse(["inspect", "--snapshot", "out.dogad", "--max-snapshot-mib", text]);
        Assert.True(scan.Success, scan.Error);
        Assert.True(inspect.Success, inspect.Error);
        var scanOptions = ArtifactBudgets.ForMiB(Assert.IsType<ScanCommand>(scan.Command).MaxSnapshotMiB);
        var inspectOptions = ArtifactBudgets.ForMiB(Assert.IsType<InspectCommand>(inspect.Command).MaxSnapshotMiB);
        Assert.Equal(scanOptions.ToReadOptions(), inspectOptions.ToReadOptions());
    }

    [Theory]
    [InlineData("0")]
    [InlineData("1025")]
    [InlineData("-1")]
    [InlineData("99999999999999")]
    public void CliRejectsInvalidSnapshotBudget(string value)
    {
        Assert.False(CliArgumentParser.Parse(["inspect", "--snapshot", "out.dogad", "--max-snapshot-mib", value]).Success);
    }

    [Fact]
    public async Task FailedVerifiedWriteKeepsPreviousOutputAndRemovesTemporaryFile()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"dogad-preserve-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "result.dogad");
        var token = TestContext.Current.CancellationToken;
        try
        {
            await File.WriteAllTextAsync(path, "previous-result", token);
            var collector = new ProbeCollector("probe", _ => Task.CompletedTask);
            await Assert.ThrowsAsync<DogadArtifactException>(() => new ScanWorkflow().ExecuteAsync(new ScanWorkflowRequest
            {
                Target = "review.invalid", OutputPath = path, ProductVersion = "regression",
                Profile = new CollectionProfile { Name = "probe", RequestedCapabilities = new HashSet<string> { "probe" } },
                Collectors = [collector], ArtifactOptions = new DogadWriteOptions { MaxSnapshotBytes = 32 }
            }, token));
            Assert.Equal("previous-result", await File.ReadAllTextAsync(path, token));
            Assert.Single(Directory.GetFiles(directory));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public async Task TimedOutCollectorRetainsItsPhysicalSlotUntilItActuallyExits()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var tokenStillUsable = false;
        var first = new ProbeCollector("a.blocking", async token =>
        {
            entered.TrySetResult();
            try
            {
                await release.Task; // Deliberately ignores cancellation.
                _ = token.WaitHandle; // Throws if the executor disposed the CTS at the wait timeout.
                tokenStillUsable = true;
            }
            finally { exited.TrySetResult(); }
        });
        var second = new ProbeCollector("b.next", _ => Task.CompletedTask);
        var plan = new CollectionPlanner().BuildPlan(new CollectionProfile
        {
            Name = "lifetime", RequestedCapabilities = new HashSet<string> { first.Id, second.Id },
            MaxConcurrency = 1, CollectorTimeout = TimeSpan.FromSeconds(1)
        }, [first, second]);
        var testToken = TestContext.Current.CancellationToken;
        try
        {
            var execution = new CollectionExecutor().ExecuteAsync(plan, Guid.NewGuid(), "review.invalid", testToken);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), testToken);
            var result = await execution.WaitAsync(TimeSpan.FromSeconds(5), testToken);
            Assert.False(second.Invoked);
            Assert.Contains(result.Data.Coverage.SelectMany(item => item.Issues),
                item => item.Code == "collection.collector.capacity-exhausted");
        }
        finally
        {
            release.TrySetResult();
            await exited.Task.WaitAsync(TimeSpan.FromSeconds(5), testToken);
        }
        Assert.True(tokenStillUsable);
    }

    [Fact]
    public async Task SysvolLateEnumerationFailureRetainsAlreadyValidatedFiles()
    {
        var gpoGuid = Guid.Parse("33333333-3333-3333-3333-333333333333");
        var root = $"\\\\review.invalid\\SYSVOL\\review.invalid\\Policies\\{gpoGuid:B}";
        var factory = new PartialEnumerationFactory(root);
        var context = new CollectionContext(Guid.NewGuid(), "dc.review.invalid", new HashSet<string>(), new SnapshotFragment
        {
            Content = new SnapshotContent
            {
                GroupPolicyObjects = [new AdGroupPolicyObject
                {
                    Id = new AdObjectId(Guid.Parse("22222222-2222-2222-2222-222222222222")),
                    GpoGuid = gpoGuid, FileSystemPath = root,
                    DistinguishedName = $"CN={gpoGuid:B},CN=Policies,CN=System,DC=review,DC=invalid"
                }]
            }
        });
        var result = await new GpoSysvolCollector(factory).CollectAsync(context, TestContext.Current.CancellationToken);
        Assert.Equal(CapabilityStatus.Partial, Assert.Single(result.Fragment.Coverage).Status);
        Assert.Single(result.Fragment.Content.GroupPolicyFiles);
        Assert.Equal("1", Assert.Single(result.Fragment.Content.GroupPolicySettings).Value);
    }

    private static AdSnapshot Snapshot() => new()
    {
        Metadata = new SnapshotMetadata
        {
            SnapshotId = Guid.Parse("11111111-1111-1111-1111-111111111111"), SchemaVersion = SnapshotSchema.CurrentVersion,
            ProductVersion = "regression", StartedAt = DateTimeOffset.UnixEpoch, CompletedAt = DateTimeOffset.UnixEpoch,
            CompletionStatus = SnapshotCompletionStatus.Complete, Target = new TargetIdentity { InitialTarget = "review.invalid" }
        }
    };

    private static async Task<MemoryStream> Artifact()
    {
        var output = new MemoryStream();
        await new DogadArtifactSerializer().WriteAsync(Snapshot(), output, TestContext.Current.CancellationToken);
        output.Position = 0;
        return output;
    }
    private static IReadOnlyList<LdapAttributeValue> Text(params string[] values) => values.Select(LdapAttributeValue.FromText).ToArray();
    private static LdapSearchEntry Entry(params (string Name, IReadOnlyList<LdapAttributeValue> Values)[] values) => new()
    {
        DistinguishedName = "CN=Group,DC=review,DC=invalid",
        Attributes = values.ToDictionary(item => item.Name, item => item.Values, StringComparer.OrdinalIgnoreCase)
    };
    private sealed class RangeClient(params LdapSearchEntry[] responses) : IReadOnlyLdapClient
    {
        private readonly Queue<LdapSearchEntry> _responses = new(responses);
        public Task<LdapSearchResult> SearchAsync(LdapSearchRequest request, CancellationToken token) =>
            Task.FromResult(new LdapSearchResult([_responses.Dequeue()]));
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    private sealed class ProbeCollector(string id, Func<CancellationToken, Task> operation) : ICollector
    {
        public string Id => id;
        public string Version => "1";
        public bool Invoked { get; private set; }
        public IReadOnlySet<string> ProvidesCapabilities { get; } = new HashSet<string> { id };
        public IReadOnlySet<string> RequiresCapabilities { get; } = new HashSet<string>();
        public async Task<CollectorResult> CollectAsync(CollectionContext context, CancellationToken cancellationToken)
        {
            Invoked = true;
            await operation(cancellationToken);
            return new CollectorResult(Id, Version, new SnapshotFragment { Coverage = [new CapabilityCoverage
            {
                CapabilityId = Id, Status = CapabilityStatus.Complete,
                StartedAt = DateTimeOffset.UnixEpoch, CompletedAt = DateTimeOffset.UnixEpoch
            }] });
        }
    }
    private sealed class NonSeekableStream(byte[] bytes) : Stream
    {
        private readonly MemoryStream _inner = new(bytes, writable: false);
        public long BytesRead => _inner.Position;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => _inner.ReadAsync(buffer, cancellationToken);
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) _inner.Dispose(); base.Dispose(disposing); }
    }
    private sealed class PartialEnumerationFactory(string root) : IReadOnlySysvolClientFactory
    {
        public ValueTask<IReadOnlySysvolClient> CreateAsync(CancellationToken token) => ValueTask.FromResult<IReadOnlySysvolClient>(new PartialClient(root));
    }
    private sealed class PartialClient(string root) : IReadOnlySysvolClient
    {
        public async IAsyncEnumerable<SysvolFileEntry> EnumerateFilesAsync(string path, [EnumeratorCancellation] CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            yield return new SysvolFileEntry { FullPath = root + "\\GPT.INI", RelativePath = "GPT.INI", Length = 20 };
            await Task.Yield();
            throw new IOException("Controlled late enumeration failure");
        }
        public Task<byte[]> ReadFileAsync(string path, int maxBytes, CancellationToken token) =>
            Task.FromResult(Encoding.UTF8.GetBytes("[General]\nVersion=1\n"));
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
