using System.Buffers.Binary;
using System.Text;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Sysvol;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class GpoSysvolCollectorTests
{
    private static readonly DateTimeOffset FixedNow =
        new(2026, 9, 5, 22, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task CollectAsync_InventoriesAndNormalizesSupportedPolicyFilesWithoutStoringCpassword()
    {
        var gpoObjectId = new AdObjectId(Guid.Parse("11111111-1111-1111-1111-111111111111"));
        var gpoGuid = Guid.Parse("22222222-2222-2222-2222-222222222222");
        const string root = "\\\\mini.lab\\SYSVOL\\mini.lab\\Policies\\{22222222-2222-2222-2222-222222222222}";
        var client = new FakeSysvolClient(
            root,
            new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["GPT.INI"] = Encoding.UTF8.GetBytes("[General]\r\nVersion=65537\r\n"),
                ["Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"] =
                    Encoding.UTF8.GetBytes("[System Access]\r\nMinimumPasswordLength = 14\r\nClearTextPassword = 0\r\n"),
                ["Machine\\Registry.pol"] = CreateRegistryPolDword(
                    "Software\\Policies\\Example",
                    "Enabled",
                    1),
                ["Machine\\Preferences\\Groups\\Groups.xml"] =
                    Encoding.UTF8.GetBytes("<Groups><User name=\"legacy\" cpassword=\"dont-store-me\" /></Groups>"),
                ["Machine\\Scripts\\Startup\\audit.cmd"] = Encoding.UTF8.GetBytes("echo hello")
            });
        var collector = new GpoSysvolCollector(
            new FakeSysvolClientFactory(client),
            new SysvolClientOptions { MaxFileBytes = 1024 * 1024, MaxFilesPerGpo = 100 },
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(gpoObjectId, gpoGuid, root),
            CancellationToken.None);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Complete, coverage.Status);
        Assert.Equal(5, coverage.ObservedItemCount);
        Assert.Equal(5, result.Fragment.Content.GroupPolicyFiles.Count);

        Assert.Contains(result.Fragment.Content.GroupPolicySettings, setting =>
            setting.Kind == GpoSettingKind.Ini &&
            setting.Key == "Version" &&
            setting.Value == "65537");
        Assert.Contains(result.Fragment.Content.GroupPolicySettings, setting =>
            setting.Kind == GpoSettingKind.SecurityTemplate &&
            setting.Key == "MinimumPasswordLength" &&
            setting.Value == "14");
        Assert.Contains(result.Fragment.Content.GroupPolicySettings, setting =>
            setting.Kind == GpoSettingKind.RegistryPolicy &&
            setting.Key == "Enabled" &&
            setting.Value == "1");
        Assert.Contains(result.Fragment.Content.GroupPolicySettings, setting =>
            setting.Kind == GpoSettingKind.PreferenceSignal &&
            setting.Key == "cpassword-present" &&
            setting.Value == "true");

        Assert.DoesNotContain(result.Fragment.Content.GroupPolicySettings, setting =>
            string.Equals(setting.Value, "dont-store-me", StringComparison.Ordinal));
        Assert.DoesNotContain(result.Fragment.Observations, fact =>
            string.Equals(fact.Value, "dont-store-me", StringComparison.Ordinal));
    }

    [Fact]
    public async Task CollectAsync_OversizedFileMakesCoveragePartialWithoutReadingContent()
    {
        var gpoObjectId = new AdObjectId(Guid.Parse("33333333-3333-3333-3333-333333333333"));
        var gpoGuid = Guid.Parse("44444444-4444-4444-4444-444444444444");
        const string root = "\\\\mini.lab\\SYSVOL\\mini.lab\\Policies\\{44444444-4444-4444-4444-444444444444}";
        var client = new FakeSysvolClient(
            root,
            new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Machine\\huge.bin"] = new byte[128]
            });
        var collector = new GpoSysvolCollector(
            new FakeSysvolClientFactory(client),
            new SysvolClientOptions { MaxFileBytes = 16, MaxFilesPerGpo = 100 },
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(
            CreateContext(gpoObjectId, gpoGuid, root),
            CancellationToken.None);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Partial, coverage.Status);
        Assert.Contains(coverage.Issues, issue =>
            issue.Code == "collection.gpo.sysvol.file-too-large");
        var file = Assert.Single(result.Fragment.Content.GroupPolicyFiles);
        Assert.Null(file.Sha256);
        Assert.Equal(128, file.Length);
    }

    [Fact]
    public void RegistryPolicyParser_StringDataIsMetadataOnly()
    {
        var bytes = CreateRegistryPolString(
            "Software\\Policies\\Example",
            "Endpoint",
            "potentially-sensitive-text");

        var parsed = SysvolPolicyParsers.ParseRegistryPolicy(
            bytes,
            "Machine\\Registry.pol",
            GpoPolicyScope.Machine);

        Assert.True(parsed.Success);
        var setting = Assert.Single(parsed.Settings);
        Assert.Equal(FactDisposition.MetadataOnly, setting.Disposition);
        Assert.Null(setting.Value);
        Assert.True(setting.DataLength > 0);
    }

    private static CollectionContext CreateContext(
        AdObjectId gpoObjectId,
        Guid gpoGuid,
        string root) =>
        new(
            Guid.Parse("eb885b07-1e33-4501-bd16-6b57148445bc"),
            "dc01.mini.lab",
            new HashSet<string>(StringComparer.Ordinal)
            {
                CollectionCapabilities.GroupPolicySysvol
            },
            new SnapshotFragment
            {
                Content = new SnapshotContent
                {
                    GroupPolicyObjects =
                    [
                        new AdGroupPolicyObject
                        {
                            Id = gpoObjectId,
                            DistinguishedName = $"CN={{{gpoGuid:D}}},CN=Policies,CN=System,DC=mini,DC=lab",
                            Name = $"{{{gpoGuid:D}}}",
                            GpoGuid = gpoGuid,
                            FileSystemPath = root
                        }
                    ]
                },
                Coverage =
                [
                    new CapabilityCoverage
                    {
                        CapabilityId = CollectionCapabilities.GroupPolicyMetadata,
                        ContractVersion = 1,
                        Status = CapabilityStatus.Complete,
                        StartedAt = FixedNow,
                        CompletedAt = FixedNow
                    }
                ]
            });

    private static byte[] CreateRegistryPolDword(string key, string name, uint value)
    {
        Span<byte> data = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(data, value);
        return CreateRegistryPolRecord(key, name, 4, data.ToArray());
    }

    private static byte[] CreateRegistryPolString(string key, string name, string value) =>
        CreateRegistryPolRecord(key, name, 1, Encoding.Unicode.GetBytes(value + "\0"));

    private static byte[] CreateRegistryPolRecord(string key, string name, uint type, byte[] data)
    {
        using var stream = new MemoryStream();
        stream.Write([0x50, 0x52, 0x65, 0x67]);
        WriteUInt32(stream, 1);
        WriteUtf16Char(stream, '[');
        WriteUtf16Field(stream, key, ';');
        WriteUtf16Field(stream, name, ';');
        WriteUInt32(stream, type);
        WriteUtf16Char(stream, ';');
        WriteUInt32(stream, checked((uint)data.Length));
        WriteUtf16Char(stream, ';');
        stream.Write(data);
        WriteUtf16Char(stream, ']');
        return stream.ToArray();
    }

    private static void WriteUtf16Field(Stream stream, string value, char delimiter)
    {
        stream.Write(Encoding.Unicode.GetBytes(value + "\0"));
        WriteUtf16Char(stream, delimiter);
    }

    private static void WriteUtf16Char(Stream stream, char value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void WriteUInt32(Stream stream, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        stream.Write(bytes);
    }

    private sealed class FakeSysvolClientFactory : IReadOnlySysvolClientFactory
    {
        private readonly IReadOnlySysvolClient _client;

        public FakeSysvolClientFactory(IReadOnlySysvolClient client)
        {
            _client = client;
        }

        public ValueTask<IReadOnlySysvolClient> CreateAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(_client);
        }
    }

    private sealed class FakeSysvolClient : IReadOnlySysvolClient
    {
        private readonly string _root;
        private readonly IReadOnlyDictionary<string, byte[]> _files;

        public FakeSysvolClient(string root, IReadOnlyDictionary<string, byte[]> files)
        {
            _root = root;
            _files = files;
        }

        public async IAsyncEnumerable<SysvolFileEntry> EnumerateFilesAsync(
            string rootPath,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            Assert.Equal(_root, rootPath);
            foreach (var item in _files.OrderBy(item => item.Key, StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return new SysvolFileEntry
                {
                    FullPath = $"{_root}\\{item.Key}",
                    RelativePath = item.Key,
                    Length = item.Value.LongLength,
                    LastWriteTimeUtc = FixedNow
                };
                await Task.Yield();
            }
        }

        public Task<byte[]> ReadFileAsync(
            string fullPath,
            int maxBytes,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var prefix = _root + "\\";
            var relativePath = fullPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                ? fullPath[prefix.Length..]
                : throw new InvalidOperationException("Unexpected fake SYSVOL path.");
            var bytes = _files[relativePath];
            if (bytes.Length > maxBytes)
            {
                throw new SysvolFileTooLargeException(fullPath, bytes.Length, maxBytes);
            }

            return Task.FromResult(bytes.ToArray());
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _utcNow;

        public FixedTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow() => _utcNow;
    }
}
