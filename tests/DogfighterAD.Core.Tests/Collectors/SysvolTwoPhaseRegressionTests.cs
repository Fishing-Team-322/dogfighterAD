using System.Runtime.CompilerServices;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Sysvol;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class SysvolTwoPhaseRegressionTests
{
    [Fact]
    public async Task Collector_CompletesEnumerationBeforeStartingReads()
    {
        var gpoId = new AdObjectId(Guid.Parse("70a22dfd-41d2-4a4a-ae90-e7efec0f4816"));
        var gpoGuid = Guid.Parse("31b2f340-016d-11d2-945f-00c04fb984f9");
        var root = $"\\\\mini.lab\\SYSVOL\\mini.lab\\Policies\\{gpoGuid:B}";
        var client = new EnumerationMustFinishClient(root, 32);
        var collector = new GpoSysvolCollector(
            new SingleClientFactory(client),
            new SysvolClientOptions
            {
                MaxFileBytes = 1024,
                MaxFilesPerGpo = 64
            });

        var result = await collector.CollectAsync(
            CreateContext(gpoId, gpoGuid, root),
            TestContext.Current.CancellationToken);

        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(CapabilityStatus.Complete, coverage.Status);
        Assert.Equal(32, result.Fragment.Content.GroupPolicyFiles.Count);
        Assert.True(client.EnumerationCompleted);
        Assert.Equal(32, client.ReadCalls);
    }

    [Fact]
    public async Task RealWorker_TwoPhaseEnumerationThenReads_AllFilesWithoutTimeout()
    {
        var workerPath = SystemSysvolClientFactory.GetDefaultWorkerExecutablePath();
        Assert.True(
            File.Exists(workerPath),
            "Build the test project with its SYSVOL worker deployment target enabled.");

        var root = Path.Combine(Path.GetTempPath(), $"dogad-sysvol-two-phase-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.Current.CancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        byte[] expected = [1, 2, 3, 4];

        try
        {
            for (var index = 0; index < 32; index++)
            {
                await File.WriteAllBytesAsync(
                    Path.Combine(root, $"file-{index:D2}.dat"),
                    expected,
                    deadline.Token);
            }

            var factory = new SystemSysvolClientFactory(workerPath, TimeSpan.FromSeconds(5));
            await using var client = await factory.CreateAsync(deadline.Token);

            var entries = new List<SysvolFileEntry>();
            await foreach (var file in client.EnumerateFilesAsync(root, deadline.Token))
            {
                entries.Add(file);
            }

            Assert.Equal(32, entries.Count);
            foreach (var file in entries)
            {
                var bytes = await client.ReadFileAsync(file.FullPath, 16, deadline.Token);
                Assert.Equal(expected, bytes);
            }
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static CollectionContext CreateContext(
        AdObjectId gpoId,
        Guid gpoGuid,
        string root)
    {
        var now = new DateTimeOffset(2026, 9, 7, 0, 0, 0, TimeSpan.Zero);
        return new CollectionContext(
            Guid.Parse("8d63cdd4-e229-42d5-83b7-97ac8c3d6ae2"),
            "dc.mini.lab",
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
                            Id = gpoId,
                            DistinguishedName = $"CN={gpoGuid:B},CN=Policies,CN=System,DC=mini,DC=lab",
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
                        StartedAt = now,
                        CompletedAt = now
                    }
                ]
            });
    }

    private sealed class SingleClientFactory : IReadOnlySysvolClientFactory
    {
        private readonly IReadOnlySysvolClient _client;

        public SingleClientFactory(IReadOnlySysvolClient client)
        {
            _client = client;
        }

        public ValueTask<IReadOnlySysvolClient> CreateAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(_client);
        }
    }

    private sealed class EnumerationMustFinishClient : IReadOnlySysvolClient
    {
        private readonly string _root;
        private readonly int _count;

        public EnumerationMustFinishClient(string root, int count)
        {
            _root = root;
            _count = count;
        }

        public bool EnumerationCompleted { get; private set; }
        public int ReadCalls { get; private set; }

        public async IAsyncEnumerable<SysvolFileEntry> EnumerateFilesAsync(
            string rootPath,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            Assert.Equal(_root, rootPath);
            for (var index = 0; index < _count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return new SysvolFileEntry
                {
                    FullPath = $"{_root}\\file-{index:D2}.dat",
                    RelativePath = $"file-{index:D2}.dat",
                    Length = 4
                };
                await Task.Yield();
            }

            EnumerationCompleted = true;
        }

        public Task<byte[]> ReadFileAsync(
            string fullPath,
            int maxBytes,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!EnumerationCompleted)
            {
                throw new IOException("Read began before enumeration completed.");
            }

            ReadCalls++;
            return Task.FromResult<byte[]>([1, 2, 3, 4]);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
