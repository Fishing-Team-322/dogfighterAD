using DogfighterAD.Application.Collection;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Cli;
using DogfighterAD.Domain.Snapshots;
using DogfighterAD.Serialization;

namespace DogfighterAD.Core.Tests.Cli;

public sealed class CliTests
{
    [Fact]
    public void ScanArguments_ParseReadOnlyCompositionOptions()
    {
        var result = CliArgumentParser.Parse(
        [
            "scan",
            "--target", "dc01.mini.lab",
            "--output", "audit.dogad",
            "--profile", "audit-full",
            "--ldaps",
            "--ldap-port", "636",
            "--sysvol-authority", "dc01.mini.lab",
            "--sysvol-authority", "dc02.mini.lab"
        ]);

        Assert.True(result.Success, result.Error);
        var command = Assert.IsType<ScanCommand>(result.Command);
        Assert.Equal("dc01.mini.lab", command.Target);
        Assert.Equal("audit.dogad", command.OutputPath);
        Assert.Equal("audit-full", command.Profile);
        Assert.True(command.UseLdaps);
        Assert.Equal(636, command.LdapPort);
        Assert.Null(command.Username);
        Assert.Equal(2, command.ApprovedSysvolAuthorities.Count);
    }

    [Fact]
    public void ScanArguments_UsernameEnablesPromptedLdapCredential()
    {
        var result = CliArgumentParser.Parse(
        [
            "scan",
            "--target", "dc.mini.lab",
            "--output", "audit.dogad",
            "-u", "MINILAB\\alice"
        ]);

        Assert.True(result.Success, result.Error);
        var command = Assert.IsType<ScanCommand>(result.Command);
        Assert.Equal("MINILAB\\alice", command.Username);
    }

    [Theory]
    [InlineData("-p")]
    [InlineData("--password")]
    [InlineData("--passwd")]
    public void ScanArguments_RejectPasswordOptions(string option)
    {
        var result = CliArgumentParser.Parse(
        [
            "scan",
            "--target", "dc01.mini.lab",
            "--output", "audit.dogad",
            "-u", "MINILAB\\alice",
            option
        ]);

        Assert.False(result.Success);
        Assert.Contains("not supported", result.Error ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("hidden interactive prompt", result.Error ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("-p", "SECRET_CANARY")]
    [InlineData("--password", "SECRET_CANARY")]
    public void ScanArguments_RejectPasswordOptionWithoutEchoingFollowingSecret(
        string option,
        string secret)
    {
        var result = CliArgumentParser.Parse(
        [
            "scan",
            "--target", "dc01.mini.lab",
            "--output", "audit.dogad",
            "-u", "MINILAB\\alice",
            option, secret
        ]);

        Assert.False(result.Success);
        Assert.DoesNotContain(secret, result.Error ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public void ScanArguments_RejectInlinePasswordWithoutEchoingIt()
    {
        const string secret = "SECRET_CANARY";
        var result = CliArgumentParser.Parse(
        [
            "scan",
            "--target", "dc01.mini.lab",
            "--output", "audit.dogad",
            "-u", "MINILAB\\alice",
            $"--password={secret}"
        ]);

        Assert.False(result.Success);
        Assert.DoesNotContain(secret, result.Error ?? string.Empty, StringComparison.Ordinal);
        Assert.Contains("hidden interactive prompt", result.Error ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ScanArguments_RejectIpTargetWithExplicitNegotiateCredential()
    {
        var result = CliArgumentParser.Parse(
        [
            "scan",
            "--target", "192.168.57.30",
            "--output", "audit.dogad",
            "-u", "MINILAB\\alice"
        ]);

        Assert.False(result.Success);
        Assert.Contains("DNS hostname", result.Error ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("IP address", result.Error ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("MINILAB\\alice", "alice", "MINILAB")]
    [InlineData("alice@mini.lab", "alice@mini.lab", null)]
    public void CredentialPrompt_SplitsDomainQualifiedNames(
        string input,
        string expectedAccount,
        string? expectedDomain)
    {
        var result = ConsoleCredentialPrompt.SplitAccountName(input);

        Assert.Equal(expectedAccount, result.AccountName);
        Assert.Equal(expectedDomain, result.Domain);
    }

    [Fact]
    public void InspectArguments_ParseSnapshotOnly()
    {
        var result = CliArgumentParser.Parse(
            ["inspect", "--snapshot", "audit.dogad"]);

        Assert.True(result.Success, result.Error);
        var command = Assert.IsType<InspectCommand>(result.Command);
        Assert.Equal("audit.dogad", command.SnapshotPath);
    }

    [Fact]
    public async Task ScanWorkflow_WritesAndReadsVerifiedDogadWithoutNetwork()
    {
        var token = TestContext.Current.CancellationToken;
        var directory = Path.Combine(
            Path.GetTempPath(),
            $"dogfighter-cli-{Guid.NewGuid():N}");
        var artifactPath = Path.Combine(directory, "synthetic.dogad");

        try
        {
            var profile = new CollectionProfile
            {
                Name = "synthetic",
                RequestedCapabilities = new HashSet<string>(StringComparer.Ordinal)
                {
                    CollectionCapabilities.DirectoryCore
                },
                MaxConcurrency = 1,
                CollectorTimeout = TimeSpan.FromSeconds(5)
            };
            var workflow = new ScanWorkflow();

            var result = await workflow.ExecuteAsync(
                new ScanWorkflowRequest
                {
                    Target = "synthetic",
                    OutputPath = artifactPath,
                    ProductVersion = "test",
                    Profile = profile,
                    Collectors = [new SyntheticRootCollector()]
                },
                token);

            Assert.Equal(SnapshotCompletionStatus.Complete, result.Snapshot.Metadata.CompletionStatus);
            Assert.True(File.Exists(artifactPath));
            Assert.DoesNotContain(
                Directory.EnumerateFiles(directory),
                path => Path.GetFileName(path).Contains(".tmp-", StringComparison.Ordinal));

            var serializer = new DogadArtifactSerializer();
            await using var source = File.OpenRead(artifactPath);
            var readBack = await serializer.ReadAsync(source, cancellationToken: token);

            Assert.Equal(result.Snapshot.Metadata.SnapshotId, readBack.Metadata.SnapshotId);
            Assert.Equal("synthetic", readBack.Metadata.CollectionProfile);
            Assert.Equal("dc01.synthetic.test", readBack.Metadata.Target.RootDseDnsHostName);
            Assert.Equal("synthetic.test", readBack.Metadata.Target.ForestDnsName);
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Theory]
    [InlineData(SnapshotCompletionStatus.Complete, CliExitCodes.Success)]
    [InlineData(SnapshotCompletionStatus.Partial, CliExitCodes.Partial)]
    [InlineData(SnapshotCompletionStatus.Failed, CliExitCodes.CollectionFailed)]
    public void ExitCode_ReflectsSnapshotCompleteness(
        SnapshotCompletionStatus status,
        int expected)
    {
        Assert.Equal(expected, CliExitCodes.FromSnapshotStatus(status));
    }

    private sealed class SyntheticRootCollector : ICollector
    {
        public string Id => "test.root";
        public string Version => "1";
        public IReadOnlySet<string> ProvidesCapabilities { get; } =
            new HashSet<string>(StringComparer.Ordinal)
            {
                CollectionCapabilities.DirectoryCore
            };
        public IReadOnlySet<string> RequiresCapabilities { get; } =
            new HashSet<string>(StringComparer.Ordinal);

        public Task<CollectorResult> CollectAsync(
            CollectionContext context,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var now = DateTimeOffset.UtcNow;

            return Task.FromResult(new CollectorResult(
                Id,
                Version,
                new SnapshotFragment
                {
                    Content = new SnapshotContent
                    {
                        DirectoryEnvironment = new DirectoryEnvironment
                        {
                            DnsHostName = "dc01.synthetic.test",
                            DefaultNamingContext = "DC=synthetic,DC=test",
                            RootDomainNamingContext = "DC=synthetic,DC=test",
                            ConfigurationNamingContext = "CN=Configuration,DC=synthetic,DC=test",
                            SchemaNamingContext = "CN=Schema,CN=Configuration,DC=synthetic,DC=test",
                            NamingContexts = ["DC=synthetic,DC=test"]
                        }
                    },
                    Coverage =
                    [
                        new CapabilityCoverage
                        {
                            CapabilityId = CollectionCapabilities.DirectoryCore,
                            ContractVersion = CapabilityContractCatalog.GetCurrentVersion(
                                CollectionCapabilities.DirectoryCore),
                            Status = CapabilityStatus.Complete,
                            StartedAt = now,
                            CompletedAt = now,
                            ObservedItemCount = 1
                        }
                    ]
                }));
        }
    }
}
