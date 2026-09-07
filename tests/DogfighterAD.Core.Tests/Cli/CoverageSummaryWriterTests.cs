using DogfighterAD.Cli;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Cli;

public sealed class CoverageSummaryWriterTests
{
    [Fact]
    public async Task WriteAsync_PrintsIssueCodeSeverityAndSafeMessage()
    {
        var now = DateTimeOffset.UtcNow;
        const string safeMessage = "LDAP authentication failed (code=49/InvalidCredentials).";
        var snapshot = new AdSnapshot
        {
            Metadata = new SnapshotMetadata
            {
                SnapshotId = Guid.NewGuid(),
                SchemaVersion = SnapshotSchema.CurrentVersion,
                ProductVersion = "test",
                StartedAt = now,
                CompletedAt = now,
                CompletionStatus = SnapshotCompletionStatus.Failed,
                Target = new TargetIdentity { InitialTarget = "dc.mini.lab" },
                CollectionProfile = "minimal",
                RequestedCapabilities = [CollectionCapabilities.DirectoryCore]
            },
            Coverage =
            [
                new CapabilityCoverage
                {
                    CapabilityId = CollectionCapabilities.DirectoryCore,
                    Status = CapabilityStatus.Failed,
                    StartedAt = now,
                    CompletedAt = now,
                    Issues =
                    [
                        new CollectionIssue
                        {
                            Code = "collection.ldap.authentication-failed",
                            Severity = CollectionIssueSeverity.Error,
                            Message = safeMessage,
                            CapabilityId = CollectionCapabilities.DirectoryCore,
                            CollectorId = "ad.ldap.rootdse",
                            Target = "dc.mini.lab"
                        }
                    ]
                }
            ]
        };
        using var writer = new StringWriter();

        await CoverageSummaryWriter.WriteAsync(writer, snapshot);
        var text = writer.ToString();

        Assert.Contains("directory.core", text, StringComparison.Ordinal);
        Assert.Contains(
            $"[Error] collection.ldap.authentication-failed: {safeMessage}",
            text,
            StringComparison.Ordinal);
    }
}
