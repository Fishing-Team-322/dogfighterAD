using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class CertificateServicesApplicabilityTests
{
    private static readonly DateTimeOffset FixedNow =
        new(2026, 9, 8, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task CollectAsync_NoCaAndNoNtAuth_TrustIsCompleteWithZeroItems()
    {
        var collector = CreateCollector([]);

        var result = await collector.CollectAsync(CreateContext(), CancellationToken.None);

        AssertStatus(result, CollectionCapabilities.AdcsAuthorities, CapabilityStatus.NotApplicable, 0);
        AssertStatus(result, CollectionCapabilities.AdcsTemplates, CapabilityStatus.NotApplicable, 0);
        AssertStatus(result, CollectionCapabilities.AdcsPublication, CapabilityStatus.NotApplicable, 0);
        AssertStatus(result, CollectionCapabilities.AdcsAcls, CapabilityStatus.NotApplicable, 0);
        AssertStatus(result, CollectionCapabilities.AdcsTrust, CapabilityStatus.Complete, 0);

        var trust = Assert.IsType<CertificateServiceTrust>(result.Fragment.Content.CertificateServices!.Trust);
        Assert.False(trust.NtAuthObjectPresent);
        Assert.Contains(result.Fragment.Observations, fact =>
            fact.CapabilityId == CollectionCapabilities.AdcsTrust &&
            fact.Path == "trust.ntAuthObjectPresent" &&
            fact.Value == "false");
    }

    [Fact]
    public async Task CollectAsync_NoCaButNtAuthPresent_TrustIsCompleteWithOneItem()
    {
        var collector = CreateCollector([NtAuthEntry()]);

        var result = await collector.CollectAsync(CreateContext(), CancellationToken.None);

        AssertStatus(result, CollectionCapabilities.AdcsAuthorities, CapabilityStatus.NotApplicable, 0);
        AssertStatus(result, CollectionCapabilities.AdcsTemplates, CapabilityStatus.NotApplicable, 0);
        AssertStatus(result, CollectionCapabilities.AdcsPublication, CapabilityStatus.NotApplicable, 0);
        AssertStatus(result, CollectionCapabilities.AdcsAcls, CapabilityStatus.NotApplicable, 0);
        AssertStatus(result, CollectionCapabilities.AdcsTrust, CapabilityStatus.Complete, 1);

        var trust = Assert.IsType<CertificateServiceTrust>(result.Fragment.Content.CertificateServices!.Trust);
        Assert.True(trust.NtAuthObjectPresent);
        Assert.Equal(
            "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=mini,DC=lab",
            trust.DistinguishedName);
    }

    private static void AssertStatus(
        CollectorResult result,
        string capabilityId,
        CapabilityStatus expectedStatus,
        int expectedItems)
    {
        var coverage = Assert.Single(
            result.Fragment.Coverage,
            item => item.CapabilityId == capabilityId);
        Assert.Equal(expectedStatus, coverage.Status);
        Assert.Equal(expectedItems, coverage.ObservedItemCount);
        Assert.Empty(coverage.Issues);
    }

    private static CertificateServicesCollector CreateCollector(IReadOnlyList<LdapSearchEntry> entries) =>
        new(
            new FakeLdapClientFactory(new FakeLdapClient(new LdapSearchResult(entries))),
            new FixedTimeProvider(FixedNow));

    private static CollectionContext CreateContext() =>
        new(
            Guid.Parse("11111111-2222-3333-4444-555555555555"),
            "dc01.mini.lab",
            new HashSet<string>(StringComparer.Ordinal)
            {
                CollectionCapabilities.AdcsAuthorities,
                CollectionCapabilities.AdcsTemplates,
                CollectionCapabilities.AdcsPublication,
                CollectionCapabilities.AdcsAcls,
                CollectionCapabilities.AdcsTrust
            },
            new SnapshotFragment
            {
                Content = new SnapshotContent
                {
                    DirectoryEnvironment = new DirectoryEnvironment
                    {
                        DnsHostName = "dc01.mini.lab",
                        DefaultNamingContext = "DC=mini,DC=lab",
                        ConfigurationNamingContext = "CN=Configuration,DC=mini,DC=lab",
                        SchemaNamingContext = "CN=Schema,CN=Configuration,DC=mini,DC=lab",
                        RootDomainNamingContext = "DC=mini,DC=lab"
                    }
                }
            });

    private static LdapSearchEntry NtAuthEntry() =>
        new()
        {
            DistinguishedName = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=mini,DC=lab",
            Attributes = new Dictionary<string, IReadOnlyList<LdapAttributeValue>>(StringComparer.OrdinalIgnoreCase)
            {
                ["objectClass"] =
                [
                    LdapAttributeValue.FromText("top"),
                    LdapAttributeValue.FromText("certificationAuthority")
                ],
                ["objectGUID"] =
                [
                    LdapAttributeValue.FromBytes(
                        Guid.Parse("cccccccc-1111-2222-3333-444444444444").ToByteArray())
                ],
                ["cn"] = [LdapAttributeValue.FromText("NTAuthCertificates")]
            }
        };

    private sealed class FakeLdapClientFactory : IReadOnlyLdapClientFactory
    {
        private readonly IReadOnlyLdapClient client;

        public FakeLdapClientFactory(IReadOnlyLdapClient client) => this.client = client;

        public ValueTask<IReadOnlyLdapClient> CreateAsync(
            string target,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(client);
        }
    }

    private sealed class FakeLdapClient : IReadOnlyLdapClient
    {
        private readonly LdapSearchResult result;

        public FakeLdapClient(LdapSearchResult result) => this.result = result;

        public Task<LdapSearchResult> SearchAsync(
            LdapSearchRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(result);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset now;

        public FixedTimeProvider(DateTimeOffset now) => this.now = now;

        public override DateTimeOffset GetUtcNow() => now;
    }
}
