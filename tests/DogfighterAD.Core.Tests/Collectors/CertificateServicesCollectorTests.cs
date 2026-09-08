using System.Buffers.Binary;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class CertificateServicesCollectorTests
{
    private static readonly DateTimeOffset FixedNow =
        new(2026, 9, 8, 12, 0, 0, TimeSpan.Zero);

    private static readonly Guid AuthorityGuid =
        Guid.Parse("aaaaaaaa-1111-2222-3333-444444444444");

    private static readonly Guid TemplateGuid =
        Guid.Parse("bbbbbbbb-1111-2222-3333-444444444444");

    [Fact]
    public async Task CollectAsync_CollectsAuthorityTemplatePublicationAclAndNtAuthPosture()
    {
        var client = new FakeLdapClient(new LdapSearchResult(
        [
            AuthorityEntry("UserTemplate"),
            TemplateEntry(),
            NtAuthEntry()
        ]));
        var collector = new CertificateServicesCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(CreateContext(), CancellationToken.None);

        var request = Assert.Single(client.Requests);
        Assert.Equal(
            "CN=Public Key Services,CN=Services,CN=Configuration,DC=mini,DC=lab",
            request.BaseDn);
        Assert.Equal(LdapSearchScope.Subtree, request.Scope);
        Assert.Equal(500, request.PageSize);
        Assert.Equal(LdapSecurityDescriptorSections.Dacl, request.SecurityDescriptorSections);
        Assert.Contains("certificateTemplates", request.Attributes);
        Assert.Contains("msPKI-Certificate-Name-Flag", request.Attributes);
        Assert.Contains("nTSecurityDescriptor", request.Attributes);

        var services = Assert.IsType<CertificateServicesSnapshot>(result.Fragment.Content.CertificateServices);
        var authority = Assert.Single(services.Authorities);
        Assert.Equal(new AdObjectId(AuthorityGuid), authority.Id);
        Assert.Equal("ca01.mini.lab", authority.DnsHostName);

        var template = Assert.Single(services.Templates);
        Assert.Equal(new AdObjectId(TemplateGuid), template.Id);
        Assert.Equal("UserTemplate", template.CommonName);
        Assert.Equal("1.3.6.1.5.5.7.3.2", Assert.Single(template.ExtendedKeyUsages));
        Assert.Equal(1, template.CertificateNameFlags);
        Assert.Equal(0, template.EnrollmentFlags);
        Assert.Equal(0, template.RequiredAuthorizedSignatures);
        Assert.Equal(-31_536_000_000_000L, template.ExpirationPeriodTicks);
        Assert.Equal(-6_048_000_000_000L, template.OverlapPeriodTicks);

        var publication = Assert.Single(services.Publications);
        Assert.Equal(authority.Id, publication.AuthorityId);
        Assert.Equal(template.Id, publication.TemplateId);
        Assert.Equal(2, services.SecurityDescriptors.Count);
        Assert.Empty(services.Aces);

        var trust = Assert.IsType<CertificateServiceTrust>(services.Trust);
        Assert.True(trust.NtAuthObjectPresent);

        Assert.All(result.Fragment.Coverage, coverage => Assert.Equal(CapabilityStatus.Complete, coverage.Status));
        Assert.Contains(result.Fragment.Observations, fact =>
            fact.CapabilityId == CollectionCapabilities.AdcsTemplates &&
            fact.SubjectId == $"adcs-template:{TemplateGuid:D}" &&
            fact.Path == "template.certificateNameFlags" &&
            fact.Value == "1");
        Assert.Contains(result.Fragment.Observations, fact =>
            fact.CapabilityId == CollectionCapabilities.AdcsPublication &&
            fact.Path == "template.publishedOnCa" &&
            fact.Value == AuthorityGuid.ToString("D"));
    }

    [Fact]
    public async Task CollectAsync_NoEnterpriseCa_IsNotApplicableInsteadOfFailure()
    {
        var client = new FakeLdapClient(new LdapSearchResult([]));
        var collector = new CertificateServicesCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(CreateContext(), CancellationToken.None);

        var services = Assert.IsType<CertificateServicesSnapshot>(result.Fragment.Content.CertificateServices);
        Assert.Empty(services.Authorities);
        Assert.Empty(services.Templates);
        Assert.Empty(services.Publications);
        Assert.All(result.Fragment.Coverage, coverage =>
        {
            Assert.Equal(CapabilityStatus.NotApplicable, coverage.Status);
            Assert.Empty(coverage.Issues);
        });
    }

    [Fact]
    public async Task CollectAsync_MissingTemplateOperand_MakesTemplatesPartial()
    {
        var template = TemplateEntry();
        var attributes = template.Attributes
            .Where(pair => !pair.Key.Equals("msPKI-RA-Signature", StringComparison.OrdinalIgnoreCase))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);
        var client = new FakeLdapClient(new LdapSearchResult(
        [
            AuthorityEntry("UserTemplate"),
            template with { Attributes = attributes }
        ]));
        var collector = new CertificateServicesCollector(
            new FakeLdapClientFactory(client),
            new FixedTimeProvider(FixedNow));

        var result = await collector.CollectAsync(CreateContext(), CancellationToken.None);

        var templateCoverage = Assert.Single(result.Fragment.Coverage.Where(item =>
            item.CapabilityId == CollectionCapabilities.AdcsTemplates));
        Assert.Equal(CapabilityStatus.Partial, templateCoverage.Status);
        Assert.Contains(templateCoverage.Issues, issue =>
            issue.Code == "collection.adcs.template.operands-missing" &&
            issue.Message.Contains("msPKI-RA-Signature", StringComparison.Ordinal));
    }

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

    private static LdapSearchEntry AuthorityEntry(string publishedTemplate) =>
        new()
        {
            DistinguishedName = "CN=MINI-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=mini,DC=lab",
            Attributes = Attributes(
                ("objectClass", Text("top", "pKIEnrollmentService")),
                ("objectGUID", Binary(AuthorityGuid.ToByteArray())),
                ("cn", Text("MINI-CA")),
                ("dNSHostName", Text("ca01.mini.lab")),
                ("certificateTemplates", Text(publishedTemplate)),
                ("nTSecurityDescriptor", Binary(EmptyDacl())))
        };

    private static LdapSearchEntry TemplateEntry() =>
        new()
        {
            DistinguishedName = "CN=UserTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=mini,DC=lab",
            Attributes = Attributes(
                ("objectClass", Text("top", "pKICertificateTemplate")),
                ("objectGUID", Binary(TemplateGuid.ToByteArray())),
                ("cn", Text("UserTemplate")),
                ("displayName", Text("User Template")),
                ("msPKI-Cert-Template-OID", Text("1.3.6.1.4.1.311.21.8.1")),
                ("msPKI-Template-Schema-Version", Text("2")),
                ("msPKI-Template-Minor-Revision", Text("3")),
                ("pKIExtendedKeyUsage", Text("1.3.6.1.5.5.7.3.2")),
                ("msPKI-Certificate-Application-Policy", Text("1.3.6.1.5.5.7.3.2")),
                ("msPKI-Certificate-Name-Flag", Text("1")),
                ("msPKI-Enrollment-Flag", Text("0")),
                ("msPKI-Private-Key-Flag", Text("0")),
                ("msPKI-RA-Signature", Text("0")),
                ("pKIExpirationPeriod", Binary(Int64Bytes(-31_536_000_000_000L))),
                ("pKIOverlapPeriod", Binary(Int64Bytes(-6_048_000_000_000L))),
                ("nTSecurityDescriptor", Binary(EmptyDacl())))
        };

    private static LdapSearchEntry NtAuthEntry() =>
        new()
        {
            DistinguishedName = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=mini,DC=lab",
            Attributes = Attributes(
                ("objectClass", Text("top", "certificationAuthority")),
                ("objectGUID", Binary(Guid.Parse("cccccccc-1111-2222-3333-444444444444").ToByteArray())),
                ("cn", Text("NTAuthCertificates")))
        };

    private static IReadOnlyDictionary<string, IReadOnlyList<LdapAttributeValue>> Attributes(
        params (string Name, IReadOnlyList<LdapAttributeValue> Values)[] values) =>
        values.ToDictionary(item => item.Name, item => item.Values, StringComparer.OrdinalIgnoreCase);

    private static IReadOnlyList<LdapAttributeValue> Text(params string[] values) =>
        values.Select(LdapAttributeValue.FromText).ToArray();

    private static IReadOnlyList<LdapAttributeValue> Binary(params byte[][] values) =>
        values.Select(LdapAttributeValue.FromBytes).ToArray();

    private static byte[] Int64Bytes(long value)
    {
        var bytes = new byte[sizeof(long)];
        BinaryPrimitives.WriteInt64LittleEndian(bytes, value);
        return bytes;
    }

    private static byte[] EmptyDacl()
    {
        const ushort selfRelativeAndDaclPresent = 0x8004;
        var descriptor = new byte[28];
        descriptor[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(descriptor.AsSpan(2, 2), selfRelativeAndDaclPresent);
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(16, 4), 20);
        descriptor[20] = 2;
        BinaryPrimitives.WriteUInt16LittleEndian(descriptor.AsSpan(22, 2), 8);
        return descriptor;
    }

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

        public List<LdapSearchRequest> Requests { get; } = [];

        public Task<LdapSearchResult> SearchAsync(
            LdapSearchRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(request);
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
