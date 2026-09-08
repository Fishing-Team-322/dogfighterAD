using System.Globalization;
using System.Text;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Application.Analysis.Rules;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Collectors.ActiveDirectory.Sysvol;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Analysis;

public sealed class AnalysisCollectionTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task SecurityPolicyCollectorPreservesMissingFieldsInsteadOfDefaulting(bool omitLength)
    {
        var domain = DomainEntry(omitLength); var client = new PolicyClient(domain, PsoEntry());
        var collector = new SecurityPolicyCollector(new PolicyFactory(client), new FixedClock());
        var result = await collector.CollectAsync(new(Guid.NewGuid(), "review.invalid", new HashSet<string> { CollectionCapabilities.DirectorySecurityPolicy },
            new() { Content = new() { Domains = [AnalysisFixture.Domain] } }), TestContext.Current.CancellationToken);
        var coverage = Assert.Single(result.Fragment.Coverage);
        Assert.Equal(omitLength ? CapabilityStatus.Partial : CapabilityStatus.Complete, coverage.Status);
        Assert.Equal(2, coverage.ObservedItemCount);
        var domainFacts = result.Fragment.Observations.Where(f => f.SubjectId == AnalysisFixture.Subject(AnalysisFixture.Domain)).ToArray();
        if (omitLength)
        {
            Assert.DoesNotContain(domainFacts, f => f.Path == "policy.minimumPasswordLength");
            Assert.Contains(domainFacts, f => f.Path == "policy.minimumPasswordLength.readState" && f.Value == "NotReturned");
        }
        else Assert.Contains(domainFacts, f => f.Path == "policy.minimumPasswordLength" && f.Value == "14");
        Assert.Contains(domainFacts, f => f.Path == "policy.complexityEnabled" && f.Value == "true");
        Assert.Contains(result.Fragment.Observations, f => f.SubjectId.StartsWith("password-policy:", StringComparison.Ordinal) && f.Path == "policy.minimumPasswordLength" && f.Value == "20");
        Assert.Contains(client.Requests, r => r.Attributes.Contains("minPwdLength"));
        Assert.Contains(client.Requests, r => r.Attributes.Contains("msDS-MinimumPasswordLength"));
        Assert.DoesNotContain(client.Requests.SelectMany(r => r.Attributes), a => a is "unicodePwd" or "userPassword" or "msDS-ManagedPassword");
        Assert.All(result.Fragment.Observations, f => Assert.Equal(FactIdFactory.Create(f.CapabilityId, f.SubjectId, f.Path, f.ValueKind, f.Value), f.FactId));
    }
    public static IEnumerable<object[]> RegistryTemplateCases() => BuiltInRulePack.RegistryDefinitions.Select(d => new object[] { d.KeyPath, d.ValueName });
    [Theory, MemberData(nameof(RegistryTemplateCases))]
    public void CollectorNormalizesAllRuleDwordsFromSecurityTemplates(string keyPath, string name)
    {
        var text = $"[Registry Values]\r\nMACHINE\\{keyPath}\\{name}=4,1\r\n";
        var parsed = SysvolPolicyParsers.ParseSecurityTemplate(Encoding.UTF8.GetBytes(text), "Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf");
        Assert.True(parsed.Success, parsed.Error); var setting = Assert.Single(parsed.Settings);
        Assert.Equal(GpoSettingKind.RegistryPolicy, setting.Kind); Assert.Equal(FactDisposition.Stored, setting.Disposition);
        Assert.Equal(4u, setting.RegistryValueType); Assert.Equal(keyPath, setting.Section); Assert.Equal(name, setting.Key); Assert.Equal("1", setting.Value);
    }
    [Theory]
    [InlineData("MACHINE\\Software\\Private\\ClientSecret=1,SECRET_CANARY")]
    [InlineData("MACHINE\\Software\\Private\\Unknown=4,42")]
    [InlineData("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RunAsPPL=1,SECRET_CANARY")]
    public void SecurityTemplateExtensionDoesNotExportUnknownOrNonDwordValues(string line)
    {
        var parsed = SysvolPolicyParsers.ParseSecurityTemplate(Encoding.UTF8.GetBytes("[Registry Values]\n" + line), "Machine\\GptTmpl.inf");
        Assert.True(parsed.Success, parsed.Error); var setting = Assert.Single(parsed.Settings);
        Assert.Null(setting.Value); Assert.NotEqual(FactDisposition.Stored, setting.Disposition);
    }
    [Theory]
    [InlineData("<Groups />", "false")]
    [InlineData("<Groups cpassword='' />", "false")]
    [InlineData("<Groups cpassword='SECRET_CANARY' />", "true")]
    public void CpasswordSignalIsExplicitAndNeverContainsTheSecret(string xml, string expected)
    {
        var parsed = SysvolPolicyParsers.ScanPreferencesXml(Encoding.UTF8.GetBytes(xml), "Machine\\Preferences\\Groups\\Groups.xml");
        Assert.True(parsed.Success, parsed.Error); var setting = Assert.Single(parsed.Settings);
        Assert.Equal("cpassword-present", setting.Key); Assert.Equal(expected, setting.Value);
        Assert.DoesNotContain(parsed.Settings, s => s.Value?.Contains("SECRET_CANARY", StringComparison.Ordinal) == true);
    }
    private static LdapSearchEntry DomainEntry(bool omitLength)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        { ["minPwdLength"] = "14", ["pwdHistoryLength"] = "24", ["lockoutThreshold"] = "5", ["lockoutDuration"] = "-9000000000",
          ["lockOutObservationWindow"] = "-9000000000", ["minPwdAge"] = "-864000000000", ["maxPwdAge"] = "-36288000000000",
          ["ms-DS-MachineAccountQuota"] = "0", ["pwdProperties"] = "1" };
        if (omitLength) values.Remove("minPwdLength");
        return Entry(AnalysisFixture.Domain.Id.Value, AnalysisFixture.Domain.DistinguishedName, values);
    }
    private static LdapSearchEntry PsoEntry() => Entry(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), "CN=Admins,CN=Password Settings Container,CN=System,DC=review,DC=invalid",
        new Dictionary<string, string>
        { ["msDS-MinimumPasswordLength"] = "20", ["msDS-PasswordHistoryLength"] = "24", ["msDS-LockoutThreshold"] = "5",
          ["msDS-LockoutDuration"] = "-9000000000", ["msDS-LockoutObservationWindow"] = "-9000000000",
          ["msDS-MinimumPasswordAge"] = "-864000000000", ["msDS-MaximumPasswordAge"] = "-36288000000000",
          ["msDS-PasswordSettingsPrecedence"] = "1", ["msDS-PasswordComplexityEnabled"] = "TRUE", ["msDS-PasswordReversibleEncryptionEnabled"] = "FALSE" });
    private static LdapSearchEntry Entry(Guid id, string dn, Dictionary<string, string> values)
    {
        var attributes = values.ToDictionary(k => k.Key, v => (IReadOnlyList<LdapAttributeValue>)new[] { LdapAttributeValue.FromText(v.Value) }, StringComparer.OrdinalIgnoreCase);
        attributes["objectGUID"] = [LdapAttributeValue.FromBytes(id.ToByteArray())];
        return new() { DistinguishedName = dn, Attributes = attributes };
    }
    private sealed class FixedClock : TimeProvider { public override DateTimeOffset GetUtcNow() => AnalysisFixture.Now; }
    private sealed class PolicyFactory(PolicyClient client) : IReadOnlyLdapClientFactory
    {
        public ValueTask<IReadOnlyLdapClient> CreateAsync(string target, CancellationToken cancellationToken) => ValueTask.FromResult<IReadOnlyLdapClient>(client);
    }
    private sealed class PolicyClient(LdapSearchEntry domain, LdapSearchEntry pso) : IReadOnlyLdapClient
    {
        public List<LdapSearchRequest> Requests { get; } = [];
        public Task<LdapSearchResult> SearchAsync(LdapSearchRequest request, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); Requests.Add(request); return Task.FromResult(new LdapSearchResult([request.Scope == LdapSearchScope.Base ? domain : pso])); }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
