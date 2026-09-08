using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Collectors.ActiveDirectory.Collectors;

/// <summary>
/// Read-only AD CS directory collector. It reads the Configuration NC only and deliberately does not
/// contact CA RPC endpoints, registry, web enrollment, HTTP(S), or any other runtime surface.
/// </summary>
public sealed class CertificateServicesCollector : ICollector
{
    public const string CollectorId = "ad.ldap.adcs";
    public const string CollectorVersion = "0.3.2";
    private const int DefaultPageSize = 500;

    private static readonly IReadOnlySet<string> ProvidedCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.AdcsAuthorities,
            CollectionCapabilities.AdcsTemplates,
            CollectionCapabilities.AdcsPublication,
            CollectionCapabilities.AdcsAcls,
            CollectionCapabilities.AdcsTrust
        };

    private static readonly IReadOnlySet<string> RequiredCapabilities =
        new HashSet<string>(StringComparer.Ordinal)
        {
            CollectionCapabilities.DirectoryCore
        };

    private static readonly string[] Attributes =
    [
        "objectClass",
        "objectGUID",
        "objectSid",
        "cn",
        "displayName",
        "dNSHostName",
        "whenCreated",
        "whenChanged",
        "certificateTemplates",
        "cACertificate",
        "msPKI-Cert-Template-OID",
        "msPKI-Template-Schema-Version",
        "msPKI-Template-Minor-Revision",
        "pKIExtendedKeyUsage",
        "msPKI-Certificate-Application-Policy",
        "msPKI-Certificate-Name-Flag",
        "msPKI-Enrollment-Flag",
        "msPKI-Private-Key-Flag",
        "msPKI-RA-Signature",
        "pKIExpirationPeriod",
        "pKIOverlapPeriod",
        "nTSecurityDescriptor"
    ];

    private readonly IReadOnlyLdapClientFactory _ldapClientFactory;
    private readonly SecurityDescriptorDaclParser _daclParser = new();
    private readonly TimeProvider _timeProvider;

    public CertificateServicesCollector(
        IReadOnlyLdapClientFactory ldapClientFactory,
        TimeProvider? timeProvider = null)
    {
        _ldapClientFactory = ldapClientFactory ?? throw new ArgumentNullException(nameof(ldapClientFactory));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public string Id => CollectorId;
    public string Version => CollectorVersion;
    public IReadOnlySet<string> ProvidesCapabilities => ProvidedCapabilities;
    public IReadOnlySet<string> RequiresCapabilities => RequiredCapabilities;

    public async Task<CollectorResult> CollectAsync(
        CollectionContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var startedAt = _timeProvider.GetUtcNow();
        var configurationNc = context.AvailableData.Content.DirectoryEnvironment?.ConfigurationNamingContext;
        if (string.IsNullOrWhiteSpace(configurationNc))
        {
            var completedAt = _timeProvider.GetUtcNow();
            return new CollectorResult(
                CollectorId,
                CollectorVersion,
                FailureFragment(
                    context.Target,
                    "collection.adcs.configuration-naming-context-unavailable",
                    "AD CS collection requires RootDSE configurationNamingContext.",
                    startedAt,
                    completedAt));
        }

        var publicKeyServicesDn = $"CN=Public Key Services,CN=Services,{configurationNc}";
        var authorities = new List<CertificateAuthority>();
        var templates = new List<CertificateTemplate>();
        var publications = new List<CertificateTemplatePublication>();
        var descriptors = new List<AdSecurityDescriptor>();
        var aces = new List<AdAce>();
        var observations = new List<ObservedFact>();
        var issues = new List<CollectionIssue>();
        var authorityPublishedNames = new Dictionary<AdObjectId, IReadOnlyList<string>>();
        var ntAuthEntries = new List<LdapSearchEntry>();

        await using var client = await _ldapClientFactory
            .CreateAsync(context.Target, cancellationToken)
            .ConfigureAwait(false);

        var request = new LdapSearchRequest
        {
            BaseDn = publicKeyServicesDn,
            Filter = "(|(objectClass=pKIEnrollmentService)(objectClass=pKICertificateTemplate)(&(objectClass=certificationAuthority)(cn=NTAuthCertificates)))",
            Scope = LdapSearchScope.Subtree,
            Attributes = Attributes,
            PageSize = DefaultPageSize,
            SecurityDescriptorSections = LdapSecurityDescriptorSections.Dacl
        };

        await foreach (var entry in client.SearchEntriesAsync(request, cancellationToken))
        {
            var classes = entry.GetTextValues("objectClass");
            if (classes.Contains("pKIEnrollmentService", StringComparer.OrdinalIgnoreCase))
            {
                CollectAuthority(
                    entry,
                    context.Target,
                    authorities,
                    authorityPublishedNames,
                    descriptors,
                    aces,
                    observations,
                    issues);
            }
            else if (classes.Contains("pKICertificateTemplate", StringComparer.OrdinalIgnoreCase))
            {
                CollectTemplate(
                    entry,
                    context.Target,
                    templates,
                    descriptors,
                    aces,
                    observations,
                    issues);
            }
            else if (classes.Contains("certificationAuthority", StringComparer.OrdinalIgnoreCase) &&
                     string.Equals(entry.GetSingleTextValue("cn"), "NTAuthCertificates", StringComparison.OrdinalIgnoreCase))
            {
                ntAuthEntries.Add(entry);
            }
        }

        ResolvePublications(
            authorityPublishedNames,
            templates,
            publications,
            observations,
            issues,
            context.Target);

        var trust = CollectTrust(
            ntAuthEntries,
            context.Target,
            observations,
            issues);

        var orderedAuthorities = authorities.OrderBy(item => item.Id.Value).ToArray();
        var orderedTemplates = templates.OrderBy(item => item.Id.Value).ToArray();
        var orderedPublications = publications
            .Distinct()
            .OrderBy(item => item.AuthorityId.Value)
            .ThenBy(item => item.TemplateId.Value)
            .ToArray();
        var orderedDescriptors = descriptors
            .OrderBy(item => item.TargetObjectId.Value)
            .ToArray();
        var orderedAces = aces
            .OrderBy(item => item.TargetObjectId.Value)
            .ThenBy(item => item.AceIndex)
            .ToArray();

        var completed = _timeProvider.GetUtcNow();
        var noAuthorities = orderedAuthorities.Length == 0;
        var noDirectoryAdcsObjects = noAuthorities && orderedTemplates.Length == 0;
        var trustItemCount = trust.NtAuthObjectPresent ? 1 : 0;
        var certificateServices = new CertificateServicesSnapshot
        {
            Authorities = orderedAuthorities,
            Templates = orderedTemplates,
            Publications = orderedPublications,
            SecurityDescriptors = orderedDescriptors,
            Aces = orderedAces,
            Trust = trust
        };

        return new CollectorResult(
            CollectorId,
            CollectorVersion,
            new SnapshotFragment
            {
                Content = new SnapshotContent
                {
                    CertificateServices = certificateServices
                },
                Coverage =
                [
                    Coverage(CollectionCapabilities.AdcsAuthorities, orderedAuthorities.Length, startedAt, completed, issues, noAuthorities),
                    Coverage(CollectionCapabilities.AdcsTemplates, orderedTemplates.Length, startedAt, completed, issues, noDirectoryAdcsObjects),
                    Coverage(CollectionCapabilities.AdcsPublication, orderedPublications.Length, startedAt, completed, issues, noAuthorities),
                    Coverage(CollectionCapabilities.AdcsAcls, orderedDescriptors.Length, startedAt, completed, issues, noDirectoryAdcsObjects),
                    Coverage(CollectionCapabilities.AdcsTrust, trustItemCount, startedAt, completed, issues, notApplicable: false)
                ],
                Observations = observations
                    .DistinctBy(item => item.FactId, StringComparer.Ordinal)
                    .OrderBy(item => item.FactId, StringComparer.Ordinal)
                    .ToArray()
            });
    }

    private void CollectAuthority(
        LdapSearchEntry entry,
        string endpoint,
        ICollection<CertificateAuthority> authorities,
        IDictionary<AdObjectId, IReadOnlyList<string>> publishedNames,
        ICollection<AdSecurityDescriptor> descriptors,
        ICollection<AdAce> aces,
        ICollection<ObservedFact> observations,
        ICollection<CollectionIssue> issues)
    {
        var id = LdapValueConverters.GetGuid(entry, "objectGUID");
        if (!id.HasValue)
        {
            issues.Add(Issue(
                CollectionCapabilities.AdcsAuthorities,
                "collection.adcs.authority.object-guid-missing",
                $"Enrollment Services object '{entry.DistinguishedName}' has no usable objectGUID.",
                endpoint));
            return;
        }

        var objectId = new AdObjectId(id.Value);
        var subjectId = AuthoritySubject(objectId);
        var certificates = ParseCertificates(
            entry,
            "cACertificate",
            CollectionCapabilities.AdcsAuthorities,
            subjectId,
            endpoint,
            issues);
        var cn = entry.GetSingleTextValue("cn");
        var published = GetPublishedTemplateNames(entry, issues, endpoint);

        authorities.Add(new CertificateAuthority
        {
            Id = objectId,
            DistinguishedName = entry.DistinguishedName,
            Sid = LdapValueConverters.GetSid(entry, "objectSid"),
            Name = cn,
            WhenCreated = LdapValueConverters.GetDateTimeOffset(entry, "whenCreated"),
            WhenChanged = LdapValueConverters.GetDateTimeOffset(entry, "whenChanged"),
            DnsHostName = entry.GetSingleTextValue("dNSHostName"),
            Certificates = certificates
        });
        publishedNames[objectId] = published;

        AddTextFact(observations, CollectionCapabilities.AdcsAuthorities, subjectId, "authority.cn", cn, FactValueKind.Text, endpoint, entry.DistinguishedName);
        AddTextFact(observations, CollectionCapabilities.AdcsAuthorities, subjectId, "authority.dnsHostName", entry.GetSingleTextValue("dNSHostName"), FactValueKind.Text, endpoint, entry.DistinguishedName);
        foreach (var certificate in certificates)
        {
            AddTextFact(observations, CollectionCapabilities.AdcsAuthorities, subjectId, "authority.certificateSha256", certificate.Sha256, FactValueKind.Text, endpoint, entry.DistinguishedName);
        }
        foreach (var templateName in published)
        {
            AddTextFact(observations, CollectionCapabilities.AdcsPublication, subjectId, "authority.publishedTemplateName", templateName, FactValueKind.Text, endpoint, entry.DistinguishedName);
        }

        CollectDacl(entry, objectId, subjectId, endpoint, descriptors, aces, observations, issues);
    }

    private void CollectTemplate(
        LdapSearchEntry entry,
        string endpoint,
        ICollection<CertificateTemplate> templates,
        ICollection<AdSecurityDescriptor> descriptors,
        ICollection<AdAce> aces,
        ICollection<ObservedFact> observations,
        ICollection<CollectionIssue> issues)
    {
        var id = LdapValueConverters.GetGuid(entry, "objectGUID");
        var cn = entry.GetSingleTextValue("cn");
        if (!id.HasValue || string.IsNullOrWhiteSpace(cn))
        {
            issues.Add(Issue(
                CollectionCapabilities.AdcsTemplates,
                "collection.adcs.template.identity-missing",
                $"Certificate template '{entry.DistinguishedName}' is missing a usable objectGUID or cn.",
                endpoint));
            return;
        }

        var objectId = new AdObjectId(id.Value);
        var subjectId = TemplateSubject(objectId);
        var expirationTicks = ReadIntervalTicks(entry, "pKIExpirationPeriod");
        var overlapTicks = ReadIntervalTicks(entry, "pKIOverlapPeriod");
        var nameFlags = LdapValueConverters.GetInt32(entry, "msPKI-Certificate-Name-Flag");
        var enrollmentFlags = LdapValueConverters.GetInt32(entry, "msPKI-Enrollment-Flag");
        var privateKeyFlags = LdapValueConverters.GetInt32(entry, "msPKI-Private-Key-Flag");
        var raSignatures = LdapValueConverters.GetInt32(entry, "msPKI-RA-Signature");

        ValidateRequiredTemplateOperands(
            entry,
            nameFlags,
            enrollmentFlags,
            privateKeyFlags,
            raSignatures,
            expirationTicks,
            overlapTicks,
            issues,
            endpoint);

        var ekus = entry.GetTextValues("pKIExtendedKeyUsage")
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();
        var applicationPolicies = entry.GetTextValues("msPKI-Certificate-Application-Policy")
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();

        templates.Add(new CertificateTemplate
        {
            Id = objectId,
            DistinguishedName = entry.DistinguishedName,
            Sid = LdapValueConverters.GetSid(entry, "objectSid"),
            Name = cn,
            CommonName = cn,
            DisplayName = entry.GetSingleTextValue("displayName"),
            WhenCreated = LdapValueConverters.GetDateTimeOffset(entry, "whenCreated"),
            WhenChanged = LdapValueConverters.GetDateTimeOffset(entry, "whenChanged"),
            TemplateOid = entry.GetSingleTextValue("msPKI-Cert-Template-OID"),
            SchemaVersion = LdapValueConverters.GetInt32(entry, "msPKI-Template-Schema-Version"),
            MinorRevision = LdapValueConverters.GetInt32(entry, "msPKI-Template-Minor-Revision"),
            ExtendedKeyUsages = ekus,
            ApplicationPolicies = applicationPolicies,
            CertificateNameFlags = nameFlags,
            EnrollmentFlags = enrollmentFlags,
            PrivateKeyFlags = privateKeyFlags,
            RequiredAuthorizedSignatures = raSignatures,
            ExpirationPeriodTicks = expirationTicks,
            OverlapPeriodTicks = overlapTicks
        });

        AddTextFact(observations, CollectionCapabilities.AdcsTemplates, subjectId, "template.cn", cn, FactValueKind.Text, endpoint, entry.DistinguishedName);
        AddTextFact(observations, CollectionCapabilities.AdcsTemplates, subjectId, "template.displayName", entry.GetSingleTextValue("displayName"), FactValueKind.Text, endpoint, entry.DistinguishedName);
        AddTextFact(observations, CollectionCapabilities.AdcsTemplates, subjectId, "template.oid", entry.GetSingleTextValue("msPKI-Cert-Template-OID"), FactValueKind.Text, endpoint, entry.DistinguishedName);
        AddIntegerFact(observations, CollectionCapabilities.AdcsTemplates, subjectId, "template.schemaVersion", LdapValueConverters.GetInt32(entry, "msPKI-Template-Schema-Version"), endpoint, entry.DistinguishedName);
        AddIntegerFact(observations, CollectionCapabilities.AdcsTemplates, subjectId, "template.minorRevision", LdapValueConverters.GetInt32(entry, "msPKI-Template-Minor-Revision"), endpoint, entry.DistinguishedName);
        AddIntegerFact(observations, CollectionCapabilities.AdcsTemplates, subjectId, "template.certificateNameFlags", nameFlags, endpoint, entry.DistinguishedName);
        AddIntegerFact(observations, CollectionCapabilities.AdcsTemplates, subjectId, "template.enrollmentFlags", enrollmentFlags, endpoint, entry.DistinguishedName);
        AddIntegerFact(observations, CollectionCapabilities.AdcsTemplates, subjectId, "template.privateKeyFlags", privateKeyFlags, endpoint, entry.DistinguishedName);
        AddIntegerFact(observations, CollectionCapabilities.AdcsTemplates, subjectId, "template.requiredAuthorizedSignatures", raSignatures, endpoint, entry.DistinguishedName);
        AddIntegerFact(observations, CollectionCapabilities.AdcsTemplates, subjectId, "template.expirationPeriodTicks", expirationTicks, endpoint, entry.DistinguishedName);
        AddIntegerFact(observations, CollectionCapabilities.AdcsTemplates, subjectId, "template.overlapPeriodTicks", overlapTicks, endpoint, entry.DistinguishedName);
        foreach (var eku in ekus)
        {
            AddTextFact(observations, CollectionCapabilities.AdcsTemplates, subjectId, "template.eku", eku, FactValueKind.Text, endpoint, entry.DistinguishedName);
        }
        foreach (var policy in applicationPolicies)
        {
            AddTextFact(observations, CollectionCapabilities.AdcsTemplates, subjectId, "template.applicationPolicy", policy, FactValueKind.Text, endpoint, entry.DistinguishedName);
        }

        CollectDacl(entry, objectId, subjectId, endpoint, descriptors, aces, observations, issues);
    }

    private static void ValidateRequiredTemplateOperands(
        LdapSearchEntry entry,
        int? nameFlags,
        int? enrollmentFlags,
        int? privateKeyFlags,
        int? raSignatures,
        long? expirationTicks,
        long? overlapTicks,
        ICollection<CollectionIssue> issues,
        string endpoint)
    {
        var missing = new List<string>();
        if (!nameFlags.HasValue) missing.Add("msPKI-Certificate-Name-Flag");
        if (!enrollmentFlags.HasValue) missing.Add("msPKI-Enrollment-Flag");
        if (!privateKeyFlags.HasValue) missing.Add("msPKI-Private-Key-Flag");
        if (!raSignatures.HasValue) missing.Add("msPKI-RA-Signature");
        if (!expirationTicks.HasValue) missing.Add("pKIExpirationPeriod");
        if (!overlapTicks.HasValue) missing.Add("pKIOverlapPeriod");

        if (missing.Count > 0)
        {
            issues.Add(Issue(
                CollectionCapabilities.AdcsTemplates,
                "collection.adcs.template.operands-missing",
                $"Certificate template '{entry.DistinguishedName}' is missing or has invalid security operand(s): {string.Join(", ", missing)}.",
                endpoint));
        }
    }

    private IReadOnlyList<CertificateServiceCertificate> ParseCertificates(
        LdapSearchEntry entry,
        string attributeName,
        string capability,
        string subjectId,
        string endpoint,
        ICollection<CollectionIssue> issues)
    {
        var result = new List<CertificateServiceCertificate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in entry.GetBinaryValues(attributeName))
        {
            try
            {
                using var certificate = X509CertificateLoader.LoadCertificate(raw);
                var sha256 = certificate.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant();
                if (!seen.Add(sha256))
                {
                    continue;
                }

                result.Add(new CertificateServiceCertificate
                {
                    Sha256 = sha256,
                    Subject = certificate.Subject,
                    Issuer = certificate.Issuer,
                    SerialNumber = certificate.SerialNumber,
                    NotBefore = new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
                    NotAfter = new DateTimeOffset(certificate.NotAfter.ToUniversalTime())
                });
            }
            catch (CryptographicException)
            {
                issues.Add(Issue(
                    capability,
                    "collection.adcs.certificate.invalid",
                    $"AD CS object '{entry.DistinguishedName}' contains a cACertificate value that could not be parsed as X.509.",
                    endpoint));
            }
        }

        return result
            .OrderBy(item => item.Sha256, StringComparer.Ordinal)
            .ToArray();
    }

    private static IReadOnlyList<string> GetPublishedTemplateNames(
        LdapSearchEntry entry,
        ICollection<CollectionIssue> issues,
        string endpoint)
    {
        var ranged = entry.Attributes.Keys.Any(name =>
            name.StartsWith("certificateTemplates;range=", StringComparison.OrdinalIgnoreCase));
        if (ranged)
        {
            issues.Add(Issue(
                CollectionCapabilities.AdcsPublication,
                "collection.adcs.publication.range-incomplete",
                $"CA '{entry.DistinguishedName}' returned ranged certificateTemplates data; publication inventory is not complete.",
                endpoint));
        }

        if (!entry.Attributes.ContainsKey("certificateTemplates") && !ranged)
        {
            issues.Add(Issue(
                CollectionCapabilities.AdcsPublication,
                "collection.adcs.publication.attribute-unavailable",
                $"CA '{entry.DistinguishedName}' did not return certificateTemplates; empty publication was not inferred.",
                endpoint));
        }

        return entry.GetTextValues("certificateTemplates")
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ThenBy(value => value, StringComparer.Ordinal)
            .ToArray();
    }

    private void ResolvePublications(
        IReadOnlyDictionary<AdObjectId, IReadOnlyList<string>> authorityPublishedNames,
        IReadOnlyCollection<CertificateTemplate> templates,
        ICollection<CertificateTemplatePublication> publications,
        ICollection<ObservedFact> observations,
        ICollection<CollectionIssue> issues,
        string endpoint)
    {
        var byName = templates
            .GroupBy(item => item.CommonName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);

        foreach (var authority in authorityPublishedNames.OrderBy(pair => pair.Key.Value))
        {
            foreach (var publishedName in authority.Value)
            {
                if (!byName.TryGetValue(publishedName, out var matches) || matches.Length != 1)
                {
                    issues.Add(Issue(
                        CollectionCapabilities.AdcsPublication,
                        "collection.adcs.publication.template-unresolved",
                        $"CA {authority.Key} publishes template name '{publishedName}', but it did not resolve to exactly one collected template.",
                        endpoint));
                    continue;
                }

                var template = matches[0];
                publications.Add(new CertificateTemplatePublication(authority.Key, template.Id));
                AddTextFact(
                    observations,
                    CollectionCapabilities.AdcsPublication,
                    TemplateSubject(template.Id),
                    "template.publishedOnCa",
                    authority.Key.ToString(),
                    FactValueKind.Guid,
                    endpoint,
                    template.DistinguishedName);
            }
        }
    }

    private CertificateServiceTrust CollectTrust(
        IReadOnlyList<LdapSearchEntry> entries,
        string endpoint,
        ICollection<ObservedFact> observations,
        ICollection<CollectionIssue> issues)
    {
        if (entries.Count == 0)
        {
            AddTextFact(
                observations,
                CollectionCapabilities.AdcsTrust,
                "adcs-trust:ntauth",
                "trust.ntAuthObjectPresent",
                "false",
                FactValueKind.Boolean,
                endpoint,
                "CN=NTAuthCertificates");
            return new CertificateServiceTrust
            {
                NtAuthObjectPresent = false
            };
        }

        if (entries.Count > 1)
        {
            issues.Add(Issue(
                CollectionCapabilities.AdcsTrust,
                "collection.adcs.trust.duplicate-ntauth",
                $"LDAP returned {entries.Count} NTAuthCertificates objects; exactly one was expected.",
                endpoint));
        }

        var entry = entries
            .OrderBy(item => item.DistinguishedName, StringComparer.OrdinalIgnoreCase)
            .First();
        var id = LdapValueConverters.GetGuid(entry, "objectGUID");
        if (!id.HasValue)
        {
            issues.Add(Issue(
                CollectionCapabilities.AdcsTrust,
                "collection.adcs.trust.object-guid-missing",
                $"NTAuthCertificates object '{entry.DistinguishedName}' has no usable objectGUID.",
                endpoint));
        }

        var subjectId = id.HasValue ? $"adcs-trust:{id.Value:D}" : "adcs-trust:ntauth";
        var certificates = ParseCertificates(
            entry,
            "cACertificate",
            CollectionCapabilities.AdcsTrust,
            subjectId,
            endpoint,
            issues);

        AddTextFact(observations, CollectionCapabilities.AdcsTrust, subjectId, "trust.ntAuthObjectPresent", "true", FactValueKind.Boolean, endpoint, entry.DistinguishedName);
        foreach (var certificate in certificates)
        {
            AddTextFact(observations, CollectionCapabilities.AdcsTrust, subjectId, "trust.certificateSha256", certificate.Sha256, FactValueKind.Text, endpoint, entry.DistinguishedName);
        }

        return new CertificateServiceTrust
        {
            NtAuthObjectPresent = true,
            NtAuthObjectId = id.HasValue ? new AdObjectId(id.Value) : null,
            DistinguishedName = entry.DistinguishedName,
            Certificates = certificates
        };
    }

    private void CollectDacl(
        LdapSearchEntry entry,
        AdObjectId targetId,
        string subjectId,
        string endpoint,
        ICollection<AdSecurityDescriptor> descriptors,
        ICollection<AdAce> aces,
        ICollection<ObservedFact> observations,
        ICollection<CollectionIssue> issues)
    {
        var values = entry.GetBinaryValues("nTSecurityDescriptor");
        if (values.Count != 1)
        {
            issues.Add(Issue(
                CollectionCapabilities.AdcsAcls,
                "collection.adcs.acl.security-descriptor-unavailable",
                $"AD CS object '{entry.DistinguishedName}' returned {values.Count} nTSecurityDescriptor values; exactly one DACL descriptor was expected.",
                endpoint));
            return;
        }

        var parsed = _daclParser.Parse(values[0]);
        if (parsed.DescriptorStateReliable)
        {
            descriptors.Add(new AdSecurityDescriptor
            {
                TargetObjectId = targetId,
                DaclState = parsed.State,
                ControlFlags = parsed.ControlFlags
            });
            AddTextFact(observations, CollectionCapabilities.AdcsAcls, subjectId, "securityDescriptor.parseComplete", parsed.Complete ? "true" : "false", FactValueKind.Boolean, endpoint, entry.DistinguishedName);
            AddTextFact(observations, CollectionCapabilities.AdcsAcls, subjectId, "securityDescriptor.aceCount", parsed.Aces.Count.ToString(CultureInfo.InvariantCulture), FactValueKind.Integer, endpoint, entry.DistinguishedName);
            AddTextFact(observations, CollectionCapabilities.AdcsAcls, subjectId, "securityDescriptor.daclState", parsed.State.ToString(), FactValueKind.Text, endpoint, entry.DistinguishedName);
            AddTextFact(observations, CollectionCapabilities.AdcsAcls, subjectId, "securityDescriptor.controlFlags", parsed.ControlFlags.ToString(CultureInfo.InvariantCulture), FactValueKind.Integer, endpoint, entry.DistinguishedName);
        }

        for (var index = 0; index < parsed.Aces.Count; index++)
        {
            var source = parsed.Aces[index];
            var ace = new AdAce
            {
                TargetObjectId = targetId,
                AceIndex = index,
                TrusteeSid = source.TrusteeSid,
                AccessType = source.AccessType,
                AccessMask = source.AccessMask,
                AceFlags = source.AceFlags,
                ObjectType = source.ObjectType,
                InheritedObjectType = source.InheritedObjectType,
                IsInherited = source.IsInherited
            };
            aces.Add(ace);

            var prefix = $"securityDescriptor.dacl.ace[{index}]";
            AddTextFact(observations, CollectionCapabilities.AdcsAcls, subjectId, $"{prefix}.trusteeSid", ace.TrusteeSid, FactValueKind.Sid, endpoint, entry.DistinguishedName);
            AddTextFact(observations, CollectionCapabilities.AdcsAcls, subjectId, $"{prefix}.accessType", ace.AccessType.ToString(), FactValueKind.Text, endpoint, entry.DistinguishedName);
            AddTextFact(observations, CollectionCapabilities.AdcsAcls, subjectId, $"{prefix}.accessMask", ace.AccessMask.ToString(CultureInfo.InvariantCulture), FactValueKind.Integer, endpoint, entry.DistinguishedName);
            AddTextFact(observations, CollectionCapabilities.AdcsAcls, subjectId, $"{prefix}.aceFlags", ace.AceFlags.ToString(CultureInfo.InvariantCulture), FactValueKind.Integer, endpoint, entry.DistinguishedName);
            AddTextFact(observations, CollectionCapabilities.AdcsAcls, subjectId, $"{prefix}.objectTypePresent", ace.ObjectType.HasValue ? "true" : "false", FactValueKind.Boolean, endpoint, entry.DistinguishedName);
            AddTextFact(observations, CollectionCapabilities.AdcsAcls, subjectId, $"{prefix}.objectType", ace.ObjectType?.ToString("D"), FactValueKind.Guid, endpoint, entry.DistinguishedName);
            AddTextFact(observations, CollectionCapabilities.AdcsAcls, subjectId, $"{prefix}.isInherited", ace.IsInherited ? "true" : "false", FactValueKind.Boolean, endpoint, entry.DistinguishedName);
        }

        if (!parsed.Complete)
        {
            issues.Add(Issue(
                CollectionCapabilities.AdcsAcls,
                "collection.adcs.acl.security-descriptor-partial",
                $"DACL for '{entry.DistinguishedName}' could not be fully normalized: {parsed.Error}",
                endpoint));
        }
    }

    private static long? ReadIntervalTicks(LdapSearchEntry entry, string attributeName)
    {
        var values = entry.GetBinaryValues(attributeName);
        if (values.Count != 1 || values[0].Length != sizeof(long))
        {
            return null;
        }

        return BinaryPrimitives.ReadInt64LittleEndian(values[0]);
    }

    private void AddIntegerFact(
        ICollection<ObservedFact> observations,
        string capability,
        string subjectId,
        string path,
        long? value,
        string endpoint,
        string locator)
    {
        AddTextFact(
            observations,
            capability,
            subjectId,
            path,
            value?.ToString(CultureInfo.InvariantCulture),
            FactValueKind.Integer,
            endpoint,
            locator);
    }

    private void AddTextFact(
        ICollection<ObservedFact> observations,
        string capability,
        string subjectId,
        string path,
        string? value,
        FactValueKind kind,
        string endpoint,
        string locator)
    {
        if (value is null)
        {
            return;
        }

        observations.Add(new ObservedFact
        {
            FactId = FactIdFactory.Create(capability, subjectId, path, kind, value),
            CapabilityId = capability,
            SubjectId = subjectId,
            Path = path,
            Value = value,
            ValueKind = kind,
            Source = new ObservationSource
            {
                CollectorId = CollectorId,
                CollectorVersion = CollectorVersion,
                SourceKind = "ldap",
                Endpoint = endpoint,
                Locator = locator
            },
            ObservedAt = _timeProvider.GetUtcNow()
        });
    }

    private static CapabilityCoverage Coverage(
        string capability,
        int observedItemCount,
        DateTimeOffset startedAt,
        DateTimeOffset completedAt,
        IReadOnlyCollection<CollectionIssue> issues,
        bool notApplicable)
    {
        var capabilityIssues = issues
            .Where(issue => StringComparer.Ordinal.Equals(issue.CapabilityId, capability))
            .OrderBy(issue => issue.Code, StringComparer.Ordinal)
            .ThenBy(issue => issue.Message, StringComparer.Ordinal)
            .ToArray();

        return new CapabilityCoverage
        {
            CapabilityId = capability,
            ContractVersion = CapabilityContractCatalog.GetCurrentVersion(capability),
            Status = capabilityIssues.Length > 0
                ? CapabilityStatus.Partial
                : notApplicable
                    ? CapabilityStatus.NotApplicable
                    : CapabilityStatus.Complete,
            StartedAt = startedAt,
            CompletedAt = completedAt,
            ObservedItemCount = observedItemCount,
            Issues = capabilityIssues
        };
    }

    private static CollectionIssue Issue(
        string capability,
        string code,
        string message,
        string target) =>
        new()
        {
            Code = code,
            Severity = CollectionIssueSeverity.Error,
            Message = message,
            CapabilityId = capability,
            CollectorId = CollectorId,
            Target = target
        };

    private static string AuthoritySubject(AdObjectId id) => $"adcs-ca:{id}";
    private static string TemplateSubject(AdObjectId id) => $"adcs-template:{id}";

    private static SnapshotFragment FailureFragment(
        string target,
        string code,
        string message,
        DateTimeOffset startedAt,
        DateTimeOffset completedAt)
    {
        var issue = new CollectionIssue
        {
            Code = code,
            Severity = CollectionIssueSeverity.Error,
            Message = message,
            CollectorId = CollectorId,
            Target = target
        };

        return new SnapshotFragment
        {
            Coverage = ProvidedCapabilities
                .OrderBy(capability => capability, StringComparer.Ordinal)
                .Select(capability => new CapabilityCoverage
                {
                    CapabilityId = capability,
                    ContractVersion = CapabilityContractCatalog.GetCurrentVersion(capability),
                    Status = CapabilityStatus.Failed,
                    StartedAt = startedAt,
                    CompletedAt = completedAt,
                    ObservedItemCount = 0,
                    Issues = [issue with { CapabilityId = capability }]
                })
                .ToArray()
        };
    }
}
