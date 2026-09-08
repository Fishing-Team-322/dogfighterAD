using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Web;

public sealed record UiCertificateServicesView
{
    public bool Available { get; init; }
    public IReadOnlyList<UiCertificateServicesCoverage> Coverage { get; init; } = [];
    public IReadOnlyList<UiCertificateAuthorityView> Authorities { get; init; } = [];
    public IReadOnlyList<UiCertificateTemplateView> Templates { get; init; } = [];
    public UiNtAuthView? NtAuth { get; init; }

    public static UiCertificateServicesView FromSnapshot(AdSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var services = snapshot.Content.CertificateServices;
        var coverage = snapshot.Coverage
            .Where(item => item.CapabilityId.StartsWith("adcs.", StringComparison.Ordinal))
            .OrderBy(item => item.CapabilityId, StringComparer.Ordinal)
            .Select(item => new UiCertificateServicesCoverage(
                item.CapabilityId,
                item.ContractVersion,
                item.Status.ToString(),
                item.ObservedItemCount,
                item.Issues.Select(issue => issue.Code).OrderBy(code => code, StringComparer.Ordinal).ToArray()))
            .ToArray();

        if (services is null)
        {
            return new UiCertificateServicesView
            {
                Available = false,
                Coverage = coverage
            };
        }

        var authorityById = services.Authorities.ToDictionary(item => item.Id);
        var templateById = services.Templates.ToDictionary(item => item.Id);
        var publicationsByAuthority = services.Publications
            .GroupBy(item => item.AuthorityId)
            .ToDictionary(group => group.Key, group => group.OrderBy(item => item.TemplateId.Value).ToArray());
        var publicationsByTemplate = services.Publications
            .GroupBy(item => item.TemplateId)
            .ToDictionary(group => group.Key, group => group.OrderBy(item => item.AuthorityId.Value).ToArray());
        var descriptorByTarget = services.SecurityDescriptors.ToDictionary(item => item.TargetObjectId);
        var acesByTarget = services.Aces
            .GroupBy(item => item.TargetObjectId)
            .ToDictionary(group => group.Key, group => group.OrderBy(item => item.AceIndex).ToArray());

        var authorities = services.Authorities
            .OrderBy(item => item.Name ?? item.DistinguishedName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Id.Value)
            .Select(authority =>
            {
                descriptorByTarget.TryGetValue(authority.Id, out var descriptor);
                var grants = acesByTarget.TryGetValue(authority.Id, out var targetAces)
                    ? targetAces.Select(MapGrant).ToArray()
                    : [];
                return new UiCertificateAuthorityView
                {
                    StableId = $"adcs-ca:{authority.Id}",
                    Name = authority.Name,
                    DistinguishedName = authority.DistinguishedName,
                    DnsHostName = authority.DnsHostName,
                    Certificates = authority.Certificates.Select(MapCertificate).ToArray(),
                    PublishedTemplates = publicationsByAuthority.TryGetValue(authority.Id, out var published)
                        ? published.Select(publication =>
                        {
                            templateById.TryGetValue(publication.TemplateId, out var template);
                            return new UiPublishedObject(
                                publication.TemplateId.ToString(),
                                template?.DisplayName ?? template?.CommonName ?? template?.Name ?? publication.TemplateId.ToString());
                        }).ToArray()
                        : [],
                    DaclState = descriptor?.DaclState.ToString(),
                    DirectAces = grants
                };
            })
            .ToArray();

        var templates = services.Templates
            .OrderBy(item => item.DisplayName ?? item.CommonName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Id.Value)
            .Select(template =>
            {
                descriptorByTarget.TryGetValue(template.Id, out var descriptor);
                var grants = acesByTarget.TryGetValue(template.Id, out var targetAces)
                    ? targetAces.Select(MapGrant).ToArray()
                    : [];
                var publishedAuthorities = publicationsByTemplate.TryGetValue(template.Id, out var published)
                    ? published.Select(publication =>
                    {
                        authorityById.TryGetValue(publication.AuthorityId, out var authority);
                        return new UiPublishedAuthority(
                            publication.AuthorityId.ToString(),
                            authority?.Name ?? publication.AuthorityId.ToString(),
                            authority?.DnsHostName);
                    }).ToArray()
                    : [];

                return new UiCertificateTemplateView
                {
                    StableId = $"adcs-template:{template.Id}",
                    CommonName = template.CommonName,
                    DisplayName = template.DisplayName,
                    DistinguishedName = template.DistinguishedName,
                    TemplateOid = template.TemplateOid,
                    SchemaVersion = template.SchemaVersion,
                    MinorRevision = template.MinorRevision,
                    CertificateNameFlags = template.CertificateNameFlags,
                    EnrollmentFlags = template.EnrollmentFlags,
                    PrivateKeyFlags = template.PrivateKeyFlags,
                    RequiredAuthorizedSignatures = template.RequiredAuthorizedSignatures,
                    ExpirationPeriodTicks = template.ExpirationPeriodTicks,
                    OverlapPeriodTicks = template.OverlapPeriodTicks,
                    ExtendedKeyUsages = template.ExtendedKeyUsages.OrderBy(value => value, StringComparer.Ordinal).ToArray(),
                    ApplicationPolicies = template.ApplicationPolicies.OrderBy(value => value, StringComparer.Ordinal).ToArray(),
                    PublishedAuthorities = publishedAuthorities,
                    DaclState = descriptor?.DaclState.ToString(),
                    DirectAces = grants
                };
            })
            .ToArray();

        return new UiCertificateServicesView
        {
            Available = true,
            Coverage = coverage,
            Authorities = authorities,
            Templates = templates,
            NtAuth = services.Trust is null
                ? null
                : new UiNtAuthView
                {
                    ObjectPresent = services.Trust.NtAuthObjectPresent,
                    DistinguishedName = services.Trust.DistinguishedName,
                    Certificates = services.Trust.Certificates.Select(MapCertificate).ToArray()
                }
        };
    }

    private static UiCertificateView MapCertificate(CertificateServiceCertificate certificate) => new()
    {
        Sha256 = certificate.Sha256,
        Subject = certificate.Subject,
        Issuer = certificate.Issuer,
        SerialNumber = certificate.SerialNumber,
        NotBefore = certificate.NotBefore,
        NotAfter = certificate.NotAfter
    };

    private static UiCertificateAceView MapGrant(AdAce ace) => new()
    {
        AceIndex = ace.AceIndex,
        TrusteeSid = ace.TrusteeSid,
        AccessType = ace.AccessType.ToString(),
        AccessMask = $"0x{ace.AccessMask:X8}",
        AceFlags = $"0x{ace.AceFlags:X2}",
        ObjectType = ace.ObjectType?.ToString("D"),
        IsInherited = ace.IsInherited,
        Rights = DescribeRights(ace).ToArray()
    };

    private static IEnumerable<string> DescribeRights(AdAce ace)
    {
        const uint controlAccess = 0x00000100;
        const uint writeProperty = 0x00000020;
        const uint writeDacl = 0x00040000;
        const uint writeOwner = 0x00080000;
        const uint genericWrite = 0x40000000;
        const uint genericAll = 0x10000000;
        var enroll = Guid.Parse("0e10c968-78fb-11d2-90d4-00c04f79dc55");
        var autoEnroll = Guid.Parse("a05b8cc2-17bc-4802-a710-e7c15ab866a2");

        if ((ace.AccessMask & genericAll) != 0) yield return "GenericAll";
        if ((ace.AccessMask & genericWrite) != 0) yield return "GenericWrite";
        if ((ace.AccessMask & writeDacl) != 0) yield return "WriteDacl";
        if ((ace.AccessMask & writeOwner) != 0) yield return "WriteOwner";
        if ((ace.AccessMask & writeProperty) != 0) yield return ace.ObjectType.HasValue ? "WriteProperty (scoped)" : "WriteProperty";
        if ((ace.AccessMask & controlAccess) != 0)
        {
            if (!ace.ObjectType.HasValue || ace.ObjectType.Value == enroll) yield return "Enroll";
            if (!ace.ObjectType.HasValue || ace.ObjectType.Value == autoEnroll) yield return "AutoEnroll";
            if (ace.ObjectType.HasValue && ace.ObjectType.Value != enroll && ace.ObjectType.Value != autoEnroll) yield return "ControlAccess (scoped)";
        }
    }
}

public sealed record UiCertificateServicesCoverage(
    string CapabilityId,
    int ContractVersion,
    string Status,
    int ObservedItemCount,
    IReadOnlyList<string> IssueCodes);

public sealed record UiPublishedObject(string Id, string Name);
public sealed record UiPublishedAuthority(string Id, string Name, string? DnsHostName);

public sealed record UiCertificateAuthorityView
{
    public required string StableId { get; init; }
    public string? Name { get; init; }
    public required string DistinguishedName { get; init; }
    public string? DnsHostName { get; init; }
    public IReadOnlyList<UiCertificateView> Certificates { get; init; } = [];
    public IReadOnlyList<UiPublishedObject> PublishedTemplates { get; init; } = [];
    public string? DaclState { get; init; }
    public IReadOnlyList<UiCertificateAceView> DirectAces { get; init; } = [];
}

public sealed record UiCertificateTemplateView
{
    public required string StableId { get; init; }
    public required string CommonName { get; init; }
    public string? DisplayName { get; init; }
    public required string DistinguishedName { get; init; }
    public string? TemplateOid { get; init; }
    public int? SchemaVersion { get; init; }
    public int? MinorRevision { get; init; }
    public int? CertificateNameFlags { get; init; }
    public int? EnrollmentFlags { get; init; }
    public int? PrivateKeyFlags { get; init; }
    public int? RequiredAuthorizedSignatures { get; init; }
    public long? ExpirationPeriodTicks { get; init; }
    public long? OverlapPeriodTicks { get; init; }
    public IReadOnlyList<string> ExtendedKeyUsages { get; init; } = [];
    public IReadOnlyList<string> ApplicationPolicies { get; init; } = [];
    public IReadOnlyList<UiPublishedAuthority> PublishedAuthorities { get; init; } = [];
    public string? DaclState { get; init; }
    public IReadOnlyList<UiCertificateAceView> DirectAces { get; init; } = [];
}

public sealed record UiCertificateAceView
{
    public int AceIndex { get; init; }
    public required string TrusteeSid { get; init; }
    public required string AccessType { get; init; }
    public required string AccessMask { get; init; }
    public required string AceFlags { get; init; }
    public string? ObjectType { get; init; }
    public bool IsInherited { get; init; }
    public IReadOnlyList<string> Rights { get; init; } = [];
}

public sealed record UiNtAuthView
{
    public bool ObjectPresent { get; init; }
    public string? DistinguishedName { get; init; }
    public IReadOnlyList<UiCertificateView> Certificates { get; init; } = [];
}

public sealed record UiCertificateView
{
    public required string Sha256 { get; init; }
    public string? Subject { get; init; }
    public string? Issuer { get; init; }
    public string? SerialNumber { get; init; }
    public DateTimeOffset? NotBefore { get; init; }
    public DateTimeOffset? NotAfter { get; init; }
}
