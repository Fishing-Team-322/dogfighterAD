namespace DogfighterAD.Domain.Snapshots;

/// <summary>
/// Normalized directory-derived AD CS posture. This model deliberately contains only facts that can
/// be collected read-only from Active Directory. CA runtime/registry/RPC/web-enrollment state belongs
/// to separate future capabilities and must not be inferred from these objects.
/// </summary>
public sealed record CertificateServicesSnapshot
{
    public IReadOnlyList<CertificateAuthority> Authorities { get; init; } = [];
    public IReadOnlyList<CertificateTemplate> Templates { get; init; } = [];
    public IReadOnlyList<CertificateTemplatePublication> Publications { get; init; } = [];

    /// <summary>
    /// DACL rows are intentionally scoped inside CertificateServices instead of being mixed into the
    /// directory.acls inventory. The same normalized ACE representation is reused, but coverage and
    /// absence semantics remain owned by adcs.acls.
    /// </summary>
    public IReadOnlyList<AdSecurityDescriptor> SecurityDescriptors { get; init; } = [];
    public IReadOnlyList<AdAce> Aces { get; init; } = [];

    public CertificateServiceTrust? Trust { get; init; }
}

public sealed record CertificateAuthority : AdDirectoryObject
{
    /// <summary>DNS host name published on the pKIEnrollmentService object.</summary>
    public string? DnsHostName { get; init; }

    public IReadOnlyList<CertificateServiceCertificate> Certificates { get; init; } = [];
}

public sealed record CertificateTemplate : AdDirectoryObject
{
    public required string CommonName { get; init; }
    public string? DisplayName { get; init; }
    public string? TemplateOid { get; init; }
    public int? SchemaVersion { get; init; }
    public int? MinorRevision { get; init; }

    public IReadOnlyList<string> ExtendedKeyUsages { get; init; } = [];
    public IReadOnlyList<string> ApplicationPolicies { get; init; } = [];

    public int? CertificateNameFlags { get; init; }
    public int? EnrollmentFlags { get; init; }
    public int? PrivateKeyFlags { get; init; }
    public int? RequiredAuthorizedSignatures { get; init; }

    /// <summary>
    /// Raw AD interval converted to signed 100-nanosecond ticks. AD stores certificate-template
    /// validity/overlap periods as negative relative intervals; preserving the signed value keeps
    /// the source semantics available to offline analysis without inventing a display unit.
    /// </summary>
    public long? ExpirationPeriodTicks { get; init; }
    public long? OverlapPeriodTicks { get; init; }
}

public sealed record CertificateTemplatePublication(
    AdObjectId AuthorityId,
    AdObjectId TemplateId);

/// <summary>Directory posture of CN=NTAuthCertificates for the forest.</summary>
public sealed record CertificateServiceTrust
{
    public bool NtAuthObjectPresent { get; init; }
    public AdObjectId? NtAuthObjectId { get; init; }
    public string? DistinguishedName { get; init; }
    public IReadOnlyList<CertificateServiceCertificate> Certificates { get; init; } = [];
}

/// <summary>
/// Non-secret certificate metadata sufficient for inventory, UI display and NTAuth/CA matching.
/// The DER certificate is intentionally not persisted merely because it is readable.
/// </summary>
public sealed record CertificateServiceCertificate
{
    public required string Sha256 { get; init; }
    public string? Subject { get; init; }
    public string? Issuer { get; init; }
    public string? SerialNumber { get; init; }
    public DateTimeOffset? NotBefore { get; init; }
    public DateTimeOffset? NotAfter { get; init; }
}
