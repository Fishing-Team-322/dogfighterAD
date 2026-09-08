using DogfighterAD.Domain.Snapshots;
using DogfighterAD.Web;

namespace DogfighterAD.Core.Tests;

public sealed class WebCertificateServicesViewTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 8, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void FromSnapshot_LegacySnapshotWithoutCertificateServices_IsUnavailable()
    {
        var view = UiCertificateServicesView.FromSnapshot(CreateSnapshot(certificateServices: null));

        Assert.False(view.Available);
        Assert.Empty(view.Authorities);
        Assert.Empty(view.Templates);
    }

    [Fact]
    public void FromSnapshot_ProjectsPublicationTrustAndDirectAceRights()
    {
        var authorityId = new AdObjectId(Guid.Parse("aaaaaaaa-1111-2222-3333-444444444444"));
        var templateId = new AdObjectId(Guid.Parse("bbbbbbbb-1111-2222-3333-444444444444"));
        var authority = new CertificateAuthority
        {
            Id = authorityId,
            DistinguishedName = "CN=MINI-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=mini,DC=lab",
            Name = "MINI-CA",
            DnsHostName = "ca01.mini.lab"
        };
        var template = new CertificateTemplate
        {
            Id = templateId,
            DistinguishedName = "CN=UserTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=mini,DC=lab",
            Name = "UserTemplate",
            CommonName = "UserTemplate",
            DisplayName = "User Template",
            ExtendedKeyUsages = ["1.3.6.1.5.5.7.3.2"]
        };
        var services = new CertificateServicesSnapshot
        {
            Authorities = [authority],
            Templates = [template],
            Publications = [new CertificateTemplatePublication(authorityId, templateId)],
            SecurityDescriptors = [new AdSecurityDescriptor { TargetObjectId = templateId, DaclState = AdDaclState.Present }],
            Aces =
            [
                new AdAce
                {
                    TargetObjectId = templateId,
                    AceIndex = 0,
                    TrusteeSid = "S-1-5-11",
                    AccessType = AdAccessControlType.Allow,
                    AccessMask = 0x40000100,
                    AceFlags = 0,
                    ObjectType = null,
                    IsInherited = false
                }
            ],
            Trust = new CertificateServiceTrust
            {
                NtAuthObjectPresent = true,
                DistinguishedName = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=mini,DC=lab"
            }
        };

        var view = UiCertificateServicesView.FromSnapshot(CreateSnapshot(services));

        Assert.True(view.Available);
        var ca = Assert.Single(view.Authorities);
        Assert.Equal("ca01.mini.lab", ca.DnsHostName);
        Assert.Equal("User Template", Assert.Single(ca.PublishedTemplates).Name);

        var projectedTemplate = Assert.Single(view.Templates);
        Assert.Equal("MINI-CA", Assert.Single(projectedTemplate.PublishedAuthorities).Name);
        Assert.Equal("Present", projectedTemplate.DaclState);
        var ace = Assert.Single(projectedTemplate.DirectAces);
        Assert.Contains("GenericWrite", ace.Rights);
        Assert.Contains("Enroll", ace.Rights);
        Assert.Contains("AutoEnroll", ace.Rights);
        Assert.True(view.NtAuth!.ObjectPresent);
    }

    private static AdSnapshot CreateSnapshot(CertificateServicesSnapshot? certificateServices) => new()
    {
        Metadata = new SnapshotMetadata
        {
            SnapshotId = Guid.Parse("11111111-2222-3333-4444-555555555555"),
            SchemaVersion = SnapshotSchema.CurrentVersion,
            ProductVersion = "ui-test",
            StartedAt = Now.AddMinutes(-1),
            CompletedAt = Now,
            CompletionStatus = SnapshotCompletionStatus.Complete,
            Target = new TargetIdentity { InitialTarget = "dc01.mini.lab" },
            RequestedCapabilities = [],
            Collectors = []
        },
        Content = new SnapshotContent { CertificateServices = certificateServices },
        Coverage = certificateServices is null
            ? []
            :
            [
                new CapabilityCoverage
                {
                    CapabilityId = CollectionCapabilities.AdcsTemplates,
                    ContractVersion = 1,
                    Status = CapabilityStatus.Complete,
                    StartedAt = Now.AddMinutes(-1),
                    CompletedAt = Now,
                    ObservedItemCount = certificateServices.Templates.Count
                }
            ]
    };
}
