using System.Net;
using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Collectors.ActiveDirectory.Sysvol;

namespace DogfighterAD.Cli;

internal static class CollectionComposition
{
    internal static readonly TimeSpan LdapBindTimeout = TimeSpan.FromSeconds(15);
    internal static readonly TimeSpan LdapRequestTimeout = TimeSpan.FromSeconds(30);

    public static IReadOnlyCollection<ICollector> CreateCollectors(
        ScanCommand command,
        NetworkCredential? ldapCredential = null)
    {
        ArgumentNullException.ThrowIfNull(command);

        var ldapFactory = new SystemLdapClientFactory(new LdapClientOptions
        {
            Port = command.LdapPort ?? (command.UseLdaps ? 636 : 389),
            UseLdaps = command.UseLdaps,
            BindTimeout = LdapBindTimeout,
            RequestTimeout = LdapRequestTimeout,
            AuthenticationMode = SelectAuthenticationMode(command),
            TreatTargetAsFullyQualifiedDnsHostName = UsesExplicitNamedServerBinding(ldapCredential),
            Credential = ldapCredential
        });
        var sysvolFactory = new SystemSysvolClientFactory();
        var sysvolOptions = new SysvolClientOptions
        {
            ApprovedAuthorities = command.ApprovedSysvolAuthorities
        };

        return
        [
            new RootDseCollector(ldapFactory),
            new DomainMetadataCollector(ldapFactory),
            new DirectoryObjectsCollector(ldapFactory),
            new GroupMembershipCollector(ldapFactory),
            new TrustCollector(ldapFactory),
            new AclCollector(ldapFactory),
            new GpoMetadataCollector(ldapFactory),
            new GpoLinkCollector(ldapFactory),
            new GpoSysvolCollector(sysvolFactory, sysvolOptions)
        ];
    }

    internal static LdapAuthenticationMode SelectAuthenticationMode(ScanCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);
        return command.LdapAuthenticationMode;
    }

    internal static bool UsesExplicitNamedServerBinding(NetworkCredential? credential) =>
        credential is not null;
}
