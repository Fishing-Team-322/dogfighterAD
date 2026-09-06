using DogfighterAD.Application.Contracts;
using DogfighterAD.Collectors.ActiveDirectory.Collectors;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;
using DogfighterAD.Collectors.ActiveDirectory.Sysvol;

namespace DogfighterAD.Cli;

internal static class CollectionComposition
{
    public static IReadOnlyCollection<ICollector> CreateCollectors(ScanCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);

        var ldapFactory = new SystemLdapClientFactory(new LdapClientOptions
        {
            Port = command.LdapPort ?? (command.UseLdaps ? 636 : 389),
            UseLdaps = command.UseLdaps,
            RequestTimeout = TimeSpan.FromSeconds(30)
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
}
