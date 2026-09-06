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
            AuthenticationMode = SelectAuthenticationMode(ldapCredential),
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

    internal static LdapAuthenticationMode SelectAuthenticationMode(NetworkCredential? credential)
    {
        // A down-level DOMAIN\\user identity from a non-domain workstation should not depend on
        // Kerberos KDC/SPN discovery merely to reach the explicitly named DC. Use NTLM challenge/
        // response for that explicit identity. Current-OS-context and UPN credentials retain
        // Negotiate so Kerberos remains available where the environment supports it.
        return credential is not null && !string.IsNullOrWhiteSpace(credential.Domain)
            ? LdapAuthenticationMode.Ntlm
            : LdapAuthenticationMode.Negotiate;
    }
}
