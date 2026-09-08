using System.Globalization;

namespace DogfighterAD.Domain.Snapshots;

/// <summary>Only these explicitly reviewed non-secret DWORD settings are exported from security templates.</summary>
public static class SecurityRegistryCatalog
{
    public static IReadOnlyList<(string KeyPath, string ValueName)> Settings { get; } = new (string, string)[]
    {
        (@"Software\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated"),
        (@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"),
        (@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "LocalAccountTokenFilterPolicy"),
        (@"System\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential"),
        (@"System\CurrentControlSet\Control\Lsa", "RunAsPPL"),
        (@"System\CurrentControlSet\Control\Lsa", "NoLMHash"),
        (@"System\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel"),
        (@"System\CurrentControlSet\Services\NTDS\Parameters", "LDAPServerIntegrity"),
        (@"System\CurrentControlSet\Services\NTDS\Parameters", "LdapEnforceChannelBinding"),
        (@"System\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature"),
        (@"System\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature"),
        (@"System\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1"),
        (@"Software\Policies\Microsoft\Windows\LanmanWorkstation", "AllowInsecureGuestAuth"),
        (@"Software\Policies\Microsoft\Windows NT\Terminal Services", "UserAuthentication"),
        (@"Software\Policies\Microsoft\Windows NT\Terminal Services", "SecurityLayer"),
        (@"Software\Policies\Microsoft\Windows\WinRM\Service", "AllowBasic"),
        (@"Software\Policies\Microsoft\Windows\WinRM\Service", "AllowUnencryptedTraffic"),
        (@"Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters", "AllowEncryptionOracle"),
        (@"Software\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"),
        (@"Software\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate"),
    };
    public static bool Contains(string keyPath, string valueName) => Settings.Any(x =>
        x.KeyPath.Equals(keyPath, StringComparison.OrdinalIgnoreCase) && x.ValueName.Equals(valueName, StringComparison.OrdinalIgnoreCase));

    public static bool TryParseTemplateDword(string section, string key, string value,
        out string keyPath, out string valueName, out uint number)
    {
        keyPath = valueName = string.Empty; number = 0;
        if (!section.Equals("Registry Values", StringComparison.OrdinalIgnoreCase) ||
            !key.StartsWith("MACHINE\\", StringComparison.OrdinalIgnoreCase)) return false;
        var path = key[8..];
        var slash = path.LastIndexOf('\\');
        if (slash < 1 || slash == path.Length - 1) return false;
        keyPath = path[..slash]; valueName = path[(slash + 1)..];
        if (!Contains(keyPath, valueName)) return false;
        var fields = value.Split(',');
        return fields.Length == 2 && fields[0].Trim() == "4" &&
            uint.TryParse(fields[1].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out number);
    }
}
