using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Collectors.ActiveDirectory.Sysvol;

internal static class SysvolPolicyParsers
{
    private static readonly HashSet<string> SafeGptIniKeys =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "Version",
            "displayName"
        };

    private static readonly HashSet<string> SafeSystemAccessKeys =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "MinimumPasswordAge",
            "MaximumPasswordAge",
            "MinimumPasswordLength",
            "PasswordComplexity",
            "PasswordHistorySize",
            "ClearTextPassword",
            "RequireLogonToChangePassword",
            "LockoutBadCount",
            "ResetLockoutCount",
            "LockoutDuration",
            "ForceLogoffWhenHourExpire",
            "NewAdministratorName",
            "NewGuestName",
            "EnableAdminAccount",
            "EnableGuestAccount",
            "LSAAnonymousNameLookup"
        };

    private static readonly HashSet<string> SafeEventAuditKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "AuditSystemEvents", "AuditLogonEvents", "AuditObjectAccess", "AuditPrivilegeUse",
        "AuditPolicyChange", "AuditAccountManage", "AuditProcessTracking", "AuditDSAccess", "AuditAccountLogon"
    };

    private static readonly HashSet<string> SafeKerberosKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "MaxTicketAge", "MaxRenewAge", "MaxServiceAge", "MaxClockSkew", "TicketValidateClient"
    };

    public static ParsedSettingsResult ParseGptIni(byte[] bytes, string relativePath) =>
        ParseIni(bytes, relativePath, GpoSettingKind.Ini, GpoPolicyScope.Common);

    public static ParsedSettingsResult ParseSecurityTemplate(byte[] bytes, string relativePath) =>
        ParseIni(bytes, relativePath, GpoSettingKind.SecurityTemplate, GpoPolicyScope.Machine);

    public static ParsedSettingsResult ParseRegistryPolicy(
        byte[] bytes,
        string relativePath,
        GpoPolicyScope scope)
    {
        if (bytes.Length < 8 || BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0, 4)) != 0x67655250)
        {
            return ParsedSettingsResult.Failed("Registry.pol has an invalid PReg signature.");
        }

        var version = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4, 4));
        if (version != 1)
        {
            return ParsedSettingsResult.Failed($"Registry.pol version {version} is not supported by v1.");
        }

        var settings = new List<ParsedSetting>();
        var offset = 8;
        var sequence = 0;

        try
        {
            while (offset < bytes.Length)
            {
                SkipUtf16Nulls(bytes, ref offset);
                if (offset >= bytes.Length)
                {
                    break;
                }

                ExpectUtf16Char(bytes, ref offset, '[');
                var keyPath = ReadNullTerminatedUtf16Field(bytes, ref offset);
                ExpectUtf16Char(bytes, ref offset, ';');
                var valueName = ReadNullTerminatedUtf16Field(bytes, ref offset);
                ExpectUtf16Char(bytes, ref offset, ';');

                // v1 has no explicit typed representation for a Registry.pol record with an empty
                // value name. Reject it at the parser boundary instead of constructing a setting
                // that the snapshot invariant validator will later reject and thereby losing the
                // entire scan artifact. A future model can add a dedicated operation/identity when
                // its protocol semantics are deliberately supported.
                if (valueName.Length == 0)
                {
                    return ParsedSettingsResult.Failed(
                        $"Registry.pol record {sequence + 1} has an empty value name that is not supported by v1.");
                }

                var type = ReadUInt32(bytes, ref offset);
                ExpectUtf16Char(bytes, ref offset, ';');
                var size = ReadUInt32(bytes, ref offset);
                ExpectUtf16Char(bytes, ref offset, ';');

                if (size > 65535 || size > bytes.Length - offset)
                {
                    return ParsedSettingsResult.Failed(
                        $"Registry.pol record {sequence + 1} declares invalid data size {size}.");
                }

                var data = bytes.AsSpan(offset, checked((int)size));
                offset += checked((int)size);
                ExpectUtf16Char(bytes, ref offset, ']');

                var normalized = NormalizeRegistryData(type, data);
                settings.Add(new ParsedSetting
                {
                    Scope = scope,
                    SourceRelativePath = relativePath,
                    Sequence = ++sequence,
                    Kind = GpoSettingKind.RegistryPolicy,
                    Section = keyPath,
                    Key = valueName,
                    Value = normalized.Value,
                    ValueKind = normalized.ValueKind,
                    Disposition = normalized.Disposition,
                    DataLength = data.Length,
                    RegistryValueType = type
                });
            }
        }
        catch (InvalidDataException exception)
        {
            return ParsedSettingsResult.Failed(exception.Message);
        }

        return ParsedSettingsResult.Succeeded(settings);
    }

    public static ParsedSettingsResult ScanPreferencesXml(byte[] bytes, string relativePath)
    {
        try
        {
            using var stream = new MemoryStream(bytes, writable: false);
            using var reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                IgnoreComments = true,
                IgnoreWhitespace = true
            });
            var document = XDocument.Load(reader, LoadOptions.None);
            var elements = document.Root?.DescendantsAndSelf() ?? Enumerable.Empty<XElement>();
            var cpasswordCount = elements
                .SelectMany(element => element.Attributes())
                .Count(attribute => string.Equals(
                    attribute.Name.LocalName,
                    "cpassword",
                    StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(attribute.Value));

            return ParsedSettingsResult.Succeeded(
            [
                new ParsedSetting
                {
                    Scope = ScopeFromRelativePath(relativePath),
                    SourceRelativePath = relativePath,
                    Sequence = 1,
                    Kind = GpoSettingKind.PreferenceSignal,
                    Section = "PreferencesXml",
                    Key = "cpassword-present",
                    Value = cpasswordCount > 0 ? "true" : "false",
                    ValueKind = FactValueKind.Boolean,
                    Disposition = FactDisposition.Stored,
                    DataLength = cpasswordCount
                }
            ]);
        }
        catch (XmlException)
        {
            return ParsedSettingsResult.Failed("Preferences XML is malformed. Source content is intentionally omitted.");
        }
    }

    public static GpoPolicyScope ScopeFromRelativePath(string relativePath)
    {
        if (relativePath.StartsWith("Machine\\", StringComparison.OrdinalIgnoreCase))
        {
            return GpoPolicyScope.Machine;
        }

        if (relativePath.StartsWith("User\\", StringComparison.OrdinalIgnoreCase))
        {
            return GpoPolicyScope.User;
        }

        return GpoPolicyScope.Common;
    }

    private static ParsedSettingsResult ParseIni(
        byte[] bytes,
        string relativePath,
        GpoSettingKind kind,
        GpoPolicyScope scope)
    {
        var text = DecodeText(bytes);
        var settings = new List<ParsedSetting>();
        var section = string.Empty;
        var sequence = 0;
        var lineNumber = 0;

        foreach (var rawLine in text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            lineNumber++;
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith(';') || line.StartsWith('#'))
            {
                continue;
            }

            if (line.StartsWith('[') && line.EndsWith(']') && line.Length > 2)
            {
                section = line[1..^1].Trim();
                continue;
            }

            var separator = line.IndexOf('=');
            if (separator <= 0)
            {
                return ParsedSettingsResult.Failed(
                    $"INI-like policy file '{relativePath}' has invalid line {lineNumber}.");
            }

            var key = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            if (kind == GpoSettingKind.SecurityTemplate &&
                SecurityRegistryCatalog.TryParseTemplateDword(section, key, value, out var registryPath, out var valueName, out var dword))
            {
                settings.Add(new ParsedSetting
                {
                    Scope = GpoPolicyScope.Machine, SourceRelativePath = relativePath,
                    Sequence = ++sequence, Kind = GpoSettingKind.RegistryPolicy,
                    Section = registryPath, Key = valueName,
                    Value = dword.ToString(CultureInfo.InvariantCulture), ValueKind = FactValueKind.Integer,
                    Disposition = FactDisposition.Stored, DataLength = 4, RegistryValueType = 4
                });
                continue;
            }
            var disposition = DetermineIniDisposition(kind, section, key, value);

            settings.Add(new ParsedSetting
            {
                Scope = scope,
                SourceRelativePath = relativePath,
                Sequence = ++sequence,
                Kind = kind,
                Section = section,
                Key = key,
                Value = disposition == FactDisposition.Stored ? value : null,
                ValueKind = FactValueKind.Text,
                Disposition = disposition,
                DataLength = Encoding.UTF8.GetByteCount(value)
            });
        }

        return ParsedSettingsResult.Succeeded(settings);
    }

    private static FactDisposition DetermineIniDisposition(
        GpoSettingKind kind,
        string section,
        string key,
        string value)
    {
        if (LooksSensitiveKey(key))
        {
            return FactDisposition.Redacted;
        }

        if (kind == GpoSettingKind.Ini)
        {
            return section.Equals("General", StringComparison.OrdinalIgnoreCase) && SafeGptIniKeys.Contains(key) &&
                (!key.Equals("Version", StringComparison.OrdinalIgnoreCase) || IsInteger(value))
                ? FactDisposition.Stored
                : FactDisposition.MetadataOnly;
        }

        if (kind != GpoSettingKind.SecurityTemplate)
        {
            return FactDisposition.MetadataOnly;
        }

        if (section.Equals("System Access", StringComparison.OrdinalIgnoreCase))
        {
            var accountName = key.Equals("NewAdministratorName", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("NewGuestName", StringComparison.OrdinalIgnoreCase);
            return SafeSystemAccessKeys.Contains(key) && (accountName || IsInteger(value))
                ? FactDisposition.Stored
                : FactDisposition.MetadataOnly;
        }

        // Approving an entire section exports arbitrary attacker-controlled keys. Require both
        // the known section/key and its expected value shape instead.
        var allowed = section.ToUpperInvariant() switch
        {
            "EVENT AUDIT" => SafeEventAuditKeys.Contains(key) && IsInteger(value),
            "KERBEROS POLICY" => SafeKerberosKeys.Contains(key) && IsInteger(value),
            "UNICODE" => key.Equals("Unicode", StringComparison.OrdinalIgnoreCase) && bool.TryParse(value, out _),
            "VERSION" => (key.Equals("Revision", StringComparison.OrdinalIgnoreCase) && IsInteger(value)) ||
                (key.Equals("signature", StringComparison.OrdinalIgnoreCase) && value.Trim('"').Equals("$CHICAGO$", StringComparison.OrdinalIgnoreCase)),
            "PRIVILEGE RIGHTS" => IsPrivilegeName(key) && IsSidList(value),
            "GROUP MEMBERSHIP" => IsMembershipKey(key) && IsSidList(value),
            _ => false
        };
        return allowed ? FactDisposition.Stored : FactDisposition.MetadataOnly;
    }

    private static bool IsInteger(string value) =>
        long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out _);

    private static bool IsPrivilegeName(string key) =>
        key.Length <= 100 && key.StartsWith("Se", StringComparison.Ordinal) &&
        (key.EndsWith("Privilege", StringComparison.Ordinal) || key.EndsWith("LogonRight", StringComparison.Ordinal)) &&
        key.All(char.IsAsciiLetter);

    private static bool IsMembershipKey(string key)
    {
        var separator = key.LastIndexOf("__", StringComparison.Ordinal);
        return separator > 0 && IsSid(key[..separator]) &&
            (key[(separator + 2)..].Equals("Members", StringComparison.OrdinalIgnoreCase) ||
             key[(separator + 2)..].Equals("Memberof", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsSidList(string value) =>
        value.Length == 0 || value.Split(',').All(item => IsSid(item.Trim()));

    private static bool IsSid(string value)
    {
        var sid = value.StartsWith('*') ? value[1..] : value;
        if (sid.Length > 184) return false;
        var parts = sid.Split('-');
        return parts.Length is >= 4 and <= 18 && parts[0] == "S" && parts[1] == "1" &&
            ulong.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var authority) &&
            authority <= 0xffffffffffffUL &&
            parts.Skip(3).All(part => uint.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out _));
    }

    private static bool LooksSensitiveKey(string key)
    {
        if (SafeSystemAccessKeys.Contains(key))
        {
            return false;
        }

        return key.Equals("password", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("passwd", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("pwd", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("secret", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("credential", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("credentials", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("cpassword", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("apikey", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("api_key", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("token", StringComparison.OrdinalIgnoreCase) ||
            key.EndsWith("Password", StringComparison.OrdinalIgnoreCase) ||
            key.EndsWith("Secret", StringComparison.OrdinalIgnoreCase) ||
            key.EndsWith("Token", StringComparison.OrdinalIgnoreCase) ||
            key.EndsWith("ApiKey", StringComparison.OrdinalIgnoreCase);
    }

    private static string DecodeText(byte[] bytes)
    {
        if (bytes.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF }))
        {
            bytes = bytes[3..];
        }

        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        }

        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
        {
            return Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2);
        }

        if (LooksLikeUtf16Le(bytes))
        {
            return Encoding.Unicode.GetString(bytes);
        }

        try
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return Encoding.Latin1.GetString(bytes);
        }
    }

    private static bool LooksLikeUtf16Le(byte[] bytes)
    {
        if (bytes.Length < 4 || bytes.Length % 2 != 0)
        {
            return false;
        }

        var sampledPairs = Math.Min(bytes.Length / 2, 64);
        var zeroHighBytes = 0;
        for (var index = 0; index < sampledPairs; index++)
        {
            if (bytes[(index * 2) + 1] == 0)
            {
                zeroHighBytes++;
            }
        }

        return zeroHighBytes >= sampledPairs * 3 / 4;
    }

    private static RegistryDataNormalization NormalizeRegistryData(uint type, ReadOnlySpan<byte> data)
    {
        return type switch
        {
            1 or 2 or 7 => new RegistryDataNormalization(
                null,
                type == 7 ? FactValueKind.Json : FactValueKind.Text,
                FactDisposition.MetadataOnly),
            3 => new RegistryDataNormalization(null, FactValueKind.Binary, FactDisposition.MetadataOnly),
            4 when data.Length == 4 => new RegistryDataNormalization(
                BinaryPrimitives.ReadUInt32LittleEndian(data).ToString(CultureInfo.InvariantCulture),
                FactValueKind.Integer,
                FactDisposition.Stored),
            5 when data.Length == 4 => new RegistryDataNormalization(
                BinaryPrimitives.ReadUInt32BigEndian(data).ToString(CultureInfo.InvariantCulture),
                FactValueKind.Integer,
                FactDisposition.Stored),
            11 when data.Length == 8 => new RegistryDataNormalization(
                BinaryPrimitives.ReadUInt64LittleEndian(data).ToString(CultureInfo.InvariantCulture),
                FactValueKind.Integer,
                FactDisposition.Stored),
            1 or 2 or 3 or 4 or 5 or 7 or 11 =>
                throw new InvalidDataException($"Registry.pol type {type} has invalid data length {data.Length}."),
            _ => throw new InvalidDataException($"Registry.pol contains unsupported registry type {type}.")
        };
    }

    private static uint ReadUInt32(byte[] bytes, ref int offset)
    {
        if (offset > bytes.Length - 4)
        {
            throw new InvalidDataException("Registry.pol ended while reading a DWORD field.");
        }

        var value = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
        offset += 4;
        return value;
    }

    private static string ReadNullTerminatedUtf16Field(byte[] bytes, ref int offset)
    {
        var builder = new StringBuilder();
        while (true)
        {
            if (offset > bytes.Length - 2)
            {
                throw new InvalidDataException("Registry.pol ended inside a NUL-terminated UTF-16 field.");
            }

            var character = (char)BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2));
            offset += 2;
            if (character == '\0')
            {
                return builder.ToString();
            }

            builder.Append(character);
        }
    }

    private static void ExpectUtf16Char(byte[] bytes, ref int offset, char expected)
    {
        if (offset > bytes.Length - 2)
        {
            throw new InvalidDataException($"Registry.pol ended before expected '{expected}'.");
        }

        var actual = (char)BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2));
        offset += 2;
        if (actual != expected)
        {
            throw new InvalidDataException($"Registry.pol expected '{expected}' but found U+{(int)actual:X4}.");
        }
    }

    private static void SkipUtf16Nulls(byte[] bytes, ref int offset)
    {
        while (offset <= bytes.Length - 2 &&
               BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2)) == 0)
        {
            offset += 2;
        }
    }

    private sealed record RegistryDataNormalization(
        string? Value,
        FactValueKind ValueKind,
        FactDisposition Disposition);
}

internal sealed record ParsedSetting
{
    public required GpoPolicyScope Scope { get; init; }
    public required string SourceRelativePath { get; init; }
    public required int Sequence { get; init; }
    public required GpoSettingKind Kind { get; init; }
    public string? Section { get; init; }
    public required string Key { get; init; }
    public string? Value { get; init; }
    public required FactValueKind ValueKind { get; init; }
    public required FactDisposition Disposition { get; init; }
    public int DataLength { get; init; }
    public uint? RegistryValueType { get; init; }
}

internal sealed record ParsedSettingsResult(
    bool Success,
    IReadOnlyList<ParsedSetting> Settings,
    string? Error)
{
    public static ParsedSettingsResult Succeeded(IReadOnlyList<ParsedSetting> settings) =>
        new(true, settings, null);

    public static ParsedSettingsResult Failed(string error) =>
        new(false, [], error);
}
