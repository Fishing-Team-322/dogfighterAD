using System.Globalization;

namespace DogfighterAD.Collectors.ActiveDirectory.Ldap;

internal static class LdapValueConverters
{
    private const int MaxSidSubAuthorities = 15;
    private const ulong MaxSidIdentifierAuthority = 0x0000FFFFFFFFFFFFUL;

    private static readonly string[] GeneralizedTimeFormats =
    [
        "yyyyMMddHHmmss'Z'",
        "yyyyMMddHHmmss.FFFFFFF'Z'"
    ];

    public static Guid? GetGuid(LdapSearchEntry entry, string attributeName)
    {
        var value = entry.GetBinaryValues(attributeName).SingleOrDefault();
        return value is { Length: 16 } ? new Guid(value) : null;
    }

    public static string? GetSid(LdapSearchEntry entry, string attributeName)
    {
        var values = GetNormalizedSids(entry, attributeName)
            .Take(2)
            .ToArray();
        return values.Length == 1 ? values[0] : null;
    }

    public static IReadOnlyList<string> GetSids(LdapSearchEntry entry, string attributeName) =>
        GetNormalizedSids(entry, attributeName).ToArray();

    public static int? GetInt32(LdapSearchEntry entry, string attributeName)
    {
        var value = entry.GetSingleTextValue(attributeName);
        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;
    }

    public static long? GetInt64(LdapSearchEntry entry, string attributeName)
    {
        var value = entry.GetSingleTextValue(attributeName);
        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;
    }

    public static DateTimeOffset? GetFileTimeUtc(LdapSearchEntry entry, string attributeName)
    {
        var fileTime = GetInt64(entry, attributeName);
        return FileTimeToUtc(fileTime);
    }

    public static DateTimeOffset? FileTimeToUtc(long? fileTime)
    {
        if (!fileTime.HasValue || fileTime.Value <= 0 || fileTime.Value == long.MaxValue)
        {
            return null;
        }

        try
        {
            return new DateTimeOffset(DateTime.FromFileTimeUtc(fileTime.Value));
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    public static DateTimeOffset? GetDateTimeOffset(LdapSearchEntry entry, string attributeName)
    {
        var value = entry.GetSingleTextValue(attributeName);
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (DateTimeOffset.TryParseExact(
                value,
                GeneralizedTimeFormats,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var generalizedTime))
        {
            return generalizedTime;
        }

        return DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var parsed)
            ? parsed
            : null;
    }

    public static string? DistinguishedNameToDnsName(string distinguishedName)
    {
        if (string.IsNullOrWhiteSpace(distinguishedName))
        {
            return null;
        }

        var labels = distinguishedName
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(part => part.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            .Select(part => part[3..])
            .Where(part => !string.IsNullOrWhiteSpace(part))
            .ToArray();

        return labels.Length == 0 ? null : string.Join('.', labels);
    }

    public static string? FormatSid(ReadOnlySpan<byte> sid)
    {
        if (sid.Length < 8)
        {
            return null;
        }

        var revision = sid[0];
        var subAuthorityCount = sid[1];
        var requiredLength = 8 + (subAuthorityCount * 4);
        if (subAuthorityCount > MaxSidSubAuthorities || sid.Length < requiredLength)
        {
            return null;
        }

        ulong identifierAuthority = 0;
        for (var index = 2; index < 8; index++)
        {
            identifierAuthority = (identifierAuthority << 8) | sid[index];
        }

        var parts = new List<string>(3 + subAuthorityCount)
        {
            "S",
            revision.ToString(CultureInfo.InvariantCulture),
            identifierAuthority.ToString(CultureInfo.InvariantCulture)
        };

        var offset = 8;
        for (var index = 0; index < subAuthorityCount; index++)
        {
            var subAuthority = (uint)(
                sid[offset]
                | (sid[offset + 1] << 8)
                | (sid[offset + 2] << 16)
                | (sid[offset + 3] << 24));

            parts.Add(subAuthority.ToString(CultureInfo.InvariantCulture));
            offset += 4;
        }

        return string.Join('-', parts);
    }

    private static IEnumerable<string> GetNormalizedSids(
        LdapSearchEntry entry,
        string attributeName)
    {
        var values = new List<string>();

        foreach (var binary in entry.GetBinaryValues(attributeName))
        {
            var normalized = FormatSid(binary);
            if (normalized is not null)
            {
                values.Add(normalized);
            }
        }

        foreach (var text in entry.GetTextValues(attributeName))
        {
            var normalized = NormalizeSidText(text);
            if (normalized is not null)
            {
                values.Add(normalized);
            }
        }

        return values
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase);
    }

    private static string? NormalizeSidText(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var parts = value.Trim().Split('-', StringSplitOptions.None);
        if (parts.Length < 3 ||
            !parts[0].Equals("S", StringComparison.OrdinalIgnoreCase) ||
            !byte.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var revision) ||
            !ulong.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var identifierAuthority) ||
            identifierAuthority > MaxSidIdentifierAuthority)
        {
            return null;
        }

        var subAuthorityCount = parts.Length - 3;
        if (subAuthorityCount > MaxSidSubAuthorities)
        {
            return null;
        }

        var normalized = new string[parts.Length];
        normalized[0] = "S";
        normalized[1] = revision.ToString(CultureInfo.InvariantCulture);
        normalized[2] = identifierAuthority.ToString(CultureInfo.InvariantCulture);

        for (var index = 3; index < parts.Length; index++)
        {
            if (!uint.TryParse(
                    parts[index],
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out var subAuthority))
            {
                return null;
            }

            normalized[index] = subAuthority.ToString(CultureInfo.InvariantCulture);
        }

        return string.Join('-', normalized);
    }
}
