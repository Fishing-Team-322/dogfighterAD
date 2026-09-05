using System.Globalization;

namespace DogfighterAD.Collectors.ActiveDirectory.Ldap;

internal static class LdapValueConverters
{
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
        var value = entry.GetBinaryValues(attributeName).SingleOrDefault();
        return value is null ? null : FormatSid(value);
    }

    public static IReadOnlyList<string> GetSids(LdapSearchEntry entry, string attributeName) =>
        entry.GetBinaryValues(attributeName)
            .Select(value => FormatSid(value))
            .Where(value => value is not null)
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();

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
        if (sid.Length < requiredLength)
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
}
