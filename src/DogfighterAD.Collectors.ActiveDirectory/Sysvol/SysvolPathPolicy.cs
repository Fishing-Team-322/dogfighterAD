namespace DogfighterAD.Collectors.ActiveDirectory.Sysvol;

internal sealed record ValidatedSysvolRoot(
    string RootPath,
    string DomainDnsName,
    Guid GpoGuid,
    IReadOnlySet<string> ApprovedAuthorities);

/// <summary>
/// Enforces the network/source boundary for GPO SYSVOL reads before filesystem I/O.
/// The domain DFS namespace and the current scan target are approved automatically;
/// alternate DC/referral authorities must be configured explicitly.
/// </summary>
internal static class SysvolPathPolicy
{
    public static bool IsValidAuthority(string? value) =>
        TryNormalizeAuthority(value, out _);

    public static bool TryValidateGpoRoot(
        string rootPath,
        string distinguishedName,
        Guid gpoGuid,
        string target,
        IReadOnlySet<string> configuredAuthorities,
        out ValidatedSysvolRoot scope)
    {
        scope = null!;

        if (!TryGetDomainDnsName(distinguishedName, out var domainDnsName) ||
            !TrySplitUnc(rootPath, out var authority, out var segments) ||
            segments.Length != 4 ||
            !segments[0].Equals("SYSVOL", StringComparison.OrdinalIgnoreCase) ||
            !segments[1].Equals(domainDnsName, StringComparison.OrdinalIgnoreCase) ||
            !segments[2].Equals("Policies", StringComparison.OrdinalIgnoreCase) ||
            !Guid.TryParse(segments[3], out var pathGpoGuid) ||
            pathGpoGuid != gpoGuid)
        {
            return false;
        }

        var approvedAuthorities = BuildApprovedAuthorities(
            domainDnsName,
            target,
            configuredAuthorities);

        if (!approvedAuthorities.Contains(authority))
        {
            return false;
        }

        scope = new ValidatedSysvolRoot(
            $"\\\\{authority}\\SYSVOL\\{domainDnsName}\\Policies\\{gpoGuid:B}",
            domainDnsName,
            gpoGuid,
            approvedAuthorities);
        return true;
    }

    public static bool TryValidateFile(
        ValidatedSysvolRoot scope,
        SysvolFileEntry file,
        out string relativePath)
    {
        relativePath = string.Empty;

        if (!TryNormalizeRelativePath(file.RelativePath, out relativePath) ||
            !TrySplitUnc(file.FullPath, out var authority, out var segments) ||
            !scope.ApprovedAuthorities.Contains(authority) ||
            segments.Length < 5 ||
            !segments[0].Equals("SYSVOL", StringComparison.OrdinalIgnoreCase) ||
            !segments[1].Equals(scope.DomainDnsName, StringComparison.OrdinalIgnoreCase) ||
            !segments[2].Equals("Policies", StringComparison.OrdinalIgnoreCase) ||
            !Guid.TryParse(segments[3], out var pathGpoGuid) ||
            pathGpoGuid != scope.GpoGuid)
        {
            return false;
        }

        var fullPathRelative = string.Join("\\", segments.Skip(4));
        return fullPathRelative.Equals(relativePath, StringComparison.OrdinalIgnoreCase);
    }

    private static IReadOnlySet<string> BuildApprovedAuthorities(
        string domainDnsName,
        string target,
        IReadOnlySet<string> configuredAuthorities)
    {
        var approved = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            domainDnsName
        };

        if (TryNormalizeAuthority(target, out var targetAuthority))
        {
            approved.Add(targetAuthority);
        }

        foreach (var configured in configuredAuthorities)
        {
            if (TryNormalizeAuthority(configured, out var configuredAuthority))
            {
                approved.Add(configuredAuthority);
            }
        }

        return approved;
    }

    private static bool TryGetDomainDnsName(string distinguishedName, out string domainDnsName)
    {
        domainDnsName = string.Empty;
        if (string.IsNullOrWhiteSpace(distinguishedName))
        {
            return false;
        }

        var labels = distinguishedName
            .Split(',', StringSplitOptions.TrimEntries)
            .Where(component => component.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            .Select(component => component[3..].Trim())
            .ToArray();

        if (labels.Length == 0 || labels.Any(label => !IsValidDnsLabel(label)))
        {
            return false;
        }

        domainDnsName = string.Join(".", labels);
        return true;
    }

    private static bool IsValidDnsLabel(string label) =>
        !string.IsNullOrWhiteSpace(label) &&
        label is not "." and not ".." &&
        label.IndexOfAny(['\\', '/', ':', '\0']) < 0;

    private static bool TryNormalizeAuthority(string? value, out string authority)
    {
        authority = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var candidate = value.Trim().TrimEnd('.');
        if (candidate.Length == 0 ||
            candidate is "." or ".." ||
            candidate.IndexOfAny(['\\', '/', ':', '\0']) >= 0)
        {
            return false;
        }

        authority = candidate;
        return true;
    }

    private static bool TrySplitUnc(
        string value,
        out string authority,
        out string[] segments)
    {
        authority = string.Empty;
        segments = [];

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var normalized = value.Trim().Replace('/', '\\').TrimEnd('\\');
        if (!normalized.StartsWith("\\\\", StringComparison.Ordinal) ||
            normalized.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
            normalized.StartsWith("\\\\.\\", StringComparison.Ordinal))
        {
            return false;
        }

        var parts = normalized[2..].Split('\\', StringSplitOptions.None);
        if (parts.Length < 2 ||
            parts.Any(part => string.IsNullOrWhiteSpace(part) || part is "." or "..") ||
            !TryNormalizeAuthority(parts[0], out authority))
        {
            return false;
        }

        segments = parts[1..];
        return true;
    }

    private static bool TryNormalizeRelativePath(string value, out string relativePath)
    {
        relativePath = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var normalized = value.Replace('/', '\\');
        if (normalized.StartsWith('\\') ||
            normalized.EndsWith('\\') ||
            normalized.Contains(':'))
        {
            return false;
        }

        var segments = normalized.Split('\\', StringSplitOptions.None);
        if (segments.Length == 0 ||
            segments.Any(segment => string.IsNullOrWhiteSpace(segment) || segment is "." or ".."))
        {
            return false;
        }

        relativePath = string.Join("\\", segments);
        return true;
    }
}
