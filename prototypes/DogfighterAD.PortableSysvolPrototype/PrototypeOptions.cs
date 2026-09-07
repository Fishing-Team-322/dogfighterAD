using System.Net;

namespace DogfighterAD.PortableSysvolPrototype;

internal sealed record PrototypeOptions
{
    public bool ShowHelp { get; init; }
    public required string Server { get; init; }
    public required string Kdc { get; init; }
    public required string Domain { get; init; }
    public required string Realm { get; init; }
    public required string User { get; init; }
    public required Guid GpoGuid { get; init; }
    public required TimeSpan PhaseTimeout { get; init; }
    public required int MaxBytes { get; init; }

    public static bool TryParse(
        IReadOnlyList<string> args,
        out PrototypeOptions options,
        out string error)
    {
        options = null!;
        error = string.Empty;

        if (args.Count is 1 && args[0] is "-h" or "--help")
        {
            options = new PrototypeOptions
            {
                ShowHelp = true,
                Server = string.Empty,
                Kdc = string.Empty,
                Domain = string.Empty,
                Realm = string.Empty,
                User = string.Empty,
                GpoGuid = Guid.Empty,
                PhaseTimeout = TimeSpan.FromSeconds(20),
                MaxBytes = 64 * 1024
            };
            return true;
        }

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Count; i++)
        {
            var name = args[i];
            if (name is "--password" or "-p" || name.StartsWith("--password=", StringComparison.OrdinalIgnoreCase))
            {
                error = "Password command-line arguments are intentionally rejected.";
                return false;
            }

            if (!name.StartsWith("--", StringComparison.Ordinal) || i + 1 >= args.Count)
            {
                error = $"Invalid argument '{name}'.";
                return false;
            }

            if (!values.TryAdd(name, args[++i]))
            {
                error = $"Duplicate argument '{name}'.";
                return false;
            }
        }

        if (!TryRequired(values, "--server", out var server, out error) ||
            !TryRequired(values, "--domain", out var domain, out error) ||
            !TryRequired(values, "--user", out var user, out error) ||
            !TryRequired(values, "--gpo", out var gpoText, out error))
        {
            return false;
        }

        if (!IsDnsName(server) || IPAddress.TryParse(server, out _))
        {
            error = "--server must be a DNS hostname/FQDN, not an IP literal.";
            return false;
        }

        if (!IsDnsName(domain))
        {
            error = "--domain must be a DNS domain name.";
            return false;
        }

        if (user.IndexOfAny(['\\', '/', '@', ':', '\0']) >= 0 || string.IsNullOrWhiteSpace(user))
        {
            error = "--user must be an account name only; provide the Kerberos realm separately.";
            return false;
        }

        if (!Guid.TryParse(gpoText, out var gpoGuid) || gpoGuid == Guid.Empty)
        {
            error = "--gpo must be a non-empty GPO GUID.";
            return false;
        }

        var realm = values.GetValueOrDefault("--realm", domain.ToUpperInvariant()).Trim().TrimEnd('.');
        if (!IsDnsName(realm))
        {
            error = "--realm must be a valid Kerberos realm name.";
            return false;
        }

        var kdc = values.GetValueOrDefault("--kdc", server).Trim().TrimEnd('.');
        if (!IsDnsName(kdc) || IPAddress.TryParse(kdc, out _))
        {
            error = "--kdc must be a DNS hostname/FQDN.";
            return false;
        }

        var timeoutSeconds = 20;
        if (values.TryGetValue("--timeout-seconds", out var timeoutText) &&
            (!int.TryParse(timeoutText, out timeoutSeconds) || timeoutSeconds is < 5 or > 120))
        {
            error = "--timeout-seconds must be between 5 and 120.";
            return false;
        }

        var maxBytes = 64 * 1024;
        if (values.TryGetValue("--max-bytes", out var maxBytesText) &&
            (!int.TryParse(maxBytesText, out maxBytes) || maxBytes is < 1 or > 1024 * 1024))
        {
            error = "--max-bytes must be between 1 and 1048576.";
            return false;
        }

        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "--server", "--domain", "--realm", "--kdc", "--user", "--gpo", "--timeout-seconds", "--max-bytes"
        };
        var unknown = values.Keys.FirstOrDefault(key => !known.Contains(key));
        if (unknown is not null)
        {
            error = $"Unknown argument '{unknown}'.";
            return false;
        }

        options = new PrototypeOptions
        {
            ShowHelp = false,
            Server = server.Trim().TrimEnd('.'),
            Kdc = kdc,
            Domain = domain.Trim().TrimEnd('.').ToLowerInvariant(),
            Realm = realm.ToUpperInvariant(),
            User = user.Trim(),
            GpoGuid = gpoGuid,
            PhaseTimeout = TimeSpan.FromSeconds(timeoutSeconds),
            MaxBytes = maxBytes
        };
        return true;
    }

    private static bool TryRequired(
        IReadOnlyDictionary<string, string> values,
        string name,
        out string value,
        out string error)
    {
        if (!values.TryGetValue(name, out value!) || string.IsNullOrWhiteSpace(value))
        {
            error = $"Missing required argument {name}.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static bool IsDnsName(string value)
    {
        var candidate = value.Trim().TrimEnd('.');
        if (candidate.Length is < 1 or > 253 || candidate.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        var labels = candidate.Split('.', StringSplitOptions.None);
        return labels.All(label =>
            label.Length is >= 1 and <= 63 &&
            char.IsLetterOrDigit(label[0]) &&
            char.IsLetterOrDigit(label[^1]) &&
            label.All(character => char.IsLetterOrDigit(character) || character == '-'));
    }
}
