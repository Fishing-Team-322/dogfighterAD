namespace DogfighterAD.Cli;

internal abstract record CliCommand;

internal sealed record ScanCommand : CliCommand
{
    public required string Target { get; init; }
    public required string OutputPath { get; init; }
    public string Profile { get; init; } = "minimal";
    public bool UseLdaps { get; init; }
    public int? LdapPort { get; init; }
    public string? Username { get; init; }
    public bool PromptForPassword { get; init; }
    public IReadOnlySet<string> ApprovedSysvolAuthorities { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);
}

internal sealed record InspectCommand : CliCommand
{
    public required string SnapshotPath { get; init; }
}

internal sealed record CliParseResult(
    CliCommand? Command,
    bool ShowHelp,
    string? Error)
{
    public bool Success => Error is null;
}

internal static class CliArgumentParser
{
    private static readonly IReadOnlySet<string> ProhibitedCredentialOptions =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "--passwd",
            "--credential",
            "--credentials"
        };

    public static CliParseResult Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        if (args.Count == 0 || IsHelp(args[0]))
        {
            return new CliParseResult(null, ShowHelp: true, Error: null);
        }

        return args[0].ToLowerInvariant() switch
        {
            "scan" => ParseScan(args.Skip(1).ToArray()),
            "inspect" => ParseInspect(args.Skip(1).ToArray()),
            _ => new CliParseResult(
                null,
                ShowHelp: false,
                Error: $"Unknown command '{args[0]}'.")
        };
    }

    private static CliParseResult ParseScan(IReadOnlyList<string> args)
    {
        string? target = null;
        string? output = null;
        var profile = "minimal";
        var useLdaps = false;
        int? ldapPort = null;
        string? username = null;
        var promptForPassword = false;
        var authorities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var index = 0; index < args.Count; index++)
        {
            var token = args[index];
            if (IsHelp(token))
            {
                return new CliParseResult(null, ShowHelp: true, Error: null);
            }

            if (LooksLikeInlinePassword(token))
            {
                return PasswordValueRejected();
            }

            if (ProhibitedCredentialOptions.Contains(token))
            {
                return PasswordValueRejected();
            }

            switch (token)
            {
                case "--target":
                    if (!TryReadValue(args, ref index, out target))
                    {
                        return MissingValue(token);
                    }
                    break;

                case "--output":
                    if (!TryReadValue(args, ref index, out output))
                    {
                        return MissingValue(token);
                    }
                    break;

                case "--profile":
                    if (!TryReadValue(args, ref index, out profile))
                    {
                        return MissingValue(token);
                    }
                    break;

                case "--ldaps":
                    useLdaps = true;
                    break;

                case "--ldap-port":
                    if (!TryReadValue(args, ref index, out var portValue))
                    {
                        return MissingValue(token);
                    }

                    if (!int.TryParse(portValue, out var parsedPort) || parsedPort is < 1 or > 65535)
                    {
                        return new CliParseResult(null, false, "LDAP port must be between 1 and 65535.");
                    }

                    ldapPort = parsedPort;
                    break;

                case "-u":
                case "--username":
                case "--user":
                    if (!TryReadValue(args, ref index, out username))
                    {
                        return MissingValue(token);
                    }
                    break;

                case "-p":
                case "--password":
                    if (index + 1 < args.Count && !IsOptionToken(args[index + 1]))
                    {
                        return PasswordValueRejected();
                    }
                    promptForPassword = true;
                    break;

                case "--sysvol-authority":
                    if (!TryReadValue(args, ref index, out var authority))
                    {
                        return MissingValue(token);
                    }

                    authorities.Add(authority);
                    break;

                default:
                    return new CliParseResult(null, false, $"Unknown scan option '{token}'.");
            }
        }

        if (string.IsNullOrWhiteSpace(target))
        {
            return new CliParseResult(null, false, "scan requires --target <host-or-domain>.");
        }

        if (string.IsNullOrWhiteSpace(output))
        {
            return new CliParseResult(null, false, "scan requires --output <snapshot.dogad>.");
        }

        if (!string.Equals(Path.GetExtension(output), ".dogad", StringComparison.OrdinalIgnoreCase))
        {
            return new CliParseResult(null, false, "scan output must use the .dogad extension.");
        }

        if (username is not null && !promptForPassword)
        {
            return new CliParseResult(
                null,
                false,
                "-u/--username requires -p/--password so the LDAP password is read from a hidden interactive prompt.");
        }

        if (promptForPassword && string.IsNullOrWhiteSpace(username))
        {
            return new CliParseResult(
                null,
                false,
                "-p/--password requires -u/--username <DOMAIN\\user|user@domain>.");
        }

        return new CliParseResult(
            new ScanCommand
            {
                Target = target,
                OutputPath = output,
                Profile = profile,
                UseLdaps = useLdaps,
                LdapPort = ldapPort,
                Username = username,
                PromptForPassword = promptForPassword,
                ApprovedSysvolAuthorities = authorities
            },
            ShowHelp: false,
            Error: null);
    }

    private static CliParseResult ParseInspect(IReadOnlyList<string> args)
    {
        string? snapshot = null;

        for (var index = 0; index < args.Count; index++)
        {
            var token = args[index];
            if (IsHelp(token))
            {
                return new CliParseResult(null, ShowHelp: true, Error: null);
            }

            switch (token)
            {
                case "--snapshot":
                    if (!TryReadValue(args, ref index, out snapshot))
                    {
                        return MissingValue(token);
                    }
                    break;

                default:
                    return new CliParseResult(null, false, $"Unknown inspect option '{token}'.");
            }
        }

        if (string.IsNullOrWhiteSpace(snapshot))
        {
            return new CliParseResult(null, false, "inspect requires --snapshot <snapshot.dogad>.");
        }

        return new CliParseResult(
            new InspectCommand { SnapshotPath = snapshot },
            ShowHelp: false,
            Error: null);
    }

    private static bool TryReadValue(
        IReadOnlyList<string> args,
        ref int index,
        out string value)
    {
        if (index + 1 >= args.Count ||
            string.IsNullOrWhiteSpace(args[index + 1]) ||
            IsOptionToken(args[index + 1]))
        {
            value = string.Empty;
            return false;
        }

        index++;
        value = args[index];
        return true;
    }

    private static CliParseResult MissingValue(string option) =>
        new(null, ShowHelp: false, Error: $"Option '{option}' requires a value.");

    private static CliParseResult PasswordValueRejected() =>
        new(
            null,
            ShowHelp: false,
            Error: "Password values are never accepted in command-line arguments. Use -u/--username with -p/--password to enter the LDAP password in a hidden interactive prompt.");

    private static bool LooksLikeInlinePassword(string token) =>
        token.StartsWith("--password=", StringComparison.OrdinalIgnoreCase) ||
        token.StartsWith("--passwd=", StringComparison.OrdinalIgnoreCase) ||
        (token.Length > 2 && token.StartsWith("-p", StringComparison.OrdinalIgnoreCase));

    private static bool IsOptionToken(string value) =>
        value.Length > 0 && value[0] == '-';

    private static bool IsHelp(string value) =>
        string.Equals(value, "--help", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(value, "-h", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(value, "help", StringComparison.OrdinalIgnoreCase);
}
