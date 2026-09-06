using System.Net;
using System.Security;

namespace DogfighterAD.Cli;

internal static class ConsoleCredentialPrompt
{
    public static NetworkCredential ReadNetworkCredential(
        string username,
        TextWriter promptWriter)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentNullException.ThrowIfNull(promptWriter);

        if (Console.IsInputRedirected)
        {
            throw new InvalidOperationException(
                "The LDAP password prompt requires an interactive console; redirected password input is intentionally unsupported.");
        }

        promptWriter.Write($"LDAP password for {username}: ");
        promptWriter.Flush();

        using var password = new SecureString();
        try
        {
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                {
                    break;
                }

                if (key.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.RemoveAt(password.Length - 1);
                    }
                    continue;
                }

                if (char.IsControl(key.KeyChar))
                {
                    continue;
                }

                password.AppendChar(key.KeyChar);
            }
        }
        finally
        {
            promptWriter.WriteLine();
            promptWriter.Flush();
        }

        password.MakeReadOnly();
        var (accountName, domain) = SplitAccountName(username);
        return domain is null
            ? new NetworkCredential(accountName, password)
            : new NetworkCredential(accountName, password, domain);
    }

    internal static (string AccountName, string? Domain) SplitAccountName(string username)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);

        var separator = username.IndexOf('\\');
        if (separator <= 0 || separator == username.Length - 1)
        {
            return (username, null);
        }

        return (username[(separator + 1)..], username[..separator]);
    }
}
