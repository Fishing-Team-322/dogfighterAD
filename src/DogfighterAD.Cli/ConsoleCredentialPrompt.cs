using System.Net;
using System.Security;

namespace DogfighterAD.Cli;

internal static class ConsoleCredentialPrompt
{
    public static async Task<NetworkCredential> ReadNetworkCredentialAsync(
        string username,
        TextWriter promptWriter,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentNullException.ThrowIfNull(promptWriter);

        if (Console.IsInputRedirected)
        {
            throw new InvalidOperationException(
                "The LDAP password prompt requires an interactive console; redirected password input is intentionally unsupported.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        promptWriter.Write($"LDAP password for {username}: ");
        promptWriter.Flush();

        using var password = new SecureString();
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (!Console.KeyAvailable)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken)
                        .ConfigureAwait(false);
                    continue;
                }

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
        var retainedPassword = password.Copy();
        retainedPassword.MakeReadOnly();

        var (accountName, domain) = SplitAccountName(username);
        return domain is null
            ? new NetworkCredential(accountName, retainedPassword)
            : new NetworkCredential(accountName, retainedPassword, domain);
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
