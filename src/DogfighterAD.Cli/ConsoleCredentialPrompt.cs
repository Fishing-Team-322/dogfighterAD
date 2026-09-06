using System.Net;
using System.Security;

namespace DogfighterAD.Cli;

internal static class ConsoleCredentialPrompt
{
    public static async Task<PromptedNetworkCredential> ReadNetworkCredentialAsync(
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

        var password = new SecureString();
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

            password.MakeReadOnly();
            var (accountName, domain) = SplitAccountName(username);
            var credential = domain is null
                ? new NetworkCredential(accountName, password)
                : new NetworkCredential(accountName, password, domain);

            return new PromptedNetworkCredential(credential, password);
        }
        catch
        {
            password.Dispose();
            throw;
        }
        finally
        {
            promptWriter.WriteLine();
            promptWriter.Flush();
        }
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

internal sealed class PromptedNetworkCredential : IDisposable
{
    private readonly SecureString _password;
    private bool _disposed;

    public PromptedNetworkCredential(NetworkCredential credential, SecureString password)
    {
        Credential = credential ?? throw new ArgumentNullException(nameof(credential));
        _password = password ?? throw new ArgumentNullException(nameof(password));
    }

    public NetworkCredential Credential { get; }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _password.Dispose();
        _disposed = true;
    }
}
