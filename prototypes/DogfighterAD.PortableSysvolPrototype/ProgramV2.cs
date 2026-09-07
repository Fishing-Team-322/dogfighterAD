using System.Diagnostics;
using System.Text;
using Kerberos.NET;

namespace DogfighterAD.PortableSysvolPrototype;

internal static class Program
{
    private const int ExitSuccess = 0;
    private const int ExitArguments = 64;
    private const int ExitRuntime = 70;
    private const int ExitCanceled = 130;

    public static async Task<int> Main(string[] args)
    {
        if (!PrototypeOptions.TryParse(args, out var options, out var error))
        {
            Console.Error.WriteLine(error);
            WriteUsage(Console.Error);
            return ExitArguments;
        }

        if (options.ShowHelp)
        {
            WriteUsage(Console.Out);
            return ExitSuccess;
        }

        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };
        Console.CancelKeyPress += cancelHandler;

        string password;
        try
        {
            password = ReadHiddenPassword($"Kerberos password for {options.User}@{options.Realm}: ");
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException)
        {
            Console.Error.WriteLine("credential-input: failed");
            Console.CancelKeyPress -= cancelHandler;
            return ExitRuntime;
        }

        try
        {
            Console.Error.WriteLine(
                $"probe: server={options.Server} kdc={options.Kdc} realm={options.Realm} " +
                $"domain={options.Domain} gpo={options.GpoGuid:B} phase-timeout={options.PhaseTimeout} " +
                $"max-bytes={options.MaxBytes}");

            var stopwatch = Stopwatch.StartNew();
            var result = await PortableSysvolProbe.ExecuteAsync(
                    options,
                    password,
                    static stage => Console.Error.WriteLine($"[{DateTimeOffset.UtcNow:O}] {stage}"),
                    cancellation.Token)
                .ConfigureAwait(false);
            stopwatch.Stop();

            Console.WriteLine("kerberos: success");
            Console.WriteLine("smb-session: success");
            Console.WriteLine($"smb-dialect: {result.Dialect}");
            Console.WriteLine("smb-signing: required-and-verified-by-client");
            Console.WriteLine("tree-connect: SYSVOL success");
            Console.WriteLine($"path-scope: accepted {result.RelativePath}");
            Console.WriteLine($"read: {result.BytesRead} bytes");
            Console.WriteLine($"sha256: {result.Sha256Hex}");
            Console.WriteLine($"elapsed: {stopwatch.Elapsed}");
            return ExitSuccess;
        }
        catch (ProbeTimeoutException exception)
        {
            Console.Error.WriteLine($"probe: timeout stage={exception.Stage} after={exception.Timeout}");
            return ExitRuntime;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            Console.Error.WriteLine("probe: canceled");
            return ExitCanceled;
        }
        catch (KerberosProtocolException exception)
        {
            Console.Error.WriteLine($"kerberos: failed code={exception.Error?.ErrorCode.ToString() ?? "unknown"}");
            return ExitRuntime;
        }
        catch (ProbeException exception)
        {
            Console.Error.WriteLine($"probe: failed stage={exception.Stage} code={exception.Code}");
            return ExitRuntime;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"probe: failed type={exception.GetType().Name}");
            return ExitRuntime;
        }
        finally
        {
            password = string.Empty;
            Console.CancelKeyPress -= cancelHandler;
        }
    }

    private static string ReadHiddenPassword(string prompt)
    {
        if (Console.IsInputRedirected)
        {
            throw new InvalidOperationException("Redirected password input is intentionally unsupported.");
        }

        Console.Error.Write(prompt);
        var buffer = new StringBuilder();
        try
        {
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.Error.WriteLine();
                    return buffer.ToString();
                }

                if (key.Key == ConsoleKey.Backspace)
                {
                    if (buffer.Length > 0)
                    {
                        buffer.Length--;
                    }
                    continue;
                }

                if (!char.IsControl(key.KeyChar))
                {
                    buffer.Append(key.KeyChar);
                }
            }
        }
        finally
        {
            buffer.Clear();
        }
    }

    private static void WriteUsage(TextWriter writer)
    {
        writer.WriteLine("DogfighterAD portable SYSVOL Kerberos/SMB prototype");
        writer.WriteLine();
        writer.WriteLine("Usage:");
        writer.WriteLine(
            "  dotnet run --project prototypes/DogfighterAD.PortableSysvolPrototype -- " +
            "--server <dc-fqdn> --domain <domain-fqdn> --user <account> --gpo <guid> " +
            "[--realm <KERBEROS.REALM>] [--kdc <kdc-fqdn>] [--timeout-seconds <5-120>] " +
            "[--max-bytes <1-1048576>]");
        writer.WriteLine();
        writer.WriteLine("--timeout-seconds is a per-phase deadline: Kerberos acquisition and SMB work each get a fresh budget.");
        writer.WriteLine("The password is read only from a hidden interactive prompt; no password argument exists.");
        writer.WriteLine("The only readable path is SYSVOL/<domain>/Policies/{GPO-GUID}/GPT.INI on the explicitly named server.");
    }
}
