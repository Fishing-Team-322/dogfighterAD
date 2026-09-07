using System.Reflection;

namespace DogfighterAD.Cli;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler handler = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };
        Console.CancelKeyPress += handler;

        try
        {
            var productVersion = typeof(Program).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
                .InformationalVersion
                ?? typeof(Program).Assembly.GetName().Version?.ToString()
                ?? "unknown";

            return await CliApplication.RunAsync(
                    args,
                    productVersion,
                    Console.Out,
                    Console.Error,
                    cancellation.Token)
                .ConfigureAwait(false);
        }
        finally
        {
            Console.CancelKeyPress -= handler;
        }
    }
}
