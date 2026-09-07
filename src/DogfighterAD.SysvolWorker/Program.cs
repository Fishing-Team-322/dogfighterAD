using System.Buffers;
using DogfighterAD.Collectors.ActiveDirectory.Sysvol;

namespace DogfighterAD.SysvolWorker;

internal static class Program
{
    private const string TestBlockEnvironment = "DOGFIGHTERAD_SYSVOL_WORKER_TEST_BLOCK";

    public static int Main()
    {
        using var output = Console.OpenStandardOutput();
        PortableKerberosSysvolBackend? portableBackend = null;

        try
        {
            string? line;
            while ((line = Console.ReadLine()) is not null)
            {
                SysvolWorkerRequest request;
                try
                {
                    request = SysvolWorkerProtocol.DeserializeRequest(line);
                }
                catch
                {
                    WriteError(output, SysvolWorkerErrorCode.InvalidRequest);
                    continue;
                }

                var testBlockPath = Environment.GetEnvironmentVariable(TestBlockEnvironment);
                if (!string.IsNullOrEmpty(testBlockPath) &&
                    string.Equals(request.Path, testBlockPath, StringComparison.Ordinal))
                {
                    Thread.Sleep(Timeout.Infinite);
                }

                if (request.Transport == SysvolWorkerTransport.PortableKerberos)
                {
                    try
                    {
                        if (portableBackend is null || !portableBackend.Matches(request))
                        {
                            portableBackend?.Dispose();
                            portableBackend = PortableKerberosSysvolBackend.Create(request);
                        }

                        switch (request.Operation)
                        {
                            case SysvolWorkerOperation.Enumerate:
                                HandlePortableEnumerate(output, portableBackend, request.Path);
                                break;
                            case SysvolWorkerOperation.Read:
                                HandlePortableRead(output, portableBackend, request.Path, request.MaxBytes);
                                break;
                            default:
                                WriteError(output, SysvolWorkerErrorCode.InvalidRequest);
                                break;
                        }
                    }
                    catch (PortableSysvolException exception)
                    {
                        WriteError(output, exception.ErrorCode);
                    }
                    catch
                    {
                        WriteError(output, SysvolWorkerErrorCode.InternalFailure);
                    }
                    continue;
                }

                portableBackend?.Dispose();
                portableBackend = null;

                switch (request.Operation)
                {
                    case SysvolWorkerOperation.Enumerate:
                        HandleEnumerate(output, request.Path);
                        break;
                    case SysvolWorkerOperation.Read:
                        HandleRead(output, request.Path, request.MaxBytes);
                        break;
                    default:
                        WriteError(output, SysvolWorkerErrorCode.InvalidRequest);
                        break;
                }
            }

            return 0;
        }
        finally
        {
            portableBackend?.Dispose();
        }
    }

    private static void HandlePortableEnumerate(
        Stream output,
        PortableKerberosSysvolBackend backend,
        string rootPath)
    {
        foreach (var entry in backend.Enumerate(rootPath))
        {
            WriteFrame(
                output,
                SysvolWorkerFrameKind.Entry,
                SysvolWorkerProtocol.SerializeEntry(entry));
        }
        WriteFrame(output, SysvolWorkerFrameKind.Complete, ReadOnlyMemory<byte>.Empty);
    }

    private static void HandlePortableRead(
        Stream output,
        PortableKerberosSysvolBackend backend,
        string fullPath,
        int maxBytes)
    {
        if (maxBytes < 1)
        {
            WriteError(output, SysvolWorkerErrorCode.InvalidRequest);
            return;
        }

        var content = backend.Read(fullPath, maxBytes);
        const int chunkSize = 64 * 1024;
        for (var offset = 0; offset < content.Length; offset += chunkSize)
        {
            var count = Math.Min(chunkSize, content.Length - offset);
            WriteFrame(
                output,
                SysvolWorkerFrameKind.Data,
                content.AsMemory(offset, count));
        }
        WriteFrame(output, SysvolWorkerFrameKind.Complete, ReadOnlyMemory<byte>.Empty);
    }

    private static void HandleEnumerate(Stream output, string rootPath)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
        {
            WriteError(output, SysvolWorkerErrorCode.InvalidRequest);
            return;
        }

        try
        {
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = false,
                AttributesToSkip = FileAttributes.ReparsePoint
            };

            foreach (var fullPath in Directory.EnumerateFiles(rootPath, "*", options))
            {
                var info = new FileInfo(fullPath);
                var entry = new SysvolWorkerEntry
                {
                    FullPath = fullPath,
                    RelativePath = Path.GetRelativePath(rootPath, fullPath)
                        .Replace(Path.DirectorySeparatorChar, '\\')
                        .Replace(Path.AltDirectorySeparatorChar, '\\'),
                    Length = info.Length,
                    LastWriteTimeUtc = info.LastWriteTimeUtc
                };

                WriteFrame(
                    output,
                    SysvolWorkerFrameKind.Entry,
                    SysvolWorkerProtocol.SerializeEntry(entry));
            }

            WriteFrame(output, SysvolWorkerFrameKind.Complete, ReadOnlyMemory<byte>.Empty);
        }
        catch (DirectoryNotFoundException)
        {
            WriteError(output, SysvolWorkerErrorCode.NotFound);
        }
        catch (UnauthorizedAccessException)
        {
            WriteError(output, SysvolWorkerErrorCode.AccessDenied);
        }
        catch (IOException)
        {
            WriteError(output, SysvolWorkerErrorCode.IoFailure);
        }
        catch
        {
            WriteError(output, SysvolWorkerErrorCode.InternalFailure);
        }
    }

    private static void HandleRead(Stream output, string fullPath, int maxBytes)
    {
        if (string.IsNullOrWhiteSpace(fullPath) || maxBytes < 1)
        {
            WriteError(output, SysvolWorkerErrorCode.InvalidRequest);
            return;
        }

        var rented = ArrayPool<byte>.Shared.Rent(
            (int)Math.Min(64 * 1024L, (long)maxBytes + 1));

        try
        {
            using var stream = new FileStream(
                fullPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 64 * 1024,
                FileOptions.SequentialScan);

            var totalRead = 0L;
            while (true)
            {
                var remainingDetectionBudget = (long)maxBytes + 1 - totalRead;
                if (remainingDetectionBudget <= 0)
                {
                    WriteError(output, SysvolWorkerErrorCode.TooLarge);
                    return;
                }

                var requested = (int)Math.Min(rented.Length, remainingDetectionBudget);
                var read = stream.Read(rented, 0, requested);
                if (read == 0)
                {
                    WriteFrame(output, SysvolWorkerFrameKind.Complete, ReadOnlyMemory<byte>.Empty);
                    return;
                }

                var remainingPayloadBudget = Math.Max(0L, maxBytes - totalRead);
                var allowed = (int)Math.Min(read, remainingPayloadBudget);
                if (allowed > 0)
                {
                    WriteFrame(
                        output,
                        SysvolWorkerFrameKind.Data,
                        rented.AsMemory(0, allowed));
                }

                totalRead += read;
                if (totalRead > maxBytes)
                {
                    WriteError(output, SysvolWorkerErrorCode.TooLarge);
                    return;
                }
            }
        }
        catch (FileNotFoundException)
        {
            WriteError(output, SysvolWorkerErrorCode.NotFound);
        }
        catch (DirectoryNotFoundException)
        {
            WriteError(output, SysvolWorkerErrorCode.NotFound);
        }
        catch (UnauthorizedAccessException)
        {
            WriteError(output, SysvolWorkerErrorCode.AccessDenied);
        }
        catch (IOException)
        {
            WriteError(output, SysvolWorkerErrorCode.IoFailure);
        }
        catch
        {
            WriteError(output, SysvolWorkerErrorCode.InternalFailure);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static void WriteError(Stream output, SysvolWorkerErrorCode errorCode) =>
        WriteFrame(
            output,
            SysvolWorkerFrameKind.Error,
            SysvolWorkerProtocol.SerializeError(errorCode));

    private static void WriteFrame(
        Stream output,
        SysvolWorkerFrameKind kind,
        ReadOnlyMemory<byte> payload) =>
        SysvolWorkerProtocol.WriteFrameAsync(
                output,
                kind,
                payload,
                CancellationToken.None)
            .AsTask()
            .GetAwaiter()
            .GetResult();
}
