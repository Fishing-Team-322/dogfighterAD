using System.Buffers;
using System.Runtime.CompilerServices;

namespace DogfighterAD.Collectors.ActiveDirectory.Sysvol;

public interface IReadOnlySysvolClientFactory
{
    ValueTask<IReadOnlySysvolClient> CreateAsync(CancellationToken cancellationToken);
}

public interface IReadOnlySysvolClient : IAsyncDisposable
{
    IAsyncEnumerable<SysvolFileEntry> EnumerateFilesAsync(
        string rootPath,
        CancellationToken cancellationToken);

    Task<byte[]> ReadFileAsync(
        string fullPath,
        int maxBytes,
        CancellationToken cancellationToken);
}

public sealed record SysvolFileEntry
{
    public required string FullPath { get; init; }
    public required string RelativePath { get; init; }
    public long Length { get; init; }
    public DateTimeOffset? LastWriteTimeUtc { get; init; }
}

public sealed record SysvolClientOptions
{
    public int MaxFileBytes { get; init; } = 8 * 1024 * 1024;
    public int MaxFilesPerGpo { get; init; } = 10_000;

    /// <summary>
    /// Additional explicitly approved SYSVOL authorities, such as alternate DCs that may
    /// be used by an intentional DFS/referral policy. The GPO domain DFS authority and
    /// the current collection target are approved by the collector automatically.
    /// </summary>
    public IReadOnlySet<string> ApprovedAuthorities { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);
}

public sealed class SystemSysvolClientFactory : IReadOnlySysvolClientFactory
{
    public ValueTask<IReadOnlySysvolClient> CreateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<IReadOnlySysvolClient>(new SystemSysvolClient());
    }
}

internal sealed class SystemSysvolClient : IReadOnlySysvolClient
{
    public async IAsyncEnumerable<SysvolFileEntry> EnumerateFilesAsync(
        string rootPath,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = false,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        foreach (var fullPath in Directory.EnumerateFiles(rootPath, "*", options))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var info = new FileInfo(fullPath);
            yield return new SysvolFileEntry
            {
                FullPath = fullPath,
                RelativePath = Path.GetRelativePath(rootPath, fullPath)
                    .Replace(Path.DirectorySeparatorChar, '\\')
                    .Replace(Path.AltDirectorySeparatorChar, '\\'),
                Length = info.Length,
                LastWriteTimeUtc = info.LastWriteTimeUtc
            };

            await Task.Yield();
        }
    }

    public async Task<byte[]> ReadFileAsync(
        string fullPath,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fullPath);
        if (maxBytes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytes));
        }

        await using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        return await SysvolBoundedReader
            .ReadAsync(stream, fullPath, maxBytes, cancellationToken)
            .ConfigureAwait(false);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

internal static class SysvolBoundedReader
{
    public static async Task<byte[]> ReadAsync(
        Stream stream,
        string path,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (maxBytes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytes));
        }

        cancellationToken.ThrowIfCancellationRequested();

        var initialLength = stream.CanSeek ? stream.Length : 0L;
        if (initialLength > maxBytes)
        {
            throw new SysvolFileTooLargeException(path, initialLength, maxBytes);
        }

        using var output = initialLength > 0
            ? new MemoryStream(checked((int)initialLength))
            : new MemoryStream();
        var rented = ArrayPool<byte>.Shared.Rent(
            (int)Math.Min(64 * 1024L, (long)maxBytes + 1));

        try
        {
            var remainingBudget = (long)maxBytes + 1;
            while (remainingBudget > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var requested = (int)Math.Min(rented.Length, remainingBudget);
                var read = await stream
                    .ReadAsync(rented.AsMemory(0, requested), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                output.Write(rented, 0, read);
                if (output.Length > maxBytes)
                {
                    throw new SysvolFileTooLargeException(path, output.Length, maxBytes);
                }

                remainingBudget -= read;
            }

            if (stream.CanSeek && stream.Length > maxBytes)
            {
                throw new SysvolFileTooLargeException(path, stream.Length, maxBytes);
            }

            return output.ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }
}

public sealed class SysvolFileTooLargeException : IOException
{
    public SysvolFileTooLargeException(string path, long length, int maxBytes)
        : base($"SYSVOL file '{path}' is {length} bytes and exceeds the read limit of {maxBytes} bytes.")
    {
        Path = path;
        Length = length;
        MaxBytes = maxBytes;
    }

    public string Path { get; }
    public long Length { get; }
    public int MaxBytes { get; }
}
