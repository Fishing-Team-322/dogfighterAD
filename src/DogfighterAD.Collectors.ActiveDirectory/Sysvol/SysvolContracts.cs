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

        if (stream.Length > maxBytes)
        {
            throw new SysvolFileTooLargeException(fullPath, stream.Length, maxBytes);
        }

        using var buffer = new MemoryStream((int)stream.Length);
        await stream.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (buffer.Length > maxBytes)
        {
            throw new SysvolFileTooLargeException(fullPath, buffer.Length, maxBytes);
        }

        return buffer.ToArray();
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
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
