using System.Buffers.Binary;
using System.Text.Json;

namespace DogfighterAD.Collectors.ActiveDirectory.Sysvol;

internal enum SysvolWorkerOperation
{
    Enumerate = 1,
    Read = 2
}

internal enum SysvolWorkerFrameKind : byte
{
    Entry = 1,
    Data = 2,
    Complete = 3,
    Error = 4
}

internal enum SysvolWorkerErrorCode : byte
{
    InvalidRequest = 1,
    NotFound = 2,
    AccessDenied = 3,
    IoFailure = 4,
    TooLarge = 5,
    InternalFailure = 6
}

internal sealed record SysvolWorkerRequest
{
    public required SysvolWorkerOperation Operation { get; init; }
    public required string Path { get; init; }
    public int MaxBytes { get; init; }
}

internal sealed record SysvolWorkerEntry
{
    public required string FullPath { get; init; }
    public required string RelativePath { get; init; }
    public long Length { get; init; }
    public DateTimeOffset? LastWriteTimeUtc { get; init; }
}

internal readonly record struct SysvolWorkerFrame(
    SysvolWorkerFrameKind Kind,
    byte[] Payload);

internal static class SysvolWorkerProtocol
{
    private const int HeaderSize = 5;
    private const int MaxFramePayloadBytes = 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);

    public static string SerializeRequest(SysvolWorkerRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return JsonSerializer.Serialize(request, JsonOptions);
    }

    public static SysvolWorkerRequest DeserializeRequest(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return JsonSerializer.Deserialize<SysvolWorkerRequest>(value, JsonOptions)
            ?? throw new InvalidDataException("SYSVOL worker request was empty.");
    }

    public static byte[] SerializeEntry(SysvolWorkerEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return JsonSerializer.SerializeToUtf8Bytes(entry, JsonOptions);
    }

    public static SysvolWorkerEntry DeserializeEntry(ReadOnlySpan<byte> payload) =>
        JsonSerializer.Deserialize<SysvolWorkerEntry>(payload, JsonOptions)
        ?? throw new InvalidDataException("SYSVOL worker entry was empty.");

    public static byte[] SerializeError(SysvolWorkerErrorCode errorCode) =>
        [(byte)errorCode];

    public static SysvolWorkerErrorCode DeserializeError(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 1 || !Enum.IsDefined((SysvolWorkerErrorCode)payload[0]))
        {
            throw new InvalidDataException("SYSVOL worker error frame is invalid.");
        }

        return (SysvolWorkerErrorCode)payload[0];
    }

    public static async ValueTask WriteFrameAsync(
        Stream stream,
        SysvolWorkerFrameKind kind,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (payload.Length > MaxFramePayloadBytes)
        {
            throw new InvalidDataException("SYSVOL worker frame exceeds the protocol limit.");
        }

        var header = new byte[HeaderSize];
        header[0] = (byte)kind;
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(1), payload.Length);

        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        if (!payload.IsEmpty)
        {
            await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        }

        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask<SysvolWorkerFrame?> ReadFrameAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var header = new byte[HeaderSize];
        var read = await stream
            .ReadAsync(header.AsMemory(0, HeaderSize), cancellationToken)
            .ConfigureAwait(false);
        if (read == 0)
        {
            return null;
        }

        while (read < HeaderSize)
        {
            var next = await stream
                .ReadAsync(header.AsMemory(read, HeaderSize - read), cancellationToken)
                .ConfigureAwait(false);
            if (next == 0)
            {
                throw new EndOfStreamException("SYSVOL worker frame header was truncated.");
            }

            read += next;
        }

        var kind = (SysvolWorkerFrameKind)header[0];
        if (!Enum.IsDefined(kind))
        {
            throw new InvalidDataException("SYSVOL worker frame kind is invalid.");
        }

        var payloadLength = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(1));
        if (payloadLength < 0 || payloadLength > MaxFramePayloadBytes)
        {
            throw new InvalidDataException("SYSVOL worker frame length is invalid.");
        }

        var payload = new byte[payloadLength];
        var offset = 0;
        while (offset < payloadLength)
        {
            var next = await stream
                .ReadAsync(payload.AsMemory(offset, payloadLength - offset), cancellationToken)
                .ConfigureAwait(false);
            if (next == 0)
            {
                throw new EndOfStreamException("SYSVOL worker frame payload was truncated.");
            }

            offset += next;
        }

        return new SysvolWorkerFrame(kind, payload);
    }
}
