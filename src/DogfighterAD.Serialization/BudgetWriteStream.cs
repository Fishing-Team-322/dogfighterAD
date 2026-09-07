namespace DogfighterAD.Serialization;

/// <summary>Counts bytes before forwarding writes. Does not own the underlying stream.</summary>
internal sealed class BudgetWriteStream : Stream
{
    private readonly Stream _inner;
    private readonly long _limit;
    private readonly string _errorCode;
    private long _written;

    public BudgetWriteStream(Stream inner, long limit, string errorCode)
    {
        _inner = inner;
        _limit = limit;
        _errorCode = errorCode;
    }

    private void Reserve(int count)
    {
        if (count > _limit - _written)
        {
            throw new DogadArtifactException(_errorCode, "Serialized data exceeds the configured byte budget.");
        }
        _written += count;
    }

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        Reserve(buffer.Length);
        _inner.Write(buffer);
    }
    public override void WriteByte(byte value)
    {
        Reserve(1);
        _inner.WriteByte(value);
    }
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Reserve(buffer.Length);
        await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
    }
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => _written;
    public override long Position { get => _written; set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
