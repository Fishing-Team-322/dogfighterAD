namespace DogfighterAD.Serialization;

/// <summary>Checks canonical JSON incrementally without allocating a second complete payload.</summary>
internal sealed class CanonicalComparisonStream(ReadOnlyMemory<byte> expected) : Stream
{
    private int _position;
    public void ValidateComplete()
    {
        if (_position != expected.Length) throw NonCanonical();
    }
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length > expected.Length - _position ||
            !buffer.SequenceEqual(expected.Span.Slice(_position, buffer.Length)))
            throw NonCanonical();
        _position += buffer.Length;
    }
    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Write(buffer.Span);
        return ValueTask.CompletedTask;
    }
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override void Flush() { }
    public override Task FlushAsync(CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return Task.CompletedTask; }
    public override bool CanRead => false;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => _position;
    public override long Position { get => _position; set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    private static DogadArtifactException NonCanonical() => new("dogad.payload.noncanonical", "Payload is not canonical snapshot JSON.");
}
