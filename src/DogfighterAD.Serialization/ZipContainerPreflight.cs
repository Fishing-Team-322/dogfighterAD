using System.Buffers.Binary;
using System.Text;

namespace DogfighterAD.Serialization;

/// <summary>
/// Validates bounded classic-ZIP metadata before ZipArchive can allocate its entry collection.
/// .dogad is a two-file, single-disk format. ZIP64 and embedded/self-extracting archives are not
/// accepted; the supported artifact budget is below the classic-ZIP size limit.
/// </summary>
internal static class ZipContainerPreflight
{
    private const uint EndSignature = 0x06054b50;
    private const uint CentralSignature = 0x02014b50;
    private const uint LocalSignature = 0x04034b50;
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);

    public static async Task ValidateAsync(Stream source, DogadReadOptions limits, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (source.Length < 22)
            throw Invalid();

        // EOCD has at most a 65535-byte comment. Never load the entire central directory to
        // discover its size or count, and never trust just the count declared in the EOCD.
        var tail = new byte[(int)Math.Min(source.Length, 22L + ushort.MaxValue)];
        source.Position = source.Length - tail.Length;
        await source.ReadExactlyAsync(tail, token).ConfigureAwait(false);
        var end = -1;
        for (var i = tail.Length - 22; i >= 0; i--)
        {
            if (U32(tail, i) == EndSignature && i + 22 + U16(tail, i + 20) == tail.Length)
            {
                end = i;
                break;
            }
        }
        if (end < 0) throw Invalid();
        var endPosition = source.Length - tail.Length + end;
        var count = U16(tail, end + 10);
        var centralSize = U32(tail, end + 12);
        var centralOffset = U32(tail, end + 16);
        if (U16(tail, end + 4) != 0 || U16(tail, end + 6) != 0 ||
            U16(tail, end + 8) != count)
            throw Invalid();
        if (count == ushort.MaxValue || centralSize == uint.MaxValue || centralOffset == uint.MaxValue)
            throw new DogadArtifactException("dogad.container.zip64-unsupported", "ZIP64 is outside the supported .dogad container budget.");
        if (count > limits.MaxEntryCount)
            throw CountInvalid();
        if (centralSize > limits.MaxCentralDirectoryBytes)
            throw new DogadArtifactException("dogad.container.metadata-too-large", "ZIP central directory exceeds the configured metadata budget.");
        if ((long)centralOffset + centralSize != endPosition)
            throw Invalid();

        var position = (long)centralOffset;
        var centralEnd = position + centralSize;
        var seen = 0;
        var header = new byte[46];
        var localHeader = new byte[30];
        var ranges = new List<(long Start, long End)>();
        while (position < centralEnd)
        {
            token.ThrowIfCancellationRequested();
            if (++seen > limits.MaxEntryCount) throw CountInvalid();
            if (centralEnd - position < header.Length) throw Invalid();
            source.Position = position;
            await source.ReadExactlyAsync(header, token).ConfigureAwait(false);
            if (U32(header, 0) != CentralSignature) throw Invalid();
            var flags = U16(header, 8);
            var method = U16(header, 10);
            var compressedSize = U32(header, 20);
            var expandedSize = U32(header, 24);
            var nameLength = U16(header, 28);
            var extraLength = U16(header, 30);
            var commentLength = U16(header, 32);
            var localOffset = U32(header, 42);
            if (compressedSize == uint.MaxValue || expandedSize == uint.MaxValue || localOffset == uint.MaxValue ||
                U16(header, 34) != 0 || (flags & 0x2041) != 0 || method is not 0 and not 8)
                throw Invalid();
            if (method == 0 && compressedSize != expandedSize) throw Invalid();
            var next = position + 46L + nameLength + extraLength + commentLength;
            if (next > centralEnd) throw Invalid();
            // At most four UTF-8 bytes per allowed character, additionally bounded by centralSize.
            if (nameLength > 4L * limits.MaxEntryNameChars)
                throw NameTooLong();
            var nameBytes = new byte[nameLength];
            await source.ReadExactlyAsync(nameBytes, token).ConfigureAwait(false);
            string name;
            try { name = StrictUtf8.GetString(nameBytes); }
            catch (DecoderFallbackException) { throw Invalid(); }
            if (name.Length > limits.MaxEntryNameChars) throw NameTooLong();
            // The only valid names are ASCII; decoding platform-specific ZIP codepages is unnecessary.
            if (name != DogadFormat.ManifestEntryName && name != DogadFormat.SnapshotEntryName)
                throw new DogadArtifactException("dogad.container.entry-unexpected", "The container includes an unsupported entry name.");

            var expandedLimit = name == DogadFormat.ManifestEntryName ? limits.MaxManifestBytes : limits.MaxSnapshotBytes;
            if (expandedSize > expandedLimit)
                throw new DogadArtifactException("dogad.container.entry-too-large", "ZIP entry exceeds the configured expanded byte budget.");
            if ((long)localOffset + 30 > centralOffset) throw Invalid();
            source.Position = localOffset;
            await source.ReadExactlyAsync(localHeader, token).ConfigureAwait(false);
            if (U32(localHeader, 0) != LocalSignature || U16(localHeader, 6) != flags ||
                U16(localHeader, 8) != method || U16(localHeader, 26) != nameLength)
                throw Invalid();
            var localName = new byte[nameLength];
            await source.ReadExactlyAsync(localName, token).ConfigureAwait(false);
            if (!nameBytes.AsSpan().SequenceEqual(localName)) throw Invalid();
            var dataEnd = (long)localOffset + 30 + nameLength + U16(localHeader, 28) + compressedSize;
            if (dataEnd > centralOffset) throw Invalid();
            if ((flags & 8) == 0 &&
                (U32(localHeader, 18) != compressedSize || U32(localHeader, 22) != expandedSize ||
                 U32(localHeader, 14) != U32(header, 16)))
                throw Invalid();
            if (ranges.Any(range => localOffset < range.End && dataEnd > range.Start)) throw Invalid();
            ranges.Add((localOffset, dataEnd));
            position = next;
        }
        if (seen != count || position != centralEnd) throw Invalid();
        if (ranges.Count > 0 && ranges.Min(range => range.Start) != 0) throw Invalid();
        source.Position = 0;
    }

    private static ushort U16(byte[] bytes, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2));
    private static uint U32(byte[] bytes, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
    private static DogadArtifactException Invalid() => new("dogad.container.invalid", "Invalid or unsupported .dogad ZIP structure.");
    private static DogadArtifactException CountInvalid() => new("dogad.container.entry-count-invalid", "ZIP entry count exceeds the configured budget.");
    private static DogadArtifactException NameTooLong() => new("dogad.container.entry-name-too-long", "ZIP entry name exceeds the configured length budget.");
}
