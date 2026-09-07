namespace DogfighterAD.PortableSysvolPrototype;

internal static class SmbSessionKey
{
    // MS-SMB2 3.2.5.3.1: first 16 bytes, right-padded with zeros if shorter.
    public static byte[] Normalize(ReadOnlySpan<byte> key)
    {
        if (key.IsEmpty)
        {
            throw new System.Security.SecurityException("Kerberos session key is empty.");
        }
        var result = new byte[16];
        key[..Math.Min(key.Length, result.Length)].CopyTo(result);
        return result;
    }
}
