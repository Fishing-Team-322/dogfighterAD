namespace DogfighterAD.Collectors.ActiveDirectory.Ldap;

internal static class LdapFilterEncoding
{
    public static string EncodeOctetString(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty)
        {
            return string.Empty;
        }

        return string.Create(
            value.Length * 3,
            value.ToArray(),
            static (destination, bytes) =>
            {
                const string Hex = "0123456789ABCDEF";
                var offset = 0;
                foreach (var current in bytes)
                {
                    destination[offset++] = '\\';
                    destination[offset++] = Hex[current >> 4];
                    destination[offset++] = Hex[current & 0x0F];
                }
            });
    }
}
