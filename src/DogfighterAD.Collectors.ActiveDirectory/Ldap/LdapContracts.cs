namespace DogfighterAD.Collectors.ActiveDirectory.Ldap;

public interface IReadOnlyLdapClientFactory
{
    ValueTask<IReadOnlyLdapClient> CreateAsync(
        string target,
        CancellationToken cancellationToken);
}

public interface IReadOnlyLdapClient : IAsyncDisposable
{
    Task<LdapSearchResult> SearchAsync(
        LdapSearchRequest request,
        CancellationToken cancellationToken);
}

public sealed record LdapSearchRequest
{
    public required string BaseDn { get; init; }
    public required string Filter { get; init; }
    public required LdapSearchScope Scope { get; init; }
    public IReadOnlyList<string> Attributes { get; init; } = [];
    public int PageSize { get; init; }
}

public enum LdapSearchScope
{
    Base,
    OneLevel,
    Subtree
}

public sealed record LdapSearchResult(IReadOnlyList<LdapSearchEntry> Entries);

public sealed record LdapSearchEntry
{
    public required string DistinguishedName { get; init; }
    public required IReadOnlyDictionary<string, IReadOnlyList<LdapAttributeValue>> Attributes { get; init; }

    public IReadOnlyList<string> GetTextValues(string attributeName)
    {
        if (!Attributes.TryGetValue(attributeName, out var values))
        {
            return [];
        }

        return values
            .Where(value => value.Text is not null)
            .Select(value => value.Text!)
            .ToArray();
    }

    public string? GetSingleTextValue(string attributeName) =>
        GetTextValues(attributeName).FirstOrDefault();

    public IReadOnlyList<byte[]> GetBinaryValues(string attributeName)
    {
        if (!Attributes.TryGetValue(attributeName, out var values))
        {
            return [];
        }

        return values
            .Where(value => value.Bytes is not null)
            .Select(value => value.Bytes!.ToArray())
            .ToArray();
    }
}

public sealed record LdapAttributeValue
{
    private LdapAttributeValue(string? text, byte[]? bytes)
    {
        Text = text;
        Bytes = bytes;
    }

    public string? Text { get; }
    public byte[]? Bytes { get; }
    public bool IsBinary => Bytes is not null;

    public static LdapAttributeValue FromText(string value) =>
        new(value ?? throw new ArgumentNullException(nameof(value)), null);

    public static LdapAttributeValue FromBytes(byte[] value) =>
        new(null, (value ?? throw new ArgumentNullException(nameof(value))).ToArray());
}

public sealed record LdapClientOptions
{
    public int Port { get; init; } = 389;
    public bool UseLdaps { get; init; }
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);
}
