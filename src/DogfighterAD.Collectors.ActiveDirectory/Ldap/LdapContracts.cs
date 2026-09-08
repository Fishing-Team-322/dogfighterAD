using System.Net;
using System.Runtime.CompilerServices;

namespace DogfighterAD.Collectors.ActiveDirectory.Ldap;

public interface IReadOnlyLdapClientFactory
{
    ValueTask<IReadOnlyLdapClient> CreateAsync(
        string target,
        CancellationToken cancellationToken);
}

public interface IReadOnlyLdapClient : IAsyncDisposable
{
    // True only after successful authenticated bind; custom adapters default to no proof.
    bool IsAuthenticated => false;
    Task<LdapSearchResult> SearchAsync(
        LdapSearchRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    /// Streams search entries to the caller. Implementations should avoid buffering the complete
    /// directory result. The default implementation preserves compatibility for test/adaptor clients
    /// by falling back to SearchAsync.
    /// </summary>
    async IAsyncEnumerable<LdapSearchEntry> SearchEntriesAsync(
        LdapSearchRequest request,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var result = await SearchAsync(request, cancellationToken).ConfigureAwait(false);
        foreach (var entry in result.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return entry;
        }
    }
}

public sealed record LdapSearchRequest
{
    public required string BaseDn { get; init; }
    public required string Filter { get; init; }
    public required LdapSearchScope Scope { get; init; }
    public IReadOnlyList<string> Attributes { get; init; } = [];
    public int PageSize { get; init; }
    public LdapSecurityDescriptorSections SecurityDescriptorSections { get; init; }
}

public enum LdapSearchScope
{
    Base,
    OneLevel,
    Subtree
}

[Flags]
public enum LdapSecurityDescriptorSections
{
    None = 0,
    Owner = 1,
    Group = 2,
    Dacl = 4,
    Sacl = 8
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

public enum LdapAuthenticationMode
{
    Negotiate,
    Ntlm
}

public sealed record LdapClientOptions
{
    public int Port { get; init; } = 389;
    public bool UseLdaps { get; init; }
    public TimeSpan BindTimeout { get; init; } = TimeSpan.FromSeconds(15);
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);
    public LdapAuthenticationMode AuthenticationMode { get; init; } = LdapAuthenticationMode.Negotiate;

    /// <summary>
    /// Marks the supplied target as the fully-qualified DNS name of the exact LDAP server rather
    /// than a domain/server name that Windows LDAP may try to rediscover. Use only when the caller
    /// contract already requires a named server FQDN.
    /// </summary>
    public bool TreatTargetAsFullyQualifiedDnsHostName { get; init; }

    /// <summary>
    /// Optional explicit credential for LDAP authentication. When null, the current operating-system
    /// security context is used. Credential material is runtime-only and is never snapshot data.
    /// </summary>
    public NetworkCredential? Credential { get; init; }
}
