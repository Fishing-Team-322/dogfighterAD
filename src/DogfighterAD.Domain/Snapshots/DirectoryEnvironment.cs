namespace DogfighterAD.Domain.Snapshots;

public sealed record DirectoryEnvironment
{
    public string? DnsHostName { get; init; }
    public string? DefaultNamingContext { get; init; }
    public string? ConfigurationNamingContext { get; init; }
    public string? SchemaNamingContext { get; init; }
    public string? RootDomainNamingContext { get; init; }
    public IReadOnlyList<string> NamingContexts { get; init; } = [];
    public IReadOnlyList<string> SupportedCapabilities { get; init; } = [];
    public IReadOnlyList<string> SupportedControls { get; init; } = [];
    public IReadOnlyList<string> SupportedLdapVersions { get; init; } = [];
}
