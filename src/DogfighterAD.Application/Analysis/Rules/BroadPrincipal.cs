using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Application.Analysis.Rules;

internal static class BroadPrincipal
{
    public static bool Matches(string? sid, AdSnapshot snapshot, RuleCheck check)
    {
        if (sid is null) return false;
        if (new[] { "S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-7" }.Contains(sid, StringComparer.OrdinalIgnoreCase)) return true;
        if (!sid.EndsWith("-513", StringComparison.Ordinal)) return false;
        var domainSids = snapshot.Content.Domains.Select(domain => check.Text(CollectionCapabilities.DirectoryDomains,
            "domain.objectSid", FactValueKind.Sid, $"ad-object:{domain.Id}")).ToArray();
        check.Require(domainSids.Length > 0, CollectionCapabilities.DirectoryDomains, "domain.objectSid", "field.not-observed");
        return domainSids.Any(d => StringComparer.OrdinalIgnoreCase.Equals(sid, d + "-513"));
    }
}
