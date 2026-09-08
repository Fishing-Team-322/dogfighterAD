using DogfighterAD.Application.Contracts;

namespace DogfighterAD.Application.Analysis.Rules;

/// <summary>
/// Public factory for the built-in Certificate Services rule slice. The returned rules are pure
/// offline analyzers and perform no network or CA runtime operations.
/// </summary>
public static class CertificateServicesRulePack
{
    public const string Version = "1.1.0";

    public static IReadOnlyList<IRule> Create() => CertificateServicesRuleCatalogV2.Create();
}
