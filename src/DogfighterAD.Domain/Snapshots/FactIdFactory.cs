using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace DogfighterAD.Domain.Snapshots;

public static class FactIdFactory
{
    public const int CurrentVersion = 1;

    public static string Create(
        string capabilityId,
        string subjectId,
        string path,
        FactValueKind valueKind,
        string? value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(capabilityId);
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var canonical = string.Concat(
            Encode(CurrentVersion.ToString(CultureInfo.InvariantCulture)),
            Encode(capabilityId),
            Encode(subjectId),
            Encode(path),
            Encode(valueKind.ToString()),
            Encode(value ?? string.Empty));

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return $"fact:v{CurrentVersion}:{Convert.ToHexStringLower(hash)}";
    }

    private static string Encode(string value) =>
        $"{Encoding.UTF8.GetByteCount(value).ToString(CultureInfo.InvariantCulture)}:{value}";
}
