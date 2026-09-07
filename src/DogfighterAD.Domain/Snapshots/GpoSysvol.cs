namespace DogfighterAD.Domain.Snapshots;

public sealed record AdGpoSysvolFile
{
    public required AdObjectId GpoId { get; init; }
    public required string RelativePath { get; init; }
    public long Length { get; init; }
    public string? Sha256 { get; init; }
    public DateTimeOffset? LastWriteTimeUtc { get; init; }
    public required GpoSysvolFileKind Kind { get; init; }
}

public sealed record AdGpoSetting
{
    public required AdObjectId GpoId { get; init; }
    public required GpoPolicyScope Scope { get; init; }
    public required string SourceRelativePath { get; init; }
    public required int Sequence { get; init; }
    public required GpoSettingKind Kind { get; init; }
    public string? Section { get; init; }
    public required string Key { get; init; }
    public string? Value { get; init; }
    public required FactValueKind ValueKind { get; init; }
    public FactDisposition Disposition { get; init; } = FactDisposition.Stored;
    public int DataLength { get; init; }
}

public enum GpoSysvolFileKind
{
    Other,
    GptIni,
    SecurityTemplate,
    RegistryPolicy,
    PreferencesXml
}

public enum GpoPolicyScope
{
    Common,
    Machine,
    User
}

public enum GpoSettingKind
{
    Ini,
    SecurityTemplate,
    RegistryPolicy,
    PreferenceSignal
}
