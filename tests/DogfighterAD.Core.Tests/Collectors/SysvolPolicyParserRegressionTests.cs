using System.Buffers.Binary;
using System.Text;
using DogfighterAD.Collectors.ActiveDirectory.Sysvol;
using DogfighterAD.Domain.Snapshots;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class SysvolPolicyParserRegressionTests
{
    [Theory]
    [InlineData("Software\\Policies\\Review;Probe", "Enabled")]
    [InlineData("Software\\Policies\\ReviewProbe", "Enabled;Flag")]
    public void RegistryPol_SemicolonInsideNullTerminatedFieldIsPreserved(
        string keyPath,
        string valueName)
    {
        var parsed = SysvolPolicyParsers.ParseRegistryPolicy(
            BuildDwordPolicy(keyPath, valueName, 1),
            "Machine\\Registry.pol",
            GpoPolicyScope.Machine);

        Assert.True(parsed.Success, parsed.Error);
        var setting = Assert.Single(parsed.Settings);
        Assert.Equal(keyPath, setting.Section);
        Assert.Equal(valueName, setting.Key);
        Assert.Equal("1", setting.Value);
    }

    [Fact]
    public void RegistryPol_EmptyValueNameIsRejectedAtParserBoundary()
    {
        var parsed = SysvolPolicyParsers.ParseRegistryPolicy(
            BuildDwordPolicy("Software\\Policies\\ReviewProbe", string.Empty, 1),
            "Machine\\Registry.pol",
            GpoPolicyScope.Machine);

        Assert.False(parsed.Success);
        Assert.Empty(parsed.Settings);
        Assert.NotNull(parsed.Error);
        Assert.Contains("empty value name", parsed.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RegistryPol_MissingNullTerminatorFailsWithoutTreatingSemicolonAsTerminator()
    {
        using var output = new MemoryStream();
        WriteUInt32(output, 0x67655250u);
        WriteUInt32(output, 1u);
        WriteUtf16Char(output, '[');
        output.Write(Encoding.Unicode.GetBytes("Software\\Policies\\Broken;StillField"));

        var parsed = SysvolPolicyParsers.ParseRegistryPolicy(
            output.ToArray(),
            "Machine\\Registry.pol",
            GpoPolicyScope.Machine);

        Assert.False(parsed.Success);
        Assert.NotNull(parsed.Error);
    }

    [Fact]
    public void GptIni_UnknownSensitiveAndUnknownKeysDoNotExportValues()
    {
        var marker = "SECRET_CANARY_DO_NOT_STORE";
        var parsed = SysvolPolicyParsers.ParseGptIni(
            Encoding.UTF8.GetBytes(
                $"[General]\r\nVersion=65537\r\nClientSecret={marker}\r\nApiKey={marker}\r\nUnclassified={marker}\r\n"),
            "GPT.INI");

        Assert.True(parsed.Success, parsed.Error);
        var version = Assert.Single(parsed.Settings, setting => setting.Key == "Version");
        Assert.Equal(FactDisposition.Stored, version.Disposition);
        Assert.Equal("65537", version.Value);

        foreach (var setting in parsed.Settings.Where(setting => setting.Key != "Version"))
        {
            Assert.NotEqual(FactDisposition.Stored, setting.Disposition);
            Assert.Null(setting.Value);
        }

        Assert.DoesNotContain(parsed.Settings, setting => setting.Value == marker);
    }

    [Fact]
    public void SecurityTemplate_KnownPolicyValueIsStoredButUnknownSectionIsMetadataOnly()
    {
        var marker = "SECRET_CANARY_DO_NOT_STORE";
        var parsed = SysvolPolicyParsers.ParseSecurityTemplate(
            Encoding.UTF8.GetBytes(
                $"[System Access]\r\nMinimumPasswordLength = 14\r\n[Service]\r\nApiKey={marker}\r\n"),
            "Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf");

        Assert.True(parsed.Success, parsed.Error);
        var minimum = Assert.Single(
            parsed.Settings,
            setting => setting.Key == "MinimumPasswordLength");
        Assert.Equal(FactDisposition.Stored, minimum.Disposition);
        Assert.Equal("14", minimum.Value);

        var apiKey = Assert.Single(parsed.Settings, setting => setting.Key == "ApiKey");
        Assert.NotEqual(FactDisposition.Stored, apiKey.Disposition);
        Assert.Null(apiKey.Value);
    }

    private static byte[] BuildDwordPolicy(string keyPath, string valueName, uint value)
    {
        using var output = new MemoryStream();
        WriteUInt32(output, 0x67655250u);
        WriteUInt32(output, 1u);
        WriteUtf16Char(output, '[');
        WriteNullTerminatedField(output, keyPath);
        WriteUtf16Char(output, ';');
        WriteNullTerminatedField(output, valueName);
        WriteUtf16Char(output, ';');
        WriteUInt32(output, 4u);
        WriteUtf16Char(output, ';');
        WriteUInt32(output, 4u);
        WriteUtf16Char(output, ';');
        WriteUInt32(output, value);
        WriteUtf16Char(output, ']');
        return output.ToArray();
    }

    private static void WriteNullTerminatedField(Stream output, string value)
    {
        output.Write(Encoding.Unicode.GetBytes(value + "\0"));
    }

    private static void WriteUtf16Char(Stream output, char value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes, value);
        output.Write(bytes);
    }

    private static void WriteUInt32(Stream output, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        output.Write(bytes);
    }
}
