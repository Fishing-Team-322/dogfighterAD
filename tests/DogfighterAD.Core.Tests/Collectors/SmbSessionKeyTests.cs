using DogfighterAD.PortableSysvolPrototype;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class SmbSessionKeyTests
{
    [Theory]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(32)]
    public void NormalizesLengthWithoutChangingInput(int length)
    {
        var input = Enumerable.Range(1, length).Select(x => (byte)x).ToArray();
        var original = input.ToArray();
        var result = SmbSessionKey.Normalize(input);
        Assert.Equal(16, result.Length);
        Assert.Equal(original.Take(16), result.Take(Math.Min(length, 16)));
        Assert.All(result.Skip(length), value => Assert.Equal((byte)0, value));
        result[0] = 0;
        Assert.Equal(original, input);
    }

    [Fact]
    public void RejectsMissingKey() =>
        Assert.Throws<System.Security.SecurityException>(() => SmbSessionKey.Normalize([]));
}
