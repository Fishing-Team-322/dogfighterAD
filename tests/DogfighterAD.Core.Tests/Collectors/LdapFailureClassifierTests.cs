using System.DirectoryServices.Protocols;
using DogfighterAD.Collectors.ActiveDirectory.Ldap;

namespace DogfighterAD.Core.Tests.Collectors;

public sealed class LdapFailureClassifierTests
{
    [Theory]
    [InlineData(49, "collection.ldap.authentication-failed")]
    [InlineData(81, "collection.ldap.server-unavailable")]
    [InlineData(82, "collection.ldap.server-unavailable")]
    [InlineData(85, "collection.ldap.timeout")]
    [InlineData(91, "collection.ldap.server-unavailable")]
    [InlineData(1234, "collection.ldap.failed")]
    public void Create_ClassifiesLdapExceptionWithoutLeakingRawMessage(
        int errorCode,
        string expectedIssueCode)
    {
        const string secret = "SECRET_CANARY";
        var exception = new LdapException(errorCode, secret);

        var result = LdapFailureClassifier.Create(exception);

        Assert.Equal(expectedIssueCode, result.IssueCode);
        Assert.DoesNotContain(secret, result.SafeMessage, StringComparison.Ordinal);
        Assert.Contains(errorCode.ToString(), result.SafeMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void AuthenticationFailure_MessageDoesNotAssumeNegotiate()
    {
        var result = LdapFailureClassifier.Create(new LdapException(49, "SECRET_CANARY"));

        Assert.Equal("collection.ldap.authentication-failed", result.IssueCode);
        Assert.DoesNotContain("Negotiate", result.SafeMessage, StringComparison.OrdinalIgnoreCase);
    }
}
