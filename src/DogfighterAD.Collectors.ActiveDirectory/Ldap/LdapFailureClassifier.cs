using System.DirectoryServices.Protocols;
using DogfighterAD.Application.Contracts;

namespace DogfighterAD.Collectors.ActiveDirectory.Ldap;

internal static class LdapFailureClassifier
{
    private const int InvalidCredentialsResultCode = 49;

    public static CollectorOperationalException Create(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        return exception switch
        {
            LdapException ldapException => FromLdapException(ldapException),
            DirectoryOperationException directoryException => FromDirectoryOperationException(directoryException),
            _ => new CollectorOperationalException(
                "collection.ldap.failed",
                $"LDAP operation failed ({exception.GetType().Name}). Detailed exception text is intentionally omitted.",
                exception)
        };
    }

    private static CollectorOperationalException FromLdapException(LdapException exception) =>
        exception.ErrorCode switch
        {
            InvalidCredentialsResultCode => new CollectorOperationalException(
                "collection.ldap.authentication-failed",
                "LDAP authentication failed (code=49/InvalidCredentials). Verify the supplied username/password and Negotiate prerequisites.",
                exception),
            81 or 82 or 91 => new CollectorOperationalException(
                "collection.ldap.server-unavailable",
                $"LDAP connection or negotiation failed (code={exception.ErrorCode}). Verify target resolution, routing, firewall and Negotiate prerequisites.",
                exception),
            85 => new CollectorOperationalException(
                "collection.ldap.timeout",
                "LDAP connection/request timed out (code=85). Verify reachability, name resolution and authentication negotiation.",
                exception),
            _ => new CollectorOperationalException(
                "collection.ldap.failed",
                $"LDAP operation failed (LdapException, code={exception.ErrorCode}). Detailed server/error text is intentionally omitted.",
                exception)
        };

    private static CollectorOperationalException FromDirectoryOperationException(
        DirectoryOperationException exception)
    {
        var response = exception.Response;
        if (response is null)
        {
            return new CollectorOperationalException(
                "collection.ldap.failed",
                "LDAP operation failed (DirectoryOperationException without a response). Detailed exception text is intentionally omitted.",
                exception);
        }

        var resultCode = response.ResultCode;
        if ((int)resultCode == InvalidCredentialsResultCode)
        {
            return new CollectorOperationalException(
                "collection.ldap.authentication-failed",
                "LDAP authentication failed (code=49/InvalidCredentials). Verify the supplied username/password and Negotiate prerequisites.",
                exception);
        }

        return resultCode switch
        {
            ResultCode.InappropriateAuthentication or ResultCode.AuthMethodNotSupported =>
                new CollectorOperationalException(
                    "collection.ldap.authentication-failed",
                    $"LDAP authentication was rejected (result={resultCode}, code={(int)resultCode}). Verify the supplied identity and Negotiate prerequisites.",
                    exception),
            ResultCode.Unavailable => new CollectorOperationalException(
                "collection.ldap.server-unavailable",
                $"LDAP server reported unavailable (result={resultCode}, code={(int)resultCode}).",
                exception),
            ResultCode.TimeLimitExceeded => new CollectorOperationalException(
                "collection.ldap.timeout",
                $"LDAP server time limit was exceeded (result={resultCode}, code={(int)resultCode}).",
                exception),
            ResultCode.StrongAuthRequired or ResultCode.ConfidentialityRequired => new CollectorOperationalException(
                "collection.ldap.security-required",
                $"LDAP server requires stronger authentication/transport protection (result={resultCode}, code={(int)resultCode}).",
                exception),
            _ => new CollectorOperationalException(
                "collection.ldap.failed",
                $"LDAP server rejected the operation (result={resultCode}, code={(int)resultCode}). Detailed server/error text is intentionally omitted.",
                exception)
        };
    }
}
