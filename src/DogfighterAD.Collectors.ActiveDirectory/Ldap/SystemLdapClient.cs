using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security;
using DogfighterAD.Application.Contracts;

namespace DogfighterAD.Collectors.ActiveDirectory.Ldap;

public sealed class SystemLdapClientFactory : IReadOnlyLdapClientFactory
{
    internal const int MaxOutstandingNativeSetups = 16;

    // WLDAP32/native LDAP setup is not forcibly cancellable by Task.WaitAsync. Keep a process-wide
    // hard cap so timed-out setup calls cannot accumulate without bound across repeated scans. A
    // slot is released only when the physical setup task actually exits, not when the caller stops
    // waiting for it.
    private static readonly SemaphoreSlim NativeSetupSlots =
        new(MaxOutstandingNativeSetups, MaxOutstandingNativeSetups);

    private readonly LdapClientOptions _options;

    public SystemLdapClientFactory(LdapClientOptions? options = null)
    {
        _options = options ?? new LdapClientOptions();
        ValidateOptions(_options);
    }

    public async ValueTask<IReadOnlyLdapClient> CreateAsync(
        string target,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        cancellationToken.ThrowIfCancellationRequested();

        if (!await NativeSetupSlots.WaitAsync(0, cancellationToken).ConfigureAwait(false))
        {
            throw new CollectorOperationalException(
                "collection.ldap.setup-capacity",
                $"LDAP native setup capacity is exhausted ({MaxOutstandingNativeSetups} unfinished setup operations). " +
                "Wait for prior timed-out native operations to finish before starting more LDAP setup work.");
        }

        // Clone an explicit credential before entering native LDAP code. A timed-out native setup
        // may continue on its isolated task after the CLI scan scope returns; it must therefore not
        // depend on the prompt-owned SecureString lifetime.
        CredentialLease? credentialLease = null;
        Task<ConnectionSetupResult> setupTask;
        try
        {
            credentialLease = CreateCredentialLease(_options.Credential);

            // Native LDAP may block synchronously not only in Bind(), but also while initializing or
            // configuring the handle. Keep the complete native setup boundary off the orchestration
            // thread and apply an external deadline to the caller's wait.
            setupTask = Task.Run(
                () => CreateAndBindConnection(target, credentialLease),
                CancellationToken.None);
        }
        catch
        {
            credentialLease?.Dispose();
            NativeSetupSlots.Release();
            throw;
        }

        ObserveBackgroundFault(setupTask);

        try
        {
            var setup = await setupTask
                .WaitAsync(_options.BindTimeout, cancellationToken)
                .ConfigureAwait(false);
            var client = new SystemLdapClient(
                setup.Connection,
                _options.RequestTimeout,
                setup.CredentialLease);
            NativeSetupSlots.Release();
            return client;
        }
        catch (TimeoutException exception)
        {
            DisposeReturnedSetupAfterCompletion(setupTask);
            throw new CollectorOperationalException(
                "collection.ldap.bind-timeout",
                $"LDAP connection/authentication setup did not complete within {_options.BindTimeout} " +
                $"(auth={_options.AuthenticationMode}, fqdn-server-bind={_options.TreatTargetAsFullyQualifiedDnsHostName}). " +
                "The native setup may still be finishing under the bounded background-operation budget. " +
                "Verify target reachability and authentication prerequisites.",
                exception);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            DisposeReturnedSetupAfterCompletion(setupTask);
            throw;
        }
        catch (CollectorOperationalException)
        {
            NativeSetupSlots.Release();
            throw;
        }
        catch (Exception exception)
        {
            NativeSetupSlots.Release();
            throw LdapFailureClassifier.Create(exception);
        }
    }

    private ConnectionSetupResult CreateAndBindConnection(
        string target,
        CredentialLease? credentialLease)
    {
        LdapConnection? connection = null;
        try
        {
            var identifier = CreateDirectoryIdentifier(
                target,
                _options.Port,
                _options.TreatTargetAsFullyQualifiedDnsHostName);
            var authType = MapAuthenticationMode(_options.AuthenticationMode);
            connection = credentialLease is null
                ? new LdapConnection(identifier)
                : new LdapConnection(identifier, credentialLease.Credential, authType);

            connection.AuthType = authType;
            connection.AutoBind = false;
            connection.Timeout = _options.RequestTimeout;
            ConfigureSession(connection, _options.UseLdaps);
            connection.Bind();
            return new ConnectionSetupResult(connection, credentialLease);
        }
        catch (Exception exception)
        {
            if (connection is not null)
            {
                TryDispose(connection);
            }

            credentialLease?.Dispose();
            throw LdapFailureClassifier.Create(exception);
        }
    }

    internal static void ConfigureSession(LdapConnection connection, bool useLdaps)
    {
        ArgumentNullException.ThrowIfNull(connection);

        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = useLdaps;
        // Collectors query the selected naming context on the selected server. Native referral
        // chasing can otherwise initiate unscoped discovery/authentication on a workgroup host.
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;

        if (!useLdaps)
        {
            // Port 389 is allowed only with SASL integrity/confidentiality protection owned by the
            // application. Do not silently fall back to an unsigned or unsealed LDAP session.
            // These options must be configured before Bind().
            connection.SessionOptions.Signing = true;
            connection.SessionOptions.Sealing = true;

            if (!connection.SessionOptions.Signing || !connection.SessionOptions.Sealing)
            {
                throw new InvalidOperationException(
                    "LDAP signing/sealing could not be enabled for the non-TLS session.");
            }
        }
    }

    internal static LdapDirectoryIdentifier CreateDirectoryIdentifier(
        string target,
        int port,
        bool fullyQualifiedDnsHostName) =>
        new(
            target,
            port,
            fullyQualifiedDnsHostName,
            connectionless: false);

    internal static AuthType MapAuthenticationMode(LdapAuthenticationMode authenticationMode) =>
        authenticationMode switch
        {
            LdapAuthenticationMode.Negotiate => AuthType.Negotiate,
            LdapAuthenticationMode.Ntlm => AuthType.Ntlm,
            _ => throw new ArgumentOutOfRangeException(
                nameof(authenticationMode),
                authenticationMode,
                "Unsupported LDAP authentication mode.")
        };

    private static CredentialLease? CreateCredentialLease(NetworkCredential? credential)
    {
        if (credential is null)
        {
            return null;
        }

        SecureString? passwordCopy = null;
        try
        {
            passwordCopy = credential.SecurePassword.Copy();
            if (!passwordCopy.IsReadOnly())
            {
                passwordCopy.MakeReadOnly();
            }

            var credentialCopy = string.IsNullOrWhiteSpace(credential.Domain)
                ? new NetworkCredential(credential.UserName, passwordCopy)
                : new NetworkCredential(credential.UserName, passwordCopy, credential.Domain);

            return new CredentialLease(credentialCopy, passwordCopy);
        }
        catch
        {
            passwordCopy?.Dispose();
            throw;
        }
    }


    private static void ObserveBackgroundFault(Task task)
    {
        _ = task.ContinueWith(
            static completedTask => _ = completedTask.Exception,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously | TaskContinuationOptions.OnlyOnFaulted,
            TaskScheduler.Default);
    }

    private static void DisposeReturnedSetupAfterCompletion(Task<ConnectionSetupResult> setupTask)
    {
        _ = setupTask.ContinueWith(
            static completedTask =>
            {
                try
                {
                    if (completedTask.Status == TaskStatus.RanToCompletion)
                    {
                        var setup = completedTask.Result;
                        try { TryDispose(setup.Connection); }
                        finally { setup.CredentialLease?.Dispose(); }
                    }
                }
                finally
                {
                    // Cleanup can itself enter native code. It owns the budget until it exits.
                    NativeSetupSlots.Release();
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.None,
            TaskScheduler.Default);
    }

    private static void TryDispose(LdapConnection connection)
    {
        try
        {
            connection.Dispose();
        }
        catch (Exception)
        {
            // Cleanup must never replace the safe operational error already selected for output.
        }
    }

    private static void ValidateOptions(LdapClientOptions options)
    {
        if (options.Port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "LDAP port must be between 1 and 65535.");
        }

        if (options.BindTimeout <= TimeSpan.Zero || options.BindTimeout.TotalMilliseconds > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "LDAP bind timeout must be greater than zero.");
        }

        if (options.RequestTimeout <= TimeSpan.Zero || options.RequestTimeout.TotalMilliseconds > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "LDAP request timeout must be greater than zero.");
        }
    }

    private sealed record ConnectionSetupResult(
        LdapConnection Connection,
        CredentialLease? CredentialLease);

    private sealed class CredentialLease : IDisposable
    {
        private readonly SecureString _password;
        private bool _disposed;

        public CredentialLease(NetworkCredential credential, SecureString password)
        {
            Credential = credential ?? throw new ArgumentNullException(nameof(credential));
            _password = password ?? throw new ArgumentNullException(nameof(password));
        }

        public NetworkCredential Credential { get; }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _password.Dispose();
            _disposed = true;
        }
    }
}

internal sealed class SystemLdapClient : IReadOnlyLdapClient
{
    private const LdapSecurityDescriptorSections AllSecurityDescriptorSections =
        LdapSecurityDescriptorSections.Owner |
        LdapSecurityDescriptorSections.Group |
        LdapSecurityDescriptorSections.Dacl |
        LdapSecurityDescriptorSections.Sacl;

    private static readonly IReadOnlySet<string> BinaryAttributeNames =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "objectGUID",
            "objectSid",
            "sIDHistory",
            "securityIdentifier",
            "nTSecurityDescriptor"
        };

    private readonly LdapConnection _connection;
    private readonly TimeSpan _requestTimeout;
    private readonly IDisposable? _credentialLease;
    private bool _disposed;

    public SystemLdapClient(
        LdapConnection connection,
        TimeSpan requestTimeout,
        IDisposable? credentialLease = null)
    {
        _connection = connection ?? throw new ArgumentNullException(nameof(connection));
        _requestTimeout = requestTimeout;
        _credentialLease = credentialLease;
    }

    public async Task<LdapSearchResult> SearchAsync(
        LdapSearchRequest request,
        CancellationToken cancellationToken)
    {
        var entries = new List<LdapSearchEntry>();

        await foreach (var entry in SearchEntriesAsync(request, cancellationToken))
        {
            entries.Add(entry);
        }

        return new LdapSearchResult(entries);
    }

    public async IAsyncEnumerable<LdapSearchEntry> SearchEntriesAsync(
        LdapSearchRequest request,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request);

        byte[]? cookie = null;

        do
        {
            cancellationToken.ThrowIfCancellationRequested();

            var nativeRequest = new SearchRequest(
                request.BaseDn,
                request.Filter,
                MapScope(request.Scope),
                request.Attributes.ToArray());

            if (request.SecurityDescriptorSections != LdapSecurityDescriptorSections.None)
            {
                nativeRequest.Controls.Add(new SecurityDescriptorFlagControl(
                    MapSecurityMasks(request.SecurityDescriptorSections)));
            }

            PageResultRequestControl? pagingControl = null;
            if (request.PageSize > 0)
            {
                pagingControl = new PageResultRequestControl(request.PageSize);
                if (cookie is { Length: > 0 })
                {
                    pagingControl.Cookie = cookie;
                }

                nativeRequest.Controls.Add(pagingControl);
            }

            var nativeResponse = (SearchResponse)await SendRequestAsync(
                nativeRequest,
                cancellationToken).ConfigureAwait(false);

            foreach (SearchResultEntry entry in nativeResponse.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return MapEntry(entry);
            }

            if (pagingControl is null)
            {
                break;
            }

            cookie = nativeResponse.Controls
                .OfType<PageResultResponseControl>()
                .Select(control => control.Cookie)
                .FirstOrDefault();
        }
        while (cookie is { Length: > 0 });
    }

    public ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            try
            {
                _connection.Dispose();
            }
            finally
            {
                _credentialLease?.Dispose();
                _disposed = true;
            }
        }

        return ValueTask.CompletedTask;
    }

    private async Task<DirectoryResponse> SendRequestAsync(
        DirectoryRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        IAsyncResult pendingRequest;
        try
        {
            pendingRequest = _connection.BeginSendRequest(
                request,
                _requestTimeout,
                PartialResultProcessing.NoPartialResultSupport,
                callback: null,
                state: null);
        }
        catch (Exception) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (LdapException exception)
        {
            throw LdapFailureClassifier.Create(exception);
        }
        catch (DirectoryOperationException exception)
        {
            throw LdapFailureClassifier.Create(exception);
        }

        using var cancellationRegistration = cancellationToken.Register(
            static state =>
            {
                var cancellationState = (CancellationState)state!;
                try
                {
                    cancellationState.Connection.Abort(cancellationState.PendingRequest);
                }
                catch (ObjectDisposedException)
                {
                    // Disposal and cancellation can race. The caller still observes cancellation.
                }
                catch (LdapException)
                {
                    // Abort may race with normal completion; EndSendRequest owns final status.
                }
            },
            new CancellationState(_connection, pendingRequest));

        try
        {
            return await Task<DirectoryResponse>.Factory
                .FromAsync(pendingRequest, _connection.EndSendRequest)
                .ConfigureAwait(false);
        }
        catch (Exception) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (LdapException exception)
        {
            throw LdapFailureClassifier.Create(exception);
        }
        catch (DirectoryOperationException exception)
        {
            throw LdapFailureClassifier.Create(exception);
        }
    }

    private static LdapSearchEntry MapEntry(SearchResultEntry entry)
    {
        var attributes = new Dictionary<string, IReadOnlyList<LdapAttributeValue>>(
            StringComparer.OrdinalIgnoreCase);

        foreach (string attributeName in entry.Attributes.AttributeNames)
        {
            var attribute = entry.Attributes[attributeName];
            attributes[attributeName] = MapAttributeValues(attributeName, attribute);
        }

        return new LdapSearchEntry
        {
            DistinguishedName = entry.DistinguishedName ?? string.Empty,
            Attributes = attributes
        };
    }

    internal static IReadOnlyList<LdapAttributeValue> MapAttributeValues(
        string attributeName,
        DirectoryAttribute attribute)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(attributeName);
        ArgumentNullException.ThrowIfNull(attribute);

        if (BinaryAttributeNames.Contains(attributeName))
        {
            return attribute
                .GetValues(typeof(byte[]))
                .Cast<byte[]>()
                .Select(LdapAttributeValue.FromBytes)
                .ToArray();
        }

        return attribute
            .GetValues(typeof(string))
            .Select(value => LdapAttributeValue.FromText(
                Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty))
            .ToArray();
    }

    private static SearchScope MapScope(LdapSearchScope scope) => scope switch
    {
        LdapSearchScope.Base => SearchScope.Base,
        LdapSearchScope.OneLevel => SearchScope.OneLevel,
        LdapSearchScope.Subtree => SearchScope.Subtree,
        _ => throw new ArgumentOutOfRangeException(nameof(scope), scope, "Unknown LDAP search scope.")
    };

    internal static SecurityMasks MapSecurityMasks(LdapSecurityDescriptorSections sections)
    {
        var result = SecurityMasks.None;

        if (sections.HasFlag(LdapSecurityDescriptorSections.Owner))
        {
            result |= SecurityMasks.Owner;
        }

        if (sections.HasFlag(LdapSecurityDescriptorSections.Group))
        {
            result |= SecurityMasks.Group;
        }

        if (sections.HasFlag(LdapSecurityDescriptorSections.Dacl))
        {
            result |= SecurityMasks.Dacl;
        }

        if (sections.HasFlag(LdapSecurityDescriptorSections.Sacl))
        {
            result |= SecurityMasks.Sacl;
        }

        return result;
    }

    private static void ValidateRequest(LdapSearchRequest request)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Filter);

        if (request.PageSize < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "LDAP page size cannot be negative.");
        }

        if ((request.SecurityDescriptorSections & ~AllSecurityDescriptorSections) != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request),
                "LDAP security descriptor selection contains unsupported flags.");
        }

        if (request.Attributes.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("LDAP attribute names cannot be empty.", nameof(request));
        }
    }

    private sealed record CancellationState(
        LdapConnection Connection,
        IAsyncResult PendingRequest);
}
