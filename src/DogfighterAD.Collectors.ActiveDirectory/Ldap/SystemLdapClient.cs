using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Runtime.CompilerServices;
using DogfighterAD.Application.Contracts;

namespace DogfighterAD.Collectors.ActiveDirectory.Ldap;

public sealed class SystemLdapClientFactory : IReadOnlyLdapClientFactory
{
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

        // WLDAP32 may block synchronously not only in Bind(), but also while initializing/configuring
        // the native LDAP handle. Keep the complete native setup boundary off the orchestration
        // thread and apply an external hard deadline to the whole operation.
        var setupTask = Task.Run(
            () => CreateAndBindConnection(target),
            CancellationToken.None);
        ObserveBackgroundFault(setupTask);

        try
        {
            var connection = await setupTask
                .WaitAsync(_options.BindTimeout, cancellationToken)
                .ConfigureAwait(false);
            return new SystemLdapClient(connection, _options.RequestTimeout);
        }
        catch (TimeoutException exception)
        {
            DisposeReturnedConnectionAfterCompletion(setupTask);
            throw new CollectorOperationalException(
                "collection.ldap.bind-timeout",
                $"LDAP connection/authentication setup did not complete within {_options.BindTimeout} (auth={_options.AuthenticationMode}). Verify target reachability and authentication prerequisites.",
                exception);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            DisposeReturnedConnectionAfterCompletion(setupTask);
            throw;
        }
        catch (CollectorOperationalException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw LdapFailureClassifier.Create(exception);
        }
    }

    private LdapConnection CreateAndBindConnection(string target)
    {
        LdapConnection? connection = null;
        try
        {
            var identifier = new LdapDirectoryIdentifier(target, _options.Port);
            var authType = MapAuthenticationMode(_options.AuthenticationMode);
            connection = _options.Credential is null
                ? new LdapConnection(identifier)
                : new LdapConnection(identifier, _options.Credential, authType);

            connection.AuthType = authType;
            connection.AutoBind = false;
            connection.Timeout = _options.RequestTimeout;
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.SecureSocketLayer = _options.UseLdaps;
            connection.Bind();
            return connection;
        }
        catch (Exception exception)
        {
            if (connection is not null)
            {
                TryDispose(connection);
            }

            throw LdapFailureClassifier.Create(exception);
        }
    }

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

    private static void ObserveBackgroundFault(Task task)
    {
        _ = task.ContinueWith(
            static completedTask => _ = completedTask.Exception,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously | TaskContinuationOptions.OnlyOnFaulted,
            TaskScheduler.Default);
    }

    private static void DisposeReturnedConnectionAfterCompletion(Task<LdapConnection> setupTask)
    {
        _ = setupTask.ContinueWith(
            static completedTask =>
            {
                if (completedTask.Status == TaskStatus.RanToCompletion)
                {
                    TryDispose(completedTask.Result);
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
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

        if (options.BindTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "LDAP bind timeout must be greater than zero.");
        }

        if (options.RequestTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "LDAP request timeout must be greater than zero.");
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
    private bool _disposed;

    public SystemLdapClient(
        LdapConnection connection,
        TimeSpan requestTimeout)
    {
        _connection = connection ?? throw new ArgumentNullException(nameof(connection));
        _requestTimeout = requestTimeout;
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
            _connection.Dispose();
            _disposed = true;
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
