using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Runtime.CompilerServices;

namespace DogfighterAD.Collectors.ActiveDirectory.Ldap;

public sealed class SystemLdapClientFactory : IReadOnlyLdapClientFactory
{
    private readonly LdapClientOptions _options;

    public SystemLdapClientFactory(LdapClientOptions? options = null)
    {
        _options = options ?? new LdapClientOptions();
        ValidateOptions(_options);
    }

    public ValueTask<IReadOnlyLdapClient> CreateAsync(
        string target,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        cancellationToken.ThrowIfCancellationRequested();

        var identifier = new LdapDirectoryIdentifier(target, _options.Port);
        var connection = new LdapConnection(identifier)
        {
            AuthType = AuthType.Negotiate
        };

        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = _options.UseLdaps;

        return ValueTask.FromResult<IReadOnlyLdapClient>(
            new SystemLdapClient(connection, _options.RequestTimeout));
    }

    private static void ValidateOptions(LdapClientOptions options)
    {
        if (options.Port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "LDAP port must be between 1 and 65535.");
        }

        if (options.RequestTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "LDAP request timeout must be greater than zero.");
        }
    }
}

internal sealed class SystemLdapClient : IReadOnlyLdapClient
{
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

        IAsyncResult pendingRequest = _connection.BeginSendRequest(
            request,
            _requestTimeout,
            PartialResultProcessing.NoPartialResultSupport,
            callback: null,
            state: null);

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
    }

    private static LdapSearchEntry MapEntry(SearchResultEntry entry)
    {
        var attributes = new Dictionary<string, IReadOnlyList<LdapAttributeValue>>(
            StringComparer.OrdinalIgnoreCase);

        foreach (string attributeName in entry.Attributes.AttributeNames)
        {
            var attribute = entry.Attributes[attributeName];
            var values = new List<LdapAttributeValue>(attribute.Count);

            for (var index = 0; index < attribute.Count; index++)
            {
                var rawValue = attribute[index];
                switch (rawValue)
                {
                    case byte[] bytes:
                        values.Add(LdapAttributeValue.FromBytes(bytes));
                        break;
                    case string text:
                        values.Add(LdapAttributeValue.FromText(text));
                        break;
                    default:
                        values.Add(LdapAttributeValue.FromText(
                            Convert.ToString(rawValue, CultureInfo.InvariantCulture) ?? string.Empty));
                        break;
                }
            }

            attributes[attributeName] = values;
        }

        return new LdapSearchEntry
        {
            DistinguishedName = entry.DistinguishedName ?? string.Empty,
            Attributes = attributes
        };
    }

    private static SearchScope MapScope(LdapSearchScope scope) => scope switch
    {
        LdapSearchScope.Base => SearchScope.Base,
        LdapSearchScope.OneLevel => SearchScope.OneLevel,
        LdapSearchScope.Subtree => SearchScope.Subtree,
        _ => throw new ArgumentOutOfRangeException(nameof(scope), scope, "Unknown LDAP search scope.")
    };

    private static void ValidateRequest(LdapSearchRequest request)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Filter);

        if (request.PageSize < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "LDAP page size cannot be negative.");
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
