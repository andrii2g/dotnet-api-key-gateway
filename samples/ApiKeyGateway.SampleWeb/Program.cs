using ApiKeyGateway;

var builder = WebApplication.CreateBuilder(args);
var storeName = builder.Configuration["ApiKeys:Store"] ?? "InMemory";

builder.Services.AddApiKeyAuthentication(options =>
{
    options.CurrentEnvironment = builder.Configuration["ApiKeys:CurrentEnvironment"] ?? "local";
    options.HashPepper = builder.Configuration["ApiKeys:HashPepper"] ?? "sample-dev-pepper-value-with-at-least-32-bytes";
    options.AllowXApiKeyHeader = true;
    options.UpdateLastUsed = true;
});

if (string.Equals(storeName, "InMemory", StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddSingleton<IApiKeyStore, InMemoryApiKeyStore>();
}
else
{
    var connectionString = builder.Configuration["ApiKeys:ConnectionString"];
    if (string.IsNullOrWhiteSpace(connectionString))
    {
        throw new InvalidOperationException("ApiKeys:ConnectionString must be configured for database-backed sample storage.");
    }

    var dialectValue = builder.Configuration["ApiKeys:Dialect"] ?? "MySql";
    if (!Enum.TryParse<ApiKeySqlDialect>(dialectValue, ignoreCase: true, out var dialect))
    {
        throw new InvalidOperationException($"Unsupported ApiKeys:Dialect '{dialectValue}'.");
    }

    var commandTimeoutSeconds = builder.Configuration.GetValue<int?>("ApiKeys:CommandTimeoutSeconds") ?? 30;
    builder.Services.AddApiKeyGatewayStore(options =>
    {
        options.Dialect = dialect;
        options.ConnectionString = connectionString;
        options.CommandTimeoutSeconds = commandTimeoutSeconds;
    });
}

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (IConfiguration configuration) => TypedResults.Ok(new
{
    service = "ApiKeyGateway.SampleWeb",
    environment = configuration["ApiKeys:CurrentEnvironment"] ?? "local",
    store = storeName,
    endpoints = new[]
    {
        "POST /api-keys",
        "POST /api-keys/{publicKey}/revoke",
        "GET /secure/personas",
        "GET /health"
    }
}));

app.MapPost("/api-keys", async (CreateApiKeyInput input, IApiKeyService apiKeyService, CancellationToken cancellationToken) =>
{
    var result = await apiKeyService.CreateAsync(
        new ApiKeyCreateRequest(
            input.App,
            input.Env,
            input.Scopes,
            input.ExpiresAt,
            input.Name,
            input.CreatedBy),
        cancellationToken);

    return TypedResults.Created($"/api-keys/{result.PublicKey}", result);
});

app.MapPost("/api-keys/{keyOrPublicKey}/revoke", async (string keyOrPublicKey, IApiKeyService apiKeyService, CancellationToken cancellationToken) =>
{
    await apiKeyService.RevokeAsync(NormalizeRevocationIdentifier(keyOrPublicKey), cancellationToken);
    return TypedResults.NoContent();
});

app.MapGet("/secure/personas", () => TypedResults.Ok(new
{
    message = "Authenticated with API key.",
    tip = "Call this endpoint with Authorization: Bearer <fullApiKey>."
})).RequireApiKeyScope("personas:execute");

app.MapGet("/health", () => TypedResults.Ok(new { status = "ok" }));

app.Run();

static string NormalizeRevocationIdentifier(string value)
{
    ArgumentException.ThrowIfNullOrWhiteSpace(value);

    var trimmed = value.Trim();
    var parser = new ApiKeyParser();
    if (parser.TryParse(trimmed, out var parsed))
    {
        return parsed.PublicKey;
    }

    var underscoreIndex = trimmed.IndexOf('_');
    if (underscoreIndex > 0)
    {
        var candidate = trimmed[..underscoreIndex].Trim().ToUpperInvariant();
        if (candidate.Length == ApiKeyConstants.PublicKeyLength)
        {
            return candidate;
        }
    }

    return trimmed;
}

internal sealed record CreateApiKeyInput(
    string App,
    string Env,
    string[] Scopes,
    DateTimeOffset? ExpiresAt = null,
    string? Name = null,
    string? CreatedBy = null);

internal sealed class InMemoryApiKeyStore : IApiKeyStore
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, ApiKeyRecord> _records = new(StringComparer.Ordinal);
    private long _nextId;

    public Task<ApiKeyRecord?> FindByPublicKeyAsync(string publicKey, CancellationToken cancellationToken = default)
    {
        _records.TryGetValue(publicKey, out var record);
        return Task.FromResult(record);
    }

    public Task<ApiKeyRecord> CreateAsync(ApiKeyRecord record, CancellationToken cancellationToken = default)
    {
        var id = Interlocked.Increment(ref _nextId);
        var stored = record with { Id = id };
        if (!_records.TryAdd(stored.PublicKey, stored))
        {
            throw new InvalidOperationException("Public key already exists.");
        }

        return Task.FromResult(stored);
    }

    public Task<bool> PublicKeyExistsAsync(string publicKey, CancellationToken cancellationToken = default) =>
        Task.FromResult(_records.ContainsKey(publicKey));

    public Task MarkUsedAsync(long id, DateTimeOffset usedAt, string? ipAddress, string? userAgent, CancellationToken cancellationToken = default)
    {
        var current = _records.Values.SingleOrDefault(record => record.Id == id);
        if (current is not null)
        {
            _records[current.PublicKey] = current with
            {
                LastUsedAt = usedAt,
                LastUsedIp = ipAddress,
                LastUsedUserAgent = userAgent,
                UpdatedAt = usedAt
            };
        }

        return Task.CompletedTask;
    }

    public Task RevokeAsync(string publicKey, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        if (_records.TryGetValue(publicKey, out var current))
        {
            _records[publicKey] = current with
            {
                RevokedAt = revokedAt,
                UpdatedAt = revokedAt
            };
        }

        return Task.CompletedTask;
    }
}
