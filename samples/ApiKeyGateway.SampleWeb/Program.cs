using System.Collections.Concurrent;
using ApiKeyGateway;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<IApiKeyStore, InMemoryApiKeyStore>();
builder.Services.AddApiKeyAuthentication(options =>
{
    options.CurrentEnvironment = builder.Configuration["ApiKeys:CurrentEnvironment"] ?? "local";
    options.HashPepper = builder.Configuration["ApiKeys:HashPepper"] ?? "sample-dev-pepper-value-with-at-least-32-bytes";
    options.AllowXApiKeyHeader = true;
    options.UpdateLastUsed = true;
});

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

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

app.MapPost("/api-keys/{publicKey}/revoke", async (string publicKey, IApiKeyService apiKeyService, CancellationToken cancellationToken) =>
{
    await apiKeyService.RevokeAsync(publicKey, cancellationToken);
    return TypedResults.NoContent();
});

app.MapGet("/secure/personas", () => TypedResults.Ok(new
{
    message = "Authenticated with API key.",
    tip = "Call this endpoint with Authorization: Bearer <fullApiKey>."
})).RequireApiKeyScope("personas:execute");

app.Run();

internal sealed record CreateApiKeyInput(
    string App,
    string Env,
    string[] Scopes,
    DateTimeOffset? ExpiresAt = null,
    string? Name = null,
    string? CreatedBy = null);

internal sealed class InMemoryApiKeyStore : IApiKeyStore
{
    private readonly ConcurrentDictionary<string, ApiKeyRecord> _records = new(StringComparer.Ordinal);
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
