using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace ApiKeyGateway.Tests;

public sealed class AspNetCoreTests
{
    [Fact]
    public async Task ValidKey_ReturnsSuccess()
    {
        using var client = await CreateClient(new ApiKeyValidationResult.Success(
            123, "crm", "prod", "ABCDEFGHJKLMNP23", ["personas:execute"]));

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "ak_crm_ABCDEFGHJKLMNP23_secret");
        var response = await client.GetAsync("/secure");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task MissingKey_Returns401()
    {
        using var client = await CreateClient(new ApiKeyValidationResult.Failure(ApiKeyValidationFailureReason.Missing));

        var response = await client.GetAsync("/secure");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("""{"error":"invalid_api_key"}""", body);
    }

    [Fact]
    public async Task InvalidKey_Returns401()
    {
        using var client = await CreateClient(new ApiKeyValidationResult.Failure(ApiKeyValidationFailureReason.InvalidSecret));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "bad");

        var response = await client.GetAsync("/secure");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task EnvironmentMismatch_Returns401()
    {
        using var client = await CreateClient(new ApiKeyValidationResult.Failure(ApiKeyValidationFailureReason.EnvironmentMismatch));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "ak_crm_ABCDEFGHJKLMNP23_secret");

        var response = await client.GetAsync("/secure");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task MissingScope_Returns403()
    {
        using var client = await CreateClient(new ApiKeyValidationResult.Success(
            123, "crm", "prod", "ABCDEFGHJKLMNP23", ["personas:read"]));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "ak_crm_ABCDEFGHJKLMNP23_secret");

        var response = await client.GetAsync("/secure");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("""{"error":"insufficient_scope"}""", body);
    }

    [Fact]
    public async Task StoreUnavailable_Returns503()
    {
        using var client = await CreateClient(new ApiKeyValidationResult.Failure(ApiKeyValidationFailureReason.StoreUnavailable));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "ak_crm_ABCDEFGHJKLMNP23_secret");

        var response = await client.GetAsync("/secure");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("""{"error":"api_key_validation_unavailable"}""", body);
    }

    [Fact]
    public async Task Claims_AreProjectedOnSuccess()
    {
        using var client = await CreateClient(new ApiKeyValidationResult.Success(
            123, "crm", "prod", "ABCDEFGHJKLMNP23", ["personas:execute", "personas:read"]));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "ak_crm_ABCDEFGHJKLMNP23_secret");

        var response = await client.GetFromJsonAsync<Dictionary<string, string[]>>("/claims");

        Assert.NotNull(response);
        Assert.Equal(["123"], response[ApiKeyAuthenticationDefaults.ApiKeyIdClaimType]);
        Assert.Equal(["crm"], response[ApiKeyAuthenticationDefaults.ApiKeyAppClaimType]);
        Assert.Equal(["prod"], response[ApiKeyAuthenticationDefaults.ApiKeyEnvironmentClaimType]);
        Assert.Equal(["ABCDEFGHJKLMNP23"], response[ApiKeyAuthenticationDefaults.ApiKeyPublicClaimType]);
        Assert.Equal(["personas:execute", "personas:read"], response["scope"]);
    }

    private static async Task<HttpClient> CreateClient(ApiKeyValidationResult result)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddRouting();
        builder.Services.AddApiKeyAuthentication(options =>
        {
            options.CurrentEnvironment = "prod";
            options.HashPepper = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        });
        builder.Services.AddSingleton<IApiKeyStore>(new NullStore());
        builder.Services.AddSingleton<IApiKeyService>(new StubApiKeyService(result));

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapGet("/secure", () => Results.Ok()).RequireApiKeyScope("personas:execute");
        app.MapGet("/claims", (ClaimsPrincipal user) =>
            user.Claims
                .GroupBy(claim => claim.Type)
                .ToDictionary(group => group.Key, group => group.Select(claim => claim.Value).ToArray()))
            .RequireAuthorization();

        await app.StartAsync();
        return app.GetTestClient();
    }

    private sealed class StubApiKeyService(ApiKeyValidationResult result) : IApiKeyService
    {
        public Task<ApiKeyCreateResult> CreateAsync(ApiKeyCreateRequest request, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ApiKeyValidationResult> ValidateAsync(ApiKeyValidationRequest request, CancellationToken cancellationToken = default) =>
            Task.FromResult(result);

        public Task RevokeAsync(string publicKey, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class NullStore : IApiKeyStore
    {
        public Task<ApiKeyRecord?> FindByPublicKeyAsync(string publicKey, CancellationToken cancellationToken = default) => Task.FromResult<ApiKeyRecord?>(null);
        public Task<ApiKeyRecord> CreateAsync(ApiKeyRecord record, CancellationToken cancellationToken = default) => Task.FromResult(record);
        public Task<bool> PublicKeyExistsAsync(string publicKey, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task MarkUsedAsync(long id, DateTimeOffset usedAt, string? ipAddress, string? userAgent, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task RevokeAsync(string publicKey, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
