using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ApiKeyGateway.AspNetCore;

public static class AssemblyMarker
{
}

public static class ApiKeyAuthenticationDefaults
{
    public const string AuthenticationScheme = "ApiKey";
    public const string ApiKeyIdClaimType = "api_key_id";
    public const string ApiKeyAppClaimType = "api_key_app";
    public const string ApiKeyEnvironmentClaimType = "api_key_env";
    public const string ApiKeyPublicClaimType = "api_key_public";
    internal const string FailureReasonItemKey = "__ApiKeyFailureReason";
}

internal sealed record ApiKeyScopeMetadata(IReadOnlyCollection<string> Scopes);

public sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> schemeOptions,
    ILoggerFactory loggerFactory,
    UrlEncoder encoder,
    IApiKeyService apiKeyService,
    IOptions<ApiKeyOptions> apiKeyOptions)
    : AuthenticationHandler<AuthenticationSchemeOptions>(schemeOptions, loggerFactory, encoder)
{
    private readonly IApiKeyService _apiKeyService = apiKeyService;
    private readonly ApiKeyOptions _apiKeyOptions = apiKeyOptions.Value;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var apiKey = ReadApiKey();
        var request = new ApiKeyValidationRequest(
            ApiKey: apiKey,
            CurrentEnvironment: _apiKeyOptions.CurrentEnvironment,
            RequiredScopes: Array.Empty<string>(),
            IpAddress: Context.Connection.RemoteIpAddress?.ToString(),
            UserAgent: Request.Headers.UserAgent.ToString());

        var result = await _apiKeyService.ValidateAsync(request, Context.RequestAborted);
        if (result is ApiKeyValidationResult.Failure failure)
        {
            Context.Items[ApiKeyAuthenticationDefaults.FailureReasonItemKey] = failure.Reason;
            return AuthenticateResult.Fail(failure.Reason.ToString());
        }

        var success = (ApiKeyValidationResult.Success)result;
        var claims = new List<Claim>
        {
            new(ApiKeyAuthenticationDefaults.ApiKeyIdClaimType, success.Id.ToString()),
            new(ApiKeyAuthenticationDefaults.ApiKeyAppClaimType, success.App),
            new(ApiKeyAuthenticationDefaults.ApiKeyEnvironmentClaimType, success.Env),
            new(ApiKeyAuthenticationDefaults.ApiKeyPublicClaimType, success.PublicKey)
        };

        claims.AddRange(success.Scopes.Select(scope => new Claim("scope", scope)));

        var identity = new ClaimsIdentity(claims, ApiKeyAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, ApiKeyAuthenticationDefaults.AuthenticationScheme);
        return AuthenticateResult.Success(ticket);
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (Response.HasStarted)
        {
            return;
        }

        var reason = GetFailureReason();
        if (reason == ApiKeyValidationFailureReason.StoreUnavailable)
        {
            Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            Response.ContentType = "application/json";
            await Response.WriteAsync("""{"error":"api_key_validation_unavailable"}""");
            return;
        }

        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.ContentType = "application/json";
        Response.Headers.WWWAuthenticate = ApiKeyAuthenticationDefaults.AuthenticationScheme;
        await Response.WriteAsync("""{"error":"invalid_api_key"}""");
    }

    protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        if (Response.HasStarted)
        {
            return;
        }

        Response.StatusCode = StatusCodes.Status403Forbidden;
        Response.ContentType = "application/json";
        await Response.WriteAsync("""{"error":"insufficient_scope"}""");
    }

    private string? ReadApiKey()
    {
        if (Request.Headers.TryGetValue("Authorization", out var authorizationValues))
        {
            var authorization = authorizationValues.ToString();
            if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return authorization["Bearer ".Length..].Trim();
            }
        }

        if (_apiKeyOptions.AllowXApiKeyHeader && Request.Headers.TryGetValue("X-API-Key", out var apiKeyValues))
        {
            return apiKeyValues.ToString().Trim();
        }

        return null;
    }

    private ApiKeyValidationFailureReason? GetFailureReason()
    {
        if (Context.Items.TryGetValue(ApiKeyAuthenticationDefaults.FailureReasonItemKey, out var value) &&
            value is ApiKeyValidationFailureReason reason)
        {
            return reason;
        }

        var feature = Context.Features.Get<IAuthenticateResultFeature>();
        var message = feature?.AuthenticateResult?.Failure?.Message;
        return Enum.TryParse<ApiKeyValidationFailureReason>(message, out var parsedReason) ? parsedReason : null;
    }
}

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddApiKeyAuthentication(
        this IServiceCollection services,
        Action<ApiKeyOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = ApiKeyAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = ApiKeyAuthenticationDefaults.AuthenticationScheme;
            options.DefaultForbidScheme = ApiKeyAuthenticationDefaults.AuthenticationScheme;
        }).AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
            ApiKeyAuthenticationDefaults.AuthenticationScheme,
            _ => { });

        services.AddAuthorization();

        services.AddSingleton<ISystemClock, SystemClock>();
        services.AddSingleton<IApiKeyParser, ApiKeyParser>();
        services.AddSingleton<IApiKeyGenerator>(provider => new ApiKeyGenerator(provider.GetRequiredService<IOptions<ApiKeyOptions>>().Value));
        services.AddSingleton<IApiKeyHasher>(provider => new ApiKeyHasher(provider.GetRequiredService<IOptions<ApiKeyOptions>>().Value));
        services.AddSingleton<ApiKeyValidator>(provider =>
            new ApiKeyValidator(
                provider.GetRequiredService<IApiKeyStore>(),
                provider.GetRequiredService<IApiKeyParser>(),
                provider.GetRequiredService<IApiKeyHasher>(),
                provider.GetRequiredService<ISystemClock>(),
                provider.GetRequiredService<IOptions<ApiKeyOptions>>().Value));
        services.AddSingleton<IApiKeyService>(provider =>
            new ApiKeyService(
                provider.GetRequiredService<IApiKeyStore>(),
                provider.GetRequiredService<IApiKeyGenerator>(),
                provider.GetRequiredService<IApiKeyHasher>(),
                provider.GetRequiredService<ApiKeyValidator>(),
                provider.GetRequiredService<ISystemClock>()));

        return services;
    }
}

public static class ApiKeyAuthorizationExtensions
{
    public static TBuilder RequireApiKeyScope<TBuilder>(this TBuilder builder, params string[] scopes)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(scopes);

        var normalized = scopes
            .Select(scope => scope.Trim())
            .Where(scope => !string.IsNullOrWhiteSpace(scope))
            .ToArray();

        builder.WithMetadata(new ApiKeyScopeMetadata(normalized));
        builder.RequireAuthorization(policy =>
        {
            foreach (var scope in normalized)
            {
                policy.RequireClaim("scope", scope);
            }
        });

        return builder;
    }
}
