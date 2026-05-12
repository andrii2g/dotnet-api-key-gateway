using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ApiKeyGateway;

public static class AssemblyMarker
{
}

public interface ISystemClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemClock : ISystemClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

public sealed class ApiKeyOptions
{
    public string CurrentEnvironment { get; init; } = "dev";

    public string HashPepper { get; init; } = string.Empty;

    public bool AllowXApiKeyHeader { get; init; } = true;

    public bool UpdateLastUsed { get; init; } = true;

    public int SecretBytes { get; init; } = ApiKeyConstants.MinimumSecretBytes;
}

public sealed class ApiKeyStoreUnavailableException : Exception
{
    public ApiKeyStoreUnavailableException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}

public static class ApiKeyConstants
{
    public const string Prefix = "ak";
    public const int PublicKeyRandomBytes = 10;
    public const int PublicKeyLength = 16;
    public const int MinimumSecretBytes = 32;
    public const int MaxAppLength = 3;
    public const int MaxEnvironmentLength = 10;
    public const int MaxMetadataLength = 100;
}

public sealed record ApiKeyRecord(
    long Id,
    string App,
    string Env,
    string PublicKey,
    string Hash,
    IReadOnlyCollection<string> Scopes,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? RevokedAt,
    DateTimeOffset CreatedAt,
    DateTimeOffset? UpdatedAt,
    DateTimeOffset? LastUsedAt,
    string? Name,
    string? CreatedBy,
    string? LastUsedIp,
    string? LastUsedUserAgent);

public sealed record ApiKeyCreateRequest(
    string App,
    string Env,
    IReadOnlyCollection<string> Scopes,
    DateTimeOffset? ExpiresAt = null,
    string? Name = null,
    string? CreatedBy = null);

public sealed record ApiKeyCreateResult(
    long Id,
    string App,
    string Env,
    string PublicKey,
    string FullApiKey,
    IReadOnlyCollection<string> Scopes,
    DateTimeOffset? ExpiresAt,
    string? Name,
    string? CreatedBy);

public sealed record ParsedApiKey(
    string App,
    string PublicKey,
    string Secret);

public sealed record ApiKeyValidationRequest(
    string? ApiKey,
    string CurrentEnvironment,
    IReadOnlyCollection<string> RequiredScopes,
    string? IpAddress = null,
    string? UserAgent = null);

public abstract record ApiKeyValidationResult
{
    public sealed record Success(
        long Id,
        string App,
        string Env,
        string PublicKey,
        IReadOnlyCollection<string> Scopes) : ApiKeyValidationResult;

    public sealed record Failure(
        ApiKeyValidationFailureReason Reason) : ApiKeyValidationResult;
}

public enum ApiKeyValidationFailureReason
{
    Missing,
    Malformed,
    UnknownPublicKey,
    AppMismatch,
    EnvironmentMismatch,
    Revoked,
    Expired,
    InvalidSecret,
    MissingRequiredScope,
    StoreUnavailable
}

public sealed record GeneratedApiKey(
    string App,
    string PublicKey,
    string Secret,
    string FullApiKey);

public interface IApiKeyService
{
    Task<ApiKeyCreateResult> CreateAsync(
        ApiKeyCreateRequest request,
        CancellationToken cancellationToken = default);

    Task<ApiKeyValidationResult> ValidateAsync(
        ApiKeyValidationRequest request,
        CancellationToken cancellationToken = default);

    Task RevokeAsync(
        string publicKey,
        CancellationToken cancellationToken = default);
}

public interface IApiKeyStore
{
    Task<ApiKeyRecord?> FindByPublicKeyAsync(
        string publicKey,
        CancellationToken cancellationToken = default);

    Task<ApiKeyRecord> CreateAsync(
        ApiKeyRecord record,
        CancellationToken cancellationToken = default);

    Task<bool> PublicKeyExistsAsync(
        string publicKey,
        CancellationToken cancellationToken = default);

    Task MarkUsedAsync(
        long id,
        DateTimeOffset usedAt,
        string? ipAddress,
        string? userAgent,
        CancellationToken cancellationToken = default);

    Task RevokeAsync(
        string publicKey,
        DateTimeOffset revokedAt,
        CancellationToken cancellationToken = default);
}

public interface IApiKeyGenerator
{
    GeneratedApiKey Generate(string app);
}

public interface IApiKeyHasher
{
    string HashSecret(string secret);

    bool VerifySecret(string secret, string storedHash);
}

public interface IApiKeyParser
{
    bool TryParse(string? apiKey, out ParsedApiKey parsed);
}

public sealed class ApiKeyGenerator(ApiKeyOptions options) : IApiKeyGenerator
{
    private readonly ApiKeyOptions _options = options ?? throw new ArgumentNullException(nameof(options));

    public GeneratedApiKey Generate(string app)
    {
        var normalizedApp = ApiKeyValidators.NormalizeApp(app);
        ApiKeyValidators.ValidateApp(normalizedApp);

        var publicKey = GeneratePublicKey();
        var secret = GenerateSecret();
        var fullApiKey = $"{ApiKeyConstants.Prefix}_{normalizedApp}_{publicKey}_{secret}";

        return new GeneratedApiKey(normalizedApp, publicKey, secret, fullApiKey);
    }

    internal string GeneratePublicKey()
    {
        Span<byte> bytes = stackalloc byte[ApiKeyConstants.PublicKeyRandomBytes];
        RandomNumberGenerator.Fill(bytes);
        return Base32NoPadding.Encode(bytes);
    }

    internal string GenerateSecret()
    {
        var byteCount = Math.Max(_options.SecretBytes, ApiKeyConstants.MinimumSecretBytes);
        var bytes = new byte[byteCount];
        RandomNumberGenerator.Fill(bytes);
        return Base64Url.Encode(bytes);
    }
}

public sealed class ApiKeyParser : IApiKeyParser
{
    public bool TryParse(string? apiKey, out ParsedApiKey parsed)
    {
        parsed = null!;

        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return false;
        }

        var parts = apiKey.Trim().Split('_', 4);
        if (parts.Length != 4)
        {
            return false;
        }

        if (!string.Equals(parts[0], ApiKeyConstants.Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var app = parts[1];
        var publicKey = parts[2];
        var secret = parts[3];

        if (!ApiKeyValidators.IsValidApp(app) || !ApiKeyValidators.IsValidPublicKey(publicKey) || string.IsNullOrWhiteSpace(secret))
        {
            return false;
        }

        parsed = new ParsedApiKey(app, publicKey, secret);
        return true;
    }
}

public sealed class ApiKeyHasher(ApiKeyOptions options) : IApiKeyHasher
{
    private readonly byte[] _pepperBytes = ResolvePepperBytes(options ?? throw new ArgumentNullException(nameof(options)));

    public string HashSecret(string secret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);

        var secretBytes = Encoding.UTF8.GetBytes(secret);
        using var hmac = new HMACSHA256(_pepperBytes);
        var hashBytes = hmac.ComputeHash(secretBytes);
        var encoded = Base64Url.Encode(hashBytes);
        return $"hmac-sha256:{encoded}";
    }

    public bool VerifySecret(string secret, string storedHash)
    {
        if (string.IsNullOrEmpty(storedHash) || !storedHash.StartsWith("hmac-sha256:", StringComparison.Ordinal))
        {
            return false;
        }

        var calculated = HashSecret(secret);
        var storedBytes = Encoding.UTF8.GetBytes(storedHash);
        var calculatedBytes = Encoding.UTF8.GetBytes(calculated);
        return CryptographicOperations.FixedTimeEquals(storedBytes, calculatedBytes);
    }

    private static byte[] ResolvePepperBytes(ApiKeyOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.HashPepper))
        {
            throw new InvalidOperationException("ApiKeys:HashPepper must be configured.");
        }

        if (TryDecodeBase64(options.HashPepper, out var decoded))
        {
            if (decoded.Length < ApiKeyConstants.MinimumSecretBytes)
            {
                throw new InvalidOperationException("Hash pepper must decode to at least 32 bytes.");
            }

            return decoded;
        }

        var raw = Encoding.UTF8.GetBytes(options.HashPepper);
        if (raw.Length < ApiKeyConstants.MinimumSecretBytes)
        {
            throw new InvalidOperationException("Hash pepper must be at least 32 bytes.");
        }

        return raw;
    }

    private static bool TryDecodeBase64(string value, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromBase64String(value);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }
}

public sealed class ApiKeyValidator(
    IApiKeyStore store,
    IApiKeyParser parser,
    IApiKeyHasher hasher,
    ISystemClock clock,
    ApiKeyOptions options)
{
    private readonly IApiKeyStore _store = store ?? throw new ArgumentNullException(nameof(store));
    private readonly IApiKeyParser _parser = parser ?? throw new ArgumentNullException(nameof(parser));
    private readonly IApiKeyHasher _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
    private readonly ISystemClock _clock = clock ?? throw new ArgumentNullException(nameof(clock));
    private readonly ApiKeyOptions _options = options ?? throw new ArgumentNullException(nameof(options));

    public async Task<ApiKeyValidationResult> ValidateAsync(
        ApiKeyValidationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (string.IsNullOrWhiteSpace(request.ApiKey))
        {
            return new ApiKeyValidationResult.Failure(ApiKeyValidationFailureReason.Missing);
        }

        var currentEnvironment = ApiKeyValidators.NormalizeEnv(request.CurrentEnvironment);
        var requiredScopes = ApiKeyValidators.NormalizeScopes(request.RequiredScopes, allowEmpty: true);

        ApiKeyValidators.ValidateEnv(currentEnvironment);
        ApiKeyValidators.ValidateScopes(requiredScopes, allowEmpty: true);

        if (!_parser.TryParse(request.ApiKey, out var parsed))
        {
            return new ApiKeyValidationResult.Failure(ApiKeyValidationFailureReason.Malformed);
        }

        ApiKeyRecord? record;
        try
        {
            record = await _store.FindByPublicKeyAsync(parsed.PublicKey, cancellationToken);
        }
        catch (ApiKeyStoreUnavailableException)
        {
            return new ApiKeyValidationResult.Failure(ApiKeyValidationFailureReason.StoreUnavailable);
        }

        if (record is null)
        {
            return new ApiKeyValidationResult.Failure(ApiKeyValidationFailureReason.UnknownPublicKey);
        }

        if (!string.Equals(record.App, parsed.App, StringComparison.Ordinal))
        {
            return new ApiKeyValidationResult.Failure(ApiKeyValidationFailureReason.AppMismatch);
        }

        if (!string.Equals(record.Env, currentEnvironment, StringComparison.Ordinal))
        {
            return new ApiKeyValidationResult.Failure(ApiKeyValidationFailureReason.EnvironmentMismatch);
        }

        if (record.RevokedAt is not null)
        {
            return new ApiKeyValidationResult.Failure(ApiKeyValidationFailureReason.Revoked);
        }

        var now = _clock.UtcNow;
        if (record.ExpiresAt is not null && record.ExpiresAt <= now)
        {
            return new ApiKeyValidationResult.Failure(ApiKeyValidationFailureReason.Expired);
        }

        if (!_hasher.VerifySecret(parsed.Secret, record.Hash))
        {
            return new ApiKeyValidationResult.Failure(ApiKeyValidationFailureReason.InvalidSecret);
        }

        if (!HasRequiredScopes(record.Scopes, requiredScopes))
        {
            return new ApiKeyValidationResult.Failure(ApiKeyValidationFailureReason.MissingRequiredScope);
        }

        if (_options.UpdateLastUsed)
        {
            await MarkUsedBestEffortAsync(record.Id, request.IpAddress, request.UserAgent, cancellationToken);
        }

        return new ApiKeyValidationResult.Success(record.Id, record.App, record.Env, record.PublicKey, record.Scopes);
    }

    private async Task MarkUsedBestEffortAsync(
        long id,
        string? ipAddress,
        string? userAgent,
        CancellationToken cancellationToken)
    {
        try
        {
            await _store.MarkUsedAsync(id, _clock.UtcNow, ipAddress, userAgent, cancellationToken);
        }
        catch (ApiKeyStoreUnavailableException)
        {
        }
    }

    internal static bool HasRequiredScopes(
        IReadOnlyCollection<string> actualScopes,
        IReadOnlyCollection<string> requiredScopes)
    {
        if (requiredScopes.Count == 0)
        {
            return true;
        }

        var actual = actualScopes.ToHashSet(StringComparer.Ordinal);
        return requiredScopes.All(actual.Contains);
    }
}

public sealed class ApiKeyService(
    IApiKeyStore store,
    IApiKeyGenerator generator,
    IApiKeyHasher hasher,
    ApiKeyValidator validator,
    ISystemClock clock) : IApiKeyService
{
    private readonly IApiKeyStore _store = store ?? throw new ArgumentNullException(nameof(store));
    private readonly IApiKeyGenerator _generator = generator ?? throw new ArgumentNullException(nameof(generator));
    private readonly IApiKeyHasher _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
    private readonly ApiKeyValidator _validator = validator ?? throw new ArgumentNullException(nameof(validator));
    private readonly ISystemClock _clock = clock ?? throw new ArgumentNullException(nameof(clock));

    public async Task<ApiKeyCreateResult> CreateAsync(ApiKeyCreateRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var app = ApiKeyValidators.NormalizeApp(request.App);
        var env = ApiKeyValidators.NormalizeEnv(request.Env);
        var scopes = ApiKeyValidators.NormalizeScopes(request.Scopes);
        var name = ApiKeyValidators.NormalizeOptionalMetadata(request.Name, ApiKeyConstants.MaxMetadataLength);
        var createdBy = ApiKeyValidators.NormalizeOptionalMetadata(request.CreatedBy, ApiKeyConstants.MaxMetadataLength);

        ApiKeyValidators.ValidateApp(app);
        ApiKeyValidators.ValidateEnv(env);
        ApiKeyValidators.ValidateScopes(scopes);
        ApiKeyValidators.ValidateExpiresAt(request.ExpiresAt, _clock.UtcNow);

        GeneratedApiKey generated = null!;
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            generated = _generator.Generate(app);
            if (!await _store.PublicKeyExistsAsync(generated.PublicKey, cancellationToken))
            {
                break;
            }

            if (attempt == 5)
            {
                throw new InvalidOperationException("Could not generate unique API key public id.");
            }
        }

        var hash = _hasher.HashSecret(generated.Secret);
        var record = new ApiKeyRecord(
            0,
            app,
            env,
            generated.PublicKey,
            hash,
            scopes,
            request.ExpiresAt,
            null,
            _clock.UtcNow,
            null,
            null,
            name,
            createdBy,
            null,
            null);

        var created = await _store.CreateAsync(record, cancellationToken);
        return new ApiKeyCreateResult(
            created.Id,
            created.App,
            created.Env,
            created.PublicKey,
            generated.FullApiKey,
            created.Scopes,
            created.ExpiresAt,
            created.Name,
            created.CreatedBy);
    }

    public Task<ApiKeyValidationResult> ValidateAsync(ApiKeyValidationRequest request, CancellationToken cancellationToken = default) =>
        _validator.ValidateAsync(request, cancellationToken);

    public Task RevokeAsync(string publicKey, CancellationToken cancellationToken = default)
    {
        var normalized = ApiKeyValidators.NormalizePublicKey(publicKey);
        ApiKeyValidators.ValidatePublicKey(normalized);
        return _store.RevokeAsync(normalized, _clock.UtcNow, cancellationToken);
    }
}

public static class ApiKeyRedactor
{
    public static string Redact(string? apiKey)
    {
        if (!new ApiKeyParser().TryParse(apiKey, out var parsed))
        {
            return "****";
        }

        var suffixLength = Math.Min(4, parsed.Secret.Length);
        var suffix = parsed.Secret[^suffixLength..];
        return $"{ApiKeyConstants.Prefix}_{parsed.App}_{parsed.PublicKey}_****{suffix}";
    }
}

internal static class ApiKeyValidators
{
    private static readonly Regex AppRegex = new("^[a-z0-9]{1,3}$", RegexOptions.Compiled);
    private static readonly Regex EnvRegex = new("^[a-z0-9_-]{1,10}$", RegexOptions.Compiled);
    private static readonly Regex ScopeRegex = new("^[a-z][a-z0-9:-]{1,80}$", RegexOptions.Compiled);
    private static readonly Regex PublicKeyRegex = new("^[A-Z2-7]{16}$", RegexOptions.Compiled);

    public static string NormalizeApp(string value) => value?.Trim().ToLowerInvariant() ?? string.Empty;

    public static string NormalizeEnv(string value) => value?.Trim().ToLowerInvariant() ?? string.Empty;

    public static string NormalizePublicKey(string value) => value?.Trim().ToUpperInvariant() ?? string.Empty;

    public static IReadOnlyCollection<string> NormalizeScopes(
        IReadOnlyCollection<string>? scopes,
        bool allowEmpty = false)
    {
        if (scopes is null)
        {
            return allowEmpty ? Array.Empty<string>() : throw new ArgumentException("Scopes are required.", nameof(scopes));
        }

        var normalized = scopes
            .Select(scope => scope?.Trim().ToLowerInvariant() ?? string.Empty)
            .Where(scope => !string.IsNullOrWhiteSpace(scope))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (!allowEmpty && normalized.Length == 0)
        {
            throw new ArgumentException("Scopes must not be empty.", nameof(scopes));
        }

        return normalized;
    }

    public static string? NormalizeOptionalMetadata(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var normalized = value.Trim();
        if (normalized.Length > maxLength)
        {
            throw new ArgumentException($"Metadata must be at most {maxLength} characters.", nameof(value));
        }

        return normalized;
    }

    public static bool IsValidApp(string value) => AppRegex.IsMatch(value);

    public static bool IsValidPublicKey(string value) => PublicKeyRegex.IsMatch(value);

    public static void ValidateApp(string value)
    {
        if (!IsValidApp(value))
        {
            throw new ArgumentException("App must match ^[a-z0-9]{1,3}$.", nameof(value));
        }
    }

    public static void ValidateEnv(string value)
    {
        if (!EnvRegex.IsMatch(value))
        {
            throw new ArgumentException("Environment must match ^[a-z0-9_-]{1,10}$.", nameof(value));
        }
    }

    public static void ValidateScopes(IReadOnlyCollection<string> scopes, bool allowEmpty = false)
    {
        if (!allowEmpty && scopes.Count == 0)
        {
            throw new ArgumentException("Scopes must not be empty.", nameof(scopes));
        }

        foreach (var scope in scopes)
        {
            if (!ScopeRegex.IsMatch(scope))
            {
                throw new ArgumentException("Scope must match ^[a-z][a-z0-9:-]{1,80}$.", nameof(scopes));
            }
        }
    }

    public static void ValidateExpiresAt(DateTimeOffset? expiresAt, DateTimeOffset now)
    {
        if (expiresAt is not null && expiresAt <= now)
        {
            throw new ArgumentException("ExpiresAt must be in the future.", nameof(expiresAt));
        }
    }

    public static void ValidatePublicKey(string publicKey)
    {
        if (!IsValidPublicKey(publicKey))
        {
            throw new ArgumentException("Public key must match ^[A-Z2-7]{16}$.", nameof(publicKey));
        }
    }
}

internal static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> bytes)
    {
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}

internal static class Base32NoPadding
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return string.Empty;
        }

        var outputLength = (int)Math.Ceiling(data.Length * 8 / 5d);
        var chars = new char[outputLength];
        var buffer = 0;
        var bitsLeft = 0;
        var index = 0;

        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;

            while (bitsLeft >= 5)
            {
                chars[index++] = Alphabet[(buffer >> (bitsLeft - 5)) & 31];
                bitsLeft -= 5;
            }
        }

        if (bitsLeft > 0)
        {
            chars[index++] = Alphabet[(buffer << (5 - bitsLeft)) & 31];
        }

        return new string(chars, 0, index);
    }
}
