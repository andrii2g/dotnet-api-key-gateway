using System.Security.Cryptography;
using System.Collections.Concurrent;

namespace ApiKeyGateway.Tests;

public sealed class CoreTests
{
    [Fact]
    public void Generator_UsesExpectedFormat_AndLengths()
    {
        var generator = new ApiKeyGenerator(new ApiKeyOptions { HashPepper = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) });

        var generated = generator.Generate("CrM");

        Assert.Equal("crm", generated.App);
        Assert.StartsWith("ak_crm_", generated.FullApiKey, StringComparison.Ordinal);
        Assert.Equal(ApiKeyConstants.PublicKeyLength, generated.PublicKey.Length);
        Assert.Equal(43, generated.Secret.Length);
    }

    [Fact]
    public void Generator_UsesConfiguredSecretBytes()
    {
        var generator = new ApiKeyGenerator(new ApiKeyOptions
        {
            HashPepper = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            SecretBytes = 48
        });

        var generated = generator.Generate("crm");

        Assert.Equal(64, generated.Secret.Length);
    }

    [Fact]
    public void Parser_ParsesValidKey()
    {
        var parser = new ApiKeyParser();

        var success = parser.TryParse("ak_crm_ABCDEFGHJKLMNP23_secret-value", out var parsed);

        Assert.True(success);
        Assert.Equal("crm", parsed.App);
        Assert.Equal("ABCDEFGHJKLMNP23", parsed.PublicKey);
        Assert.Equal("secret-value", parsed.Secret);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("bad")]
    [InlineData("ak_crm_short_secret")]
    [InlineData("ak_crm_ABCDEFGHJKLMNP23_")]
    [InlineData("zz_crm_7F3K9Q2M8N4P6R1T_secret")]
    public void Parser_RejectsMalformedKeys(string? value)
    {
        var parser = new ApiKeyParser();

        var success = parser.TryParse(value, out _);

        Assert.False(success);
    }

    [Fact]
    public void Hasher_HashesAndVerifies()
    {
        var hasher = new ApiKeyHasher(new ApiKeyOptions
        {
            HashPepper = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
        });

        var hash = hasher.HashSecret("secret");

        Assert.StartsWith("hmac-sha256:", hash, StringComparison.Ordinal);
        Assert.True(hasher.VerifySecret("secret", hash));
        Assert.False(hasher.VerifySecret("other", hash));
    }

    [Fact]
    public void Redactor_MasksSecret()
    {
        var redacted = ApiKeyRedactor.Redact("ak_crm_ABCDEFGHJKLMNP23_secretvalue");

        Assert.Equal("ak_crm_ABCDEFGHJKLMNP23_****alue", redacted);
    }

    [Fact]
    public void Redactor_ReturnsFallbackForMalformedKey()
    {
        Assert.Equal("****", ApiKeyRedactor.Redact("bad"));
    }

    [Fact]
    public async Task Service_CreateAsync_PersistsNormalizedMetadata()
    {
        var store = new InMemoryStore();
        var service = CreateService(store);

        var result = await service.CreateAsync(new ApiKeyCreateRequest(
            "CRM",
            "PROD",
            ["personas:read", "personas:read", "personas:execute"],
            DateTimeOffset.UtcNow.AddHours(1),
            "  CRM integration  ",
            "  admin@example.com  "));

        Assert.Equal("crm", result.App);
        Assert.Equal("prod", result.Env);
        Assert.Equal("CRM integration", result.Name);
        Assert.Equal("admin@example.com", result.CreatedBy);
        Assert.Equal(2, result.Scopes.Count);
    }

    [Fact]
    public async Task Service_CreateAsync_RetriesPublicKeyCollision()
    {
        var store = new InMemoryStore();
        var generator = new SequentialGenerator(
            new GeneratedApiKey("crm", "AAAAAAAAAAAAAAAA", "secret-one", "ak_crm_AAAAAAAAAAAAAAAA_secret-one"),
            new GeneratedApiKey("crm", "BBBBBBBBBBBBBBBB", "secret-two", "ak_crm_BBBBBBBBBBBBBBBB_secret-two"));
        var service = CreateService(store, generator: generator);

        await service.CreateAsync(new ApiKeyCreateRequest("crm", "prod", ["personas:read"]));
        var second = await service.CreateAsync(new ApiKeyCreateRequest("crm", "prod", ["personas:read"]));

        Assert.Equal("BBBBBBBBBBBBBBBB", second.PublicKey);
    }

    [Fact]
    public async Task Validator_ReturnsMissingForBlankApiKey()
    {
        var validator = CreateValidator(new InMemoryStore());

        var result = await validator.ValidateAsync(new ApiKeyValidationRequest(null, "prod", []));

        Assert.Equal(ApiKeyValidationFailureReason.Missing, Assert.IsType<ApiKeyValidationResult.Failure>(result).Reason);
    }

    [Fact]
    public async Task Validator_ReturnsMalformedForInvalidApiKey()
    {
        var validator = CreateValidator(new InMemoryStore());

        var result = await validator.ValidateAsync(new ApiKeyValidationRequest("bad", "prod", []));

        Assert.Equal(ApiKeyValidationFailureReason.Malformed, Assert.IsType<ApiKeyValidationResult.Failure>(result).Reason);
    }

    [Fact]
    public async Task Validator_ReturnsUnknownPublicKey()
    {
        var validator = CreateValidator(new InMemoryStore());

        var result = await validator.ValidateAsync(new ApiKeyValidationRequest("ak_crm_ABCDEFGHJKLMNP23_secret", "prod", []));

        Assert.Equal(ApiKeyValidationFailureReason.UnknownPublicKey, Assert.IsType<ApiKeyValidationResult.Failure>(result).Reason);
    }

    [Fact]
    public async Task Validator_ReturnsStoreUnavailable()
    {
        var store = new InMemoryStore { ThrowOnFind = true };
        var validator = CreateValidator(store);

        var result = await validator.ValidateAsync(new ApiKeyValidationRequest("ak_crm_ABCDEFGHJKLMNP23_secret", "prod", []));

        Assert.Equal(ApiKeyValidationFailureReason.StoreUnavailable, Assert.IsType<ApiKeyValidationResult.Failure>(result).Reason);
    }

    [Fact]
    public async Task Validator_ReturnsAppMismatch()
    {
        var setup = await CreateStoredKeyAsync("crm", "prod", ["personas:read"]);
        var validator = CreateValidator(setup.Store, setup.Hasher);

        var result = await validator.ValidateAsync(new ApiKeyValidationRequest(setup.FullApiKey.Replace("ak_crm_", "ak_bot_", StringComparison.Ordinal), "prod", []));

        Assert.Equal(ApiKeyValidationFailureReason.AppMismatch, Assert.IsType<ApiKeyValidationResult.Failure>(result).Reason);
    }

    [Fact]
    public async Task Validator_ReturnsEnvironmentMismatch()
    {
        var setup = await CreateStoredKeyAsync("crm", "prod", ["personas:read"]);
        var validator = CreateValidator(setup.Store, setup.Hasher);

        var result = await validator.ValidateAsync(new ApiKeyValidationRequest(setup.FullApiKey, "stage", []));

        Assert.Equal(ApiKeyValidationFailureReason.EnvironmentMismatch, Assert.IsType<ApiKeyValidationResult.Failure>(result).Reason);
    }

    [Fact]
    public async Task Validator_ReturnsRevoked()
    {
        var setup = await CreateStoredKeyAsync("crm", "prod", ["personas:read"], revokedAt: DateTimeOffset.UtcNow);
        var validator = CreateValidator(setup.Store, setup.Hasher);

        var result = await validator.ValidateAsync(new ApiKeyValidationRequest(setup.FullApiKey, "prod", []));

        Assert.Equal(ApiKeyValidationFailureReason.Revoked, Assert.IsType<ApiKeyValidationResult.Failure>(result).Reason);
    }

    [Fact]
    public async Task Validator_ReturnsExpired()
    {
        var setup = await CreateStoredKeyAsync("crm", "prod", ["personas:read"], expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1));
        var validator = CreateValidator(setup.Store, setup.Hasher);

        var result = await validator.ValidateAsync(new ApiKeyValidationRequest(setup.FullApiKey, "prod", []));

        Assert.Equal(ApiKeyValidationFailureReason.Expired, Assert.IsType<ApiKeyValidationResult.Failure>(result).Reason);
    }

    [Fact]
    public async Task Validator_ReturnsInvalidSecret()
    {
        var setup = await CreateStoredKeyAsync("crm", "prod", ["personas:read"]);
        var validator = CreateValidator(setup.Store, setup.Hasher);

        var result = await validator.ValidateAsync(new ApiKeyValidationRequest($"{ApiKeyConstants.Prefix}_crm_{setup.PublicKey}_wrong-secret", "prod", []));

        Assert.Equal(ApiKeyValidationFailureReason.InvalidSecret, Assert.IsType<ApiKeyValidationResult.Failure>(result).Reason);
    }

    [Fact]
    public async Task Validator_ReturnsMissingRequiredScope()
    {
        var setup = await CreateStoredKeyAsync("crm", "prod", ["personas:read"]);
        var validator = CreateValidator(setup.Store, setup.Hasher);

        var result = await validator.ValidateAsync(new ApiKeyValidationRequest(setup.FullApiKey, "prod", ["personas:execute"]));

        Assert.Equal(ApiKeyValidationFailureReason.MissingRequiredScope, Assert.IsType<ApiKeyValidationResult.Failure>(result).Reason);
    }

    [Fact]
    public async Task Validator_Succeeds_AndMarksUsage()
    {
        var setup = await CreateStoredKeyAsync("crm", "prod", ["personas:read"]);
        var validator = CreateValidator(setup.Store, setup.Hasher);

        var result = await validator.ValidateAsync(new ApiKeyValidationRequest(setup.FullApiKey, "prod", ["personas:read"], "127.0.0.1", "agent"));

        var success = Assert.IsType<ApiKeyValidationResult.Success>(result);
        Assert.Equal(setup.PublicKey, success.PublicKey);
        Assert.Equal("127.0.0.1", setup.Store.LastMarkedIp);
        Assert.Equal("agent", setup.Store.LastMarkedUserAgent);
    }

    [Fact]
    public async Task Validator_IgnoresMarkUsedAvailabilityFailure()
    {
        var setup = await CreateStoredKeyAsync("crm", "prod", ["personas:read"]);
        setup.Store.ThrowOnMarkUsed = true;
        var validator = CreateValidator(setup.Store, setup.Hasher);

        var result = await validator.ValidateAsync(new ApiKeyValidationRequest(setup.FullApiKey, "prod", ["personas:read"]));

        Assert.IsType<ApiKeyValidationResult.Success>(result);
    }

    private static ApiKeyService CreateService(
        InMemoryStore store,
        IApiKeyGenerator? generator = null,
        IApiKeyHasher? hasher = null,
        ApiKeyOptions? options = null,
        ISystemClock? clock = null)
    {
        options ??= CreateOptions();
        hasher ??= new ApiKeyHasher(options);
        var parser = new ApiKeyParser();
        clock ??= new FakeClock(DateTimeOffset.UtcNow);
        generator ??= new ApiKeyGenerator(options);
        var validator = new ApiKeyValidator(store, parser, hasher, clock, options);
        return new ApiKeyService(store, generator, hasher, validator, clock);
    }

    private static ApiKeyValidator CreateValidator(
        InMemoryStore store,
        IApiKeyHasher? hasher = null,
        ApiKeyOptions? options = null,
        ISystemClock? clock = null)
    {
        options ??= CreateOptions();
        hasher ??= new ApiKeyHasher(options);
        clock ??= new FakeClock(DateTimeOffset.UtcNow);
        return new ApiKeyValidator(store, new ApiKeyParser(), hasher, clock, options);
    }

    private static ApiKeyOptions CreateOptions() => new()
    {
        HashPepper = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        SecretBytes = 32,
        UpdateLastUsed = true
    };

    private static async Task<(InMemoryStore Store, IApiKeyHasher Hasher, string FullApiKey, string PublicKey)> CreateStoredKeyAsync(
        string app,
        string env,
        IReadOnlyCollection<string> scopes,
        DateTimeOffset? expiresAt = null,
        DateTimeOffset? revokedAt = null)
    {
        var store = new InMemoryStore();
        var options = CreateOptions();
        var hasher = new ApiKeyHasher(options);
        var generator = new ApiKeyGenerator(options);
        var generated = generator.Generate(app);
        var record = new ApiKeyRecord(
            1,
            app,
            env,
            generated.PublicKey,
            hasher.HashSecret(generated.Secret),
            scopes,
            expiresAt,
            revokedAt,
            DateTimeOffset.UtcNow,
            null,
            null,
            null,
            null,
            null,
            null);
        await store.CreateAsync(record);
        return (store, hasher, generated.FullApiKey, generated.PublicKey);
    }

    private sealed class FakeClock(DateTimeOffset utcNow) : ISystemClock
    {
        public DateTimeOffset UtcNow { get; } = utcNow;
    }

    private sealed class InMemoryStore : IApiKeyStore
    {
        private readonly ConcurrentDictionary<string, ApiKeyRecord> _records = new(StringComparer.Ordinal);
        private long _nextId = 0;

        public bool ThrowOnFind { get; set; }
        public bool ThrowOnMarkUsed { get; set; }
        public string? LastMarkedIp { get; private set; }
        public string? LastMarkedUserAgent { get; private set; }

        public Task<ApiKeyRecord?> FindByPublicKeyAsync(string publicKey, CancellationToken cancellationToken = default)
        {
            if (ThrowOnFind)
            {
                throw new ApiKeyStoreUnavailableException("Unavailable");
            }

            _records.TryGetValue(publicKey, out var record);
            return Task.FromResult(record);
        }

        public Task<ApiKeyRecord> CreateAsync(ApiKeyRecord record, CancellationToken cancellationToken = default)
        {
            var created = record with { Id = record.Id == 0 ? Interlocked.Increment(ref _nextId) : record.Id };
            _records[created.PublicKey] = created;
            return Task.FromResult(created);
        }

        public Task<bool> PublicKeyExistsAsync(string publicKey, CancellationToken cancellationToken = default) =>
            Task.FromResult(_records.ContainsKey(publicKey));

        public Task MarkUsedAsync(long id, DateTimeOffset usedAt, string? ipAddress, string? userAgent, CancellationToken cancellationToken = default)
        {
            if (ThrowOnMarkUsed)
            {
                throw new ApiKeyStoreUnavailableException("Unavailable");
            }

            var existing = _records.Values.Single(record => record.Id == id);
            var updated = existing with
            {
                LastUsedAt = usedAt,
                UpdatedAt = usedAt,
                LastUsedIp = ipAddress,
                LastUsedUserAgent = userAgent
            };
            _records[updated.PublicKey] = updated;
            LastMarkedIp = ipAddress;
            LastMarkedUserAgent = userAgent;
            return Task.CompletedTask;
        }

        public Task RevokeAsync(string publicKey, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
        {
            if (_records.TryGetValue(publicKey, out var existing))
            {
                _records[publicKey] = existing with { RevokedAt = revokedAt, UpdatedAt = revokedAt };
            }

            return Task.CompletedTask;
        }
    }

    private sealed class SequentialGenerator(params GeneratedApiKey[] values) : IApiKeyGenerator
    {
        private readonly Queue<GeneratedApiKey> _values = new(values);

        public GeneratedApiKey Generate(string app) => _values.Dequeue();
    }
}
