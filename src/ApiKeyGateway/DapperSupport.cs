using System.Data.Common;
using System.Text.Json;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MySqlConnector;
using Npgsql;

namespace ApiKeyGateway;

public interface IApiKeyDbConnectionFactory
{
    ValueTask<DbConnection> OpenConnectionAsync(CancellationToken cancellationToken = default);
}

public enum ApiKeySqlDialect
{
    MySql,
    PostgreSql
}

public sealed class ApiKeyStoreOptions
{
    public ApiKeySqlDialect Dialect { get; set; } = ApiKeySqlDialect.MySql;

    public string ConnectionString { get; set; } = string.Empty;

    public int CommandTimeoutSeconds { get; set; } = 30;
}

internal sealed class ApiKeyRow
{
    public long Id { get; init; }
    public string App { get; init; } = string.Empty;
    public string Env { get; init; } = string.Empty;
    public string PublicKey { get; init; } = string.Empty;
    public string Hash { get; init; } = string.Empty;
    public string Scopes { get; init; } = string.Empty;
    public DateTimeOffset? ExpiresAt { get; init; }
    public DateTimeOffset? RevokedAt { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset? UpdatedAt { get; init; }
    public DateTimeOffset? LastUsedAt { get; init; }
    public string? Name { get; init; }
    public string? CreatedBy { get; init; }
    public string? LastUsedIp { get; init; }
    public string? LastUsedUserAgent { get; init; }

    public ApiKeyRecord ToRecord()
    {
        return new ApiKeyRecord(
            Id,
            App,
            Env,
            PublicKey,
            Hash,
            ScopeJsonSerializer.Deserialize(Scopes),
            ExpiresAt,
            RevokedAt,
            CreatedAt,
            UpdatedAt,
            LastUsedAt,
            Name,
            CreatedBy,
            LastUsedIp,
            LastUsedUserAgent);
    }
}

internal static class ScopeJsonSerializer
{
    public static string Serialize(IReadOnlyCollection<string> scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        return JsonSerializer.Serialize(scopes);
    }

    public static IReadOnlyCollection<string> Deserialize(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);

        var scopes = JsonSerializer.Deserialize<string[]>(json);
        if (scopes is null)
        {
            throw new InvalidOperationException("Stored scopes JSON could not be deserialized.");
        }

        return scopes;
    }
}

internal sealed record ApiKeySqlStatements(
    string FindByPublicKey,
    string FindById,
    string Create,
    string PublicKeyExists,
    string MarkUsed,
    string Revoke);

internal static class ApiKeySqlStatementFactory
{
    public static ApiKeySqlStatements Create(ApiKeySqlDialect dialect)
    {
        return dialect switch
        {
            ApiKeySqlDialect.MySql => new ApiKeySqlStatements(
                """
                SELECT
                    id,
                    app,
                    env,
                    public_key AS PublicKey,
                    hash,
                    CAST(scopes AS CHAR) AS Scopes,
                    expires_at AS ExpiresAt,
                    revoked_at AS RevokedAt,
                    created_at AS CreatedAt,
                    updated_at AS UpdatedAt,
                    last_used_at AS LastUsedAt,
                    name AS Name,
                    created_by AS CreatedBy,
                    last_used_ip AS LastUsedIp,
                    last_used_user_agent AS LastUsedUserAgent
                FROM api_keys
                WHERE public_key = @PublicKey
                LIMIT 1;
                """,
                """
                SELECT
                    id,
                    app,
                    env,
                    public_key AS PublicKey,
                    hash,
                    CAST(scopes AS CHAR) AS Scopes,
                    expires_at AS ExpiresAt,
                    revoked_at AS RevokedAt,
                    created_at AS CreatedAt,
                    updated_at AS UpdatedAt,
                    last_used_at AS LastUsedAt,
                    name AS Name,
                    created_by AS CreatedBy,
                    last_used_ip AS LastUsedIp,
                    last_used_user_agent AS LastUsedUserAgent
                FROM api_keys
                WHERE id = @Id
                LIMIT 1;
                """,
                """
                INSERT INTO api_keys (
                    app, env, public_key, hash, scopes, expires_at, revoked_at,
                    created_at, updated_at, last_used_at, name, created_by,
                    last_used_ip, last_used_user_agent
                ) VALUES (
                    @App, @Env, @PublicKey, @Hash, @Scopes, @ExpiresAt, @RevokedAt,
                    @CreatedAt, @UpdatedAt, @LastUsedAt, @Name, @CreatedBy,
                    @LastUsedIp, @LastUsedUserAgent
                );

                SELECT LAST_INSERT_ID();
                """,
                """
                SELECT 1
                FROM api_keys
                WHERE public_key = @PublicKey
                LIMIT 1;
                """,
                """
                UPDATE api_keys
                SET
                    last_used_at = @UsedAt,
                    last_used_ip = @IpAddress,
                    last_used_user_agent = @UserAgent,
                    updated_at = @UsedAt
                WHERE id = @Id;
                """,
                """
                UPDATE api_keys
                SET
                    revoked_at = @RevokedAt,
                    updated_at = @RevokedAt
                WHERE public_key = @PublicKey
                  AND revoked_at IS NULL;
                """),
            ApiKeySqlDialect.PostgreSql => new ApiKeySqlStatements(
                """
                SELECT
                    id,
                    app,
                    env,
                    public_key AS "PublicKey",
                    hash,
                    scopes::text AS "Scopes",
                    expires_at AS "ExpiresAt",
                    revoked_at AS "RevokedAt",
                    created_at AS "CreatedAt",
                    updated_at AS "UpdatedAt",
                    last_used_at AS "LastUsedAt",
                    name AS "Name",
                    created_by AS "CreatedBy",
                    last_used_ip AS "LastUsedIp",
                    last_used_user_agent AS "LastUsedUserAgent"
                FROM api_keys
                WHERE public_key = @PublicKey
                LIMIT 1;
                """,
                """
                SELECT
                    id,
                    app,
                    env,
                    public_key AS "PublicKey",
                    hash,
                    scopes::text AS "Scopes",
                    expires_at AS "ExpiresAt",
                    revoked_at AS "RevokedAt",
                    created_at AS "CreatedAt",
                    updated_at AS "UpdatedAt",
                    last_used_at AS "LastUsedAt",
                    name AS "Name",
                    created_by AS "CreatedBy",
                    last_used_ip AS "LastUsedIp",
                    last_used_user_agent AS "LastUsedUserAgent"
                FROM api_keys
                WHERE id = @Id
                LIMIT 1;
                """,
                """
                INSERT INTO api_keys (
                    app, env, public_key, hash, scopes, expires_at, revoked_at,
                    created_at, updated_at, last_used_at, name, created_by,
                    last_used_ip, last_used_user_agent
                ) VALUES (
                    @App, @Env, @PublicKey, @Hash, CAST(@Scopes AS jsonb), @ExpiresAt, @RevokedAt,
                    @CreatedAt, @UpdatedAt, @LastUsedAt, @Name, @CreatedBy,
                    @LastUsedIp, @LastUsedUserAgent
                )
                RETURNING id;
                """,
                """
                SELECT 1
                FROM api_keys
                WHERE public_key = @PublicKey
                LIMIT 1;
                """,
                """
                UPDATE api_keys
                SET
                    last_used_at = @UsedAt,
                    last_used_ip = @IpAddress,
                    last_used_user_agent = @UserAgent,
                    updated_at = @UsedAt
                WHERE id = @Id;
                """,
                """
                UPDATE api_keys
                SET
                    revoked_at = @RevokedAt,
                    updated_at = @RevokedAt
                WHERE public_key = @PublicKey
                  AND revoked_at IS NULL;
                """),
            _ => throw new ArgumentOutOfRangeException(nameof(dialect))
        };
    }
}

public sealed class DefaultApiKeyDbConnectionFactory(IOptions<ApiKeyStoreOptions> options) : IApiKeyDbConnectionFactory
{
    private readonly ApiKeyStoreOptions _options = options?.Value ?? throw new ArgumentNullException(nameof(options));

    public async ValueTask<DbConnection> OpenConnectionAsync(CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_options.ConnectionString))
        {
            throw new InvalidOperationException("ApiKeys:ConnectionString must be configured.");
        }

        DbConnection connection = _options.Dialect switch
        {
            ApiKeySqlDialect.MySql => new MySqlConnection(_options.ConnectionString),
            ApiKeySqlDialect.PostgreSql => new NpgsqlConnection(_options.ConnectionString),
            _ => throw new ArgumentOutOfRangeException()
        };

        await connection.OpenAsync(cancellationToken);
        return connection;
    }
}

public sealed class ApiKeyStore : IApiKeyStore
{
    private readonly IApiKeyDbConnectionFactory _connectionFactory;
    private readonly ApiKeySqlStatements _sql;
    private readonly int _commandTimeoutSeconds;

    public ApiKeyStore(
        IApiKeyDbConnectionFactory connectionFactory,
        IOptions<ApiKeyStoreOptions> options)
    {
        ArgumentNullException.ThrowIfNull(connectionFactory);
        ArgumentNullException.ThrowIfNull(options);

        _connectionFactory = connectionFactory;
        var value = options.Value;
        if (value.CommandTimeoutSeconds <= 0)
        {
            throw new InvalidOperationException("ApiKeys:CommandTimeoutSeconds must be greater than zero.");
        }

        _commandTimeoutSeconds = value.CommandTimeoutSeconds;
        _sql = ApiKeySqlStatementFactory.Create(value.Dialect);
    }

    public async Task<ApiKeyRecord?> FindByPublicKeyAsync(string publicKey, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken);
            var command = CreateCommand(_sql.FindByPublicKey, new { PublicKey = publicKey }, cancellationToken);
            var row = await connection.QuerySingleOrDefaultAsync<ApiKeyRow>(command);
            return row?.ToRecord();
        }
        catch (Exception ex) when (ShouldWrapAvailability(ex))
        {
            throw new ApiKeyStoreUnavailableException("API key store lookup unavailable.", ex);
        }
    }

    public async Task<ApiKeyRecord> CreateAsync(ApiKeyRecord record, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);

        try
        {
            await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken);
            var parameters = ToParameters(record);
            var createCommand = CreateCommand(_sql.Create, parameters, cancellationToken);
            var id = await connection.ExecuteScalarAsync<long>(createCommand);

            var findCommand = CreateCommand(_sql.FindById, new { Id = id }, cancellationToken);
            var row = await connection.QuerySingleAsync<ApiKeyRow>(findCommand);
            return row.ToRecord();
        }
        catch (Exception ex) when (ShouldWrapAvailability(ex))
        {
            throw new ApiKeyStoreUnavailableException("API key store create unavailable.", ex);
        }
    }

    public async Task<bool> PublicKeyExistsAsync(string publicKey, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken);
            var command = CreateCommand(_sql.PublicKeyExists, new { PublicKey = publicKey }, cancellationToken);
            var result = await connection.ExecuteScalarAsync<int?>(command);
            return result.HasValue;
        }
        catch (Exception ex) when (ShouldWrapAvailability(ex))
        {
            throw new ApiKeyStoreUnavailableException("API key store exists check unavailable.", ex);
        }
    }

    public async Task MarkUsedAsync(long id, DateTimeOffset usedAt, string? ipAddress, string? userAgent, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken);
            var command = CreateCommand(_sql.MarkUsed, new { Id = id, UsedAt = usedAt, IpAddress = ipAddress, UserAgent = userAgent }, cancellationToken);
            await connection.ExecuteAsync(command);
        }
        catch (Exception ex) when (ShouldWrapAvailability(ex))
        {
            throw new ApiKeyStoreUnavailableException("API key store mark-used unavailable.", ex);
        }
    }

    public async Task RevokeAsync(string publicKey, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken);
            var command = CreateCommand(_sql.Revoke, new { PublicKey = publicKey, RevokedAt = revokedAt }, cancellationToken);
            await connection.ExecuteAsync(command);
        }
        catch (Exception ex) when (ShouldWrapAvailability(ex))
        {
            throw new ApiKeyStoreUnavailableException("API key store revoke unavailable.", ex);
        }
    }

    internal static bool ShouldWrapAvailability(Exception exception) =>
        exception is TimeoutException or DbException;

    private CommandDefinition CreateCommand(string sql, object parameters, CancellationToken cancellationToken) =>
        new(sql, parameters, commandTimeout: _commandTimeoutSeconds, cancellationToken: cancellationToken);

    private static object ToParameters(ApiKeyRecord record)
    {
        return new
        {
            record.App,
            record.Env,
            record.PublicKey,
            record.Hash,
            Scopes = ScopeJsonSerializer.Serialize(record.Scopes),
            record.ExpiresAt,
            record.RevokedAt,
            record.CreatedAt,
            record.UpdatedAt,
            record.LastUsedAt,
            record.Name,
            record.CreatedBy,
            record.LastUsedIp,
            record.LastUsedUserAgent
        };
    }
}

public static class ApiKeyGatewayDapperServiceCollectionExtensions
{
    public static IServiceCollection AddApiKeyGatewayDapper(
        this IServiceCollection services,
        Action<ApiKeyStoreOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);
        services.AddSingleton<IApiKeyDbConnectionFactory, DefaultApiKeyDbConnectionFactory>();
        services.AddSingleton<IApiKeyStore, ApiKeyStore>();
        return services;
    }
}
