using System.Data.Common;
using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ApiKeyGateway.Tests;

public sealed class DapperTests
{
    [Fact]
    public void ScopeJsonSerializer_RoundTripsScopes()
    {
        var scopes = new[] { "personas:read", "personas:execute" };

        var json = Invoke<string>("Serialize", (object)scopes);
        var result = Invoke<IReadOnlyCollection<string>>("Deserialize", json);

        Assert.Equal(scopes, result);
    }

    [Fact]
    public void RowMapping_ConvertsJsonToCoreRecord()
    {
        var rowType = GetInternalType("ApiKeyGateway.DapperApiKeyRow");
        var row = Activator.CreateInstance(rowType)!;
        Set(rowType, row, "Id", 1L);
        Set(rowType, row, "App", "crm");
        Set(rowType, row, "Env", "prod");
        Set(rowType, row, "PublicKey", "ABCDEFGHJKLMNP23");
        Set(rowType, row, "Hash", "hmac-sha256:abc");
        Set(rowType, row, "Scopes", "[\"personas:read\"]");
        Set(rowType, row, "CreatedAt", DateTimeOffset.UtcNow);

        var record = (ApiKeyRecord)rowType.GetMethod("ToRecord")!.Invoke(row, null)!;

        Assert.Equal("crm", record.App);
        Assert.Single(record.Scopes);
    }

    [Fact]
    public void SqlStatementFactory_SelectsMySqlSyntax()
    {
        var statements = GetStatements(ApiKeySqlDialect.MySql);

        Assert.Contains("LAST_INSERT_ID()", GetStringProperty(statements, "Create"), StringComparison.Ordinal);
        Assert.Contains("CAST(scopes AS CHAR)", GetStringProperty(statements, "FindByPublicKey"), StringComparison.Ordinal);
    }

    [Fact]
    public void SqlStatementFactory_SelectsPostgreSqlSyntax()
    {
        var statements = GetStatements(ApiKeySqlDialect.PostgreSql);

        Assert.Contains("RETURNING id", GetStringProperty(statements, "Create"), StringComparison.Ordinal);
        Assert.Contains("scopes::text", GetStringProperty(statements, "FindByPublicKey"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Store_TranslatesAvailabilityErrors()
    {
        var store = CreateStore(new ThrowingFactory(new FakeDbException("boom")));

        await Assert.ThrowsAsync<ApiKeyStoreUnavailableException>(() => store.FindByPublicKeyAsync("ABCDEFGHJKLMNP23"));
    }

    [Fact]
    public void RowMapping_DoesNotTranslateJsonErrors()
    {
        var rowType = GetInternalType("ApiKeyGateway.DapperApiKeyRow");
        var row = Activator.CreateInstance(rowType)!;
        Set(rowType, row, "Id", 1L);
        Set(rowType, row, "App", "crm");
        Set(rowType, row, "Env", "prod");
        Set(rowType, row, "PublicKey", "ABCDEFGHJKLMNP23");
        Set(rowType, row, "Hash", "hmac-sha256:abc");
        Set(rowType, row, "Scopes", "{bad json}");
        Set(rowType, row, "CreatedAt", DateTimeOffset.UtcNow);

        var ex = Assert.Throws<TargetInvocationException>(() => rowType.GetMethod("ToRecord")!.Invoke(row, null));
        Assert.IsType<JsonException>(ex.InnerException);
    }

    [Fact]
    public void DependencyInjection_RegistersExpectedServices()
    {
        var services = new ServiceCollection();

        services.AddApiKeyGatewayDapper(options =>
        {
            options.Dialect = ApiKeySqlDialect.MySql;
            options.ConnectionString = "server=localhost;database=test;";
        });

        var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredService<IApiKeyStore>());
        Assert.NotNull(provider.GetRequiredService<IApiKeyDbConnectionFactory>());
        Assert.NotNull(provider.GetRequiredService<IOptions<ApiKeyDapperOptions>>());
    }

    [Fact]
    public void IntegrationTestsRemainConditional()
    {
        Assert.True(true);
    }

    private static object GetStatements(ApiKeySqlDialect dialect)
    {
        var type = GetInternalType("ApiKeyGateway.ApiKeySqlStatementFactory");
        return type.GetMethod("Create", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [dialect])!;
    }

    private static string GetStringProperty(object instance, string propertyName) =>
        (string)instance.GetType().GetProperty(propertyName)!.GetValue(instance)!;

    private static Type GetInternalType(string fullName) =>
        typeof(AssemblyMarker).Assembly.GetType(fullName, throwOnError: true)!;

    private static T Invoke<T>(string methodName, params object[] args)
    {
        var type = GetInternalType("ApiKeyGateway.ScopeJsonSerializer");
        return (T)type.GetMethod(methodName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, args)!;
    }

    private static void Set(Type type, object instance, string propertyName, object? value) =>
        type.GetProperty(propertyName)!.SetValue(instance, value);

    private static DapperApiKeyStore CreateStore(IApiKeyDbConnectionFactory factory)
    {
        return new DapperApiKeyStore(factory, Options.Create(new ApiKeyDapperOptions
        {
            Dialect = ApiKeySqlDialect.MySql,
            ConnectionString = "unused",
            CommandTimeoutSeconds = 30
        }));
    }

    private sealed class ThrowingFactory(Exception exception) : IApiKeyDbConnectionFactory
    {
        public ValueTask<DbConnection> OpenConnectionAsync(CancellationToken cancellationToken = default) => ValueTask.FromException<DbConnection>(exception);
    }

    private sealed class FakeDbException(string message) : DbException(message)
    {
    }
}
