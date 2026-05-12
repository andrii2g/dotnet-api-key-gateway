namespace ApiKeyGateway.Dapper.Tests;

public sealed class ScaffoldTests
{
    [Fact]
    public void DapperProjectIsLoadable()
    {
        Assert.NotNull(typeof(ApiKeyGateway.Dapper.AssemblyMarker));
    }
}
