namespace ApiKeyGateway.AspNetCore.Tests;

public sealed class ScaffoldTests
{
    [Fact]
    public void AspNetCoreProjectIsLoadable()
    {
        Assert.NotNull(typeof(ApiKeyGateway.AspNetCore.AssemblyMarker));
    }
}
