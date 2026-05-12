namespace ApiKeyGateway.Tests;

public sealed class ScaffoldTests
{
    [Fact]
    public void CoreProjectIsLoadable()
    {
        Assert.NotNull(typeof(ApiKeyGateway.AssemblyMarker));
    }
}
