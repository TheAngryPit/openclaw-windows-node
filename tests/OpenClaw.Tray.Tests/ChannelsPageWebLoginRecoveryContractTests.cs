using System.Linq;

namespace OpenClaw.Tray.Tests;

/// <summary>
/// Source-contract tests for the WhatsApp/QR linking recovery flow (issue #957).
///
/// The Channels linking UI is WinUI code-behind that can't be unit-tested without
/// a UI thread, so — following the ChannelsPageDiscordConfigContractTests
/// convention — these assert the source wiring: the linking flow must branch on
/// the gateway's "no web-login provider loaded" signal and surface actionable
/// recovery (a copyable gateway-host install command) instead of leaking the
/// relayed internal exception.
/// </summary>
public sealed class ChannelsPageWebLoginRecoveryContractTests
{
    private static string ReadChannelsPage() =>
        Read("src", "OpenClaw.Tray.WinUI", "Pages", "ChannelsPage.xaml.cs");

    [Fact]
    public void LinkingFlow_BranchesOnMissingWebLoginProvider()
    {
        var source = ReadChannelsPage();

        // The page must consult both detection properties rather than only
        // echoing the raw gateway error — provider-missing and unsupported-method
        // get different, correct recovery guidance.
        Assert.Contains("LooksLikeMissingWebLoginProvider", source, StringComparison.Ordinal);
        Assert.Contains("LooksLikeWebLoginUnsupported", source, StringComparison.Ordinal);
    }

    [Fact]
    public void LinkingFlow_ShowsActionableRecoveryCommand()
    {
        var source = ReadChannelsPage();

        // Recovery must offer the exact gateway-host command to load the provider,
        // mirroring the existing missing-plugin recovery affordance.
        Assert.Contains("openclaw plugins install @openclaw/", source, StringComparison.Ordinal);

        // Recovery must be a distinct, copyable affordance with a Copy button.
        Assert.Contains("recoveryPanel", source, StringComparison.Ordinal);
        Assert.Contains("Clipboard.SetContent", source, StringComparison.Ordinal);
    }

    [Fact]
    public void LinkingFlow_DoesNotSurfaceRawStackTraceAsHeadline()
    {
        var source = ReadChannelsPage();

        // The missing-provider branch must not reuse the generic
        // "returned an error — see details below" headline; it gets its own
        // "isn't available on this gateway yet" actionable message.
        Assert.Contains("isn't available on this gateway yet", source, StringComparison.Ordinal);
    }

    [Fact]
    public void GatewayClient_DoesNotLeakStackTraceIntoWebLoginRawResponse()
    {
        // The relayed internal exception (with internal CI build paths) must not
        // be dumped into the user-facing WebLoginStartResult/WaitResult. Both
        // catch blocks assigned RawResponse = ex.ToString() (issue #957); the fix
        // surfaces ex.Message instead. Scope the assertion to the web-login
        // region so unrelated methods (and the fix's explanatory comments) don't
        // affect the result.
        var source = Read("src", "OpenClaw.Shared", "OpenClawGatewayClient.cs");
        var region = ExtractWebLoginRegion(source);

        Assert.DoesNotContain("RawResponse = ex.ToString()", region, StringComparison.Ordinal);
    }

    /// <summary>
    /// Slice covering both web-login methods: from the WebLoginStartAsync
    /// signature to the start of the next unrelated method. Keeps the leak
    /// assertion scoped without a full C# parser.
    /// </summary>
    private static string ExtractWebLoginRegion(string source)
    {
        var start = source.IndexOf("WebLoginStartAsync(bool force", StringComparison.Ordinal);
        Assert.True(start >= 0, "Could not find WebLoginStartAsync in OpenClawGatewayClient.cs");

        var end = source.IndexOf("SendConnectMessageAsync", start, StringComparison.Ordinal);
        if (end < 0) end = source.Length;

        return source.Substring(start, end - start);
    }

    private static string Read(params string[] parts)
        => File.ReadAllText(Path.Combine(new[] { TestRepositoryPaths.GetRepositoryRoot() }.Concat(parts).ToArray()));
}
