using OpenClaw.Shared;
using Xunit;

namespace OpenClaw.Shared.Tests;

/// <summary>
/// Tests for the computed boolean properties on <see cref="ChannelStartResult"/>
/// and <see cref="ConfigPatchResult"/>. These contain pattern-matching logic
/// whose boundary conditions are not covered elsewhere.
/// </summary>
public class ChannelStartResultTests
{
    [Theory]
    [InlineData("unknown channel: whatsapp", true)]
    [InlineData("Unknown Channel: telegram", true)]  // case-insensitive
    [InlineData("UNKNOWN CHANNEL: signal", true)]
    public void LooksLikeMissingPlugin_IsTrueWhenErrorContainsUnknownChannel(string error, bool expected)
    {
        var result = new ChannelStartResult { Ok = false, Error = error };
        Assert.Equal(expected, result.LooksLikeMissingPlugin);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("channel is not configured")]
    [InlineData("plugin not found")]
    [InlineData("timeout connecting to channel")]
    public void LooksLikeMissingPlugin_IsFalseForOtherErrors(string? error)
    {
        var result = new ChannelStartResult { Ok = false, Error = error };
        Assert.False(result.LooksLikeMissingPlugin);
    }

    [Fact]
    public void LooksLikeMissingPlugin_IsFalseWhenOkTrueAndNoError()
    {
        var result = new ChannelStartResult { Ok = true, Started = true };
        Assert.False(result.LooksLikeMissingPlugin);
    }
}

/// <summary>
/// Tests for <see cref="WebLoginStartResult.LooksLikeMissingWebLoginProvider"/>,
/// which turns the gateway's "no web-login provider loaded" signal (issue #957)
/// into the actionable-recovery branch in the Channels linking flow.
/// </summary>
public class WebLoginStartResultTests
{
    [Theory]
    [InlineData("web login provider is not available")]        // exact string from issue #957
    [InlineData("Web Login Provider is not available")]         // case-insensitive
    [InlineData("WEB LOGIN PROVIDER IS NOT AVAILABLE")]
    [InlineData("web-login provider not loaded")]               // hyphenated variant
    public void LooksLikeMissingWebLoginProvider_IsTrueForProviderSignals(string error)
    {
        var result = new WebLoginStartResult { Error = error };
        Assert.True(result.LooksLikeMissingWebLoginProvider);
        // Provider-missing must NOT be misclassified as an unsupported method.
        Assert.False(result.LooksLikeWebLoginUnsupported);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("channel is not configured")]
    [InlineData("timeout waiting for web.login.start response")]
    [InlineData("gateway connection is not open")]
    [InlineData("rate limited")]
    [InlineData("unknown method: web.login.start")]             // unsupported method, not a missing provider
    public void LooksLikeMissingWebLoginProvider_IsFalseForOtherErrors(string? error)
    {
        var result = new WebLoginStartResult { Error = error };
        Assert.False(result.LooksLikeMissingWebLoginProvider);
    }

    [Theory]
    [InlineData("unknown method: web.login.start")]            // older gateway with no web.login RPC
    [InlineData("Unknown Method: web.login.start")]            // case-insensitive
    public void LooksLikeWebLoginUnsupported_IsTrueForUnknownMethod(string error)
    {
        var result = new WebLoginStartResult { Error = error };
        Assert.True(result.LooksLikeWebLoginUnsupported);
        // Unsupported-method must NOT be misclassified as a missing provider
        // (installing a plugin wouldn't add the RPC).
        Assert.False(result.LooksLikeMissingWebLoginProvider);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("web login provider is not available")]
    [InlineData("unknown method: usage.status")]              // different unknown method
    public void LooksLikeWebLoginUnsupported_IsFalseForOtherErrors(string? error)
    {
        var result = new WebLoginStartResult { Error = error };
        Assert.False(result.LooksLikeWebLoginUnsupported);
    }

    [Fact]
    public void DetectionFlags_AreFalseOnSuccess()
    {
        var result = new WebLoginStartResult { QrDataUrl = "data:image/png;base64,AAAA" };
        Assert.False(result.LooksLikeMissingWebLoginProvider);
        Assert.False(result.LooksLikeWebLoginUnsupported);
    }
}

public class ConfigPatchResultTests
{
    [Theory]
    [InlineData("baseHash is stale")]
    [InlineData("invalid baseHash value")]
    [InlineData("BaseHash mismatch")]          // case-insensitive
    public void LooksLikeStaleBaseHash_IsTrueWhenErrorMentionsBaseHash(string error)
    {
        var result = new ConfigPatchResult { Ok = false, Error = error };
        Assert.True(result.LooksLikeStaleBaseHash);
    }

    [Theory]
    [InlineData("stale config detected")]
    [InlineData("STALE: config was updated by another client")]
    public void LooksLikeStaleBaseHash_IsTrueWhenErrorMentionsStale(string error)
    {
        var result = new ConfigPatchResult { Ok = false, Error = error };
        Assert.True(result.LooksLikeStaleBaseHash);
    }

    [Theory]
    [InlineData("conflict detected in hash value")]
    [InlineData("write conflict: baseHash changed")]
    public void LooksLikeStaleBaseHash_IsTrueWhenConflictAndHashCombined(string error)
    {
        var result = new ConfigPatchResult { Ok = false, Error = error };
        Assert.True(result.LooksLikeStaleBaseHash);
    }

    [Theory]
    [InlineData("property 'conflict_mode' is invalid")]  // must NOT be treated as stale hash
    [InlineData("validation conflict on field 'mode'")]
    [InlineData("conflict in schema definition")]
    public void LooksLikeStaleBaseHash_IsFalseWhenConflictAlone(string error)
    {
        var result = new ConfigPatchResult { Ok = false, Error = error };
        Assert.False(result.LooksLikeStaleBaseHash);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("gateway rejected the patch")]
    [InlineData("permission denied")]
    public void LooksLikeStaleBaseHash_IsFalseForOtherErrors(string? error)
    {
        var result = new ConfigPatchResult { Ok = false, Error = error };
        Assert.False(result.LooksLikeStaleBaseHash);
    }

    [Fact]
    public void LooksLikeStaleBaseHash_IsFalseWhenOkTrue()
    {
        var result = new ConfigPatchResult { Ok = true };
        Assert.False(result.LooksLikeStaleBaseHash);
    }
}
