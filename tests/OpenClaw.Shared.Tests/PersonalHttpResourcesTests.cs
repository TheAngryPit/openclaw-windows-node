using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using OpenClaw.TestSupport;
using Xunit;

namespace OpenClaw.Shared.Tests;

public sealed class PersonalHttpResourcesTests
{
    [Theory]
    [InlineData(HttpStatusCode.OK, UserAvatarStatus.Ready)]
    [InlineData(HttpStatusCode.Unauthorized, UserAvatarStatus.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden, UserAvatarStatus.Unauthorized)]
    [InlineData(HttpStatusCode.Redirect, UserAvatarStatus.Failed)]
    public async Task PersonalAvatarUsesExactServeOriginCurrentProfileAndNoBearerFallback(HttpStatusCode status, UserAvatarStatus expected)
    {
        using var identity = new TempDirectory("personal-http-");
        await using var peer = new PersonalGatewayProtocolFixture();
        using var handler = new RecordingHandler(_ => Task.FromResult(Image(status)));
        using var client = peer.CreateClient(identity.Path, handler);
        await ReadyAsync(peer, client);
        var avatar = client.ResolveUserAvatarAsync("person-42", "7");
        await SelfAsync(peer);
        Assert.Equal(expected, (await avatar).Status);
        var request = Assert.Single(handler.Requests);
        Assert.Equal("https://protocol.example.ts.net/api/users/person-42/avatar?v=7", request.Uri.AbsoluteUri);
        AssertPersonalHeaders(request);
        Assert.Equal(UserAvatarStatus.Cancelled, (await client.ResolveUserAvatarAsync("gateway-owner", null)).Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task PersonalLegacyMediaUsesServeReadThenOnlyReturnedSourceBoundTicket()
    {
        using var identity = new TempDirectory("personal-legacy-");
        await using var peer = new PersonalGatewayProtocolFixture();
        var count = 0;
        using var handler = new RecordingHandler(_ => Task.FromResult(Interlocked.Increment(ref count) == 1
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(
                """{"available":true,"mimeType":"image/png","sizeBytes":3,"mediaTicket":"fixture-ticket"}""", Encoding.UTF8, "application/json") }
            : Image(HttpStatusCode.OK)));
        using var client = peer.CreateClient(identity.Path, handler);
        await ReadyAsync(peer, client);
        var media = client.ResolveAssistantMediaAsync("main", new ChatMediaContentInfo
        {
            Kind = ChatMediaContentKind.Image, Source = ChatMediaContentSource.LegacyDirective,
            GatewaySource = "/fixture/banner.png"
        });
        await SelfAsync(peer);
        Assert.Equal(AssistantMediaResolutionStatus.Ready, (await media).Status);
        Assert.Equal(2, handler.Requests.Count);
        Assert.All(handler.Requests, AssertPersonalHeaders);
        Assert.All(handler.Requests, request => Assert.Equal("protocol.example.ts.net", request.Uri.Host));
        Assert.Contains("meta=1", handler.Requests[0].Uri.Query, StringComparison.Ordinal);
        Assert.Contains("mediaTicket=fixture-ticket", handler.Requests[1].Uri.Query, StringComparison.Ordinal);
        Assert.Contains("source=%2Ffixture%2Fbanner.png", handler.Requests[1].Uri.Query, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProfileInvalidationDuringHttpCannotPublishOldAvatar()
    {
        using var identity = new TempDirectory("personal-http-retire-");
        await using var peer = new PersonalGatewayProtocolFixture();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var handler = new RecordingHandler(async _ =>
        {
            entered.TrySetResult();
            await release.Task;
            return Image(HttpStatusCode.OK);
        });
        using var client = peer.CreateClient(identity.Path, handler);
        await ReadyAsync(peer, client);
        var changed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        client.SelfProfileChanged += (_, _) => changed.TrySetResult();
        var avatar = client.ResolveUserAvatarAsync("person-42", null);
        await SelfAsync(peer);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await peer.ProfileChangedAsync();
        await changed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        release.TrySetResult();
        Assert.Equal(UserAvatarStatus.Cancelled, (await avatar).Status);
        Assert.False(client.IsConnectedToGateway);
    }

    [Theory]
    [InlineData("/api/chat/media/outgoing/main/image/full?mediaTicket=fixture-ticket", true)]
    [InlineData("/api/chat/media/outgoing/main/image/full", false)]
    [InlineData("https://other.example/api/chat/media/outgoing/main/image/full?mediaTicket=fixture-ticket", false)]
    public async Task PersonalStructuredMediaUsesOnlyCurrentSocketArtifactTicket(string url, bool expected)
    {
        using var identity = new TempDirectory("personal-ticket-");
        await using var peer = new PersonalGatewayProtocolFixture();
        using var handler = new RecordingHandler(_ => Task.FromResult(Image(HttpStatusCode.OK)));
        using var client = peer.CreateClient(identity.Path, handler);
        await ReadyAsync(peer, client);
        var media = client.ResolveAssistantMediaAsync("main", new ChatMediaContentInfo
        {
            Kind = ChatMediaContentKind.Image, Source = ChatMediaContentSource.Structured, ArtifactId = "fixture-artifact"
        });
        var rpc = await peer.ReceiveAsync();
        Assert.Equal("artifacts.download", rpc.GetProperty("method").GetString());
        await peer.SendAsync(new { type = "res", id = rpc.GetProperty("id").GetString(), ok = true,
            payload = new { artifact = new { type = "image", mimeType = "image/png", sizeBytes = 3 }, url } });
        Assert.Equal(expected ? AssistantMediaResolutionStatus.Ready : AssistantMediaResolutionStatus.Unavailable, (await media).Status);
        Assert.Equal(expected ? 1 : 0, handler.Requests.Count);
        Assert.All(handler.Requests, request => Assert.Null(request.Authorization));
    }

    private static async Task ReadyAsync(PersonalGatewayProtocolFixture peer, OpenClawGatewayClient client)
    {
        var hello = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        client.HandshakeSucceeded += (_, _) => hello.TrySetResult();
        await client.ConnectAsync();
        await peer.ChallengeAsync();
        await peer.HelloAsync(await peer.ReceiveAsync());
        await hello.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var epoch = client.PersonalHandshakeConnectionEpoch!.Value;
        var self = client.ReadPersonalIdentityAsync(epoch);
        await SelfAsync(peer);
        await self;
        client.VerifyPersonalIdentity("person-42", epoch);
    }

    private static async Task SelfAsync(PersonalGatewayProtocolFixture peer)
    {
        var self = await peer.ReceiveAsync();
        Assert.Equal("users.self", self.GetProperty("method").GetString());
        await peer.SelfAsync(self);
    }

    private static void AssertPersonalHeaders(Request request)
    {
        Assert.Null(request.Authorization);
        Assert.Equal("https://protocol.example.ts.net", request.Origin);
        Assert.Equal("operator.read,operator.write", request.Scopes);
        Assert.False(request.ForwardedIdentity);
    }

    private static HttpResponseMessage Image(HttpStatusCode status)
    {
        var response = new HttpResponseMessage(status) { Content = new ByteArrayContent([1, 2, 3]) };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("image/png");
        return response;
    }

    private sealed record Request(Uri Uri, string? Authorization, string? Origin, string? Scopes, bool ForwardedIdentity);
    private sealed class RecordingHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public List<Request> Requests { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string? Header(string name) => request.Headers.TryGetValues(name, out var values) ? string.Join(",", values) : null;
            Requests.Add(new(request.RequestUri!, request.Headers.Authorization?.ToString(), Header("Origin"), Header("x-openclaw-scopes"),
                request.Headers.Any(header => header.Key.StartsWith("Tailscale-", StringComparison.OrdinalIgnoreCase) ||
                    header.Key.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase) || header.Key is "Cookie" or "Sec-Fetch-Site")));
            return respond(request);
        }
    }
}
