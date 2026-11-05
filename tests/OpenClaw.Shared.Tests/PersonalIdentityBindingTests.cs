using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text;
using System.Net.WebSockets;
using Org.BouncyCastle.Math.EC.Rfc8032;
using OpenClaw.TestSupport;
using Xunit;

namespace OpenClaw.Shared.Tests;

public sealed class PersonalIdentityBindingTests
{
    [Theory]
    [InlineData("bind", "[\"personal-identity\",\"tailscale\",\"bind\",\"binding-1\",\"1716480000000\"]")]
    [InlineData("use", "[\"personal-identity\",\"tailscale\",\"use\",\"binding-1\",\"person-1\",\"boot-1\",\"1716480000000\"]")]
    public void V4PayloadMatchesOwnerOrderedJsonGoldenVector(string phase, string intentJson)
    {
        using var directory = new TempDirectory("personal-v4-");
        var identity = new DeviceIdentity(directory.Path);
        identity.Initialize();
        var intent = new PersonalIdentityIntent(phase, "binding-1", 1716480000000,
            phase == "use" ? "person-1" : null, phase == "use" ? "boot-1" : null);
        var payload = identity.BuildConnectPayloadV4("nonce-1", 1716480000000, "gateway-client", "ui", "operator",
            ["operator.read", "operator.write"], "local-token", " WINDOWS ", " WINDOWS ", intent);
        // Independent TypeScript JSON.stringify vector, with only the generated device id substituted.
        Assert.Equal("[\"openclaw-device-auth\",\"v4\",\"" + identity.DeviceId +
            "\",\"gateway-client\",\"ui\",\"operator\",[\"operator.read\",\"operator.write\"],\"1716480000000\",\"local-token\",\"nonce-1\",\"windows\",\"windows\"," + intentJson + "]", payload);
        var envelope = ConnectEnvelopeBuilder.PrepareOperator(new("connect-1", "1", "operator",
            ["operator.read", "operator.write"], new TokenConnectCredential("local-token"), "nonce-1", 1716480000000,
            UseV2Signature: true, ClientIdentity: OperatorClientIdentity.Interactive, PersonalIdentity: _ => intent),
            new DeviceIdentityConnectEnvelopeSigner(identity));
        Assert.Equal(payload, envelope.SigningArguments.BuildPayload(identity));
        using var wire = JsonDocument.Parse(envelope.Serialize(envelope.Sign()));
        Assert.Equal(phase, wire.RootElement.GetProperty("params").GetProperty("personalIdentity").GetProperty("phase").GetString());
        Assert.Equal("local-token", wire.RootElement.GetProperty("params").GetProperty("auth").GetProperty("token").GetString());
    }

    [Theory]
    [InlineData("wss://127.0.0.1:18789", true)]
    [InlineData("wss://[::1]:18789", true)]
    [InlineData("wss://localhost:18789", true)]
    [InlineData("ws://127.0.0.1:18789", false)]
    [InlineData("wss://gateway.example.ts.net", false)]
    [InlineData("wss://local-token@localhost:18789", false)]
    [InlineData("wss://localhost:18789?token=private", false)]
    public void PrimaryRequiresCredentialFreeLocalWssUrl(string url, bool expected) =>
        Assert.Equal(expected, PersonalIdentityBinding.IsLocalWss(url));

    [Theory]
    [InlineData("binding-1", "person-1", "boot-1", "boot-1", 64, true)]
    [InlineData("wrong-binding", "person-1", "boot-1", "boot-1", 64, false)]
    [InlineData("binding-1", "gateway-owner", "boot-1", "boot-1", 64, false)]
    [InlineData("binding-1", "", "boot-1", "boot-1", 64, false)]
    [InlineData("binding-1", "person-1", "boot-1", "other-boot", 64, false)]
    [InlineData("binding-1", "person-1", "boot-1", "boot-1", 63, false)]
    public void BindingRejectsWrongAdmissionAndBoot(string bindingId, string profile, string gateway, string boot, int pinLength, bool expected)
    {
        using var hello = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            server = new { bootId = boot },
            personalIdentityBinding = new { mode = "personal-identity", provider = "tailscale", bindingId,
                profileId = profile, gatewayId = gateway, tlsFingerprint = new string('a', pinLength) }
        }));
        Assert.Equal(expected, PersonalIdentityBinding.TryRead(hello.RootElement, "binding-1", out _));
    }

    [Fact]
    public void AttestedPinAcceptsOnlyThatCertificate()
    {
        using var key = RSA.Create();
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var pin = Convert.ToHexString(SHA256.HashData(certificate.RawData)).ToLowerInvariant();
        Assert.True(new PersonalIdentityBinding("binding", "person", "boot", pin).ValidateCertificate(certificate));
        Assert.False(new PersonalIdentityBinding("binding", "person", "boot", new string('0', 64)).ValidateCertificate(certificate));
        Assert.False(new PersonalIdentityBinding("binding", "person", "boot", pin).ValidateCertificate(null));
    }

    [Theory]
    [InlineData("boot", "token", true)]
    [InlineData("boot", "device-token", true)]
    [InlineData("boot", "password", true)]
    [InlineData("other", "token", false)]
    [InlineData("boot", "tailscale", false)]
    [InlineData("boot", "bootstrap-token", false)]
    public void LocalUseRequiresBoundBootAndLocalCredentialMethod(string bootId, string method, bool expected)
    {
        using var hello = JsonDocument.Parse(JsonSerializer.Serialize(new { server = new { bootId }, auth = new { method } }));
        Assert.Equal(expected, new PersonalIdentityBinding("binding", "person", "boot", new string('a', 64)).AcceptsLocalHello(hello.RootElement));
    }

    [Fact]
    public void V4SignatureCoversDeviceScopesTimestampAndEveryBindingAuthorityField()
    {
        using var directory = new TempDirectory("personal-signature-");
        var identity = new DeviceIdentity(directory.Path);
        identity.Initialize();
        var intent = new PersonalIdentityIntent("use", "binding", 1716480000000, "person", "boot");
        var payload = identity.BuildConnectPayloadV4("nonce", 1716480000000, "gateway-client", "ui", "operator",
            ["operator.read"], "token", "windows", "windows", intent);
        var signature = Decode(identity.SignConnectPayloadV4("nonce", 1716480000000, "gateway-client", "ui", "operator",
            ["operator.read"], "token", "windows", "windows", intent));
        var key = Decode(identity.PublicKeyBase64Url);
        bool Verify(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            return Ed25519.Verify(signature, 0, key, 0, bytes, 0, bytes.Length);
        }
        Assert.True(Verify(payload));
        foreach (var change in new[] { (identity.DeviceId, "other-device"), ("operator.read", "operator.admin"),
            ("1716480000000", "1716480000001"), ("binding", "other-binding"), ("person\"", "other-person\""), ("boot", "other-boot") })
            Assert.False(Verify(payload.Replace(change.Item1, change.Item2, StringComparison.Ordinal)));
    }

    private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') +
        new string('=', (4 - value.Length % 4) % 4));

    [Theory]
    [InlineData("https://127.0.0.1:18789/gateway/avatar/person", true)]
    [InlineData("http://127.0.0.1:18789/gateway/avatar/person", false)]
    [InlineData("https://localhost:18789/gateway/avatar/person", false)]
    [InlineData("https://127.0.0.1:18790/gateway/avatar/person", false)]
    [InlineData("https://127.0.0.1:18789/other/avatar/person", false)]
    [InlineData("https://127.0.0.1:18789/gateway-evil/avatar/person", false)]
    public void LocalHttpPinCannotEscapeExactAuthorityAndGatewayBasePath(string request, bool expected) =>
        Assert.Equal(expected, new LocalGatewayTlsPin("primary", "wss://127.0.0.1:18789/gateway/", new string('a', 64))
            .MatchesHttpRequest(new Uri(request)));

    [Fact]
    public async Task SupersededTransportCannotPublishItsLateAdmission()
    {
        using var server = new ControlledUpgradeWebSocketServer(stalledUpgradeCount: 0);
        using var client = new AdmissionPublicationClient(server.WebSocketUrl);
        var old = client.ConnectAsync();
        await client.FirstPreparation.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await client.ConnectAsync().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(2, client.PublishedAdmission);
        client.ReleaseFirst.TrySetResult();
        await old.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(2, client.PublishedAdmission);
        Assert.True(client.Connected);
    }

    private sealed class AdmissionPublicationClient(string url) : WebSocketClientBase(url, "fixture-token")
    {
        private int _preparations;
        public int PublishedAdmission;
        public bool Connected => IsConnected;
        public TaskCompletionSource FirstPreparation = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseFirst = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override string ClientRole => "admission-fixture";
        protected override int ReceiveBufferSize => 8192;
        protected override bool ShouldAutoReconnect() => false;
        protected override Task ProcessMessageAsync(string json) => Task.CompletedTask;
        protected override async Task PrepareTransportAsync(ClientWebSocket socket, Uri uri, long generation, CancellationToken cancellationToken)
        {
            var value = Interlocked.Increment(ref _preparations);
            if (value == 1)
            {
                FirstPreparation.TrySetResult();
                await ReleaseFirst.Task.WaitAsync(cancellationToken);
            }
            if (!TryApplyToCurrentTransport(socket, generation, () => PublishedAdmission = value))
                throw new OperationCanceledException();
        }
    }
}
