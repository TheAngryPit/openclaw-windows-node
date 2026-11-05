using OpenClaw.Shared;
using OpenClaw.Connection;
using OpenClaw.TestSupport;

namespace OpenClaw.Connection.Tests;

public class CredentialResolverTests
{
    private readonly MockDeviceIdentityReader _mockReader = new();
    private readonly CredentialResolver _resolver;

    public CredentialResolverTests()
    {
        _resolver = new CredentialResolver(_mockReader);
    }

    [Fact]
    public void PersonalOperatorIgnoresStoredOperatorCredentialsAndPreservesNodeResolution()
    {
        var record = new GatewayRecord { Id = "personal", Url = "wss://fixture.example.ts.net",
            OperatorAuthentication = OperatorAuthenticationMode.PersonalTailscale,
            SharedGatewayToken = "shared", BootstrapToken = "bootstrap" };
        _mockReader.OperatorReadResult = DeviceTokenReadResult.Corrupt("must not be used");
        _mockReader.NodeToken = "node-token";
        var personal = Assert.IsType<GatewayCredential>(_resolver.ResolveOperator(record, "/fixture"));
        Assert.Empty(personal.Token);
        Assert.Equal(OperatorAuthenticationMode.PersonalTailscale, personal.OperatorAuthentication);
        Assert.Equal("node-token", _resolver.ResolveNode(record, "/fixture")!.Token);
        Assert.Equal("shared", record.SharedGatewayToken);
    }

    // ─── Operator resolution ───

    [Fact]
    public void LocalPersonalSelectionPreservesManagedRecordAndIndependentNodeCredentials()
    {
        var original = new GatewayRecord { Id = "primary", Url = "wss://127.0.0.1:18789",
            IsLocal = true, SetupManagedDistroName = "OpenClawGateway", RequiresV2Signature = true,
            LocalTlsPin = new("primary", "wss://127.0.0.1:18789", new string('a', 64)),
            SharedGatewayToken = "local-shared", BootstrapToken = "bootstrap" };
        var personal = (new GatewayRecord { Id = original.Id, Url = original.Url,
            OperatorAuthentication = OperatorAuthenticationMode.PersonalTailscaleLocal,
            PersonalIdentityServeUrl = "wss://fixture.example.ts.net", SharedGatewayToken = original.SharedGatewayToken,
            BootstrapToken = original.BootstrapToken }).PreserveAdvancedFields(original);
        _mockReader.OperatorToken = "operator-device";
        _mockReader.NodeToken = "node-device";
        var result = _resolver.ResolveOperator(personal, "/fixture")!;
        Assert.Equal("operator-device", result.Token);
        Assert.Equal(OperatorAuthenticationMode.PersonalTailscaleLocal, result.OperatorAuthentication);
        Assert.Equal("node-device", _resolver.ResolveNode(personal, "/fixture")!.Token);
        Assert.Equal(original.Url, personal.Url);
        Assert.Equal(original.Id, personal.Id);
        Assert.Equal(original.SetupManagedDistroName, personal.SetupManagedDistroName);
        Assert.True(personal.IsLocal);
        Assert.True(personal.RequiresV2Signature);
        Assert.Equal(original.LocalTlsPin, personal.LocalTlsPin);
        Assert.Equal(original.LocalTlsPin, _resolver.ResolveNode(personal, "/fixture")!.LocalTlsPin);
        var rejected = personal with { Url = "ws://127.0.0.1:18789" };
        Assert.Null(_resolver.ResolveOperator(rejected, "/fixture"));
        Assert.Null(_resolver.ResolveNode(rejected, "/fixture"));
        Assert.Null(_resolver.ResolveNode(personal with { LocalTlsPin = null }, "/fixture"));
        Assert.Null(_resolver.ResolveNode(personal with { Id = "different-record" }, "/fixture"));
        Assert.Null(_resolver.ResolveNode(personal with { Url = "wss://127.0.0.1:18790" }, "/fixture"));
        Assert.Equal(original.LocalTlsPin, rejected.LocalTlsPin);
        _mockReader.OperatorToken = null;
        Assert.Null(_resolver.ResolveOperator(personal with { SharedGatewayToken = null }, "/missing"));
    }

    [Fact]
    public void ExplicitTlsUpgradePreservesManagedOwnershipAndCredentialsAndCannotRepointRecord()
    {
        var original = new GatewayRecord { Id = "primary", Url = "ws://127.0.0.1:18789", IsLocal = true,
            SetupManagedDistroName = "OpenClawGateway", SharedGatewayToken = "shared", BootstrapToken = "bootstrap",
            RequiresV2Signature = true, BrowserControlPort = 19200 };
        var pin = new LocalGatewayTlsPin("primary", "wss://127.0.0.1:18789", new string('a', 64));
        var upgraded = GatewayRecordEditing.UpgradeManagedLocalTls(original, pin);
        Assert.Equal(original with { Url = pin.GatewayUrl, LocalTlsPin = pin }, upgraded);
        Assert.Throws<InvalidOperationException>(() => GatewayRecordEditing.UpgradeManagedLocalTls(original,
            pin with { GatewayRecordId = "other" }));
        Assert.Throws<InvalidOperationException>(() => GatewayRecordEditing.UpgradeManagedLocalTls(original,
            pin with { GatewayUrl = "wss://127.0.0.1:18790" }));
        Assert.Throws<InvalidOperationException>(() => GatewayRecordEditing.UpgradeManagedLocalTls(original,
            pin with { GatewayUrl = "wss://localhost:18789" }));
        var editing = (new GatewayRecord { Id = upgraded.Id, Url = "wss://other.example", FriendlyName = "edited" })
            .PreserveAdvancedFields(upgraded);
        Assert.Equal(pin, editing.LocalTlsPin);
        Assert.Null(_resolver.ResolveNode(editing, "/fixture"));
    }

    [Fact]
    public void ExplicitTlsUpgradeAndPersonalSelectionRoundTripThroughRegistryWithoutChangingNodeCredentials()
    {
        using var directory = new TempDirectory("personal-tls-registry-");
        var registry = new GatewayRegistry(directory.Path);
        var original = new GatewayRecord { Id = "primary", Url = "ws://127.0.0.1:18789", IsLocal = true,
            SetupManagedDistroName = "OpenClawGateway", RequiresV2Signature = true,
            SharedGatewayToken = "synthetic-private-shared", BootstrapToken = "synthetic-private-bootstrap" };
        registry.AddOrUpdate(original);
        registry.SetActive(original.Id);
        registry.Save();
        var identity = new DeviceIdentity(registry.GetIdentityDirectory(original.Id));
        identity.Initialize();
        identity.StoreDeviceTokenWithScopes("synthetic-operator-device", ["operator.read"]);
        identity.StoreDeviceTokenForRole("node", "synthetic-node-device", []);
        var identityFile = Path.Combine(registry.GetIdentityDirectory(original.Id), "device-key-ed25519.json");
        var before = File.ReadAllBytes(identityFile);
        var pin = new LocalGatewayTlsPin(original.Id, "wss://127.0.0.1:18789", new string('a', 64));
        registry.UpdateAndSave(original.Id, current => GatewayRecordEditing.UpgradeManagedLocalTls(current, pin) with
        {
            OperatorAuthentication = OperatorAuthenticationMode.PersonalTailscaleLocal,
            PersonalIdentityServeUrl = "wss://fixture.example.ts.net"
        });
        var reloaded = new GatewayRegistry(directory.Path);
        reloaded.Load();
        Assert.Equal(original with { Url = pin.GatewayUrl, LocalTlsPin = pin,
            OperatorAuthentication = OperatorAuthenticationMode.PersonalTailscaleLocal,
            PersonalIdentityServeUrl = "wss://fixture.example.ts.net" }, reloaded.GetActive());
        Assert.Equal(before, File.ReadAllBytes(identityFile));
        var resolver = new CredentialResolver(new DeviceIdentityFileReader());
        Assert.Equal("synthetic-node-device", resolver.ResolveNode(reloaded.GetActive()!, reloaded.GetIdentityDirectory(original.Id))!.Token);
        Assert.Equal(pin, resolver.ResolveNode(reloaded.GetActive()!, reloaded.GetIdentityDirectory(original.Id))!.LocalTlsPin);
        var ordinary = resolver.ResolveOperator(reloaded.GetActive()! with { OperatorAuthentication = OperatorAuthenticationMode.GatewayCredential },
            reloaded.GetIdentityDirectory(original.Id))!;
        Assert.Equal(pin, ordinary.LocalTlsPin);
        Assert.Equal("wss://fixture.example.ts.net", ordinary.PersonalIdentityServeUrl);
    }

    [Fact]
    public void ResolveOperator_PrefersDeviceToken_OverSharedAndBootstrap()
    {
        var record = new GatewayRecord
        {
            Id = "gw-1",
            Url = "wss://test",
            SharedGatewayToken = "shared",
            BootstrapToken = "boot"
        };
        _mockReader.OperatorToken = "paired-tok";

        var result = _resolver.ResolveOperator(record, "/id");

        Assert.NotNull(result);
        Assert.Equal("paired-tok", result.Token);
        Assert.False(result.IsBootstrapToken);
        Assert.Equal(CredentialResolver.SourceDeviceToken, result.Source);
    }

    [Fact]
    public void ResolveOperator_FallsToSharedToken_WhenNoDeviceToken()
    {
        var record = new GatewayRecord
        {
            Id = "gw-1",
            Url = "wss://test",
            SharedGatewayToken = "shared",
            BootstrapToken = "boot"
        };
        _mockReader.OperatorToken = null;

        var result = _resolver.ResolveOperator(record, "/id");

        Assert.NotNull(result);
        Assert.Equal("shared", result.Token);
        Assert.False(result.IsBootstrapToken);
        Assert.Equal(CredentialResolver.SourceSharedGatewayToken, result.Source);
    }

    [Fact]
    public void ResolveOperatorDetailed_SharedTokenOnly_IsResolvedNotFallback()
    {
        var record = new GatewayRecord
        {
            Id = "gw-1",
            Url = "wss://test",
            SharedGatewayToken = "shared",
            BootstrapToken = "boot"
        };
        _mockReader.OperatorToken = null;

        var result = _resolver.ResolveOperatorDetailed(record, "/id");

        Assert.NotNull(result.Credential);
        Assert.Equal("shared", result.Credential!.Token);
        Assert.Equal(CredentialResolver.SourceSharedGatewayToken, result.Credential.Source);
        Assert.Equal(GatewayCredentialResolutionStatus.Resolved, result.Status);
        Assert.False(result.FallbackUsed);
        Assert.False(result.Credential.FallbackUsed);
    }

    [Fact]
    public void ResolveOperator_FallsToBootstrap_WhenNoDeviceOrShared()
    {
        var record = new GatewayRecord
        {
            Id = "gw-1",
            Url = "wss://test",
            BootstrapToken = "boot"
        };
        _mockReader.OperatorToken = null;

        var result = _resolver.ResolveOperator(record, "/id");

        Assert.NotNull(result);
        Assert.Equal("boot", result.Token);
        Assert.True(result.IsBootstrapToken);
        Assert.Equal(CredentialResolver.SourceBootstrapToken, result.Source);
    }

    [Fact]
    public void ResolveOperator_ReturnsNull_WhenNoCredentials()
    {
        var record = new GatewayRecord { Id = "gw-1", Url = "wss://test" };
        _mockReader.OperatorToken = null;

        var result = _resolver.ResolveOperator(record, "/id");

        Assert.Null(result);
    }

    [Fact]
    public void ResolveOperatorDetailed_ReturnsMissing_WhenNoCredentials()
    {
        var record = new GatewayRecord { Id = "gw-1", Url = "wss://test" };
        _mockReader.OperatorToken = null;

        var result = _resolver.ResolveOperatorDetailed(record, "/id");

        Assert.Null(result.Credential);
        Assert.Equal(GatewayCredentialResolutionStatus.Missing, result.Status);
    }

    [Fact]
    public void ResolveOperatorDetailed_ReturnsCorrupt_WhenStoredTokenFileIsInvalidAndNoFallbackExists()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "openclaw-corrupt-token-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            File.WriteAllText(Path.Combine(tempDir, "device-key-ed25519.json"), "{ broken json");
            var resolver = new CredentialResolver(DeviceIdentityFileReader.Instance);
            var record = new GatewayRecord { Id = "gw-1", Url = "wss://test" };

            var result = resolver.ResolveOperatorDetailed(record, tempDir);

            Assert.Null(result.Credential);
            Assert.Equal(GatewayCredentialResolutionStatus.Corrupt, result.Status);
            Assert.Contains("corrupt", result.Detail, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("null")]
    public void ResolveOperatorDetailed_ReturnsCorrupt_WhenStoredTokenFileHasWrongJsonShape(string json)
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "openclaw-wrong-shape-token-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            File.WriteAllText(Path.Combine(tempDir, "device-key-ed25519.json"), json);
            var resolver = new CredentialResolver(DeviceIdentityFileReader.Instance);
            var record = new GatewayRecord { Id = "gw-1", Url = "wss://test" };

            var result = resolver.ResolveOperatorDetailed(record, tempDir);

            Assert.Null(result.Credential);
            Assert.Equal(GatewayCredentialResolutionStatus.Corrupt, result.Status);
            Assert.Contains("not a JSON object", result.Detail, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void ResolveOperatorDetailed_FallsBack_WhenStoredTokenFileHasWrongJsonShapeAndSharedTokenExists()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "openclaw-wrong-shape-fallback-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            File.WriteAllText(Path.Combine(tempDir, "device-key-ed25519.json"), "[]");
            var resolver = new CredentialResolver(DeviceIdentityFileReader.Instance);
            var record = new GatewayRecord
            {
                Id = "gw-1",
                Url = "wss://test",
                SharedGatewayToken = "shared"
            };

            var result = resolver.ResolveOperatorDetailed(record, tempDir);

            Assert.NotNull(result.Credential);
            Assert.Equal("shared", result.Credential!.Token);
            Assert.Equal(GatewayCredentialResolutionStatus.FallbackUsed, result.Status);
            Assert.Equal(GatewayCredentialResolutionStatus.Corrupt, result.PrimaryStatus);
            Assert.True(result.FallbackUsed);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void ResolveOperatorDetailed_ReportsFallbackUsed_WhenStoredTokenIsCorruptAndSharedTokenExists()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "openclaw-fallback-token-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            File.WriteAllText(Path.Combine(tempDir, "device-key-ed25519.json"), "{ broken json");
            var resolver = new CredentialResolver(DeviceIdentityFileReader.Instance);
            var record = new GatewayRecord
            {
                Id = "gw-1",
                Url = "wss://test",
                SharedGatewayToken = "shared"
            };

            var result = resolver.ResolveOperatorDetailed(record, tempDir);

            Assert.NotNull(result.Credential);
            Assert.Equal("shared", result.Credential!.Token);
            Assert.Equal(CredentialResolver.SourceSharedGatewayToken, result.Credential.Source);
            Assert.Equal(GatewayCredentialResolutionStatus.FallbackUsed, result.Status);
            Assert.Equal(GatewayCredentialResolutionStatus.Corrupt, result.PrimaryStatus);
            Assert.True(result.FallbackUsed);
            Assert.True(result.Credential.FallbackUsed);
            Assert.Contains("corrupt", result.Detail, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void ResolveOperatorDetailed_ReportsFallbackUsed_WhenStoredTokenIsUnreadableAndSharedTokenExists()
    {
        var reader = new MockDeviceIdentityReader
        {
            OperatorReadResult = DeviceTokenReadResult.Unreadable("access denied")
        };
        var resolver = new CredentialResolver(reader);
        var record = new GatewayRecord
        {
            Id = "gw-1",
            Url = "wss://test",
            SharedGatewayToken = "shared"
        };

        var result = resolver.ResolveOperatorDetailed(record, "/id");

        Assert.NotNull(result.Credential);
        Assert.Equal("shared", result.Credential!.Token);
        Assert.Equal(CredentialResolver.SourceSharedGatewayToken, result.Credential.Source);
        Assert.Equal(GatewayCredentialResolutionStatus.FallbackUsed, result.Status);
        Assert.Equal(GatewayCredentialResolutionStatus.Unreadable, result.PrimaryStatus);
        Assert.True(result.FallbackUsed);
        Assert.True(result.Credential.FallbackUsed);
        Assert.Contains("unreadable", result.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("access denied", result.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ResolveOperator_NeverDowngradesPairedDevice()
    {
        // Even if bootstrap is present, paired device token wins
        var record = new GatewayRecord
        {
            Id = "gw-1",
            Url = "wss://test",
            BootstrapToken = "boot"
        };
        _mockReader.OperatorToken = "paired-tok";

        var result = _resolver.ResolveOperator(record, "/id");

        Assert.NotNull(result);
        Assert.Equal("paired-tok", result.Token);
        Assert.False(result.IsBootstrapToken);
    }

    // ─── Node resolution ───

    [Fact]
    public void ResolveNode_PrefersNodeDeviceToken_OverSharedAndBootstrap()
    {
        var record = new GatewayRecord
        {
            Id = "gw-1",
            Url = "wss://test",
            SharedGatewayToken = "shared",
            BootstrapToken = "boot"
        };
        _mockReader.NodeToken = "node-paired-tok";

        var result = _resolver.ResolveNode(record, "/id");

        Assert.NotNull(result);
        Assert.Equal("node-paired-tok", result.Token);
        Assert.False(result.IsBootstrapToken);
        Assert.Equal(CredentialResolver.SourceNodeDeviceToken, result.Source);
    }

    [Fact]
    public void ResolveNode_FallsToSharedToken_WhenNoNodeToken()
    {
        var record = new GatewayRecord
        {
            Id = "gw-1",
            Url = "wss://test",
            SharedGatewayToken = "shared"
        };
        _mockReader.NodeToken = null;

        var result = _resolver.ResolveNode(record, "/id");

        Assert.NotNull(result);
        Assert.Equal("shared", result.Token);
        Assert.False(result.IsBootstrapToken);
    }

    [Fact]
    public void ResolveNode_FallsToBootstrap_WhenNoNodeOrShared()
    {
        var record = new GatewayRecord
        {
            Id = "gw-1",
            Url = "wss://test",
            BootstrapToken = "boot"
        };
        _mockReader.NodeToken = null;

        var result = _resolver.ResolveNode(record, "/id");

        Assert.NotNull(result);
        Assert.Equal("boot", result.Token);
        Assert.True(result.IsBootstrapToken);
    }

    [Fact]
    public void ResolveNodeDetailed_ReportsBootstrapRequired_WhenBootstrapTokenIsUsed()
    {
        var record = new GatewayRecord
        {
            Id = "gw-1",
            Url = "wss://test",
            BootstrapToken = "boot"
        };
        _mockReader.NodeToken = null;

        var result = _resolver.ResolveNodeDetailed(record, "/id");

        Assert.NotNull(result.Credential);
        Assert.Equal("boot", result.Credential!.Token);
        Assert.True(result.Credential.IsBootstrapToken);
        Assert.Equal(GatewayCredentialResolutionStatus.BootstrapRequired, result.Status);
        Assert.True(result.BootstrapRequired);
    }

    [Fact]
    public void ResolveNode_ReturnsNull_WhenNoCredentials()
    {
        var record = new GatewayRecord { Id = "gw-1", Url = "wss://test" };
        _mockReader.NodeToken = null;

        var result = _resolver.ResolveNode(record, "/id");

        Assert.Null(result);
    }

    [Fact]
    public void ResolveNode_NeverDowngradesPairedNode()
    {
        var record = new GatewayRecord
        {
            Id = "gw-1",
            Url = "wss://test",
            SharedGatewayToken = "shared",
            BootstrapToken = "boot"
        };
        _mockReader.NodeToken = "node-paired-tok";

        var result = _resolver.ResolveNode(record, "/id");

        Assert.Equal("node-paired-tok", result!.Token);
        Assert.False(result.IsBootstrapToken);
    }

    // ─── Edge cases ───

    [Fact]
    public void ResolveOperator_ThrowsOnNullRecord()
    {
        Assert.Throws<ArgumentNullException>(() => _resolver.ResolveOperator(null!, "/id"));
    }

    [Fact]
    public void ResolveNode_ThrowsOnNullRecord()
    {
        Assert.Throws<ArgumentNullException>(() => _resolver.ResolveNode(null!, "/id"));
    }

    [Fact]
    public void ResolveOperator_SkipsWhitespaceTokens()
    {
        var record = new GatewayRecord
        {
            Id = "gw-1",
            Url = "wss://test",
            SharedGatewayToken = "   ",
            BootstrapToken = "  "
        };
        _mockReader.OperatorToken = "  ";

        var result = _resolver.ResolveOperator(record, "/id");

        Assert.Null(result);
    }

    // ─── Mock ───

    private sealed class MockDeviceIdentityReader : IDeviceIdentityReader
    {
        public string? OperatorToken { get; set; }
        public string? NodeToken { get; set; }
        public DeviceTokenReadResult? OperatorReadResult { get; set; }
        public DeviceTokenReadResult? NodeReadResult { get; set; }

        public string? TryReadStoredDeviceToken(string dataPath) => OperatorToken;
        public string? TryReadStoredNodeDeviceToken(string dataPath) => NodeToken;
        public DeviceTokenReadResult ReadStoredDeviceToken(string dataPath) =>
            OperatorReadResult ?? IDeviceIdentityReaderExtensions.FromToken(OperatorToken);
        public DeviceTokenReadResult ReadStoredNodeDeviceToken(string dataPath) =>
            NodeReadResult ?? IDeviceIdentityReaderExtensions.FromToken(NodeToken);
    }

    private static class IDeviceIdentityReaderExtensions
    {
        public static DeviceTokenReadResult FromToken(string? token) =>
            string.IsNullOrWhiteSpace(token)
                ? DeviceTokenReadResult.Missing()
                : DeviceTokenReadResult.Resolved(token!);
    }
}
