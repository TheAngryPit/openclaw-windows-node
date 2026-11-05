// Existing Mac/Core personal-identity handshake contract. Bind over trusted Serve,
// then use the attested certificate on local WSS; never persist binding authority.
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenClaw.Shared;

/// <summary>Signed connect intent, created fresh for each Gateway challenge.</summary>
public sealed record PersonalIdentityIntent(
    [property: JsonPropertyName("phase")] string Phase,
    [property: JsonPropertyName("bindingId")] string BindingId,
    [property: JsonPropertyName("issuedAtMs")] long IssuedAtMs,
    [property: JsonPropertyName("profileId"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ProfileId = null,
    [property: JsonPropertyName("gatewayId"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? GatewayId = null)
{
    [JsonPropertyName("mode")] public string Mode => "personal-identity";
    [JsonPropertyName("provider")] public string Provider => "tailscale";

    internal string[] SignatureValue => Phase switch
    {
        "bind" when !string.IsNullOrWhiteSpace(BindingId) && ProfileId is null && GatewayId is null =>
            [Mode, Provider, Phase, BindingId, IssuedAtMs.ToString(CultureInfo.InvariantCulture)],
        "use" when !string.IsNullOrWhiteSpace(BindingId) && !string.IsNullOrWhiteSpace(ProfileId) && !string.IsNullOrWhiteSpace(GatewayId) =>
            [Mode, Provider, Phase, BindingId, ProfileId, GatewayId, IssuedAtMs.ToString(CultureInfo.InvariantCulture)],
        _ => throw new InvalidOperationException("Invalid personal identity intent.")
    };

    internal static readonly JsonSerializerOptions SignatureJson = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
}

/// <summary>Volatile attestation accepted only from the normal trusted Serve TLS channel.</summary>
public sealed record PersonalIdentityBinding(string BindingId, string ProfileId, string GatewayId, string TlsFingerprint)
{
    public static bool TryRead(JsonElement hello, string expectedBindingId, out PersonalIdentityBinding? result)
    {
        result = null;
        if (hello.ValueKind != JsonValueKind.Object ||
            !hello.TryGetProperty("personalIdentityBinding", out var binding) || binding.ValueKind != JsonValueKind.Object ||
            Read(binding, "mode") != "personal-identity" || Read(binding, "provider") != "tailscale" ||
            Read(binding, "bindingId") != expectedBindingId || string.IsNullOrWhiteSpace(expectedBindingId) ||
            Read(binding, "profileId") is not { Length: > 0 } profile || profile == "gateway-owner" || profile != profile.Trim() ||
            Read(binding, "gatewayId") is not { Length: > 0 } gateway ||
            !hello.TryGetProperty("server", out var server) || Read(server, "bootId") != gateway ||
            Read(binding, "tlsFingerprint") is not { } fingerprint || !IsFingerprint(fingerprint))
            return false;
        result = new(expectedBindingId, profile, gateway, fingerprint.ToLowerInvariant());
        return true;
    }

    internal static string? Read(JsonElement value, string name) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var item) && item.ValueKind == JsonValueKind.String
            ? item.GetString() : null;

    public static bool IsFingerprint(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);

    /// <summary>Use hello must come from the bound boot with ordinary local credential admission.</summary>
    public bool AcceptsLocalHello(JsonElement hello) => hello.ValueKind == JsonValueKind.Object &&
        hello.TryGetProperty("server", out var server) && Read(server, "bootId") == GatewayId &&
        hello.TryGetProperty("auth", out var auth) && Read(auth, "method") is "token" or "password" or "device-token";

    public static bool IsLocalWss(string? value) => Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        uri.Scheme == "wss" && uri.IsLoopback && string.IsNullOrEmpty(uri.UserInfo) &&
        string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment);

    /// <summary>Exact attested leaf pin; never TOFU, chain fallback, or a global callback.</summary>
    internal bool ValidateCertificate(X509Certificate? certificate) => certificate is not null &&
        CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(certificate.GetRawCertData()), Convert.FromHexString(TlsFingerprint));
}
