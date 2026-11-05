// Record-scoped local TLS pin, populated only by an explicit verified Gateway TLS upgrade.
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenClaw.Shared;

/// <summary>Exact leaf certificate and loopback WSS endpoint for one logical Gateway record.</summary>
public sealed record LocalGatewayTlsPin(string GatewayRecordId, string GatewayUrl, string Fingerprint)
{
    public bool Matches(string recordId, string endpoint) => GatewayRecordId == recordId &&
        MatchesEndpoint(endpoint);

    public bool MatchesEndpoint(string endpoint) => !string.IsNullOrWhiteSpace(GatewayRecordId) &&
        PersonalIdentityBinding.IsLocalWss(GatewayUrl) && PersonalIdentityBinding.IsLocalWss(endpoint) &&
        new Uri(GatewayUrl) == new Uri(endpoint) && PersonalIdentityBinding.IsFingerprint(Fingerprint);

    /// <summary>The same pinned Gateway HTTPS origin/base path, never a redirected or remote origin.</summary>
    internal bool MatchesHttpRequest(Uri? request)
    {
        if (request is null || !MatchesEndpoint(GatewayUrl) || request.Scheme != "https" ||
            !string.IsNullOrEmpty(request.UserInfo)) return false;
        var endpoint = new Uri(GatewayUrl);
        var basePath = endpoint.AbsolutePath.TrimEnd('/') + "/";
        return string.Equals(request.Host, endpoint.Host, StringComparison.OrdinalIgnoreCase) && request.Port == endpoint.Port &&
            (request.AbsolutePath == endpoint.AbsolutePath || request.AbsolutePath.StartsWith(basePath, StringComparison.Ordinal));
    }

    internal bool ValidateCertificate(X509Certificate? certificate) => certificate is not null &&
        PersonalIdentityBinding.IsFingerprint(Fingerprint) && CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(certificate.GetRawCertData()), Convert.FromHexString(Fingerprint));
}
