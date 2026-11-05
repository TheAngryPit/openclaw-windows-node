using System.Text.Json;
using System.Net.WebSockets;

namespace OpenClaw.Shared;

public partial class OpenClawGatewayClient
{
    private sealed record PersonalHandshake(long Epoch, string RecoveryScope, string? ProfileId = null);
    private readonly OperatorAuthenticationMode _operatorAuthentication;
    private PersonalHandshake? _personalHandshake;
    private readonly string _deviceIdentityPath;
    private readonly HttpClient _personalServeHttpClient;

    /// <summary>Auxiliary trusted Serve admission route. The primary Gateway URL stays local.</summary>
    public string? PrimaryPersonalIdentityServeUrl { get; init; }
    private PersonalIdentityBinding? _primaryPersonalBinding;
    private Func<long, PersonalIdentityIntent>? _personalIdentityIntent;
    private PersonalIdentityBinding? _capturedPersonalBinding;
    private bool _oneShotPersonalBinding;
    private string[]? _personalBindingScopes;
    private string? _primaryServeRecoveryScope;

    public bool IsLocalPersonalAuthentication => _operatorAuthentication == OperatorAuthenticationMode.PersonalTailscaleLocal;
    public bool RequiresPersonalIdentityVerification => IsPersonalTailscaleAuthentication || IsLocalPersonalAuthentication;

    public PersonalIdentityBinding? CurrentPrimaryPersonalBinding => Volatile.Read(ref _primaryPersonalBinding);

    private void RetirePrimaryPersonalBinding()
    {
        if (!IsLocalPersonalAuthentication) return;
        Volatile.Write(ref _primaryPersonalBinding, null);
        _personalIdentityIntent = null;
        _primaryServeRecoveryScope = null;
    }

    private bool TryGetPersonalHttpBaseUri(GatewayConnectionLease lease, out Uri baseUri)
    {
        baseUri = null!;
        if (!RequiresPersonalIdentityVerification || !IsCurrentMediaLease(lease) ||
            lease.PersonalAuthority is not PersonalHandshake { ProfileId: not null } personal ||
            IsLocalPersonalAuthentication && CurrentPrimaryPersonalBinding?.ProfileId != personal.ProfileId ||
            !PersonalTailscaleGatewayRoute.TryNormalizeGatewayUrl(
                IsLocalPersonalAuthentication ? PrimaryPersonalIdentityServeUrl : _currentGatewayUrl, out var route, out _))
            return false;
        return TryBuildMediaHttpBaseUri(route, out baseUri);
    }

    private async Task<bool> VerifyCurrentPersonalHttpIdentityAsync(GatewayConnectionLease lease, CancellationToken cancellationToken)
    {
        if (!IsCurrentMediaLease(lease) || lease.PersonalAuthority is not PersonalHandshake personal) return false;
        try
        {
            var self = await SendResponseRequestAsync("users.self", new { }, 30000, lease.Generation,
                requestCancellationToken: cancellationToken).ConfigureAwait(false);
            return IsCurrentMediaLease(lease) && self.ValueKind == JsonValueKind.Object &&
                self.TryGetProperty("profile", out var profile) &&
                PersonalIdentityBinding.Read(profile, "id") == personal.ProfileId && personal.ProfileId != "gateway-owner";
        }
        catch (Exception ex) when (ex is InvalidOperationException or TimeoutException or OperationCanceledException or JsonException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return false;
        }
    }

    private HttpRequestMessage CreatePersonalServeReadRequest(Uri uri, string accept)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.ParseAdd(accept);
        request.Headers.Add("Origin", uri.GetLeftPart(UriPartial.Authority));
        request.Headers.TryAddWithoutValidation("x-openclaw-scopes", string.Join(",", GrantedOperatorScopes));
        return request;
    }

    protected override async Task PrepareTransportAsync(ClientWebSocket socket, Uri uri, long generation, CancellationToken cancellationToken)
    {
        await base.PrepareTransportAsync(socket, uri, generation, cancellationToken).ConfigureAwait(false);
        if (!IsLocalPersonalAuthentication) return;
        if (!TryApplyToCurrentTransport(socket, generation, RetirePrimaryPersonalBinding))
            throw new OperationCanceledException("The personal Gateway transport was superseded.");
        if (LocalTlsPin is null || !PersonalIdentityBinding.IsLocalWss(uri.AbsoluteUri) ||
            !PersonalTailscaleGatewayRoute.TryNormalizeGatewayUrl(PrimaryPersonalIdentityServeUrl, out var serve, out _))
            throw new InvalidOperationException("Personal Primary identity requires local WSS and a trusted Tailscale Serve address.");

        var bindingId = Guid.NewGuid().ToString();
        using var admission = new OpenClawGatewayClient(serve, string.Empty, _logger,
            identityPath: _deviceIdentityPath, persistHandshakeDeviceTokens: false, requireExistingIdentity: true,
            operatorAuthentication: OperatorAuthenticationMode.PersonalTailscale)
        {
            ClientIdentity = OperatorClientIdentity.Interactive,
            SupportsExecApprovals = SupportsExecApprovals,
            _oneShotPersonalBinding = true,
            _personalBindingScopes = GetRequestedScopes("operator"),
            _personalIdentityIntent = issuedAt => new("bind", bindingId, issuedAt)
        };
        var completion = new TaskCompletionSource<PersonalIdentityBinding>(TaskCreationOptions.RunContinuationsAsynchronously);
        admission.HandshakeSucceeded += (_, _) =>
        {
            if (admission._capturedPersonalBinding is { } binding &&
                admission._deviceIdentity.DeviceId == _deviceIdentity.DeviceId)
                completion.TrySetResult(binding);
            else completion.TrySetException(new InvalidOperationException("Personal Serve binding was not verified."));
        };
        admission.AuthenticationFailed += (_, _) => completion.TrySetException(new InvalidOperationException("Personal Serve admission failed."));
        admission.StatusChanged += (_, status) =>
        {
            if (status is ConnectionStatus.Error or ConnectionStatus.Disconnected)
                completion.TrySetException(new InvalidOperationException("Personal Serve admission disconnected."));
        };
        await admission.ConnectAsync().ConfigureAwait(false);
        var result = await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (!string.Equals(result.TlsFingerprint, LocalTlsPin.Fingerprint, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The trusted Serve binding does not match the configured local Gateway TLS certificate.");
        if (!TryApplyToCurrentTransport(socket, generation, () =>
        {
            Volatile.Write(ref _primaryPersonalBinding, result);
            _primaryServeRecoveryScope = admission.PersonalRecoveryScope;
            _personalIdentityIntent = issuedAt => new("use", result.BindingId, issuedAt, result.ProfileId, result.GatewayId);
            socket.Options.RemoteCertificateValidationCallback = (_, certificate, _, _) => result.ValidateCertificate(certificate);
        }))
            throw new OperationCanceledException("The personal Gateway transport was superseded.");
    }

    public bool IsPersonalTailscaleAuthentication =>
        _operatorAuthentication == OperatorAuthenticationMode.PersonalTailscale;

    public long? PersonalHandshakeConnectionEpoch =>
        TryGetHandshakeConnectionGeneration(out var epoch) &&
        Volatile.Read(ref _personalHandshake)?.Epoch == epoch ? epoch : null;

    public string? PersonalRecoveryScope =>
        PersonalHandshakeConnectionEpoch is { } epoch &&
        Volatile.Read(ref _personalHandshake) is { } handshake && handshake.Epoch == epoch
            ? handshake.RecoveryScope : null;

    public string CurrentGatewayUrl => _currentGatewayUrl;

    public async Task<JsonElement> ReadPersonalIdentityAsync(long expectedEpoch)
    {
        if (!RequiresPersonalIdentityVerification || PersonalHandshakeConnectionEpoch != expectedEpoch)
            throw new InvalidOperationException("The personal Gateway connection changed.");
        var result = await SendResponseRequestAsync(
            "users.self", new { }, 30000, expectedEpoch, allowPersonalIdentityRead: true).ConfigureAwait(false);
        if (PersonalHandshakeConnectionEpoch != expectedEpoch)
            throw new InvalidOperationException("The personal Gateway connection changed.");
        return result;
    }

    public void VerifyPersonalIdentity(string profileId, long expectedEpoch)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(profileId);
        var handshake = Volatile.Read(ref _personalHandshake);
        if (profileId == "gateway-owner" ||
            IsLocalPersonalAuthentication && CurrentPrimaryPersonalBinding?.ProfileId != profileId ||
            !RequiresPersonalIdentityVerification || handshake is null ||
            handshake.Epoch != expectedEpoch || PersonalHandshakeConnectionEpoch != expectedEpoch)
            throw new InvalidOperationException("The personal Gateway connection changed.");
        var verified = handshake with { ProfileId = profileId };
        if (!ReferenceEquals(Interlocked.CompareExchange(ref _personalHandshake, verified, handshake), handshake))
            throw new InvalidOperationException("The personal Gateway connection changed.");
        if (PersonalHandshakeConnectionEpoch != expectedEpoch)
        {
            Interlocked.CompareExchange(ref _personalHandshake, null, verified);
            throw new InvalidOperationException("The personal Gateway connection changed.");
        }
        RequestInitialState(expectedEpoch);
    }

    private void RequestInitialState(long epoch)
    {
        _ = Task.Run(async () =>
        {
            await Task.Delay(500);
            if (!TryGetReadyConnectionGeneration(out var current) || current != epoch)
                return;
            await CheckHealthAsync();
            await RequestSessionsAsync();
            await SubscribeSessionEventsAsync();
            await RequestUsageAsync();
            await RequestNodesAsync();
            await RequestAgentsListAsync();
        });
    }

    private bool HasVerifiedPersonalIdentity(long epoch) =>
        Volatile.Read(ref _personalHandshake) is { ProfileId: not null } handshake && handshake.Epoch == epoch;

    private bool TryAcceptPersonalHandshake(JsonElement payload, long epoch)
    {
        if (IsLocalPersonalAuthentication)
        {
            var expected = CurrentPrimaryPersonalBinding;
            if (expected is null || !expected.AcceptsLocalHello(payload))
                return false;
            if (string.IsNullOrWhiteSpace(_primaryServeRecoveryScope)) return false;
            Volatile.Write(ref _personalHandshake, new PersonalHandshake(epoch, _primaryServeRecoveryScope));
            return true;
        }
        if (_oneShotPersonalBinding && (_personalIdentityIntent?.Invoke(1) is not { } intent ||
            !PersonalIdentityBinding.TryRead(payload, intent.BindingId, out _capturedPersonalBinding)))
            return false;
        if (!payload.TryGetProperty("auth", out var auth) ||
            auth.ValueKind != JsonValueKind.Object ||
            !auth.TryGetProperty("method", out var method) ||
            method.ValueKind != JsonValueKind.String || method.GetString() != "tailscale" ||
            !auth.TryGetProperty("recoveryScope", out var scope) ||
            scope.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(scope.GetString()))
            return false;
        Volatile.Write(ref _personalHandshake, new PersonalHandshake(epoch, scope.GetString()!));
        return true;
    }

    public object CreatePersonalBrowserAuthResponse(string nonce, long signedAt, long expectedEpoch)
    {
        var handshake = Volatile.Read(ref _personalHandshake);
        var primaryBinding = CurrentPrimaryPersonalBinding;
        if (string.IsNullOrWhiteSpace(nonce) || System.Text.Encoding.UTF8.GetByteCount(nonce) > 512 ||
            nonce.Contains('|') || nonce.Any(character => char.IsControl(character) || character == '\uFEFF') ||
            signedAt <= 0 || !RequiresPersonalIdentityVerification || IsLocalPersonalAuthentication && primaryBinding is null ||
            !TryGetReadyConnectionGeneration(out var epoch) || epoch != expectedEpoch ||
            handshake is not { ProfileId: not null } || handshake.Epoch != epoch ||
            AuthenticatedSigningDeviceId != _deviceIdentity.DeviceId)
            throw new InvalidOperationException("Personal Gateway identity is unavailable.");

        var scopes = GrantedOperatorScopes.ToArray();
        var signature = _deviceIdentity.SignConnectPayloadV3(
            nonce, signedAt, "gateway-client", "ui", "operator", scopes, string.Empty,
            WindowsClientMetadata.Platform, WindowsClientMetadata.DeviceFamily);
        if (!TryGetReadyConnectionGeneration(out var currentEpoch) || currentEpoch != epoch ||
            !ReferenceEquals(handshake, Volatile.Read(ref _personalHandshake)))
            throw new InvalidOperationException("The personal Gateway connection changed.");

        return new
        {
            client = new
            {
                id = "gateway-client", mode = "ui", version = AppVersionInfo.Version,
                platform = WindowsClientMetadata.Platform, deviceFamily = WindowsClientMetadata.DeviceFamily
            },
            scopes,
            auth = new { },
            requiredAuthMethod = "tailscale",
            expectedRecoveryScope = handshake.RecoveryScope,
            expectedGatewayId = primaryBinding?.GatewayId,
            device = new
            {
                id = _deviceIdentity.DeviceId, publicKey = _deviceIdentity.PublicKeyBase64Url,
                signature, signedAt, nonce
            }
        };
    }
}
