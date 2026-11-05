using System.Text.Json;
using OpenClaw.Shared;

namespace OpenClaw.Connection;

public sealed partial class GatewayConnectionManager
{
    private enum PersonalVerification { NotRequired, Verified, Stale, Rejected }
    private PersonalOperatorLease? _personalOperatorLease;

    public PersonalOperatorLease? CurrentPersonalOperatorLease
    {
        get
        {
            var lease = Volatile.Read(ref _personalOperatorLease);
            var client = _activeLifecycle?.DataClient;
            if (lease is null || client is not { RequiresPersonalIdentityVerification: true } ||
                lease.Generation != Interlocked.Read(ref _generation) ||
                client.SessionMutationConnectionEpoch != lease.TransportEpoch ||
                client.AuthenticatedSigningDeviceId != lease.DeviceId ||
                client.PersonalRecoveryScope != lease.RecoveryScope ||
                _registry.ActiveGatewayId != lease.GatewayId ||
                _registry.GetById(lease.GatewayId) is not { } record ||
                !GatewayPersonalAuthenticationPolicy.TryNormalizeOperatorRoute(record, out var route) ||
                route != lease.GatewayUrl || new Uri(client.CurrentGatewayUrl).AbsoluteUri != new Uri(route).AbsoluteUri ||
                lease.PersonalIdentityServeUrl != record.PersonalIdentityServeUrl ||
                client.IsLocalPersonalAuthentication && (record.LocalTlsPin != client.LocalTlsPin ||
                    !string.Equals(record.LocalTlsPin?.Fingerprint, lease.TlsFingerprint, StringComparison.OrdinalIgnoreCase)) ||
                client.IsLocalPersonalAuthentication &&
                    (client.CurrentPrimaryPersonalBinding is not { } binding || binding.GatewayId != lease.BoundGatewayId ||
                     binding.TlsFingerprint != lease.TlsFingerprint || binding.ProfileId != lease.IdentityProfileId))
                return null;
            return lease;
        }
    }

    private async Task<(PersonalVerification Disposition, PersonalOperatorLease? Lease)> VerifyPersonalOperatorAsync(long generation)
    {
        var client = _activeLifecycle?.DataClient;
        var record = _activeGatewayRecordId is null ? null : _registry.GetById(_activeGatewayRecordId);
        if (record is null || record.OperatorAuthentication == OperatorAuthenticationMode.GatewayCredential)
        {
            return (PersonalVerification.NotRequired, null);
        }

        if (client is not { RequiresPersonalIdentityVerification: true } ||
            client.PersonalHandshakeConnectionEpoch is not { } epoch ||
            client.PersonalRecoveryScope is not { } scope ||
            !GatewayPersonalAuthenticationPolicy.TryNormalizeOperatorRoute(record, out var route) ||
            new Uri(route).AbsoluteUri != new Uri(client.CurrentGatewayUrl).AbsoluteUri)
            return (PersonalVerification.Rejected, null);

        try
        {
            var self = await client.ReadPersonalIdentityAsync(epoch).ConfigureAwait(false);
            if (!IsCurrent()) return (PersonalVerification.Stale, null);
            if (!GatewayPersonalAuthenticationPolicy.TryGetCanonicalProfileId(self, out var profile) ||
                client.IsLocalPersonalAuthentication && client.CurrentPrimaryPersonalBinding?.ProfileId != profile)
                return (PersonalVerification.Rejected, null);
            client.VerifyPersonalIdentity(profile, epoch);
            if (!IsCurrent() || client.SessionMutationConnectionEpoch != epoch ||
                client.AuthenticatedSigningDeviceId is not { Length: > 0 } deviceId)
                return (PersonalVerification.Stale, null);
            var lease = new PersonalOperatorLease(record.Id, route, profile, scope, deviceId, generation, epoch)
            {
                PersonalIdentityServeUrl = record.PersonalIdentityServeUrl,
                BoundGatewayId = client.CurrentPrimaryPersonalBinding?.GatewayId,
                TlsFingerprint = client.CurrentPrimaryPersonalBinding?.TlsFingerprint
            };
            return (PersonalVerification.Verified, lease);
        }
        catch (Exception ex) when (ex is InvalidOperationException or TimeoutException or
            OperationCanceledException or JsonException)
        {
            if (!IsCurrent()) return (PersonalVerification.Stale, null);
            _diagnostics.Record("identity", "Personal profile verification unavailable", ex.GetType().Name);
            return (PersonalVerification.Rejected, null);
        }

        bool IsCurrent() =>
            generation == Interlocked.Read(ref _generation) &&
            ReferenceEquals(client, _activeLifecycle?.DataClient) &&
            client.PersonalHandshakeConnectionEpoch == epoch &&
            client.PersonalRecoveryScope == scope &&
            _registry.ActiveGatewayId == record.Id &&
            _registry.GetById(record.Id) is { } current && current.OperatorAuthentication == record.OperatorAuthentication &&
            current.PersonalIdentityServeUrl == record.PersonalIdentityServeUrl &&
            GatewayPersonalAuthenticationPolicy.TryNormalizeOperatorRoute(current, out var currentRoute) &&
            currentRoute == route;
    }

    public async Task<string?> CreatePersonalBrowserAuthResponseAsync(
        string nonce, long signedAt, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(nonce) || System.Text.Encoding.UTF8.GetByteCount(nonce) > 512 || nonce.Contains('|') ||
            nonce.Any(character => char.IsControl(character) || character == '\uFEFF') ||
            signedAt <= 0 || Math.Abs((double)new DateTimeOffset(_clock.UtcNow).ToUnixTimeMilliseconds() - signedAt) > 300_000)
            return null;

        var lease = CurrentPersonalOperatorLease;
        var client = _activeLifecycle?.DataClient;
        if (lease is null || client is null) return null;
        try
        {
            var self = await client.ReadPersonalIdentityAsync(lease.TransportEpoch).ConfigureAwait(false);
            if (cancellationToken.IsCancellationRequested ||
                !ReferenceEquals(lease, CurrentPersonalOperatorLease) ||
                !ReferenceEquals(client, _activeLifecycle?.DataClient))
                return null;
            if (!GatewayPersonalAuthenticationPolicy.TryGetCanonicalProfileId(self, out var profile) ||
                profile != lease.IdentityProfileId)
            {
                await RevokePersonalOperatorAsync(lease).ConfigureAwait(false);
                return null;
            }
            var response = client.CreatePersonalBrowserAuthResponse(nonce, signedAt, lease.TransportEpoch);
            return ReferenceEquals(lease, CurrentPersonalOperatorLease)
                ? JsonSerializer.Serialize(response, new JsonSerializerOptions
                {
                    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
                }) : null;
        }
        catch (Exception ex) when (ex is InvalidOperationException or TimeoutException or
            OperationCanceledException or JsonException)
        {
            await RevokePersonalOperatorAsync(lease).ConfigureAwait(false);
            return null;
        }
    }

    private async Task RevokePersonalOperatorAsync(PersonalOperatorLease expected)
    {
        await _transitionSemaphore.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!ReferenceEquals(expected, CurrentPersonalOperatorLease)) return;
            _stateMachine.TryTransition(ConnectionTrigger.WebSocketError,
                "Personal identity changed. Reconnect this Gateway.");
            _stateMachine.Current = _stateMachine.Current with { PersonalIdentityProfileId = null };
            await DisposeActiveClientAsync().ConfigureAwait(false);
            EmitStateChanged();
        }
        finally
        {
            _transitionSemaphore.Release();
        }
    }
}
