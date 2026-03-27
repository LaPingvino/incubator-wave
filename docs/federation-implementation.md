# HTTP Federation Transport — Implementation Guide

**Status:** Phase 1 (Minimum Viable Federation)
**Date:** 2026-03-27

## Overview

This document describes the Phase 1 implementation of the Wave Federation
Protocol using HTTPS as the transport layer. It replaces the original
XMPP-based federation with a simpler HTTP/WebSocket approach inspired by
Matrix's operational model.

For the full protocol specification, see
[wave-federation-spec-draft.md](wave-federation-spec-draft.md).

## Architecture

The implementation plugs into Wave's existing federation bus via Guice
dependency injection. No changes to `WaveServerImpl` or the OT engine
are needed.

```
┌─────────────────────────────────────────────────────┐
│                   WaveServerImpl                     │
│                                                      │
│  implements WaveletFederationProvider (local side)    │
│  implements WaveletFederationListener.Factory         │
└──────────┬──────────────────────────┬────────────────┘
           │                          │
   @FederationRemoteBridge    @FederationHostBridge
           │                          │
┌──────────▼──────────┐   ┌──────────▼──────────────┐
│ HttpFederationRemote │   │  HttpFederationHost      │
│                      │   │                          │
│ Makes outbound HTTP  │   │  Receives inbound HTTP   │
│ calls to remote Wave │   │  requests from remote    │
│ servers              │   │  Wave servers via         │
│                      │   │  servlets                 │
└──────────────────────┘   └──────────────────────────┘
```

### Outbound Path (HttpFederationRemote)

When a local user adds a participant from a remote domain, or when a
remote wavelet needs history:

1. `HttpFederationRemote.submitRequest()` is called
2. It discovers the remote server via `.well-known/wave/server`
3. It POSTs the signed delta to `/_wave/federation/v1/submit`
4. The remote server applies it and returns the result

### Inbound Path (Servlets)

When a remote server sends a delta for a locally-hosted wavelet:

1. `FederationSubmitServlet` receives the POST
2. It decodes the JSON, verifies the signature (when enabled)
3. It forwards to the local WaveletProvider for OT and application
4. It returns the result as JSON

## Source Layout

### Main source tree (`wave/src/main/java/...`)

Non-servlet classes that don't depend on Jakarta APIs:

```
org/waveprotocol/wave/federation/http/
├── FederationJsonCodec.java        # JSON serialization for federation messages
├── FederationKeyManager.java       # Ed25519 key generation/storage/signing
├── FederationDiscoveryClient.java  # .well-known discovery with caching
├── FederationKeyClient.java        # Remote key fetching with caching
├── HttpFederationRemote.java       # WaveletFederationProvider (outbound)
├── HttpFederationHost.java         # WaveletFederationListener.Factory (outbound push)
├── HttpFederationTransport.java    # FederationTransport lifecycle
└── HttpFederationModule.java       # Guice module wiring
```

### Jakarta overrides (`wave/src/jakarta-overrides/java/...`)

Servlets that depend on `jakarta.servlet.http.HttpServlet`:

```
org/waveprotocol/wave/federation/http/
├── WellKnownWaveServlet.java       # GET /.well-known/wave/server
├── FederationKeysServlet.java      # GET /_wave/keys/v1
├── FederationSubmitServlet.java    # POST /_wave/federation/v1/submit
└── FederationHistoryServlet.java   # GET /_wave/federation/v1/history/*
```

## Configuration

All settings live in `wave/config/reference.conf` under the `federation`
block:

```hocon
federation {
  # Master switch
  enable_federation : false

  # Transport: "noop" or "http"
  transport : "http"

  # Ed25519 signing key (auto-generated if missing)
  signing_key_path : "federation-signing-key.pem"
  signing_key_id : "ed25519:wave01"

  # Cache TTLs
  key_cache_ttl_ms : 86400000       # 24 hours
  discovery_cache_ttl_ms : 3600000  # 1 hour

  # HTTP client settings
  http_max_connections : 20
  http_request_timeout_ms : 30000

  # Legacy X.509 settings (retained for backward compat)
  waveserver_disable_verification : true
  waveserver_disable_signer_verification : true
}
```

## Enabling Federation

### Quick start (two servers on the same machine)

1. Edit `config/application.conf` on each server:

   **Server A** (port 9898, domain `alpha.wave`):
   ```hocon
   core.wave_server_domain = "alpha.wave"
   core.http_frontend_addresses = ["localhost:9898"]
   core.http_frontend_public_address = "alpha.wave:9898"
   federation.enable_federation = true
   ```

   **Server B** (port 9899, domain `beta.wave`):
   ```hocon
   core.wave_server_domain = "beta.wave"
   core.http_frontend_addresses = ["localhost:9899"]
   core.http_frontend_public_address = "beta.wave:9899"
   federation.enable_federation = true
   ```

2. Add DNS entries (or `/etc/hosts`) for `alpha.wave` and `beta.wave`.

3. Start both servers. Each will auto-generate an Ed25519 signing key on
   first startup.

4. On Server A, create a wave and add `user@beta.wave` as a participant.

### Production setup

1. Ensure your domain has HTTPS (via Caddy, nginx, or similar).
2. The `.well-known/wave/server` endpoint must be accessible at your domain root.
3. Set `federation.enable_federation = true` in `application.conf`.
4. The signing key is auto-generated; back it up from the configured path.
5. Restart the server.

## Protocol Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/.well-known/wave/server` | GET | Server discovery |
| `/_wave/keys/v1` | GET | Public signing keys |
| `/_wave/federation/v1/submit` | POST | Submit delta to remote |
| `/_wave/federation/v1/history/*` | GET | Request delta history |

## Build Changes

- **BouncyCastle**: Upgraded from `bcprov-jdk16:1.45` to
  `bcprov-jdk18on:1.78.1` + `bcpkix-jdk18on:1.78.1`. Ed25519 uses Java
  17's built-in `java.security` APIs; BouncyCastle is retained for legacy
  X.509 operations.

- **Protobuf**: Added `ED25519 = 2` to
  `ProtocolSignature.SignatureAlgorithm` in `federation.protodevel`.

## Phase 2 Roadmap

- WebSocket server-to-server streaming for real-time delta push
- Snapshot endpoint for fast initial sync
- DoltLite-based cold sync (experimental)
- LLM-assisted federation setup wizard

## Compatibility

Phase 1 is backward compatible:

- Federation is disabled by default (`enable_federation = false`)
- When disabled, `NoOpFederationModule` is used (identical to before)
- No changes to `WaveServerImpl`, OT engine, or client code
- Existing single-server deployments are unaffected
