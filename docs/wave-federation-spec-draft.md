# SupaWave Federation Protocol — Draft Specification v0.1

**Status:** Draft for discussion
**Date:** 2026-03-27
**Authors:** Joop Kiefte, with input from Yuri Zelikov

## 1. Goals

1. **Federate Wave instances** with minimal operational friction
2. **Preserve Wave's core model** — real-time OT on structured documents, not chat-over-widgets
3. **Borrow Matrix's operational simplicity** — HTTPS transport, `.well-known` discovery, HTTP key exchange
4. **Reuse existing federation interfaces** — plug into `WaveletFederationProvider` / `WaveletFederationListener` without changing the Wave server core
5. **LLM-assisted setup** — an agent can configure federation end-to-end in minutes

## 2. Design Principles

- **HTTPS as transport.** No custom TCP protocols, no XMPP servers to install. Every reverse proxy, CDN, and firewall already speaks HTTPS.
- **WebSocket for real-time.** HTTP request/response for history and key exchange; WebSocket upgrade for live delta streaming.
- **Content-negotiated serialization.** Support JSON (human-readable, easy debugging), Protocol Buffers (existing codebase compatibility), and optionally S-expressions (lightweight, IRC-like simplicity). Servers negotiate via `Accept` / `Content-Type`.
- **Existing Wave semantics.** The federation messages map 1:1 to the existing protobuf types (`ProtocolSignedDelta`, `ProtocolAppliedWaveletDelta`, `ProtocolHashedVersion`, etc.). This is a new transport, not a new protocol.
- **Signing without certificate chains.** Replace X.509 certificate exchange with HTTP-fetchable signing keys (inspired by Matrix's key server approach). Ed25519 as default algorithm (faster, simpler than RSA).

## 3. Server Discovery

### 3.1 Well-Known Endpoint

A Wave server advertises its federation endpoint via a static JSON file:

```
GET https://example.com/.well-known/wave/server
```

Response:

```json
{
  "w.server": "wave.example.com:443",
  "w.protocol_version": "1.0",
  "w.transports": ["https", "wss"],
  "w.serialization": ["application/protobuf", "application/json", "application/x-wave-sexp"]
}
```

**Rationale:** Any web developer can serve a static JSON file. No SRV DNS records, no special DNS knowledge required. This is directly borrowed from Matrix's `/.well-known/matrix/server`.

### 3.2 Fallback Discovery

If `.well-known` is not present, attempt federation directly at `https://<domain>:443/_wave/federation/v1/`. This allows zero-configuration federation for servers where the Wave domain matches the server hostname.

## 4. Server Identity & Signing Keys

### 4.1 Key Endpoint

Each server publishes its signing keys over HTTPS:

```
GET https://wave.example.com/_wave/keys/v1
```

Response:

```json
{
  "server_name": "example.com",
  "signing_keys": {
    "ed25519:wave01": {
      "key": "<base64url-encoded-public-key>"
    }
  },
  "old_signing_keys": {
    "ed25519:wave00": {
      "key": "<base64url-encoded-public-key>",
      "expired_ts": 1711500000000
    }
  },
  "valid_until_ts": 1714092000000
}
```

**Rationale:** Replaces the in-band X.509 certificate chain exchange (`ProtocolSignerInfo`) with a simple HTTP fetch. Keys are cacheable until `valid_until_ts`. This eliminates the `postSignerInfo` / `getDeltaSignerInfo` round-trips that added latency and complexity to the original protocol.

### 4.2 Key Verification

Servers verify remote keys by:

1. Fetching the key endpoint over TLS (server identity verified by the TLS certificate, as with any HTTPS connection)
2. Caching keys until `valid_until_ts`
3. Optionally, a **notary server** can provide third-party key attestation (future extension, not required for v1)

### 4.3 Delta Signing

Deltas are signed using Ed25519 (or optionally RSA for backward compatibility). The signature covers the serialized delta bytes, matching the existing `ProtocolSignedDelta` structure:

```json
{
  "delta": "<base64url-encoded-serialized-delta>",
  "signatures": [
    {
      "key_id": "ed25519:wave01",
      "domain": "example.com",
      "signature": "<base64url-encoded-signature>"
    }
  ]
}
```

This maps directly to the existing `ProtocolSignedDelta` / `ProtocolSignature` protobuf messages but uses key IDs instead of signer certificate hashes.

## 5. Federation API Endpoints

All endpoints are prefixed with `/_wave/federation/v1/`.

### 5.1 Submit Delta

```
POST /_wave/federation/v1/submit
Content-Type: application/json

{
  "wavelet_name": {
    "wave_id": {"domain": "example.com", "id": "w+abc123"},
    "wavelet_id": {"domain": "example.com", "id": "conv+root"}
  },
  "signed_delta": {
    "delta": "<base64url>",
    "signatures": [...]
  }
}
```

Response (success):

```json
{
  "operations_applied": 3,
  "hashed_version_after": {
    "version": 45,
    "history_hash": "<base64url>"
  },
  "application_timestamp": 1711500000000
}
```

Response (error):

```json
{
  "error_code": "NOT_ACCEPTABLE",
  "error_message": "Delta does not apply at current version"
}
```

**Maps to:** `WaveletFederationProvider.submitRequest()`

### 5.2 Request History

```
GET /_wave/federation/v1/history/{wave_domain}/{wave_id}/{wavelet_domain}/{wavelet_id}
    ?start_version=10
    &start_hash=<base64url>
    &end_version=45
    &end_hash=<base64url>
    &limit=100
```

Response:

```json
{
  "deltas": ["<base64url>", "<base64url>", ...],
  "last_committed_version": {
    "version": 42,
    "history_hash": "<base64url>"
  },
  "version_truncated_at": 30
}
```

**Maps to:** `WaveletFederationProvider.requestHistory()`

### 5.3 Wavelet Snapshot (new — not in original protocol)

```
GET /_wave/federation/v1/snapshot/{wave_domain}/{wave_id}/{wavelet_domain}/{wavelet_id}
```

Response:

```json
{
  "wavelet_name": {...},
  "hashed_version": {"version": 45, "history_hash": "<base64url>"},
  "participants": ["user@example.com", "user@other.com"],
  "documents": {
    "b+main": {
      "content": "<document-content>",
      "version": 45
    }
  },
  "last_modified_time": 1711500000000
}
```

**Rationale:** The original protocol required replaying full delta history to reconstruct state. A snapshot endpoint allows fast initial sync — new federated servers can start from a snapshot and then follow live deltas, rather than replaying potentially thousands of deltas.

### 5.4 Real-Time Delta Stream (WebSocket)

```
GET /_wave/federation/v1/stream
Connection: Upgrade
Upgrade: websocket
```

After upgrade, the WebSocket carries bidirectional messages:

**Subscribe to wavelet updates:**
```json
{"type": "subscribe", "wavelet": {"wave_id": {...}, "wavelet_id": {...}}, "from_version": 42}
```

**Delta update (server → remote):**
```json
{"type": "delta_update", "wavelet": {...}, "deltas": ["<base64url>", ...]}
```

**Commit update (server → remote):**
```json
{"type": "commit_update", "wavelet": {...}, "committed_version": {"version": 42, "history_hash": "<base64url>"}}
```

**Maps to:** `WaveletFederationListener.waveletDeltaUpdate()` and `waveletCommitUpdate()`

## 6. Error Codes

The existing federation error codes are preserved but no longer mapped to XMPP stanzas:

| Code | Name | HTTP Status | Meaning |
|------|------|-------------|---------|
| 0 | OK | 200 | Success |
| 1 | BAD_REQUEST | 400 | Malformed request |
| 2 | ITEM_NOT_FOUND | 404 | Wavelet not found or unauthorized |
| 3 | NOT_ACCEPTABLE | 409 | Delta doesn't apply, invalid signer |
| 4 | NOT_AUTHORIZED | 403 | Missing or invalid credentials |
| 5 | RESOURCE_CONSTRAINT | 429 | Rate limit / back off |
| 6 | UNDEFINED_CONDITION | 500 | Unknown error |
| 7 | REMOTE_SERVER_TIMEOUT | 504 | Upstream timeout |
| 8 | UNEXPECTED_REQUEST | 400 | Out-of-sequence request |
| 9 | INTERNAL_SERVER_ERROR | 500 | Server error |

## 7. Serialization Formats

Servers negotiate serialization via HTTP content negotiation (`Accept` / `Content-Type`).

### 7.1 Protocol Buffers (default)

The existing `.protodevel` message definitions, serialized as standard protobuf binary. Content type: `application/protobuf`.

### 7.2 JSON

Direct JSON mapping of the protobuf messages. Content type: `application/json`. Bytes fields encoded as base64url.

### 7.3 S-Expression (optional, experimental)

A lightweight text format inspired by IRC's simplicity:

```
(delta (wave example.com w+abc123) (wavelet example.com conv+root)
  :author user@example.com
  :version 42
  :hash "base64url..."
  (ops
    (retain 15)
    (insert "hello world")
    (annotation-start "style/bold" "true")
    (retain 11)
    (annotation-end "style/bold")))
```

Content type: `application/x-wave-sexp`. Line-oriented framing (one top-level form per line) for easy streaming and debugging.

**Rationale:** Debuggable with `netcat`/`websocat`, parseable in ~50 lines of code in any language, naturally maps to the tree-structured document operations. Good for lightweight/experimental federation and development tooling.

## 8. Implementation Plan

### Phase 1: HTTP Federation Transport

Create a new Guice module `HttpFederationModule` that binds:

- `WaveletFederationProvider` (FederationRemoteBridge) → `HttpFederationRemote`
  - Implements `submitRequest()` → HTTP POST to remote `/_wave/federation/v1/submit`
  - Implements `requestHistory()` → HTTP GET to remote `/_wave/federation/v1/history/...`
  - Implements `getDeltaSignerInfo()` → HTTP GET to remote `/_wave/keys/v1` (simplified)
  - Implements `postSignerInfo()` → no-op (keys fetched on demand, not pushed)

- `WaveletFederationListener.Factory` (FederationHostBridge) → `HttpFederationHost`
  - Exposes servlet endpoints for incoming federation requests
  - Implements `waveletDeltaUpdate()` → sends over WebSocket to subscribed remotes
  - Implements `waveletCommitUpdate()` → sends over WebSocket to subscribed remotes

- `FederationTransport` → `HttpFederationTransport`
  - On `startFederation()`: registers servlet endpoints, starts key rotation timer

### Phase 2: Discovery & Key Management

- Implement `.well-known/wave/server` endpoint
- Implement `/_wave/keys/v1` endpoint
- Replace `CertificateManager` X.509 logic with Ed25519 key management
- Add key caching with TTL-based refresh

### Phase 3: WebSocket Streaming

- Implement `/_wave/federation/v1/stream` WebSocket endpoint
- Server-to-server WebSocket connections for real-time delta push
- Automatic reconnection with history catch-up via HTTP

### Phase 4: Snapshot Sync

- Implement snapshot endpoint for fast initial federation
- DoltLite-based cold sync as alternative catch-up mechanism (experimental)

### Phase 5: LLM-Assisted Setup

- `supawave federation enable` command
- Interactive agent generates: `.well-known` file, signing keys, reverse proxy config
- Diagnostic agent for troubleshooting federation issues

## 9. Compatibility with Existing Code

The key insight is that **no changes to `WaveServerImpl` are needed**. The federation bus architecture is transport-agnostic:

```
                          ┌─────────────────────────┐
                          │     WaveServerImpl       │
                          │                          │
                          │  implements Provider     │
                          │  implements Listener.    │
                          │    Factory               │
                          └──────┬──────────┬────────┘
                                 │          │
              FederationRemote   │          │  FederationHost
              Bridge             │          │  Bridge
                                 │          │
                    ┌────────────▼─┐  ┌─────▼────────────┐
                    │  HttpFedRem  │  │  HttpFedHost      │
                    │              │  │                    │
                    │ HTTP client  │  │  Servlet endpoints │
                    │ → remote     │  │  ← remote          │
                    │   servers    │  │    servers          │
                    └──────────────┘  └────────────────────┘
```

The `NoOpFederationModule` is simply replaced with `HttpFederationModule` in the Guice configuration. All existing delta serialization, OT, certificate verification (adapted for Ed25519), and wavelet container logic remains unchanged.

## 10. Shareable Links (Parallel Track)

Independent of server-to-server federation, shareable links provide the lowest-friction collaboration path:

```
https://supawave.ai/w/abc123
https://supawave.ai/w/abc123?access=edit&token=<signed-jwt>
```

- **Read-only:** Extend existing public waves feature (already implemented)
- **Write access:** JWT-based guest tokens with configurable permissions
- **No account required:** Guest participants appear as `anonymous-<hash>@supawave.ai`
- **Upgradeable:** Guests can create accounts and retain their contributions

This requires zero federation infrastructure and delivers the highest immediate value for collaboration adoption.

## 11. Future Extensions

### DoltLite Cold Sync
For offline-capable and bandwidth-efficient catch-up, wavelet state could be stored in DoltLite tables. The prolly-tree structure enables efficient incremental sync — only changed chunks transfer. This would serve as an alternative to replaying HTTP history requests for large wavelets.

### S-Expression Lightweight Federation
For casual/development federation (e.g., two developers on a LAN), a pure S-expression-over-TCP mode inspired by IRC could provide a zero-infrastructure option:

```
CONNECT wave.local 6697
SUBSCRIBE example.com/w+abc123/conv+root
(delta ...)
(delta ...)
```

### Notary Servers
Third-party key attestation for high-security deployments, following Matrix's perspectives model.

### Bridging
Protocol bridges to Matrix, XMPP, or email for notification-level federation (not real-time OT, but presence and message forwarding).

---

## Appendix A: Mapping to Existing Interfaces

| HTTP Endpoint | Maps to Interface | Method |
|---------------|-------------------|--------|
| POST `/submit` | `WaveletFederationProvider` | `submitRequest()` |
| GET `/history/...` | `WaveletFederationProvider` | `requestHistory()` |
| GET `/_wave/keys/v1` | `WaveletFederationProvider` | `getDeltaSignerInfo()` (simplified) |
| POST `/submit` (inbound) | `WaveletFederationListener` | `waveletDeltaUpdate()` |
| WS `commit_update` | `WaveletFederationListener` | `waveletCommitUpdate()` |
| WS `subscribe` | `WaveletFederationListener.Factory` | `listenerForDomain()` |

## Appendix B: Example Federation Flow

**Setup:** Server A (`alpha.wave`) wants to federate with Server B (`beta.wave`).

1. **Discovery:** A fetches `https://beta.wave/.well-known/wave/server` → learns federation endpoint
2. **Key exchange:** A fetches `https://wave.beta.wave/_wave/keys/v1` → caches B's signing key
3. **User on A adds participant from B:** `user@beta.wave` added to wavelet on A
4. **A notifies B:** POST to B's submit endpoint with the add-participant delta, signed by A
5. **B verifies:** B fetches A's key (if not cached), verifies delta signature
6. **B subscribes:** B opens WebSocket to A's stream endpoint, subscribes to the wavelet
7. **Real-time sync:** A pushes deltas over WebSocket as users collaborate
8. **B user edits:** B submits delta to A via HTTP POST, A applies via OT, broadcasts to all subscribers
9. **Commit:** A sends commit updates over WebSocket when deltas are persisted

Total setup for server admin: serve one `.well-known` JSON file, ensure `/_wave/` routes reach the Wave server.
