/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.waveprotocol.wave.federation.http;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.google.inject.name.Named;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Fetches and caches signing keys from remote Wave servers' {@code /_wave/keys/v1} endpoint.
 *
 * <p>When verifying signatures on incoming federation messages, this client retrieves
 * the signing public keys from the originating server. Results are cached with a
 * configurable TTL to minimize network traffic and latency.
 *
 * <p>The cache is thread-safe, using {@link ConcurrentHashMap} for storage. Individual
 * key lookups can be performed synchronously via {@link #getPublicKey(String, String)}
 * or asynchronously via {@link #fetchKeys(String)}.
 */
@Singleton
public class FederationKeyClient {

  private static final Logger LOG = Logger.getLogger(FederationKeyClient.class.getName());

  private static final String KEYS_PATH = "/_wave/keys/v1";
  private static final Base64.Decoder BASE64URL_DECODER = Base64.getUrlDecoder();

  /**
   * Contains the signing key information returned by a remote Wave server.
   */
  public static class RemoteKeyInfo {
    private final String serverName;
    private final Map<String, byte[]> signingKeys;
    private final long validUntilTs;

    /**
     * Creates a new remote key info.
     *
     * @param serverName the server name
     * @param signingKeys map of key ID to raw public key bytes
     * @param validUntilTs timestamp (ms since epoch) until which the keys are valid
     */
    public RemoteKeyInfo(String serverName, Map<String, byte[]> signingKeys, long validUntilTs) {
      this.serverName = serverName;
      this.signingKeys = Collections.unmodifiableMap(new HashMap<>(signingKeys));
      this.validUntilTs = validUntilTs;
    }

    /** Returns the server name that owns these keys. */
    public String getServerName() { return serverName; }

    /**
     * Returns an unmodifiable map of key ID to public key bytes.
     * Key IDs follow the format {@code "ed25519:<name>"}.
     */
    public Map<String, byte[]> getSigningKeys() { return signingKeys; }

    /** Returns the timestamp (ms since epoch) until which these keys are valid. */
    public long getValidUntilTs() { return validUntilTs; }

    @Override
    public String toString() {
      return "RemoteKeyInfo{server=" + serverName + ", keys=" + signingKeys.size()
          + ", validUntil=" + validUntilTs + "}";
    }
  }

  /**
   * A cached key info entry with an expiration timestamp.
   */
  private static class CachedEntry {
    final RemoteKeyInfo info;
    final long expiresAtMs;

    CachedEntry(RemoteKeyInfo info, long expiresAtMs) {
      this.info = info;
      this.expiresAtMs = expiresAtMs;
    }

    boolean isExpired() {
      return System.currentTimeMillis() >= expiresAtMs;
    }
  }

  private final long cacheTtlMs;
  private final ConcurrentHashMap<String, CachedEntry> cache = new ConcurrentHashMap<>();
  private final CloseableHttpClient httpClient;

  /**
   * Creates a new key client with the specified cache TTL.
   *
   * @param cacheTtlMs time-to-live for cached key information, in milliseconds
   */
  @Inject
  public FederationKeyClient(@Named("federation_key_cache_ttl_ms") long cacheTtlMs) {
    this.cacheTtlMs = cacheTtlMs;
    this.httpClient = HttpClients.createDefault();
  }

  /**
   * Asynchronously fetches signing keys from a remote server's {@code /_wave/keys/v1} endpoint.
   *
   * <p>If a cached, non-expired result exists for the given server address, it is returned
   * immediately. Otherwise, an HTTPS GET request is made to
   * {@code https://<serverAddress>/_wave/keys/v1} and the result is cached.
   *
   * <p>The expected JSON response format is:
   * <pre>{
   *   "server": "wave.example.com",
   *   "signingKeys": {
   *     "ed25519:wave01": "&lt;base64url-public-key&gt;"
   *   },
   *   "validUntilTs": 1700000000000
   * }</pre>
   *
   * @param serverAddress the server address to fetch keys from (e.g. "wave.example.com:443")
   * @return a future that resolves to the remote key info
   */
  public CompletableFuture<RemoteKeyInfo> fetchKeys(String serverAddress) {
    CachedEntry cached = cache.get(serverAddress);
    if (cached != null && !cached.isExpired()) {
      return CompletableFuture.completedFuture(cached.info);
    }

    return CompletableFuture.supplyAsync(() -> {
      String url = "https://" + serverAddress + KEYS_PATH;
      HttpGet request = new HttpGet(url);
      request.setHeader("Accept", "application/json");

      try (CloseableHttpResponse response = httpClient.execute(request)) {
        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != 200) {
          throw new IOException("Key fetch from " + url + " returned HTTP " + statusCode);
        }

        String body = EntityUtils.toString(response.getEntity(), "UTF-8");
        RemoteKeyInfo info = parseKeysResponse(body);

        // Use the minimum of the server's validUntilTs and our cache TTL for expiration.
        long expiresAt = Math.min(
            info.getValidUntilTs(),
            System.currentTimeMillis() + cacheTtlMs);
        cache.put(serverAddress, new CachedEntry(info, expiresAt));

        LOG.info("Fetched signing keys from " + serverAddress + ": " + info);
        return info;
      } catch (IOException e) {
        LOG.log(Level.WARNING, "Failed to fetch keys from " + serverAddress, e);
        throw new RuntimeException("Key fetch failed for " + serverAddress, e);
      }
    });
  }

  /**
   * Gets a specific public key from a remote server, fetching keys if not already cached.
   *
   * <p>This is a blocking convenience method. It fetches the keys from the remote server
   * (or uses cached values) and returns the public key bytes for the specified key ID.
   *
   * @param serverAddress the server address to fetch keys from
   * @param keyId the key identifier (e.g. "ed25519:wave01")
   * @return the raw public key bytes, or {@code null} if the key ID is not found
   * @throws RuntimeException if the key fetch fails
   */
  public byte[] getPublicKey(String serverAddress, String keyId) {
    try {
      RemoteKeyInfo info = fetchKeys(serverAddress).get();
      return info.getSigningKeys().get(keyId);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RuntimeException("Interrupted while fetching keys from " + serverAddress, e);
    } catch (ExecutionException e) {
      throw new RuntimeException("Failed to fetch keys from " + serverAddress, e.getCause());
    }
  }

  /**
   * Fetches remote signing keys and builds a {@link ProtocolSignerInfo} compatible
   * with the federation bus.
   *
   * <p>This is a convenience method for {@link HttpFederationRemote#getDeltaSignerInfo}.
   * It maps the HTTP key exchange model to the protobuf-based signer info model.
   *
   * @param domain the remote domain to fetch keys from
   * @param signerId the signer ID (ignored in HTTP federation; keys are domain-level)
   * @return a synthetic {@link ProtocolSignerInfo}, or {@code null} if fetch fails
   */
  public org.waveprotocol.wave.federation.Proto.ProtocolSignerInfo fetchSignerInfo(
      String domain, com.google.protobuf.ByteString signerId) {
    try {
      RemoteKeyInfo info = fetchKeys(domain).get();
      if (info == null || info.getSigningKeys().isEmpty()) {
        return null;
      }
      // Build a ProtocolSignerInfo from the HTTP key info.
      // In HTTP federation, the "certificate" is the raw public key bytes.
      org.waveprotocol.wave.federation.Proto.ProtocolSignerInfo.Builder builder =
          org.waveprotocol.wave.federation.Proto.ProtocolSignerInfo.newBuilder();
      builder.setHashAlgorithm(
          org.waveprotocol.wave.federation.Proto.ProtocolSignerInfo.HashAlgorithm.SHA256);
      builder.setDomain(info.getServerName());
      for (byte[] keyBytes : info.getSigningKeys().values()) {
        builder.addCertificate(com.google.protobuf.ByteString.copyFrom(keyBytes));
      }
      return builder.build();
    } catch (Exception e) {
      LOG.log(Level.WARNING, "fetchSignerInfo failed for domain " + domain, e);
      return null;
    }
  }

  /**
   * Invalidates the cached key info for a server, forcing a fresh fetch on the
   * next request.
   *
   * @param serverAddress the server address whose cache entry to remove
   */
  public void invalidate(String serverAddress) {
    cache.remove(serverAddress);
  }

  /**
   * Parses a keys JSON response into a {@link RemoteKeyInfo}.
   */
  private static RemoteKeyInfo parseKeysResponse(String json) {
    JsonObject root = JsonParser.parseString(json).getAsJsonObject();

    String serverName = root.get("server").getAsString();
    long validUntilTs = root.get("validUntilTs").getAsLong();

    Map<String, byte[]> signingKeys = new HashMap<>();
    JsonObject keysObj = root.getAsJsonObject("signingKeys");
    for (Map.Entry<String, JsonElement> entry : keysObj.entrySet()) {
      byte[] keyBytes = BASE64URL_DECODER.decode(entry.getValue().getAsString());
      signingKeys.put(entry.getKey(), keyBytes);
    }

    return new RemoteKeyInfo(serverName, signingKeys, validUntilTs);
  }
}
