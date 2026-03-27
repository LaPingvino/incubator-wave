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

import com.google.gson.JsonArray;
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Fetches and caches {@code .well-known/wave/server} discovery responses from remote
 * Wave federation servers.
 *
 * <p>When a local server needs to communicate with a remote Wave server, it first
 * discovers the remote server's federation endpoint by making an HTTPS GET request
 * to {@code https://<domain>/.well-known/wave/server}. The response contains the
 * server address, protocol version, supported transports, and serialization formats.
 *
 * <p>Results are cached in memory with a configurable TTL to avoid repeated network
 * requests. The cache is thread-safe and uses {@link ConcurrentHashMap} for storage.
 */
@Singleton
public class FederationDiscoveryClient {

  private static final Logger LOG = Logger.getLogger(FederationDiscoveryClient.class.getName());

  private static final String WELL_KNOWN_PATH = "/.well-known/wave/server";

  /**
   * Contains the discovery information returned by a remote Wave server.
   */
  public static class DiscoveryResult {
    private final String serverAddress;
    private final String protocolVersion;
    private final List<String> transports;
    private final List<String> serializations;

    public DiscoveryResult(String serverAddress, String protocolVersion,
        List<String> transports, List<String> serializations) {
      this.serverAddress = serverAddress;
      this.protocolVersion = protocolVersion;
      this.transports = Collections.unmodifiableList(new ArrayList<>(transports));
      this.serializations = Collections.unmodifiableList(new ArrayList<>(serializations));
    }

    /** Returns the federation server address (host:port). */
    public String getServerAddress() { return serverAddress; }

    /** Returns the federation protocol version string (e.g. "0.4"). */
    public String getProtocolVersion() { return protocolVersion; }

    /** Returns the list of supported transport protocols (e.g. ["http", "xmpp"]). */
    public List<String> getTransports() { return transports; }

    /** Returns the list of supported serialization formats (e.g. ["json", "protobuf"]). */
    public List<String> getSerializations() { return serializations; }

    @Override
    public String toString() {
      return "DiscoveryResult{server=" + serverAddress + ", version=" + protocolVersion
          + ", transports=" + transports + ", serializations=" + serializations + "}";
    }
  }

  /**
   * A cached discovery result with an expiration timestamp.
   */
  private static class CachedEntry {
    final DiscoveryResult result;
    final long expiresAtMs;

    CachedEntry(DiscoveryResult result, long expiresAtMs) {
      this.result = result;
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
   * Creates a new discovery client with the specified cache TTL.
   *
   * @param cacheTtlMs time-to-live for cached discovery results, in milliseconds
   */
  @Inject
  public FederationDiscoveryClient(
      @Named("federation_discovery_cache_ttl_ms") long cacheTtlMs) {
    this.cacheTtlMs = cacheTtlMs;
    this.httpClient = HttpClients.createDefault();
  }

  /**
   * Discovers the federation endpoint for a remote Wave server by fetching
   * {@code https://<domain>/.well-known/wave/server}.
   *
   * <p>If a cached, non-expired result exists for the given domain, it is returned
   * immediately without a network request. Otherwise, an HTTPS GET request is made
   * and the result is cached for future use.
   *
   * <p>The returned {@link CompletableFuture} completes on a background thread.
   * If the HTTP request fails or the response is malformed, the future completes
   * exceptionally with an {@link IOException} or {@link RuntimeException}.
   *
   * @param domain the domain to discover (e.g. "wave.example.com")
   * @return a future that resolves to the discovery result
   */
  public CompletableFuture<DiscoveryResult> discover(String domain) {
    CachedEntry cached = cache.get(domain);
    if (cached != null && !cached.isExpired()) {
      return CompletableFuture.completedFuture(cached.result);
    }

    return CompletableFuture.supplyAsync(() -> {
      String url = "https://" + domain + WELL_KNOWN_PATH;
      HttpGet request = new HttpGet(url);
      request.setHeader("Accept", "application/json");

      try (CloseableHttpResponse response = httpClient.execute(request)) {
        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != 200) {
          throw new IOException("Discovery request to " + url + " returned HTTP " + statusCode);
        }

        String body = EntityUtils.toString(response.getEntity(), "UTF-8");
        DiscoveryResult result = parseDiscoveryResponse(body);

        cache.put(domain, new CachedEntry(result,
            System.currentTimeMillis() + cacheTtlMs));

        LOG.info("Discovered federation server for " + domain + ": " + result);
        return result;
      } catch (IOException e) {
        LOG.log(Level.WARNING, "Failed to discover federation server for " + domain, e);
        throw new RuntimeException("Discovery failed for " + domain, e);
      }
    });
  }

  /**
   * Parses a discovery JSON response into a {@link DiscoveryResult}.
   *
   * @param json the raw JSON response body
   * @return the parsed result
   */
  private static DiscoveryResult parseDiscoveryResponse(String json) {
    JsonObject root = JsonParser.parseString(json).getAsJsonObject();

    String serverAddress = root.get("server").getAsString();
    String protocolVersion = root.get("protocolVersion").getAsString();

    List<String> transports = parseStringArray(root.getAsJsonArray("transports"));
    List<String> serializations = parseStringArray(root.getAsJsonArray("serializations"));

    return new DiscoveryResult(serverAddress, protocolVersion, transports, serializations);
  }

  /**
   * Blocking convenience method that discovers the federation server address
   * for a remote domain and returns just the server address string.
   *
   * <p>This method is intended for use by {@link HttpFederationRemote} where
   * the caller is already on an executor thread and blocking is acceptable.
   *
   * @param domain the domain to discover
   * @return the server address (host:port), or {@code null} if discovery fails
   */
  public String discoverServer(String domain) {
    try {
      DiscoveryResult result = discover(domain).join();
      return result.getServerAddress();
    } catch (Exception e) {
      LOG.log(Level.WARNING, "discoverServer failed for " + domain, e);
      return null;
    }
  }

  /**
   * Invalidates the cached discovery result for a domain, forcing a fresh fetch
   * on the next call to {@link #discover(String)}.
   *
   * @param domain the domain whose cache entry to remove
   */
  public void invalidate(String domain) {
    cache.remove(domain);
  }

  private static List<String> parseStringArray(JsonArray array) {
    List<String> result = new ArrayList<>();
    if (array != null) {
      for (JsonElement element : array) {
        result.add(element.getAsString());
      }
    }
    return result;
  }
}
