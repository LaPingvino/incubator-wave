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

import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.google.protobuf.ByteString;

import org.waveprotocol.wave.federation.Proto.ProtocolHashedVersion;
import org.waveprotocol.wave.federation.WaveletFederationListener;
import org.waveprotocol.wave.model.id.WaveletName;
import org.waveprotocol.wave.util.logging.Log;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Outbound notification system for pushing wavelet updates to remote servers
 * that are interested in locally-hosted wavelets.
 *
 * <p>Implements {@link WaveletFederationListener.Factory} to provide per-domain
 * listeners. Each listener is cached so that the same instance is reused for
 * all notifications to a given domain.
 *
 * <p><b>Phase 1 behavior:</b> Updates are logged but not actively pushed to remote
 * servers. Remote servers are expected to catch up by polling the history endpoint.
 * In Phase 2, real-time push notifications will be added via WebSocket.
 */
@Singleton
public class HttpFederationHost implements WaveletFederationListener.Factory {

  private static final Log LOG = Log.get(HttpFederationHost.class);

  private final FederationJsonCodec codec;
  private final FederationDiscoveryClient discoveryClient;
  private final ConcurrentHashMap<String, WaveletFederationListener> listenerCache;

  /**
   * Constructs a new HTTP federation host.
   *
   * @param codec JSON codec for encoding federation messages
   * @param discoveryClient client for discovering remote server addresses
   */
  @Inject
  public HttpFederationHost(FederationJsonCodec codec,
      FederationDiscoveryClient discoveryClient) {
    this.codec = codec;
    this.discoveryClient = discoveryClient;
    this.listenerCache = new ConcurrentHashMap<>();
  }

  /**
   * Returns a {@link WaveletFederationListener} for the given remote domain.
   *
   * <p>Listeners are cached per domain so that repeated calls with the same domain
   * return the same instance.
   *
   * @param domain the recipient domain for updates
   * @return a listener that handles update delivery to the given domain
   */
  @Override
  public WaveletFederationListener listenerForDomain(String domain) {
    return listenerCache.computeIfAbsent(domain, d -> new DomainListener(d));
  }

  /**
   * Per-domain listener implementation.
   *
   * <p>In Phase 1, this logs updates and immediately calls back with success.
   * Remote servers will catch up via the history endpoint. In Phase 2, this
   * will push updates over WebSocket connections.
   */
  private static class DomainListener implements WaveletFederationListener {

    private static final Log LOG = Log.get(DomainListener.class);

    private final String domain;

    DomainListener(String domain) {
      this.domain = domain;
    }

    /**
     * Handles a delta update notification for a remote domain.
     *
     * <p>Phase 1: Logs the update and signals success. Remote servers catch up
     * by polling the history endpoint.
     *
     * @param waveletName the wavelet that was updated
     * @param deltas the serialized applied deltas
     * @param callback callback to signal completion
     */
    @Override
    public void waveletDeltaUpdate(WaveletName waveletName, List<ByteString> deltas,
        WaveletUpdateCallback callback) {
      LOG.fine("Delta update for domain " + domain + " on wavelet " + waveletName
          + " (" + deltas.size() + " deltas). Phase 1: not pushing, remote will poll history.");
      callback.onSuccess();
    }

    /**
     * Handles a commit update notification for a remote domain.
     *
     * <p>Phase 1: Logs the commit and signals success. Remote servers catch up
     * by polling the history endpoint.
     *
     * @param waveletName the wavelet that was committed
     * @param committedVersion the version committed to persistent storage
     * @param callback callback to signal completion
     */
    @Override
    public void waveletCommitUpdate(WaveletName waveletName,
        ProtocolHashedVersion committedVersion, WaveletUpdateCallback callback) {
      LOG.fine("Commit update for domain " + domain + " on wavelet " + waveletName
          + " at version " + committedVersion.getVersion()
          + ". Phase 1: not pushing, remote will poll history.");
      callback.onSuccess();
    }
  }
}
