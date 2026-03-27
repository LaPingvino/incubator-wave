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

import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.inject.Singleton;
import com.google.inject.name.Named;
import com.typesafe.config.Config;

import org.waveprotocol.wave.federation.FederationHostBridge;
import org.waveprotocol.wave.federation.FederationRemoteBridge;
import org.waveprotocol.wave.federation.FederationTransport;
import org.waveprotocol.wave.federation.WaveletFederationListener;
import org.waveprotocol.wave.federation.WaveletFederationProvider;

/**
 * Guice module for the HTTP federation subsystem.
 *
 * <p>Binds the federation provider, listener factory, and transport to their
 * HTTP implementations, mirroring the structure of
 * {@code org.waveprotocol.wave.federation.noop.NoOpFederationModule}.
 *
 * <p>Also binds the supporting infrastructure classes ({@link FederationJsonCodec},
 * {@link FederationKeyManager}, {@link FederationDiscoveryClient},
 * {@link FederationKeyClient}) and configuration values extracted from the
 * application's {@link Config}.
 */
public class HttpFederationModule extends AbstractModule {

  @Override
  protected void configure() {
    // Core federation bus bindings (mirrors NoOpFederationModule)
    bind(WaveletFederationProvider.class).annotatedWith(FederationRemoteBridge.class)
        .to(HttpFederationRemote.class).in(Singleton.class);

    bind(WaveletFederationListener.Factory.class).annotatedWith(FederationHostBridge.class)
        .to(HttpFederationHost.class).in(Singleton.class);

    bind(FederationTransport.class).to(HttpFederationTransport.class).in(Singleton.class);

    // Infrastructure singletons
    bind(FederationJsonCodec.class).in(Singleton.class);
    bind(FederationKeyManager.class).in(Singleton.class);
    bind(FederationDiscoveryClient.class).in(Singleton.class);
    bind(FederationKeyClient.class).in(Singleton.class);
  }

  /**
   * Provides the file path to the Ed25519 signing key.
   *
   * @param config the application configuration
   * @return the signing key file path
   */
  @Provides
  @Named("federation_signing_key_path")
  String signingKeyPath(Config config) {
    return config.getString("federation.signing_key_path");
  }

  /**
   * Provides the identifier for the server's signing key.
   *
   * @param config the application configuration
   * @return the signing key ID (e.g., "ed25519:wave01")
   */
  @Provides
  @Named("federation_signing_key_id")
  String signingKeyId(Config config) {
    return config.getString("federation.signing_key_id");
  }

  /**
   * Provides the TTL in milliseconds for cached remote signing keys.
   *
   * @param config the application configuration
   * @return the key cache TTL in milliseconds
   */
  @Provides
  @Named("federation_key_cache_ttl_ms")
  long keyCacheTtlMs(Config config) {
    return config.getLong("federation.key_cache_ttl_ms");
  }

  /**
   * Provides the TTL in milliseconds for cached discovery results.
   *
   * @param config the application configuration
   * @return the discovery cache TTL in milliseconds
   */
  @Provides
  @Named("federation_discovery_cache_ttl_ms")
  long discoveryCacheTtlMs(Config config) {
    return config.getLong("federation.discovery_cache_ttl_ms");
  }

  // Note: @Named("wave_server_domain") is already bound by the parent
  // injector in ServerMain. It does not need to be re-provided here.
  // FederationKeyManager and other classes that inject it will receive
  // the value from the parent binding.
}
