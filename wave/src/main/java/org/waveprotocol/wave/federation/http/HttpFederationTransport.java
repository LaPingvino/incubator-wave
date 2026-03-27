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

import org.waveprotocol.wave.federation.FederationTransport;
import org.waveprotocol.wave.util.logging.Log;

/**
 * HTTP-based federation transport implementation.
 *
 * <p>Performs startup verification of the federation subsystem, ensuring that
 * the local server's signing keys are available and valid before federation
 * operations begin.
 */
@Singleton
public class HttpFederationTransport implements FederationTransport {

  private static final Log LOG = Log.get(HttpFederationTransport.class);

  private final FederationKeyManager keyManager;

  /**
   * Constructs a new HTTP federation transport.
   *
   * @param keyManager the key manager used for signing and key verification
   */
  @Inject
  public HttpFederationTransport(FederationKeyManager keyManager) {
    this.keyManager = keyManager;
  }

  /**
   * Starts the HTTP federation subsystem.
   *
   * <p>Verifies that the key manager has valid signing keys and logs the
   * server's key ID and domain. If key verification fails, an error is logged
   * but startup continues (federation requests will fail individually).
   */
  @Override
  public void startFederation() {
    LOG.info("Starting HTTP federation transport...");

    try {
      // Verify the key manager initialized successfully by checking that a
      // public key is available. The constructor would have thrown if key
      // generation/loading failed, but belt-and-suspenders here.
      byte[] pubKey = keyManager.getPublicKeyBytes();
      if (pubKey == null || pubKey.length == 0) {
        LOG.severe("Federation key manager does not have valid signing keys. "
            + "Federation operations will fail until keys are configured.");
      } else {
        LOG.info("Federation key ID: " + keyManager.getKeyId());
        LOG.info("Federation domain: " + keyManager.getDomain());
        LOG.info("Federation public key: " + keyManager.getPublicKeyBase64Url());
      }
    } catch (Exception e) {
      LOG.severe("Error verifying federation keys during startup", e);
    }

    LOG.info("HTTP federation transport started successfully.");
  }
}
