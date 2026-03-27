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
import com.typesafe.config.Config;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;
import org.waveprotocol.wave.util.logging.Log;

/**
 * Serves the federation signing keys at {@code /_wave/keys/v1}.
 *
 * <p>Remote Wave servers fetch this endpoint to obtain the public keys used
 * by this server to sign delta submissions. The response includes the current
 * signing key(s) and their validity period.
 *
 * <p>Response format:
 * <pre>{@code
 * {
 *   "server_name": "example.com",
 *   "signing_keys": {
 *     "ed25519:wave01": {
 *       "key": "<base64url-encoded-public-key>"
 *     }
 *   },
 *   "old_signing_keys": {},
 *   "valid_until_ts": <epoch-millis-24h-from-now>
 * }
 * }</pre>
 */
@Singleton
public final class FederationKeysServlet extends HttpServlet {

  private static final Log LOG = Log.get(FederationKeysServlet.class);

  /** Validity period for key responses: 24 hours in milliseconds. */
  private static final long KEY_VALIDITY_MILLIS = TimeUnit.HOURS.toMillis(24);

  private final String serverDomain;
  private final FederationKeyManager keyManager;

  /**
   * Constructs the servlet with the key manager and server configuration.
   *
   * @param keyManager the federation key manager holding the server's signing keys
   * @param config the Typesafe Config providing {@code core.wave_server_domain}
   */
  @Inject
  public FederationKeysServlet(FederationKeyManager keyManager, Config config) {
    this.keyManager = keyManager;
    this.serverDomain = config.getString("core.wave_server_domain");
    LOG.info("FederationKeysServlet initialised for domain: " + serverDomain);
  }

  /**
   * Handles GET requests by returning the server's current signing keys.
   *
   * @param req the HTTP request
   * @param resp the HTTP response
   * @throws IOException if writing the response fails
   */
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    try {
      byte[] publicKey = keyManager.getPublicKeyBytes();
      String keyId = keyManager.getKeyId();

      String base64UrlKey = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey);

      // Flat map of keyId → base64url public key, matching what
      // FederationKeyClient.parseKeysResponse() expects.
      JSONObject signingKeys = new JSONObject();
      signingKeys.put(keyId, base64UrlKey);

      JSONObject json = new JSONObject();
      json.put("server", serverDomain);
      json.put("signingKeys", signingKeys);
      json.put("validUntilTs", System.currentTimeMillis() + KEY_VALIDITY_MILLIS);

      setCorsHeaders(resp);
      resp.setContentType("application/json; charset=UTF-8");
      resp.setStatus(HttpServletResponse.SC_OK);
      resp.getWriter().write(json.toString());
    } catch (Exception e) {
      LOG.warning("Failed to serve federation keys", e);
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
          "Failed to retrieve signing keys");
    }
  }

  /**
   * Handles CORS preflight requests for federation endpoints.
   */
  @Override
  protected void doOptions(HttpServletRequest req, HttpServletResponse resp) {
    setCorsHeaders(resp);
    resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
  }

  /**
   * Writes a JSON error response with the specified HTTP status code.
   *
   * @param resp the HTTP response
   * @param status the HTTP status code
   * @param message the error message
   * @throws IOException if writing the response fails
   */
  private static void sendError(HttpServletResponse resp, int status, String message)
      throws IOException {
    JSONObject error = new JSONObject();
    error.put("error", message);
    setCorsHeaders(resp);
    resp.setContentType("application/json; charset=UTF-8");
    resp.setStatus(status);
    resp.getWriter().write(error.toString());
  }

  /**
   * Sets standard CORS headers required for cross-origin federation requests.
   *
   * @param resp the HTTP response to add headers to
   */
  private static void setCorsHeaders(HttpServletResponse resp) {
    resp.setHeader("Access-Control-Allow-Origin", "*");
    resp.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    resp.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }
}
