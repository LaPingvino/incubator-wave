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
import org.json.JSONArray;
import org.json.JSONObject;
import org.waveprotocol.wave.util.logging.Log;

/**
 * Serves the Wave server discovery document at {@code /.well-known/wave/server}.
 *
 * <p>Remote Wave servers use this endpoint to discover the capabilities and
 * transport information of this server before initiating federation. The
 * response is a static JSON document describing the server address, supported
 * protocol version, transports, and serialization formats.
 *
 * <p>Response format:
 * <pre>{@code
 * {
 *   "w.server": "example.com",
 *   "w.protocol_version": "1.0",
 *   "w.transports": ["https", "wss"],
 *   "w.serialization": ["application/json", "application/protobuf"]
 * }
 * }</pre>
 */
@Singleton
public final class WellKnownWaveServlet extends HttpServlet {

  private static final Log LOG = Log.get(WellKnownWaveServlet.class);

  private final String serverAddress;

  /**
   * Constructs the servlet, reading the server address from configuration.
   *
   * @param config the Typesafe Config providing {@code core.wave_server_domain}
   *     and optionally {@code core.http_frontend_public_address}
   */
  @Inject
  public WellKnownWaveServlet(Config config) {
    // Prefer the public address if set, fall back to the wave server domain.
    if (config.hasPath("core.http_frontend_public_address")
        && !config.getString("core.http_frontend_public_address").isEmpty()) {
      this.serverAddress = config.getString("core.http_frontend_public_address");
    } else {
      this.serverAddress = config.getString("core.wave_server_domain");
    }
    LOG.info("WellKnownWaveServlet initialised for server: " + serverAddress);
  }

  /**
   * Handles GET requests by returning the server discovery JSON document.
   *
   * @param req the HTTP request
   * @param resp the HTTP response
   * @throws IOException if writing the response fails
   */
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    JSONObject json = new JSONObject();
    json.put("server", serverAddress);
    json.put("protocolVersion", "1.0");
    json.put("transports", new JSONArray().put("https").put("wss"));
    json.put("serializations",
        new JSONArray().put("application/json").put("application/protobuf"));

    setCorsHeaders(resp);
    resp.setContentType("application/json; charset=UTF-8");
    resp.setStatus(HttpServletResponse.SC_OK);
    resp.getWriter().write(json.toString());
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
