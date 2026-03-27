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

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.google.protobuf.ByteString;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.waveprotocol.box.server.frontend.CommittedWaveletSnapshot;
import org.waveprotocol.box.server.waveserver.WaveletProvider;
import org.waveprotocol.box.server.waveserver.WaveServerException;
import org.waveprotocol.wave.model.id.WaveId;
import org.waveprotocol.wave.model.id.WaveletId;
import org.waveprotocol.wave.model.id.WaveletName;
import org.waveprotocol.wave.model.operation.wave.TransformedWaveletDelta;
import org.waveprotocol.wave.model.version.HashedVersion;
import org.waveprotocol.wave.util.logging.Log;

/**
 * Serves delta history for locally-hosted wavelets to remote federation peers.
 *
 * <p>Handles
 * {@code GET /_wave/federation/v1/history/{wave_domain}/{wave_id}/{wavelet_domain}/{wavelet_id}}.
 *
 * <p>Query parameters:
 * <ul>
 *   <li>{@code start_version} (required) — inclusive start version number</li>
 *   <li>{@code start_hash} (optional) — base64url-encoded hash at start version</li>
 *   <li>{@code end_version} (required) — exclusive end version number</li>
 *   <li>{@code end_hash} (optional) — base64url-encoded hash at end version</li>
 *   <li>{@code limit} (optional) — maximum number of deltas to return (default 100)</li>
 *   <li>{@code domain} (optional) — the requesting server's domain</li>
 * </ul>
 *
 * <p>The response is a JSON object containing an array of delta summaries,
 * the committed version, and a truncation indicator.
 *
 * @see <a href="docs/wave-federation-spec-draft.md">Federation Protocol Spec, section 5.2</a>
 */
@Singleton
public final class FederationHistoryServlet extends HttpServlet {

  private static final Log LOG = Log.get(FederationHistoryServlet.class);
  private static final Gson GSON = new Gson();
  private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

  /** Default maximum number of deltas returned per request. */
  private static final int DEFAULT_LIMIT = 100;

  /**
   * Expected path prefix. The servlet container typically strips the base path,
   * so the pathInfo starts at the wavelet-name segments.
   */
  private static final String PATH_PREFIX = "/_wave/federation/v1/history/";

  private final WaveletProvider waveletProvider;

  /**
   * Constructs the history servlet.
   *
   * @param waveletProvider the local wave server providing delta history
   */
  @Inject
  public FederationHistoryServlet(WaveletProvider waveletProvider) {
    this.waveletProvider = waveletProvider;
    LOG.info("FederationHistoryServlet initialised");
  }

  /**
   * Handles GET requests for wavelet delta history.
   *
   * <p>The wavelet name components are extracted from the request path.
   * Version range and limit are taken from query parameters.
   */
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    try {
      WaveletName waveletName = parseWaveletNameFromPath(req);
      if (waveletName == null) {
        sendError(resp, HttpServletResponse.SC_BAD_REQUEST,
            "Invalid path: expected /_wave/federation/v1/history/"
                + "{wave_domain}/{wave_id}/{wavelet_domain}/{wavelet_id}");
        return;
      }

      String startVersionStr = req.getParameter("start_version");
      String endVersionStr = req.getParameter("end_version");
      if (startVersionStr == null || endVersionStr == null) {
        sendError(resp, HttpServletResponse.SC_BAD_REQUEST,
            "Missing required query parameters: start_version, end_version");
        return;
      }

      long startVersion;
      long endVersion;
      try {
        startVersion = Long.parseLong(startVersionStr);
        endVersion = Long.parseLong(endVersionStr);
      } catch (NumberFormatException e) {
        sendError(resp, HttpServletResponse.SC_BAD_REQUEST, "Invalid version number format");
        return;
      }

      if (startVersion < 0 || endVersion < startVersion) {
        sendError(resp, HttpServletResponse.SC_BAD_REQUEST,
            "Invalid version range: start_version must be >= 0 and <= end_version");
        return;
      }

      int limit = DEFAULT_LIMIT;
      String limitStr = req.getParameter("limit");
      if (limitStr != null) {
        try {
          int parsed = Integer.parseInt(limitStr);
          if (parsed > 0) limit = parsed;
        } catch (NumberFormatException ignored) { }
      }

      // Resolve hashed versions.
      HashedVersion startHV = resolveHashedVersion(
          waveletName, startVersion, req.getParameter("start_hash"));
      HashedVersion endHV = resolveHashedVersion(
          waveletName, endVersion, req.getParameter("end_hash"));

      if (startHV == null || endHV == null) {
        sendError(resp, HttpServletResponse.SC_NOT_FOUND,
            "Could not resolve hashed versions for the requested range");
        return;
      }

      // Collect deltas.
      List<TransformedWaveletDelta> deltas = new ArrayList<>();
      final int maxDeltas = limit;
      waveletProvider.getHistory(waveletName, startHV, endHV, delta -> {
        if (deltas.size() < maxDeltas) {
          deltas.add(delta);
          return true;
        }
        return false;
      });

      // Get committed version from snapshot.
      HashedVersion committedVersion = null;
      try {
        CommittedWaveletSnapshot snapshot = waveletProvider.getSnapshot(waveletName);
        if (snapshot != null) {
          committedVersion = snapshot.committedVersion;
        }
      } catch (WaveServerException e) {
        LOG.warning("Could not fetch snapshot for committed version", e);
      }

      // Check truncation.
      long truncatedAtVersion = -1;
      if (!deltas.isEmpty() && deltas.size() >= maxDeltas) {
        TransformedWaveletDelta lastDelta = deltas.get(deltas.size() - 1);
        long lastResultingVersion = lastDelta.getResultingVersion().getVersion();
        if (lastResultingVersion < endVersion) {
          truncatedAtVersion = lastResultingVersion;
        }
      }

      // Build JSON response using Gson.
      JsonObject responseJson = new JsonObject();
      responseJson.addProperty("wavelet_name",
          waveletName.waveId.getDomain() + "/"
              + waveletName.waveId.getId() + "/"
              + waveletName.waveletId.getDomain() + "/"
              + waveletName.waveletId.getId());

      JsonArray deltasJson = new JsonArray();
      for (TransformedWaveletDelta delta : deltas) {
        JsonObject d = new JsonObject();
        d.addProperty("version", delta.getAppliedAtVersion());
        d.addProperty("resulting_version", delta.getResultingVersion().getVersion());
        d.addProperty("author", delta.getAuthor().getAddress());
        d.addProperty("application_timestamp", delta.getApplicationTimestamp());
        d.addProperty("operations_count", delta.size());
        deltasJson.add(d);
      }
      responseJson.add("deltas", deltasJson);

      if (committedVersion != null) {
        responseJson.addProperty("committed_version", committedVersion.getVersion());
        if (committedVersion.getHistoryHash().length > 0) {
          responseJson.addProperty("committed_version_hash",
              BASE64URL.encodeToString(committedVersion.getHistoryHash()));
        }
      }
      responseJson.addProperty("truncated_at_version", truncatedAtVersion);

      setCorsHeaders(resp);
      resp.setContentType("application/json; charset=UTF-8");
      resp.setStatus(HttpServletResponse.SC_OK);
      resp.getWriter().write(GSON.toJson(responseJson));

    } catch (WaveServerException e) {
      LOG.warning("Wave server error while serving history", e);
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
          "Wave server error: " + e.getMessage());
    } catch (Exception e) {
      LOG.warning("Unexpected error serving history", e);
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
          "Internal error: " + e.getMessage());
    }
  }

  /** Handles CORS preflight requests. */
  @Override
  protected void doOptions(HttpServletRequest req, HttpServletResponse resp) {
    setCorsHeaders(resp);
    resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
  }

  /**
   * Resolves a {@link HashedVersion} for the given wavelet and version number.
   * If a hash parameter is provided, it is used directly; otherwise the wave
   * server is queried.
   */
  private HashedVersion resolveHashedVersion(
      WaveletName waveletName, long version, String hashParam) {
    if (hashParam != null && !hashParam.isEmpty()) {
      try {
        byte[] hash = Base64.getUrlDecoder().decode(hashParam);
        return HashedVersion.of(version, hash);
      } catch (IllegalArgumentException e) {
        LOG.warning("Invalid base64url hash parameter: " + hashParam);
        return null;
      }
    }
    try {
      return waveletProvider.getHashedVersion(waveletName, version);
    } catch (WaveServerException e) {
      LOG.warning("Could not resolve hashed version " + version
          + " for " + waveletName, e);
      return null;
    }
  }

  /**
   * Extracts the wavelet name from the servlet request path.
   * Supports both full URI path and pathInfo styles.
   */
  private static WaveletName parseWaveletNameFromPath(HttpServletRequest req) {
    String path = req.getPathInfo();
    if (path == null) {
      path = req.getRequestURI();
      if (path.startsWith(PATH_PREFIX)) {
        path = path.substring(PATH_PREFIX.length());
      }
    } else if (path.startsWith("/")) {
      path = path.substring(1);
    }

    if (path == null || path.isEmpty()) return null;

    String[] parts = path.split("/");
    if (parts.length != 4) return null;

    try {
      WaveId waveId = WaveId.of(parts[0], parts[1]);
      WaveletId waveletId = WaveletId.of(parts[2], parts[3]);
      return WaveletName.of(waveId, waveletId);
    } catch (Exception e) {
      LOG.warning("Failed to parse wavelet name from path: " + path, e);
      return null;
    }
  }

  private static void sendError(HttpServletResponse resp, int status, String message)
      throws IOException {
    setCorsHeaders(resp);
    resp.setContentType("application/json; charset=UTF-8");
    resp.setStatus(status);
    resp.getWriter().write("{\"error\":\"" + message.replace("\"", "\\\"") + "\"}");
  }

  private static void setCorsHeaders(HttpServletResponse resp) {
    resp.setHeader("Access-Control-Allow-Origin", "*");
    resp.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    resp.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }
}
