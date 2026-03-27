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
import com.google.protobuf.InvalidProtocolBufferException;
import com.typesafe.config.Config;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.waveprotocol.box.server.waveserver.WaveletProvider;
import org.waveprotocol.wave.federation.Proto.ProtocolSignedDelta;
import org.waveprotocol.wave.federation.Proto.ProtocolWaveletDelta;
import org.waveprotocol.wave.model.id.WaveletName;
import org.waveprotocol.wave.model.version.HashedVersion;
import org.waveprotocol.wave.util.logging.Log;

/**
 * Receives delta submissions from remote Wave servers for wavelets hosted on
 * this server.
 *
 * <p>Handles {@code POST /_wave/federation/v1/submit}. The request body is a
 * JSON-encoded submit request containing a wavelet name and a signed delta
 * (encoded using {@link FederationJsonCodec}).
 *
 * <p>The servlet extracts the inner {@link ProtocolWaveletDelta} from the
 * signed delta wrapper and forwards it to the local {@link WaveletProvider}
 * for OT transformation and application.
 *
 * @see FederationJsonCodec#decodeSubmitRequest(String)
 * @see <a href="docs/wave-federation-spec-draft.md">Federation Protocol Spec</a>
 */
@Singleton
public final class FederationSubmitServlet extends HttpServlet {

  private static final Log LOG = Log.get(FederationSubmitServlet.class);

  /** Maximum time in seconds to wait for a submit to complete. */
  private static final long SUBMIT_TIMEOUT_SECONDS = 30;

  private final WaveletProvider waveletProvider;
  private final FederationJsonCodec codec;
  private final boolean verifySignatures;

  /**
   * Constructs the submit servlet.
   *
   * @param waveletProvider the local wave server for applying deltas
   * @param codec the JSON codec for decoding/encoding federation messages
   * @param config application configuration; when
   *     {@code federation.waveserver_disable_verification} is true, signature
   *     verification is skipped (the default for Phase 1)
   */
  @Inject
  public FederationSubmitServlet(
      WaveletProvider waveletProvider,
      FederationJsonCodec codec,
      Config config) {
    this.waveletProvider = waveletProvider;
    this.codec = codec;
    // Default: verification disabled (matches existing config default)
    this.verifySignatures = config.hasPath("federation.waveserver_disable_verification")
        ? !config.getBoolean("federation.waveserver_disable_verification")
        : false;
    LOG.info("FederationSubmitServlet initialised (signature verification: "
        + verifySignatures + ")");
  }

  /**
   * Handles POST requests containing a delta submission from a remote server.
   *
   * <p>Flow:
   * <ol>
   *   <li>Read and parse the JSON request body via {@link FederationJsonCodec}</li>
   *   <li>Extract the inner {@link ProtocolWaveletDelta} from the signed wrapper</li>
   *   <li>Submit to the local wave server via {@link WaveletProvider#submitRequest}</li>
   *   <li>Block until the submission completes (with timeout)</li>
   *   <li>Return the result as JSON</li>
   * </ol>
   *
   * @param req the HTTP request containing the JSON-encoded submit
   * @param resp the HTTP response
   * @throws IOException if reading the request or writing the response fails
   */
  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String body = readBody(req);
    if (body == null || body.isEmpty()) {
      sendError(resp, HttpServletResponse.SC_BAD_REQUEST, "Empty request body");
      return;
    }

    try {
      // Decode the submit request using the federation JSON codec.
      FederationJsonCodec.SubmitRequest submitRequest = codec.decodeSubmitRequest(body);
      WaveletName waveletName = submitRequest.getWaveletName();
      ProtocolSignedDelta signedDelta = submitRequest.getDelta();

      // Extract the inner ProtocolWaveletDelta from the signed delta bytes.
      ProtocolWaveletDelta delta;
      try {
        delta = ProtocolWaveletDelta.parseFrom(signedDelta.getDelta());
      } catch (InvalidProtocolBufferException e) {
        sendError(resp, HttpServletResponse.SC_BAD_REQUEST,
            "Invalid delta encoding: " + e.getMessage());
        return;
      }

      // Submit synchronously using a latch-based callback.
      CountDownLatch latch = new CountDownLatch(1);
      AtomicReference<String> resultRef = new AtomicReference<>();
      AtomicReference<String> errorRef = new AtomicReference<>();

      waveletProvider.submitRequest(waveletName, delta,
          new WaveletProvider.SubmitRequestListener() {
            @Override
            public void onSuccess(int operationsApplied,
                HashedVersion hashedVersionAfterApplication, long applicationTimestamp) {
              // Build a ProtocolHashedVersion for the codec
              org.waveprotocol.wave.federation.Proto.ProtocolHashedVersion protoVersion =
                  org.waveprotocol.wave.federation.Proto.ProtocolHashedVersion.newBuilder()
                      .setVersion(hashedVersionAfterApplication.getVersion())
                      .setHistoryHash(com.google.protobuf.ByteString.copyFrom(
                          hashedVersionAfterApplication.getHistoryHash()))
                      .build();
              resultRef.set(codec.encodeSubmitResponse(
                  operationsApplied, protoVersion, applicationTimestamp));
              latch.countDown();
            }

            @Override
            public void onFailure(String errorMessage) {
              errorRef.set(errorMessage);
              latch.countDown();
            }
          });

      boolean completed = latch.await(SUBMIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
      if (!completed) {
        sendError(resp, HttpServletResponse.SC_GATEWAY_TIMEOUT,
            "Submit request timed out");
        return;
      }

      String error = errorRef.get();
      if (error != null) {
        sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, error);
        return;
      }

      setCorsHeaders(resp);
      resp.setContentType("application/json; charset=UTF-8");
      resp.setStatus(HttpServletResponse.SC_OK);
      resp.getWriter().write(resultRef.get());

    } catch (IllegalArgumentException e) {
      LOG.warning("Malformed submit request: " + e.getMessage());
      sendError(resp, HttpServletResponse.SC_BAD_REQUEST,
          "Malformed request: " + e.getMessage());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      sendError(resp, HttpServletResponse.SC_SERVICE_UNAVAILABLE,
          "Request interrupted");
    } catch (Exception e) {
      LOG.severe("Unexpected error processing submit request", e);
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
          "Internal error: " + e.getMessage());
    }
  }

  /** Handles CORS preflight requests for federation endpoints. */
  @Override
  protected void doOptions(HttpServletRequest req, HttpServletResponse resp) {
    setCorsHeaders(resp);
    resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
  }

  private static String readBody(HttpServletRequest req) {
    try {
      BufferedReader reader = req.getReader();
      StringBuilder sb = new StringBuilder();
      char[] buf = new char[4096];
      int len;
      while ((len = reader.read(buf)) != -1) {
        sb.append(buf, 0, len);
      }
      return sb.toString();
    } catch (IOException e) {
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
    resp.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    resp.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }
}
