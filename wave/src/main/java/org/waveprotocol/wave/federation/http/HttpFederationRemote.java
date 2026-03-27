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

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.waveprotocol.wave.federation.FederationErrors;
import org.waveprotocol.wave.federation.Proto.ProtocolHashedVersion;
import org.waveprotocol.wave.federation.Proto.ProtocolSignedDelta;
import org.waveprotocol.wave.federation.Proto.ProtocolSignerInfo;
import org.waveprotocol.wave.federation.WaveletFederationProvider;
import org.waveprotocol.wave.model.id.WaveletName;
import org.waveprotocol.wave.util.logging.Log;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Outbound federation provider that sends requests to remote Wave servers over HTTP.
 *
 * <p>When the local server needs to submit deltas, fetch history, or retrieve signer
 * information from a remote Wave server, this class discovers the remote server's
 * address via {@link FederationDiscoveryClient} and issues the appropriate HTTP requests.
 *
 * <p>All HTTP calls are executed asynchronously on a dedicated thread pool to avoid
 * blocking the caller.
 */
@Singleton
public class HttpFederationRemote implements WaveletFederationProvider {

  private static final Log LOG = Log.get(HttpFederationRemote.class);

  private static final Base64.Encoder BASE64URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

  private final FederationJsonCodec codec;
  private final FederationDiscoveryClient discoveryClient;
  private final FederationKeyClient keyClient;
  private final FederationKeyManager keyManager;
  private final ExecutorService executor;
  private final CloseableHttpClient httpClient;

  /**
   * Constructs a new HTTP federation remote.
   *
   * @param codec JSON codec for encoding and decoding federation messages
   * @param discoveryClient client for discovering remote server addresses
   * @param keyClient client for fetching remote signing keys
   * @param keyManager local key manager for signing operations
   */
  @Inject
  public HttpFederationRemote(FederationJsonCodec codec,
      FederationDiscoveryClient discoveryClient, FederationKeyClient keyClient,
      FederationKeyManager keyManager) {
    this.codec = codec;
    this.discoveryClient = discoveryClient;
    this.keyClient = keyClient;
    this.keyManager = keyManager;
    this.executor = Executors.newCachedThreadPool();
    this.httpClient = HttpClients.createDefault();
  }

  /**
   * Submits a signed delta to the remote server that hosts the given wavelet.
   *
   * <p>The remote server is discovered from the wavelet's domain. The delta is
   * POSTed as JSON to {@code /_wave/federation/v1/submit} on the remote server.
   *
   * @param waveletName the target wavelet
   * @param delta the signed delta to submit
   * @param listener callback for the result
   */
  @Override
  public void submitRequest(WaveletName waveletName, ProtocolSignedDelta delta,
      SubmitResultListener listener) {
    executor.submit(() -> {
      try {
        String remoteDomain = waveletName.waveId.getDomain();
        String serverAddress = discoveryClient.discoverServer(remoteDomain);
        if (serverAddress == null) {
          listener.onFailure(FederationErrors.badRequest(
              "Could not discover server for domain: " + remoteDomain));
          return;
        }

        String url = "https://" + serverAddress + "/_wave/federation/v1/submit";
        String jsonBody = codec.encodeSubmitRequest(waveletName, delta);

        HttpPost post = new HttpPost(url);
        post.setEntity(new StringEntity(jsonBody, ContentType.APPLICATION_JSON));

        try (CloseableHttpResponse response = httpClient.execute(post)) {
          int statusCode = response.getStatusLine().getStatusCode();
          String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

          if (statusCode >= 200 && statusCode < 300) {
            FederationJsonCodec.SubmitResponse submitResponse =
                codec.decodeSubmitResponse(responseBody);
            listener.onSuccess(
                submitResponse.getOperationsApplied(),
                submitResponse.getHashedVersionAfter(),
                submitResponse.getApplicationTimestamp());
          } else {
            LOG.warning("Submit request failed with status " + statusCode
                + " for wavelet " + waveletName + ": " + responseBody);
            try {
              listener.onFailure(codec.decodeError(responseBody));
            } catch (Exception decodeEx) {
              listener.onFailure(FederationErrors.internalServerError(
                  "Remote server returned status " + statusCode + ": " + responseBody));
            }
          }
        }
      } catch (Exception e) {
        LOG.severe("Submit request failed for wavelet " + waveletName, e);
        listener.onFailure(FederationErrors.internalServerError(
            "Submit request failed: " + e.getMessage()));
      }
    });
  }

  /**
   * Requests delta history from the remote server that hosts the given wavelet.
   *
   * <p>The remote server is discovered from the wavelet's domain. History is
   * fetched via GET from {@code /_wave/federation/v1/history/...} with version
   * parameters encoded as query parameters.
   *
   * @param waveletName the target wavelet
   * @param domain the requesting domain
   * @param startVersion the start version (inclusive)
   * @param endVersion the end version (exclusive)
   * @param lengthLimit maximum byte size of the response
   * @param listener callback for the result
   */
  @Override
  public void requestHistory(WaveletName waveletName, String domain,
      ProtocolHashedVersion startVersion, ProtocolHashedVersion endVersion,
      long lengthLimit, HistoryResponseListener listener) {
    executor.submit(() -> {
      try {
        String remoteDomain = waveletName.waveId.getDomain();
        String serverAddress = discoveryClient.discoverServer(remoteDomain);
        if (serverAddress == null) {
          listener.onFailure(FederationErrors.badRequest(
              "Could not discover server for domain: " + remoteDomain));
          return;
        }

        String startHash = BASE64URL_ENCODER.encodeToString(
            startVersion.getHistoryHash().toByteArray());
        String endHash = BASE64URL_ENCODER.encodeToString(
            endVersion.getHistoryHash().toByteArray());

        String url = "https://" + serverAddress
            + "/_wave/federation/v1/history/"
            + urlEncode(waveletName.waveId.getDomain()) + "/"
            + urlEncode(waveletName.waveId.getId()) + "/"
            + urlEncode(waveletName.waveletId.getDomain()) + "/"
            + urlEncode(waveletName.waveletId.getId())
            + "?start_version=" + startVersion.getVersion()
            + "&start_hash=" + urlEncode(startHash)
            + "&end_version=" + endVersion.getVersion()
            + "&end_hash=" + urlEncode(endHash)
            + "&limit=" + lengthLimit
            + "&domain=" + urlEncode(domain);

        HttpGet get = new HttpGet(url);

        try (CloseableHttpResponse response = httpClient.execute(get)) {
          int statusCode = response.getStatusLine().getStatusCode();
          String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

          if (statusCode >= 200 && statusCode < 300) {
            FederationJsonCodec.HistoryResponse historyResponse =
                codec.decodeHistoryResponse(responseBody);
            listener.onSuccess(
                historyResponse.getDeltas(),
                historyResponse.getCommittedVersion(),
                historyResponse.getTruncatedAt());
          } else {
            LOG.warning("History request failed with status " + statusCode
                + " for wavelet " + waveletName + ": " + responseBody);
            try {
              listener.onFailure(codec.decodeError(responseBody));
            } catch (Exception decodeEx) {
              listener.onFailure(FederationErrors.internalServerError(
                  "Remote server returned status " + statusCode + ": " + responseBody));
            }
          }
        }
      } catch (Exception e) {
        LOG.severe("History request failed for wavelet " + waveletName, e);
        listener.onFailure(FederationErrors.internalServerError(
            "History request failed: " + e.getMessage()));
      }
    });
  }

  /**
   * Retrieves signer information for a delta from the remote server.
   *
   * <p>In HTTP federation, signing keys are fetched from the remote server's
   * {@code /_wave/keys/v1} endpoint. The response is mapped to a synthetic
   * {@link ProtocolSignerInfo} for compatibility with the federation bus.
   *
   * @param signerId the signer identifier (hash of certificate chain)
   * @param waveletName the wavelet the delta belongs to
   * @param deltaEndVersion the version after the signed delta was applied
   * @param listener callback for the result
   */
  @Override
  public void getDeltaSignerInfo(ByteString signerId, WaveletName waveletName,
      ProtocolHashedVersion deltaEndVersion, DeltaSignerInfoResponseListener listener) {
    executor.submit(() -> {
      try {
        String remoteDomain = waveletName.waveId.getDomain();
        ProtocolSignerInfo signerInfo = keyClient.fetchSignerInfo(remoteDomain, signerId);
        if (signerInfo != null) {
          listener.onSuccess(signerInfo);
        } else {
          listener.onFailure(FederationErrors.badRequest(
              "Could not fetch signer info for domain: " + remoteDomain));
        }
      } catch (Exception e) {
        LOG.severe("getDeltaSignerInfo failed for wavelet " + waveletName, e);
        listener.onFailure(FederationErrors.internalServerError(
            "Failed to fetch signer info: " + e.getMessage()));
      }
    });
  }

  /**
   * Posts signer information to a remote server.
   *
   * <p>In HTTP federation, keys are fetched on demand via the keys endpoint rather
   * than being pushed. This method is a no-op that immediately signals success.
   *
   * @param destinationDomain the target domain
   * @param signerInfo the signer information to post
   * @param listener callback for the result
   */
  @Override
  public void postSignerInfo(String destinationDomain, ProtocolSignerInfo signerInfo,
      PostSignerInfoResponseListener listener) {
    // In HTTP federation, keys are fetched on demand from /_wave/keys/v1.
    // No need to push signer info proactively.
    LOG.fine("postSignerInfo is a no-op in HTTP federation (keys are fetched on demand) "
        + "for domain: " + destinationDomain);
    listener.onSuccess();
  }

  /**
   * URL-encodes a string using UTF-8.
   */
  private static String urlEncode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }
}
