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
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.protobuf.ByteString;

import org.waveprotocol.wave.federation.FederationErrorProto.FederationError;
import org.waveprotocol.wave.federation.Proto.ProtocolHashedVersion;
import org.waveprotocol.wave.federation.Proto.ProtocolSignature;
import org.waveprotocol.wave.federation.Proto.ProtocolSignedDelta;
import org.waveprotocol.wave.model.id.WaveId;
import org.waveprotocol.wave.model.id.WaveletId;
import org.waveprotocol.wave.model.id.WaveletName;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * JSON serialization and deserialization of federation protocol messages for the
 * HTTP transport layer.
 *
 * <p>All byte fields are encoded using Base64url (RFC 4648 section 5) without padding.
 * Protobuf messages are serialized to their individual fields rather than using
 * protobuf's built-in JSON format, ensuring clean interoperability with non-Java
 * implementations.
 */
public class FederationJsonCodec {

  private static final Base64.Encoder BASE64URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder BASE64URL_DECODER = Base64.getUrlDecoder();

  private final Gson gson;

  /**
   * Constructs a new codec with a default Gson instance.
   */
  public FederationJsonCodec() {
    this.gson = new Gson();
  }

  // ---- Inner types for decoded responses ----

  /**
   * Decoded submit response containing the result of a delta submission.
   */
  public static class SubmitResponse {
    private final int operationsApplied;
    private final ProtocolHashedVersion hashedVersionAfter;
    private final long applicationTimestamp;

    public SubmitResponse(int operationsApplied, ProtocolHashedVersion hashedVersionAfter,
        long applicationTimestamp) {
      this.operationsApplied = operationsApplied;
      this.hashedVersionAfter = hashedVersionAfter;
      this.applicationTimestamp = applicationTimestamp;
    }

    public int getOperationsApplied() { return operationsApplied; }
    public ProtocolHashedVersion getHashedVersionAfter() { return hashedVersionAfter; }
    public long getApplicationTimestamp() { return applicationTimestamp; }
  }

  /**
   * Wrapper for a decoded submit request, containing both the wavelet name and the delta.
   */
  public static class SubmitRequest {
    private final WaveletName waveletName;
    private final ProtocolSignedDelta delta;

    public SubmitRequest(WaveletName waveletName, ProtocolSignedDelta delta) {
      this.waveletName = waveletName;
      this.delta = delta;
    }

    public WaveletName getWaveletName() { return waveletName; }
    public ProtocolSignedDelta getDelta() { return delta; }
  }

  /**
   * Decoded history response containing applied deltas and version information.
   */
  public static class HistoryResponse {
    private final List<ByteString> deltas;
    private final ProtocolHashedVersion committedVersion;
    private final long truncatedAt;

    public HistoryResponse(List<ByteString> deltas, ProtocolHashedVersion committedVersion,
        long truncatedAt) {
      this.deltas = deltas;
      this.committedVersion = committedVersion;
      this.truncatedAt = truncatedAt;
    }

    public List<ByteString> getDeltas() { return deltas; }
    public ProtocolHashedVersion getCommittedVersion() { return committedVersion; }
    public long getTruncatedAt() { return truncatedAt; }
  }

  // ---- Submit Request/Response ----

  /**
   * Encodes a submit request to JSON.
   *
   * <p>JSON structure:
   * <pre>{
   *   "waveletName": {
   *     "waveId": { "domain": "...", "id": "..." },
   *     "waveletId": { "domain": "...", "id": "..." }
   *   },
   *   "delta": {
   *     "delta": "&lt;base64url&gt;",
   *     "signatures": [
   *       {
   *         "signatureBytes": "&lt;base64url&gt;",
   *         "signerId": "&lt;base64url&gt;",
   *         "signatureAlgorithm": "SHA1_RSA"
   *       }
   *     ]
   *   }
   * }</pre>
   *
   * @param waveletName the target wavelet
   * @param delta the signed delta to submit
   * @return JSON string
   */
  public String encodeSubmitRequest(WaveletName waveletName, ProtocolSignedDelta delta) {
    JsonObject root = new JsonObject();
    root.add("waveletName", encodeWaveletName(waveletName));
    root.add("delta", encodeSignedDelta(delta));
    return gson.toJson(root);
  }

  /**
   * Decodes a submit request from JSON.
   *
   * @param json the JSON string to decode
   * @return a {@link SubmitRequest} containing the wavelet name and signed delta
   * @throws IllegalArgumentException if the JSON is malformed or missing required fields
   */
  public SubmitRequest decodeSubmitRequest(String json) {
    JsonObject root = JsonParser.parseString(json).getAsJsonObject();
    WaveletName waveletName = decodeWaveletName(root.getAsJsonObject("waveletName"));
    ProtocolSignedDelta delta = decodeSignedDelta(root.getAsJsonObject("delta"));
    return new SubmitRequest(waveletName, delta);
  }

  /**
   * Encodes a submit response to JSON.
   *
   * <p>JSON structure:
   * <pre>{
   *   "operationsApplied": 3,
   *   "hashedVersionAfter": {
   *     "version": 42,
   *     "historyHash": "&lt;base64url&gt;"
   *   },
   *   "applicationTimestamp": 1700000000000
   * }</pre>
   *
   * @param opsApplied the number of operations applied
   * @param version the hashed version after application
   * @param timestamp the application timestamp in milliseconds since epoch
   * @return JSON string
   */
  public String encodeSubmitResponse(int opsApplied, ProtocolHashedVersion version,
      long timestamp) {
    JsonObject root = new JsonObject();
    root.addProperty("operationsApplied", opsApplied);
    root.add("hashedVersionAfter", encodeHashedVersion(version));
    root.addProperty("applicationTimestamp", timestamp);
    return gson.toJson(root);
  }

  /**
   * Decodes a submit response from JSON.
   *
   * @param json the JSON string to decode
   * @return a {@link SubmitResponse}
   * @throws IllegalArgumentException if the JSON is malformed or missing required fields
   */
  public SubmitResponse decodeSubmitResponse(String json) {
    JsonObject root = JsonParser.parseString(json).getAsJsonObject();
    int opsApplied = root.get("operationsApplied").getAsInt();
    ProtocolHashedVersion version = decodeHashedVersion(
        root.getAsJsonObject("hashedVersionAfter"));
    long timestamp = root.get("applicationTimestamp").getAsLong();
    return new SubmitResponse(opsApplied, version, timestamp);
  }

  // ---- History Request/Response ----

  /**
   * Encodes a history request to JSON.
   *
   * <p>JSON structure:
   * <pre>{
   *   "waveletName": { ... },
   *   "startVersion": { "version": 0, "historyHash": "&lt;base64url&gt;" },
   *   "endVersion": { "version": 100, "historyHash": "&lt;base64url&gt;" },
   *   "limit": 50
   * }</pre>
   *
   * <p>Although history requests typically use GET parameters in the HTTP transport,
   * this method is provided for consistency and for use in POST-based transports.
   *
   * @param waveletName the target wavelet
   * @param start the start version (exclusive)
   * @param end the end version (inclusive)
   * @param limit maximum number of deltas to return
   * @return JSON string
   */
  public String encodeHistoryRequest(WaveletName waveletName, ProtocolHashedVersion start,
      ProtocolHashedVersion end, long limit) {
    JsonObject root = new JsonObject();
    root.add("waveletName", encodeWaveletName(waveletName));
    root.add("startVersion", encodeHashedVersion(start));
    root.add("endVersion", encodeHashedVersion(end));
    root.addProperty("limit", limit);
    return gson.toJson(root);
  }

  /**
   * Encodes a history response to JSON.
   *
   * <p>JSON structure:
   * <pre>{
   *   "deltas": ["&lt;base64url&gt;", ...],
   *   "committedVersion": { "version": 42, "historyHash": "&lt;base64url&gt;" },
   *   "truncatedAt": 0
   * }</pre>
   *
   * <p>A {@code truncatedAt} value of 0 indicates the response was not truncated.
   *
   * @param deltas list of serialized applied wavelet deltas
   * @param committed the last committed version
   * @param truncatedAt the version at which results were truncated, or 0 if not truncated
   * @return JSON string
   */
  public String encodeHistoryResponse(List<ByteString> deltas,
      ProtocolHashedVersion committed, long truncatedAt) {
    JsonObject root = new JsonObject();
    JsonArray deltaArray = new JsonArray();
    for (ByteString delta : deltas) {
      deltaArray.add(encodeBytes(delta));
    }
    root.add("deltas", deltaArray);
    root.add("committedVersion", encodeHashedVersion(committed));
    root.addProperty("truncatedAt", truncatedAt);
    return gson.toJson(root);
  }

  /**
   * Decodes a history response from JSON.
   *
   * @param json the JSON string to decode
   * @return a {@link HistoryResponse}
   * @throws IllegalArgumentException if the JSON is malformed or missing required fields
   */
  public HistoryResponse decodeHistoryResponse(String json) {
    JsonObject root = JsonParser.parseString(json).getAsJsonObject();
    JsonArray deltaArray = root.getAsJsonArray("deltas");
    List<ByteString> deltas = new ArrayList<>();
    for (JsonElement element : deltaArray) {
      deltas.add(decodeBytes(element.getAsString()));
    }
    ProtocolHashedVersion committed = decodeHashedVersion(
        root.getAsJsonObject("committedVersion"));
    long truncatedAt = root.get("truncatedAt").getAsLong();
    return new HistoryResponse(deltas, committed, truncatedAt);
  }

  // ---- Error encoding/decoding ----

  /**
   * Encodes a federation error to JSON.
   *
   * <p>JSON structure:
   * <pre>{
   *   "error": {
   *     "code": "BAD_REQUEST",
   *     "message": "Missing required field"
   *   }
   * }</pre>
   *
   * @param error the federation error
   * @return JSON string
   */
  public String encodeError(FederationError error) {
    JsonObject root = new JsonObject();
    JsonObject errorObj = new JsonObject();
    errorObj.addProperty("code", error.getErrorCode().name());
    if (error.hasErrorMessage()) {
      errorObj.addProperty("message", error.getErrorMessage());
    }
    root.add("error", errorObj);
    return gson.toJson(root);
  }

  /**
   * Decodes a federation error from JSON.
   *
   * @param json the JSON string to decode
   * @return a {@link FederationError}
   * @throws IllegalArgumentException if the JSON is malformed or the error code is unknown
   */
  public FederationError decodeError(String json) {
    JsonObject root = JsonParser.parseString(json).getAsJsonObject();
    JsonObject errorObj = root.getAsJsonObject("error");
    FederationError.Code code = FederationError.Code.valueOf(errorObj.get("code").getAsString());
    FederationError.Builder builder = FederationError.newBuilder().setErrorCode(code);
    if (errorObj.has("message")) {
      builder.setErrorMessage(errorObj.get("message").getAsString());
    }
    return builder.build();
  }

  // ---- Well-known and keys responses ----

  /**
   * Encodes a {@code .well-known/wave/server} discovery response to JSON.
   *
   * <p>JSON structure:
   * <pre>{
   *   "server": "wave.example.com:443",
   *   "protocolVersion": "0.4",
   *   "transports": ["http", "xmpp"],
   *   "serializations": ["json", "protobuf"]
   * }</pre>
   *
   * @param serverAddress the server address (host:port)
   * @param protocolVersion the federation protocol version
   * @param transports supported transport protocols
   * @param serializations supported serialization formats
   * @return JSON string
   */
  public String encodeWellKnownResponse(String serverAddress, String protocolVersion,
      List<String> transports, List<String> serializations) {
    JsonObject root = new JsonObject();
    root.addProperty("server", serverAddress);
    root.addProperty("protocolVersion", protocolVersion);
    root.add("transports", toJsonArray(transports));
    root.add("serializations", toJsonArray(serializations));
    return gson.toJson(root);
  }

  /**
   * Encodes a {@code /_wave/keys/v1} signing keys response to JSON.
   *
   * <p>JSON structure:
   * <pre>{
   *   "server": "wave.example.com",
   *   "signingKeys": {
   *     "ed25519:wave01": "&lt;base64url-public-key&gt;",
   *     "ed25519:wave02": "&lt;base64url-public-key&gt;"
   *   },
   *   "validUntilTs": 1700000000000
   * }</pre>
   *
   * @param serverName the server name
   * @param signingKeys map of key ID to base64url-encoded public key
   * @param validUntilTs timestamp in milliseconds until which the keys are valid
   * @return JSON string
   */
  public String encodeKeysResponse(String serverName, Map<String, String> signingKeys,
      long validUntilTs) {
    JsonObject root = new JsonObject();
    root.addProperty("server", serverName);
    JsonObject keysObj = new JsonObject();
    for (Map.Entry<String, String> entry : signingKeys.entrySet()) {
      keysObj.addProperty(entry.getKey(), entry.getValue());
    }
    root.add("signingKeys", keysObj);
    root.addProperty("validUntilTs", validUntilTs);
    return gson.toJson(root);
  }

  // ---- Private helper methods ----

  private JsonObject encodeWaveletName(WaveletName waveletName) {
    JsonObject obj = new JsonObject();
    JsonObject waveIdObj = new JsonObject();
    waveIdObj.addProperty("domain", waveletName.waveId.getDomain());
    waveIdObj.addProperty("id", waveletName.waveId.getId());
    obj.add("waveId", waveIdObj);
    JsonObject waveletIdObj = new JsonObject();
    waveletIdObj.addProperty("domain", waveletName.waveletId.getDomain());
    waveletIdObj.addProperty("id", waveletName.waveletId.getId());
    obj.add("waveletId", waveletIdObj);
    return obj;
  }

  private WaveletName decodeWaveletName(JsonObject obj) {
    JsonObject waveIdObj = obj.getAsJsonObject("waveId");
    JsonObject waveletIdObj = obj.getAsJsonObject("waveletId");
    WaveId waveId = WaveId.of(waveIdObj.get("domain").getAsString(),
        waveIdObj.get("id").getAsString());
    WaveletId waveletId = WaveletId.of(waveletIdObj.get("domain").getAsString(),
        waveletIdObj.get("id").getAsString());
    return WaveletName.of(waveId, waveletId);
  }

  private JsonObject encodeSignedDelta(ProtocolSignedDelta delta) {
    JsonObject obj = new JsonObject();
    obj.addProperty("delta", encodeBytes(delta.getDelta()));
    JsonArray sigs = new JsonArray();
    for (ProtocolSignature sig : delta.getSignatureList()) {
      JsonObject sigObj = new JsonObject();
      sigObj.addProperty("signatureBytes", encodeBytes(sig.getSignatureBytes()));
      sigObj.addProperty("signerId", encodeBytes(sig.getSignerId()));
      sigObj.addProperty("signatureAlgorithm", sig.getSignatureAlgorithm().name());
      sigs.add(sigObj);
    }
    obj.add("signatures", sigs);
    return obj;
  }

  private ProtocolSignedDelta decodeSignedDelta(JsonObject obj) {
    ProtocolSignedDelta.Builder builder = ProtocolSignedDelta.newBuilder();
    builder.setDelta(decodeBytes(obj.get("delta").getAsString()));
    JsonArray sigs = obj.getAsJsonArray("signatures");
    for (JsonElement sigElem : sigs) {
      JsonObject sigObj = sigElem.getAsJsonObject();
      ProtocolSignature.Builder sigBuilder = ProtocolSignature.newBuilder();
      sigBuilder.setSignatureBytes(decodeBytes(sigObj.get("signatureBytes").getAsString()));
      sigBuilder.setSignerId(decodeBytes(sigObj.get("signerId").getAsString()));
      sigBuilder.setSignatureAlgorithm(
          ProtocolSignature.SignatureAlgorithm.valueOf(
              sigObj.get("signatureAlgorithm").getAsString()));
      builder.addSignature(sigBuilder.build());
    }
    return builder.build();
  }

  private JsonObject encodeHashedVersion(ProtocolHashedVersion version) {
    JsonObject obj = new JsonObject();
    obj.addProperty("version", version.getVersion());
    obj.addProperty("historyHash", encodeBytes(version.getHistoryHash()));
    return obj;
  }

  private ProtocolHashedVersion decodeHashedVersion(JsonObject obj) {
    return ProtocolHashedVersion.newBuilder()
        .setVersion(obj.get("version").getAsLong())
        .setHistoryHash(decodeBytes(obj.get("historyHash").getAsString()))
        .build();
  }

  private static String encodeBytes(ByteString bytes) {
    return BASE64URL_ENCODER.encodeToString(bytes.toByteArray());
  }

  private static ByteString decodeBytes(String base64url) {
    return ByteString.copyFrom(BASE64URL_DECODER.decode(base64url));
  }

  private static JsonArray toJsonArray(List<String> strings) {
    JsonArray array = new JsonArray();
    for (String s : strings) {
      array.add(s);
    }
    return array;
  }
}
