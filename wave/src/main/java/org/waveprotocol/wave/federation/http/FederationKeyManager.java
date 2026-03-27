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
import com.google.inject.name.Named;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Manages Ed25519 key generation, storage, signing, and verification for
 * the Wave federation HTTP transport.
 *
 * <p>On construction, this manager either loads an existing Ed25519 key pair from disk
 * or generates a new one and persists it. The private key is stored in PKCS#8 PEM format
 * and the public key in X.509 PEM format.
 *
 * <p>Uses Java 17's built-in Ed25519 support ({@code java.security.KeyPairGenerator}
 * with algorithm "Ed25519"), requiring no external cryptography libraries.
 *
 * <p>This class is thread-safe. The key pair is loaded once at construction time
 * and all signing/verification operations use thread-safe JCA primitives.
 */
@Singleton
public class FederationKeyManager {

  private static final Logger LOG = Logger.getLogger(FederationKeyManager.class.getName());

  private static final String ALGORITHM = "Ed25519";
  private static final String PRIVATE_KEY_FILENAME = "federation_private.pem";
  private static final String PUBLIC_KEY_FILENAME = "federation_public.pem";
  private static final String PEM_PRIVATE_HEADER = "-----BEGIN PRIVATE KEY-----";
  private static final String PEM_PRIVATE_FOOTER = "-----END PRIVATE KEY-----";
  private static final String PEM_PUBLIC_HEADER = "-----BEGIN PUBLIC KEY-----";
  private static final String PEM_PUBLIC_FOOTER = "-----END PUBLIC KEY-----";

  private static final Base64.Encoder BASE64_ENCODER = Base64.getMimeEncoder(64, "\n".getBytes());
  private static final Base64.Decoder BASE64_DECODER = Base64.getMimeDecoder();
  private static final Base64.Encoder BASE64URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

  private final PrivateKey privateKey;
  private final PublicKey publicKey;
  private final String keyId;
  private final String domain;

  /**
   * Creates a new key manager, loading keys from disk or generating new ones.
   *
   * <p>If the key files exist at the specified path, they are loaded. Otherwise, a new
   * Ed25519 key pair is generated and saved to that path. The directory is created if
   * it does not already exist.
   *
   * @param keyPath directory path where key files are stored
   * @param keyId identifier for this signing key (e.g. "ed25519:wave01")
   * @param domain the server domain associated with this key
   * @throws RuntimeException if key generation, loading, or saving fails
   */
  @Inject
  public FederationKeyManager(
      @Named("federation_signing_key_path") String keyPath,
      @Named("federation_signing_key_id") String keyId,
      @Named("wave_server_domain") String domain) {
    this.keyId = keyId;
    this.domain = domain;

    Path keyDir = Paths.get(keyPath);
    Path privateKeyFile = keyDir.resolve(PRIVATE_KEY_FILENAME);
    Path publicKeyFile = keyDir.resolve(PUBLIC_KEY_FILENAME);

    try {
      if (Files.exists(privateKeyFile) && Files.exists(publicKeyFile)) {
        LOG.info("Loading existing Ed25519 key pair from " + keyDir);
        this.privateKey = loadPrivateKey(privateKeyFile);
        this.publicKey = loadPublicKey(publicKeyFile);
      } else {
        LOG.info("Generating new Ed25519 key pair at " + keyDir);
        Files.createDirectories(keyDir);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        KeyPair keyPair = keyGen.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
        savePrivateKey(privateKeyFile, this.privateKey);
        savePublicKey(publicKeyFile, this.publicKey);
        LOG.info("Ed25519 key pair generated and saved with key ID: " + keyId);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Ed25519 algorithm not available. Requires Java 17+.", e);
    } catch (IOException | InvalidKeySpecException e) {
      throw new RuntimeException("Failed to load or save Ed25519 key pair at " + keyDir, e);
    }
  }

  /**
   * Signs the given data with this server's Ed25519 private key.
   *
   * @param data the bytes to sign
   * @return the Ed25519 signature bytes (64 bytes)
   * @throws RuntimeException if signing fails due to an algorithm or key error
   */
  public byte[] sign(byte[] data) {
    try {
      Signature signer = Signature.getInstance(ALGORITHM);
      signer.initSign(privateKey);
      signer.update(data);
      return signer.sign();
    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
      throw new RuntimeException("Failed to sign data with Ed25519", e);
    }
  }

  /**
   * Verifies an Ed25519 signature against the provided public key.
   *
   * @param data the original data that was signed
   * @param signature the signature bytes to verify
   * @param publicKeyBytes the X.509-encoded public key bytes of the signer
   * @return {@code true} if the signature is valid, {@code false} otherwise
   */
  public boolean verify(byte[] data, byte[] signature, byte[] publicKeyBytes) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
      PublicKey pubKey = keyFactory.generatePublic(keySpec);

      Signature verifier = Signature.getInstance(ALGORITHM);
      verifier.initVerify(pubKey);
      verifier.update(data);
      return verifier.verify(signature);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException
        | InvalidKeyException | SignatureException e) {
      LOG.log(Level.WARNING, "Signature verification failed", e);
      return false;
    }
  }

  /**
   * Returns this server's signing key identifier.
   *
   * @return the key ID string (e.g. "ed25519:wave01")
   */
  public String getKeyId() {
    return keyId;
  }

  /**
   * Returns the raw X.509-encoded bytes of this server's Ed25519 public key.
   *
   * <p>These bytes can be used by remote servers for signature verification
   * via {@link #verify(byte[], byte[], byte[])}.
   *
   * @return the public key bytes in X.509 encoding
   */
  public byte[] getPublicKeyBytes() {
    return publicKey.getEncoded();
  }

  /**
   * Returns this server's Ed25519 public key encoded as a Base64url string
   * (without padding), suitable for inclusion in JSON key responses.
   *
   * @return base64url-encoded public key
   */
  public String getPublicKeyBase64Url() {
    return BASE64URL_ENCODER.encodeToString(publicKey.getEncoded());
  }

  /**
   * Returns the domain this key manager is associated with.
   *
   * @return the server domain
   */
  public String getDomain() {
    return domain;
  }

  // ---- Private PEM I/O methods ----

  private static void savePrivateKey(Path path, PrivateKey key) throws IOException {
    String pem = PEM_PRIVATE_HEADER + "\n"
        + BASE64_ENCODER.encodeToString(key.getEncoded()) + "\n"
        + PEM_PRIVATE_FOOTER + "\n";
    try (Writer writer = Files.newBufferedWriter(path)) {
      writer.write(pem);
    }
  }

  private static void savePublicKey(Path path, PublicKey key) throws IOException {
    String pem = PEM_PUBLIC_HEADER + "\n"
        + BASE64_ENCODER.encodeToString(key.getEncoded()) + "\n"
        + PEM_PUBLIC_FOOTER + "\n";
    try (Writer writer = Files.newBufferedWriter(path)) {
      writer.write(pem);
    }
  }

  private static PrivateKey loadPrivateKey(Path path)
      throws IOException, InvalidKeySpecException {
    String pem = readPemContent(path, PEM_PRIVATE_HEADER, PEM_PRIVATE_FOOTER);
    byte[] keyBytes = BASE64_DECODER.decode(pem);
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    try {
      KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
      return keyFactory.generatePrivate(spec);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Ed25519 algorithm not available", e);
    }
  }

  private static PublicKey loadPublicKey(Path path)
      throws IOException, InvalidKeySpecException {
    String pem = readPemContent(path, PEM_PUBLIC_HEADER, PEM_PUBLIC_FOOTER);
    byte[] keyBytes = BASE64_DECODER.decode(pem);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    try {
      KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
      return keyFactory.generatePublic(spec);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Ed25519 algorithm not available", e);
    }
  }

  /**
   * Reads a PEM file and extracts the Base64 content between the header and footer markers.
   */
  private static String readPemContent(Path path, String header, String footer)
      throws IOException {
    StringBuilder sb = new StringBuilder();
    try (Reader reader = Files.newBufferedReader(path)) {
      char[] buf = new char[4096];
      int read;
      while ((read = reader.read(buf)) != -1) {
        sb.append(buf, 0, read);
      }
    }
    String content = sb.toString();
    int start = content.indexOf(header);
    int end = content.indexOf(footer);
    if (start == -1 || end == -1) {
      throw new IOException("Invalid PEM file: " + path + " (missing header/footer)");
    }
    return content.substring(start + header.length(), end).replaceAll("\\s+", "");
  }
}
