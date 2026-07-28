/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package org.hyperledger.besu.ethereum.trie.audit;

import static java.nio.charset.StandardCharsets.UTF_8;

import org.hyperledger.besu.crypto.MessageDigestFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.tuweni.bytes.Bytes;

/** Deterministic identifiers for audit records. */
public final class AuditRecordIds {
  private static final int BLOCK_WIDTH = 20;
  private static final int SHORT_DIGEST_BYTES = 8;

  private AuditRecordIds() {}

  public static String stateId(final long blockNumber, final Bytes stateRoot) {
    return "state_" + block(blockNumber) + "_" + digest("audit-state-id-v1", blockNumber, stateRoot, null);
  }

  public static String pathId(final long blockNumber, final Bytes stateRoot, final Bytes trieKey) {
    return "path_" + block(blockNumber) + "_" + digest("audit-path-id-v1", blockNumber, stateRoot, trieKey);
  }

  public static String errorId(final String stateId, final int attempt, final String errorCode) {
    return "error_" + stateId + "_attempt-" + String.format("%02d", attempt) + "_" + errorCode;
  }

  public static void requireSameIntrinsicFields(
      final String id, final String expected, final String observed) {
    if (!expected.equals(observed)) {
      throw new IllegalArgumentException(
          "Deterministic ID collision for " + id + ": expected " + expected + " but observed " + observed);
    }
  }

  private static String block(final long value) {
    if (value < 0) throw new IllegalArgumentException("Block number must be non-negative");
    return String.format("%0" + BLOCK_WIDTH + "d", value);
  }

  private static String digest(
      final String domain, final long blockNumber, final Bytes stateRoot, final Bytes trieKey) {
    try {
      final MessageDigest digest = MessageDigestFactory.create(MessageDigestFactory.SHA256_ALG);
      update(digest, domain.getBytes(UTF_8));
      update(digest, Long.toUnsignedString(blockNumber).getBytes(UTF_8));
      update(digest, stateRoot.toArrayUnsafe());
      if (trieKey != null) update(digest, trieKey.toArrayUnsafe());
      final byte[] full = digest.digest();
      final StringBuilder shortDigest = new StringBuilder(SHORT_DIGEST_BYTES * 2);
      for (int i = 0; i < SHORT_DIGEST_BYTES; i++) shortDigest.append(String.format("%02x", full[i]));
      return shortDigest.toString();
    } catch (final NoSuchAlgorithmException e) {
      throw new IllegalStateException("JVM does not provide SHA-256", e);
    }
  }

  private static void update(final MessageDigest digest, final byte[] value) {
    digest.update((byte) (value.length >>> 24));
    digest.update((byte) (value.length >>> 16));
    digest.update((byte) (value.length >>> 8));
    digest.update((byte) value.length);
    digest.update(value);
  }
}
