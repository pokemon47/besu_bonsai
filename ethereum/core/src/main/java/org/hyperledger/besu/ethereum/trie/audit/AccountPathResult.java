/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package org.hyperledger.besu.ethereum.trie.audit;

import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;

/** Result of traversing one authenticated account-trie path. */
public record AccountPathResult(
    AuditValidationStatus status,
    Bytes key,
    List<AccountPathStep> steps,
    int consumedNibbles,
    int remainingNibbles,
    int proofNodeCount,
    int totalProofRlpBytes,
    Optional<Bytes> terminalNodeBytes,
    Optional<Bytes> accountValueBytes,
    Optional<Integer> accountValuePayloadOffset,
    Optional<Integer> accountValuePayloadLength,
    String error) {
  public boolean isValid() {
    return status == AuditValidationStatus.VALID;
  }
}
