/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import org.hyperledger.besu.ethereum.trie.MerkleTrie;
import org.hyperledger.besu.ethereum.trie.Node;
import org.hyperledger.besu.ethereum.trie.patricia.BranchNode;
import org.hyperledger.besu.ethereum.trie.patricia.LeafNode;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/** Counts account terminal values through a separate node visitor. */
public final class ForestAccountLeafCounter {
  private ForestAccountLeafCounter() {}

  public static CountResult count(final MerkleTrie<Bytes32, Bytes> trie) {
    final int[] count = {0};
    try {
      trie.visitAll(
          node -> {
            if (node instanceof LeafNode<?> || (node instanceof BranchNode<?> branch && branch.getValue().isPresent())) {
              count[0]++;
            }
          });
      return new CountResult(AuditValidationStatus.VALID, count[0], "");
    } catch (final RuntimeException ex) {
      return new CountResult(AuditValidationStatus.MALFORMED, count[0], ex.getMessage());
    }
  }

  public record CountResult(AuditValidationStatus status, int count, String error) {}
}
