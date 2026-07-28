/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package org.hyperledger.besu.ethereum.trie.audit;

import org.hyperledger.besu.ethereum.trie.MerkleTrieException;
import org.hyperledger.besu.ethereum.trie.Node;
import org.hyperledger.besu.ethereum.trie.NodeLoader;
import org.hyperledger.besu.ethereum.trie.hash.TrieHashFunction;
import org.hyperledger.besu.ethereum.trie.patricia.StoredNodeFactory;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/** Opens a read-only Forest root and validates its identity before traversal. */
public final class ForestAccountTrieLoader {
  private final NodeLoader nodeLoader;
  private final Bytes rootLocation;
  private final Bytes32 expectedRootIdentity;
  private final TrieHashFunction activeTrieHashFunction;
  private final String policyIdentity;

  public ForestAccountTrieLoader(
      final NodeLoader nodeLoader,
      final Bytes rootLocation,
      final Bytes32 expectedRootIdentity,
      final TrieHashFunction activeTrieHashFunction,
      final String policyIdentity) {
    this.nodeLoader = nodeLoader;
    this.rootLocation = rootLocation;
    this.expectedRootIdentity = expectedRootIdentity;
    this.activeTrieHashFunction = activeTrieHashFunction;
    this.policyIdentity = policyIdentity;
  }

  public LoadResult load() {
    final StoredNodeFactory<Bytes> nodeFactory = new RuntimeCheckedStoredNodeFactory(nodeLoader);
    try {
      final Optional<Node<Bytes>> root = nodeFactory.retrieve(rootLocation, expectedRootIdentity);
      if (root.isEmpty()) {
        return new LoadResult(
            AuditValidationStatus.MISSING, Optional.empty(), policyIdentity, "Root node missing");
      }
      final Node<Bytes> decodedRoot = root.get();
      final Bytes32 calculatedRootIdentity =
          activeTrieHashFunction.hash(decodedRoot.getEncodedBytes());
      if (!expectedRootIdentity.equals(calculatedRootIdentity)) {
        return new LoadResult(
            AuditValidationStatus.REFERENCE_MISMATCH,
            Optional.empty(),
            policyIdentity,
            "Root identity mismatch: expected "
                + expectedRootIdentity
                + " but calculated "
                + calculatedRootIdentity);
      }
      return new LoadResult(AuditValidationStatus.VALID, Optional.of(decodedRoot), policyIdentity, "");
    } catch (final MerkleTrieException ex) {
      return new LoadResult(AuditValidationStatus.MALFORMED, Optional.empty(), policyIdentity, ex.getMessage());
    } catch (final RuntimeException ex) {
      return new LoadResult(AuditValidationStatus.MALFORMED, Optional.empty(), policyIdentity, ex.getMessage());
    }
  }

  public record LoadResult(
      AuditValidationStatus status,
      Optional<Node<Bytes>> root,
      String policyIdentity,
      String error) {}

  /** Uses the production decoder without relying on its assertion-only hash check. */
  private static final class RuntimeCheckedStoredNodeFactory extends StoredNodeFactory<Bytes> {
    private final NodeLoader loader;

    private RuntimeCheckedStoredNodeFactory(final NodeLoader loader) {
      super(loader, value -> value, value -> value);
      this.loader = loader;
    }

    @Override
    public Optional<Node<Bytes>> retrieve(final Bytes location, final Bytes32 hash)
        throws MerkleTrieException {
      return loader.getNode(location, hash).map(rlp -> decode(location, rlp));
    }
  }
}
