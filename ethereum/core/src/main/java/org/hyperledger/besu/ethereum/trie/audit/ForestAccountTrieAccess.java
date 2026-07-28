/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.proof.hashing.ProofPathHashing;
import org.hyperledger.besu.ethereum.trie.MerkleTrie;
import org.hyperledger.besu.ethereum.trie.Node;
import org.hyperledger.besu.ethereum.trie.hash.TrieHashFunction;
import org.hyperledger.besu.ethereum.trie.patricia.StoredMerklePatriciaTrie;
import org.hyperledger.besu.ethereum.trie.forest.storage.ForestWorldStateKeyValueStorage;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/** Opens the account trie through the read-only Forest node-storage boundary. */
public final class ForestAccountTrieAccess {
  private final ForestWorldStateKeyValueStorage storage;

  public ForestAccountTrieAccess(final ForestWorldStateKeyValueStorage storage) {
    this.storage = storage;
  }

  public OpenedAccountTrie open(
      final Hash stateRoot, final TrieHashFunction hashFunction, final String policyIdentity) {
    final Bytes32 root = Bytes32.wrap(stateRoot.toArrayUnsafe());
    final ForestAccountTrieLoader.LoadResult loaded =
        new ForestAccountTrieLoader(
                (location, hash) -> storage.getAccountStateTrieNode(hash),
                Bytes.EMPTY,
                root,
                hashFunction,
                policyIdentity)
            .load();
    if (!loaded.root().isPresent()) {
      throw new IllegalStateException("Unable to load account root: " + loaded.status() + " " + loaded.error());
    }
    final MerkleTrie<Bytes32, Bytes> trie =
        new StoredMerklePatriciaTrie<>(
            (location, hash) -> storage.getAccountStateTrieNode(hash),
            root,
            Bytes.EMPTY,
            value -> value,
            value -> value);
    return new OpenedAccountTrie(trie, loaded.root().orElseThrow(), loaded.status(), policyIdentity);
  }

  public record OpenedAccountTrie(
      MerkleTrie<Bytes32, Bytes> trie,
      Node<Bytes> root,
      AuditValidationStatus status,
      String policyIdentity) {}
}
