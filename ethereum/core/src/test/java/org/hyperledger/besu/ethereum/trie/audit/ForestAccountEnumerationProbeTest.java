/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.MutableWorldState;
import org.hyperledger.besu.ethereum.proof.hashing.KeccakProofPathHashing;
import org.hyperledger.besu.ethereum.proof.hashing.ProofPathHashingHolder;
import org.hyperledger.besu.ethereum.storage.keyvalue.WorldStatePreimageKeyValueStorage;
import org.hyperledger.besu.ethereum.trie.patricia.SimpleMerklePatriciaTrie;
import org.hyperledger.besu.ethereum.trie.patricia.StoredMerklePatriciaTrie;
import org.hyperledger.besu.ethereum.trie.forest.storage.ForestWorldStateKeyValueStorage;
import org.hyperledger.besu.ethereum.trie.forest.worldview.ForestMutableWorldState;
import org.hyperledger.besu.evm.internal.EvmConfiguration;
import org.hyperledger.besu.evm.worldstate.WorldUpdater;
import org.hyperledger.besu.services.kvstore.InMemoryKeyValueStorage;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ForestAccountEnumerationProbeTest {
  private static final Address FIRST =
      Address.fromHexString("0x1234567890123456789012345678901234567890");
  private static final Address SECOND =
      Address.fromHexString("0x2234567890123456789012345678901234567890");

  @BeforeEach
  void useKeccakPolicy() {
    ProofPathHashingHolder.set(new KeccakProofPathHashing());
  }

  @Test
  void acceptsAnEmptyTrieWithoutInvokingAuthentication() {
    final SimpleMerklePatriciaTrie<Bytes32, Bytes> empty =
        new SimpleMerklePatriciaTrie<>(value -> value);
    final ForestAccountEnumerator.EnumerationResult result =
        ForestAccountEnumerator.enumerate(
            empty,
            key -> {
              throw new AssertionError("No account should be authenticated for an empty trie");
            });

    assertThat(result.isValid()).isTrue();
    assertThat(result.entries()).isEmpty();
    assertThat(result.independentCount().count()).isZero();
  }

  @Test
  void visitsEveryForestLeafOnceWithExactKeyAndAuthenticatedAccountValue() {
    final InMemoryKeyValueStorage rawStorage = new InMemoryKeyValueStorage();
    final ForestWorldStateKeyValueStorage storage = new ForestWorldStateKeyValueStorage(rawStorage);
    final ForestMutableWorldState mutable =
        new ForestMutableWorldState(
            storage,
            new WorldStatePreimageKeyValueStorage(new InMemoryKeyValueStorage()),
            EvmConfiguration.DEFAULT);
    final WorldUpdater updater = mutable.updater();
    updater.createAccount(FIRST).setBalance(Wei.of(42));
    updater.createAccount(SECOND).setBalance(Wei.of(7));
    updater.commit();
    mutable.persist(null);

    final Hash rootHash = mutable.rootHash();
    final ForestMutableWorldState reopened =
        new ForestMutableWorldState(
            rootHash,
            new ForestWorldStateKeyValueStorage(rawStorage),
            new WorldStatePreimageKeyValueStorage(new InMemoryKeyValueStorage()),
            EvmConfiguration.DEFAULT);
    assertThat(reopened.rootHash()).isEqualTo(rootHash);
    assertThat(reopened.get(FIRST)).isNotNull();
    assertThat(reopened.get(SECOND)).isNotNull();

    final StoredMerklePatriciaTrie<Bytes32, Bytes> trie =
        new StoredMerklePatriciaTrie<>(
            (location, hash) -> storage.getAccountStateTrieNode(hash),
            Bytes32.wrap(rootHash.toArrayUnsafe()),
            value -> value,
            value -> value);
    final ForestAccountTrieLoader.LoadResult loaded =
        new ForestAccountTrieLoader(
                (location, hash) -> storage.getAccountStateTrieNode(hash),
                Bytes.EMPTY,
                Bytes32.wrap(rootHash.toArrayUnsafe()),
                ProofPathHashingHolder.get().trieHashFunction(),
                "keccak")
            .load();
    assertThat(loaded.root()).isPresent();

    final ForestAccountEnumerationProbe.EnumerationReport report =
        ForestAccountEnumerationProbe.observe(
            trie,
            key ->
                new ForestAccountPathTraverser(
                        key,
                        ProofPathHashingHolder.get().trieHashFunction(),
                        "keccak")
                    .traverse(loaded.root().orElseThrow()));

    assertThat(report.leafCount()).isEqualTo(2);
    assertThat(report.keys()).hasSize(2);
    assertThat(report.leaves()).allSatisfy(leaf -> {
      assertThat(leaf.key().size()).isEqualTo(32);
      assertThat(leaf.value()).isEqualTo(leaf.authenticatedPath().accountValueBytes().orElseThrow());
      assertThat(leaf.valueMatchesAuthenticatedPath()).isTrue();
      assertThat(leaf.authenticatedPath().isValid()).isTrue();
    });
    assertThat(report.nodeKinds()).containsKey(ForestAccountEnumerationProbe.NodeKind.LEAF);
    assertThat(report.referenceKinds()).isNotEmpty();

    final Map<Bytes32, Bytes> secondaryResult =
        trie.entriesFrom(root -> Map.of(Bytes32.ZERO, root.getEncodedBytes()));
    assertThat(secondaryResult).containsKey(Bytes32.ZERO);
    assertThat(secondaryResult).hasSize(1);

    final ForestAccountEnumerator.EnumerationResult complete =
        ForestAccountEnumerator.enumerate(
            trie,
            key ->
                new ForestAccountPathTraverser(
                        key,
                        ProofPathHashingHolder.get().trieHashFunction(),
                        "keccak")
                    .traverse(loaded.root().orElseThrow()));
    assertThat(complete.isValid()).isTrue();
    assertThat(complete.entries()).hasSize(2);
    assertThat(complete.entries().size()).isEqualTo(complete.independentCount().count());
  }
}
