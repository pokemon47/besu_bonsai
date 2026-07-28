/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hyperledger.besu.ethereum.trie.CompactEncoding.bytesToPath;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.MutableWorldState;
import org.hyperledger.besu.ethereum.proof.hashing.KeccakProofPathHashing;
import org.hyperledger.besu.ethereum.proof.hashing.ProofPathHashingHolder;
import org.hyperledger.besu.ethereum.storage.keyvalue.WorldStatePreimageKeyValueStorage;
import org.hyperledger.besu.ethereum.trie.MerkleTrie;
import org.hyperledger.besu.ethereum.trie.Node;
import org.hyperledger.besu.ethereum.trie.patricia.DefaultNodeFactory;
import org.hyperledger.besu.ethereum.trie.patricia.SimpleMerklePatriciaTrie;
import org.hyperledger.besu.ethereum.trie.patricia.StoredMerklePatriciaTrie;
import org.hyperledger.besu.ethereum.trie.forest.storage.ForestWorldStateKeyValueStorage;
import org.hyperledger.besu.ethereum.trie.forest.worldview.ForestMutableWorldState;
import org.hyperledger.besu.evm.internal.EvmConfiguration;
import org.hyperledger.besu.evm.worldstate.WorldUpdater;
import org.hyperledger.besu.services.kvstore.InMemoryKeyValueStorage;

import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Phase 1 probe for read-only Forest proof-path observability. */
class ForestTrieAuditProbeTest {

  private static final Address TARGET =
      Address.fromHexString("0x1234567890123456789012345678901234567890");

  @BeforeEach
  void useKeccakPolicy() {
    ProofPathHashingHolder.set(new KeccakProofPathHashing());
  }

  @Test
  void opensPersistedForestStateByRootAndMeasuresOneAccountPathReadOnly() {
    final InMemoryKeyValueStorage rawStorage = new InMemoryKeyValueStorage();
    final ForestWorldStateKeyValueStorage storage = new ForestWorldStateKeyValueStorage(rawStorage);
    final MutableWorldState mutable =
        new ForestMutableWorldState(
            storage,
            new WorldStatePreimageKeyValueStorage(new InMemoryKeyValueStorage()),
            EvmConfiguration.DEFAULT);
    final WorldUpdater updater = mutable.updater();
    updater.createAccount(TARGET).setBalance(Wei.of(42));
    updater.createAccount(Address.fromHexString("0x2234567890123456789012345678901234567890"));
    updater.commit();
    mutable.persist(null);

    final Hash historicalRoot = mutable.rootHash();
    assertThat(storage.isWorldStateAvailable(historicalRoot)).isTrue();

    final ForestMutableWorldState historical =
        new ForestMutableWorldState(
            historicalRoot,
            new ForestWorldStateKeyValueStorage(rawStorage),
            new WorldStatePreimageKeyValueStorage(new InMemoryKeyValueStorage()),
            EvmConfiguration.DEFAULT);
    assertThat(historical.get(TARGET)).isNotNull();

    final Bytes32 accountKey = ProofPathHashingHolder.get().accountTrieKey(TARGET);
    final StoredMerklePatriciaTrie<Bytes32, Bytes> trie =
        new StoredMerklePatriciaTrie<>(
            (location, hash) -> storage.getAccountStateTrieNode(hash),
            Bytes32.wrap(historicalRoot.toArrayUnsafe()),
            b -> b,
            b -> b);
    final ForestTriePathProbe.PathReport report =
        ForestTriePathProbe.analyse(accountKey, trie.getValueWithProof(accountKey));

    assertThat(report.steps()).isNotEmpty();
    assertThat(report.steps().get(0).incomingReference())
        .isEqualTo(ForestTriePathProbe.ReferenceKind.ROOT);
    assertThat(report.terminal().nodeKind())
        .isIn(ForestTriePathProbe.NodeKind.LEAF, ForestTriePathProbe.NodeKind.BRANCH);
    assertThat(report.terminal().terminalKind())
        .isIn(ForestTriePathProbe.TerminalKind.LEAF, ForestTriePathProbe.TerminalKind.BRANCH_VALUE);
    assertThat(report.consumedNibbles()).isEqualTo(64);
    assertThat(report.remainingNibbles()).isZero();
    assertThat(report.steps()).allSatisfy(
        step -> assertThat(step.compactPathNibbleLength()).isGreaterThanOrEqualTo(0));
    assertThat(report.steps()).allSatisfy(step -> assertThat(step.nodeRlpLength()).isPositive());
  }

  @Test
  void exposesNodeAndReferenceTaxonomyForSyntheticTrieForms() {
    final DefaultNodeFactory<Bytes> factory = new DefaultNodeFactory<>(value -> value);
    final Node<Bytes> shortLeaf = factory.createLeaf(bytesToPath(Bytes32.ZERO), Bytes.of(1));
    final Node<Bytes> longLeaf = factory.createLeaf(bytesToPath(Bytes32.fromHexString("0x01")), Bytes.repeat((byte) 1, 64));
    final Node<Bytes> extension = factory.createExtension(Bytes.of(1, 2), shortLeaf);
    final Node<Bytes> branch = factory.createBranch(
        List.of(
            extension,
            longLeaf,
            org.hyperledger.besu.ethereum.trie.NullNode.<Bytes>instance(),
            org.hyperledger.besu.ethereum.trie.NullNode.<Bytes>instance(),
            org.hyperledger.besu.ethereum.trie.NullNode.<Bytes>instance(),
            org.hyperledger.besu.ethereum.trie.NullNode.<Bytes>instance(),
            org.hyperledger.besu.ethereum.trie.NullNode.<Bytes>instance(),
            org.hyperledger.besu.ethereum.trie.NullNode.<Bytes>instance(),
            org.hyperledger.besu.ethereum.trie.NullNode.<Bytes>instance(),
            org.hyperledger.besu.ethereum.trie.NullNode.<Bytes>instance(),
            org.hyperledger.besu.ethereum.trie.NullNode.<Bytes>instance(),
            org.hyperledger.besu.ethereum.trie.NullNode.<Bytes>instance(),
            org.hyperledger.besu.ethereum.trie.NullNode.<Bytes>instance(),
            org.hyperledger.besu.ethereum.trie.NullNode.<Bytes>instance(),
            org.hyperledger.besu.ethereum.trie.NullNode.<Bytes>instance(),
            org.hyperledger.besu.ethereum.trie.NullNode.<Bytes>instance()),
        java.util.Optional.empty());

    assertThat(branch.getChildren().get(0).getClass().getSimpleName()).isEqualTo("ExtensionNode");
    assertThat(branch.getChildren().get(1).isReferencedByHash()).isTrue();
    assertThat(branch.getChildren().get(2).getClass().getSimpleName()).isEqualTo("NullNode");
    assertThat(extension.getPath().toHexString()).isEqualTo("0x0102");
    assertThat(shortLeaf.getPath().get(shortLeaf.getPath().size() - 1))
        .isEqualTo(org.hyperledger.besu.ethereum.trie.CompactEncoding.LEAF_TERMINATOR);
    assertThat(shortLeaf.getEncodedBytes().size()).isPositive();

    final Bytes32 keyOne = Bytes32.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000000");
    final Bytes32 keyTwo = Bytes32.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001");
    final SimpleMerklePatriciaTrie<Bytes32, Bytes> syntheticTrie =
        new SimpleMerklePatriciaTrie<>(value -> value);
    syntheticTrie.put(keyOne, Bytes.repeat((byte) 1, 64));
    syntheticTrie.put(keyTwo, Bytes.repeat((byte) 2, 64));
    final ForestTriePathProbe.PathReport report =
        ForestTriePathProbe.analyse(keyOne, syntheticTrie.getValueWithProof(keyOne));

    assertThat(report.steps()).extracting(ForestTriePathProbe.Step::nodeKind)
        .contains(ForestTriePathProbe.NodeKind.BRANCH, ForestTriePathProbe.NodeKind.LEAF);
    assertThat(report.steps().get(0).incomingReference())
        .isEqualTo(ForestTriePathProbe.ReferenceKind.ROOT);
    assertThat(report.terminal().outgoingReference())
        .isEqualTo(ForestTriePathProbe.ReferenceKind.NONE);
    assertThat(report.terminal().terminalKind()).isEqualTo(ForestTriePathProbe.TerminalKind.LEAF);
    assertThat(report.steps()).anySatisfy(
        step ->
            assertThat(step.outgoingReference())
                .isIn(ForestTriePathProbe.ReferenceKind.INLINE, ForestTriePathProbe.ReferenceKind.HASHED));
  }
}
