/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package org.hyperledger.besu.ethereum.trie.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hyperledger.besu.ethereum.trie.CompactEncoding.bytesToPath;

import org.hyperledger.besu.ethereum.trie.Node;
import org.hyperledger.besu.ethereum.trie.NullNode;
import org.hyperledger.besu.ethereum.trie.Proof;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;
import org.hyperledger.besu.ethereum.trie.hash.KeccakTrieHashFunction;
import org.hyperledger.besu.ethereum.trie.hash.TrieHashFunction;
import org.hyperledger.besu.ethereum.trie.hash.TrieHashFunctionHolder;
import org.hyperledger.besu.ethereum.trie.patricia.DefaultNodeFactory;
import org.hyperledger.besu.ethereum.trie.patricia.SimpleMerklePatriciaTrie;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ForestAccountPathTraverserTest {
  private static final TrieHashFunction HASH = new KeccakTrieHashFunction();
  private static final Bytes32 KEY = Bytes32.fromHexString("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

  @BeforeEach
  void useKeccak() {
    TrieHashFunctionHolder.set(HASH);
  }

  @Test
  void traversesRootLeafAndExposesAuthenticatedLeaf() {
    final DefaultNodeFactory<Bytes> factory = new DefaultNodeFactory<>(value -> value);
    final Node<Bytes> leaf = factory.createLeaf(bytesToPath(KEY), Bytes.of(1));
    final ForestAccountTrieLoader.LoadResult loaded = load(singleNodeStore(leaf), leaf.getHash());

    assertThat(loaded.status()).isEqualTo(AuditValidationStatus.VALID);
    final AccountPathResult result = traverse(loaded.root().orElseThrow());

    assertThat(result.status()).isEqualTo(AuditValidationStatus.VALID);
    assertThat(result.proofNodeCount()).isEqualTo(1);
    assertThat(result.consumedNibbles()).isEqualTo(64);
    assertThat(result.remainingNibbles()).isZero();
    assertThat(result.terminalNodeBytes()).contains(leaf.getEncodedBytes());
    assertThat(result.accountValueBytes()).contains(Bytes.of(1));
    assertThat(result.accountValuePayloadOffset()).isPresent();
    assertThat(result.accountValuePayloadLength()).contains(1);
    assertThat(result.steps()).singleElement().satisfies(step -> {
      assertThat(step.incomingReference()).isEqualTo("ROOT");
      assertThat(step.outgoingReference()).isEqualTo("NONE");
      assertThat(step.terminal()).isTrue();
      assertThat(step.compactPathKind()).isEqualTo("LEAF");
    });
  }

  @Test
  void authenticatesHashedChildAndCountsLogicalNodes() {
    final DefaultNodeFactory<Bytes> factory = new DefaultNodeFactory<>(value -> value);
    final Bytes keyPath = bytesToPath(KEY);
    final Node<Bytes> child = factory.createLeaf(keyPath.slice(1), Bytes.repeat((byte) 7, 64));
    final Node<Bytes> root = branch(factory, keyPath.get(0), child);
    final Map<Bytes32, Bytes> nodes = new HashMap<>();
    nodes.put(root.getHash(), root.getEncodedBytes());
    nodes.put(child.getHash(), child.getEncodedBytes());

    final ForestAccountTrieLoader.LoadResult loaded = load(nodes, root.getHash());
    final AccountPathResult result = traverse(loaded.root().orElseThrow());

    assertThat(result.status()).isEqualTo(AuditValidationStatus.VALID);
    assertThat(result.proofNodeCount()).isEqualTo(2);
    assertThat(result.steps()).extracting(AccountPathStep::incomingReference)
        .containsExactly("ROOT", "HASHED");
    assertThat(result.steps().get(0).outgoingReference()).isEqualTo("HASHED");
    assertThat(result.totalProofRlpBytes()).isEqualTo(root.getEncodedBytes().size() + child.getEncodedBytes().size());
  }

  @Test
  void acceptsInlineChildAndReportsEmptyChildAsMissing() {
    final DefaultNodeFactory<Bytes> factory = new DefaultNodeFactory<>(value -> value);
    final Bytes keyPath = bytesToPath(KEY);
    final Node<Bytes> inlineLeaf = factory.createLeaf(keyPath.slice(63), Bytes.of(1));
    final Node<Bytes> root = factory.createExtension(keyPath.slice(0, 63), inlineLeaf);
    final ForestAccountTrieLoader.LoadResult loaded = load(singleNodeStore(root), root.getHash());

    final AccountPathResult valid = traverse(loaded.root().orElseThrow());
    assertThat(valid.status()).isEqualTo(AuditValidationStatus.VALID);
    assertThat(valid.steps()).extracting(AccountPathStep::incomingReference)
        .containsExactly("ROOT", "INLINE");

    final Node<Bytes> emptyRoot = branch(factory, keyPath.get(0), NullNode.instance());
    final ForestAccountTrieLoader.LoadResult emptyLoaded = load(singleNodeStore(emptyRoot), emptyRoot.getHash());
    final AccountPathResult missing = traverse(emptyLoaded.root().orElseThrow());
    assertThat(missing.status()).isEqualTo(AuditValidationStatus.MISSING);
  }

  @Test
  void explicitlyTraversesBranchToInlineLeaf() {
    final DefaultNodeFactory<Bytes> factory = new DefaultNodeFactory<>(value -> value);
    final Bytes keyPath = bytesToPath(KEY);
    final Node<Bytes> root = branchChain(factory, keyPath, Bytes.of(1));
    final ForestAccountTrieLoader.LoadResult loaded = load(storeChain(root), root.getHash());
    final AccountPathResult result = traverse(loaded.root().orElseThrow());

    assertThat(result.status()).isEqualTo(AuditValidationStatus.VALID);
    assertThat(result.steps()).anySatisfy(step -> assertThat(step.outgoingReference()).isEqualTo("INLINE"));
    assertThat(result.steps()).extracting(AccountPathStep::incomingReference)
        .contains("INLINE");
  }

  @Test
  void explicitlyTraversesExtensionToHashedChild() {
    final DefaultNodeFactory<Bytes> factory = new DefaultNodeFactory<>(value -> value);
    final Bytes keyPath = bytesToPath(KEY);
    final Node<Bytes> child = factory.createLeaf(keyPath.slice(1), Bytes.repeat((byte) 8, 64));
    final Node<Bytes> root = factory.createExtension(keyPath.slice(0, 1), child);
    final ForestAccountTrieLoader.LoadResult loaded = load(store(root, child), root.getHash());
    final AccountPathResult result = traverse(loaded.root().orElseThrow());

    assertThat(result.status()).isEqualTo(AuditValidationStatus.VALID);
    assertThat(result.steps()).extracting(AccountPathStep::outgoingReference)
        .containsExactly("HASHED", "NONE");
  }

  @Test
  void explicitlyTraversesBothHashedAndInlineTransitions() {
    final DefaultNodeFactory<Bytes> factory = new DefaultNodeFactory<>(value -> value);
    final Bytes keyPath = bytesToPath(KEY);
    final Node<Bytes> root = branchChain(factory, keyPath, Bytes.of(1));
    final ForestAccountTrieLoader.LoadResult loaded = load(storeChain(root), root.getHash());
    final AccountPathResult result = traverse(loaded.root().orElseThrow());

    assertThat(result.status()).isEqualTo(AuditValidationStatus.VALID);
    assertThat(result.steps()).extracting(AccountPathStep::outgoingReference)
        .contains("HASHED", "INLINE");
    assertThat(result.proofNodeCount()).isGreaterThan(4);
  }

  @Test
  void rejectsRootAndChildReferenceMismatchesExplicitly() {
    final DefaultNodeFactory<Bytes> factory = new DefaultNodeFactory<>(value -> value);
    final Bytes keyPath = bytesToPath(KEY);
    final Node<Bytes> child = factory.createLeaf(keyPath.slice(1), Bytes.repeat((byte) 3, 64));
    final Node<Bytes> root = branch(factory, keyPath.get(0), child);
    final Map<Bytes32, Bytes> nodes = new HashMap<>();
    nodes.put(root.getHash(), root.getEncodedBytes());
    nodes.put(child.getHash(), factory.createLeaf(keyPath.slice(1), Bytes.repeat((byte) 4, 64)).getEncodedBytes());

    final ForestAccountTrieLoader.LoadResult loaded = load(nodes, root.getHash());
    final AccountPathResult childMismatch = traverse(loaded.root().orElseThrow());
    assertThat(childMismatch.status()).isEqualTo(AuditValidationStatus.REFERENCE_MISMATCH);

    final Map<Bytes32, Bytes> wrongRootStore = new HashMap<>();
    wrongRootStore.put(Bytes32.ZERO, root.getEncodedBytes());
    final ForestAccountTrieLoader.LoadResult rootMismatch = load(wrongRootStore, Bytes32.ZERO);
    assertThat(rootMismatch.status()).isEqualTo(AuditValidationStatus.REFERENCE_MISMATCH);
  }

  @Test
  void validatesExtensionPathAndBranchValueTermination() {
    final DefaultNodeFactory<Bytes> factory = new DefaultNodeFactory<>(value -> value);
    final Bytes keyPath = bytesToPath(KEY);
    final Node<Bytes> leaf = factory.createLeaf(keyPath.slice(63), Bytes.of(2));
    final Node<Bytes> extension = factory.createExtension(keyPath.slice(0, 63), leaf);
    final ForestAccountTrieLoader.LoadResult loaded = load(singleNodeStore(extension), extension.getHash());
    final AccountPathResult result = traverse(loaded.root().orElseThrow());
    assertThat(result.status()).isEqualTo(AuditValidationStatus.VALID);
    assertThat(result.steps()).extracting(AccountPathStep::nodeType)
        .containsExactly("ExtensionNode", "LeafNode");
    assertThat(result.steps().get(0).compactPathKind()).isEqualTo("EXTENSION");

    final Node<Bytes> branchTerminal = factory.createBranch(
        Collections.nCopies(16, NullNode.<Bytes>instance()), Optional.of(Bytes.of(9)));
    final Node<Bytes> terminalExtension = factory.createExtension(keyPath.slice(0, 64), branchTerminal);
    final ForestAccountTrieLoader.LoadResult branchLoaded = load(store(terminalExtension, branchTerminal), terminalExtension.getHash());
    final AccountPathResult branchResult = traverse(branchLoaded.root().orElseThrow());
    assertThat(branchResult.status()).isEqualTo(AuditValidationStatus.VALID);
    assertThat(branchResult.steps().get(1).terminal()).isTrue();
  }

  @Test
  void rejectsLeafPathMismatch() {
    final DefaultNodeFactory<Bytes> factory = new DefaultNodeFactory<>(value -> value);
    final Node<Bytes> leaf = factory.createLeaf(bytesToPath(Bytes32.ZERO), Bytes.of(1));
    final ForestAccountTrieLoader.LoadResult loaded = load(singleNodeStore(leaf), leaf.getHash());
    final AccountPathResult result = traverse(loaded.root().orElseThrow());
    assertThat(result.status()).isEqualTo(AuditValidationStatus.MALFORMED);
  }

  @Test
  void reportsOddAndEvenCompactPathEncodings() {
    final DefaultNodeFactory<Bytes> factory = new DefaultNodeFactory<>(value -> value);
    final Node<Bytes> evenLeaf = factory.createLeaf(bytesToPath(KEY), Bytes.of(1));
    final AccountPathResult even = traverse(evenLeaf);
    assertThat(even.status()).isEqualTo(AuditValidationStatus.VALID);
    assertThat(even.steps().get(0).compactPathOdd()).isFalse();

    final Bytes keyPath = bytesToPath(KEY);
    final Node<Bytes> oddExtension = factory.createExtension(keyPath.slice(0, 1),
        factory.createLeaf(keyPath.slice(1), Bytes.of(1)));
    final AccountPathResult odd = traverse(oddExtension);
    assertThat(odd.status()).isEqualTo(AuditValidationStatus.VALID);
    assertThat(odd.steps().get(0).compactPathOdd()).isTrue();
  }

  @Test
  void reportsIncompleteConsumptionAsUnexpectedEarlyTermination() {
    final DefaultNodeFactory<Bytes> factory = new DefaultNodeFactory<>(value -> value);
    final Node<Bytes> shortLeaf = factory.createLeaf(bytesToPath(KEY).slice(0, 2), Bytes.of(1));
    final AccountPathResult result = traverse(shortLeaf);
    assertThat(result.status()).isEqualTo(AuditValidationStatus.MALFORMED);
    assertThat(result.error()).contains("remaining key");
  }

  @Test
  void provesInlineTerminalIsOmittedFromProofListButIncludedLogically() {
    final SimpleMerklePatriciaTrie<Bytes32, Bytes> trie =
        new SimpleMerklePatriciaTrie<>(value -> value);
    final Bytes32 siblingKey = Bytes32.wrap(Bytes.concatenate(KEY.slice(0, 31), Bytes.of((byte) 0xee)).toArray());
    trie.put(KEY, Bytes.of(1));
    trie.put(siblingKey, Bytes.of(2));
    final Proof<Bytes> proof = trie.getValueWithProof(KEY);
    final AtomicReference<Node<Bytes>> root = new AtomicReference<>();
    trie.entriesFrom(node -> {
      root.set(node);
      return Map.of();
    });

    final AccountPathResult result = traverse(root.get());
    assertThat(result.status()).isEqualTo(AuditValidationStatus.VALID);
    assertThat(result.steps()).anySatisfy(step -> {
      assertThat(step.terminal()).isTrue();
      assertThat(step.incomingReference()).isEqualTo("INLINE");
    });
    assertThat(result.proofNodeCount()).isGreaterThan(proof.getProofRelatedNodes().size());
    assertThat(result.steps()).hasSize(result.proofNodeCount());
    assertThat(proof.getProofRelatedNodes()).doesNotContain(result.terminalNodeBytes().orElseThrow());
  }

  @Test
  void reportsInvalidKeyLengthAndMalformedCompactPathStructurally() {
    final DefaultNodeFactory<Bytes> factory = new DefaultNodeFactory<>(value -> value);
    final Node<Bytes> leaf = factory.createLeaf(bytesToPath(KEY), Bytes.of(1));
    final AccountPathResult invalidKey =
        new ForestAccountPathTraverser(Bytes.of(1), HASH, "keccak").traverse(leaf);
    assertThat(invalidKey.status()).isEqualTo(AuditValidationStatus.MALFORMED);

    final BytesValueRLPOutput output = new BytesValueRLPOutput();
    output.startList();
    output.writeBytes(Bytes.of((byte) 0x40));
    output.writeBytes(Bytes.of(1));
    output.endList();
    final Bytes malformed = output.encoded();
    final Map<Bytes32, Bytes> nodes = Map.of(HASH.hash(malformed), malformed);
    final ForestAccountTrieLoader.LoadResult loaded =
        load(nodes, HASH.hash(malformed));
    assertThat(loaded.status()).isEqualTo(AuditValidationStatus.MALFORMED);
  }

  private static AccountPathResult traverse(final Node<Bytes> root) {
    return new ForestAccountPathTraverser(KEY, HASH, "keccak").traverse(root);
  }

  private static ForestAccountTrieLoader.LoadResult load(
      final Map<Bytes32, Bytes> nodes, final Bytes32 rootHash) {
    return new ForestAccountTrieLoader(
            (location, hash) -> Optional.ofNullable(nodes.get(hash)),
            Bytes.EMPTY,
            rootHash,
            HASH,
            "keccak")
        .load();
  }

  private static Map<Bytes32, Bytes> singleNodeStore(final Node<Bytes> node) {
    return Map.of(node.getHash(), node.getEncodedBytes());
  }

  private static Map<Bytes32, Bytes> store(final Node<Bytes> first, final Node<Bytes> second) {
    final Map<Bytes32, Bytes> result = new HashMap<>();
    result.put(first.getHash(), first.getEncodedBytes());
    result.put(second.getHash(), second.getEncodedBytes());
    return result;
  }

  private static Map<Bytes32, Bytes> storeChain(final Node<Bytes> root) {
    final Map<Bytes32, Bytes> nodes = new HashMap<>();
    collect(root, nodes);
    return nodes;
  }

  private static void collect(final Node<Bytes> node, final Map<Bytes32, Bytes> nodes) {
    nodes.put(node.getHash(), node.getEncodedBytes());
    for (final Node<Bytes> child : node.getChildren()) {
      if (!(child instanceof NullNode)) collect(child, nodes);
    }
  }

  private static Node<Bytes> branchChain(
      final DefaultNodeFactory<Bytes> factory, final Bytes keyPath, final Bytes value) {
    Node<Bytes> current = factory.createLeaf(keyPath.slice(63), value);
    for (int index = 62; index >= 0; index--) {
      current = branch(factory, keyPath.get(index), current);
    }
    return current;
  }

  private static Node<Bytes> branch(
      final DefaultNodeFactory<Bytes> factory, final byte index, final Node<Bytes> child) {
    final List<Node<Bytes>> children = new ArrayList<>(Collections.nCopies(16, NullNode.<Bytes>instance()));
    children.set(index, child);
    return factory.createBranch(children, Optional.empty());
  }
}
