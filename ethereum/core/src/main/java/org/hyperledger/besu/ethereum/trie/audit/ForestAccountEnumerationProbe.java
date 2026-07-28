/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import org.hyperledger.besu.ethereum.trie.MerkleTrie;
import org.hyperledger.besu.ethereum.trie.Node;
import org.hyperledger.besu.ethereum.trie.TrieIterator;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/** Observes complete read-only account-leaf enumeration without imposing circuit limits. */
public final class ForestAccountEnumerationProbe {
  private ForestAccountEnumerationProbe() {}

  public static EnumerationReport observe(
      final MerkleTrie<Bytes32, Bytes> trie,
      final Function<Bytes32, AccountPathResult> authenticatedLookup) {
    final List<LeafObservation> leaves = new ArrayList<>();
    final Set<Bytes32> keys = new HashSet<>();
    trie.visitLeafs(
        (key, node) -> {
          final Bytes value = node.getValue().orElseThrow();
          if (!keys.add(key)) {
            throw new IllegalStateException("Duplicate enumerated account key: " + key);
          }
          final AccountPathResult authenticated = authenticatedLookup.apply(key);
          final boolean valueMatches =
              authenticated.accountValueBytes().map(value::equals).orElse(false);
          leaves.add(
              new LeafObservation(
                  key,
                  value,
                  node.getEncodedBytes(),
                  node.getPath().size(),
                  authenticated,
                  valueMatches));
          return TrieIterator.State.CONTINUE;
        });

    final NodeFormReport nodeForms = observeNodeForms(trie);

    return new EnumerationReport(
        List.copyOf(leaves),
        leaves.size(),
        Set.copyOf(keys),
        nodeForms.nodeKinds(),
        nodeForms.referenceKinds());
  }

  static NodeFormReport observeNodeForms(final MerkleTrie<Bytes32, Bytes> trie) {
    final EnumMap<NodeKind, Integer> nodeKinds = new EnumMap<>(NodeKind.class);
    final EnumMap<ReferenceKind, Integer> references = new EnumMap<>(ReferenceKind.class);
    trie.visitAll(
        node -> {
          nodeKinds.merge(NodeKind.from(node), 1, Integer::sum);
          references.merge(ReferenceKind.from(node), 1, Integer::sum);
        });
    return new NodeFormReport(MapCopy.copy(nodeKinds), MapCopy.copy(references));
  }

  public record EnumerationReport(
      List<LeafObservation> leaves,
      int leafCount,
      Set<Bytes32> keys,
      java.util.Map<NodeKind, Integer> nodeKinds,
      java.util.Map<ReferenceKind, Integer> referenceKinds) {}

  public record LeafObservation(
      Bytes32 key,
      Bytes value,
      Bytes encodedLeaf,
      int compactPathLength,
      AccountPathResult authenticatedPath,
      boolean valueMatchesAuthenticatedPath) {}

  public record NodeFormReport(
      java.util.Map<NodeKind, Integer> nodeKinds,
      java.util.Map<ReferenceKind, Integer> referenceKinds) {}

  public enum NodeKind {
    BRANCH,
    EXTENSION,
    LEAF,
    NULL,
    OTHER;

    private static NodeKind from(final Node<?> node) {
      final String name = node.getClass().getSimpleName();
      return switch (name) {
        case "BranchNode" -> BRANCH;
        case "ExtensionNode" -> EXTENSION;
        case "LeafNode" -> LEAF;
        case "NullNode" -> NULL;
        default -> OTHER;
      };
    }
  }

  public enum ReferenceKind {
    INLINE,
    HASHED,
    ROOT,
    NONE;

    private static ReferenceKind from(final Node<?> node) {
      if (node instanceof org.hyperledger.besu.ethereum.trie.NullNode) {
        return NONE;
      }
      return node.isReferencedByHash() ? HASHED : INLINE;
    }
  }

  private static final class MapCopy {
    private static <K extends Enum<K>> java.util.Map<K, Integer> copy(
        final java.util.Map<K, Integer> source) {
      return java.util.Map.copyOf(source);
    }
  }
}
