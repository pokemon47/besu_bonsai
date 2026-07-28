/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import static org.hyperledger.besu.ethereum.trie.CompactEncoding.LEAF_TERMINATOR;

import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPInput;
import org.hyperledger.besu.ethereum.trie.Proof;

import java.util.ArrayList;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/** Read-only analysis of one ordered Forest trie proof path. */
final class ForestTriePathProbe {

  private ForestTriePathProbe() {}

  static PathReport analyse(final Bytes32 key, final Proof<Bytes> proof) {
    final List<Step> steps = new ArrayList<>();
    int consumed = 0;
    final Bytes keyPath = org.hyperledger.besu.ethereum.trie.CompactEncoding.bytesToPath(key);

    for (int index = 0; index < proof.getProofRelatedNodes().size(); index++) {
      final Bytes encoded = proof.getProofRelatedNodes().get(index);
      final RLPInput input = RLP.input(encoded);
      final int itemCount = input.enterList();
      final NodeKind kind;
      final Bytes compactPath;
      final CompactPathKind compactPathKind;
      final boolean compactPathOdd;
      final int compactPathNibbleLength;
      final int consumedAfter;
      final ReferenceKind nextReference;
      final TerminalKind terminalKind;

      if (itemCount == 17) {
        kind = NodeKind.BRANCH;
        compactPath = Bytes.EMPTY;
        compactPathKind = CompactPathKind.NONE;
        compactPathOdd = false;
        compactPathNibbleLength = 0;
        final int branchIndex = consumed < keyPath.size() ? keyPath.get(consumed) : -1;
        nextReference = classifyBranchReference(input, branchIndex);
        consumedAfter = branchIndex >= 0 && branchIndex != LEAF_TERMINATOR ? consumed + 1 : consumed;
        final boolean branchValuePresent = !input.nextIsNull();
        terminalKind =
            branchIndex == LEAF_TERMINATOR
                ? (branchValuePresent ? TerminalKind.BRANCH_VALUE : TerminalKind.INVALID)
                : TerminalKind.NONE;
        if (input.nextIsNull()) {
          input.skipNext();
        } else {
          input.readBytes();
        }
      } else if (itemCount == 2) {
        compactPath = input.readBytes();
        final Bytes decodedPath = org.hyperledger.besu.ethereum.trie.CompactEncoding.decode(compactPath);
        final boolean leaf = decodedPath.size() > 0 && decodedPath.get(decodedPath.size() - 1) == LEAF_TERMINATOR;
        kind = leaf ? NodeKind.LEAF : NodeKind.EXTENSION;
        final int pathNibbles = leaf ? decodedPath.size() - 1 : decodedPath.size();
        compactPathKind = leaf ? CompactPathKind.LEAF : CompactPathKind.EXTENSION;
        compactPathOdd = (pathNibbles & 1) == 1;
        compactPathNibbleLength = pathNibbles;
        if (leaf) {
          input.skipNext();
          nextReference = ReferenceKind.NONE;
          terminalKind = TerminalKind.LEAF;
        } else {
          nextReference = classifyChildReference(input);
          terminalKind = TerminalKind.NONE;
        }
        consumedAfter = consumed + pathNibbles;
      } else {
        throw new IllegalArgumentException("Unexpected trie node list size: " + itemCount);
      }

      input.leaveList();
      steps.add(
          new Step(
              index,
              kind,
              index == 0 ? ReferenceKind.ROOT : steps.get(index - 1).outgoingReference(),
              nextReference,
              terminalKind,
              consumed,
              consumedAfter,
              Math.max(0, 64 - consumedAfter),
              compactPath,
              compactPathKind,
              compactPathOdd,
              compactPathNibbleLength,
              encoded.size()));
      consumed = consumedAfter;
    }

    final Step terminal = steps.isEmpty() ? null : steps.get(steps.size() - 1);
    return new PathReport(key, steps, consumed, Math.max(0, 64 - consumed), terminal);
  }

  private static ReferenceKind classifyBranchReference(final RLPInput input, final int branchIndex) {
    ReferenceKind selected = ReferenceKind.NONE;
    for (int i = 0; i < 16; i++) {
      final ReferenceKind current;
      if (input.nextIsNull()) {
        input.skipNext();
        current = ReferenceKind.EMPTY;
      } else if (input.nextIsList()) {
        input.skipNext();
        current = ReferenceKind.INLINE;
      } else {
        input.readBytes32();
        current = ReferenceKind.HASHED;
      }
      if (i == branchIndex) {
        selected = current;
      }
    }
    return selected;
  }

  private static ReferenceKind classifyChildReference(final RLPInput input) {
    if (input.nextIsList()) {
      input.skipNext();
      return ReferenceKind.INLINE;
    }
    input.readBytes32();
    return ReferenceKind.HASHED;
  }

  enum NodeKind {
    BRANCH,
    EXTENSION,
    LEAF
  }

  enum ReferenceKind {
    ROOT,
    HASHED,
    INLINE,
    EMPTY,
    NONE
  }

  enum CompactPathKind {
    EXTENSION,
    LEAF,
    NONE
  }

  enum TerminalKind {
    LEAF,
    BRANCH_VALUE,
    NONE,
    INVALID
  }

  record Step(
      int nodeIndex,
      NodeKind nodeKind,
      ReferenceKind incomingReference,
      ReferenceKind outgoingReference,
      TerminalKind terminalKind,
      int consumedNibblesBefore,
      int consumedNibblesAfter,
      int remainingNibbles,
      Bytes compactPath,
      CompactPathKind compactPathKind,
      boolean compactPathOdd,
      int compactPathNibbleLength,
      int nodeRlpLength) {}

  record PathReport(
      Bytes32 key,
      List<Step> steps,
      int consumedNibbles,
      int remainingNibbles,
      Step terminal) {}
}
