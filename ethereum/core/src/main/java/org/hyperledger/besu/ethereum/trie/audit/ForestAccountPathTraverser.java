/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package org.hyperledger.besu.ethereum.trie.audit;

import static org.hyperledger.besu.ethereum.trie.CompactEncoding.LEAF_TERMINATOR;

import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPInput;
import org.hyperledger.besu.ethereum.trie.CompactEncoding;
import org.hyperledger.besu.ethereum.trie.MerkleTrieException;
import org.hyperledger.besu.ethereum.trie.Node;
import org.hyperledger.besu.ethereum.trie.NullNode;
import org.hyperledger.besu.ethereum.trie.PathNodeVisitor;
import org.hyperledger.besu.ethereum.trie.StoredNode;
import org.hyperledger.besu.ethereum.trie.hash.TrieHashFunction;
import org.hyperledger.besu.ethereum.trie.patricia.BranchNode;
import org.hyperledger.besu.ethereum.trie.patricia.ExtensionNode;
import org.hyperledger.besu.ethereum.trie.patricia.LeafNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/** Traverses an already-loaded account trie root without opening Forest storage. */
public final class ForestAccountPathTraverser {
  private final TrieHashFunction activeTrieHashFunction;
  private final String policyIdentity;
  private final boolean captureEncodedBytes;
  private final Bytes accountKey;
  private final Bytes keyPath;
  private final List<AccountPathStep> steps = new ArrayList<>();
  private AuditValidationStatus failureStatus;
  private String failureMessage;
  private Bytes terminalBytes;
  private Bytes accountValueBytes;
  private Integer accountValuePayloadOffset;
  private Integer accountValuePayloadLength;
  private int totalRlpBytes;

  public ForestAccountPathTraverser(
      final Bytes32 accountKey,
      final TrieHashFunction activeTrieHashFunction,
      final String policyIdentity) {
    this((Bytes) accountKey, activeTrieHashFunction, policyIdentity, false);
  }

  public ForestAccountPathTraverser(
      final Bytes accountKey,
      final TrieHashFunction activeTrieHashFunction,
      final String policyIdentity) {
    this(accountKey, activeTrieHashFunction, policyIdentity, false);
  }

  public ForestAccountPathTraverser(
      final Bytes32 accountKey,
      final TrieHashFunction activeTrieHashFunction,
      final String policyIdentity,
      final boolean captureEncodedBytes) {
    this((Bytes) accountKey, activeTrieHashFunction, policyIdentity, captureEncodedBytes);
  }

  public ForestAccountPathTraverser(
      final Bytes accountKey,
      final TrieHashFunction activeTrieHashFunction,
      final String policyIdentity,
      final boolean captureEncodedBytes) {
    this.accountKey = accountKey;
    this.activeTrieHashFunction = activeTrieHashFunction;
    this.policyIdentity = policyIdentity;
    this.captureEncodedBytes = captureEncodedBytes;
    this.keyPath = accountKey.size() == 32 ? CompactEncoding.bytesToPath(accountKey) : Bytes.EMPTY;
  }

  public String policyIdentity() {
    return policyIdentity;
  }

  public AccountPathResult traverse(final Node<Bytes> root) {
    if (accountKey.size() != 32) {
      return failure(AuditValidationStatus.MALFORMED, "Account trie key must be exactly 32 bytes");
    }
    try {
      walk(root, keyPath, "ROOT", Optional.empty(), 0);
      if (failureStatus != null) {
        return failure(failureStatus, failureMessage);
      }
      final int consumed = keyPath.size() - 1;
      if (consumed != 64) {
        return failure(AuditValidationStatus.MALFORMED, "Account path did not consume 64 nibbles");
      }
      return new AccountPathResult(
          AuditValidationStatus.VALID,
          accountKey,
          List.copyOf(steps),
          consumed,
          0,
          steps.size(),
          totalRlpBytes,
          Optional.ofNullable(terminalBytes),
          Optional.ofNullable(accountValueBytes),
          Optional.ofNullable(accountValuePayloadOffset),
          Optional.ofNullable(accountValuePayloadLength),
          "");
    } catch (final MerkleTrieException ex) {
      final AuditValidationStatus status =
          ex.getMessage() != null && ex.getMessage().startsWith("Unable to load trie node")
              ? AuditValidationStatus.MISSING
              : AuditValidationStatus.MALFORMED;
      return failure(status, ex.getMessage());
    } catch (final RuntimeException ex) {
      return failure(AuditValidationStatus.MALFORMED, ex.getMessage());
    }
  }

  private void walk(
      final Node<Bytes> node,
      final Bytes remaining,
      final String incomingReference,
      final Optional<Bytes32> expectedHash,
      final int consumedBefore) {
    if (node instanceof NullNode) {
      fail(AuditValidationStatus.MISSING, "Selected child is empty");
      return;
    }
    final PathNodeVisitor<Bytes> visitor =
        new PathNodeVisitor<>() {
          @Override
          public Node<Bytes> visit(final ExtensionNode<Bytes> extensionNode, final Bytes path) {
            return visitExtension(extensionNode, path, incomingReference, expectedHash, consumedBefore);
          }

          @Override
          public Node<Bytes> visit(final BranchNode<Bytes> branchNode, final Bytes path) {
            return visitBranch(branchNode, path, incomingReference, expectedHash, consumedBefore);
          }

          @Override
          public Node<Bytes> visit(final LeafNode<Bytes> leafNode, final Bytes path) {
            return visitLeaf(leafNode, path, incomingReference, expectedHash, consumedBefore);
          }

          @Override
          public Node<Bytes> visit(final NullNode<Bytes> nullNode, final Bytes path) {
            fail(AuditValidationStatus.MISSING, "Selected child is empty");
            return nullNode;
          }
        };
    node.accept(visitor, remaining);
  }

  private Node<Bytes> visitExtension(
      final ExtensionNode<Bytes> node,
      final Bytes remaining,
      final String incoming,
      final Optional<Bytes32> expected,
      final int consumedBefore) {
    if (!validateIdentity(node, expected)) return node;
    final PathInfo pathInfo = compactPath(node, false);
    if (pathInfo == null) return node;
    if (!startsWith(remaining, node.getPath())) {
      fail(AuditValidationStatus.MALFORMED, "Extension path mismatch");
      return node;
    }
    final int consumedBy = node.getPath().size();
    final Node<Bytes> child = node.getChild();
    final String outgoing = referenceType(child);
    addStep(node, incoming, outgoing, consumedBefore, consumedBy, pathInfo, false);
    walk(child, remaining.slice(consumedBy), outgoing, storedHash(child), consumedBefore + consumedBy);
    return node;
  }

  private Node<Bytes> visitBranch(
      final BranchNode<Bytes> node,
      final Bytes remaining,
      final String incoming,
      final Optional<Bytes32> expected,
      final int consumedBefore) {
    if (!validateIdentity(node, expected)) return node;
    if (remaining.isEmpty()) {
      fail(AuditValidationStatus.MALFORMED, "Branch reached without a path nibble");
      return node;
    }
    final byte nibble = remaining.get(0);
    if (nibble == LEAF_TERMINATOR) {
      if (remaining.size() != 1 || node.getValue().isEmpty()) {
        fail(AuditValidationStatus.MALFORMED, "Invalid branch terminal");
        return node;
      }
      final PathInfo none = new PathInfo("NONE", false, 0, Bytes.EMPTY);
      addStep(node, incoming, "NONE", consumedBefore, 0, none, true);
      terminalBytes = node.getEncodedBytes();
      return node;
    }
    if (nibble > 0x0f) {
      fail(AuditValidationStatus.MALFORMED, "Invalid branch path nibble");
      return node;
    }
    final Node<Bytes> child = node.child(nibble);
    final String outgoing = referenceType(child);
    addStep(node, incoming, outgoing, consumedBefore, 1, new PathInfo("NONE", false, 0, Bytes.EMPTY), false);
    if (child instanceof NullNode) {
      fail(AuditValidationStatus.MISSING, "Selected branch child is empty");
      return node;
    }
    walk(child, remaining.slice(1), outgoing, storedHash(child), consumedBefore + 1);
    return node;
  }

  private Node<Bytes> visitLeaf(
      final LeafNode<Bytes> node,
      final Bytes remaining,
      final String incoming,
      final Optional<Bytes32> expected,
      final int consumedBefore) {
    if (!validateIdentity(node, expected)) return node;
    final PathInfo pathInfo = compactPath(node, true);
    if (pathInfo == null) return node;
    if (!remaining.equals(node.getPath())) {
      fail(AuditValidationStatus.MALFORMED, "Leaf compact path does not consume the remaining key");
      return node;
    }
    final int consumedBy = Math.max(0, node.getPath().size() - 1);
    addStep(node, incoming, "NONE", consumedBefore, consumedBy, pathInfo, true);
    terminalBytes = node.getEncodedBytes();
    accountValueBytes = node.getValue().orElseThrow();
    final ItemSpan accountItem = accountValueItem(node.getEncodedBytes());
    if (accountItem == null) return node;
    accountValuePayloadOffset = accountItem.payloadOffset;
    accountValuePayloadLength = accountItem.payloadLength;
    return node;
  }

  private ItemSpan accountValueItem(final Bytes encodedNode) {
    try {
      final ItemSpan outer = itemSpan(encodedNode, 0);
      if (!outer.list || outer.payloadOffset + outer.payloadLength != encodedNode.size()) {
        fail(AuditValidationStatus.MALFORMED, "Leaf outer RLP has invalid bounds");
        return null;
      }
      final ItemSpan compact = itemSpan(encodedNode, outer.payloadOffset);
      final ItemSpan value = itemSpan(encodedNode, compact.end());
      if (value.end() != encodedNode.size() || value.list) {
        fail(AuditValidationStatus.MALFORMED, "Leaf account-value item has invalid bounds");
        return null;
      }
      return value;
    } catch (final RuntimeException ex) {
      fail(AuditValidationStatus.MALFORMED, "Malformed leaf RLP: " + ex.getMessage());
      return null;
    }
  }

  private static ItemSpan itemSpan(final Bytes input, final int offset) {
    if (offset >= input.size()) throw new IllegalArgumentException("RLP item outside node");
    final int prefix = input.get(offset) & 0xff;
    if (prefix <= 0x7f) return new ItemSpan(false, offset, 1, offset + 1);
    if (prefix <= 0xb7) {
      final int length = prefix - 0x80;
      return new ItemSpan(false, offset + 1, length, offset + 1 + length);
    }
    if (prefix <= 0xbf) {
      final int lengthBytes = prefix - 0xb7;
      final int length = readLength(input, offset + 1, lengthBytes);
      return new ItemSpan(false, offset + 1 + lengthBytes, length, offset + 1 + lengthBytes + length);
    }
    if (prefix <= 0xf7) {
      final int length = prefix - 0xc0;
      return new ItemSpan(true, offset + 1, length, offset + 1 + length);
    }
    final int lengthBytes = prefix - 0xf7;
    final int length = readLength(input, offset + 1, lengthBytes);
    return new ItemSpan(true, offset + 1 + lengthBytes, length, offset + 1 + lengthBytes + length);
  }

  private static int readLength(final Bytes input, final int offset, final int lengthBytes) {
    if (lengthBytes == 0 || offset + lengthBytes > input.size()) {
      throw new IllegalArgumentException("Invalid RLP length");
    }
    int length = 0;
    for (int i = 0; i < lengthBytes; i++) length = (length << 8) | (input.get(offset + i) & 0xff);
    return length;
  }

  private boolean validateIdentity(final Node<Bytes> node, final Optional<Bytes32> expected) {
    if (expected.isEmpty()) return true;
    final Bytes32 calculated = activeTrieHashFunction.hash(node.getEncodedBytes());
    if (!expected.get().equals(calculated)) {
      fail(
          AuditValidationStatus.REFERENCE_MISMATCH,
          "Child identity mismatch: expected " + expected.get() + " but calculated " + calculated);
      return false;
    }
    return true;
  }

  private PathInfo compactPath(final Node<Bytes> node, final boolean leaf) {
    try {
      final RLPInput input = RLP.input(node.getEncodedBytes());
      if (input.enterList() != 2) {
        fail(AuditValidationStatus.MALFORMED, "Path node must contain exactly two RLP items");
        return null;
      }
      final Bytes original = input.readBytes();
      final Bytes canonical = CompactEncoding.encode(node.getPath());
      if (!original.equals(canonical)) {
        fail(AuditValidationStatus.MALFORMED, "Compact path is not canonical");
        return null;
      }
      final Bytes decoded = CompactEncoding.decode(original);
      if (!decoded.equals(node.getPath())) {
        fail(AuditValidationStatus.MALFORMED, "Compact path does not match decoded node path");
        return null;
      }
      input.skipNext();
      input.leaveList();
      final int nibbleLength = leaf ? Math.max(0, node.getPath().size() - 1) : node.getPath().size();
      return new PathInfo(leaf ? "LEAF" : "EXTENSION", (nibbleLength & 1) == 1, nibbleLength, original);
    } catch (final RuntimeException ex) {
      fail(AuditValidationStatus.MALFORMED, "Malformed encoded compact path: " + ex.getMessage());
      return null;
    }
  }

  private void addStep(
      final Node<Bytes> node,
      final String incoming,
      final String outgoing,
      final int consumedBefore,
      final int consumedBy,
      final PathInfo pathInfo,
      final boolean terminal) {
    final int after = consumedBefore + consumedBy;
    final int remaining = Math.max(0, 64 - after);
    final Bytes encoded = node.getEncodedBytes();
    totalRlpBytes += encoded.size();
    steps.add(
        new AccountPathStep(
            steps.size(),
            node.getClass().getSimpleName(),
            incoming,
            outgoing,
            consumedBefore,
            consumedBy,
            after,
            remaining,
            pathInfo.kind,
            pathInfo.odd,
            pathInfo.nibbleLength,
            encoded.size(),
            terminal,
            captureEncodedBytes ? encoded : Bytes.EMPTY));
  }

  private static boolean startsWith(final Bytes value, final Bytes prefix) {
    return value.size() >= prefix.size() && value.slice(0, prefix.size()).equals(prefix);
  }

  private static String referenceType(final Node<Bytes> node) {
    if (node instanceof NullNode) return "EMPTY";
    if (node instanceof StoredNode) return "HASHED";
    return "INLINE";
  }

  private static Optional<Bytes32> storedHash(final Node<Bytes> node) {
    return node instanceof StoredNode ? Optional.of(node.getHash()) : Optional.empty();
  }

  private void fail(final AuditValidationStatus status, final String message) {
    if (failureStatus == null) {
      failureStatus = status;
      failureMessage = message;
    }
  }

  private AccountPathResult failure(final AuditValidationStatus status, final String message) {
    return new AccountPathResult(
        status,
        accountKey,
        List.copyOf(steps),
        steps.isEmpty() ? 0 : steps.get(steps.size() - 1).consumedNibblesAfter(),
        Math.max(0, 64 - (steps.isEmpty() ? 0 : steps.get(steps.size() - 1).consumedNibblesAfter())),
        steps.size(),
        totalRlpBytes,
        Optional.ofNullable(terminalBytes),
        Optional.ofNullable(accountValueBytes),
        Optional.ofNullable(accountValuePayloadOffset),
        Optional.ofNullable(accountValuePayloadLength),
        message == null ? "" : message);
  }

  private record PathInfo(String kind, boolean odd, int nibbleLength, Bytes encoded) {}

  private record ItemSpan(boolean list, int payloadOffset, int payloadLength, int end) {}
}
