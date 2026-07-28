/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package org.hyperledger.besu.ethereum.trie.audit;

import org.apache.tuweni.bytes.Bytes;

/** One logical node and parent-reference transition in an account path. */
public record AccountPathStep(
    int nodeIndex,
    String nodeType,
    String incomingReference,
    String outgoingReference,
    int consumedNibblesBefore,
    int consumedNibblesByNode,
    int consumedNibblesAfter,
    int remainingNibbles,
    String compactPathKind,
    boolean compactPathOdd,
    int compactPathNibbleLength,
    int encodedRlpLength,
    boolean terminal,
    Bytes encodedNodeRlp) {
  public AccountPathStep(
      final int nodeIndex,
      final String nodeType,
      final String incomingReference,
      final String outgoingReference,
      final int consumedNibblesBefore,
      final int consumedNibblesByNode,
      final int consumedNibblesAfter,
      final int remainingNibbles,
      final String compactPathKind,
      final boolean compactPathOdd,
      final int compactPathNibbleLength,
      final int encodedRlpLength,
      final boolean terminal) {
    this(
        nodeIndex,
        nodeType,
        incomingReference,
        outgoingReference,
        consumedNibblesBefore,
        consumedNibblesByNode,
        consumedNibblesAfter,
        remainingNibbles,
        compactPathKind,
        compactPathOdd,
        compactPathNibbleLength,
        encodedRlpLength,
        terminal,
        Bytes.EMPTY);
  }
}
