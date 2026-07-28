/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.MutableWorldState;
import org.hyperledger.besu.ethereum.trie.pathbased.common.provider.WorldStateQueryParams;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;

import java.util.Objects;
import java.util.Optional;

/** Read-only Phase 4A probe for canonical historical Forest state resolution. */
public final class HistoricalForestStateResolutionProbe {
  private final Blockchain blockchain;
  private final WorldStateArchive worldStateArchive;

  public HistoricalForestStateResolutionProbe(
      final Blockchain blockchain, final WorldStateArchive worldStateArchive) {
    this.blockchain = Objects.requireNonNull(blockchain);
    this.worldStateArchive = Objects.requireNonNull(worldStateArchive);
  }

  public Resolution resolve(final long blockNumber) {
    final Optional<Hash> canonicalHash = blockchain.getBlockHashByNumber(blockNumber);
    if (canonicalHash.isEmpty()) {
      return Resolution.failure(
          Status.BLOCK_HEADER_RESOLUTION_FAILED,
          blockNumber,
          Optional.empty(),
          Optional.empty(),
          Optional.empty(),
          "No canonical block hash for block " + blockNumber);
    }

    final Optional<BlockHeader> header = blockchain.getBlockHeaderSafe(blockNumber);
    if (header.isEmpty()) {
      return Resolution.failure(
          Status.BLOCK_HEADER_RESOLUTION_FAILED,
          blockNumber,
          canonicalHash,
          Optional.empty(),
          Optional.empty(),
          "No canonical header for block " + blockNumber);
    }

    final BlockHeader resolvedHeader = header.get();
    final boolean canonicalHashMatches = canonicalHash.get().equals(resolvedHeader.getHash());
    final boolean headerIsCanonical = blockchain.blockIsOnCanonicalChain(resolvedHeader.getHash());
    if (!canonicalHashMatches || !headerIsCanonical) {
      return Resolution.failure(
          Status.CANONICALITY_MISMATCH,
          blockNumber,
          canonicalHash,
          header,
          Optional.of(resolvedHeader.getStateRoot()),
          "Canonical block/header identity mismatch");
    }

    final Hash stateRoot = resolvedHeader.getStateRoot();
    final Optional<MutableWorldState> state =
        worldStateArchive.getWorldState(
            WorldStateQueryParams.withStateRootAndBlockHashAndNoUpdateNodeHead(
                stateRoot, canonicalHash.get()));
    if (state.isEmpty()) {
      return Resolution.failure(
          Status.HISTORICAL_STATE_UNAVAILABLE,
          blockNumber,
          canonicalHash,
          header,
          Optional.of(stateRoot),
          "Historical Forest state is unavailable");
    }

    final Hash openedRoot = state.get().rootHash();
    if (!stateRoot.equals(openedRoot)) {
      return Resolution.failure(
          Status.OPENED_ROOT_MISMATCH,
          blockNumber,
          canonicalHash,
          header,
          Optional.of(stateRoot),
          "Opened root " + openedRoot + " differs from header root " + stateRoot);
    }

    return new Resolution(
        Status.RESOLVED,
        blockNumber,
        canonicalHash,
        header,
        Optional.of(stateRoot),
        state,
        "");
  }

  public enum Status {
    RESOLVED,
    BLOCK_HEADER_RESOLUTION_FAILED,
    CANONICALITY_MISMATCH,
    HISTORICAL_STATE_UNAVAILABLE,
    OPENED_ROOT_MISMATCH
  }

  public record Resolution(
      Status status,
      long blockNumber,
      Optional<Hash> canonicalHash,
      Optional<BlockHeader> header,
      Optional<Hash> stateRoot,
      Optional<MutableWorldState> worldState,
      String error) {
    private static Resolution failure(
        final Status status,
        final long blockNumber,
        final Optional<Hash> canonicalHash,
        final Optional<BlockHeader> header,
        final Optional<Hash> stateRoot,
        final String error) {
      return new Resolution(
          status,
          blockNumber,
          canonicalHash,
          header,
          stateRoot,
          Optional.empty(),
          error);
    }

    public boolean isResolved() {
      return status == Status.RESOLVED;
    }
  }
}
