/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.MutableWorldState;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;

import java.util.Optional;

import org.junit.jupiter.api.Test;

class HistoricalForestStateResolutionProbeTest {
  private static final long BLOCK = 42L;
  private static final Hash BLOCK_HASH = Hash.fromHexString("0x" + "11".repeat(32));
  private static final Hash STATE_ROOT = Hash.fromHexString("0x" + "22".repeat(32));

  @Test
  void resolvesCanonicalHeaderAndHistoricalStateAndChecksOpenedRoot() {
    final Blockchain blockchain = mock(Blockchain.class);
    final WorldStateArchive archive = mock(WorldStateArchive.class);
    final BlockHeader header = mock(BlockHeader.class);
    final MutableWorldState state = mock(MutableWorldState.class);
    when(blockchain.getBlockHashByNumber(BLOCK)).thenReturn(Optional.of(BLOCK_HASH));
    when(blockchain.getBlockHeaderSafe(BLOCK)).thenReturn(Optional.of(header));
    when(blockchain.blockIsOnCanonicalChain(BLOCK_HASH)).thenReturn(true);
    when(header.getHash()).thenReturn(BLOCK_HASH);
    when(header.getStateRoot()).thenReturn(STATE_ROOT);
    when(archive.getWorldState(any())).thenReturn(Optional.of(state));
    when(state.rootHash()).thenReturn(STATE_ROOT);

    final HistoricalForestStateResolutionProbe.Resolution result =
        new HistoricalForestStateResolutionProbe(blockchain, archive).resolve(BLOCK);

    assertThat(result.status())
        .isEqualTo(HistoricalForestStateResolutionProbe.Status.RESOLVED);
    assertThat(result.worldState()).contains(state);
  }

  @Test
  void distinguishesResolutionAndCanonicalityFailures() {
    final Blockchain blockchain = mock(Blockchain.class);
    final WorldStateArchive archive = mock(WorldStateArchive.class);
    when(blockchain.getBlockHashByNumber(BLOCK)).thenReturn(Optional.empty());
    assertThat(new HistoricalForestStateResolutionProbe(blockchain, archive).resolve(BLOCK).status())
        .isEqualTo(HistoricalForestStateResolutionProbe.Status.BLOCK_HEADER_RESOLUTION_FAILED);

    final BlockHeader header = mock(BlockHeader.class);
    final Hash otherHash = Hash.fromHexString("0x" + "33".repeat(32));
    when(blockchain.getBlockHashByNumber(BLOCK)).thenReturn(Optional.of(BLOCK_HASH));
    when(blockchain.getBlockHeaderSafe(BLOCK)).thenReturn(Optional.of(header));
    when(header.getHash()).thenReturn(otherHash);
    when(header.getStateRoot()).thenReturn(STATE_ROOT);
    when(blockchain.blockIsOnCanonicalChain(otherHash)).thenReturn(false);
    assertThat(new HistoricalForestStateResolutionProbe(blockchain, archive).resolve(BLOCK).status())
        .isEqualTo(HistoricalForestStateResolutionProbe.Status.CANONICALITY_MISMATCH);
  }

  @Test
  void distinguishesUnavailableStateAndOpenedRootMismatch() {
    final Blockchain blockchain = mock(Blockchain.class);
    final WorldStateArchive archive = mock(WorldStateArchive.class);
    final BlockHeader header = mock(BlockHeader.class);
    when(blockchain.getBlockHashByNumber(BLOCK)).thenReturn(Optional.of(BLOCK_HASH));
    when(blockchain.getBlockHeaderSafe(BLOCK)).thenReturn(Optional.of(header));
    when(blockchain.blockIsOnCanonicalChain(BLOCK_HASH)).thenReturn(true);
    when(header.getHash()).thenReturn(BLOCK_HASH);
    when(header.getStateRoot()).thenReturn(STATE_ROOT);

    when(archive.getWorldState(any())).thenReturn(Optional.empty());
    assertThat(new HistoricalForestStateResolutionProbe(blockchain, archive).resolve(BLOCK).status())
        .isEqualTo(HistoricalForestStateResolutionProbe.Status.HISTORICAL_STATE_UNAVAILABLE);

    final MutableWorldState state = mock(MutableWorldState.class);
    when(archive.getWorldState(any())).thenReturn(Optional.of(state));
    when(state.rootHash()).thenReturn(Hash.fromHexString("0x" + "44".repeat(32)));
    assertThat(new HistoricalForestStateResolutionProbe(blockchain, archive).resolve(BLOCK).status())
        .isEqualTo(HistoricalForestStateResolutionProbe.Status.OPENED_ROOT_MISMATCH);
  }
}
