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

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.MutableWorldState;
import org.hyperledger.besu.ethereum.proof.hashing.KeccakProofPathHashing;
import org.hyperledger.besu.ethereum.proof.hashing.ProofPathHashingHolder;
import org.hyperledger.besu.ethereum.storage.keyvalue.WorldStatePreimageKeyValueStorage;
import org.hyperledger.besu.ethereum.trie.forest.storage.ForestWorldStateKeyValueStorage;
import org.hyperledger.besu.ethereum.trie.forest.worldview.ForestMutableWorldState;
import org.hyperledger.besu.evm.internal.EvmConfiguration;
import org.hyperledger.besu.evm.worldstate.WorldUpdater;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;
import org.hyperledger.besu.services.kvstore.InMemoryKeyValueStorage;

import org.apache.tuweni.bytes.Bytes;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AccountStateAuditProcessorTest {
  private static final long BLOCK = 42L;
  private static final Hash BLOCK_HASH = Hash.fromHexString("0x" + "11".repeat(32));
  private static final Address ACCOUNT =
      Address.fromHexString("0x1234567890123456789012345678901234567890");

  @TempDir Path tempDirectory;

  @BeforeEach
  void useKeccakPolicy() {
    ProofPathHashingHolder.set(new KeccakProofPathHashing());
  }

  @Test
  void processesAndRecoversOneCompleteStateWithV2Fragments() throws Exception {
    final InMemoryKeyValueStorage rawStorage = new InMemoryKeyValueStorage();
    final ForestWorldStateKeyValueStorage storage = new ForestWorldStateKeyValueStorage(rawStorage);
    final ForestMutableWorldState worldState =
        new ForestMutableWorldState(
            storage,
            new WorldStatePreimageKeyValueStorage(new InMemoryKeyValueStorage()),
            EvmConfiguration.DEFAULT);
    final WorldUpdater updater = worldState.updater();
    updater.createAccount(ACCOUNT).setBalance(Wei.of(42));
    updater.commit();
    worldState.persist(null);
    final Hash stateRoot = worldState.rootHash();

    final Blockchain blockchain = mock(Blockchain.class);
    final WorldStateArchive archive = mock(WorldStateArchive.class);
    final BlockHeader header = mock(BlockHeader.class);
    when(blockchain.getBlockHashByNumber(BLOCK)).thenReturn(Optional.of(BLOCK_HASH));
    when(blockchain.getBlockHeaderSafe(BLOCK)).thenReturn(Optional.of(header));
    when(blockchain.blockIsOnCanonicalChain(BLOCK_HASH)).thenReturn(true);
    when(header.getHash()).thenReturn(BLOCK_HASH);
    when(header.getStateRoot()).thenReturn(stateRoot);
    when(archive.getWorldState(any())).thenReturn(Optional.of(worldState));

    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    final AccountStateAuditProcessor processor =
        new AccountStateAuditProcessor(
            new HistoricalForestStateResolutionProbe(blockchain, archive),
            new ForestAccountTrieAccess(storage),
            persistence);

    final AccountStateAuditProcessor.ProcessResult result =
        processor.process(
            new AccountStateAuditProcessor.Input(
                BLOCK, "keccak256", "run-v2", "ignored", tempDirectory, "audit-test"));

    assertThat(result.finalClassification()).isEqualTo("COMPLETED");
    final AuditRunPersistence.V2Recovery recovery = persistence.scanV2();
    assertThat(recovery.activeCheckpoints()).containsKey(result.stateId());
    final AuditRunPersistence.V2Checkpoint checkpoint = recovery.activeCheckpoints().get(result.stateId());
    assertThat(checkpoint.finalClassification()).isEqualTo("COMPLETED");
    assertThat(checkpoint.internalStatus()).isEqualTo("COMMITTED");
    assertThat(checkpoint.fragments()).hasSize(4);
    assertThat(result.accountCount()).isEqualTo(1);
    assertThat(tempDirectory.resolve(checkpoint.attemptDirectory()).resolve("retained_paths.jsonl"))
        .isRegularFile();
    final String pathSummary =
        Files.readString(tempDirectory.resolve(checkpoint.attemptDirectory()).resolve("path_summary.jsonl"));
    assertThat(pathSummary)
        .contains("audit_path_summary_v2")
        .contains("terminal_form")
        .contains("branch_node_count")
        .contains("maximum_node_rlp_bytes")
        .contains("compact_path_nibble_count");
    assertThat(Files.readString(tempDirectory.resolve(checkpoint.attemptDirectory()).resolve("state_summary.json")))
        .contains("account_summary_record_count")
        .contains("root_verification_passed")
        .contains("maximum_proof_node_count");
    assertThat(tempDirectory.resolve("state_summary_v2.jsonl")).isRegularFile();
}

  @Test
  void recordsUnavailableAsFinalClassificationWithoutPretendingItWasCommittedData() throws Exception {
    final Blockchain blockchain = mock(Blockchain.class);
    final WorldStateArchive archive = mock(WorldStateArchive.class);
    final BlockHeader header = mock(BlockHeader.class);
    final Hash stateRoot = Hash.fromHexString("0x" + "22".repeat(32));
    when(blockchain.getBlockHashByNumber(BLOCK)).thenReturn(Optional.of(BLOCK_HASH));
    when(blockchain.getBlockHeaderSafe(BLOCK)).thenReturn(Optional.of(header));
    when(blockchain.blockIsOnCanonicalChain(BLOCK_HASH)).thenReturn(true);
    when(header.getHash()).thenReturn(BLOCK_HASH);
    when(header.getStateRoot()).thenReturn(stateRoot);
    when(archive.getWorldState(any())).thenReturn(Optional.empty());

    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    final AccountStateAuditProcessor processor =
        new AccountStateAuditProcessor(
            new HistoricalForestStateResolutionProbe(blockchain, archive),
            mock(ForestAccountTrieAccess.class),
            persistence);

    final AccountStateAuditProcessor.ProcessResult result =
        processor.process(
            new AccountStateAuditProcessor.Input(
                BLOCK, "keccak256", "run-v2", "ignored", tempDirectory, "audit-test"));

    assertThat(result.finalClassification()).isEqualTo("UNAVAILABLE");
    final AuditRunPersistence.V2Checkpoint checkpoint =
        persistence.scanV2().activeCheckpoints().get(result.stateId());
    assertThat(checkpoint.finalClassification()).isEqualTo("UNAVAILABLE");
    assertThat(checkpoint.internalStatus()).isEqualTo("COMMITTED");
    assertThat(checkpoint.attemptDirectory()).isNull();
    assertThat(checkpoint.fragments()).isEmpty();
    assertThat(Files.readString(tempDirectory.resolve("state_summary_v2.jsonl")))
        .contains("UNAVAILABLE");
    try (var errors = Files.list(tempDirectory.resolve("states").resolve(result.stateId()).resolve("diagnostic"))) {
      assertThat(Files.readString(errors.findFirst().orElseThrow()))
          .contains("audit_errors_v2")
          .contains("HISTORICAL_STATE_UNAVAILABLE")
          .contains("attempt_number")
          .contains("retryable");
    }
}

  @Test
  void rejectedAttemptsRemainInternalAndASecondFailureGetsFailedClassification() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    final String state = AuditRecordIds.stateId(7, Bytes.fromHexString("0x" + "33".repeat(32)));
    persistence.recordRejectedAttemptV2(
        "run-v2", state, 7, "0x" + "44".repeat(32), "0x" + "33".repeat(32),
        "audit-test", "AUTH", "REFERENCE_MISMATCH", "first");
    persistence.recordRejectedAttemptV2(
        "run-v2", state, 7, "0x" + "44".repeat(32), "0x" + "33".repeat(32),
        "audit-test", "AUTH", "REFERENCE_MISMATCH", "second");
    persistence.recordFinalClassificationV2(
        "run-v2", state, 7, "0x" + "44".repeat(32), "0x" + "33".repeat(32),
        "FAILED", "audit-test", "PROCESSING", "RETRY_EXHAUSTED", "second");

    final AuditRunPersistence.V2Recovery recovery = persistence.scanV2();
    assertThat(recovery.rejectedCheckpoints()).hasSize(2);
    assertThat(recovery.activeCheckpoints().get(state).finalClassification()).isEqualTo("FAILED");
    assertThat(recovery.activeCheckpoints().get(state).internalStatus()).isEqualTo("COMMITTED");
    assertThat(recovery.activeCheckpoints().get(state).attemptDirectory()).isNull();
}
}
