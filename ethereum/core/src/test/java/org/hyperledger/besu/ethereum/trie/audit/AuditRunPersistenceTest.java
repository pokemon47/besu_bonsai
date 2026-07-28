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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuditRunPersistenceTest {
  private static final String ROOT_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  private static final String ROOT_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

  @TempDir Path tempDirectory;

  @Test
  void deterministicIdsAreStableSeparatedAndOrderIndependent() {
    final Bytes root = Bytes.fromHexString(ROOT_A);
    final String state = AuditRecordIds.stateId(12_500, root);
    final String path = AuditRecordIds.pathId(12_500, root, Bytes.fromHexString("0x01"));

    assertThat(state).isEqualTo(AuditRecordIds.stateId(12_500, root));
    assertThat(state).startsWith("state_00000000000000012500_");
    assertThat(path).startsWith("path_00000000000000012500_");
    assertThat(state).isNotEqualTo(path);
    assertThat(state).isNotEqualTo(AuditRecordIds.stateId(12_500, Bytes.fromHexString(ROOT_B)));
  }

  @Test
  void shortenedIdCollisionValidationUsesFullIntrinsicFields() {
    AuditRecordIds.requireSameIntrinsicFields("state_x", "root-a", "root-a");
    assertThatThrownBy(() -> AuditRecordIds.requireSameIntrinsicFields("state_x", "root-a", "root-b"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("collision");
  }

  @Test
  void commitsWholeAttemptDirectoryAndReconstructsPerStateCheckpoints() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String stateA = AuditRecordIds.stateId(2, Bytes.fromHexString(ROOT_A));
    final String stateB = AuditRecordIds.stateId(1, Bytes.fromHexString(ROOT_B));

    persistence.commitState(input(stateA, 2, ROOT_A));
    persistence.commitState(input(stateB, 1, ROOT_B));

    final AuditRunPersistence.Recovery recovery = persistence.scan();
    assertThat(recovery.activeCheckpoints()).containsKeys(stateA, stateB);
    assertThat(Files.exists(tempDirectory.resolve("states").resolve(stateA).resolve("attempt-01.part")))
        .isFalse();
    assertThat(Files.exists(tempDirectory.resolve("states").resolve(stateA).resolve("attempts/attempt-01")))
        .isTrue();
    assertThat(Files.readString(tempDirectory.resolve("run_manifest.json"))).contains("schema_version");
  }

  @Test
  void canonicalSerialisationPreservesEmptyFragmentsAndFinalNewlines() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String state = AuditRecordIds.stateId(12, Bytes.fromHexString(ROOT_A));
    persistence.commitState(input(state, 12, ROOT_A));

    final Path attempt = tempDirectory.resolve("states").resolve(state).resolve("attempts/attempt-01");
    assertThat(Files.readString(attempt.resolve("path_summary.jsonl")))
        .isEqualTo("{\"block_number\":12,\"schema_version\":\"audit_path_summary_v1\",\"state_id\":\"" + state + "\"}\n");
    assertThat(Files.size(attempt.resolve("errors.jsonl"))).isZero();
    assertThat(Files.readString(tempDirectory.resolve("state_summary.csv")))
        .startsWith("schema_version,state_id,block_number,state_root,state_status,")
        .endsWith("\n");
    assertThat(Files.readString(attempt.resolve("path_summary.jsonl")).lines()).hasSize(1);
  }

  @Test
  void highestValidAttemptIsActiveAndOlderAttemptIsExcluded() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String state = AuditRecordIds.stateId(3, Bytes.fromHexString(ROOT_A));
    persistence.commitState(input(state, 3, ROOT_A));
    persistence.commitState(input(state, 3, ROOT_A));

    final AuditRunPersistence.Recovery recovery = persistence.scan();
    assertThat(recovery.activeCheckpoints().get(state).attemptNumber()).isEqualTo(2);
    persistence.rebuildStateSummary();
    assertThat(Files.readString(tempDirectory.resolve("state_summary.csv"))).contains("attempt-02");
    assertThat(Files.readString(tempDirectory.resolve("state_summary.csv"))).doesNotContain("attempt-01");
  }

  @Test
  void fullJournalScanWorksWithoutLatestAndIgnoresStalePointer() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String state = AuditRecordIds.stateId(4, Bytes.fromHexString(ROOT_A));
    persistence.commitState(input(state, 4, ROOT_A));
    Files.delete(tempDirectory.resolve("checkpoints/latest"));
    assertThat(persistence.scan().activeCheckpoints()).containsKey(state);
    Files.writeString(tempDirectory.resolve("checkpoints/latest"), "checkpoint_missing.json\n");
    assertThat(persistence.scan().activeCheckpoints()).containsKey(state);
    Files.writeString(tempDirectory.resolve("checkpoints/latest"), "not-a-checkpoint-pointer\n");
    assertThat(persistence.scan().activeCheckpoints()).containsKey(state);
  }

  @Test
  void interruptedAttemptArtifactsAreNeverActive() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String abandonedState = AuditRecordIds.stateId(10, Bytes.fromHexString(ROOT_A));
    final Path stateDirectory = tempDirectory.resolve("states").resolve(abandonedState);
    Files.createDirectories(stateDirectory.resolve("attempts/attempt-01"));
    Files.createDirectories(stateDirectory.resolve("attempt-02.part"));
    assertThat(persistence.scan().activeCheckpoints()).doesNotContainKey(abandonedState);

    final String state = AuditRecordIds.stateId(11, Bytes.fromHexString(ROOT_A));
    persistence.commitState(input(state, 10, ROOT_A));
    final AuditRunPersistence.Recovery committed = persistence.scan();
    assertThat(committed.activeCheckpoints()).containsKey(state);
    Files.deleteIfExists(
        tempDirectory.resolve("checkpoints").resolve("checkpoint_" + state + "_attempt-01.json"));
    assertThat(persistence.scan().activeCheckpoints()).doesNotContainKey(state);
  }

  @Test
  void checkpointWithoutAttemptIsInvalidAndDoesNotTriggerRerun() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String state = AuditRecordIds.stateId(16, Bytes.fromHexString(ROOT_A));
    final AuditRunPersistence.AttemptCommit commit = persistence.commitState(input(state, 16, ROOT_A));
    try (var walk = Files.walk(commit.attemptDirectory())) {
      for (final Path child : walk.sorted(java.util.Comparator.reverseOrder()).toList()) {
        Files.deleteIfExists(child);
      }
    }
    assertThat(persistence.scan().activeCheckpoints()).doesNotContainKey(state);
    assertThat(persistence.scan().invalidCheckpointArtifacts()).anyMatch(value -> value.contains(state));
    persistence.rebuildStateSummary();
    assertThat(Files.readString(tempDirectory.resolve("state_summary.csv"))).doesNotContain(state);
  }

  @Test
  void fragmentDigestMismatchInvalidatesAttemptWithoutRerunningIt() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String state = AuditRecordIds.stateId(5, Bytes.fromHexString(ROOT_A));
    final AuditRunPersistence.AttemptCommit commit = persistence.commitState(input(state, 5, ROOT_A));
    Files.writeString(commit.attemptDirectory().resolve("path_summary.jsonl"), "tampered\n");

    final AuditRunPersistence.Recovery recovery = persistence.scan();
    assertThat(recovery.activeCheckpoints()).doesNotContainKey(state);
    assertThat(recovery.invalidCheckpoints()).extracting(AuditRunPersistence.Checkpoint::stateId)
        .contains(state);
  }

  @Test
  void checkpointRecordCountMismatchInvalidatesAttempt() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String state = AuditRecordIds.stateId(11, Bytes.fromHexString(ROOT_A));
    persistence.commitState(input(state, 11, ROOT_A));
    final Path checkpoint = checkpointPath(state);
    Files.writeString(
        checkpoint,
        Files.readString(checkpoint).replaceFirst("\\\"record_count\\\":1", "\\\"record_count\\\":2"));
    assertThat(persistence.scan().activeCheckpoints()).doesNotContainKey(state);
  }

  @Test
  void checkpointByteSizeMismatchIsDistinguishedFromDigestMismatch() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String state = AuditRecordIds.stateId(17, Bytes.fromHexString(ROOT_A));
    persistence.commitState(input(state, 17, ROOT_A));
    final Path checkpoint = checkpointPath(state);
    final String json = Files.readString(checkpoint);
    final String updated = json.replaceFirst("\\\"byte_size\\\":[0-9]+", "\\\"byte_size\\\":999999");
    Files.writeString(checkpoint, updated);
    final AuditRunPersistence.Recovery recovery = persistence.scan();
    assertThat(recovery.activeCheckpoints()).doesNotContainKey(state);
    assertThat(recovery.invalidCheckpointArtifacts()).anyMatch(value -> value.contains("byte-size mismatch"));
    assertThat(recovery.invalidCheckpointArtifacts()).noneMatch(value -> value.contains("digest mismatch"));
  }

  @Test
  void rejectedAttemptHistorySurvivesRestartAndAllowsOnlyOneRetry() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String state = AuditRecordIds.stateId(6, Bytes.fromHexString(ROOT_A));
    persistence.recordRejectedAttempt("run-1", state, 6, ROOT_A, 1, "test", "first failure");
    assertThat(persistence.scan().rejectedCheckpoints()).hasSize(1);
    persistence.commitState(input(state, 6, ROOT_A));
    assertThat(persistence.scan().activeCheckpoints().get(state).attemptNumber()).isEqualTo(2);
    persistence.recordRejectedAttempt("run-1", state, 6, ROOT_A, 3, "test", "second failure");
    assertThatThrownBy(() -> persistence.commitState(input(state, 6, ROOT_A)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("retry limit");
    assertThat(Files.readString(tempDirectory.resolve("run_manifest.json"))).contains("FAILED");

    final AuditRunPersistence restarted = new AuditRunPersistence(tempDirectory);
    assertThat(restarted.scan().rejectedCheckpoints()).hasSize(2);
    assertThatThrownBy(() -> restarted.commitState(input(state, 6, ROOT_A)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("retry limit");
  }

  @Test
  void stateIdConflictIsRejectedWithoutCreatingAnotherAttempt() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String state = AuditRecordIds.stateId(13, Bytes.fromHexString(ROOT_A));
    persistence.commitState(input(state, 13, ROOT_A));
    assertThatThrownBy(() -> persistence.commitState(input(state, 14, ROOT_B)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("intrinsic-field conflict");
    assertThat(persistence.scan().activeCheckpoints().get(state).attemptNumber()).isEqualTo(1);
  }

  @Test
  void compatibilityEvaluatorRequiresExplicitSupportForDifferentAnalyserVersions() {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    final AuditRunPersistence.Manifest stored = manifest();
    final AuditRunPersistence.CompatibilityDeclaration compatible =
        new AuditRunPersistence.CompatibilityDeclaration(
            "analyser-v2",
            Set.of(AuditRunSchema.RUN_SCHEMA),
            Set.of(AuditRunSchema.CHECKPOINT_FORMAT),
            Set.of(
                AuditRunSchema.PATH_FRAGMENT_SCHEMA,
                AuditRunSchema.RETAINED_FRAGMENT_SCHEMA,
                AuditRunSchema.ERROR_FRAGMENT_SCHEMA,
                AuditRunSchema.STATE_FRAGMENT_SCHEMA));
    assertThat(persistence.validateCompatibility(stored, compatible).compatible()).isTrue();
    final AuditRunPersistence.CompatibilityResult incompatible =
        persistence.validateCompatibility(
            stored,
            new AuditRunPersistence.CompatibilityDeclaration(
                "analyser-v3", Set.of(), Set.of(), Set.of()));
    assertThat(incompatible.compatible()).isFalse();
    assertThat(incompatible.restartRequired()).isTrue();
    assertThat(incompatible.detail())
        .contains("stored_analyser")
        .contains("current_analyser")
        .contains("run_schema")
        .contains("checkpoint_format")
        .contains("fragment_formats")
        .contains("restart_required=true");
  }

  @Test
  void degradedDerivedReplacementPreservesAuthoritativeCommit() throws Exception {
    final AuditFileOperations degraded =
        (source, target, options) -> {
          for (var option : options) {
            if (option == java.nio.file.StandardCopyOption.ATOMIC_MOVE
                && "state_summary.csv".equals(target.getFileName().toString())) {
              throw new java.nio.file.AtomicMoveNotSupportedException(source.toString(), target.toString(), "test");
            }
          }
          return Files.move(source, target, options);
        };
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory, degraded);
    persistence.initialize(manifest());
    final String state = AuditRecordIds.stateId(18, Bytes.fromHexString(ROOT_A));
    persistence.commitState(input(state, 18, ROOT_A));
    assertThat(persistence.scan().activeCheckpoints()).containsKey(state);
    assertThat(Files.readString(tempDirectory.resolve("state_summary.csv"))).contains(state);
    assertThat(Files.readString(tempDirectory.resolve("run_manifest.json"))).contains("true");
  }

  @Test
  void failedFinalisationDoesNotMarkRunCompleted() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String state = AuditRecordIds.stateId(15, Bytes.fromHexString(ROOT_A));
    persistence.commitState(input(state, 15, ROOT_A));
    assertThatThrownBy(
            () -> persistence.finalizeRun(Set.of("missing-state"), manifest()))
        .isInstanceOf(IOException.class);
    assertThat(Files.readString(tempDirectory.resolve("run_manifest.json")))
        .contains("RUNNING")
        .doesNotContain("COMPLETED");
  }

  @Test
  void schemaMismatchInvalidatesCheckpoint() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String state = AuditRecordIds.stateId(8, Bytes.fromHexString(ROOT_A));
    persistence.commitState(input(state, 8, ROOT_A));
    final Path checkpoint;
    try (var paths = Files.list(tempDirectory.resolve("checkpoints"))) {
      checkpoint =
          paths
              .filter(path -> path.getFileName().toString().startsWith("checkpoint_"))
              .findFirst()
              .orElseThrow();
    }
    Files.writeString(
        checkpoint,
        Files.readString(checkpoint).replace(AuditRunSchema.CHECKPOINT_SCHEMA, "audit_checkpoint_v0"));

    assertThat(persistence.scan().activeCheckpoints()).doesNotContainKey(state);
    assertThat(persistence.scan().invalidCheckpoints())
        .extracting(AuditRunPersistence.Checkpoint::stateId)
        .contains(state);
  }

  @Test
  void finalisationIsDeterministic() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String stateA = AuditRecordIds.stateId(8, Bytes.fromHexString(ROOT_A));
    final String stateB = AuditRecordIds.stateId(7, Bytes.fromHexString(ROOT_B));
    persistence.commitState(input(stateA, 8, ROOT_A));
    persistence.commitState(input(stateB, 7, ROOT_B));

    persistence.finalizeRun(Set.of(stateA, stateB), manifest());
    assertThat(Files.readString(tempDirectory.resolve("path_summary.jsonl")))
        .contains("\"block_number\":7")
        .contains("\"block_number\":8");
    assertThat(Files.readString(tempDirectory.resolve("global_summary.json"))).contains("COMPLETED");
    assertThat(Files.readString(tempDirectory.resolve("audit_report.md"))).contains("COMPLETED");
  }

  @Test
  void finalisationUsesOnlyActiveAttemptRecordsAndIgnoresPartDirectories() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String stateA = AuditRecordIds.stateId(20, Bytes.fromHexString(ROOT_A));
    final String stateB = AuditRecordIds.stateId(19, Bytes.fromHexString(ROOT_B));
    persistence.commitState(inputWithMarker(stateA, 20, ROOT_A, "old"));
    persistence.commitState(inputWithMarker(stateB, 19, ROOT_B, "state-b"));
    persistence.commitState(inputWithMarker(stateA, 20, ROOT_A, "new"));
    Files.writeString(
        tempDirectory.resolve("checkpoints/latest"),
        "checkpoint_" + stateB + "_attempt-01.json\n");
    final Path abandoned = tempDirectory.resolve("states/abandoned/attempt-01.part");
    Files.createDirectories(abandoned);
    Files.writeString(abandoned.resolve("path_summary.jsonl"), "part-only-marker\n");

    persistence.finalizeRun(Set.of(stateA, stateB), manifest());
    final String paths = Files.readString(tempDirectory.resolve("path_summary.jsonl"));
    assertThat(paths).contains("new").contains("state-b").doesNotContain("old").doesNotContain("part-only-marker");
    assertThat(Files.readString(tempDirectory.resolve("state_summary.csv"))).contains(stateA).contains(stateB);
    assertThat(paths.lines().filter(line -> line.contains("state_id")).count()).isEqualTo(2);
  }

  @Test
  void damagedManifestIsNonAuthoritativeAndFragmentsRemainInspectable() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final String state = AuditRecordIds.stateId(9, Bytes.fromHexString(ROOT_A));
    persistence.commitState(input(state, 9, ROOT_A));
    Files.writeString(tempDirectory.resolve("run_manifest.json"), "not-json\n");
    assertThat(persistence.scan().activeCheckpoints()).containsKey(state);
    assertThat(Files.exists(tempDirectory.resolve("states").resolve(state).resolve("attempts/attempt-01")))
        .isTrue();
  }

  @Test
  void manifestReplacementLeavesOnlyParseableCurrentManifest() throws Exception {
    final AuditRunPersistence persistence = new AuditRunPersistence(tempDirectory);
    persistence.initialize(manifest());
    final Path manifestPath = tempDirectory.resolve("run_manifest.json");
    assertThat(Files.isRegularFile(manifestPath)).isTrue();
    assertThat(Files.exists(manifestPath.resolveSibling("run_manifest.json.tmp"))).isFalse();
    persistence.initialize(manifest().withStatus("RUNNING", null));
    assertThat(Files.readString(manifestPath)).contains("RUNNING");
    assertThat(Files.exists(manifestPath.resolveSibling("run_manifest.json.tmp"))).isFalse();
  }

  private AuditRunPersistence.Manifest manifest() {
    return new AuditRunPersistence.Manifest(
        AuditRunSchema.RUN_SCHEMA,
        AuditRunSchema.CHECKPOINT_FORMAT,
        Map.of(
            "path_summary", AuditRunSchema.PATH_FRAGMENT_SCHEMA,
            "retained_paths", AuditRunSchema.RETAINED_FRAGMENT_SCHEMA,
            "errors", AuditRunSchema.ERROR_FRAGMENT_SCHEMA,
            "state_summary", AuditRunSchema.STATE_FRAGMENT_SCHEMA),
        "test-analyser",
        Map.of("test-analyser", true),
        "run-1",
        "account",
        "keccak",
        "keccak",
        "synthetic",
        Map.of(),
        Map.of(),
        Map.of(),
        "CREATED",
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z",
        null,
        0,
        0,
        0,
        Map.of(),
        true,
        false,
        null);
  }

  private static AuditRunPersistence.StateAttemptInput input(
      final String stateId, final long block, final String root) {
    return new AuditRunPersistence.StateAttemptInput(
        "run-1",
        stateId,
        block,
        root,
        "test-analyser",
        stateSummary(stateId, block, root),
        List.of(Map.of("block_number", block, "state_id", stateId)),
        List.of(Map.of("block_number", block, "state_id", stateId)),
        List.of());
  }

  private static Map<String, Object> stateSummary(
      final String stateId, final long block, final String root) {
    final Map<String, Object> summary = new HashMap<>();
    summary.put("schema_version", AuditRunSchema.STATE_FRAGMENT_SCHEMA);
    summary.put("state_id", stateId);
    summary.put("block_number", block);
    summary.put("state_root", root);
    summary.put("state_status", "COMPLETED");
    summary.put("path_count", 1);
    summary.put("valid_count", 1);
    summary.put("missing_count", 0);
    summary.put("malformed_count", 0);
    summary.put("reference_mismatch_count", 0);
    summary.put("max_proof_node_count", 1);
    summary.put("branch_node_count", 0);
    summary.put("extension_node_count", 0);
    summary.put("leaf_node_count", 1);
    summary.put("hashed_reference_count", 0);
    summary.put("inline_reference_count", 0);
    summary.put("empty_reference_count", 0);
    summary.put("total_rlp_bytes", 3);
    summary.put("error_count", 0);
    summary.put("checkpoint_reference", "pending");
    return summary;
  }

  private static AuditRunPersistence.StateAttemptInput inputWithMarker(
      final String stateId, final long block, final String root, final String marker) {
    final Map<String, Object> record = new HashMap<>();
    record.put("block_number", block);
    record.put("state_id", stateId);
    record.put("marker", marker);
    return new AuditRunPersistence.StateAttemptInput(
        "run-1", stateId, block, root, "test-analyser", stateSummary(stateId, block, root),
        List.of(record), List.of(record), List.of(record));
  }

  private Path checkpointPath(final String stateId) throws IOException {
    try (var paths = Files.list(tempDirectory.resolve("checkpoints"))) {
      return paths
          .filter(path -> path.getFileName().toString().startsWith("checkpoint_" + stateId + "_"))
          .findFirst()
          .orElseThrow();
    }
  }
}
