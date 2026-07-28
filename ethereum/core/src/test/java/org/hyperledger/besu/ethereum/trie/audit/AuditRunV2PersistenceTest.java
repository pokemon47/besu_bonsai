/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

class AuditRunV2PersistenceTest {
  private static final String ROOT = "0x" + "11".repeat(32);
  private static final String BLOCK_HASH = "0x" + "22".repeat(32);

  @TempDir Path tempDirectory;

  @Test
  void compatibleV2ManifestCanResume() throws Exception {
    final AuditRunPersistence persistence = persistence("compatible");
    final AuditRunPersistence.Manifest manifest = manifest("run-1", "keccak256", "policy-a");
    persistence.initialize(manifest);
    persistence.ensureCompatibleV2Manifest(manifest);
  }

  @Test
  void phase4CManifestCannotResumeAsPhase4D() throws Exception {
    final AuditRunPersistence persistence = persistence("phase-marker");
    persistence.initialize(manifest("run-1", "keccak256", "policy-a", "4C"));
    assertThatThrownBy(() -> persistence.ensureCompatibleV2Manifest(manifest("run-1", "keccak256", "policy-a", "4D")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("phase");
  }

  @Test
  void preExistingV1ManifestIsRejected() throws Exception {
    final AuditRunPersistence persistence = persistence("v1");
    final AuditRunPersistence.Manifest v1 = manifest("run-1", "keccak256", "policy-a").withStatus("RUNNING", null);
    persistence.initialize(
        new AuditRunPersistence.Manifest(
            AuditRunSchema.RUN_SCHEMA,
            AuditRunSchema.CHECKPOINT_FORMAT,
            Map.of(),
            v1.analyserVersion(),
            Map.of(),
            v1.runId(),
            v1.auditMode(),
            v1.hashVariant(),
            v1.hashPolicyIdentity(),
            v1.databaseIdentity(),
            Map.of(),
            Map.of(),
            Map.of(),
            "RUNNING",
            v1.startTimestamp(),
            v1.lastUpdateTimestamp(),
            null,
            0,
            0,
            0,
            Map.of(),
            null,
            false,
            null));
    assertThatThrownBy(() -> persistence.ensureCompatibleV2Manifest(manifest("run-1", "keccak256", "policy-a")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("not compatible");
  }

  @Test
  void incompatibleV2FieldsAreRejected() throws Exception {
    final AuditRunPersistence.Manifest base = manifest("run-1", "keccak256", "policy-a");
    for (final AuditRunPersistence.Manifest mismatch : List.of(
        manifest("run-2", "keccak256", "policy-a"),
        manifest("run-1", "poseidon2", "policy-a"),
        manifest("run-1", "keccak256", "policy-b"))) {
      final AuditRunPersistence persistence = persistence("mismatch-" + mismatch.runId() + mismatch.hashVariant() + mismatch.hashPolicyIdentity());
      persistence.initialize(base);
      assertThatThrownBy(() -> persistence.ensureCompatibleV2Manifest(mismatch))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("mismatch");
    }
  }

  @Test
  void rejectedV2AttemptThenValidSecondAttemptCompletes() throws Exception {
    final AuditRunPersistence persistence = persistence("retry");
    final AuditRunPersistence.Manifest manifest = manifest("run-1", "keccak256", "policy-a");
    persistence.initialize(manifest);
    final String state = AuditRecordIds.stateId(1, Bytes.fromHexString(ROOT));
    persistence.recordRejectedAttemptV2(
        "run-1", state, 1, BLOCK_HASH, ROOT, "audit-test", "ENUMERATION", "DUPLICATE_KEY", "first");
    final AuditRunPersistence.V2AttemptCommit commit = persistence.commitStateV2(input(state, 1, "second"));
    assertThat(commit.checkpoint().attemptNumber()).isEqualTo(2);
    assertThat(persistence.scanV2().rejectedCheckpoints()).hasSize(1);
    assertThat(persistence.scanV2().activeCheckpoints().get(state).attemptNumber()).isEqualTo(2);
    assertThat(Files.readString(tempDirectory.resolve("retry/state_summary_v2.jsonl"))).contains("attempt_number");
  }

  @Test
  void promotedV2AttemptWithoutCheckpointIsNotCompleted() throws Exception {
    final AuditRunPersistence persistence = persistence("no-checkpoint");
    persistence.initialize(manifest("run-1", "keccak256", "policy-a"));
    final String state = AuditRecordIds.stateId(2, Bytes.fromHexString(ROOT));
    final AuditRunPersistence.V2AttemptCommit commit = persistence.commitStateV2(input(state, 2, "one"));
    deleteCheckpoint(state, 1);
    assertThat(persistence.scanV2().activeCheckpoints()).doesNotContainKey(state);
    assertThat(Files.isDirectory(commit.attemptDirectory())).isTrue();
  }

  @Test
  void V2CheckpointWithoutValidAttemptIsRejected() throws Exception {
    final AuditRunPersistence persistence = persistence("no-attempt");
    persistence.initialize(manifest("run-1", "keccak256", "policy-a"));
    final String state = AuditRecordIds.stateId(3, Bytes.fromHexString(ROOT));
    persistence.commitStateV2(input(state, 3, "one"));
    deleteRecursively(tempDirectory.resolve("no-attempt/states").resolve(state).resolve("attempts/attempt-01"));
    assertThat(persistence.scanV2().activeCheckpoints()).doesNotContainKey(state);
  }

  @Test
  void V2FragmentDigestSizeAndCountFailuresAreRejected() throws Exception {
    assertThatTamperingRejects("digest", json -> rewriteCheckpoint(json, "\"sha256\":\"[0-9a-f]+\"", "\"sha256\":\"deadbeef\""));
    assertThatTamperingRejects("size", json -> rewriteCheckpoint(json, "\"byte_size\":\\d+", "\"byte_size\":999999"));
    assertThatTamperingRejects("count", json -> rewriteCheckpoint(json, "\"record_count\":1", "\"record_count\":2"));
  }

  @Test
  void checkpointPromotionFailureCannotLeaveCompletedState() throws Exception {
    final Path run = tempDirectory.resolve("checkpoint-failure");
    final AuditFileOperations failing =
        (source, target, options) -> {
          for (final java.nio.file.StandardCopyOption option : options) {
            if (option == java.nio.file.StandardCopyOption.ATOMIC_MOVE
                && target.getFileName().toString().startsWith("checkpoint_")) {
              throw new java.nio.file.AtomicMoveNotSupportedException(source.toString(), target.toString(), "test");
            }
          }
          return Files.move(source, target, options);
        };
    final AuditRunPersistence persistence = new AuditRunPersistence(run, failing);
    persistence.initialize(manifest("run-1", "keccak256", "policy-a"));
    final String state = AuditRecordIds.stateId(7, Bytes.fromHexString(ROOT));
    assertThatThrownBy(() -> persistence.commitStateV2(input(state, 7, "one")))
        .isInstanceOf(IOException.class);
    assertThat(persistence.scanV2().activeCheckpoints()).doesNotContainKey(state);
  }

  @Test
  void V2CheckpointPointingAtV1AttemptIsRejected() throws Exception {
    final AuditRunPersistence persistence = persistence("v2-v1-attempt");
    persistence.initialize(manifest("run-1", "keccak256", "policy-a"));
    final String state = AuditRecordIds.stateId(8, Bytes.fromHexString(ROOT));
    persistence.commitStateV2(input(state, 8, "one"));
    final Path checkpoint = tempDirectory.resolve("v2-v1-attempt/checkpoints/checkpoint_" + state + "_attempt-01.json");
    final Path v1Attempt = tempDirectory.resolve("v2-v1-attempt/states").resolve(state).resolve("attempts/v1");
    Files.createDirectories(v1Attempt);
    Files.writeString(v1Attempt.resolve("path_summary.jsonl"), "{\"schema_version\":\"audit_path_summary_v1\"}\n");
    Files.writeString(
        checkpoint,
        Files.readString(checkpoint).replace("attempt-01", "v1"));
    assertThat(persistence.scanV2().activeCheckpoints()).doesNotContainKey(state);
  }

  @Test
  void mixedV1AndV2CheckpointJournalsFailClearly() throws Exception {
    final AuditRunPersistence persistence = persistence("mixed");
    persistence.initialize(manifest("run-1", "keccak256", "policy-a"));
    final String state = AuditRecordIds.stateId(4, Bytes.fromHexString(ROOT));
    persistence.commitStateV2(input(state, 4, "v2"));
    Files.writeString(
        tempDirectory.resolve("mixed/checkpoints/checkpoint_v1.json"),
        "{\"schema_version\":\"audit_checkpoint_v1\",\"checkpoint_format\":\"checkpoint_format_v1\"}\n");
    assertThatThrownBy(persistence::scanV2).isInstanceOf(IOException.class).hasMessageContaining("mixture");
  }

  @Test
  void partDirectoriesAndEmptyRetainedFragmentAreNonAuthoritativeButValid() throws Exception {
    final AuditRunPersistence persistence = persistence("parts");
    persistence.initialize(manifest("run-1", "keccak256", "policy-a"));
    final String state = AuditRecordIds.stateId(5, Bytes.fromHexString(ROOT));
    persistence.commitStateV2(input(state, 5, "one"));
    Files.createDirectories(tempDirectory.resolve("parts/states/abandoned/attempt-01.part"));
    Files.createDirectories(tempDirectory.resolve("parts/states/abandoned/metric-indexes/attempt-01.part"));
    assertThat(persistence.scanV2().activeCheckpoints()).containsKey(state);
    final Path retained = tempDirectory.resolve("parts/states").resolve(state).resolve("attempts/attempt-01/retained_paths.jsonl");
    assertThat(Files.readString(retained)).isEmpty();
  }

  @ParameterizedTest(name = "retained fragment corruption: {0}")
  @MethodSource("retainedCorruptions")
  void retainedFragmentCorruptionIsNotAuthoritative(final String name, final Tamper tamper) throws Exception {
    final AuditRunPersistence persistence = persistence("retained-" + name);
    persistence.initialize(manifest("run-1", "keccak256", "policy-a", "4D"));
    final String state = AuditRecordIds.stateId(9, Bytes.fromHexString(ROOT));
    persistence.commitStateV2(inputWithRetained(state, 9, "retained"));
    final Path retained = tempDirectory.resolve("retained-" + name).resolve("states").resolve(state)
        .resolve("attempts/attempt-01/retained_paths.jsonl");
    tamper.apply(retained);
    assertThat(persistence.scanV2().activeCheckpoints()).doesNotContainKey(state);
  }

  private static Stream<Arguments> retainedCorruptions() {
    return Stream.of(
        Arguments.of("sha256", (Tamper) path -> Files.writeString(path, Files.readString(path) + "x")),
        Arguments.of("byte-size", (Tamper) path -> Files.writeString(path, Files.readString(path) + "x")),
        Arguments.of("record-count", (Tamper) path -> Files.writeString(path, Files.readString(path) + "{\"schema_version\":\"audit_retained_paths_v2\"}\n")));
  }

  private AuditRunPersistence persistence(final String name) {
    return new AuditRunPersistence(tempDirectory.resolve(name));
  }

  private AuditRunPersistence.Manifest manifest(final String runId, final String hashVariant, final String policy) {
    return manifest(runId, hashVariant, policy, "4C");
  }

  private AuditRunPersistence.Manifest manifest(final String runId, final String hashVariant, final String policy, final String phase) {
    return new AuditRunPersistence.Manifest(
        AuditRunSchema.RUN_SCHEMA_V2,
        AuditRunSchema.CHECKPOINT_FORMAT_V2,
        Map.of(
            "path_summary", AuditRunSchema.PATH_FRAGMENT_SCHEMA_V2,
            "retained_paths", AuditRunSchema.RETAINED_FRAGMENT_SCHEMA_V2,
            "errors", AuditRunSchema.ERROR_FRAGMENT_SCHEMA_V2,
            "state_summary", AuditRunSchema.STATE_FRAGMENT_SCHEMA_V2),
        "audit-test",
        Map.of(),
        runId,
        "account",
        hashVariant,
        policy,
        "not-provided",
        Map.of(),
        Map.of(
            "phase", phase,
            "proof_path_hashing_class", "policy",
            "trie_hash_function_class", "trie",
            "parameter_identity_available", false),
        Map.of(),
        "RUNNING",
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z",
        null,
        0,
        0,
        0,
        Map.of(),
        null,
        false,
        null);
  }

  private AuditRunPersistence.V2StateAttemptInput input(final String state, final long block, final String marker) {
    return new AuditRunPersistence.V2StateAttemptInput(
        "run-1", state, block, BLOCK_HASH, ROOT, "COMPLETED", "audit-test",
        Map.of("schema_version", AuditRunSchema.STATE_FRAGMENT_SCHEMA_V2, "marker", marker),
        List.of(Map.of("state_id", state, "marker", marker)), List.of(), List.of());
  }

  private AuditRunPersistence.V2StateAttemptInput inputWithRetained(final String state, final long block, final String marker) {
    return new AuditRunPersistence.V2StateAttemptInput(
        "run-1", state, block, BLOCK_HASH, ROOT, "COMPLETED", "audit-test",
        Map.of("schema_version", AuditRunSchema.STATE_FRAGMENT_SCHEMA_V2, "marker", marker),
        List.of(Map.of("state_id", state, "marker", marker)),
        List.of(Map.of("schema_version", AuditRunSchema.RETAINED_FRAGMENT_SCHEMA_V2, "state_id", state, "marker", marker)),
        List.of());
  }

  private void deleteCheckpoint(final String state, final int attempt)
      throws IOException {
    final Path checkpoint =
        tempDirectory.resolve("no-checkpoint/checkpoints/checkpoint_" + state + "_attempt-" + String.format("%02d", attempt) + ".json");
    if (!Files.exists(checkpoint)) {
      throw new IOException("Checkpoint not found: " + checkpoint);
    }
    Files.delete(checkpoint);
  }

  private void assertThatTamperingRejects(final String name, final Tamper tamper) throws Exception {
    final AuditRunPersistence persistence = persistence(name);
    persistence.initialize(manifest("run-1", "keccak256", "policy-a"));
    final String state = AuditRecordIds.stateId(6, Bytes.fromHexString(ROOT));
    persistence.commitStateV2(input(state, 6, "one"));
    final Path checkpoint = tempDirectory.resolve(name).resolve("checkpoints/checkpoint_" + state + "_attempt-01.json");
    tamper.apply(checkpoint);
    assertThat(persistence.scanV2().activeCheckpoints()).doesNotContainKey(state);
  }

  private void rewriteCheckpoint(final Path checkpoint, final String regex, final String replacement) throws IOException {
    Files.writeString(checkpoint, Files.readString(checkpoint).replaceFirst(regex, replacement));
  }

  private void deleteRecursively(final Path path) throws IOException {
    if (!Files.exists(path)) return;
    try (var walk = Files.walk(path)) {
      for (final Path child : walk.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(child);
    }
  }

  @FunctionalInterface
  private interface Tamper {
    void apply(Path checkpoint) throws IOException;
  }
}
