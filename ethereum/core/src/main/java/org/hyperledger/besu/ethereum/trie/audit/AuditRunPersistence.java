/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package org.hyperledger.besu.ethereum.trie.audit;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.core.JsonGenerator;

import org.hyperledger.besu.crypto.MessageDigestFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.BufferedWriter;
import java.nio.channels.FileChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

/** Account-audit run persistence, recovery, and deterministic finalisation foundation. */
public final class AuditRunPersistence {
  private static final ObjectMapper MAPPER =
      JsonMapper.builder()
          .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
          .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
          .build()
          .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
          .setSerializationInclusion(JsonInclude.Include.NON_NULL);

  private final Path runDirectory;
  private final Path statesDirectory;
  private final Path checkpointsDirectory;
  private final AuditFileOperations fileOperations;

  public AuditRunPersistence(final Path runDirectory) {
    this(runDirectory, AuditFileOperations.system());
  }

  AuditRunPersistence(final Path runDirectory, final AuditFileOperations fileOperations) {
    this.runDirectory = runDirectory;
    this.statesDirectory = runDirectory.resolve("states");
    this.checkpointsDirectory = runDirectory.resolve("checkpoints");
    this.fileOperations = Objects.requireNonNull(fileOperations);
  }

  public CompatibilityResult validateCompatibility(
      final Manifest stored, final CompatibilityDeclaration current) {
    final boolean schemaSupported = current.supportedRunSchemas().contains(stored.schemaVersion());
    final boolean checkpointSupported =
        current.supportedCheckpointFormats().contains(stored.checkpointFormat());
    final boolean fragmentsSupported =
        stored.fragmentFormats().values().stream().allMatch(current.supportedFragmentSchemas()::contains);
    final boolean exactAnalyser = Objects.equals(stored.analyserVersion(), current.analyserVersion());
    final boolean compatible = schemaSupported && checkpointSupported && fragmentsSupported
        && (exactAnalyser || (schemaSupported && checkpointSupported && fragmentsSupported));
    final String detail = compatible ? "compatible" : compatibilityFailure(stored, current, schemaSupported, checkpointSupported, fragmentsSupported);
    return new CompatibilityResult(compatible, !compatible, detail);
  }

  private static String compatibilityFailure(
      final Manifest stored,
      final CompatibilityDeclaration current,
      final boolean schemaSupported,
      final boolean checkpointSupported,
      final boolean fragmentsSupported) {
    return "stored_analyser=" + stored.analyserVersion()
        + ", current_analyser=" + current.analyserVersion()
        + ", run_schema=" + stored.schemaVersion()
        + ", checkpoint_format=" + stored.checkpointFormat()
        + ", fragment_formats=" + stored.fragmentFormats()
        + ", schema_supported=" + schemaSupported
        + ", checkpoint_supported=" + checkpointSupported
        + ", fragments_supported=" + fragmentsSupported
        + ", restart_required=true";
  }

  public void initialize(final Manifest manifest) throws IOException {
    Files.createDirectories(statesDirectory);
    Files.createDirectories(checkpointsDirectory);
    writeDerivedJson("run_manifest.json", manifest);
  }

  /** Creates a v2 manifest or rejects an incompatible existing run without replacing it. */
  public void ensureCompatibleV2Manifest(final Manifest expected) throws IOException {
    final Path manifestPath = runDirectory.resolve("run_manifest.json");
    if (!Files.exists(manifestPath)) {
      initialize(expected);
      return;
    }
    final Manifest stored;
    try {
      stored = MAPPER.readValue(Files.readString(manifestPath), Manifest.class);
    } catch (final IOException invalid) {
      throw new IOException("Existing run manifest is unreadable; refusing v2 resume", invalid);
    }
    if (!AuditRunSchema.RUN_SCHEMA_V2.equals(stored.schemaVersion())
        || !AuditRunSchema.CHECKPOINT_FORMAT_V2.equals(stored.checkpointFormat())) {
      throw new IOException("Existing run manifest is not compatible with Phase 4C v2");
    }
    requireManifestField("run_id", expected.runId(), stored.runId());
    requireManifestField("audit_mode", expected.auditMode(), stored.auditMode());
    requireManifestField("hash_variant", expected.hashVariant(), stored.hashVariant());
    requireManifestField("hash_policy_identity", expected.hashPolicyIdentity(), stored.hashPolicyIdentity());
    requireManifestField("fragment_formats", expected.fragmentFormats(), stored.fragmentFormats());
    if (!Objects.equals(expected.databaseIdentity(), "not-provided")
        && !Objects.equals(expected.databaseIdentity(), stored.databaseIdentity())) {
      throw new IOException("Manifest database identity mismatch");
    }
    if (!Objects.equals(expected.chainMetadata(), Map.of())
        && !Objects.equals(expected.chainMetadata(), stored.chainMetadata())) {
      throw new IOException("Manifest chain identity mismatch");
    }
    final Object expectedParameterAvailability = expected.runConfiguration().get("parameter_identity_available");
    if (expectedParameterAvailability != null
        && !Objects.equals(expectedParameterAvailability, stored.runConfiguration().get("parameter_identity_available"))) {
      throw new IOException("Manifest hash-parameter identity availability mismatch");
    }
    final Object expectedPhase = expected.runConfiguration().get("phase");
    if (expectedPhase != null
        && !Objects.equals(expectedPhase, stored.runConfiguration().get("phase"))) {
      throw new IOException("Manifest audit phase mismatch");
    }
    for (final String identityKey : List.of("proof_path_hashing_class", "trie_hash_function_class")) {
      if (!Objects.equals(expected.runConfiguration().get(identityKey), stored.runConfiguration().get(identityKey))) {
        throw new IOException("Manifest " + identityKey + " mismatch");
      }
    }
  }

  private static void requireManifestField(final String name, final Object expected, final Object stored)
      throws IOException {
    if (!Objects.equals(expected, stored)) {
      throw new IOException("Manifest " + name + " mismatch");
    }
  }

  public AttemptCommit commitState(final StateAttemptInput input) throws IOException {
    Objects.requireNonNull(input);
    ensureStateIdentityIsConsistent(input);
    final int attempt = nextAttempt(input.stateId());
    final Path stateDirectory = statesDirectory.resolve(input.stateId());
    final Path attemptsDirectory = stateDirectory.resolve("attempts");
    Files.createDirectories(attemptsDirectory);
    final Path staging = stateDirectory.resolve(String.format("attempt-%02d.part", attempt));
    final Path completed = attemptsDirectory.resolve(String.format("attempt-%02d", attempt));
    if (Files.exists(staging) || Files.exists(completed)) {
      throw new IOException("Attempt already exists: " + input.stateId() + " attempt " + attempt);
    }
    Files.createDirectories(staging);
    try {
      final List<FragmentIntegrity> fragments = writeAndValidateFragments(staging, input);
      fsyncDirectory(staging);
      final Path promoted = promoteDirectory(staging, completed);
      fsyncDirectory(attemptsDirectory);
      final Checkpoint checkpoint =
          new Checkpoint(
              AuditRunSchema.CHECKPOINT_SCHEMA,
              AuditRunSchema.CHECKPOINT_FORMAT,
              input.runId(),
              input.stateId(),
              input.blockNumber(),
              input.stateRoot(),
              attempt,
              "COMMITTED",
              runDirectory.relativize(promoted).toString(),
              fragments,
              input.analyserVersion(),
              Instant.now().toString(),
              0,
              null);
      final Path checkpointPath = checkpointsDirectory.resolve(checkpointFilename(input.stateId(), attempt));
      atomicWriteJson(checkpointPath, checkpoint);
      validateCheckpoint(checkpoint);
      atomicWriteText(checkpointsDirectory.resolve("latest"), checkpointPath.getFileName() + "\n");
      rebuildStateSummary();
      return new AttemptCommit(checkpoint, promoted);
    } catch (final IOException | RuntimeException failure) {
      deleteRecursively(staging);
      throw failure;
    }
  }

  /** Commits one Phase 4C state attempt using additive v2 schemas. */
  public V2AttemptCommit commitStateV2(final V2StateAttemptInput input) throws IOException {
    Objects.requireNonNull(input);
    final int attempt = nextAttemptV2(input.stateId());
    final Path stateDirectory = statesDirectory.resolve(input.stateId());
    final Path attemptsDirectory = stateDirectory.resolve("attempts");
    Files.createDirectories(attemptsDirectory);
    final Path staging = stateDirectory.resolve(String.format("attempt-%02d.part", attempt));
    final Path completed = attemptsDirectory.resolve(String.format("attempt-%02d", attempt));
    if (Files.exists(staging) || Files.exists(completed)) {
      throw new IOException("Attempt already exists: " + input.stateId() + " attempt " + attempt);
    }
    Files.createDirectories(staging);
    try {
      final List<FragmentIntegrity> fragments = writeV2Fragments(staging, input);
      fsyncDirectory(staging);
      final Path promoted = promoteDirectory(staging, completed);
      fsyncDirectory(attemptsDirectory);
      final V2Checkpoint checkpoint =
          new V2Checkpoint(
              AuditRunSchema.CHECKPOINT_SCHEMA_V2,
              AuditRunSchema.CHECKPOINT_FORMAT_V2,
              input.runId(),
              input.stateId(),
              input.blockNumber(),
              input.blockHash(),
              input.stateRoot(),
              attempt,
              input.finalClassification(),
              "COMMITTED",
              runDirectory.relativize(promoted).toString(),
              fragments,
              input.analyserVersion(),
              Instant.now().toString(),
              attempt - 1,
              null,
              null,
              null,
              false,
              null);
      final Path checkpointPath =
          checkpointsDirectory.resolve(checkpointFilename(input.stateId(), attempt));
      atomicWriteJson(checkpointPath, checkpoint);
      validateV2Checkpoint(checkpoint);
      atomicWriteText(checkpointsDirectory.resolve("latest"), checkpointPath.getFileName() + "\n");
      rebuildV2StateSummary();
      return new V2AttemptCommit(checkpoint, promoted);
    } catch (final IOException | RuntimeException failure) {
      deleteRecursively(staging);
      throw failure;
    }
  }

  /** Records a non-committed v2 attempt without presenting it as final state evidence. */
  public void recordRejectedAttemptV2(
      final String runId,
      final String stateId,
      final long blockNumber,
      final String blockHash,
      final String stateRoot,
      final String analyserVersion,
      final String stage,
      final String category,
      final String message)
      throws IOException {
    final int attempt = nextAttemptV2(stateId);
    final String diagnosticArtifact =
        writeV2DiagnosticError(
            runId,
            stateId,
            blockNumber,
            attempt,
            stage,
            category,
            null,
            "REJECTED",
            true,
            0,
            message,
            stateRoot);
    final V2Checkpoint rejected =
        new V2Checkpoint(
            AuditRunSchema.CHECKPOINT_SCHEMA_V2,
            AuditRunSchema.CHECKPOINT_FORMAT_V2,
            runId,
            stateId,
            blockNumber,
            blockHash,
            stateRoot,
            attempt,
            null,
            "REJECTED",
            null,
            List.of(),
            analyserVersion,
            Instant.now().toString(),
            0,
            stage + ":" + category + ":" + message,
            stage,
            category,
            true,
            diagnosticArtifact);
    atomicWriteJson(
        checkpointsDirectory.resolve(checkpointFilename(stateId, rejected.attemptNumber())), rejected);
  }

  /** Records a terminal state classification without fabricated fragment evidence. */
  public void recordFinalClassificationV2(
      final String runId,
      final String stateId,
      final long blockNumber,
      final String blockHash,
      final String stateRoot,
      final String finalClassification,
      final String analyserVersion,
      final String stage,
      final String category,
      final String message)
      throws IOException {
    if (!Set.of("FAILED", "UNAVAILABLE").contains(finalClassification)) {
      throw new IllegalArgumentException("Only FAILED or UNAVAILABLE may be terminal without fragments");
    }
    final int attempt = nextAttemptV2WithoutRetryLimit(stateId);
    final String diagnosticArtifact =
        writeV2DiagnosticError(
            runId,
            stateId,
            blockNumber,
            attempt,
            stage,
            category,
            finalClassification,
            "COMMITTED",
            false,
            Math.max(0, attempt - 1),
            message,
            stateRoot);
    final V2Checkpoint terminal =
        new V2Checkpoint(
            AuditRunSchema.CHECKPOINT_SCHEMA_V2,
            AuditRunSchema.CHECKPOINT_FORMAT_V2,
            runId,
            stateId,
            blockNumber,
            blockHash,
            stateRoot,
            attempt,
            finalClassification,
            "COMMITTED",
            null,
            List.of(),
            analyserVersion,
            Instant.now().toString(),
            Math.max(0, attempt - 1),
            stage + ":" + category + ":" + message,
            stage,
            category,
            false,
            diagnosticArtifact);
    atomicWriteJson(checkpointsDirectory.resolve(checkpointFilename(stateId, attempt)), terminal);
    rebuildV2StateSummary();
  }

  /** Rebuilds a derived v2 summary exclusively from valid checkpoint evidence. */
  public void rebuildV2StateSummary() throws IOException {
    final StringBuilder output = new StringBuilder();
    for (final V2Checkpoint checkpoint : scanV2().activeCheckpoints().values().stream()
        .sorted(Comparator.comparingLong(V2Checkpoint::blockNumber).thenComparing(V2Checkpoint::stateId))
        .toList()) {
      final Map<String, Object> summary = new TreeMap<>();
      summary.put("schema_version", AuditRunSchema.STATE_FRAGMENT_SCHEMA_V2);
      summary.put("state_id", checkpoint.stateId());
      summary.put("block_number", checkpoint.blockNumber());
      summary.put("block_hash", checkpoint.blockHash());
      summary.put("state_root", checkpoint.stateRoot());
      summary.put("final_classification", checkpoint.finalClassification());
      summary.put("internal_attempt_status", checkpoint.internalStatus());
      summary.put("attempt_number", checkpoint.attemptNumber());
      if (checkpoint.attemptDirectory() != null) {
        final Path summaryPath =
            runDirectory.resolve(checkpoint.attemptDirectory()).resolve("state_summary.json");
        if (!Files.isRegularFile(summaryPath)) {
          throw new IOException("Missing authoritative v2 state summary: " + summaryPath);
        }
        summary.put("authoritative_state_summary", MAPPER.readTree(Files.readString(summaryPath)));
      }
      output.append(MAPPER.writeValueAsString(summary)).append('\n');
    }
    atomicWriteText(runDirectory.resolve("state_summary_v2.jsonl"), output.toString());
  }

  private String writeV2DiagnosticError(
      final String runId,
      final String stateId,
      final long blockNumber,
      final int attempt,
      final String stage,
      final String category,
      final String finalClassification,
      final String internalStatus,
      final boolean retryable,
      final int retryCount,
      final String message,
      final String stateRoot)
      throws IOException {
    final Path directory = statesDirectory.resolve(stateId).resolve("diagnostic");
    Files.createDirectories(directory);
    final String errorId = AuditRecordIds.errorId(stateId, attempt, category);
    final String filename = String.format("attempt-%02d-%s.jsonl", attempt, errorId);
    final Path target = directory.resolve(filename);
    final Map<String, Object> record = new TreeMap<>();
    record.put("schema_version", AuditRunSchema.ERROR_FRAGMENT_SCHEMA_V2);
    record.put("error_id", errorId);
    record.put("run_id", runId);
    record.put("state_id", stateId);
    record.put("block_number", blockNumber);
    record.put("attempt_number", attempt);
    record.put("path_id", null);
    record.put("stage", stage);
    record.put("error_code", category);
    record.put("validation_status", null);
    record.put("final_classification", finalClassification);
    record.put("internal_attempt_status", internalStatus);
    record.put("retryable", retryable);
    record.put("retry_count", retryCount);
    record.put("structured_detail", Map.of("state_root", stateRoot));
    record.put("related_artifact", target.toString());
    record.put("diagnostic_message", message == null ? "" : message);
    record.put("timestamp", Instant.now().toString());
    atomicWriteText(target, MAPPER.writeValueAsString(record) + "\n");
    return runDirectory.relativize(target).toString();
  }

  public V2Recovery scanV2() throws IOException {
    final Map<String, List<V2Checkpoint>> byState = new TreeMap<>();
    final List<String> invalidArtifacts = new ArrayList<>();
    if (Files.exists(checkpointsDirectory)) {
      try (DirectoryStream<Path> paths = Files.newDirectoryStream(checkpointsDirectory, "checkpoint_*.json")) {
        for (final Path path : paths) {
          try {
            final JsonNode json = MAPPER.readTree(Files.readString(path));
            if (!AuditRunSchema.CHECKPOINT_SCHEMA_V2.equals(json.path("schema_version").asText())) {
              throw new IOException("v1/v2 checkpoint mixture is unsupported: " + path);
            }
            final V2Checkpoint checkpoint = MAPPER.treeToValue(json, V2Checkpoint.class);
            byState.computeIfAbsent(checkpoint.stateId(), ignored -> new ArrayList<>()).add(checkpoint);
          } catch (final IOException invalid) {
            if (invalid.getMessage() != null && invalid.getMessage().startsWith("v1/v2 checkpoint mixture")) {
              throw invalid;
            }
            invalidArtifacts.add(path.toString());
          } catch (final Exception invalid) {
            invalidArtifacts.add(path.toString());
          }
        }
      }
    }
    final Map<String, V2Checkpoint> active = new TreeMap<>();
    final List<V2Checkpoint> invalid = new ArrayList<>();
    final List<V2Checkpoint> rejected = new ArrayList<>();
    for (final List<V2Checkpoint> history : byState.values()) {
      history.sort(Comparator.comparingInt(V2Checkpoint::attemptNumber));
      for (final V2Checkpoint checkpoint : history) {
        if ("REJECTED".equals(checkpoint.internalStatus())) {
          try {
            validateV2Checkpoint(checkpoint);
          } catch (final IOException invalidCheckpoint) {
            invalid.add(checkpoint);
            invalidArtifacts.add(checkpoint.stateId() + ":" + invalidCheckpoint.getMessage());
            continue;
          }
          rejected.add(checkpoint);
        } else if (!"COMMITTED".equals(checkpoint.internalStatus())) {
          invalid.add(checkpoint);
        } else {
          try {
            validateV2Checkpoint(checkpoint);
            if (active.get(checkpoint.stateId()) == null
                || checkpoint.attemptNumber() > active.get(checkpoint.stateId()).attemptNumber()) {
              active.put(checkpoint.stateId(), checkpoint);
            }
          } catch (final IOException invalidCheckpoint) {
            invalid.add(checkpoint);
            invalidArtifacts.add(checkpoint.stateId() + ":" + invalidCheckpoint.getMessage());
          }
        }
      }
    }
    return new V2Recovery(active, invalid, rejected, invalidArtifacts);
  }

  public void recordRejectedAttempt(
      final String runId,
      final String stateId,
      final long blockNumber,
      final String stateRoot,
      final int attempt,
      final String analyserVersion,
      final String message)
      throws IOException {
    final boolean secondFailure =
        scan().rejectedCheckpoints().stream().filter(checkpoint -> stateId.equals(checkpoint.stateId())).count() >= 1;
    final Checkpoint rejected =
        new Checkpoint(
            AuditRunSchema.CHECKPOINT_SCHEMA,
            AuditRunSchema.CHECKPOINT_FORMAT,
            runId,
            stateId,
            blockNumber,
            stateRoot,
            attempt,
            "REJECTED",
            null,
            List.of(),
            analyserVersion,
            Instant.now().toString(),
            attempt,
            message);
    atomicWriteJson(checkpointsDirectory.resolve(checkpointFilename(stateId, attempt)), rejected);
    if (secondFailure) {
      final Path manifestPath = runDirectory.resolve("run_manifest.json");
      if (Files.isRegularFile(manifestPath)) {
        final Manifest manifest = MAPPER.readValue(Files.readString(manifestPath), Manifest.class);
        writeDerivedJson("run_manifest.json", manifest.withStatus("FAILED", message));
      }
    }
  }

  public Recovery scan() throws IOException {
    final Map<String, List<Checkpoint>> byState = new TreeMap<>();
    final List<String> invalidCheckpointArtifacts = new ArrayList<>();
    if (Files.exists(checkpointsDirectory)) {
      try (DirectoryStream<Path> paths = Files.newDirectoryStream(checkpointsDirectory, "checkpoint_*.json")) {
        for (final Path path : paths) {
          try {
            final Checkpoint checkpoint = MAPPER.readValue(Files.readString(path), Checkpoint.class);
            if (checkpoint.stateId() == null || checkpoint.attemptNumber() < 1) {
              throw new IOException("Checkpoint has invalid state or attempt identity");
            }
            byState.computeIfAbsent(checkpoint.stateId(), ignored -> new ArrayList<>()).add(checkpoint);
          } catch (final Exception invalid) {
            invalidCheckpointArtifacts.add(path.toString());
          }
        }
      }
    }
    final Map<String, Checkpoint> active = new TreeMap<>();
    final List<Checkpoint> invalid = new ArrayList<>();
    final List<Checkpoint> rejected = new ArrayList<>();
    final List<String> invalidDiagnostics = new ArrayList<>();
    for (final Map.Entry<String, List<Checkpoint>> entry : byState.entrySet()) {
      entry.getValue().sort(Comparator.comparingInt(Checkpoint::attemptNumber));
      for (final Checkpoint checkpoint : entry.getValue()) {
        if ("REJECTED".equals(checkpoint.outcome())) {
          rejected.add(checkpoint);
        } else if (!"COMMITTED".equals(checkpoint.outcome())) {
          invalid.add(checkpoint);
        } else {
          try {
            validateCheckpoint(checkpoint);
            if (active.get(entry.getKey()) == null
                || checkpoint.attemptNumber() > active.get(entry.getKey()).attemptNumber()) {
              active.put(entry.getKey(), checkpoint);
            }
          } catch (final IOException invalidCheckpoint) {
            invalid.add(checkpoint);
            invalidDiagnostics.add(checkpoint.stateId() + ": " + invalidCheckpoint.getMessage());
          }
        }
      }
    }
    invalidCheckpointArtifacts.addAll(invalidDiagnostics);
    return new Recovery(active, invalid, rejected, invalidCheckpointArtifacts);
  }

  public void rebuildStateSummary() throws IOException {
    final Recovery recovery = scan();
    final List<StateSummary> summaries =
        recovery.activeCheckpoints().values().stream()
            .map(this::readStateSummary)
            .sorted(Comparator.comparingLong(StateSummary::blockNumber).thenComparing(StateSummary::stateId))
            .toList();
    final StringBuilder csv = new StringBuilder();
    csv.append(StateSummary.CSV_HEADER).append('\n');
    for (final StateSummary summary : summaries) csv.append(summary.toCsv()).append('\n');
    atomicWriteText(runDirectory.resolve("state_summary.csv"), csv.toString());
  }

  private void ensureStateIdentityIsConsistent(final StateAttemptInput input) throws IOException {
    final Recovery recovery = scan();
    final List<Checkpoint> history = new ArrayList<>();
    history.addAll(recovery.activeCheckpoints().values());
    history.addAll(recovery.invalidCheckpoints());
    history.addAll(recovery.rejectedCheckpoints());
    for (final Checkpoint checkpoint : history) {
      if (input.stateId().equals(checkpoint.stateId())
          && (input.blockNumber() != checkpoint.blockNumber()
              || !input.stateRoot().equals(checkpoint.stateRoot()))) {
        throw new IOException("State ID intrinsic-field conflict for " + input.stateId());
      }
    }
  }

  public void finalizeRun(final Set<String> selectedStateIds, final Manifest manifest) throws IOException {
    final Recovery recovery = scan();
    if (!recovery.activeCheckpoints().keySet().containsAll(selectedStateIds)) {
      final Manifest failed = manifest.withStatus("RUNNING", "Missing or invalid selected state");
      writeDerivedJson("run_manifest.json", failed);
      throw new IOException("Finalisation requires every selected state to be committed");
    }
    writeDerivedJson("run_manifest.json", manifest.withStatus("FINALISING", null));
    rebuildStateSummary();
    final List<Checkpoint> ordered =
        recovery.activeCheckpoints().values().stream()
            .filter(checkpoint -> selectedStateIds.contains(checkpoint.stateId()))
            .sorted(Comparator.comparingLong(Checkpoint::blockNumber).thenComparing(Checkpoint::stateId))
            .toList();
    writeCombinedJsonl("path_summary.jsonl", ordered, "path_summary.jsonl");
    writeCombinedJsonl("retained_paths.jsonl", ordered, "retained_paths.jsonl");
    writeCombinedJsonl("errors.jsonl", ordered, "errors.jsonl");
    final Map<String, Object> global = new LinkedHashMap<>();
    global.put("schema_version", AuditRunSchema.RUN_SCHEMA);
    global.put("run_id", manifest.runId());
    global.put("committed_state_count", ordered.size());
    global.put("status", "COMPLETED");
    writeDerivedJson("global_summary.json", global);
    atomicWriteText(runDirectory.resolve("audit_report.md"), "# Account Audit Report\n\nStatus: COMPLETED\n");
    writeDerivedJson("run_manifest.json", manifest.withStatus("COMPLETED", null));
  }

  private List<FragmentIntegrity> writeAndValidateFragments(
      final Path staging, final StateAttemptInput input) throws IOException {
    final List<FragmentIntegrity> result = new ArrayList<>();
    result.add(writeJsonl(staging, input.stateId(), "path_summary.jsonl", AuditRunSchema.PATH_FRAGMENT_SCHEMA, input.pathRecords()));
    result.add(writeJsonl(staging, input.stateId(), "retained_paths.jsonl", AuditRunSchema.RETAINED_FRAGMENT_SCHEMA, input.retainedRecords()));
    result.add(writeJsonl(staging, input.stateId(), "errors.jsonl", AuditRunSchema.ERROR_FRAGMENT_SCHEMA, input.errorRecords()));
    final Path summary = staging.resolve("state_summary.json.part");
    writeBytes(summary, canonicalBytes(input.stateSummary()));
    fsyncFile(summary);
    final FragmentIntegrity summaryIntegrity = integrity(summary, input.stateId(), "state_summary.json", AuditRunSchema.STATE_FRAGMENT_SCHEMA, 1);
    Files.move(summary, staging.resolve("state_summary.json"));
    result.add(summaryIntegrity);
    for (final FragmentIntegrity fragment : result) {
      final Path source = staging.resolve(fragment.relativeFilename() + ".part");
      if (Files.exists(source)) Files.move(source, staging.resolve(fragment.relativeFilename()));
    }
    return result;
  }

  private List<FragmentIntegrity> writeV2Fragments(
      final Path staging, final V2StateAttemptInput input) throws IOException {
    final List<FragmentIntegrity> result = new ArrayList<>();
    result.add(writeJsonl(staging, input.stateId(), "path_summary.jsonl", AuditRunSchema.PATH_FRAGMENT_SCHEMA_V2, input.pathRecords()));
    result.add(writeJsonl(staging, input.stateId(), "retained_paths.jsonl", AuditRunSchema.RETAINED_FRAGMENT_SCHEMA_V2, input.retainedRecords()));
    result.add(writeJsonl(staging, input.stateId(), "errors.jsonl", AuditRunSchema.ERROR_FRAGMENT_SCHEMA_V2, input.errorRecords()));
    final Path summary = staging.resolve("state_summary.json.part");
    writeBytes(summary, canonicalBytes(input.stateSummary()));
    fsyncFile(summary);
    final FragmentIntegrity summaryIntegrity =
        integrity(summary, input.stateId(), "state_summary.json", AuditRunSchema.STATE_FRAGMENT_SCHEMA_V2, 1);
    Files.move(summary, staging.resolve("state_summary.json"));
    result.add(summaryIntegrity);
    for (final FragmentIntegrity fragment : result) {
      final Path source = staging.resolve(fragment.relativeFilename() + ".part");
      if (Files.exists(source)) Files.move(source, staging.resolve(fragment.relativeFilename()));
    }
    return result;
  }

  private FragmentIntegrity writeJsonl(
      final Path staging,
      final String stateId,
      final String filename,
      final String schema,
      final List<Map<String, Object>> records)
      throws IOException {
    final Path path = staging.resolve(filename + ".part");
    try (BufferedWriter writer = Files.newBufferedWriter(
        path, UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
        StandardOpenOption.WRITE)) {
      final JsonGenerator generator = MAPPER.getFactory().createGenerator(writer);
      generator.disable(JsonGenerator.Feature.AUTO_CLOSE_TARGET);
      for (final Map<String, Object> record : records) {
        final Map<String, Object> canonical = new TreeMap<>(record);
        canonical.putIfAbsent("schema_version", schema);
        generator.writeObject(canonical);
        generator.flush();
        writer.newLine();
      }
      generator.flush();
    }
    fsyncFile(path);
    return integrity(path, stateId, filename, schema, records.size());
  }

  private FragmentIntegrity integrity(
      final Path path,
      final String stateId,
      final String filename,
      final String schema,
      final int recordCount)
      throws IOException {
    return new FragmentIntegrity(
        filename,
        stateId,
        schema,
        Files.size(path),
        recordCount,
        sha256(path));
  }

  private void validateCheckpoint(final Checkpoint checkpoint) throws IOException {
    if (!AuditRunSchema.CHECKPOINT_SCHEMA.equals(checkpoint.schemaVersion())
        || !AuditRunSchema.CHECKPOINT_FORMAT.equals(checkpoint.checkpointFormat())) {
      throw new IOException("Checkpoint schema mismatch for " + checkpoint.stateId());
    }
    if (checkpoint.attemptDirectory() == null) {
      throw new IOException("Committed checkpoint has no attempt directory: " + checkpoint.stateId());
    }
    final Path attempt = runDirectory.resolve(checkpoint.attemptDirectory()).normalize();
    if (!attempt.startsWith(runDirectory.normalize())) {
      throw new IOException("Checkpoint attempt escapes run directory: " + checkpoint.stateId());
    }
    if (!Files.isDirectory(attempt)) throw new IOException("Missing attempt directory " + attempt);
    final Set<String> filenames = new java.util.HashSet<>();
    for (final FragmentIntegrity fragment : checkpoint.fragments()) {
      if (!filenames.add(fragment.relativeFilename())) {
        throw new IOException("Duplicate fragment in checkpoint: " + fragment.relativeFilename());
      }
      final Path path = attempt.resolve(fragment.relativeFilename());
      if (!Files.isRegularFile(path)) {
        throw new IOException("Fragment missing: " + path);
      }
      if (Files.size(path) != fragment.byteSize()) {
        throw new IOException("Fragment byte-size mismatch: " + path);
      }
      if (!sha256(path).equals(fragment.sha256())) {
        throw new IOException("Fragment digest mismatch: " + path);
      }
      validateFragmentContent(path, fragment);
    }
  }

  private void validateV2Checkpoint(final V2Checkpoint checkpoint) throws IOException {
    if (!AuditRunSchema.CHECKPOINT_SCHEMA_V2.equals(checkpoint.schemaVersion())
        || !AuditRunSchema.CHECKPOINT_FORMAT_V2.equals(checkpoint.checkpointFormat())) {
      throw new IOException("Checkpoint v2 schema mismatch for " + checkpoint.stateId());
    }
    if (checkpoint.finalClassification() != null
        && !Set.of("COMPLETED", "UNAVAILABLE", "FAILED").contains(checkpoint.finalClassification())) {
      throw new IOException("Invalid final state classification for " + checkpoint.stateId());
    }
    if ("REJECTED".equals(checkpoint.internalStatus())) {
      if (checkpoint.finalClassification() != null
          || checkpoint.attemptDirectory() != null
          || !checkpoint.fragments().isEmpty()
          || checkpoint.diagnosticErrorArtifact() == null) {
        throw new IOException("Rejected v2 checkpoint contains committed evidence: " + checkpoint.stateId());
      }
      validateDiagnosticError(checkpoint);
      return;
    }
    if (!"COMMITTED".equals(checkpoint.internalStatus())) {
      throw new IOException("Checkpoint v2 has unknown internal status: " + checkpoint.stateId());
    }
    if (checkpoint.attemptDirectory() == null) {
      if (!checkpoint.fragments().isEmpty()
          || !Set.of("FAILED", "UNAVAILABLE").contains(checkpoint.finalClassification())
          || checkpoint.diagnosticErrorArtifact() == null) {
        throw new IOException("Terminal v2 classification has invalid evidence: " + checkpoint.stateId());
      }
      validateDiagnosticError(checkpoint);
      return;
    }
    if (!"COMPLETED".equals(checkpoint.finalClassification())) {
      throw new IOException("Committed v2 attempt is not COMPLETED: " + checkpoint.stateId());
    }
    if (checkpoint.diagnosticErrorArtifact() != null) {
      throw new IOException("Completed v2 checkpoint contains diagnostic failure evidence: " + checkpoint.stateId());
    }
    final Path attempt = runDirectory.resolve(checkpoint.attemptDirectory()).normalize();
    if (!attempt.startsWith(runDirectory.normalize()) || !Files.isDirectory(attempt)) {
      throw new IOException("Missing or escaping v2 attempt directory: " + checkpoint.stateId());
    }
    final Set<String> filenames = new java.util.HashSet<>();
    for (final FragmentIntegrity fragment : checkpoint.fragments()) {
      if (!filenames.add(fragment.relativeFilename())) {
        throw new IOException("Duplicate v2 fragment: " + fragment.relativeFilename());
      }
      final Path path = attempt.resolve(fragment.relativeFilename());
      if (!Files.isRegularFile(path) || Files.size(path) != fragment.byteSize()) {
        throw new IOException("Missing or invalid v2 fragment: " + path);
      }
      if (!sha256(path).equals(fragment.sha256())) {
        throw new IOException("V2 fragment digest mismatch: " + path);
      }
      validateV2FragmentContent(path, fragment);
    }
  }

  private void validateDiagnosticError(final V2Checkpoint checkpoint) throws IOException {
    final Path path = runDirectory.resolve(checkpoint.diagnosticErrorArtifact()).normalize();
    if (!path.startsWith(runDirectory.normalize()) || !Files.isRegularFile(path)) {
      throw new IOException("Missing v2 diagnostic error artifact: " + checkpoint.stateId());
    }
    final JsonNode error = MAPPER.readTree(Files.readString(path));
    if (!AuditRunSchema.ERROR_FRAGMENT_SCHEMA_V2.equals(error.path("schema_version").asText())
        || !checkpoint.stateId().equals(error.path("state_id").asText())
        || checkpoint.attemptNumber() != error.path("attempt_number").asInt()) {
      throw new IOException("Invalid v2 diagnostic error artifact: " + path);
    }
  }

  private static void validateV2FragmentContent(
      final Path path, final FragmentIntegrity fragment) throws IOException {
    if ("state_summary.json".equals(fragment.relativeFilename())) {
      final JsonNode summary = MAPPER.readTree(Files.readString(path));
      if (!AuditRunSchema.STATE_FRAGMENT_SCHEMA_V2.equals(summary.path("schema_version").asText())
          || fragment.recordCount() != 1) {
        throw new IOException("Invalid v2 state summary: " + path);
      }
      return;
    }
    final List<String> lines = Files.readAllLines(path, UTF_8);
    if (lines.stream().filter(line -> !line.isEmpty()).count() != fragment.recordCount()) {
      throw new IOException("V2 fragment record-count mismatch: " + path);
    }
    for (final String line : lines) {
      if (!line.isEmpty()
          && !fragment.schemaVersion().equals(MAPPER.readTree(line).path("schema_version").asText())) {
        throw new IOException("V2 fragment schema mismatch: " + path);
      }
    }
  }

  private static void validateFragmentContent(
      final Path path, final FragmentIntegrity fragment) throws IOException {
    if ("state_summary.json".equals(fragment.relativeFilename())) {
      final StateSummary summary = MAPPER.readValue(Files.readString(path), StateSummary.class);
      if (!AuditRunSchema.STATE_FRAGMENT_SCHEMA.equals(summary.schemaVersion())) {
        throw new IOException("State-summary schema mismatch: " + path);
      }
      if (fragment.recordCount() != 1) throw new IOException("State-summary count mismatch: " + path);
      return;
    }
    final List<String> lines = Files.readAllLines(path, UTF_8);
    final long nonEmptyLines = lines.stream().filter(line -> !line.isEmpty()).count();
    if (nonEmptyLines != fragment.recordCount()) {
      throw new IOException("Fragment record-count mismatch: " + path);
    }
    for (final String line : lines) {
      if (line.isEmpty()) continue;
      final JsonNode record = MAPPER.readTree(line);
      if (record == null
          || !fragment.schemaVersion().equals(record.path("schema_version").asText(null))) {
        throw new IOException("Fragment schema mismatch: " + path);
      }
    }
  }

  private StateSummary readStateSummary(final Checkpoint checkpoint) {
    try {
      final Path path = runDirectory.resolve(checkpoint.attemptDirectory()).resolve("state_summary.json");
      return MAPPER.readValue(Files.readString(path), StateSummary.class)
          .withCheckpointReference(checkpointFilename(checkpoint.stateId(), checkpoint.attemptNumber()));
    } catch (final IOException e) {
      throw new IllegalStateException("Invalid state summary for " + checkpoint.stateId(), e);
    }
  }

  private void writeCombinedJsonl(
      final String outputName, final List<Checkpoint> checkpoints, final String fragmentName) throws IOException {
    final Path target = runDirectory.resolve(outputName);
    final Path temporary = target.resolveSibling(target.getFileName() + ".tmp");
    Files.createDirectories(target.getParent());
    try (var output = Files.newOutputStream(
        temporary, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
        StandardOpenOption.WRITE)) {
      final byte[] buffer = new byte[8192];
      for (final Checkpoint checkpoint : checkpoints) {
        final Path path = runDirectory.resolve(checkpoint.attemptDirectory()).resolve(fragmentName);
        if (!Files.exists(path)) continue;
        try (InputStream input = Files.newInputStream(path)) {
          int read;
          while ((read = input.read(buffer)) >= 0) {
            if (read > 0) output.write(buffer, 0, read);
          }
        }
      }
    }
    fsyncFile(temporary);
    try {
      fileOperations.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (final java.nio.file.AtomicMoveNotSupportedException unsupported) {
      fileOperations.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
      markDerivedAtomicityDegraded();
    }
  }

  private int nextAttempt(final String stateId) throws IOException {
    final Recovery recovery = scan();
    int maximum = 0;
    int rejectedCount = 0;
    final List<Checkpoint> all = new ArrayList<>();
    all.addAll(recovery.activeCheckpoints().values());
    all.addAll(recovery.rejectedCheckpoints());
    for (final Checkpoint checkpoint : all) {
      if (checkpoint.stateId().equals(stateId)) maximum = Math.max(maximum, checkpoint.attemptNumber());
    }
    for (final Checkpoint checkpoint : recovery.rejectedCheckpoints()) {
      if (checkpoint.stateId().equals(stateId)) rejectedCount++;
    }
    if (rejectedCount >= 2) {
      throw new IOException("State retry limit exceeded for " + stateId + " (retry limit 1)");
    }
    return maximum + 1;
  }

  private int nextAttemptV2(final String stateId) throws IOException {
    final V2Recovery recovery = scanV2();
    int maximum = 0;
    int rejectedCount = 0;
    for (final V2Checkpoint checkpoint : recovery.activeCheckpoints().values()) {
      if (stateId.equals(checkpoint.stateId())) maximum = Math.max(maximum, checkpoint.attemptNumber());
    }
    for (final V2Checkpoint checkpoint : recovery.rejectedCheckpoints()) {
      if (stateId.equals(checkpoint.stateId())) {
        maximum = Math.max(maximum, checkpoint.attemptNumber());
        rejectedCount++;
      }
    }
    if (rejectedCount >= 2) throw new IOException("State retry limit exceeded for " + stateId);
    return maximum + 1;
  }

  private int nextAttemptV2WithoutRetryLimit(final String stateId) throws IOException {
    final V2Recovery recovery = scanV2();
    int maximum = 0;
    for (final V2Checkpoint checkpoint : recovery.activeCheckpoints().values()) {
      if (stateId.equals(checkpoint.stateId())) maximum = Math.max(maximum, checkpoint.attemptNumber());
    }
    for (final V2Checkpoint checkpoint : recovery.rejectedCheckpoints()) {
      if (stateId.equals(checkpoint.stateId())) maximum = Math.max(maximum, checkpoint.attemptNumber());
    }
    for (final V2Checkpoint checkpoint : recovery.invalidCheckpoints()) {
      if (stateId.equals(checkpoint.stateId())) maximum = Math.max(maximum, checkpoint.attemptNumber());
    }
    return maximum + 1;
  }

  private Path promoteDirectory(final Path staging, final Path completed) throws IOException {
    try {
      return fileOperations.move(staging, completed, StandardCopyOption.ATOMIC_MOVE);
    } catch (final java.nio.file.AtomicMoveNotSupportedException unsupported) {
      throw new IOException("Atomic attempt-directory promotion is unavailable", unsupported);
    }
  }

  private void writeDerivedJson(final String filename, final Object value) throws IOException {
    atomicWriteText(runDirectory.resolve(filename), MAPPER.writeValueAsString(value) + "\n");
  }

  private void atomicWriteJson(final Path path, final Object value) throws IOException {
    Files.createDirectories(path.getParent());
    final Path temporary = path.resolveSibling(path.getFileName() + ".tmp");
    writeBytes(temporary, (MAPPER.writeValueAsString(value) + "\n").getBytes(UTF_8));
    fsyncFile(temporary);
    try {
      fileOperations.move(temporary, path, StandardCopyOption.ATOMIC_MOVE);
    } catch (final java.nio.file.AtomicMoveNotSupportedException unsupported) {
      throw new IOException("Atomic checkpoint promotion is unavailable", unsupported);
    }
  }

  private void atomicWriteText(final Path target, final String content) throws IOException {
    Files.createDirectories(target.getParent());
    final Path temporary = target.resolveSibling(target.getFileName() + ".tmp");
    writeBytes(temporary, content.getBytes(UTF_8));
    fsyncFile(temporary);
    try {
      fileOperations.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (final java.nio.file.AtomicMoveNotSupportedException unsupported) {
      fileOperations.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
      if (!"run_manifest.json".equals(target.getFileName().toString())) {
        markDerivedAtomicityDegraded();
      }
    }
  }

  private void markDerivedAtomicityDegraded() throws IOException {
    final Path manifestPath = runDirectory.resolve("run_manifest.json");
    if (!Files.isRegularFile(manifestPath)) return;
    final Manifest manifest = MAPPER.readValue(Files.readString(manifestPath), Manifest.class);
    if (Boolean.TRUE.equals(manifest.degradedDerivedAtomicity())) return;
    writeDerivedJson("run_manifest.json", manifest.withDegradedDerivedAtomicity());
  }

  private static void writeBytes(final Path path, final byte[] bytes) throws IOException {
    Files.write(path, bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
  }

  private static void fsyncFile(final Path path) throws IOException {
    try (FileChannel channel = FileChannel.open(path, StandardOpenOption.WRITE)) {
      channel.force(true);
    }
  }

  private static void fsyncDirectory(final Path path) throws IOException {
    try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
      channel.force(true);
    } catch (final IOException unsupported) {
      // Directory fsync is platform-specific; atomic promotion remains mandatory for authorities.
    }
  }

  private static String sha256(final Path path) throws IOException {
    try {
      final MessageDigest digest = MessageDigestFactory.create(MessageDigestFactory.SHA256_ALG);
      final byte[] buffer = new byte[8192];
      try (InputStream input = Files.newInputStream(path)) {
        int read;
        while ((read = input.read(buffer)) >= 0) {
          if (read > 0) digest.update(buffer, 0, read);
        }
      }
      final StringBuilder result = new StringBuilder(64);
      for (final byte value : digest.digest()) result.append(String.format("%02x", value));
      return result.toString();
    } catch (final NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] canonicalBytes(final Object value) throws IOException {
    return MAPPER.writeValueAsString(value).concat("\n").getBytes(UTF_8);
  }

  private static String checkpointFilename(final String stateId, final int attempt) {
    return String.format("checkpoint_%s_attempt-%02d.json", stateId, attempt);
  }

  private static void deleteRecursively(final Path path) throws IOException {
    if (!Files.exists(path)) return;
    try (var walk = Files.walk(path)) {
      for (final Path child : walk.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(child);
    }
  }

  public record FragmentIntegrity(
      String relativeFilename,
      String stateId,
      String schemaVersion,
      long byteSize,
      int recordCount,
      String sha256) {}

  public record PathSummary(
      String schemaVersion,
      String pathId,
      String stateId,
      long blockNumber,
      String stateRoot,
      String trieKey,
      String status,
      int proofNodeCount,
      long totalRlpBytes) {}

  public record RetainedPath(
      String schemaVersion,
      String pathId,
      String stateId,
      long blockNumber,
      String stateRoot,
      String trieKey,
      List<Map<String, Object>> steps) {}

  public record ErrorRecord(
      String schemaVersion,
      String errorId,
      String runId,
      String stateId,
      String pathId,
      String stage,
      String category,
      String validationStatus,
      String message,
      Map<String, Object> structuredDetail,
      int retryCount,
      String timestamp,
      String relatedArtifact) {}

  public record CompatibilityDeclaration(
      String analyserVersion,
      Set<String> supportedRunSchemas,
      Set<String> supportedCheckpointFormats,
      Set<String> supportedFragmentSchemas) {}

  public record CompatibilityResult(boolean compatible, boolean restartRequired, String detail) {}

  public enum AttemptOutcome {
    COMMITTED,
    REJECTED
  }

  public enum RunStatus {
    CREATED,
    RUNNING,
    FINALISING,
    COMPLETED,
    FAILED
  }

  public record Checkpoint(
      String schemaVersion,
      String checkpointFormat,
      String runId,
      String stateId,
      long blockNumber,
      String stateRoot,
      int attemptNumber,
      String outcome,
      String attemptDirectory,
      List<FragmentIntegrity> fragments,
      String analyserVersion,
      String timestamp,
      int retryCount,
      String failureDetail) {}

  public record StateAttemptInput(
      String runId,
      String stateId,
      long blockNumber,
      String stateRoot,
      String analyserVersion,
      Map<String, Object> stateSummary,
      List<Map<String, Object>> pathRecords,
      List<Map<String, Object>> retainedRecords,
      List<Map<String, Object>> errorRecords) {
    public StateAttemptInput(
        final String runId,
        final String stateId,
        final long blockNumber,
        final String stateRoot,
        final String analyserVersion,
        final Map<String, Object> stateSummary,
        final List<Map<String, Object>> pathRecords,
        final List<Map<String, Object>> retainedRecords,
        final List<Map<String, Object>> errorRecords) {
      this.runId = runId;
      this.stateId = stateId;
      this.blockNumber = blockNumber;
      this.stateRoot = stateRoot;
      this.analyserVersion = analyserVersion;
      this.stateSummary = stateSummary;
      this.pathRecords = List.copyOf(pathRecords);
      this.retainedRecords = List.copyOf(retainedRecords);
      this.errorRecords = List.copyOf(errorRecords);
    }
  }

  public record AttemptCommit(Checkpoint checkpoint, Path attemptDirectory) {}

  public record V2AttemptCommit(V2Checkpoint checkpoint, Path attemptDirectory) {}

  public record V2StateAttemptInput(
      String runId,
      String stateId,
      long blockNumber,
      String blockHash,
      String stateRoot,
      String finalClassification,
      String analyserVersion,
      Map<String, Object> stateSummary,
      List<Map<String, Object>> pathRecords,
      List<Map<String, Object>> retainedRecords,
      List<Map<String, Object>> errorRecords) {
    public V2StateAttemptInput(
        final String runId,
        final String stateId,
        final long blockNumber,
        final String blockHash,
        final String stateRoot,
        final String finalClassification,
        final String analyserVersion,
        final Map<String, Object> stateSummary,
        final List<Map<String, Object>> pathRecords,
        final List<Map<String, Object>> retainedRecords,
        final List<Map<String, Object>> errorRecords) {
      this.runId = runId;
      this.stateId = stateId;
      this.blockNumber = blockNumber;
      this.blockHash = blockHash;
      this.stateRoot = stateRoot;
      this.finalClassification = finalClassification;
      this.analyserVersion = analyserVersion;
      this.stateSummary = stateSummary;
      this.pathRecords = List.copyOf(pathRecords);
      this.retainedRecords = List.copyOf(retainedRecords);
      this.errorRecords = List.copyOf(errorRecords);
    }
  }

  public record V2Checkpoint(
      String schemaVersion,
      String checkpointFormat,
      String runId,
      String stateId,
      long blockNumber,
      String blockHash,
      String stateRoot,
      int attemptNumber,
      String finalClassification,
      String internalStatus,
      String attemptDirectory,
      List<FragmentIntegrity> fragments,
      String analyserVersion,
      String timestamp,
      int retryCount,
      String failureDetail,
      String failureStage,
      String failureCategory,
      boolean retryable,
      String diagnosticErrorArtifact) {}

  public record V2Recovery(
      Map<String, V2Checkpoint> activeCheckpoints,
      List<V2Checkpoint> invalidCheckpoints,
      List<V2Checkpoint> rejectedCheckpoints,
      List<String> invalidCheckpointArtifacts) {
    public V2Recovery(
        final Map<String, V2Checkpoint> activeCheckpoints,
        final List<V2Checkpoint> invalidCheckpoints,
        final List<V2Checkpoint> rejectedCheckpoints,
        final List<String> invalidCheckpointArtifacts) {
      this.activeCheckpoints = Map.copyOf(activeCheckpoints);
      this.invalidCheckpoints = List.copyOf(invalidCheckpoints);
      this.rejectedCheckpoints = List.copyOf(rejectedCheckpoints);
      this.invalidCheckpointArtifacts = List.copyOf(invalidCheckpointArtifacts);
    }
  }

  public record Recovery(
      Map<String, Checkpoint> activeCheckpoints,
      List<Checkpoint> invalidCheckpoints,
      List<Checkpoint> rejectedCheckpoints,
      List<String> invalidCheckpointArtifacts) {
    public Recovery(
        final Map<String, Checkpoint> activeCheckpoints,
        final List<Checkpoint> invalidCheckpoints,
        final List<Checkpoint> rejectedCheckpoints) {
      this(activeCheckpoints, invalidCheckpoints, rejectedCheckpoints, List.of());
    }

    public Recovery(
        final Map<String, Checkpoint> activeCheckpoints,
        final List<Checkpoint> invalidCheckpoints,
        final List<Checkpoint> rejectedCheckpoints,
        final List<String> invalidCheckpointArtifacts) {
      this.activeCheckpoints = Map.copyOf(activeCheckpoints);
      this.invalidCheckpoints = List.copyOf(invalidCheckpoints);
      this.rejectedCheckpoints = List.copyOf(rejectedCheckpoints);
      this.invalidCheckpointArtifacts = List.copyOf(invalidCheckpointArtifacts);
    }
  }

  public record StateSummary(
      String schemaVersion,
      String stateId,
      long blockNumber,
      String stateRoot,
      String stateStatus,
      int pathCount,
      int validCount,
      int missingCount,
      int malformedCount,
      int referenceMismatchCount,
      int maxProofNodeCount,
      int branchNodeCount,
      int extensionNodeCount,
      int leafNodeCount,
      int hashedReferenceCount,
      int inlineReferenceCount,
      int emptyReferenceCount,
      long totalRlpBytes,
      int errorCount,
      String checkpointReference) {
    private static final String CSV_HEADER =
        "schema_version,state_id,block_number,state_root,state_status,path_count,valid_count,missing_count,malformed_count,reference_mismatch_count,max_proof_node_count,branch_node_count,extension_node_count,leaf_node_count,hashed_reference_count,inline_reference_count,empty_reference_count,total_rlp_bytes,error_count,checkpoint_reference";

    private String toCsv() {
      return String.join(
          ",",
          csv(schemaVersion),
          csv(stateId),
          csv(Long.toString(blockNumber)),
          csv(stateRoot),
          csv(stateStatus),
          csv(Integer.toString(pathCount)),
          csv(Integer.toString(validCount)),
          csv(Integer.toString(missingCount)),
          csv(Integer.toString(malformedCount)),
          csv(Integer.toString(referenceMismatchCount)),
          csv(Integer.toString(maxProofNodeCount)),
          csv(Integer.toString(branchNodeCount)),
          csv(Integer.toString(extensionNodeCount)),
          csv(Integer.toString(leafNodeCount)),
          csv(Integer.toString(hashedReferenceCount)),
          csv(Integer.toString(inlineReferenceCount)),
          csv(Integer.toString(emptyReferenceCount)),
          csv(Long.toString(totalRlpBytes)),
          csv(Integer.toString(errorCount)),
          csv(checkpointReference));
    }

    private static String csv(final String value) {
      if (value.indexOf(',') >= 0 || value.indexOf('"') >= 0 || value.indexOf('\n') >= 0) {
        return "\"" + value.replace("\"", "\"\"") + "\"";
      }
      return value;
    }

    private StateSummary withCheckpointReference(final String reference) {
      return new StateSummary(
          schemaVersion,
          stateId,
          blockNumber,
          stateRoot,
          stateStatus,
          pathCount,
          validCount,
          missingCount,
          malformedCount,
          referenceMismatchCount,
          maxProofNodeCount,
          branchNodeCount,
          extensionNodeCount,
          leafNodeCount,
          hashedReferenceCount,
          inlineReferenceCount,
          emptyReferenceCount,
          totalRlpBytes,
          errorCount,
          reference);
    }
  }

  public record Manifest(
      String schemaVersion,
      String checkpointFormat,
      Map<String, String> fragmentFormats,
      String analyserVersion,
      Map<String, Boolean> compatibility,
      String runId,
      String auditMode,
      String hashVariant,
      String hashPolicyIdentity,
      String databaseIdentity,
      Map<String, String> chainMetadata,
      Map<String, Object> runConfiguration,
      Map<String, Object> selectedStateConfiguration,
      String status,
      String startTimestamp,
      String lastUpdateTimestamp,
      String latestCheckpoint,
      int committedStateCount,
      int failedStateCount,
      int unavailableStateCount,
      Map<String, Object> finalisationMetadata,
      Boolean stationaryDatabaseAcknowledged,
      Boolean degradedDerivedAtomicity,
      String failureDetail) {
    public Manifest withStatus(final String newStatus, final String failure) {
      return new Manifest(
          schemaVersion,
          checkpointFormat,
          fragmentFormats,
          analyserVersion,
          compatibility,
          runId,
          auditMode,
          hashVariant,
          hashPolicyIdentity,
          databaseIdentity,
          chainMetadata,
          runConfiguration,
          selectedStateConfiguration,
          newStatus,
          startTimestamp,
          Instant.now().toString(),
          latestCheckpoint,
          committedStateCount,
          failedStateCount,
          unavailableStateCount,
          finalisationMetadata,
          stationaryDatabaseAcknowledged,
          degradedDerivedAtomicity,
          failure);
    }

    public Manifest withDegradedDerivedAtomicity() {
      return new Manifest(
          schemaVersion,
          checkpointFormat,
          fragmentFormats,
          analyserVersion,
          compatibility,
          runId,
          auditMode,
          hashVariant,
          hashPolicyIdentity,
          databaseIdentity,
          chainMetadata,
          runConfiguration,
          selectedStateConfiguration,
          status,
          startTimestamp,
          lastUpdateTimestamp,
          latestCheckpoint,
          committedStateCount,
          failedStateCount,
          unavailableStateCount,
          finalisationMetadata,
          stationaryDatabaseAcknowledged,
          true,
          failureDetail);
    }
  }
}
