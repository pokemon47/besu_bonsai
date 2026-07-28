/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.proof.hashing.KeccakProofPathHashing;
import org.hyperledger.besu.ethereum.proof.hashing.Poseidon2ProofPathHashing;
import org.hyperledger.besu.ethereum.proof.hashing.ProofPathHashing;
import org.hyperledger.besu.ethereum.proof.hashing.ProofPathHashingHolder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Locale;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Coordinates one historical account state through enumeration and v2 persistence. */
public final class AccountStateAuditProcessor {
  private static final String COMPLETED = "COMPLETED";
  private static final String UNAVAILABLE = "UNAVAILABLE";
  private static final String FAILED = "FAILED";

  private final HistoricalForestStateResolutionProbe resolver;
  private final ForestAccountTrieAccess trieAccess;
  private final AuditRunPersistence persistence;

  public AccountStateAuditProcessor(
      final HistoricalForestStateResolutionProbe resolver,
      final ForestAccountTrieAccess trieAccess,
      final AuditRunPersistence persistence) {
    this.resolver = resolver;
    this.trieAccess = trieAccess;
    this.persistence = persistence;
  }

  public ProcessResult process(final Input input) throws IOException {
    try (Phase4FDiagnostics diagnostics = Phase4FDiagnostics.open(input.runDirectory(), input.blockNumber())) {
      return process(input, diagnostics);
    }
  }

  private ProcessResult process(final Input input, final Phase4FDiagnostics diagnostics) throws IOException {
    final ProofPathHashing detectedPolicy = ProofPathHashingHolder.get();
    diagnostics.stage("manifest_and_canonical_resolution");
    ensureV2Manifest(input);
    final HistoricalForestStateResolutionProbe.Resolution resolution =
        resolver.resolve(input.blockNumber());
    final String stateId =
        resolution.stateRoot().isPresent()
            ? AuditRecordIds.stateId(input.blockNumber(), resolution.stateRoot().orElseThrow())
            : "state_unresolved_" + input.blockNumber();
    if (resolution.status()
        == HistoricalForestStateResolutionProbe.Status.HISTORICAL_STATE_UNAVAILABLE) {
      persistUnavailable(input, stateId, resolution);
      return new ProcessResult(UNAVAILABLE, stateId, 0, "Historical Forest state unavailable");
    }
    if (!resolution.isResolved()) {
      persistFailure(input, stateId, resolution.status().name(), resolution.error());
      return new ProcessResult(FAILED, stateId, 0, resolution.error());
    }

    final ProofPathHashing policy = detectedPolicy;
    if (!policyMatches(input.hashVariant(), policy)) {
      persistFailure(input, stateId, "HASH_POLICY", "Requested and detected hash policies differ");
      return new ProcessResult(FAILED, stateId, 0, "Hash-policy mismatch");
    }
    final String policyIdentity = policyIdentity(policy);
    final Hash stateRoot = resolution.stateRoot().orElseThrow();
    for (int attempt = 0; attempt < 2; attempt++) {
      try {
        diagnostics.stage("historical_state_opening_and_trie_acquisition");
        diagnostics.countOperation("forest_open");
        final ForestAccountTrieAccess.OpenedAccountTrie opened =
            trieAccess.open(stateRoot, policy.trieHashFunction(), policyIdentity);
        diagnostics.stage("account_enumeration_and_authentication");
        final ForestAccountEnumerator.EnumerationResult enumeration =
            ForestAccountEnumerator.enumerate(
                opened.trie(),
                key ->
                    new ForestAccountPathTraverser(key, policy.trieHashFunction(), policyIdentity)
                        .traverse(opened.root()),
                diagnostics);
        if (!enumeration.isValid()) {
          throw new AuditProcessingException("ENUMERATION", enumeration.error());
        }
        diagnostics.stage("compact_summary_construction");
        final List<Map<String, Object>> paths = pathRecords(input, stateId, stateRoot, enumeration);
        final Map<String, Map<String, Object>> summariesByKey = new HashMap<>();
        for (final Map<String, Object> path : paths) {
          summariesByKey.put((String) path.get("trie_key"), path);
        }
        final Path indexDirectory =
            input.runDirectory().resolve("states").resolve(stateId).resolve("metric-indexes").resolve(String.format("attempt-%02d.part", attempt + 1));
        diagnostics.stage("metric_index_sort_and_percentile_selection");
        final Phase4DRetention.Result retention =
            Phase4DRetention.selectForDomain(
                input.runId(),
                input.hashVariant(),
                "not-provided",
                input.blockNumber(),
                stateRoot,
                stateId,
                enumeration.entries(),
                summariesByKey,
                input.retentionConfig(),
                indexDirectory);
        diagnostics.stage("retained_path_reruns_and_serialization");
        final List<Map<String, Object>> retained = rerunRetained(
            input, stateId, stateRoot, opened, policy, retention, summariesByKey, attempt + 1);
        diagnostics.stage("state_summary_generation");
        final Map<String, Object> summary = stateSummary(input, stateId, stateRoot, enumeration, policyIdentity, retention, retained.size());
        validateCompletionSummary(summary, paths.size());
        final AuditRunPersistence.V2StateAttemptInput attemptInput =
            new AuditRunPersistence.V2StateAttemptInput(
                input.runId(),
                stateId,
                input.blockNumber(),
                resolution.canonicalHash().orElseThrow().toHexString(),
                stateRoot.toHexString(),
                COMPLETED,
                input.analyserVersion(),
                summary,
                paths,
                retained,
                List.of());
        diagnostics.stage("fragment_hash_validation_attempt_promotion_checkpoint");
        persistence.commitStateV2(attemptInput);
        deleteRecursively(indexDirectory);
        return new ProcessResult(COMPLETED, stateId, enumeration.entries().size(), "");
      } catch (final AuditProcessingException | RuntimeException failure) {
        persistence.recordRejectedAttemptV2(
            input.runId(),
            stateId,
            input.blockNumber(),
            resolution.canonicalHash().map(Hash::toHexString).orElse(""),
            stateRoot.toHexString(),
            input.analyserVersion(),
            failure instanceof AuditProcessingException processing ? processing.stage : "PROCESSING",
            failureCode(failure),
            failure.getMessage());
        if (attempt == 1) {
          persistence.recordFinalClassificationV2(
              input.runId(),
              stateId,
              input.blockNumber(),
              resolution.canonicalHash().map(Hash::toHexString).orElse(""),
              stateRoot.toHexString(),
              FAILED,
              input.analyserVersion(),
              failure instanceof AuditProcessingException processing ? processing.stage : "PROCESSING",
              "RETRY_EXHAUSTED",
              failure.getMessage());
          return new ProcessResult(FAILED, stateId, 0, failure.getMessage());
        }
      }
    }
    return new ProcessResult(FAILED, stateId, 0, "Retry exhausted");
  }

  private void persistUnavailable(
      final Input input,
      final String stateId,
      final HistoricalForestStateResolutionProbe.Resolution resolution)
      throws IOException {
    Files.createDirectories(input.runDirectory().resolve("checkpoints"));
    persistence.recordFinalClassificationV2(
        input.runId(),
        stateId,
        input.blockNumber(),
        resolution.canonicalHash().map(Hash::toHexString).orElse(""),
        resolution.stateRoot().map(Hash::toHexString).orElse(""),
        UNAVAILABLE,
        input.analyserVersion(),
        "RESOLUTION",
        "HISTORICAL_STATE_UNAVAILABLE",
        resolution.error());
  }

  private void ensureV2Manifest(final Input input) throws IOException {
    final Path manifest = input.runDirectory().resolve("run_manifest.json");
    if (Files.exists(manifest)) return;
    final ProofPathHashing policy = ProofPathHashingHolder.get();
    final String policyIdentity = policyIdentity(policy);
    persistence.ensureCompatibleV2Manifest(
        new AuditRunPersistence.Manifest(
            AuditRunSchema.RUN_SCHEMA_V2,
            AuditRunSchema.CHECKPOINT_FORMAT_V2,
            Map.of(
                "path_summary", AuditRunSchema.PATH_FRAGMENT_SCHEMA_V2,
                "retained_paths", AuditRunSchema.RETAINED_FRAGMENT_SCHEMA_V2,
                "errors", AuditRunSchema.ERROR_FRAGMENT_SCHEMA_V2,
                "state_summary", AuditRunSchema.STATE_FRAGMENT_SCHEMA_V2),
            input.analyserVersion(),
            Map.of("v1_readable_only", true, "v2_resume", true),
            input.runId(),
            "account",
            input.hashVariant(),
            policyIdentity,
            "not-provided",
            Map.of(),
            Map.of(
                "phase", "4D",
                "single_state", true,
                "deterministic_sample_size", input.retentionConfig().sampleSize(),
                "proof_path_hashing_class", policy.getClass().getName(),
                "trie_hash_function_class", policy.trieHashFunction().getClass().getName(),
                "parameter_identity_available", false),
            Map.of("block_number", input.blockNumber()),
            "RUNNING",
            Instant.now().toString(),
            Instant.now().toString(),
            null,
            0,
            0,
            0,
            Map.of(),
            null,
            false,
            null));
  }

  private void persistFailure(
      final Input input, final String stateId, final String category, final String message)
      throws IOException {
    Files.createDirectories(input.runDirectory().resolve("checkpoints"));
    persistence.recordFinalClassificationV2(
        input.runId(), stateId, input.blockNumber(), "", "", FAILED, input.analyserVersion(), "RESOLUTION", category, message);
  }

  private static List<Map<String, Object>> pathRecords(
      final Input input,
      final String stateId,
      final Hash stateRoot,
      final ForestAccountEnumerator.EnumerationResult enumeration) {
    final List<Map<String, Object>> records = new ArrayList<>();
    for (final AccountEnumerationEntry entry : enumeration.entries()) {
      final AccountPathResult path = entry.authenticatedPath();
      final Map<String, Object> record = new LinkedHashMap<>();
      record.put("schema_version", AuditRunSchema.PATH_FRAGMENT_SCHEMA_V2);
      record.put("path_id", AuditRecordIds.pathId(input.blockNumber(), stateRoot, entry.key()));
      record.put("state_id", stateId);
      record.put("block_number", input.blockNumber());
      record.put("trie_key", entry.key().toHexString());
      record.put("status", path.status().name());
      record.put("proof_node_count", path.proofNodeCount());
      record.put("total_proof_rlp_bytes", path.totalProofRlpBytes());
      record.put("consumed_nibbles", path.consumedNibbles());
      record.put("remaining_nibbles", path.remainingNibbles());
      record.put("terminal_value_match", entry.accountValue().equals(path.accountValueBytes().orElse(null)));
      record.put("terminal_account_value_digest", path.accountValueBytes().map(Phase4DRetention::digest).orElse(""));
      record.put("node_types", path.steps().stream().map(AccountPathStep::nodeType).toList());
      record.put("incoming_reference_types", path.steps().stream().map(AccountPathStep::incomingReference).toList());
      record.put("reference_types", path.steps().stream().map(AccountPathStep::outgoingReference).toList());
      record.put("node_rlp_lengths", path.steps().stream().map(AccountPathStep::encodedRlpLength).toList());
      record.put("structural_signature", Phase4DRetention.signature(path));
      final PathMetrics metrics = metrics(path);
      record.put("terminal_form", metrics.terminalForm());
      record.put("branch_node_count", metrics.branchNodeCount());
      record.put("extension_node_count", metrics.extensionNodeCount());
      record.put("leaf_node_count", metrics.leafNodeCount());
      record.put("branch_value_terminal", metrics.branchValueTerminal());
      record.put("hashed_reference_count", metrics.hashedReferenceCount());
      record.put("inline_reference_count", metrics.inlineReferenceCount());
      record.put("empty_selected_reference_count", metrics.emptySelectedReferenceCount());
      record.put("root_reference_count", metrics.rootReferenceCount());
      record.put("maximum_node_rlp_bytes", metrics.maximumNodeRlpBytes());
      record.put("compact_path_nibble_count", metrics.compactPathNibbleCount());
      record.put("extension_path_nibble_count", metrics.extensionPathNibbleCount());
      record.put("odd_compact_path_count", metrics.oddCompactPathCount());
      record.put("even_compact_path_count", metrics.evenCompactPathCount());
      records.add(record);
    }
    return records;
  }

  private static Map<String, Object> stateSummary(
      final Input input,
      final String stateId,
      final Hash stateRoot,
      final ForestAccountEnumerator.EnumerationResult enumeration,
      final String policyIdentity,
      final Phase4DRetention.Result retention,
      final int retainedRecordCount) {
    final Map<String, Object> summary = new LinkedHashMap<>();
    summary.put("schema_version", AuditRunSchema.STATE_FRAGMENT_SCHEMA_V2);
    summary.put("state_id", stateId);
    summary.put("block_number", input.blockNumber());
    summary.put("state_root", stateRoot.toHexString());
    summary.put("final_classification", COMPLETED);
    summary.put("internal_attempt_status", "COMMITTED");
    summary.put("hash_variant", input.hashVariant());
    summary.put("hash_policy_identity", policyIdentity);
    summary.put("enumerated_account_count", enumeration.entries().size());
    summary.put("independent_terminal_count", enumeration.independentCount().count());
    summary.put("duplicate_count", enumeration.validation().duplicateCount());
    final List<PathMetrics> pathMetrics =
        enumeration.entries().stream().map(entry -> metrics(entry.authenticatedPath())).toList();
    summary.put("valid_count", enumeration.entries().size());
    summary.put("missing_count", 0);
    summary.put("malformed_count", 0);
    summary.put("reference_mismatch_count", 0);
    summary.put("terminal_value_mismatch_count", 0);
    summary.put("account_summary_record_count", enumeration.entries().size());
    summary.put("error_record_count", 0);
    summary.put("root_verification_passed", true);
    summary.put("enumeration_validation_passed", enumeration.validation().status() == AuditValidationStatus.VALID);
    summary.put("terminal_value_validation_passed", true);
    summary.put("independent_count_validation_passed", enumeration.entries().size() == enumeration.independentCount().count());
    summary.put("maximum_proof_node_count", pathMetrics.stream().mapToInt(PathMetrics::proofNodeCount).max().orElse(0));
    summary.put("maximum_proof_node_count_path_id", maximumPathId(input, stateRoot, enumeration.entries(), true));
    summary.put("total_proof_node_count", pathMetrics.stream().mapToInt(PathMetrics::proofNodeCount).sum());
    summary.put("total_branch_node_count", pathMetrics.stream().mapToInt(PathMetrics::branchNodeCount).sum());
    summary.put("total_extension_node_count", pathMetrics.stream().mapToInt(PathMetrics::extensionNodeCount).sum());
    summary.put("total_leaf_node_count", pathMetrics.stream().mapToInt(PathMetrics::leafNodeCount).sum());
    summary.put("branch_value_terminal_count", (int) pathMetrics.stream().filter(PathMetrics::branchValueTerminal).count());
    summary.put("total_hashed_reference_count", pathMetrics.stream().mapToInt(PathMetrics::hashedReferenceCount).sum());
    summary.put("total_inline_reference_count", pathMetrics.stream().mapToInt(PathMetrics::inlineReferenceCount).sum());
    summary.put("total_empty_selected_reference_count", pathMetrics.stream().mapToInt(PathMetrics::emptySelectedReferenceCount).sum());
    summary.put("maximum_total_proof_rlp_bytes", pathMetrics.stream().mapToInt(PathMetrics::totalProofRlpBytes).max().orElse(0));
    summary.put("maximum_total_proof_rlp_bytes_path_id", maximumPathId(input, stateRoot, enumeration.entries(), false));
    summary.put("maximum_node_rlp_bytes", pathMetrics.stream().mapToInt(PathMetrics::maximumNodeRlpBytes).max().orElse(0));
    summary.put("maximum_node_rlp_bytes_path_id", maximumNodeRlpPathId(input, stateRoot, enumeration.entries()));
    summary.put("total_proof_rlp_bytes", pathMetrics.stream().mapToInt(PathMetrics::totalProofRlpBytes).sum());
    summary.put("attempted_account_count", enumeration.entries().size());
    summary.put("completed_account_count", enumeration.entries().size());
    summary.put("node_kinds", enumeration.nodeKinds());
    summary.put("reference_kinds", enumeration.referenceKinds());
    final int percentileSelected = (int) retention.reasons().values().stream().filter(reasons -> reasons.stream().anyMatch(reason -> "PERCENTILE".equals(reason.get("reason")))).count();
    final int immediateSelected = retention.uniqueRetainedCount() - percentileSelected;
    summary.put("immediate_retained_path_count", immediateSelected);
    summary.put("percentile_retained_path_count", percentileSelected);
    summary.put("total_unique_retained_path_count", retainedRecordCount);
    summary.put("retained_reason_count", retention.retainedReasonCount());
    summary.put("structural_signature_count", retention.structuralSignatureCount());
    summary.put("structural_signatures", retention.candidates().values().stream().map(Phase4DRetention.Candidate::signature).distinct().sorted().toList());
    final Map<String, String> firstSeenSignatures = new TreeMap<>();
    retention.candidates().values().forEach(candidate -> firstSeenSignatures.putIfAbsent(candidate.signature(), candidate.pathId()));
    summary.put("structural_signature_first_seen", firstSeenSignatures);
    summary.put("targeted_key_match_count", (int) retention.reasons().values().stream().flatMap(List::stream).filter(reason -> "TARGETED_TRIE_KEY".equals(reason.get("reason"))).count());
    summary.put("deterministic_sample_count", (int) retention.reasons().values().stream().flatMap(List::stream).filter(reason -> "DETERMINISTIC_SAMPLE".equals(reason.get("reason"))).count());
    summary.put("percentile_selection_completed", true);
    summary.put("retained_path_rerun_count", retainedRecordCount);
    summary.put("retained_path_rerun_mismatch_count", 0);
    summary.put("metric_index_record_count", retention.indexRecordCounts());
    summary.put("percentile_population_size", retention.indexRecordCounts());
    summary.put("selected_percentile_path_ids", retention.selectedPercentilePathIds());
    summary.put("sampling_scheme_version", retention.samplingSchemeVersion());
    summary.put("sampling_domain_definition", retention.samplingDomainDefinition());
    summary.put("sampling_domain_digest", retention.samplingDomainDigest());
    summary.put("sampling_excludes_run_id", true);
    summary.put("temporary_metric_index_cleanup_status", "DELETED_AFTER_COMMIT");
    summary.put("created_at", Instant.now().toString());
    return summary;
  }

  private static String maximumPathId(final Input input, final Hash stateRoot,
      final List<AccountEnumerationEntry> entries, final boolean proofNodeCount) {
    return entries.stream().max(java.util.Comparator.comparingInt(entry -> proofNodeCount
        ? entry.authenticatedPath().proofNodeCount() : entry.authenticatedPath().totalProofRlpBytes()))
        .map(entry -> AuditRecordIds.pathId(input.blockNumber(), stateRoot, entry.key())).orElse("");
  }

  private static String maximumNodeRlpPathId(final Input input, final Hash stateRoot,
      final List<AccountEnumerationEntry> entries) {
    return entries.stream().max(java.util.Comparator.comparingInt(entry -> entry.authenticatedPath().steps().stream()
        .mapToInt(AccountPathStep::encodedRlpLength).max().orElse(0)))
        .map(entry -> AuditRecordIds.pathId(input.blockNumber(), stateRoot, entry.key())).orElse("");
  }

  private static void validateCompletionSummary(
      final Map<String, Object> summary, final int pathCount) throws AuditProcessingException {
    if (!Boolean.TRUE.equals(summary.get("root_verification_passed"))
        || !Boolean.TRUE.equals(summary.get("enumeration_validation_passed"))
        || !Boolean.TRUE.equals(summary.get("terminal_value_validation_passed"))
        || !Boolean.TRUE.equals(summary.get("independent_count_validation_passed"))
        || !Integer.valueOf(pathCount).equals(summary.get("account_summary_record_count"))
        || !Integer.valueOf(pathCount).equals(summary.get("enumerated_account_count"))
        || !Integer.valueOf(pathCount).equals(summary.get("independent_terminal_count"))
        || !Integer.valueOf(pathCount).equals(summary.get("completed_account_count"))
        || !Integer.valueOf(0).equals(summary.get("duplicate_count"))
        || !Integer.valueOf(0).equals(summary.get("missing_count"))
        || !Integer.valueOf(0).equals(summary.get("malformed_count"))
        || !Integer.valueOf(0).equals(summary.get("reference_mismatch_count"))
        || !Integer.valueOf(0).equals(summary.get("terminal_value_mismatch_count"))
        || !Boolean.TRUE.equals(summary.get("percentile_selection_completed"))
        || !Integer.valueOf(0).equals(summary.get("retained_path_rerun_mismatch_count"))
        || !Integer.valueOf(String.valueOf(summary.getOrDefault("total_unique_retained_path_count", 0))).equals(summary.get("retained_path_rerun_count"))
        || !"DELETED_AFTER_COMMIT".equals(summary.get("temporary_metric_index_cleanup_status"))
        || !Integer.valueOf(0).equals(summary.get("error_record_count"))) {
      throw new AuditProcessingException("VALIDATION", "Completion evidence invariant failed");
    }
  }

  private static List<Map<String, Object>> rerunRetained(
      final Input input,
      final String stateId,
      final Hash stateRoot,
      final ForestAccountTrieAccess.OpenedAccountTrie opened,
      final ProofPathHashing policy,
      final Phase4DRetention.Result retention,
      final Map<String, Map<String, Object>> summariesByKey,
      final int attempt)
      throws IOException, AuditProcessingException {
    final List<Map<String, Object>> records = new ArrayList<>();
    for (final Phase4DRetention.Candidate candidate : retention.candidates().values()) {
      if (!retention.reasons().containsKey(candidate.pathId())) continue;
      final AccountPathResult originalCapture =
          new ForestAccountPathTraverser(candidate.entry().key(), policy.trieHashFunction(), policyIdentity(policy), true)
              .traverse(opened.root());
      final AccountPathResult rerun =
          new ForestAccountPathTraverser(candidate.entry().key(), policy.trieHashFunction(), policyIdentity(policy), true)
              .traverse(opened.root());
      final Map<String, Object> original = summariesByKey.get(candidate.entry().key().toHexString());
      final String mismatch = rerunMismatch(candidate.entry(), candidate.pathId(), originalCapture, rerun, original);
      if (mismatch != null) {
        throw new AuditProcessingException("RERUN", "RERUN_MISMATCH path_id=" + candidate.pathId() + " " + mismatch);
      }
      final Map<String, Object> record =
          Phase4DRetention.retainedRecord(
              input.runId(), stateId, input.blockNumber(), stateRoot, candidate, rerun, retention.reasons().get(candidate.pathId()), false);
      record.put("attempt_number", attempt);
      records.add(record);
    }
    return records;
  }

  static String rerunMismatch(
      final AccountEnumerationEntry entry,
      final String pathId,
      final AccountPathResult originalCapture,
      final AccountPathResult rerun,
      final Map<String, Object> original) {
    if (original == null) return "field=summary";
    if (!pathId.equals(original.get("path_id"))) return "field=path_id";
    final PathMetrics metrics = metrics(rerun);
    if (!rerun.status().name().equals(original.get("status"))) return "field=status";
    if (rerun.proofNodeCount() != number(original, "proof_node_count")) return "field=proof_node_count";
    if (rerun.consumedNibbles() != number(original, "consumed_nibbles")) return "field=consumed_nibbles";
    if (rerun.remainingNibbles() != number(original, "remaining_nibbles")) return "field=remaining_nibbles";
    if (!metrics.terminalForm().equals(original.get("terminal_form"))) return "field=terminal_form";
    if (metrics.branchNodeCount() != number(original, "branch_node_count")) return "field=branch_node_count";
    if (metrics.extensionNodeCount() != number(original, "extension_node_count")) return "field=extension_node_count";
    if (metrics.leafNodeCount() != number(original, "leaf_node_count")) return "field=leaf_node_count";
    if (metrics.branchValueTerminal() != Boolean.TRUE.equals(original.get("branch_value_terminal"))) return "field=branch_value_terminal";
    if (metrics.hashedReferenceCount() != number(original, "hashed_reference_count")) return "field=hashed_reference_count";
    if (metrics.inlineReferenceCount() != number(original, "inline_reference_count")) return "field=inline_reference_count";
    if (metrics.emptySelectedReferenceCount() != number(original, "empty_selected_reference_count")) return "field=empty_selected_reference_count";
    if (metrics.rootReferenceCount() != number(original, "root_reference_count")) return "field=root_reference_count";
    if (metrics.maximumNodeRlpBytes() != number(original, "maximum_node_rlp_bytes")) return "field=maximum_node_rlp_bytes";
    if (metrics.compactPathNibbleCount() != number(original, "compact_path_nibble_count")) return "field=compact_path_nibble_count";
    if (metrics.extensionPathNibbleCount() != number(original, "extension_path_nibble_count")) return "field=extension_path_nibble_count";
    if (metrics.oddCompactPathCount() != number(original, "odd_compact_path_count")) return "field=odd_compact_path_count";
    if (metrics.evenCompactPathCount() != number(original, "even_compact_path_count")) return "field=even_compact_path_count";
    if (metrics.proofNodeCount() != number(original, "proof_node_count")) return "field=proof_node_count";
    if (metrics.totalProofRlpBytes() != number(original, "total_proof_rlp_bytes")) return "field=total_proof_rlp_bytes";
    final String stepMismatch = firstStepMismatch(pathNodeTypes(rerun), original.get("node_types"), "node_types");
    if (stepMismatch != null) return stepMismatch;
    final String incomingMismatch = firstStepMismatch(pathIncomingReferences(rerun), original.get("incoming_reference_types"), "incoming_reference_types");
    if (incomingMismatch != null) return incomingMismatch;
    final String outgoingMismatch = firstStepMismatch(pathOutgoingReferences(rerun), original.get("reference_types"), "reference_types");
    if (outgoingMismatch != null) return outgoingMismatch;
    final String rlpMismatch = firstStepMismatch(pathRlpLengths(rerun), original.get("node_rlp_lengths"), "node_rlp_lengths");
    if (rlpMismatch != null) return rlpMismatch;
    if (!Phase4DRetention.digest(originalCapture.accountValueBytes().orElse(org.apache.tuweni.bytes.Bytes.EMPTY)).equals(Phase4DRetention.digest(rerun.accountValueBytes().orElse(org.apache.tuweni.bytes.Bytes.EMPTY)))) return "field=terminal_account_value_digest";
    final String rawMismatch = firstStepMismatch(rawRlp(rerun), rawRlp(originalCapture), "encoded_node_rlp");
    if (rawMismatch != null) return rawMismatch;
    if (!Phase4DRetention.signature(rerun).equals(original.get("structural_signature"))) return "field=structural_signature";
    if (!entry.accountValue().equals(rerun.accountValueBytes().orElse(null))) return "field=terminal_account_value";
    return null;
  }

  private static int number(final Map<String, Object> values, final String key) {
    return ((Number) values.get(key)).intValue();
  }

  private static String firstStepMismatch(final List<?> actual, final Object expected, final String field) {
    if (!(expected instanceof List<?> expectedList)) return "field=" + field;
    final int limit = Math.min(actual.size(), expectedList.size());
    for (int i = 0; i < limit; i++) {
      if (!Objects.equals(actual.get(i), expectedList.get(i))) return "field=" + field + " step_index=" + i;
    }
    return actual.size() == expectedList.size() ? null : "field=" + field + " step_index=" + limit;
  }

  private static List<String> pathNodeTypes(final AccountPathResult path) {
    return path.steps().stream().map(AccountPathStep::nodeType).toList();
  }

  private static List<String> pathIncomingReferences(final AccountPathResult path) {
    return path.steps().stream().map(AccountPathStep::incomingReference).toList();
  }

  private static List<String> pathOutgoingReferences(final AccountPathResult path) {
    return path.steps().stream().map(AccountPathStep::outgoingReference).toList();
  }

  private static List<Integer> pathRlpLengths(final AccountPathResult path) {
    return path.steps().stream().map(AccountPathStep::encodedRlpLength).toList();
  }

  private static List<String> rawRlp(final AccountPathResult path) {
    return path.steps().stream().map(step -> step.encodedNodeRlp().toHexString().toLowerCase(Locale.ROOT)).toList();
  }

  private static void deleteRecursively(final Path path) {
    if (!Files.exists(path)) return;
    try (var stream = Files.walk(path)) {
      final List<Path> paths = stream.sorted(java.util.Comparator.reverseOrder()).toList();
      for (final Path candidate : paths) Files.deleteIfExists(candidate);
    } catch (IOException failure) {
      throw new IllegalStateException("Unable to remove temporary Phase 4D index", failure);
    }
  }

  private static PathMetrics metrics(final AccountPathResult path) {
    final List<AccountPathStep> steps = path.steps();
    final String terminalForm =
        steps.isEmpty() ? "NONE" : normalizeNodeType(steps.get(steps.size() - 1).nodeType());
    return new PathMetrics(
        terminalForm,
        countNodes(steps, "BRANCH"),
        countNodes(steps, "EXTENSION"),
        countNodes(steps, "LEAF"),
        !steps.isEmpty()
            && steps.get(steps.size() - 1).terminal()
            && "BRANCH".equals(normalizeNodeType(steps.get(steps.size() - 1).nodeType())),
        countReferences(steps, "HASHED"),
        countReferences(steps, "INLINE"),
        countReferences(steps, "EMPTY"),
        countRootReferences(steps),
        steps.stream().mapToInt(AccountPathStep::encodedRlpLength).max().orElse(0),
        steps.stream().mapToInt(AccountPathStep::compactPathNibbleLength).sum(),
        steps.stream()
            .filter(step -> "EXTENSION".equals(step.compactPathKind()))
            .mapToInt(AccountPathStep::compactPathNibbleLength)
            .sum(),
        (int) steps.stream().filter(AccountPathStep::compactPathOdd).count(),
        (int) steps.stream().filter(step -> step.compactPathNibbleLength() > 0 && !step.compactPathOdd()).count(),
        path.proofNodeCount(),
        path.totalProofRlpBytes());
  }

  private static int countNodes(final List<AccountPathStep> steps, final String type) {
    return (int) steps.stream().filter(step -> type.equals(normalizeNodeType(step.nodeType()))).count();
  }

  private static int countReferences(final List<AccountPathStep> steps, final String type) {
    return (int) steps.stream().filter(step -> type.equals(step.outgoingReference())).count();
  }

  private static int countRootReferences(final List<AccountPathStep> steps) {
    return (int) steps.stream().filter(step -> "ROOT".equals(step.incomingReference())).count();
  }

  private static String normalizeNodeType(final String type) {
    return type.endsWith("Node") ? type.substring(0, type.length() - 4).toUpperCase(Locale.ROOT) : type.toUpperCase(Locale.ROOT);
  }

  private record PathMetrics(
      String terminalForm,
      int branchNodeCount,
      int extensionNodeCount,
      int leafNodeCount,
      boolean branchValueTerminal,
      int hashedReferenceCount,
      int inlineReferenceCount,
      int emptySelectedReferenceCount,
      int rootReferenceCount,
      int maximumNodeRlpBytes,
      int compactPathNibbleCount,
      int extensionPathNibbleCount,
      int oddCompactPathCount,
      int evenCompactPathCount,
      int proofNodeCount,
      int totalProofRlpBytes) {}

  private static boolean policyMatches(final String requested, final ProofPathHashing policy) {
    return switch (requested.toLowerCase(Locale.ROOT)) {
      case "keccak", "keccak256" -> policy instanceof KeccakProofPathHashing;
      case "poseidon2" -> policy instanceof Poseidon2ProofPathHashing;
      default -> false;
    };
  }

  private static String failureCode(final Throwable failure) {
    final String message = failure.getMessage() == null ? "" : failure.getMessage().toLowerCase(Locale.ROOT);
    if (message.contains("rerun_mismatch")) return "RERUN_MISMATCH";
    if (message.contains("duplicate")) return "DUPLICATE_KEY";
    if (message.contains("count")) return "INDEPENDENT_COUNT_MISMATCH";
    if (message.contains("missing") || message.contains("unavailable")) return "REQUIRED_NODE_UNAVAILABLE";
    if (message.contains("reference") || message.contains("identity")) return "REFERENCE_MISMATCH";
    if (message.contains("value")) return "TERMINAL_VALUE_MISMATCH";
    if (message.contains("fragment")) return "FRAGMENT_VALIDATION_FAILED";
    return "ENUMERATION_FAILED";
  }

  private static String policyIdentity(final ProofPathHashing policy) {
    return policy.getClass().getSimpleName() + "/" + policy.trieHashFunction().getClass().getSimpleName();
  }

  public record Input(
      long blockNumber,
      String hashVariant,
      String runId,
      String stateId,
      Path runDirectory,
      String analyserVersion,
      Phase4DRetention.Config retentionConfig) {
    public Input(
        final long blockNumber,
        final String hashVariant,
        final String runId,
        final String stateId,
        final Path runDirectory,
        final String analyserVersion) {
      this(blockNumber, hashVariant, runId, stateId, runDirectory, analyserVersion, Phase4DRetention.Config.defaults());
    }
  }

  public record ProcessResult(String finalClassification, String stateId, int accountCount, String error) {}

  private static final class AuditProcessingException extends Exception {
    private final String stage;

    private AuditProcessingException(final String stage, final String message) {
      super(message);
      this.stage = stage;
    }
  }
}
