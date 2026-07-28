/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;

import org.hyperledger.besu.ethereum.proof.hashing.ProofPathHashing;
import org.hyperledger.besu.ethereum.proof.hashing.ProofPathHashingHolder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

/** Deterministic, single-threaded Phase 4E account-audit orchestrator. */
public final class Phase4EAccountAudit {
  private static final ObjectMapper MAPPER = JsonMapper.builder()
      .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
      .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true).build();
  private final HistoricalForestStateResolutionProbe resolver;
  private final ForestAccountTrieAccess trieAccess;
  private final AuditRunPersistence persistence;
  private final Path runDirectory;

  public Phase4EAccountAudit(
      final HistoricalForestStateResolutionProbe resolver,
      final ForestAccountTrieAccess trieAccess,
      final AuditRunPersistence persistence,
      final Path runDirectory) {
    this.resolver = resolver;
    this.trieAccess = trieAccess;
    this.persistence = persistence;
    this.runDirectory = runDirectory;
  }

  public Result run(final Config config) throws IOException {
    final Phase4EHashPolicy.Validated policy = Phase4EHashPolicy.validate(config.hashVariant());
    final AuditRunPersistence.Manifest manifest = manifest(config, policy);
    persistence.ensureCompatibleV2Manifest(manifest);
    final Phase4EScheduleJournal journal = new Phase4EScheduleJournal(runDirectory);
    List<Phase4ESchedule.Event> events = journal.readValid(config.schedule().runId());
    if (events.isEmpty()) {
      events = Phase4ESchedule.baseline(config.schedule());
      journal.append(events);
    }

    final Set<Long> adaptiveParents = new HashSet<>();
    final Set<String> knownSignatures = new HashSet<>();
    int globalMaximum = 0;
    int globalRlpMaximum = 0;
    for (final AuditRunPersistence.V2Checkpoint checkpoint : persistence.scanV2().activeCheckpoints().values()) {
      if ("COMPLETED".equals(checkpoint.finalClassification())) {
        final SummaryEvidence existing = summaryEvidence(checkpoint);
        globalMaximum = Math.max(globalMaximum, existing.maximum());
        globalRlpMaximum = Math.max(globalRlpMaximum, existing.maximumTotalRlp());
        knownSignatures.addAll(existing.signatures());
      }
    }
    int adaptiveAdds = (int) events.stream().filter(event -> event.selectionType().name().startsWith("ADAPTIVE")
        && !"SUPPRESSED".equals(event.selectedStateStatus())).map(Phase4ESchedule.Event::blockNumber).distinct().count();
    int suppressedUniqueAdds = (int) events.stream().filter(event -> "SUPPRESSED".equals(event.selectedStateStatus())).map(Phase4ESchedule.Event::blockNumber).distinct().count();
    int suppressedEvents = (int) events.stream().filter(event -> "SUPPRESSED".equals(event.selectedStateStatus())).count();
    while (true) {
      final AuditRunPersistence.V2Recovery recovery = persistence.scanV2();
      final Set<Long> resolvedBlocks = recovery.activeCheckpoints().values().stream()
          .collect(java.util.stream.Collectors.mapping(AuditRunPersistence.V2Checkpoint::blockNumber, Collectors.toSet()));
      final List<Phase4ESchedule.Event> pending = Phase4EStateQueue.pending(events, resolvedBlocks::contains);
      if (pending.isEmpty()) break;
      final Phase4ESchedule.Event event = pending.get(0);
      final AccountStateAuditProcessor processor = new AccountStateAuditProcessor(resolver, trieAccess, persistence);
      processor.process(new AccountStateAuditProcessor.Input(
          event.blockNumber(), config.hashVariant(), config.runId(), "scheduled", runDirectory,
          config.analyserVersion(), config.retentionConfig()));
      final AuditRunPersistence.V2Recovery after = persistence.scanV2();
      final AuditRunPersistence.V2Checkpoint checkpoint = after.activeCheckpoints().values().stream()
          .filter(candidate -> candidate.blockNumber() == event.blockNumber())
          .max(Comparator.comparingInt(AuditRunPersistence.V2Checkpoint::attemptNumber)).orElse(null);
      if (checkpoint != null && "COMPLETED".equals(checkpoint.finalClassification())
          && event.refinementDepth() < config.schedule().maximumRefinementDepth()
          && adaptiveAdds < config.schedule().maximumAdaptiveAdditions()
          && adaptiveParents.add(event.blockNumber())) {
        final SummaryEvidence evidence = summaryEvidence(checkpoint);
        final boolean newMaximum = evidence.maximum() > globalMaximum;
        final boolean newSignature = evidence.signatures().stream().anyMatch(knownSignatures::add);
        final boolean newRlpOutlier = Phase4ESchedule.Config.rlpOutlier(globalRlpMaximum, evidence.maximumTotalRlp());
        globalMaximum = Math.max(globalMaximum, evidence.maximum());
        globalRlpMaximum = Math.max(globalRlpMaximum, evidence.maximumTotalRlp());
        final List<Phase4ESchedule.Event> additions = new ArrayList<>();
        if (newMaximum) {
          additions.addAll(Phase4ESchedule.neighbors(config.schedule(), event,
              Phase4ESchedule.Type.ADAPTIVE_MAXIMUM_NEIGHBOR, "new_global_maximum", evidence.maximumValue()));
        }
        if (newSignature) {
          additions.addAll(Phase4ESchedule.neighbors(config.schedule(), event,
              Phase4ESchedule.Type.ADAPTIVE_SIGNATURE_NEIGHBOR, "new_signature", evidence.signature()));
        }
        if (newRlpOutlier) {
          additions.addAll(Phase4ESchedule.neighbors(config.schedule(), event,
              Phase4ESchedule.Type.ADAPTIVE_RLP_OUTLIER_NEIGHBOR, "rlp_outlier", Integer.toString(evidence.maximumTotalRlp())));
        }
        final Set<Long> known = new HashSet<>(events.stream().filter(e -> !"SUPPRESSED".equals(e.selectedStateStatus()))
            .map(Phase4ESchedule.Event::blockNumber).toList());
        final int remainingBudget = Math.max(0, config.schedule().maximumAdaptiveAdditions() - adaptiveAdds);
        final Set<Long> permittedNew = additions.stream().map(Phase4ESchedule.Event::blockNumber).distinct()
            .filter(block -> !known.contains(block)).limit(remainingBudget).collect(Collectors.toCollection(java.util.LinkedHashSet::new));
        final List<Phase4ESchedule.Event> journalEvents = additions.stream().map(candidate ->
            !known.contains(candidate.blockNumber()) && !permittedNew.contains(candidate.blockNumber())
                ? candidate.withStatus("SUPPRESSED") : candidate).toList();
        final List<Phase4ESchedule.Event> existingEvents = events;
        final List<Phase4ESchedule.Event> unique = journalEvents.stream()
            .filter(candidate -> !existingEvents.contains(candidate)).toList();
        if (!unique.isEmpty()) {
          journal.append(unique);
          events = new ArrayList<>(events);
          events.addAll(unique);
          adaptiveAdds += permittedNew.size();
          suppressedUniqueAdds += (int) journalEvents.stream().filter(e -> "SUPPRESSED".equals(e.selectedStateStatus()))
              .map(Phase4ESchedule.Event::blockNumber).distinct().count();
          suppressedEvents += (int) journalEvents.stream().filter(e -> "SUPPRESSED".equals(e.selectedStateStatus())).count();
        }
      }
    }
    final AuditRunPersistence.V2Recovery finalRecovery = persistence.scanV2();
    final Set<Long> scheduled = new TreeSet<>(events.stream().filter(event -> !"SUPPRESSED".equals(event.selectedStateStatus()))
        .map(Phase4ESchedule.Event::blockNumber).toList());
    final Set<Long> resolved = finalRecovery.activeCheckpoints().values().stream()
        .collect(java.util.stream.Collectors.mapping(AuditRunPersistence.V2Checkpoint::blockNumber, Collectors.toSet()));
    final int unresolved = (int) scheduled.stream().filter(block -> !resolved.contains(block)).count();
    final Quality quality = classify(finalRecovery, scheduled, unresolved, config.schedule().mandatoryBoundaries());
    if (unresolved == 0) {
      persistence.finalizeRun(finalRecovery.activeCheckpoints().values().stream()
          .filter(checkpoint -> scheduled.contains(checkpoint.blockNumber()))
          .map(AuditRunPersistence.V2Checkpoint::stateId).collect(Collectors.toSet()), manifest);
    }
    writeGlobal(config, policy, events, finalRecovery, scheduled, unresolved, quality, adaptiveAdds,
        suppressedUniqueAdds, suppressedEvents);
    return new Result(config.runId(), quality, scheduled.size(), unresolved, adaptiveAdds, policy);
  }

  private AuditRunPersistence.Manifest manifest(final Config config, final Phase4EHashPolicy.Validated policy) {
    return new AuditRunPersistence.Manifest(
        AuditRunSchema.RUN_SCHEMA_V2, AuditRunSchema.CHECKPOINT_FORMAT_V2,
        Map.of("path_summary", AuditRunSchema.PATH_FRAGMENT_SCHEMA_V2,
            "retained_paths", AuditRunSchema.RETAINED_FRAGMENT_SCHEMA_V2,
            "errors", AuditRunSchema.ERROR_FRAGMENT_SCHEMA_V2,
            "state_summary", AuditRunSchema.STATE_FRAGMENT_SCHEMA_V2),
        config.analyserVersion(), Map.of("v2_resume", true, "phase4e", true), config.runId(), "account",
        config.hashVariant(), policy.proofPathHashingClass() + "/" + policy.trieHashFunctionClass(),
        config.databaseIdentity(), Map.of("network", config.network()),
        Map.of("phase", "4E", "single_threaded", true, "configured_target_max_block", config.schedule().configuredTargetMaxBlock(),
            "available_canonical_height", config.schedule().availableCanonicalHeight(), "effective_max_block", config.schedule().effectiveMaxBlock(),
            "proof_path_hashing_class", policy.proofPathHashingClass(), "trie_hash_function_class", policy.trieHashFunctionClass(),
            "account_key_identity", policy.accountKeyIdentity(), "poseidon2_parameter_identity", policy.poseidon2ParameterIdentity()),
        Map.of(), "RUNNING", java.time.Instant.now().toString(), java.time.Instant.now().toString(), null, 0, 0, 0, Map.of(), true, false, null);
  }

  private SummaryEvidence summaryEvidence(final AuditRunPersistence.V2Checkpoint checkpoint) throws IOException {
    final Path summary = runDirectory.resolve(checkpoint.attemptDirectory()).resolve("state_summary.json");
    final JsonNode json = MAPPER.readTree(Files.readString(summary));
    final int maximum = json.path("maximum_proof_node_count").asInt(0);
    final int maximumTotalRlp = json.path("maximum_total_proof_rlp_bytes").asInt(0);
    final List<String> signatures = new ArrayList<>();
    json.path("structural_signatures").forEach(node -> signatures.add(node.asText()));
    final Map<String, String> firstSeen = new TreeMap<>();
    json.path("structural_signature_first_seen").fields().forEachRemaining(entry -> firstSeen.put(entry.getKey(), entry.getValue().asText()));
    return new SummaryEvidence(maximum, maximumTotalRlp, json.path("maximum_node_rlp_bytes").asInt(0), signatures, firstSeen);
  }

  private void writeGlobal(final Config config, final Phase4EHashPolicy.Validated policy,
      final List<Phase4ESchedule.Event> events, final AuditRunPersistence.V2Recovery recovery,
      final Set<Long> scheduled, final int unresolved, final Quality quality, final int adaptiveAdds,
      final int suppressedUniqueAdds, final int suppressedEvents) throws IOException {
    final Map<String, Object> global = new LinkedHashMap<>();
    global.put("schema_version", AuditRunSchema.GLOBAL_SUMMARY_SCHEMA_V1);
    global.put("run_id", config.runId());
    global.put("hash_variant", config.hashVariant());
    global.put("detected_policy_identity", policy.proofPathHashingClass() + "/" + policy.trieHashFunctionClass());
    global.put("configured_target_max_block", config.schedule().configuredTargetMaxBlock());
    global.put("available_canonical_height", config.schedule().availableCanonicalHeight());
    global.put("effective_max_block", config.schedule().effectiveMaxBlock());
    global.put("adaptive_state_count", events.stream().filter(event -> event.selectionType().name().startsWith("ADAPTIVE")).map(Phase4ESchedule.Event::blockNumber).distinct().count());
    global.put("baseline_state_count", events.stream().filter(event -> event.selectionType() == Phase4ESchedule.Type.BASELINE).map(Phase4ESchedule.Event::blockNumber).distinct().count());
    global.put("maximum_refinement_depth", config.schedule().maximumRefinementDepth());
    global.put("maximum_adaptive_additions", config.schedule().maximumAdaptiveAdditions());
    global.put("unique_adaptive_additions_consumed", adaptiveAdds);
    global.put("adaptive_additions_remaining", Math.max(0, config.schedule().maximumAdaptiveAdditions() - adaptiveAdds));
    global.put("suppressed_unique_addition_count", suppressedUniqueAdds);
    global.put("suppressed_event_count", suppressedEvents);
    global.put("adaptive_addition_derivation", "max(20, ceil(0.25 * baseline_state_count)) unless explicitly overridden");
    global.put("total_scheduled_states", scheduled.size());
    global.put("completed_count", recovery.activeCheckpoints().values().stream().filter(c -> "COMPLETED".equals(c.finalClassification())).count());
    global.put("unavailable_count", recovery.activeCheckpoints().values().stream().filter(c -> "UNAVAILABLE".equals(c.finalClassification())).count());
    global.put("failed_count", recovery.activeCheckpoints().values().stream().filter(c -> "FAILED".equals(c.finalClassification())).count());
    global.put("unresolved_count", unresolved);
    final List<Long> unavailableBlocks = recovery.activeCheckpoints().values().stream()
        .filter(c -> "UNAVAILABLE".equals(c.finalClassification())).map(AuditRunPersistence.V2Checkpoint::blockNumber).sorted().toList();
    final Set<Long> mandatoryScheduled = config.schedule().mandatoryBoundaries().stream().filter(scheduled::contains).collect(Collectors.toSet());
    global.put("unavailable_block_numbers", unavailableBlocks);
    global.put("unavailable_mandatory_block_numbers", unavailableBlocks.stream().filter(mandatoryScheduled::contains).toList());
    global.put("coverage_limitation", unavailableBlocks.isEmpty() ? "none" : "historical states unavailable for listed blocks");
    global.put("audit_quality", quality.name());
    final List<SummaryEvidence> evidence = recovery.activeCheckpoints().values().stream()
        .filter(checkpoint -> "COMPLETED".equals(checkpoint.finalClassification()))
        .map(checkpoint -> {
          try { return summaryEvidence(checkpoint); } catch (IOException failure) { throw new IllegalStateException(failure); }
        }).toList();
    final int observedMaximum = evidence.stream().mapToInt(SummaryEvidence::maximum).max().orElse(0);
    final int observedRlpMaximum = evidence.stream().mapToInt(SummaryEvidence::maximumTotalRlp).max().orElse(0);
    final int recommendedCapacity = observedMaximum == 0 ? 0 : observedMaximum + Math.max(2, (int) Math.ceil(observedMaximum * 0.10));
    final Set<String> signatures = evidence.stream().flatMap(item -> item.signatures().stream()).collect(Collectors.toCollection(TreeSet::new));
    final Map<String, String> firstSeen = new TreeMap<>();
    evidence.stream().flatMap(item -> item.firstSeen().entrySet().stream()).sorted(Map.Entry.comparingByKey())
        .forEach(entry -> firstSeen.putIfAbsent(entry.getKey(), entry.getValue()));
    global.put("global_maximum_proof_node_count", observedMaximum);
    global.put("global_maximum_total_proof_rlp_bytes", observedRlpMaximum);
    global.put("rlp_trigger_rule", "current >= ceil(previous * 1.10); first observation establishes baseline");
    global.put("global_maximum_node_rlp_bytes", evidence.stream().mapToInt(SummaryEvidence::maximumNodeRlp).max().orElse(0));
    global.put("provisional_capacity_recommendation", recommendedCapacity);
    global.put("provisional_capacity_margin", observedMaximum == 0 ? 0 : Math.max(2, (int) Math.ceil(observedMaximum * 0.10)));
    global.put("observed_structural_signature_count", signatures.size());
    global.put("observed_structural_signatures", signatures);
    global.put("structural_signature_first_seen", firstSeen);
    global.put("capacity_evidence", "audit-derived provisional; completed states only; final after configured range completes");
    global.put("schedule_schema", AuditRunSchema.SCHEDULE_SCHEMA_V1);
    writeJson(runDirectory.resolve("global_summary.json"), global);
    final String report = "# Account Audit Report\n\n"
        + "Phase: 4E\n"
        + "Quality: " + quality.name() + "\n"
        + "Hash variant: " + config.hashVariant() + "\n"
        + "Scheduled states: " + scheduled.size() + "\n"
        + "Completed: " + recovery.activeCheckpoints().values().stream().filter(c -> "COMPLETED".equals(c.finalClassification())).count() + "\n"
        + "Unavailable blocks: " + unavailableBlocks + "\n"
        + "Coverage limitation: " + (unavailableBlocks.isEmpty() ? "none" : "historical states unavailable for listed blocks") + "\n"
        + "Adaptive additions consumed: " + adaptiveAdds + " / " + config.schedule().maximumAdaptiveAdditions() + "\n"
        + "Suppressed adaptive additions: " + suppressedUniqueAdds + "\n"
        + "Provisional capacity recommendation: " + recommendedCapacity + "\n";
    Files.writeString(runDirectory.resolve("audit_report.md"), report, StandardCharsets.UTF_8,
        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
  }

  private static Quality classify(final AuditRunPersistence.V2Recovery recovery, final Set<Long> scheduled,
      final int unresolved, final Set<Long> mandatory) {
    if (unresolved > 0) return Quality.DIAGNOSTIC_ONLY;
    if (recovery.activeCheckpoints().values().stream().anyMatch(c -> "FAILED".equals(c.finalClassification()))) return Quality.DIAGNOSTIC_ONLY;
    final Set<Long> completed = recovery.activeCheckpoints().values().stream().filter(c -> "COMPLETED".equals(c.finalClassification())).map(AuditRunPersistence.V2Checkpoint::blockNumber).collect(Collectors.toSet());
    final Set<Long> scheduledMandatory = mandatory.stream().filter(scheduled::contains).collect(Collectors.toSet());
    return completed.containsAll(scheduledMandatory) ? Quality.CAPACITY_SELECTION_QUALITY : Quality.DIAGNOSTIC_ONLY;
  }

  private static void writeJson(final Path path, final Object value) throws IOException {
    Files.writeString(path, MAPPER.writeValueAsString(value) + "\n", StandardCharsets.UTF_8,
        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
  }

  private record SummaryEvidence(int maximum, int maximumTotalRlp, int maximumNodeRlp,
      List<String> signatures, Map<String, String> firstSeen) {
    String maximumValue() { return Integer.toString(maximum); }
    String signature() { return signatures.isEmpty() ? "" : signatures.get(0); }
  }

  public record Config(String runId, String hashVariant, String network, String databaseIdentity,
      String analyserVersion, Phase4ESchedule.Config schedule, Phase4DRetention.Config retentionConfig) {}

  public enum Quality { TECHNICALLY_FINALISED, DIAGNOSTIC_ONLY, CAPACITY_SELECTION_QUALITY }

  public record Result(String runId, Quality quality, int scheduledStates, int unresolvedStates,
      int adaptiveAdditions, Phase4EHashPolicy.Validated policy) {}
}
