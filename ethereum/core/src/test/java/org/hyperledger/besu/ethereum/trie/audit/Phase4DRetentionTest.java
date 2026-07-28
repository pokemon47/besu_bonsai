/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

class Phase4DRetentionTest {
  private static final Bytes32 ROOT = Bytes32.fromHexString("0x" + "11".repeat(32));

  @TempDir Path tempDirectory;

  @Test
  void structuralSignaturesAreStableAndDistinguishStructure() {
    final AccountPathResult leaf = path("LeafNode", "HASHED", 1, 17);
    final AccountPathResult inline = path("LeafNode", "INLINE", 1, 17);
    final AccountPathResult extension = path("ExtensionNode", "HASHED", 2, 17);
    assertThat(Phase4DRetention.signature(leaf)).isEqualTo(Phase4DRetention.signature(path("LeafNode", "HASHED", 1, 17)));
    assertThat(Phase4DRetention.signature(leaf)).isNotEqualTo(Phase4DRetention.signature(inline));
    assertThat(Phase4DRetention.signature(leaf)).isNotEqualTo(Phase4DRetention.signature(extension));
  }

  @ParameterizedTest(name = "retained path form {0}")
  @MethodSource("retainedPathForms")
  void retainsExactRlpForEachLogicalPathForm(
      final String name, final AccountPathResult path, final List<String> incoming, final String terminalForm) throws Exception {
    final AccountEnumerationEntry entry = new AccountEnumerationEntry(ROOT, Bytes.of(1, 2, 3), path);
    final Phase4DRetention.Result result = select(List.of(entry), new Phase4DRetention.Config(0, Set.of()));
    final Map<String, Object> retained = result.retainedRecords().get(0);
    final List<?> steps = (List<?>) retained.get("full_ordered_steps");
    assertThat(steps).hasSize(path.steps().size());
    assertThat(retained.get("structural_signature")).isEqualTo(Phase4DRetention.signature(path));
    assertThat(retained.toString()).contains("encoded_node_rlp").doesNotContain("compact_path_summary_raw");
    assertThat(retained.get("terminal_form")).isEqualTo(terminalForm);
    assertThat(path.steps().stream().map(AccountPathStep::incomingReference).toList()).isEqualTo(incoming);
    for (int i = 0; i < steps.size(); i++) {
      final String encoded = String.valueOf(((Map<?, ?>) steps.get(i)).get("encoded_node_rlp"));
      assertThat(encoded).startsWith("0x").isEqualTo(encoded.toLowerCase(Locale.ROOT));
      assertThat(Bytes.fromHexString(encoded)).isEqualTo(path.steps().get(i).encodedNodeRlp());
      assertThat(((Map<?, ?>) steps.get(i)).get("encoded_node_rlp_length"))
          .isEqualTo(path.steps().get(i).encodedNodeRlp().size());
    }
  }

  private static Stream<Arguments> retainedPathForms() {
    return Stream.of(
        Arguments.of("root-leaf", pathFixture(List.of(step("LeafNode", "ROOT", "NONE", 1, true))), List.of("ROOT"), "LEAF"),
        Arguments.of("extension", pathFixture(List.of(step("ExtensionNode", "ROOT", "HASHED", 1, false), step("LeafNode", "HASHED", "NONE", 2, true))), List.of("ROOT", "HASHED"), "LEAF"),
        Arguments.of("branch-value", pathFixture(List.of(step("BranchNode", "ROOT", "NONE", 1, true))), List.of("ROOT"), "BRANCH"),
        Arguments.of("inline-child", pathFixture(List.of(step("BranchNode", "ROOT", "INLINE", 1, false), step("LeafNode", "INLINE", "NONE", 2, true))), List.of("ROOT", "INLINE"), "LEAF"),
        Arguments.of("hashed-child", pathFixture(List.of(step("BranchNode", "ROOT", "HASHED", 1, false), step("LeafNode", "HASHED", "NONE", 2, true))), List.of("ROOT", "HASHED"), "LEAF"),
        Arguments.of("depth-five", pathFixture(List.of(step("BranchNode", "ROOT", "HASHED", 1, false), step("BranchNode", "HASHED", "HASHED", 2, false), step("ExtensionNode", "HASHED", "INLINE", 3, false), step("BranchNode", "INLINE", "HASHED", 4, false), step("LeafNode", "HASHED", "NONE", 5, true))), List.of("ROOT", "HASHED", "HASHED", "INLINE", "HASHED"), "LEAF"));
  }

  private static AccountPathResult pathFixture(final List<AccountPathStep> steps) {
    return new AccountPathResult(AuditValidationStatus.VALID, ROOT, steps, 64, 0, steps.size(), steps.stream().mapToInt(AccountPathStep::encodedRlpLength).sum(), Optional.of(Bytes.of(1)), Optional.of(Bytes.of(1, 2, 3)), Optional.of(1), Optional.of(2), "");
  }

  private static AccountPathStep step(final String type, final String incoming, final String outgoing, final int index, final boolean terminal) {
    return new AccountPathStep(index - 1, type, incoming, outgoing, index - 1, 1, index, Math.max(0, 64 - index), type.contains("Leaf") ? "LEAF" : type.contains("Extension") ? "EXTENSION" : "NONE", true, 1, 10 + index, terminal, Bytes.of((byte) (0xa0 + index)));
  }

  @Test
  void exactPercentilesUseNearestRankAndDeterministicTieBreaks() throws Exception {
    final List<AccountEnumerationEntry> entries = entries(5);
    final Phase4DRetention.Result result = select(entries, new Phase4DRetention.Config(0, Set.of()));
    assertThat(result.indexRecordCounts()).containsEntry("proof_node_count", 5);
    assertThat(result.selectedPercentilePathIds().get("proof_node_count")).hasSize(5);
    assertThat(result.retainedRecords()).isNotEmpty();
    assertThat(Files.readString(tempDirectory.resolve("proof_node_count.jsonl")))
        .startsWith("audit_metric_index_v1|");
  }

  @ParameterizedTest(name = "percentile population N={0}")
  @MethodSource("percentilePopulations")
  void percentileMatrixCoversAllMetricsAndNearestRanks(final int population) throws Exception {
    final Phase4DRetention.Result result = select(entries(population), new Phase4DRetention.Config(0, Set.of()));
    for (final String metric : List.of("proof_node_count", "total_proof_rlp_bytes", "maximum_node_rlp_bytes", "extension_node_count", "inline_reference_count")) {
      assertThat(result.indexRecordCounts()).containsEntry(metric, population);
      if (population == 0) {
        assertThat(result.selectedPercentilePathIds()).doesNotContainKey(metric);
      } else {
        assertThat(result.selectedPercentilePathIds().get(metric)).hasSize(5);
        assertThat(result.retainedRecords().toString()).contains(metric);
      }
    }
    if (population > 0) {
      assertThat(result.retainedRecords().toString()).contains("percentile", "rank", "population", "value");
    }
  }

  private static Stream<Arguments> percentilePopulations() {
    return Stream.of(Arguments.of(0), Arguments.of(1), Arguments.of(3), Arguments.of(4), Arguments.of(5));
  }

  @Test
  void deterministicSampleIsBoundedAndIndependentOfEnumerationOrder() throws Exception {
    final List<AccountEnumerationEntry> original = entries(8);
    final List<AccountEnumerationEntry> reversed = new ArrayList<>(original);
    java.util.Collections.reverse(reversed);
    final Phase4DRetention.Config config = new Phase4DRetention.Config(2, Set.of());
    final Phase4DRetention.Result first = select(original, config);
    final Phase4DRetention.Result second = select(reversed, config);
    assertThat(sampleKeys(first)).isEqualTo(sampleKeys(second));
    assertThat(sampleKeys(first)).hasSize(2);
  }

  @Test
  void samplingDomainExcludesRunIdAndSeparatesStateAndHashVariant() throws Exception {
    final List<AccountEnumerationEntry> entries = entries(4);
    final Phase4DRetention.Result first = select(entries, new Phase4DRetention.Config(2, Set.of()));
    final Phase4DRetention.Result second = select(entries, new Phase4DRetention.Config(2, Set.of()));
    assertThat(sampleKeys(first)).isEqualTo(sampleKeys(second));
    final Map<String, Map<String, Object>> summaries = summaries(entries);
    final Phase4DRetention.Result differentRoot = Phase4DRetention.selectForDomain(
        "run-a", "keccak256", "not-provided", 1, Bytes32.fromHexString("0x" + "22".repeat(32)), "state", entries,
        summaries, new Phase4DRetention.Config(2, Set.of()), tempDirectory.resolve("root"));
    final Phase4DRetention.Result differentVariant = Phase4DRetention.selectForDomain(
        "run-a", "poseidon2", "not-provided", 1, ROOT, "state", entries,
        summaries, new Phase4DRetention.Config(2, Set.of()), tempDirectory.resolve("variant"));
    assertThat(first.samplingDomainDigest()).isNotEqualTo(differentRoot.samplingDomainDigest());
    assertThat(first.samplingDomainDigest()).isNotEqualTo(differentVariant.samplingDomainDigest());
    assertThat(first.samplingSchemeVersion()).isEqualTo("audit-sampling-v2");
  }

  @Test
  void targetedKeyAndRepeatedReasonsAreDeduplicatedPerPath() throws Exception {
    final List<AccountEnumerationEntry> entries = entries(1);
    final String key = entries.get(0).key().toHexString();
    final Phase4DRetention.Result result = select(entries, new Phase4DRetention.Config(1, Set.of(key)));
    final List<?> reasons = result.retainedRecords().get(0).get("retention_reasons") instanceof List<?> value ? value : List.of();
    assertThat(reasons.toString()).contains("TARGETED_TRIE_KEY", "DETERMINISTIC_SAMPLE");
    assertThat(result.retainedRecords()).hasSize(1);
  }

  @Test
  void retainedRecordContainsAllLogicalStepsAndPhase4DSchema() throws Exception {
    final Phase4DRetention.Result result = select(entries(1), new Phase4DRetention.Config(0, Set.of()));
    final Map<String, Object> record = result.retainedRecords().get(0);
    assertThat(record).containsKeys("schema_version", "structural_signature", "retention_reasons", "full_ordered_steps", "terminal_account_value_digest");
    assertThat(record.get("schema_version")).isEqualTo(AuditRunSchema.RETAINED_FRAGMENT_SCHEMA_V2);
    assertThat((List<?>) record.get("full_ordered_steps")).hasSize(1);
    assertThat(record.toString()).contains("encoded_node_rlp").contains("encoded_node_rlp_length");
  }

  @Test
  void emptyPopulationProducesIndexesButNoPercentileSelection() throws Exception {
    final Phase4DRetention.Result result = select(List.of(), new Phase4DRetention.Config(10, Set.of()));
    assertThat(result.retainedRecords()).isEmpty();
    assertThat(result.selectedPercentilePathIds()).isEmpty();
    assertThat(result.indexRecordCounts()).containsEntry("proof_node_count", 0);
  }

  @Test
  void externalSortSpansMultipleChunksAndIsChunkSizeIndependent() throws Exception {
    final List<AccountEnumerationEntry> entries = entries(300);
    final Phase4DRetention.Result one = select(entries, new Phase4DRetention.Config(0, Set.of(), 1));
    final Phase4DRetention.Result three = Phase4DRetention.select("run", "state", 1, ROOT, entries, summaries(entries), new Phase4DRetention.Config(0, Set.of(), 3), tempDirectory.resolve("three"));
    final Phase4DRetention.Result large = Phase4DRetention.select("run", "state", 1, ROOT, entries, summaries(entries), new Phase4DRetention.Config(0, Set.of(), 1000), tempDirectory.resolve("large"));
    assertThat(one.selectedPercentilePathIds()).isEqualTo(three.selectedPercentilePathIds());
    assertThat(one.selectedPercentilePathIds()).isEqualTo(large.selectedPercentilePathIds());
    assertThat(one.indexRecordCounts()).containsEntry("proof_node_count", 300);
    assertThat(Files.exists(tempDirectory.resolve("proof_node_count.chunks"))).isFalse();
  }

  private Phase4DRetention.Result select(
      final List<AccountEnumerationEntry> entries, final Phase4DRetention.Config config) throws Exception {
    return Phase4DRetention.select("run", "state", 1, ROOT, entries, summaries(entries), config, tempDirectory);
  }

  private Map<String, Map<String, Object>> summaries(final List<AccountEnumerationEntry> entries) {
    final Map<String, Map<String, Object>> summaries = new HashMap<>();
    for (final AccountEnumerationEntry entry : entries) {
      final String pathId = "path-" + entry.key().toHexString();
      summaries.put(entry.key().toHexString(), Map.of("path_id", pathId, "status", "VALID", "trie_key", entry.key().toHexString()));
    }
    return summaries;
  }

  private List<String> sampleKeys(final Phase4DRetention.Result result) {
    return result.retainedRecords().stream()
        .filter(record -> String.valueOf(record.get("retention_reasons")).contains("DETERMINISTIC_SAMPLE"))
        .map(record -> String.valueOf(record.get("trie_key")))
        .sorted()
        .toList();
  }

  private List<AccountEnumerationEntry> entries(final int count) {
    final List<AccountEnumerationEntry> entries = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      final Bytes32 key = Bytes32.fromHexString(String.format("0x%064x", i + 1));
      entries.add(new AccountEnumerationEntry(key, Bytes.of(1, 2, i & 0xff), path("LeafNode", i % 2 == 0 ? "HASHED" : "INLINE", i + 1, 17 + i)));
    }
    return entries;
  }

  private AccountPathResult path(final String nodeType, final String incoming, final int proofNodes, final int rlpLength) {
    final AccountPathStep step = new AccountPathStep(0, nodeType, "ROOT", incoming, 0, 64, 64, 0, "LEAF", true, 64, rlpLength, true, Bytes.of((byte) 0xc0));
    return new AccountPathResult(
        AuditValidationStatus.VALID,
        ROOT,
        List.of(step),
        64,
        0,
        proofNodes,
        rlpLength,
        Optional.of(Bytes.of(1, 2)),
        Optional.of(Bytes.of(1, 2, 3)),
        Optional.of(1),
        Optional.of(2),
        "");
  }
}
