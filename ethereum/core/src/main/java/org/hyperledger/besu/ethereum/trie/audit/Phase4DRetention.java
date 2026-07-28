/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import org.hyperledger.besu.crypto.MessageDigestFactory;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.TreeMap;

import org.apache.tuweni.bytes.Bytes;

/** Deterministic, bounded retention and exact percentile selection for one state. */
public final class Phase4DRetention {
  public static final String INDEX_SCHEMA = "audit_metric_index_v1";
  public static final String SAMPLING_SCHEME_VERSION = "audit-sampling-v2";
  public static final String SAMPLING_DOMAIN_DEFINITION =
      "scheme_version|hash_variant|chain_identity|block_number|state_root|trie_key";
  private static final List<String> METRICS =
      List.of(
          "proof_node_count",
          "total_proof_rlp_bytes",
          "maximum_node_rlp_bytes",
          "extension_node_count",
          "inline_reference_count");
  private static final List<Percentile> PERCENTILES =
      List.of(
          new Percentile("p50", 0.50),
          new Percentile("p90", 0.90),
          new Percentile("p95", 0.95),
          new Percentile("p99", 0.99),
          new Percentile("maximum", 1.0));

  private Phase4DRetention() {}

  public static Result select(
      final String runId,
      final String stateId,
      final long blockNumber,
      final Bytes stateRoot,
      final List<AccountEnumerationEntry> entries,
      final Map<String, Map<String, Object>> summaries,
      final Config config,
      final Path indexDirectory)
      throws IOException {
    return selectForDomain(runId, "keccak256", "not-provided", blockNumber, stateRoot, stateId, entries, summaries, config, indexDirectory);
  }

  public static Result selectForDomain(
      final String runId,
      final String hashVariant,
      final String chainIdentity,
      final long blockNumber,
      final Bytes stateRoot,
      final String stateId,
      final List<AccountEnumerationEntry> entries,
      final Map<String, Map<String, Object>> summaries,
      final Config config,
      final Path indexDirectory)
      throws IOException {
    Files.createDirectories(indexDirectory);
    final Map<String, Candidate> candidates = new LinkedHashMap<>();
    final Map<String, IndexWriter> indexWriters = new LinkedHashMap<>();
    final Set<String> signatures = new LinkedHashSet<>();
    final List<Candidate> ordered = new ArrayList<>();
    for (final AccountEnumerationEntry entry : entries) {
      final String pathId = (String) summaries.get(entry.key().toHexString()).get("path_id");
      final Map<String, Object> summary = summaries.get(entry.key().toHexString());
      final Candidate candidate = new Candidate(entry, pathId, summary, signature(entry.authenticatedPath()));
      candidates.put(pathId, candidate);
      ordered.add(candidate);
      for (final String metric : METRICS) {
        final int value = metricValue(metric, entry.authenticatedPath());
        indexWriters.computeIfAbsent(metric, ignored -> new IndexWriter(indexDirectory.resolve(metric + ".chunks"), config.metricIndexChunkSize()))
            .add(new IndexEntry(stateId, metric, value, pathId, entry.key().toHexString(), pathId));
      }
    }
    final Map<String, List<Map<String, Object>>> reasons = new LinkedHashMap<>();
    final Map<String, Integer> maximums = new HashMap<>();
    for (final Candidate candidate : ordered) {
      final AccountPathResult path = candidate.entry().authenticatedPath();
      final int proofNodes = path.proofNodeCount();
      if (maximums.getOrDefault("proof_node_count", -1) < proofNodes) {
        maximums.put("proof_node_count", proofNodes);
        addReason(reasons, candidate.pathId(), reason("STATE_PROOF_NODE_COUNT_MAXIMUM", Map.of("metric", "proof_node_count", "value", proofNodes)));
      }
      if (signatures.add(candidate.signature())) {
        addReason(reasons, candidate.pathId(), reason("NEW_NODE_REFERENCE_SIGNATURE", Map.of("signature", candidate.signature())));
      }
      if (config.targetedKeys().contains(candidate.entry().key().toHexString().toLowerCase(Locale.ROOT))) {
        addReason(reasons, candidate.pathId(), reason("TARGETED_TRIE_KEY", Map.of("trie_key", candidate.entry().key().toHexString())));
      }
    }
    final List<Candidate> sample = new ArrayList<>(ordered);
    sample.sort(Comparator.comparing(candidate -> sampleDigest(hashVariant, chainIdentity, blockNumber, stateRoot, candidate.entry().key().toHexString())));
    for (int i = 0; i < Math.min(config.sampleSize(), sample.size()); i++) {
      final Candidate candidate = sample.get(i);
      addReason(reasons, candidate.pathId(), reason("DETERMINISTIC_SAMPLE", Map.of("rank", i + 1, "sample_size", config.sampleSize())));
    }
    final Map<String, Integer> indexCounts = new LinkedHashMap<>();
    final Map<String, List<String>> percentileIds = new LinkedHashMap<>();
    for (final String metric : METRICS) {
      final SortedIndex sorted = indexWriters.getOrDefault(metric, new IndexWriter(indexDirectory.resolve(metric + ".chunks"), config.metricIndexChunkSize())).finish(indexDirectory.resolve(metric + ".jsonl"));
      indexCounts.put(metric, sorted.count());
      for (final Percentile percentile : PERCENTILES) {
        if (sorted.count() == 0) continue;
        final int rank = Math.max(1, (int) Math.ceil(percentile.value() * sorted.count()));
        final IndexEntry selected = sorted.entryAt(rank);
        percentileIds.computeIfAbsent(metric, ignored -> new ArrayList<>()).add(selected.pathId());
        addReason(
            reasons,
            selected.pathId(),
            reason(
                "PERCENTILE",
                Map.of(
                    "metric", metric,
                    "percentile", percentile.name(),
                    "rank", rank,
                    "population", sorted.count(),
                    "value", selected.value())));
      }
    }
    final List<Map<String, Object>> retained = new ArrayList<>();
    for (final Candidate candidate : ordered) {
      final List<Map<String, Object>> selectedReasons = reasons.get(candidate.pathId());
      if (selectedReasons == null) continue;
      retained.add(retainedRecord(runId, stateId, blockNumber, stateRoot, candidate, selectedReasons, true));
    }
    return new Result(
        retained,
        candidates,
        indexCounts,
        percentileIds,
        signatures.size(),
        ordered.size(),
        (int) ordered.stream().filter(candidate -> reasons.containsKey(candidate.pathId())).count(),
        reasons.values().stream().mapToInt(List::size).sum(),
        Files.exists(indexDirectory),
        reasons,
        SAMPLING_SCHEME_VERSION,
        SAMPLING_DOMAIN_DEFINITION,
        samplingDomainDigest(hashVariant, chainIdentity, blockNumber, stateRoot));
  }

  public static Map<String, Object> retainedRecord(
      final String runId,
      final String stateId,
      final long blockNumber,
      final Bytes stateRoot,
      final Candidate candidate,
      final List<Map<String, Object>> reasons,
      final boolean immediateOrPass2) {
    return retainedRecord(runId, stateId, blockNumber, stateRoot, candidate, candidate.entry().authenticatedPath(), reasons, immediateOrPass2);
  }

  public static Map<String, Object> retainedRecord(
      final String runId,
      final String stateId,
      final long blockNumber,
      final Bytes stateRoot,
      final Candidate candidate,
      final AccountPathResult path,
      final List<Map<String, Object>> reasons,
      final boolean immediateOrPass2) {
    final Map<String, Object> record = new LinkedHashMap<>(candidate.summary());
    record.put("schema_version", AuditRunSchema.RETAINED_FRAGMENT_SCHEMA_V2);
    record.put("run_id", runId);
    record.put("state_id", stateId);
    record.put("block_number", blockNumber);
    record.put("state_root", stateRoot.toHexString());
    record.put("attempt_number", 0);
    record.put("retention_reasons", reasons);
    record.put("structural_signature", candidate.signature());
    record.put("terminal_form", path.steps().isEmpty() ? "NONE" : normalizeNodeType(path.steps().get(path.steps().size() - 1).nodeType()));
    record.put("selection_pass", immediateOrPass2 ? "PASS_1_OR_PASS_2" : "PASS_2");
    record.put("terminal_account_value_digest", digest(candidate.entry().accountValue()));
    record.put("full_ordered_steps", path.steps().stream().map(Phase4DRetention::stepRecord).toList());
    return record;
  }

  public static String signature(final AccountPathResult path) {
    final StringBuilder value = new StringBuilder();
    value.append(path.proofNodeCount()).append('|');
    for (final AccountPathStep step : path.steps()) {
      value.append(step.nodeType()).append(':')
          .append(step.incomingReference()).append(':')
          .append(step.outgoingReference()).append(':')
          .append(step.compactPathKind()).append(':')
          .append(step.compactPathNibbleLength()).append('|');
    }
    return digest(value.toString().getBytes(StandardCharsets.UTF_8));
  }

  private static Map<String, Object> stepRecord(final AccountPathStep step) {
    final Map<String, Object> record = new LinkedHashMap<>();
    record.put("step_index", step.nodeIndex());
    record.put("node_type", step.nodeType());
    record.put("incoming_reference", step.incomingReference());
    record.put("outgoing_reference", step.outgoingReference());
    record.put("consumed_nibbles_before", step.consumedNibblesBefore());
    record.put("consumed_nibbles_by_node", step.consumedNibblesByNode());
    record.put("consumed_nibbles_after", step.consumedNibblesAfter());
    record.put("remaining_nibbles", step.remainingNibbles());
    record.put("compact_path_kind", step.compactPathKind());
    record.put("compact_path_odd", step.compactPathOdd());
    record.put("compact_path_nibble_length", step.compactPathNibbleLength());
    record.put("encoded_rlp_length", step.encodedRlpLength());
    if (!step.encodedNodeRlp().isEmpty()) {
      record.put("encoded_node_rlp", step.encodedNodeRlp().toHexString().toLowerCase(Locale.ROOT));
      record.put("encoded_node_rlp_length", step.encodedNodeRlp().size());
    }
    record.put("terminal", step.terminal());
    return record;
  }

  private static int metricValue(final String metric, final AccountPathResult path) {
    return switch (metric) {
      case "proof_node_count" -> path.proofNodeCount();
      case "total_proof_rlp_bytes" -> path.totalProofRlpBytes();
      case "maximum_node_rlp_bytes" -> path.steps().stream().mapToInt(AccountPathStep::encodedRlpLength).max().orElse(0);
      case "extension_node_count" -> (int) path.steps().stream().filter(step -> step.nodeType().toUpperCase(Locale.ROOT).contains("EXTENSION")).count();
      case "inline_reference_count" -> (int) path.steps().stream().filter(step -> "INLINE".equals(step.outgoingReference())).count();
      default -> throw new IllegalArgumentException("Unknown metric: " + metric);
    };
  }

  private static String normalizeNodeType(final String type) {
    return type.endsWith("Node") ? type.substring(0, type.length() - 4).toUpperCase(Locale.ROOT) : type.toUpperCase(Locale.ROOT);
  }

  private static String indexLine(final IndexEntry entry) {
    return INDEX_SCHEMA + "|" + entry.stateId() + "|" + entry.metric() + "|" + entry.value() + "|" + entry.pathId() + "|" + entry.trieKey() + "|" + entry.sourceSummaryIdentity();
  }

  private static IndexEntry parseIndexLine(final String line) {
    final String[] fields = line.split("\\|", -1);
    if (fields.length != 7 || !INDEX_SCHEMA.equals(fields[0])) throw new IllegalArgumentException("Invalid metric index record");
    return new IndexEntry(fields[1], fields[2], Integer.parseInt(fields[3]), fields[4], fields[5], fields[6]);
  }

  private static final class IndexWriter {
    private final Path chunkDirectory;
    private final int chunkSize;
    private final List<IndexEntry> buffer = new ArrayList<>();
    private final List<Path> chunks = new ArrayList<>();

    private IndexWriter(final Path chunkDirectory, final int chunkSize) {
      this.chunkDirectory = chunkDirectory;
      this.chunkSize = chunkSize;
    }

    private void add(final IndexEntry entry) throws IOException {
      Files.createDirectories(chunkDirectory);
      buffer.add(entry);
      if (buffer.size() == chunkSize) flushChunk();
    }

    private void flushChunk() throws IOException {
      if (buffer.isEmpty()) return;
      buffer.sort(IndexEntry.ORDER);
      final Path chunk = chunkDirectory.resolve(String.format("chunk-%05d", chunks.size()));
      Files.write(chunk, buffer.stream().map(Phase4DRetention::indexLine).toList(), StandardCharsets.UTF_8);
      chunks.add(chunk);
      buffer.clear();
    }

    private SortedIndex finish(final Path output) throws IOException {
      flushChunk();
      if (chunks.isEmpty()) {
        Files.writeString(output, "", StandardCharsets.UTF_8);
        return new SortedIndex(output, 0);
      }
      final List<ChunkCursor> cursors = new ArrayList<>();
      final PriorityQueue<ChunkCursor> queue = new PriorityQueue<>(Comparator.comparing(ChunkCursor::current, IndexEntry.ORDER));
      for (final Path chunk : chunks) {
        final ChunkCursor cursor = new ChunkCursor(chunk);
        if (cursor.current() != null) {
          cursors.add(cursor);
          queue.add(cursor);
        }
      }
      int count = 0;
      try (BufferedWriter writer = Files.newBufferedWriter(output, StandardCharsets.UTF_8)) {
        while (!queue.isEmpty()) {
          final ChunkCursor cursor = queue.remove();
          writer.write(indexLine(cursor.current()));
          writer.newLine();
          count++;
          cursor.advance();
          if (cursor.current() != null) queue.add(cursor);
        }
      } finally {
        for (final ChunkCursor cursor : cursors) cursor.close();
        for (final Path chunk : chunks) Files.deleteIfExists(chunk);
        Files.deleteIfExists(chunkDirectory);
      }
      return new SortedIndex(output, count);
    }
  }

  private static final class ChunkCursor implements AutoCloseable {
    private final BufferedReader reader;
    private IndexEntry current;

    private ChunkCursor(final Path path) throws IOException {
      reader = Files.newBufferedReader(path, StandardCharsets.UTF_8);
      advance();
    }

    private IndexEntry current() { return current; }

    private void advance() throws IOException {
      final String line = reader.readLine();
      current = line == null ? null : parseIndexLine(line);
    }

    @Override
    public void close() throws IOException { reader.close(); }
  }

  private record SortedIndex(Path path, int count) {
    private IndexEntry entryAt(final int oneBasedRank) throws IOException {
      try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
        for (int index = 1; index <= oneBasedRank; index++) {
          final String line = reader.readLine();
          if (line == null) throw new EOFException("Metric index ended before selected rank");
          if (index == oneBasedRank) return parseIndexLine(line);
        }
      }
      throw new EOFException("Metric index selection failed");
    }
  }

  private static Map<String, Object> reason(final String type, final Map<String, Object> metadata) {
    final Map<String, Object> reason = new TreeMap<>();
    reason.put("reason", type);
    reason.putAll(metadata);
    return reason;
  }

  private static void addReason(final Map<String, List<Map<String, Object>>> reasons, final String pathId, final Map<String, Object> reason) {
    reasons.computeIfAbsent(pathId, ignored -> new ArrayList<>()).add(reason);
    reasons.get(pathId).sort(Comparator.comparing(item -> (String) item.get("reason")));
  }

  private static String sampleDigest(
      final String hashVariant,
      final String chainIdentity,
      final long blockNumber,
      final Bytes stateRoot,
      final String key) {
    return digest(canonicalDomain(hashVariant, chainIdentity, blockNumber, stateRoot, key).getBytes(StandardCharsets.UTF_8));
  }

  private static String canonicalDomain(
      final String hashVariant,
      final String chainIdentity,
      final long blockNumber,
      final Bytes stateRoot,
      final String key) {
    return SAMPLING_SCHEME_VERSION
        + "|" + hashVariant
        + "|" + chainIdentity
        + "|" + blockNumber
        + "|" + stateRoot.toHexString().toLowerCase(Locale.ROOT)
        + "|" + key.toLowerCase(Locale.ROOT);
  }

  private static String samplingDomainDigest(
      final String hashVariant,
      final String chainIdentity,
      final long blockNumber,
      final Bytes stateRoot) {
    return digest(canonicalDomain(hashVariant, chainIdentity, blockNumber, stateRoot, "").getBytes(StandardCharsets.UTF_8));
  }

  public static String digest(final Bytes value) {
    return digest(value.toArrayUnsafe());
  }

  private static String digest(final byte[] value) {
    try {
      final MessageDigest digest = MessageDigestFactory.create(MessageDigestFactory.SHA256_ALG);
      return bytesToHex(digest.digest(value));
    } catch (final NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String bytesToHex(final byte[] bytes) {
    final StringBuilder result = new StringBuilder(bytes.length * 2);
    for (final byte value : bytes) result.append(String.format("%02x", value));
    return result.toString();
  }

  public record Config(int sampleSize, Set<String> targetedKeys, int metricIndexChunkSize) {
    public Config(final int sampleSize, final Set<String> targetedKeys) {
      this(sampleSize, targetedKeys, 256);
    }

    public Config(final int sampleSize, final Set<String> targetedKeys, final int metricIndexChunkSize) {
      if (sampleSize < 0) throw new IllegalArgumentException("sampleSize must be non-negative");
      if (metricIndexChunkSize <= 0) throw new IllegalArgumentException("metricIndexChunkSize must be positive");
      this.sampleSize = sampleSize;
      this.targetedKeys = Set.copyOf(targetedKeys);
      this.metricIndexChunkSize = metricIndexChunkSize;
    }

    public static Config defaults() {
      return new Config(10, Set.of());
    }
  }

  public record Candidate(AccountEnumerationEntry entry, String pathId, Map<String, Object> summary, String signature) {
    public Candidate(
        final AccountEnumerationEntry entry,
        final String pathId,
        final Map<String, Object> summary,
        final String signature) {
      this.entry = entry;
      this.pathId = pathId;
      this.summary = Map.copyOf(summary);
      this.signature = signature;
    }
  }

  public record IndexEntry(String stateId, String metric, int value, String pathId, String trieKey, String sourceSummaryIdentity) {
    static final Comparator<IndexEntry> ORDER = Comparator.comparingInt(IndexEntry::value).thenComparing(IndexEntry::pathId).thenComparing(IndexEntry::trieKey);
  }

  public record Percentile(String name, double value) {}

  public record Result(
      List<Map<String, Object>> retainedRecords,
      Map<String, Candidate> candidates,
      Map<String, Integer> indexRecordCounts,
      Map<String, List<String>> selectedPercentilePathIds,
      int structuralSignatureCount,
      int enumeratedCount,
      int uniqueRetainedCount,
      int retainedReasonCount,
      boolean indexesWritten,
      Map<String, List<Map<String, Object>>> reasons,
      String samplingSchemeVersion,
      String samplingDomainDefinition,
      String samplingDomainDigest) {}
}
