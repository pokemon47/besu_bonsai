/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import java.io.BufferedWriter;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Optional, bounded-overhead timing and progress evidence for the Phase 4F pilot. */
public final class Phase4FDiagnostics implements AutoCloseable {
  private static final String ENABLED_PROPERTY = "phase4f.diagnostics";
  private static final long PROGRESS_INTERVAL_NANOS = 30_000_000_000L;
  private static final int ACCOUNT_INTERVAL = 1_000;

  private final Path output;
  private final long startedNanos = System.nanoTime();
  private final long startedCpuNanos = cpuNanos();
  private final List<Map<String, Object>> progress = new ArrayList<>();
  private final Map<String, Long> stageNanos = new LinkedHashMap<>();
  private final Map<String, Integer> operationCounts = new LinkedHashMap<>();
  private boolean closed;
  private String currentStage = "startup";
  private long stageStartedNanos = startedNanos;
  private long enumerated;
  private long authenticated;
  private long nextProgressAccount = ACCOUNT_INTERVAL;
  private long lastProgressNanos = startedNanos;
  private long progressEventCount;

  private Phase4FDiagnostics(final Path output) {
    this.output = output;
    if (output != null) Runtime.getRuntime().addShutdownHook(new Thread(this::close, "phase4f-diagnostics-shutdown"));
  }

  public static Phase4FDiagnostics open(final Path runDirectory, final long blockNumber) throws IOException {
    if (!Boolean.getBoolean(ENABLED_PROPERTY)) return new Phase4FDiagnostics(null);
    final Path directory = runDirectory.resolve("diagnostics").resolve("block-" + blockNumber);
    Files.createDirectories(directory);
    return new Phase4FDiagnostics(directory);
  }

  public void stage(final String name) {
    if (output == null) return;
    final long now = System.nanoTime();
    stageNanos.merge(currentStage, now - stageStartedNanos, Long::sum);
    currentStage = name;
    stageStartedNanos = now;
    operationCounts.merge(name, 1, Integer::sum);
  }

  public void countOperation(final String name) {
    if (output != null) operationCounts.merge(name, 1, Integer::sum);
  }

  public void enumerated() {
    if (output == null) return;
    enumerated++;
    progressIfDue();
  }

  public void authenticated() {
    if (output == null) return;
    authenticated++;
    progressIfDue();
  }

  public void progressIfDue() {
    if (output == null) return;
    final long now = System.nanoTime();
    if (enumerated < nextProgressAccount && now - lastProgressNanos < PROGRESS_INTERVAL_NANOS) return;
    progress.add(snapshot(now));
    progressEventCount++;
    nextProgressAccount = ((enumerated / ACCOUNT_INTERVAL) + 1) * ACCOUNT_INTERVAL;
    lastProgressNanos = now;
    if (progressEventCount % 4 == 0) writeProgress();
  }

  public void writeProgress() {
    if (output == null) return;
    final Path file = output.resolve("progress.jsonl");
    try (BufferedWriter writer = Files.newBufferedWriter(
        file, StandardCharsets.UTF_8, Files.exists(file)
            ? new java.nio.file.OpenOption[] {java.nio.file.StandardOpenOption.APPEND}
            : new java.nio.file.OpenOption[] {java.nio.file.StandardOpenOption.CREATE})) {
      for (Map<String, Object> event : progress) {
        writer.write(toJson(event));
        writer.newLine();
      }
      progress.clear();
    } catch (IOException failure) {
      throw new IllegalStateException("Unable to write Phase 4F progress", failure);
    }
  }

  private Map<String, Object> snapshot(final long now) {
    final Map<String, Object> event = new LinkedHashMap<>();
    event.put("elapsed_ms", (now - startedNanos) / 1_000_000L);
    event.put("cpu_ms", (cpuNanos() - startedCpuNanos) / 1_000_000L);
    event.put("accounts_enumerated", enumerated);
    event.put("accounts_authenticated", authenticated);
    event.put("heap_used_bytes", Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory());
    event.put("heap_max_bytes", Runtime.getRuntime().maxMemory());
    event.put("rss_bytes", -1L);
    event.put("rss_note", "JVM test boundary does not expose process RSS");
    event.put("bytes_written", outputBytes());
    event.put("accounts_per_second", (now == startedNanos) ? 0.0 : enumerated * 1_000_000_000.0 / (now - startedNanos));
    return event;
  }

  private long outputBytes() {
    try (var paths = Files.walk(output)) {
      return paths.filter(Files::isRegularFile).mapToLong(path -> {
        try { return Files.size(path); } catch (IOException ignored) { return 0L; }
      }).sum();
    } catch (IOException ignored) {
      return -1L;
    }
  }

  @Override
  public synchronized void close() {
    if (output == null || closed) return;
    closed = true;
    final long now = System.nanoTime();
    stageNanos.merge(currentStage, now - stageStartedNanos, Long::sum);
    progressIfDue();
    writeProgress();
    final Map<String, Object> summary = new LinkedHashMap<>();
    summary.put("schema", "phase4f_diagnostics_v1");
    summary.put("elapsed_ms", (now - startedNanos) / 1_000_000L);
    final long cpu = cpuNanos();
    summary.put("cpu_ms", cpu > 0L && cpu >= startedCpuNanos ? (cpu - startedCpuNanos) / 1_000_000L : -1L);
    summary.put("accounts_enumerated", enumerated);
    summary.put("accounts_authenticated", authenticated);
    final Map<String, Long> stageMillis = new LinkedHashMap<>();
    stageNanos.forEach((name, nanos) -> stageMillis.put(name, nanos / 1_000_000L));
    summary.put("stage_ms", stageMillis);
    summary.put("operation_counts", operationCounts);
    summary.put("progress_events", progressEventCount);
    try {
      Files.writeString(output.resolve("summary.json"), toJson(summary) + "\n", StandardCharsets.UTF_8);
    } catch (IOException failure) {
      throw new IllegalStateException("Unable to write Phase 4F diagnostics", failure);
    }
  }

  private static long cpuNanos() {
    final ThreadMXBean bean = ManagementFactory.getThreadMXBean();
    if (!bean.isCurrentThreadCpuTimeSupported()) return -1L;
    final long value = bean.getCurrentThreadCpuTime();
    return value < 0L ? -1L : value;
  }

  private static String toJson(final Object value) {
    if (value == null) return "null";
    if (value instanceof Number || value instanceof Boolean) return value.toString();
    if (value instanceof Map<?, ?> map) {
      return map.entrySet().stream().map(entry -> quote(String.valueOf(entry.getKey())) + ":" + toJson(entry.getValue()))
          .collect(java.util.stream.Collectors.joining(",", "{", "}"));
    }
    if (value instanceof Iterable<?> iterable) {
      final List<String> values = new ArrayList<>();
      iterable.forEach(item -> values.add(toJson(item)));
      return String.join(",", values).replaceFirst("^", "[") + "]";
    }
    return quote(String.valueOf(value));
  }

  private static String quote(final String value) {
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
  }
}
