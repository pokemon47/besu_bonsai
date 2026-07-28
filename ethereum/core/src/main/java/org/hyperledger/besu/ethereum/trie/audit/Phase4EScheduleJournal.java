/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

/** Append-only Phase 4E schedule journal. */
public final class Phase4EScheduleJournal {
  private static final ObjectMapper MAPPER = JsonMapper.builder()
      .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
      .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true).build();
  private final Path journal;

  public Phase4EScheduleJournal(final Path runDirectory) {
    this.journal = runDirectory.resolve("schedule.jsonl");
  }

  public synchronized void append(final List<Phase4ESchedule.Event> events) throws IOException {
    Files.createDirectories(journal.getParent());
    for (Phase4ESchedule.Event event : events) {
      Files.writeString(journal, MAPPER.writeValueAsString(event) + "\n", StandardCharsets.UTF_8,
          StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
    }
  }

  public List<Phase4ESchedule.Event> readValid(final String runId) throws IOException {
    if (!Files.exists(journal)) return List.of();
    final Map<String, Phase4ESchedule.Event> unique = new TreeMap<>();
    for (String line : Files.readAllLines(journal, StandardCharsets.UTF_8)) {
      if (line.isBlank()) continue;
      final Phase4ESchedule.Event event = MAPPER.readValue(line, Phase4ESchedule.Event.class);
      if (!AuditRunSchema.SCHEDULE_SCHEMA_V1.equals(event.schemaVersion()) || !runId.equals(event.runId())) {
        throw new IOException("Invalid Phase 4E schedule event");
      }
      final Phase4ESchedule.Event previous = unique.putIfAbsent(event.eventId(), event);
      if (previous != null && !previous.equals(event)) throw new IOException("Conflicting schedule event " + event.eventId());
    }
    return unique.values().stream().sorted(Comparator.comparingLong(Phase4ESchedule.Event::creationSequence).thenComparing(Phase4ESchedule.Event::eventId)).toList();
  }

  public Set<Long> selectedBlocks(final String runId) throws IOException {
    return readValid(runId).stream().map(Phase4ESchedule.Event::blockNumber).collect(Collectors.toCollection(java.util.TreeSet::new));
  }
}
