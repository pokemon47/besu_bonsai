/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/** Deterministic single-threaded Phase 4E state queue. */
public final class Phase4EStateQueue {
  private static final Map<Phase4ESchedule.Type, Integer> PRIORITY = Map.of(
      Phase4ESchedule.Type.MANDATORY_BOUNDARY, 0,
      Phase4ESchedule.Type.EXPLICIT_TARGET, 1,
      Phase4ESchedule.Type.BASELINE, 2,
      Phase4ESchedule.Type.BOUNDARY_NEIGHBOR, 3,
      Phase4ESchedule.Type.ADAPTIVE_MAXIMUM_NEIGHBOR, 4,
      Phase4ESchedule.Type.ADAPTIVE_SIGNATURE_NEIGHBOR, 4,
      Phase4ESchedule.Type.ADAPTIVE_RLP_OUTLIER_NEIGHBOR, 4);

  private Phase4EStateQueue() {}

  public static List<Phase4ESchedule.Event> order(final List<Phase4ESchedule.Event> events) {
    return events.stream().filter(event -> !"SUPPRESSED".equals(event.selectedStateStatus())).collect(Collectors.toMap(
        Phase4ESchedule.Event::blockNumber,
        event -> event,
        (left, right) -> compare().compare(left, right) <= 0 ? left : right))
        .values().stream().sorted(compare()).toList();
  }

  public static List<Phase4ESchedule.Event> pending(
      final List<Phase4ESchedule.Event> events, final Predicate<Long> resolved) {
    return order(events).stream().filter(event -> !resolved.test(event.blockNumber())).toList();
  }

  private static Comparator<Phase4ESchedule.Event> compare() {
    return Comparator.comparingInt((Phase4ESchedule.Event event) -> PRIORITY.get(event.selectionType()))
        .thenComparingInt(Phase4ESchedule.Event::refinementDepth)
        .thenComparingLong(Phase4ESchedule.Event::blockNumber)
        .thenComparing(Phase4ESchedule.Event::eventId);
  }
}
