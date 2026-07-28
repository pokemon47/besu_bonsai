/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.hyperledger.besu.crypto.MessageDigestFactory;
import java.security.NoSuchAlgorithmException;

/** Deterministic Phase 4E baseline and adaptive schedule construction. */
public final class Phase4ESchedule {
  private Phase4ESchedule() {}

  public static List<Event> baseline(final Config config) {
    final Set<Long> blocks = new HashSet<>();
    addIfInRange(blocks, 0, config.effectiveMaxBlock());
    for (long block = 0; block <= Math.min(4999, config.effectiveMaxBlock()); block += 500) {
      addIfInRange(blocks, block, config.effectiveMaxBlock());
    }
    for (long block = 5000; block <= Math.min(19999, config.effectiveMaxBlock()); block += 250) {
      addIfInRange(blocks, block, config.effectiveMaxBlock());
    }
    for (long block = 20000; block <= Math.min(25000, config.effectiveMaxBlock()); block += 50) {
      addIfInRange(blocks, block, config.effectiveMaxBlock());
    }
    addIfInRange(blocks, config.effectiveMaxBlock(), config.effectiveMaxBlock());
    config.mandatoryBoundaries().forEach(block -> addIfInRange(blocks, block, config.effectiveMaxBlock()));
    config.explicitTargets().forEach(block -> addIfInRange(blocks, block, config.effectiveMaxBlock()));
    final List<Event> events = new ArrayList<>();
    for (long block : blocks) {
      final Type type = config.explicitTargets().contains(block) ? Type.EXPLICIT_TARGET
          : config.mandatoryBoundaries().contains(block) ? Type.MANDATORY_BOUNDARY : Type.BASELINE;
      events.add(Event.create(config.runId(), block, type, type.name(), null, null, 0, events.size() + 1));
    }
    for (long boundary : config.mandatoryBoundaries()) {
      if (boundary - 1 >= 0 && boundary - 1 <= config.effectiveMaxBlock()) {
        events.add(Event.create(config.runId(), boundary - 1, Type.BOUNDARY_NEIGHBOR, "boundary_neighbor", boundary, "boundary", 0, 0));
      }
      if (boundary + 1 <= config.effectiveMaxBlock()) {
        events.add(Event.create(config.runId(), boundary + 1, Type.BOUNDARY_NEIGHBOR, "boundary_neighbor", boundary, "boundary", 0, 0));
      }
    }
    events.sort(Comparator.comparingLong(Event::blockNumber).thenComparing(Event::eventId));
    return resequence(events);
  }

  public static List<Event> neighbors(
      final Config config, final Event parent, final Type type, final String reason, final String trigger) {
    final List<Event> result = new ArrayList<>();
    for (long block : List.of(parent.blockNumber() - 1, parent.blockNumber() + 1)) {
      if (block >= 0 && block <= config.effectiveMaxBlock()) {
        result.add(Event.create(config.runId(), block, type, reason, parent.blockNumber(), trigger,
            parent.refinementDepth() + 1, 0));
      }
    }
    return result;
  }

  private static List<Event> resequence(final List<Event> events) {
    final List<Event> result = new ArrayList<>();
    long sequence = 1;
    for (Event event : events) result.add(event.withCreationSequence(sequence++));
    return result;
  }

  private static void addIfInRange(final Set<Long> blocks, final long block, final long max) {
    if (block >= 0 && block <= max) blocks.add(block);
  }

  public record Config(
      String runId,
      long configuredTargetMaxBlock,
      long availableCanonicalHeight,
      Set<Long> mandatoryBoundaries,
      Set<Long> explicitTargets,
      int maximumRefinementDepth,
      int maximumAdaptiveAdditions) {
    public static Config defaults(final String runId, final long configuredTargetMaxBlock, final long availableCanonicalHeight) {
      final Config provisional = new Config(runId, configuredTargetMaxBlock, availableCanonicalHeight, Set.of(), Set.of(), 2, 20);
      return new Config(runId, configuredTargetMaxBlock, availableCanonicalHeight, Set.of(), Set.of(), 2,
          derivedAdaptiveAdditions(baseline(provisional).size()));
    }

    public static int derivedAdaptiveAdditions(final int baselineStateCount) {
      return Math.max(20, (int) Math.ceil(0.25 * baselineStateCount));
    }

    public static int rlpThreshold(final int previousMaximum) {
      if (previousMaximum <= 0) return 0;
      return (int) (((long) previousMaximum * 110L + 99L) / 100L);
    }

    public static boolean rlpOutlier(final int previousMaximum, final int currentMaximum) {
      return previousMaximum > 0 && currentMaximum >= rlpThreshold(previousMaximum);
    }
    public Config(
        final String runId,
        final long configuredTargetMaxBlock,
        final long availableCanonicalHeight,
        final Set<Long> mandatoryBoundaries,
        final Set<Long> explicitTargets,
        final int maximumRefinementDepth,
        final int maximumAdaptiveAdditions) {
      if (configuredTargetMaxBlock < 0 || availableCanonicalHeight < 0) throw new IllegalArgumentException("negative ceiling");
      if (maximumRefinementDepth < 0 || maximumAdaptiveAdditions < 0) throw new IllegalArgumentException("negative adaptive limit");
      this.runId = runId;
      this.configuredTargetMaxBlock = configuredTargetMaxBlock;
      this.availableCanonicalHeight = availableCanonicalHeight;
      this.mandatoryBoundaries = Set.copyOf(mandatoryBoundaries);
      this.explicitTargets = Set.copyOf(explicitTargets);
      this.maximumRefinementDepth = maximumRefinementDepth;
      this.maximumAdaptiveAdditions = maximumAdaptiveAdditions;
    }

    public long effectiveMaxBlock() {
      return Math.min(configuredTargetMaxBlock, availableCanonicalHeight);
    }
  }

  public enum Type {
    BASELINE,
    MANDATORY_BOUNDARY,
    EXPLICIT_TARGET,
    BOUNDARY_NEIGHBOR,
    ADAPTIVE_MAXIMUM_NEIGHBOR,
    ADAPTIVE_SIGNATURE_NEIGHBOR,
    ADAPTIVE_RLP_OUTLIER_NEIGHBOR
  }

  public record Event(
      String schemaVersion,
      String eventId,
      String runId,
      long blockNumber,
      Type selectionType,
      String selectionReason,
      Long parentBlock,
      String trigger,
      int refinementDepth,
      long creationSequence,
      String timestamp,
      String selectedStateStatus) {
    static Event create(final String runId, final long block, final Type type, final String reason,
        final Long parent, final String trigger, final int depth, final long sequence) {
      final String id = eventDigest(runId + "|" + block + "|" + type + "|" + depth + "|" + (parent == null ? "" : parent) + "|" + (trigger == null ? "" : trigger));
      return new Event(AuditRunSchema.SCHEDULE_SCHEMA_V1, id, runId, block, type, reason, parent, trigger, depth, sequence, null, "PENDING");
    }

    private static String eventDigest(final String value) {
      try {
        final byte[] digest = MessageDigestFactory.create(MessageDigestFactory.SHA256_ALG).digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        final StringBuilder result = new StringBuilder(16);
        for (int i = 0; i < 8; i++) result.append(String.format("%02x", digest[i]));
        return "event_" + result;
      } catch (NoSuchAlgorithmException failure) {
        throw new IllegalStateException(failure);
      }
    }

    Event withCreationSequence(final long sequence) {
      return new Event(schemaVersion, eventId, runId, blockNumber, selectionType, selectionReason, parentBlock, trigger, refinementDepth, sequence, timestamp, selectedStateStatus);
    }

    public Event withStatus(final String status) {
      return new Event(schemaVersion, eventId, runId, blockNumber, selectionType, selectionReason, parentBlock, trigger, refinementDepth, creationSequence, timestamp, status);
    }
  }
}
