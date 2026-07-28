/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import java.util.stream.Stream;

class Phase4EScheduleTest {
  @TempDir Path tempDirectory;

  @Test
  void baselineCoversRangesBoundariesNeighborsTargetsAndEffectiveCeiling() {
    final Phase4ESchedule.Config config = config(20100, 20100, Set.of(5000L, 20000L), Set.of(1234L, 20000L));
    final List<Phase4ESchedule.Event> events = Phase4ESchedule.baseline(config);
    final Set<Long> blocks = events.stream().map(Phase4ESchedule.Event::blockNumber).collect(java.util.stream.Collectors.toSet());
    assertThat(config.effectiveMaxBlock()).isEqualTo(20100);
    assertThat(blocks).contains(0L, 500L, 5000L, 5250L, 20000L, 20050L, 20100L, 1234L, 4999L, 5001L, 19999L, 20001L);
    assertThat(blocks).allMatch(block -> block >= 0 && block <= config.effectiveMaxBlock());
    assertThat(events.stream().map(Phase4ESchedule.Event::creationSequence).distinct()).hasSize(events.size());
  }

  @Test
  void ceilingTruncatesScheduleAndIncludesBlockZero() {
    final Phase4ESchedule.Config config = config(25000, 503, Set.of(), Set.of());
    final Set<Long> blocks = Phase4ESchedule.baseline(config).stream().map(Phase4ESchedule.Event::blockNumber).collect(java.util.stream.Collectors.toSet());
    assertThat(blocks).contains(0L, 500L).doesNotContain(1000L, 5000L, 25000L);
  }

  @Test
  void fullDefaultCeilingHasExactRangeCountsAndBoundaries() {
    final List<Phase4ESchedule.Event> events = Phase4ESchedule.baseline(config(25000, 25000, Set.of(), Set.of()));
    final Set<Long> blocks = events.stream().map(Phase4ESchedule.Event::blockNumber).collect(java.util.stream.Collectors.toSet());
    assertThat(blocks).hasSize(171).contains(0L, 5000L, 20000L, 25000L);
    assertThat(events.stream().filter(event -> event.selectionType() == Phase4ESchedule.Type.BASELINE).map(Phase4ESchedule.Event::blockNumber).filter(block -> block < 5000).count()).isEqualTo(10);
    assertThat(events.stream().filter(event -> event.selectionType() == Phase4ESchedule.Type.BASELINE).map(Phase4ESchedule.Event::blockNumber).filter(block -> block >= 5000 && block < 20000).count()).isEqualTo(60);
    assertThat(events.stream().filter(event -> event.selectionType() == Phase4ESchedule.Type.BASELINE).map(Phase4ESchedule.Event::blockNumber).filter(block -> block >= 20000).count()).isEqualTo(101);
  }

  @ParameterizedTest(name = "truncated ceiling {0}")
  @MethodSource("truncatedCeilings")
  void truncatedCeilingIncludesEachRangeMaximum(final long ceiling, final long expectedCount) {
    final Set<Long> blocks = Phase4ESchedule.baseline(config(25000, ceiling, Set.of(), Set.of())).stream()
        .map(Phase4ESchedule.Event::blockNumber).collect(java.util.stream.Collectors.toSet());
    assertThat(blocks).contains(ceiling);
    assertThat(blocks).allMatch(block -> block <= ceiling);
    assertThat(blocks).hasSize((int) expectedCount);
  }

  private static Stream<Arguments> truncatedCeilings() {
    return Stream.of(Arguments.of(100L, 2L), Arguments.of(5003L, 12L), Arguments.of(20003L, 72L));
  }

  @Test
  void scheduleJournalIsAppendOnlyDeterministicAndRejectsCorruption() throws Exception {
    final Phase4EScheduleJournal journal = new Phase4EScheduleJournal(tempDirectory);
    final List<Phase4ESchedule.Event> events = Phase4ESchedule.baseline(config(1000, 1000, Set.of(), Set.of()));
    journal.append(List.of(events.get(2), events.get(0), events.get(1)));
    journal.append(List.of(events.get(0)));
    assertThat(journal.readValid("run")).containsExactly(events.get(0), events.get(1), events.get(2));
    Files.writeString(tempDirectory.resolve("schedule.jsonl"), Files.readString(tempDirectory.resolve("schedule.jsonl")) + "{}\n");
    assertThatThrownBy(() -> journal.readValid("run")).isInstanceOf(Exception.class);
  }

  @Test
  void queueUsesPriorityDepthBlockAndEventIdAndDeduplicatesBlocks() {
    final Phase4ESchedule.Event baseline = Phase4ESchedule.Event.create("run", 20, Phase4ESchedule.Type.BASELINE, "baseline", null, null, 0, 1);
    final Phase4ESchedule.Event boundary = Phase4ESchedule.Event.create("run", 20, Phase4ESchedule.Type.MANDATORY_BOUNDARY, "mandatory", null, null, 0, 2);
    final Phase4ESchedule.Event adaptive = Phase4ESchedule.Event.create("run", 19, Phase4ESchedule.Type.ADAPTIVE_MAXIMUM_NEIGHBOR, "adaptive", 20L, "max", 1, 3);
    assertThat(Phase4EStateQueue.order(List.of(baseline, adaptive, boundary))).containsExactly(boundary, adaptive);
    assertThat(Phase4EStateQueue.pending(List.of(baseline, adaptive, boundary), block -> block == 19)).containsExactly(boundary);
  }

  @Test
  void adaptiveNeighborsAreBoundedAndCarryParentAndDepth() {
    final Phase4ESchedule.Config config = config(100, 100, Set.of(), Set.of());
    final Phase4ESchedule.Event parent = Phase4ESchedule.Event.create("run", 50, Phase4ESchedule.Type.BASELINE, "baseline", null, null, 0, 1);
    final List<Phase4ESchedule.Event> neighbors = Phase4ESchedule.neighbors(config, parent, Phase4ESchedule.Type.ADAPTIVE_SIGNATURE_NEIGHBOR, "signature", "sig");
    assertThat(neighbors).extracting(Phase4ESchedule.Event::blockNumber).containsExactlyInAnyOrder(49L, 51L);
    assertThat(neighbors).allSatisfy(event -> {
      assertThat(event.parentBlock()).isEqualTo(50L);
      assertThat(event.refinementDepth()).isEqualTo(1);
    });
  }

  @Test
  void adaptiveDefaultsDeriveFortyThreeForTheStandardBaselineAndAtLeastTwentyForSmallRuns() {
    assertThat(Phase4ESchedule.Config.derivedAdaptiveAdditions(171)).isEqualTo(43);
    assertThat(Phase4ESchedule.Config.derivedAdaptiveAdditions(3)).isEqualTo(20);
    assertThat(Phase4ESchedule.Config.defaults("run", 25000, 25000).maximumAdaptiveAdditions()).isEqualTo(43);
    assertThat(new Phase4ESchedule.Config("run", 25000, 25000, Set.of(), Set.of(), 2, 99).maximumAdaptiveAdditions()).isEqualTo(99);
  }

  @ParameterizedTest(name = "RLP threshold previous={0} current={1}")
  @MethodSource("rlpThresholdCases")
  void rlpOutlierUsesCeilingTenPercentThreshold(final int previous, final int current, final boolean triggers) {
    assertThat(Phase4ESchedule.Config.rlpOutlier(previous, current)).isEqualTo(triggers);
  }

  private static Stream<Arguments> rlpThresholdCases() {
    return Stream.of(
        Arguments.of(0, 1, false),
        Arguments.of(100, 100, false),
        Arguments.of(100, 109, false),
        Arguments.of(100, 110, true),
        Arguments.of(100, 111, true),
        Arguments.of(101, 112, true),
        Arguments.of(101, 111, false));
  }

  @Test
  void phase4EHashPolicyValidationRejectsUnknownOrMismatchedVariant() {
    org.hyperledger.besu.ethereum.proof.hashing.ProofPathHashingHolder.set(new org.hyperledger.besu.ethereum.proof.hashing.KeccakProofPathHashing());
    assertThat(Phase4EHashPolicy.validate("keccak256").trieHashFunctionClass()).contains("Keccak");
    assertThatThrownBy(() -> Phase4EHashPolicy.validate("poseidon2")).isInstanceOf(IllegalStateException.class);
    assertThatThrownBy(() -> Phase4EHashPolicy.validate("unknown")).isInstanceOf(IllegalStateException.class);
  }

  private static Phase4ESchedule.Config config(final long target, final long available, final Set<Long> mandatory, final Set<Long> explicit) {
    return new Phase4ESchedule.Config("run", target, available, mandatory, explicit, 2, 4);
  }
}
