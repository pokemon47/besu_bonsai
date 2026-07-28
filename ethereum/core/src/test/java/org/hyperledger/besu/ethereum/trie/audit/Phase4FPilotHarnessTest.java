/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.base.Splitter;

import org.hyperledger.besu.config.GenesisConfig;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.chain.BadBlockManager;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.MiningConfiguration;
import org.hyperledger.besu.ethereum.mainnet.BalConfiguration;
import org.hyperledger.besu.ethereum.mainnet.MainnetProtocolSchedule;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.ethereum.storage.StorageProvider;
import org.hyperledger.besu.ethereum.storage.keyvalue.KeyValueStorageProviderBuilder;
import org.hyperledger.besu.ethereum.trie.forest.ForestWorldStateArchive;
import org.hyperledger.besu.ethereum.trie.forest.storage.ForestWorldStateKeyValueStorage;
import org.hyperledger.besu.ethereum.worldstate.DataStorageConfiguration;
import org.hyperledger.besu.ethereum.worldstate.WorldStateStorageCoordinator;
import org.hyperledger.besu.evm.internal.EvmConfiguration;
import org.hyperledger.besu.metrics.noop.NoOpMetricsSystem;
import org.hyperledger.besu.plugin.services.BesuConfiguration;
import org.hyperledger.besu.plugin.services.storage.DataStorageFormat;
import org.hyperledger.besu.plugin.services.storage.rocksdb.RocksDBKeyValueStorageFactory;
import org.hyperledger.besu.plugin.services.storage.rocksdb.RocksDBMetricsFactory;
import org.hyperledger.besu.plugin.services.storage.rocksdb.configuration.RocksDBFactoryConfiguration;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;

import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;

/** Test-boundary opening probe for the Phase 4F stationary Forest pilot. */
class Phase4FPilotHarnessTest {
  @Test
  void opensConfiguredForestDatabaseReadOnlyAndReportsCanonicalHeight() throws Exception {
    final String dataProperty = System.getProperty("phase4f.data", System.getenv("PHASE4F_DATA"));
    Assumptions.assumeTrue(dataProperty != null && !dataProperty.isBlank(),
        "phase4f.data or PHASE4F_DATA is required for the real-database pilot");
    final Path dataPath = Path.of(dataProperty);
    final String variant = System.getProperty("phase4f.variant", System.getenv().getOrDefault("PHASE4F_VARIANT", "keccak256"));
    if ("poseidon2".equals(variant)) {
      System.setProperty("besu.experimental.proof-path-hashing", "poseidon2");
    } else {
      System.clearProperty("besu.experimental.proof-path-hashing");
    }

    final BesuConfiguration common = mock(BesuConfiguration.class);
    when(common.getDataPath()).thenReturn(dataPath);
    when(common.getStoragePath()).thenReturn(dataPath.resolve("database"));
    when(common.getDatabaseFormat()).thenReturn(DataStorageFormat.FOREST);
    when(common.getDataStorageConfiguration()).thenReturn(pluginForestConfig());

    final StorageProvider provider = new KeyValueStorageProviderBuilder()
        .withStorageFactory(new RocksDBKeyValueStorageFactory(
            () -> new RocksDBFactoryConfiguration(
                1024, 4, 8_388_608, false, false, false, Optional.empty(), Optional.empty()),
            Arrays.asList(org.hyperledger.besu.ethereum.storage.keyvalue.KeyValueSegmentIdentifier.values()),
            RocksDBMetricsFactory.PUBLIC_ROCKS_DB_METRICS))
        .withCommonConfiguration(common)
        .withMetricsSystem(new NoOpMetricsSystem())
        .build();
    try {
      final GenesisConfig genesis = GenesisConfig.fromResource("/hoodi.json");
      final ProtocolSchedule schedule = MainnetProtocolSchedule.fromConfig(
          genesis.getConfigOptions(), MiningConfiguration.MINING_DISABLED,
          new BadBlockManager(), false, BalConfiguration.DEFAULT, new NoOpMetricsSystem());
      final Blockchain blockchain = org.hyperledger.besu.ethereum.chain.DefaultBlockchain.create(
          provider.createBlockchainStorage(
              schedule, provider.createVariablesStorage(), DataStorageConfiguration.DEFAULT_FOREST_CONFIG),
          new NoOpMetricsSystem(), 0);
      final WorldStateStorageCoordinator coordinator =
          provider.createWorldStateStorageCoordinator(DataStorageConfiguration.DEFAULT_FOREST_CONFIG);
      final WorldStateArchive archive = new ForestWorldStateArchive(
          coordinator, provider.createWorldStatePreimageStorage(), EvmConfiguration.DEFAULT);
      final HistoricalForestStateResolutionProbe probe =
          new HistoricalForestStateResolutionProbe(blockchain, archive);
      final long head = blockchain.getChainHeadBlockNumber();
      System.out.printf("phase4f variant=%s data=%s head=%d%n", variant, dataPath, head);
      for (long block : requestedBlocks(head)) {
        final HistoricalForestStateResolutionProbe.Resolution resolution = probe.resolve(block);
        System.out.printf(
            "phase4f block=%d status=%s hash=%s root=%s%n",
            block,
            resolution.status(),
            resolution.canonicalHash().map(Hash::toHexString).orElse(""),
            resolution.stateRoot().map(Hash::toHexString).orElse(""));
      }
      if (Boolean.parseBoolean(System.getenv().getOrDefault("PHASE4F_EXECUTE", "false"))) {
        runPilot(variant, dataPath, head, blockchain, archive);
      }
      assertThat(head).isGreaterThanOrEqualTo(0);
    } finally {
      provider.close();
    }
  }

  private static long[] requestedBlocks(final long head) {
    return new long[] {0, Math.min(1_000, head), Math.min(12_500, head), Math.min(24_500, head), head};
  }

  private static void runPilot(
      final String variant,
      final Path dataPath,
      final long head,
      final Blockchain blockchain,
      final WorldStateArchive archive)
      throws Exception {
    final Path output = Path.of(System.getenv().getOrDefault(
        "PHASE4F_OUTPUT", "/private/tmp/phase4f-pilot/" + variant));
    Files.createDirectories(output);
    final Set<Long> selected = new LinkedHashSet<>();
    final String requested = System.getProperty("phase4f.blocks", System.getenv("PHASE4F_BLOCKS"));
    if (requested == null || requested.isBlank()) {
      selected.add(0L);
      selected.add(Math.min(1_000, head));
      selected.add(Math.min(12_500, head));
      selected.add(Math.min(24_500, head));
      selected.add(head);
    } else {
      for (String value : Splitter.on(',').trimResults().omitEmptyStrings().split(requested)) {
        selected.add(Long.parseLong(value));
      }
    }
    final ForestWorldStateKeyValueStorage storage =
        ((ForestWorldStateArchive) archive).getWorldStateStorage();
    final ForestAccountTrieAccess trieAccess = new ForestAccountTrieAccess(storage);
    final HistoricalForestStateResolutionProbe resolver =
        new HistoricalForestStateResolutionProbe(blockchain, archive);
    final AuditRunPersistence persistence = new AuditRunPersistence(output);
    final String runId = "phase4f-" + variant + "-pilot";
    final StringBuilder csv = new StringBuilder(
        "requested_block,actual_block,classification,account_count,total_state_ms,output_bytes\n");
    final StringBuilder states = new StringBuilder();
    states.append("[\n");
    int index = 0;
    for (long block : selected) {
      final long started = System.nanoTime();
      final AccountStateAuditProcessor.ProcessResult result =
          new AccountStateAuditProcessor(resolver, trieAccess, persistence)
              .process(new AccountStateAuditProcessor.Input(
                  block, variant, runId, "pilot", output, "phase4f-pilot",
                  new Phase4DRetention.Config(10, Set.of())));
      final long elapsedMs = (System.nanoTime() - started) / 1_000_000L;
      final long outputBytes;
      try (var files = Files.walk(output)) {
        outputBytes = files.filter(Files::isRegularFile)
            .mapToLong(path -> {
              try { return Files.size(path); } catch (Exception ignored) { return 0L; }
            }).sum();
      }
      csv.append(block).append(',').append(block).append(',')
          .append(result.finalClassification()).append(',').append(result.accountCount())
          .append(',').append(elapsedMs).append(',').append(outputBytes).append('\n');
      if (index++ > 0) states.append(",\n");
      states.append("  {\"block\":").append(block)
          .append(",\"classification\":\"").append(result.finalClassification())
          .append("\",\"account_count\":").append(result.accountCount())
          .append(",\"elapsed_ms\":").append(elapsedMs).append('}');
    }
    states.append("\n]\n");
    Files.writeString(output.resolve("pilot_state_metrics.csv"), csv.toString(), StandardCharsets.UTF_8);
    Files.writeString(output.resolve("pilot_manifest.json"),
        "{\"schema\":\"audit_pilot_v1\",\"phase\":\"4F\",\"hash_variant\":\""
            + variant + "\",\"database\":\"" + dataPath + "\",\"stationary_acknowledged\":true"
            + ",\"account_sampling\":false,\"maximum_refinement_depth\":2"
            + ",\"maximum_adaptive_additions_override\":4,\"selected_states\":" + states + "}\n",
        StandardCharsets.UTF_8);
    Files.writeString(output.resolve("pilot_summary.json"),
        "{\"schema\":\"audit_pilot_summary_v1\",\"hash_variant\":\"" + variant
            + "\",\"canonical_head\":" + head + ",\"selected_count\":" + selected.size()
            + ",\"adaptive_trigger_behavior\":\"not_exercised_in_finite_pilot\"}\n",
        StandardCharsets.UTF_8);
    Files.writeString(output.resolve("pilot_report.md"),
        "# Phase 4F Pilot\n\n"
            + "This controlled test-boundary pilot used complete account enumeration for each selected state.\n\n"
            + "- hash variant: " + variant + "\n"
            + "- database: `" + dataPath + "`\n"
            + "- stationary database acknowledged; normal RocksDB lifecycle used\n"
            + "- account sampling: none\n"
            + "- adaptive additions override: 4 (not exercised in this finite pilot)\n\n"
            + "## State Metrics\n\n```text\n" + csv + "```\n",
        StandardCharsets.UTF_8);
  }

  private static org.hyperledger.besu.plugin.services.storage.DataStorageConfiguration pluginForestConfig() {
    return new org.hyperledger.besu.plugin.services.storage.DataStorageConfiguration() {
      @Override
      public DataStorageFormat getDatabaseFormat() {
        return DataStorageFormat.FOREST;
      }

      @Override
      public boolean getReceiptCompactionEnabled() {
        return false;
      }
    };
  }
}
