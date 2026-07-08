/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.ethereum.trie.pathbased.bonsai.worldview;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hyperledger.besu.ethereum.trie.pathbased.common.worldview.WorldStateConfig.createStatefulConfigWithTrie;
import static org.mockito.Mockito.mock;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.InMemoryKeyValueStorageProvider;
import org.hyperledger.besu.ethereum.proof.hashing.KeccakProofPathHashing;
import org.hyperledger.besu.ethereum.proof.hashing.Poseidon2ProofPathHashing;
import org.hyperledger.besu.ethereum.proof.hashing.ProofPathHashingHolder;
import org.hyperledger.besu.ethereum.trie.pathbased.bonsai.BonsaiAccount;
import org.hyperledger.besu.ethereum.trie.pathbased.bonsai.BonsaiWorldStateProvider;
import org.hyperledger.besu.ethereum.trie.pathbased.bonsai.cache.CodeCache;
import org.hyperledger.besu.ethereum.trie.pathbased.bonsai.storage.BonsaiWorldStateKeyValueStorage;
import org.hyperledger.besu.ethereum.trie.pathbased.common.PathBasedValue;
import org.hyperledger.besu.ethereum.worldstate.DataStorageConfiguration;
import org.hyperledger.besu.evm.account.Account;
import org.hyperledger.besu.evm.internal.EvmConfiguration;
import org.hyperledger.besu.evm.worldstate.UpdateTrackingAccount;
import org.hyperledger.besu.evm.worldstate.WorldUpdater;
import org.hyperledger.besu.metrics.noop.NoOpMetricsSystem;

import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class StackedNewAccountProofPathHashingTest {

  private static final Address NEW_ACCOUNT =
      Address.fromHexString("0x2222222222222222222222222222222222222222");
  private static final Wei INITIAL_BALANCE = Wei.of(1);

  private final Blockchain blockchain = mock(Blockchain.class);
  private BonsaiWorldState worldState;

  @BeforeEach
  void setUp() {
    ProofPathHashingHolder.set(new KeccakProofPathHashing());
  }

  @AfterEach
  void tearDown() {
    ProofPathHashingHolder.set(new KeccakProofPathHashing());
  }

  private BonsaiWorldState createWorldState() {
    final InMemoryKeyValueStorageProvider provider = new InMemoryKeyValueStorageProvider();
    final BonsaiWorldStateProvider archive =
        InMemoryKeyValueStorageProvider.createBonsaiInMemoryWorldStateArchive(blockchain);
    return new BonsaiWorldState(
        archive,
        new BonsaiWorldStateKeyValueStorage(
            provider, new NoOpMetricsSystem(), DataStorageConfiguration.DEFAULT_BONSAI_CONFIG),
        EvmConfiguration.DEFAULT,
        createStatefulConfigWithTrie(),
        new CodeCache());
  }

  private void persistStackedChanges(final BonsaiWorldStateUpdateAccumulator blockAccumulator) {
    worldState.calculateRootHash(
        Optional.of(worldState.getWorldStateStorage().updater()), blockAccumulator);
    worldState.persist(null);
  }

  @Test
  void stackedNewAccountUsesProofPathPolicyWhenPoseidon2Configured() {
    ProofPathHashingHolder.set(new Poseidon2ProofPathHashing());
    worldState = createWorldState();

    final BonsaiWorldStateUpdateAccumulator blockAccumulator =
        commitStackedNewAccountThroughBlockAccumulator();

    final Hash policyKey = ProofPathHashingHolder.get().accountTrieKey(NEW_ACCOUNT);
    final Hash keccakKey = NEW_ACCOUNT.addressHash();
    assertThat(policyKey).isNotEqualTo(keccakKey);

    final BonsaiAccount account =
        blockAccumulator.getAccountsToUpdate().get(NEW_ACCOUNT).getUpdated();
    assertThat(account.getAddressHash()).isEqualTo(policyKey);
    assertThat(account.getAddressHash()).isNotEqualTo(keccakKey);

    persistStackedChanges(blockAccumulator);
    final Account persistedAccount = worldState.get(NEW_ACCOUNT);
    assertThat(persistedAccount).isNotNull();
    assertThat(persistedAccount.getBalance()).isEqualTo(INITIAL_BALANCE);
  }

  @Test
  void stackedNewAccountPreservesKeccakWhenKeccakPolicyConfigured() {
    worldState = createWorldState();

    final BonsaiWorldStateUpdateAccumulator blockAccumulator =
        commitStackedNewAccountThroughBlockAccumulator();

    final BonsaiAccount account =
        blockAccumulator.getAccountsToUpdate().get(NEW_ACCOUNT).getUpdated();
    assertThat(account.getAddressHash()).isEqualTo(NEW_ACCOUNT.addressHash());
    assertThat(account.getAddressHash())
        .isEqualTo(ProofPathHashingHolder.get().accountTrieKey(NEW_ACCOUNT));

    persistStackedChanges(blockAccumulator);
    final Account persistedAccount = worldState.get(NEW_ACCOUNT);
    assertThat(persistedAccount).isNotNull();
    assertThat(persistedAccount.getBalance()).isEqualTo(INITIAL_BALANCE);
  }

  private BonsaiWorldStateUpdateAccumulator commitStackedNewAccountThroughBlockAccumulator() {
    final BonsaiWorldStateUpdateAccumulator blockAccumulator =
        (BonsaiWorldStateUpdateAccumulator) worldState.updater();
    final WorldUpdater txUpdater = blockAccumulator.updater();

    txUpdater.createAccount(NEW_ACCOUNT, 0, INITIAL_BALANCE);
    txUpdater.commit();

    final UpdateTrackingAccount<?> trackedAfterTxCommit =
        blockAccumulator.getUpdatedAccounts().stream()
            .filter(account -> account.getAddress().equals(NEW_ACCOUNT))
            .findFirst()
            .orElseThrow();
    assertThat(trackedAfterTxCommit.getWrappedAccount()).isNull();

    blockAccumulator.commit();

    final PathBasedValue<BonsaiAccount> accountUpdate =
        blockAccumulator.getAccountsToUpdate().get(NEW_ACCOUNT);
    assertThat(accountUpdate).isNotNull();
    assertThat(accountUpdate.getUpdated()).isNotNull();

    return blockAccumulator;
  }
}
