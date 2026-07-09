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
package org.hyperledger.besu.ethereum.proof.hashing;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.ethereum.trie.hash.KeccakTrieHashFunction;
import org.hyperledger.besu.ethereum.trie.hash.Poseidon2TrieHashFunction;
import org.hyperledger.besu.ethereum.trie.hash.TrieHashFunctionHolder;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ProofPathHashingConfiguratorTest {
  @BeforeEach
  void setUp() {
    System.clearProperty(ProofPathHashingConfigurator.PROOF_PATH_HASHING_PROPERTY);
    ProofPathHashingConfigurator.resetForTesting();
    ProofPathHashingHolder.set(new KeccakProofPathHashing());
  }

  @AfterEach
  void tearDown() {
    System.clearProperty(ProofPathHashingConfigurator.PROOF_PATH_HASHING_PROPERTY);
    ProofPathHashingConfigurator.resetForTesting();
    ProofPathHashingHolder.set(new KeccakProofPathHashing());
  }

  @Test
  void defaultsToKeccakWhenPropertyNotSet() {
    ProofPathHashingConfigurator.configureFromSystemProperties();

    assertThat(ProofPathHashingHolder.get()).isInstanceOf(KeccakProofPathHashing.class);
    assertThat(TrieHashFunctionHolder.get()).isInstanceOf(KeccakTrieHashFunction.class);
  }

  @Test
  void installsPoseidon2WhenPropertyRequestsIt() {
    System.setProperty(ProofPathHashingConfigurator.PROOF_PATH_HASHING_PROPERTY, "poseidon2");
    ProofPathHashingConfigurator.configureFromSystemProperties();

    assertThat(ProofPathHashingHolder.get()).isInstanceOf(Poseidon2ProofPathHashing.class);
  }

  @Test
  void synchronizesTrieHashFunctionHolderWhenPoseidon2IsInstalled() {
    System.setProperty(ProofPathHashingConfigurator.PROOF_PATH_HASHING_PROPERTY, "poseidon2");
    ProofPathHashingConfigurator.configureFromSystemProperties();

    assertThat(TrieHashFunctionHolder.get()).isInstanceOf(Poseidon2TrieHashFunction.class);
    assertThat(TrieHashFunctionHolder.get())
        .isEqualTo(ProofPathHashingHolder.get().trieHashFunction());
  }

  @Test
  void canReconfigureAfterResetForTestingClearsTheOneShotGate() {
    System.setProperty(ProofPathHashingConfigurator.PROOF_PATH_HASHING_PROPERTY, "poseidon2");
    ProofPathHashingConfigurator.configureFromSystemProperties();
    assertThat(ProofPathHashingHolder.get()).isInstanceOf(Poseidon2ProofPathHashing.class);

    System.clearProperty(ProofPathHashingConfigurator.PROOF_PATH_HASHING_PROPERTY);
    ProofPathHashingConfigurator.resetForTesting();
    ProofPathHashingHolder.set(new KeccakProofPathHashing());
    ProofPathHashingConfigurator.configureFromSystemProperties();

    assertThat(ProofPathHashingHolder.get()).isInstanceOf(KeccakProofPathHashing.class);
    assertThat(TrieHashFunctionHolder.get()).isInstanceOf(KeccakTrieHashFunction.class);
  }
}
