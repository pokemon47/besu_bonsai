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

import org.hyperledger.besu.ethereum.trie.hash.TrieHashFunctionHolder;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/** Mutable holder for active proof-path hashing policy. */
public final class ProofPathHashingHolder {
  private static final AtomicReference<ProofPathHashing> ACTIVE =
      new AtomicReference<>(new KeccakProofPathHashing());

  private ProofPathHashingHolder() {}

  /**
   * Returns the active proof-path hashing policy.
   *
   * @return the active proof-path hashing policy
   */
  public static ProofPathHashing get() {
    return ACTIVE.get();
  }

  /**
   * Replaces the active proof-path hashing policy and synchronizes the trie-node hash policy with
   * it.
   *
   * @param hashing the new proof-path hashing policy
   */
  public static void set(final ProofPathHashing hashing) {
    final ProofPathHashing validated = Objects.requireNonNull(hashing);
    ACTIVE.set(validated);
    TrieHashFunctionHolder.set(validated.trieHashFunction());
  }
}
