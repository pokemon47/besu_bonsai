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

import static org.hyperledger.besu.crypto.Hash.sha256;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.trie.hash.Poseidon2TrieHashFunction;
import org.hyperledger.besu.ethereum.trie.hash.TrieHashFunction;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt256;

/**
 * Placeholder proof-path hashing policy for Poseidon2 mode.
 *
 * <p>Besu currently has no native Poseidon2 primitive in this repository. For phase-4 wiring and
 * replay-prep, this policy intentionally uses SHA-256 as a deterministic non-Keccak hash policy
 * until a real Poseidon2 primitive is introduced.
 */
public final class Poseidon2ProofPathHashing implements ProofPathHashing {
  private static final TrieHashFunction TRIE_HASH_FUNCTION = new Poseidon2TrieHashFunction();

  /** Default constructor. */
  public Poseidon2ProofPathHashing() {}

  @Override
  public Hash accountTrieKey(final Address address) {
    return Hash.wrap(sha256(address));
  }

  @Override
  public Hash storageTrieKey(final UInt256 slotKey) {
    return Hash.wrap(sha256(slotKey));
  }

  @Override
  public Hash proofNodeIdentity(final Bytes encodedProofNodeRlp) {
    return Hash.wrap(sha256(encodedProofNodeRlp));
  }

  @Override
  public TrieHashFunction trieHashFunction() {
    return TRIE_HASH_FUNCTION;
  }
}
