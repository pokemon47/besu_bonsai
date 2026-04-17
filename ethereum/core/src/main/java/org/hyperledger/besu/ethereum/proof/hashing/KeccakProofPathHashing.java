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

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.trie.hash.KeccakTrieHashFunction;
import org.hyperledger.besu.ethereum.trie.hash.TrieHashFunction;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt256;

/** Default proof-path hashing policy backed by Keccak-based helpers. */
public final class KeccakProofPathHashing implements ProofPathHashing {
  private static final TrieHashFunction TRIE_HASH_FUNCTION = new KeccakTrieHashFunction();

  /** Default constructor. */
  public KeccakProofPathHashing() {}

  @Override
  public Hash accountTrieKey(final Address address) {
    return Hash.hash(address);
  }

  @Override
  public Hash storageTrieKey(final UInt256 slotKey) {
    return Hash.hash(slotKey);
  }

  @Override
  public Hash proofNodeIdentity(final Bytes encodedProofNodeRlp) {
    return Hash.hash(encodedProofNodeRlp);
  }

  @Override
  public TrieHashFunction trieHashFunction() {
    return TRIE_HASH_FUNCTION;
  }
}
