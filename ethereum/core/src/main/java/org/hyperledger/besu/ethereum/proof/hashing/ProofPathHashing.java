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
import org.hyperledger.besu.ethereum.trie.hash.TrieHashFunction;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt256;

/** Hash policy for proof-path keying and proof-node identity. */
public interface ProofPathHashing {
  /**
   * Returns the trie key used to look up an account in the account state trie.
   *
   * @param address the account address
   * @return the account trie key
   */
  Hash accountTrieKey(Address address);

  /**
   * Returns the trie key used to look up a storage slot in an account storage trie.
   *
   * @param slotKey the storage slot key
   * @return the storage trie key
   */
  Hash storageTrieKey(UInt256 slotKey);

  /**
   * Returns the node identity hash used when reconstructing tries from proof node payloads.
   *
   * @param encodedProofNodeRlp the encoded proof node
   * @return the proof node identity hash
   */
  Hash proofNodeIdentity(Bytes encodedProofNodeRlp);

  /**
   * Returns the trie node hash function associated with this proof-path hash policy.
   *
   * @return the trie hash function
   */
  TrieHashFunction trieHashFunction();
}
