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
package org.hyperledger.besu.ethereum.trie.hash;

import static org.hyperledger.besu.crypto.Hash.sha256;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Placeholder trie hash policy for Poseidon2 mode.
 *
 * <p>Besu currently has no native Poseidon2 primitive in this repository. For phase-4 wiring and
 * replay-prep, this policy intentionally uses SHA-256 as a deterministic non-Keccak hash policy
 * until a real Poseidon2 primitive is introduced.
 */
public final class Poseidon2TrieHashFunction implements TrieHashFunction {
  @Override
  public Bytes32 hash(final Bytes input) {
    return sha256(input);
  }
}
