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
import static org.hyperledger.besu.crypto.Hash.sha3_256;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.trie.hash.Poseidon2Bn254ByteHash;
import org.hyperledger.besu.ethereum.trie.hash.Poseidon2TrieHashFunction;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt256;
import org.junit.jupiter.api.Test;

class Poseidon2ProofPathHashingTest {
  private static final Poseidon2ProofPathHashing HASHING = new Poseidon2ProofPathHashing();

  @Test
  void delegatesAccountTrieKeyToPoseidonByteHash() {
    final Address address = Address.fromHexString("0x00112233445566778899aabbccddeeff10203040");

    assertThat(HASHING.accountTrieKey(address))
        .isEqualTo(Hash.wrap(Poseidon2Bn254ByteHash.hashBytesToBytes32(address)));
  }

  @Test
  void delegatesStorageTrieKeyToPoseidonByteHashUsingCanonicalUInt256Bytes() {
    final UInt256 slot =
        UInt256.fromHexString("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    final Bytes32 expectedBytes =
        Bytes32.fromHexString("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    assertThat(slot.toBytes()).isEqualTo(expectedBytes);
    assertThat(HASHING.storageTrieKey(slot))
        .isEqualTo(Hash.wrap(Poseidon2Bn254ByteHash.hashBytesToBytes32(slot.toBytes())));
  }

  @Test
  void delegatesProofNodeIdentityToPoseidonByteHash() {
    final Bytes encodedProofNodeRlp = Bytes.fromHexString("0xc8010283616263");

    assertThat(HASHING.proofNodeIdentity(encodedProofNodeRlp))
        .isEqualTo(Hash.wrap(Poseidon2Bn254ByteHash.hashBytesToBytes32(encodedProofNodeRlp)));
  }

  @Test
  void returnsPoseidonTrieHashFunction() {
    assertThat(HASHING.trieHashFunction()).isInstanceOf(Poseidon2TrieHashFunction.class);
  }

  @Test
  void doesNotReturnTheOldSha3PlaceholderForRepresentativeInput() {
    final Bytes encodedProofNodeRlp =
        Bytes.fromHexString("0x00112233445566778899aabbccddeeff102030405060708090a0b0c0d0e0f001");

    assertThat(HASHING.proofNodeIdentity(encodedProofNodeRlp))
        .isEqualTo(Hash.wrap(Poseidon2Bn254ByteHash.hashBytesToBytes32(encodedProofNodeRlp)));
    assertThat(HASHING.proofNodeIdentity(encodedProofNodeRlp))
        .isNotEqualTo(Hash.wrap(sha3_256(encodedProofNodeRlp)));
  }
}
