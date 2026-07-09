/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and limitations under the
 * License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.ethereum.trie.hash;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.Hash;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

class Poseidon2TrieHashFunctionTest {
  private static final Poseidon2TrieHashFunction HASH_FUNCTION = new Poseidon2TrieHashFunction();

  @Test
  void delegatesToByteHashAdapterForRepresentativeInputs() {
    assertMatchesAdapter(Bytes.EMPTY);
    assertMatchesAdapter(Bytes.fromHexString("0x00"));
    assertMatchesAdapter(Bytes.fromHexString("0x01"));
    assertMatchesAdapter(Bytes.fromHexString("0x00112233445566778899aabbccddeeff10203040"));
    assertMatchesAdapter(
        Bytes.fromHexString("0x00112233445566778899aabbccddeeff102030405060708090a0b0c0d0e0f001"));
    assertMatchesAdapter(Bytes.fromHexString("0xc8010283616263"));
    assertMatchesAdapter(
        Bytes.fromHexString(
            "0x00112233445566778899aabbccddeeff102030405060708090a0b0c0d0e0f0010203040506070809"));
  }

  @Test
  void differsFromOldSha3PlaceholderForRepresentativeNonEmptyInput() {
    final Bytes input = Bytes.fromHexString("0x01");
    assertThat(HASH_FUNCTION.hash(input))
        .isEqualTo(Poseidon2Bn254ByteHash.hashBytesToBytes32(input));
    assertThat(HASH_FUNCTION.hash(input)).isNotEqualTo(Hash.sha3_256(input));
  }

  private static void assertMatchesAdapter(final Bytes input) {
    final Bytes32 expected = Poseidon2Bn254ByteHash.hashBytesToBytes32(input);
    assertThat(HASH_FUNCTION.hash(input)).isEqualTo(expected);
  }
}
