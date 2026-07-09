/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * implied. See the License for the specific language governing permissions and limitations under the
 * License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.ethereum.trie.hash;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

class Poseidon2Bn254ByteHashTest {
  private static final BigInteger MODULUS = Poseidon2Bn254Constants.MODULUS;
  private static final ObjectMapper MAPPER =
      new ObjectMapper().setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
  private static final String FIXTURE =
      "/org/hyperledger/besu/ethereum/trie/hash/poseidon2_byte_vectors.json";

  @Test
  void matchesFixtureForPackingHashAndEncoding() throws Exception {
    final ByteVectors vectors = loadVectors();
    assertThat(vectors.repository()).isEqualTo("noir-lang/poseidon");
    assertThat(vectors.tag()).isEqualTo("v0.3.0");
    assertThat(vectors.commit()).isEqualTo("0880c371e88e583d39515fd3f877538657ac41eb");
    assertThat(hex(vectors.fieldModulus())).isEqualTo(MODULUS);
    assertThat(vectors.packingRule().chunkSizeBytes()).isEqualTo(31);
    assertThat(vectors.packingRule().endianness()).isEqualTo("little");
    assertThat(vectors.packingRule().finalPartialChunkPadding()).isEqualTo("zero");
    assertThat(vectors.packingRule().lengthField()).isFalse();
    assertThat(vectors.packingRule().domainSeparator()).isFalse();

    for (final ByteCaseRecord vector : vectors.cases()) {
      final Bytes input = bytes(vector.inputBytesHex());
      assertThat(Poseidon2Bn254ByteHash.packFields(input))
          .containsExactly(hexList(vector.packedFieldsHex()));
      assertThat(Poseidon2Bn254ByteHash.packFields(input)).hasSize(vector.packedFieldCount());

      final BigInteger hash = Poseidon2Bn254ByteHash.hashBytes(input);
      assertThat(hash).isEqualTo(hex(vector.outputFieldHex()));
      assertThat(hash.signum()).isGreaterThanOrEqualTo(0);
      assertThat(hash.compareTo(MODULUS)).isLessThan(0);

      assertThat(Poseidon2Bn254ByteHash.hashBytesToBytes32(input))
          .isEqualTo(Bytes32.fromHexString(vector.outputBytesBeHex()));
    }
  }

  @Test
  void packsLittleEndianWithinAChunk() {
    assertThat(Poseidon2Bn254ByteHash.packFields(bytes("0x0102"))).containsExactly(hex("0x0201"));
  }

  @Test
  void trailingZeroVariantsCollideAsExpected() {
    final BigInteger[] a = Poseidon2Bn254ByteHash.packFields(bytes("0x01"));
    final BigInteger[] b = Poseidon2Bn254ByteHash.packFields(bytes("0x0100"));
    final BigInteger[] c = Poseidon2Bn254ByteHash.packFields(bytes("0x010000"));

    assertThat(a).containsExactly(hex("0x01"));
    assertThat(b).containsExactly(hex("0x01"));
    assertThat(c).containsExactly(hex("0x01"));
    assertThat(Poseidon2Bn254ByteHash.hashBytes(bytes("0x01")))
        .isEqualTo(Poseidon2Bn254ByteHash.hashBytes(bytes("0x0100")));
    assertThat(Poseidon2Bn254ByteHash.hashBytes(bytes("0x01")))
        .isEqualTo(Poseidon2Bn254ByteHash.hashBytes(bytes("0x010000")));
  }

  @Test
  void emptyBytesAndZeroByteDiffer() {
    assertThat(Poseidon2Bn254ByteHash.packFields(Bytes.EMPTY)).isEmpty();
    assertThat(Poseidon2Bn254ByteHash.packFields(bytes("0x00"))).containsExactly(hex("0x00"));
    assertThat(Poseidon2Bn254ByteHash.hashBytes(Bytes.EMPTY))
        .isNotEqualTo(Poseidon2Bn254ByteHash.hashBytes(bytes("0x00")));
  }

  @Test
  void boundaryPackingCountsAreCorrect() {
    assertThat(Poseidon2Bn254ByteHash.packFields(bytes(rangeHex(31)))).hasSize(1);
    assertThat(Poseidon2Bn254ByteHash.packFields(bytes(rangeHex(32)))).hasSize(2);
    assertThat(Poseidon2Bn254ByteHash.packFields(bytes(rangeHex(33)))).hasSize(2);
    assertThat(Poseidon2Bn254ByteHash.packFields(bytes(rangeHex(62)))).hasSize(2);
    assertThat(Poseidon2Bn254ByteHash.packFields(bytes(rangeHex(63)))).hasSize(3);
    assertThat(Poseidon2Bn254ByteHash.packFields(bytes(rangeHex(64)))).hasSize(3);
  }

  @Test
  void rejectsNullInput() {
    assertThatThrownBy(() -> Poseidon2Bn254ByteHash.hashBytes(null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> Poseidon2Bn254ByteHash.hashBytesToBytes32(null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void isDeterministicAndEncodesBytes32UnsignedBigEndian() {
    final Bytes input = bytes("0xc8010283616263");
    final BigInteger first = Poseidon2Bn254ByteHash.hashBytes(input);
    final BigInteger second = Poseidon2Bn254ByteHash.hashBytes(input);

    assertThat(first).isEqualTo(second);
    assertThat(Poseidon2Bn254ByteHash.hashBytesToBytes32(input))
        .isEqualTo(
            Bytes32.fromHexString(
                "0x10c7e84bd1cd8339bfc14056169e8a72ccb35d375a17ea4e8499b7ee6b83e540"));

    assertThat(Poseidon2Bn254ByteHash.toBytes32(BigInteger.ONE.shiftLeft(255)))
        .isEqualTo(
            Bytes32.fromHexString(
                "0x8000000000000000000000000000000000000000000000000000000000000000"));
  }

  private static ByteVectors loadVectors() throws IOException {
    try (InputStream input = Poseidon2Bn254ByteHashTest.class.getResourceAsStream(FIXTURE)) {
      if (input == null) {
        throw new IOException("missing fixture: " + FIXTURE);
      }
      return MAPPER.readValue(input, ByteVectors.class);
    }
  }

  private static Bytes bytes(final String hex) {
    return Bytes.fromHexStringLenient(hex);
  }

  private static BigInteger[] hexList(final List<String> values) {
    final BigInteger[] output = new BigInteger[values.size()];
    for (int i = 0; i < values.size(); i++) {
      output[i] = hex(values.get(i));
    }
    return output;
  }

  private static BigInteger hex(final String value) {
    final String normalized = value.startsWith("0x") ? value.substring(2) : value;
    return new BigInteger(normalized, 16);
  }

  private static String rangeHex(final int length) {
    final StringBuilder builder = new StringBuilder("0x");
    for (int i = 0; i < length; i++) {
      builder.append(String.format("%02x", i));
    }
    return builder.toString();
  }

  record ByteVectors(
      String repository,
      String tag,
      String commit,
      String nargoVersion,
      String bbVersion,
      String fieldModulus,
      PackingRule packingRule,
      List<ByteCaseRecord> cases) {}

  record PackingRule(
      int chunkSizeBytes,
      String endianness,
      String finalPartialChunkPadding,
      boolean lengthField,
      boolean domainSeparator) {}

  record ByteCaseRecord(
      String caseName,
      String inputBytesHex,
      List<String> packedFieldsHex,
      int packedFieldCount,
      String outputFieldHex,
      String outputBytesBeHex) {}
}
