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
 * or implied. See the License for the specific language governing permissions and limitations under the
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
import java.util.Arrays;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import org.junit.jupiter.api.Test;

class Poseidon2Bn254HashTest {
  private static final BigInteger MODULUS = Poseidon2Bn254Constants.MODULUS;
  private static final ObjectMapper MAPPER =
      new ObjectMapper().setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
  private static final String FIXTURE =
      "/org/hyperledger/besu/ethereum/trie/hash/poseidon2_sponge_vectors.json";

  @Test
  void hashesFixedVectorsFromFixture() throws Exception {
    final PoseidonVectors vectors = loadVectors();
    for (final VectorRecord vector : vectors.fixedLengthVectors()) {
      assertThat(Poseidon2Bn254Hash.hash(prefix(vector.input(), vector.input().size())))
          .isEqualTo(hex(vector.output()));
    }
  }

  @Test
  void hashesVariableVectorsFromLogicalPrefix() throws Exception {
    final PoseidonVectors vectors = loadVectors();
    for (final VectorRecord vector : vectors.variableLengthVectors()) {
      assertThat(Poseidon2Bn254Hash.hash(prefix(vector.input(), vector.messageSize())))
          .isEqualTo(hex(vector.output()));
    }
  }

  @Test
  void paddingEquivalenceMatchesFixture() throws Exception {
    final PoseidonVectors vectors = loadVectors();
    final PaddingVectors padding = vectors.paddingEquivalence();
    final BigInteger a =
        Poseidon2Bn254Hash.hash(prefix(padding.a().input(), padding.a().messageSize()));
    final BigInteger b =
        Poseidon2Bn254Hash.hash(prefix(padding.b().input(), padding.b().messageSize()));
    final BigInteger control =
        Poseidon2Bn254Hash.hash(prefix(padding.control().input(), padding.control().messageSize()));

    assertThat(a).isEqualTo(hex(padding.a().output()));
    assertThat(b).isEqualTo(hex(padding.b().output()));
    assertThat(control).isEqualTo(hex(padding.control().output()));
    assertThat(a).isEqualTo(b);
    assertThat(control).isNotEqualTo(a);
  }

  @Test
  void rejectsInvalidInputs() {
    assertThatThrownBy(() -> Poseidon2Bn254Hash.hash(null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> Poseidon2Bn254Hash.hash(new BigInteger[] {BigInteger.ZERO, null}))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> Poseidon2Bn254Hash.hash(new BigInteger[] {BigInteger.valueOf(-1)}))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> Poseidon2Bn254Hash.hash(new BigInteger[] {MODULUS}))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () -> Poseidon2Bn254Hash.hash(new BigInteger[] {MODULUS.add(BigInteger.ONE)}))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void doesNotMutateInputAndIsDeterministic() {
    final BigInteger[] input = {
      BigInteger.ONE, BigInteger.TWO, BigInteger.valueOf(3), BigInteger.valueOf(4)
    };
    final BigInteger[] snapshot = Arrays.copyOf(input, input.length);

    final BigInteger first = Poseidon2Bn254Hash.hash(input);
    final BigInteger second = Poseidon2Bn254Hash.hash(input);

    assertThat(input).containsExactly(snapshot);
    assertThat(first).isEqualTo(second);
    assertThat(first.signum()).isGreaterThanOrEqualTo(0);
    assertThat(first.compareTo(MODULUS)).isLessThan(0);
  }

  @Test
  void emptyAndDivisibleByThreeCasesUseExpectedFinalPermutationRule() {
    assertThat(Poseidon2Bn254Hash.hash(new BigInteger[0]))
        .isEqualTo(hex("0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e"));
    assertThat(
            Poseidon2Bn254Hash.hash(
                new BigInteger[] {BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO}))
        .isEqualTo(hex("0x099f9ef8a2ccf575306ef6b7996be65db5e47d860bfab6592e52c89764b4b9cc"));
  }

  @Test
  void comparesPaddingAgainstPrefixOnly() {
    assertThat(Poseidon2Bn254Hash.hash(new BigInteger[] {BigInteger.ONE, BigInteger.TWO}))
        .isEqualTo(hex("0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383"));
    assertThat(Poseidon2Bn254Hash.hash(new BigInteger[] {BigInteger.valueOf(3), BigInteger.TWO}))
        .isEqualTo(hex("0x2decd4e3fa03b737b7b3da5172c1b9021ef2dafbd26ff8ba5efa0ed9809a87c0"));
  }

  private static PoseidonVectors loadVectors() throws IOException {
    try (InputStream input = Poseidon2Bn254HashTest.class.getResourceAsStream(FIXTURE)) {
      if (input == null) {
        throw new IOException("missing fixture: " + FIXTURE);
      }
      return MAPPER.readValue(input, PoseidonVectors.class);
    }
  }

  private static BigInteger[] prefix(final List<String> input, final int length) {
    final BigInteger[] out = new BigInteger[length];
    for (int i = 0; i < length; i++) {
      out[i] = hex(input.get(i));
    }
    return out;
  }

  private static BigInteger hex(final String value) {
    final String normalized = value.startsWith("0x") ? value.substring(2) : value;
    return new BigInteger(normalized, 16);
  }

  record PoseidonVectors(
      String repository,
      String tag,
      String commit,
      String nargoVersion,
      String bbVersion,
      String fieldModulus,
      RawPermutation rawPermutation,
      List<VectorRecord> fixedLengthVectors,
      List<VectorRecord> variableLengthVectors,
      PaddingVectors paddingEquivalence) {}

  record RawPermutation(List<String> input, List<String> output) {}

  record VectorRecord(List<String> input, int messageSize, String output) {}

  record PaddingVectors(VectorRecord a, VectorRecord b, VectorRecord control) {}
}
