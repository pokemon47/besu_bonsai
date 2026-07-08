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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

class Poseidon2Bn254PermutationTest {
  private static final BigInteger P = Poseidon2Bn254Constants.MODULUS;
  private static final BigInteger[] TEST_VECTOR_INPUT = {
    BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2), BigInteger.valueOf(3)
  };
  private static final BigInteger[] TEST_VECTOR_OUTPUT = {
    new BigInteger("01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737", 16),
    new BigInteger("239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662", 16),
    new BigInteger("04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cb", 16),
    new BigInteger("2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847a", 16)
  };
  private static final BigInteger[][] EXTERNAL_MATRIX = {
    {BigInteger.valueOf(5), BigInteger.valueOf(7), BigInteger.ONE, BigInteger.valueOf(3)},
    {BigInteger.valueOf(4), BigInteger.valueOf(6), BigInteger.ONE, BigInteger.ONE},
    {BigInteger.ONE, BigInteger.valueOf(3), BigInteger.valueOf(5), BigInteger.valueOf(7)},
    {BigInteger.ONE, BigInteger.ONE, BigInteger.valueOf(4), BigInteger.valueOf(6)}
  };

  @Test
  void knownAnswerMatchesPinnedVector() {
    assertThat(Poseidon2Bn254Permutation.permute(TEST_VECTOR_INPUT))
        .containsExactly(TEST_VECTOR_OUTPUT);
  }

  @Test
  void rejectsNullInput() {
    assertThatThrownBy(() -> Poseidon2Bn254Permutation.permute(null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void rejectsWrongLengthInput() {
    assertThatThrownBy(() -> Poseidon2Bn254Permutation.permute(new BigInteger[] {BigInteger.ZERO}))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsNullElement() {
    assertThatThrownBy(
            () ->
                Poseidon2Bn254Permutation.permute(
                    new BigInteger[] {BigInteger.ZERO, null, BigInteger.ONE, BigInteger.TWO}))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsNegativeElement() {
    assertThatThrownBy(
            () ->
                Poseidon2Bn254Permutation.permute(
                    new BigInteger[] {
                      BigInteger.valueOf(-1), BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO
                    }))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsP() {
    assertThatThrownBy(
            () ->
                Poseidon2Bn254Permutation.permute(
                    new BigInteger[] {P, BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO}))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsGreaterThanP() {
    assertThatThrownBy(
            () ->
                Poseidon2Bn254Permutation.permute(
                    new BigInteger[] {
                      P.add(BigInteger.ONE), BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO
                    }))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void doesNotMutateInputAndReturnsDistinctArray() {
    final BigInteger[] input = Arrays.copyOf(TEST_VECTOR_INPUT, 4);
    final BigInteger[] snapshot = Arrays.copyOf(input, input.length);

    final BigInteger[] output = Poseidon2Bn254Permutation.permute(input);

    assertThat(input).containsExactly(snapshot);
    assertThat(output).isNotSameAs(input);
  }

  @Test
  void outputsAreCanonicalAndDeterministic() {
    final BigInteger[] input = {
      P.subtract(BigInteger.ONE), BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO
    };
    final BigInteger[] first = Poseidon2Bn254Permutation.permute(input);
    final BigInteger[] second = Poseidon2Bn254Permutation.permute(input);

    assertThat(first).containsExactly(second);
    assertThat(first)
        .allSatisfy(
            value -> {
              assertThat(value.signum()).isGreaterThanOrEqualTo(0);
              assertThat(value.compareTo(P)).isLessThan(0);
            });
  }

  @Test
  void x5MatchesModPow() {
    for (final BigInteger value :
        new BigInteger[] {
          BigInteger.ZERO, BigInteger.ONE, P.subtract(BigInteger.ONE), BigInteger.valueOf(42)
        }) {
      assertThat(Poseidon2Bn254Permutation.x5(value))
          .isEqualTo(value.modPow(BigInteger.valueOf(5), P));
    }
  }

  @Test
  void optimizedExternalMatrixMatchesExplicitMatrix() {
    final BigInteger[] input = {
      BigInteger.ONE, BigInteger.TWO, BigInteger.valueOf(3), BigInteger.valueOf(4)
    };
    final BigInteger[] optimized = Arrays.copyOf(input, input.length);
    Poseidon2Bn254Permutation.applyExternalMatrix(optimized);

    assertThat(optimized).containsExactly(multiply(EXTERNAL_MATRIX, input));
  }

  @Test
  void optimizedInternalMatrixMatchesExplicitMatrix() {
    final BigInteger[] input = {
      BigInteger.ONE, BigInteger.TWO, BigInteger.valueOf(3), BigInteger.valueOf(4)
    };
    final BigInteger[] optimized = Arrays.copyOf(input, input.length);
    Poseidon2Bn254Permutation.applyInternalMatrix(optimized);

    assertThat(optimized).containsExactly(multiply(internalMatrix(), input));
  }

  @Test
  void constantsHaveExpectedDimensionsAndStructure() {
    assertThat(Poseidon2Bn254Constants.roundConstantRows()).isEqualTo(64);
    for (int row = 0; row < 64; row++) {
      assertThat(Poseidon2Bn254Constants.roundConstantColumns(row)).isEqualTo(4);
    }
    assertThat(Poseidon2Bn254Constants.internalMatrixSize()).isEqualTo(4);
    assertThat(Poseidon2Bn254Constants.roundConstant(0, 0)).isNotNull();
    for (int i = 0; i < 4; i++) {
      assertNonZeroRow(i);
    }
    for (int i = 4; i < 60; i++) {
      assertPartialRow(i);
    }
  }

  private void assertNonZeroRow(final int row) {
    for (int column = 0; column < 4; column++) {
      assertThat(Poseidon2Bn254Constants.roundConstant(row, column)).isNotZero();
    }
  }

  private void assertPartialRow(final int row) {
    assertThat(Poseidon2Bn254Constants.roundConstant(row, 0)).isNotZero();
    assertThat(Poseidon2Bn254Constants.roundConstant(row, 1)).isZero();
    assertThat(Poseidon2Bn254Constants.roundConstant(row, 2)).isZero();
    assertThat(Poseidon2Bn254Constants.roundConstant(row, 3)).isZero();
  }

  private BigInteger[] multiply(final BigInteger[][] matrix, final BigInteger[] vector) {
    final BigInteger[] out = new BigInteger[4];
    for (int i = 0; i < 4; i++) {
      BigInteger acc = BigInteger.ZERO;
      for (int j = 0; j < 4; j++) {
        acc = acc.add(matrix[i][j].multiply(vector[j]));
      }
      out[i] = acc.mod(P);
    }
    return out;
  }

  private BigInteger[][] internalMatrix() {
    return new BigInteger[][] {
      {
        Poseidon2Bn254Constants.internalMatrixValue(0, 0),
        Poseidon2Bn254Constants.internalMatrixValue(0, 1),
        Poseidon2Bn254Constants.internalMatrixValue(0, 2),
        Poseidon2Bn254Constants.internalMatrixValue(0, 3)
      },
      {
        Poseidon2Bn254Constants.internalMatrixValue(1, 0),
        Poseidon2Bn254Constants.internalMatrixValue(1, 1),
        Poseidon2Bn254Constants.internalMatrixValue(1, 2),
        Poseidon2Bn254Constants.internalMatrixValue(1, 3)
      },
      {
        Poseidon2Bn254Constants.internalMatrixValue(2, 0),
        Poseidon2Bn254Constants.internalMatrixValue(2, 1),
        Poseidon2Bn254Constants.internalMatrixValue(2, 2),
        Poseidon2Bn254Constants.internalMatrixValue(2, 3)
      },
      {
        Poseidon2Bn254Constants.internalMatrixValue(3, 0),
        Poseidon2Bn254Constants.internalMatrixValue(3, 1),
        Poseidon2Bn254Constants.internalMatrixValue(3, 2),
        Poseidon2Bn254Constants.internalMatrixValue(3, 3)
      }
    };
  }
}
