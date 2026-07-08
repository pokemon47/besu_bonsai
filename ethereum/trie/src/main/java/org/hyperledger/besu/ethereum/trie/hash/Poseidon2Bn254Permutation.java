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

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/** Pinned Barretenberg Poseidon2 BN254 width-4 raw permutation. */
public final class Poseidon2Bn254Permutation {
  private Poseidon2Bn254Permutation() {}

  public static BigInteger[] permute(final BigInteger[] input) {
    Objects.requireNonNull(input, "input");
    if (input.length != Poseidon2Bn254Constants.WIDTH) {
      throw new IllegalArgumentException("Poseidon2 raw permutation requires exactly 4 inputs");
    }

    final BigInteger[] state = Arrays.copyOf(input, input.length);
    for (int i = 0; i < state.length; i++) {
      validateCanonical(state[i], i);
    }

    applyExternalMatrix(state);
    for (int round = 0; round < Poseidon2Bn254Constants.FULL_ROUNDS / 2; round++) {
      fullRound(state, round);
    }
    for (int round = Poseidon2Bn254Constants.FULL_ROUNDS / 2;
        round < Poseidon2Bn254Constants.FULL_ROUNDS / 2 + Poseidon2Bn254Constants.PARTIAL_ROUNDS;
        round++) {
      partialRound(state, round);
    }
    for (int round =
            Poseidon2Bn254Constants.FULL_ROUNDS / 2 + Poseidon2Bn254Constants.PARTIAL_ROUNDS;
        round < Poseidon2Bn254Constants.TOTAL_ROUNDS;
        round++) {
      fullRound(state, round);
    }
    return state;
  }

  static BigInteger x5(final BigInteger value) {
    final BigInteger x2 = value.multiply(value).mod(Poseidon2Bn254Constants.MODULUS);
    final BigInteger x4 = x2.multiply(x2).mod(Poseidon2Bn254Constants.MODULUS);
    return x4.multiply(value).mod(Poseidon2Bn254Constants.MODULUS);
  }

  static void applyExternalMatrix(final BigInteger[] state) {
    final BigInteger a = state[0];
    final BigInteger b = state[1];
    final BigInteger c = state[2];
    final BigInteger d = state[3];
    state[0] =
        a.multiply(BigInteger.valueOf(5))
            .add(b.multiply(BigInteger.valueOf(7)))
            .add(c)
            .add(d.multiply(BigInteger.valueOf(3)))
            .mod(Poseidon2Bn254Constants.MODULUS);
    state[1] =
        a.multiply(BigInteger.valueOf(4))
            .add(b.multiply(BigInteger.valueOf(6)))
            .add(c)
            .add(d)
            .mod(Poseidon2Bn254Constants.MODULUS);
    state[2] =
        a.add(b.multiply(BigInteger.valueOf(3)))
            .add(c.multiply(BigInteger.valueOf(5)))
            .add(d.multiply(BigInteger.valueOf(7)))
            .mod(Poseidon2Bn254Constants.MODULUS);
    state[3] =
        a.add(b)
            .add(c.multiply(BigInteger.valueOf(4)))
            .add(d.multiply(BigInteger.valueOf(6)))
            .mod(Poseidon2Bn254Constants.MODULUS);
  }

  static void applyInternalMatrix(final BigInteger[] state) {
    final BigInteger sum =
        state[0].add(state[1]).add(state[2]).add(state[3]).mod(Poseidon2Bn254Constants.MODULUS);
    for (int i = 0; i < state.length; i++) {
      state[i] =
          Poseidon2Bn254Constants.internalMatrixDiagonalMinusOne(i)
              .multiply(state[i])
              .add(sum)
              .mod(Poseidon2Bn254Constants.MODULUS);
    }
  }

  private static void fullRound(final BigInteger[] state, final int round) {
    addRoundConstants(state, round);
    for (int i = 0; i < state.length; i++) {
      state[i] = x5(state[i]);
    }
    applyExternalMatrix(state);
  }

  private static void partialRound(final BigInteger[] state, final int round) {
    state[0] =
        state[0]
            .add(Poseidon2Bn254Constants.roundConstant(round, 0))
            .mod(Poseidon2Bn254Constants.MODULUS);
    state[0] = x5(state[0]);
    applyInternalMatrix(state);
  }

  private static void addRoundConstants(final BigInteger[] state, final int round) {
    for (int i = 0; i < state.length; i++) {
      state[i] =
          state[i]
              .add(Poseidon2Bn254Constants.roundConstant(round, i))
              .mod(Poseidon2Bn254Constants.MODULUS);
    }
  }

  private static void validateCanonical(final BigInteger value, final int index) {
    if (value == null) {
      throw new IllegalArgumentException("input[" + index + "] must not be null");
    }
    if (value.signum() < 0 || value.compareTo(Poseidon2Bn254Constants.MODULUS) >= 0) {
      throw new IllegalArgumentException("input[" + index + "] must be in [0, p)");
    }
  }
}
