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

/** Pinned Noir v0.3.0-compatible Poseidon2 BN254 field-array sponge. */
public final class Poseidon2Bn254Hash {
  private static final BigInteger TWO_POW_64 = BigInteger.ONE.shiftLeft(64);

  private Poseidon2Bn254Hash() {}

  public static BigInteger hash(final BigInteger[] input) {
    Objects.requireNonNull(input, "input");
    final BigInteger[] message = Arrays.copyOf(input, input.length);
    for (int i = 0; i < message.length; i++) {
      validateCanonical(message[i], i);
    }

    BigInteger[] state =
        new BigInteger[] {
          BigInteger.ZERO,
          BigInteger.ZERO,
          BigInteger.ZERO,
          BigInteger.valueOf(message.length).multiply(TWO_POW_64)
        };

    final int fullChunks = message.length / 3;
    for (int chunk = 0; chunk < fullChunks; chunk++) {
      final int base = chunk * 3;
      state[0] = state[0].add(message[base]).mod(Poseidon2Bn254Constants.MODULUS);
      state[1] = state[1].add(message[base + 1]).mod(Poseidon2Bn254Constants.MODULUS);
      state[2] = state[2].add(message[base + 2]).mod(Poseidon2Bn254Constants.MODULUS);
      state = Poseidon2Bn254Permutation.permute(state);
    }

    final int remainder = message.length % 3;
    if (remainder > 0) {
      final int base = fullChunks * 3;
      state[0] = state[0].add(message[base]).mod(Poseidon2Bn254Constants.MODULUS);
      if (remainder > 1) {
        state[1] = state[1].add(message[base + 1]).mod(Poseidon2Bn254Constants.MODULUS);
      }
    }

    if (message.length == 0 || remainder != 0) {
      state = Poseidon2Bn254Permutation.permute(state);
    }

    return state[0];
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
