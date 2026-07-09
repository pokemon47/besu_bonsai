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
import java.util.Objects;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/** Byte adapter for the pinned Noir v0.3.0-compatible Poseidon2 BN254 sponge. */
public final class Poseidon2Bn254ByteHash {
  private static final int BYTE_CHUNK_SIZE = 31;
  private static final int OUTPUT_BYTES = Bytes32.SIZE;

  private Poseidon2Bn254ByteHash() {}

  public static BigInteger hashBytes(final Bytes input) {
    return Poseidon2Bn254Hash.hash(packFields(input));
  }

  public static Bytes32 hashBytesToBytes32(final Bytes input) {
    return toBytes32(hashBytes(input));
  }

  static BigInteger[] packFields(final Bytes input) {
    Objects.requireNonNull(input, "input");

    final int packedCount = (input.size() + BYTE_CHUNK_SIZE - 1) / BYTE_CHUNK_SIZE;
    final BigInteger[] fields = new BigInteger[packedCount];
    for (int chunk = 0; chunk < packedCount; chunk++) {
      final int offset = chunk * BYTE_CHUNK_SIZE;
      final int length = Math.min(BYTE_CHUNK_SIZE, input.size() - offset);
      fields[chunk] = packChunk(input, offset, length);
    }
    return fields;
  }

  static Bytes32 toBytes32(final BigInteger value) {
    Objects.requireNonNull(value, "value");

    final byte[] raw = value.toByteArray();
    final int srcPos = Math.max(0, raw.length - OUTPUT_BYTES);
    final int length = raw.length - srcPos;
    final byte[] output = new byte[OUTPUT_BYTES];
    System.arraycopy(raw, srcPos, output, OUTPUT_BYTES - length, length);
    return Bytes32.wrap(output);
  }

  private static BigInteger packChunk(final Bytes input, final int offset, final int length) {
    BigInteger packed = BigInteger.ZERO;
    BigInteger factor = BigInteger.ONE;
    for (int i = 0; i < length; i++) {
      final long unsignedByte = input.get(offset + i) & 0xffL;
      packed = packed.add(BigInteger.valueOf(unsignedByte).multiply(factor));
      factor = factor.shiftLeft(8);
    }
    return packed;
  }
}
