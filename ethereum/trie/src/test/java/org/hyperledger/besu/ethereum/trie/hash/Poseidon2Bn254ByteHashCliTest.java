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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

class Poseidon2Bn254ByteHashCliTest {
  @Test
  void hashesEmptyInput() {
    assertSuccessfulHash("0x", Bytes.EMPTY);
  }

  @Test
  void hashesShortInput() {
    assertSuccessfulHash("0x01", Bytes.fromHexString("0x01"));
  }

  @Test
  void hashesThirtyTwoByteBoundaryInput() {
    assertSuccessfulHash(
        "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        Bytes.fromHexString("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
  }

  @Test
  void rejectsInvalidInput() {
    final RunResult result = runCli("0xabc");

    assertThat(result.exitCode()).isEqualTo(1);
    assertThat(result.stdout()).isEmpty();
    assertThat(result.stderr()).contains("Invalid input:");
  }

  @Test
  void rejectsWrongArgumentCount() {
    final ByteArrayOutputStream stdout = new ByteArrayOutputStream();
    final ByteArrayOutputStream stderr = new ByteArrayOutputStream();
    final int exitCode =
        Poseidon2Bn254ByteHashCli.run(new String[0], printStream(stdout), printStream(stderr));

    assertThat(exitCode).isEqualTo(1);
    assertThat(stdout.toString(StandardCharsets.UTF_8)).isEmpty();
    assertThat(stderr.toString(StandardCharsets.UTF_8))
        .contains("Usage: besu-poseidon2-hash <hex-bytes>");
  }

  private static void assertSuccessfulHash(final String arg, final Bytes input) {
    final RunResult result = runCli(arg);
    final BigInteger expected = Poseidon2Bn254ByteHash.hashBytes(input);

    assertThat(result.exitCode()).isZero();
    assertThat(result.stderr()).isEmpty();
    assertThat(result.stdout()).isEqualTo(Poseidon2Bn254ByteHash.toBytes32(expected).toHexString());
  }

  private static RunResult runCli(final String arg) {
    final ByteArrayOutputStream stdout = new ByteArrayOutputStream();
    final ByteArrayOutputStream stderr = new ByteArrayOutputStream();
    final int exitCode =
        Poseidon2Bn254ByteHashCli.run(new String[] {arg}, printStream(stdout), printStream(stderr));
    return new RunResult(
        exitCode,
        stdout.toString(StandardCharsets.UTF_8).trim(),
        stderr.toString(StandardCharsets.UTF_8).trim());
  }

  private static PrintStream printStream(final ByteArrayOutputStream output) {
    return new PrintStream(output, true, StandardCharsets.UTF_8);
  }

  private record RunResult(int exitCode, String stdout, String stderr) {}
}
