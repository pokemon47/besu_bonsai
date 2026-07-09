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

import java.io.PrintStream;

import org.apache.tuweni.bytes.Bytes;

public final class Poseidon2Bn254ByteHashCli {
  private Poseidon2Bn254ByteHashCli() {}

  public static void main(final String[] args) {
    final int exitCode = run(args, System.out, System.err);
    if (exitCode != 0) {
      System.exit(exitCode);
    }
  }

  static int run(final String[] args, final PrintStream stdout, final PrintStream stderr) {
    if (args.length != 1) {
      stderr.println("Usage: besu-poseidon2-hash <hex-bytes>");
      return 1;
    }

    try {
      final Bytes input = parseInput(args[0]);
      stdout.println(Poseidon2Bn254ByteHash.hashBytesToBytes32(input).toHexString());
      return 0;
    } catch (IllegalArgumentException | NullPointerException e) {
      stderr.println("Invalid input: " + e.getMessage());
      return 1;
    } catch (RuntimeException e) {
      stderr.println("Hashing failed: " + e.getMessage());
      return 1;
    }
  }

  private static Bytes parseInput(final String input) {
    if (input == null) {
      throw new IllegalArgumentException("hex input must not be null");
    }

    final String trimmed = input.trim();
    final String normalized =
        trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed : "0x" + trimmed;
    return Bytes.fromHexString(normalized);
  }
}
