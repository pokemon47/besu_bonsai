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

import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/** Configures proof-path hashing policy from runtime properties. */
public final class ProofPathHashingConfigurator {
  /** System property that selects the proof-path hashing policy. */
  public static final String PROOF_PATH_HASHING_PROPERTY = "besu.experimental.proof-path-hashing";

  private static final AtomicBoolean CONFIGURED = new AtomicBoolean(false);

  private ProofPathHashingConfigurator() {}

  /**
   * Configures the active proof-path hashing policy from JVM system properties.
   *
   * <p>The property defaults to {@code keccak}. When set to {@code poseidon2}, the temporary
   * phase-4 Poseidon2 placeholder policy is installed for proof-path hashing (NIST SHA3-256 until a
   * real Poseidon2 primitive exists).
   */
  public static void configureFromSystemProperties() {
    if (!CONFIGURED.compareAndSet(false, true)) {
      return;
    }
    final String configuredValue =
        System.getProperty(PROOF_PATH_HASHING_PROPERTY, "keccak").toLowerCase(Locale.ROOT).trim();
    if ("poseidon2".equals(configuredValue)) {
      ProofPathHashingHolder.set(new Poseidon2ProofPathHashing());
    } else {
      ProofPathHashingHolder.set(new KeccakProofPathHashing());
    }
  }

  /** Backward-compatible alias for Forest-focused callers. */
  public static void configureForForestFromSystemProperties() {
    configureFromSystemProperties();
  }
}
