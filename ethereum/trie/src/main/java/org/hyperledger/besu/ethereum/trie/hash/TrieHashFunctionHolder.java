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
package org.hyperledger.besu.ethereum.trie.hash;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Mutable holder for the active trie hash policy. Defaults to Keccak for backwards compatibility.
 */
public final class TrieHashFunctionHolder {
  private static final AtomicReference<TrieHashFunction> ACTIVE =
      new AtomicReference<>(new KeccakTrieHashFunction());

  private TrieHashFunctionHolder() {}

  public static TrieHashFunction get() {
    return ACTIVE.get();
  }

  public static void set(final TrieHashFunction hashFunction) {
    ACTIVE.set(Objects.requireNonNull(hashFunction));
  }
}
