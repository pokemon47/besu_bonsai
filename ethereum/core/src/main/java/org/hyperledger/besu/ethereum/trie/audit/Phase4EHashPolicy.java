/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import org.hyperledger.besu.ethereum.proof.hashing.KeccakProofPathHashing;
import org.hyperledger.besu.ethereum.proof.hashing.Poseidon2ProofPathHashing;
import org.hyperledger.besu.ethereum.proof.hashing.ProofPathHashing;
import org.hyperledger.besu.ethereum.proof.hashing.ProofPathHashingHolder;

/** Explicit Phase 4E hash-policy validation; never switches policies implicitly. */
public final class Phase4EHashPolicy {
  private Phase4EHashPolicy() {}

  public static Validated validate(final String requested) {
    final ProofPathHashing detected = ProofPathHashingHolder.get();
    final String normalized = requested.toLowerCase(java.util.Locale.ROOT);
    final boolean match = switch (normalized) {
      case "keccak", "keccak256" -> detected instanceof KeccakProofPathHashing;
      case "poseidon2" -> detected instanceof Poseidon2ProofPathHashing;
      default -> false;
    };
    if (!match) throw new IllegalStateException("Requested hash policy does not match active ProofPathHashing: " + requested);
    return new Validated(requested, detected.getClass().getName(), detected.trieHashFunction().getClass().getName(),
        "accountTrieKey=ForestAccountEnumerator/selected-policy", "unavailable");
  }

  public record Validated(String requestedVariant, String proofPathHashingClass, String trieHashFunctionClass,
      String accountKeyIdentity, String poseidon2ParameterIdentity) {}
}
