/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Validates complete enumeration against independently counted terminal values. */
public final class AccountEnumerationValidator {
  private AccountEnumerationValidator() {}

  public static ValidationResult validate(
      final List<AccountEnumerationEntry> entries,
      final ForestAccountLeafCounter.CountResult independentCount) {
    final Set<String> keys = new HashSet<>();
    int duplicates = 0;
    for (final AccountEnumerationEntry entry : entries) {
      if (entry.key() == null || entry.key().size() != 32) {
        return failure("Account trie key must be exactly 32 bytes", duplicates);
      }
      if (!keys.add(entry.key().toHexString())) {
        duplicates++;
        return failure("Duplicate enumerated account key: " + entry.key(), duplicates);
      }
      final AccountPathResult path = entry.authenticatedPath();
      if (path == null) {
        return failure("Missing authenticated traversal result", duplicates);
      }
      if (path.status() != AuditValidationStatus.VALID) {
        return failure(
            "Enumerated account authentication failed: " + path.status() + " " + path.error(),
            duplicates);
      }
      if (path.accountValueBytes().isEmpty()
          || !entry.accountValue().equals(path.accountValueBytes().orElseThrow())) {
        return failure("Enumerated account value differs from authenticated terminal value", duplicates);
      }
    }
    if (independentCount.status() != AuditValidationStatus.VALID) {
      return failure("Independent leaf count failed: " + independentCount.error(), duplicates);
    }
    if (entries.size() != independentCount.count()) {
      return failure(
          "Enumeration count " + entries.size() + " differs from independent count " + independentCount.count(),
          duplicates);
    }
    return new ValidationResult(AuditValidationStatus.VALID, entries.size(), independentCount.count(), duplicates, "");
  }

  private static ValidationResult failure(final String error, final int duplicates) {
    return new ValidationResult(AuditValidationStatus.MALFORMED, -1, -1, duplicates, error);
  }

  public record ValidationResult(
      AuditValidationStatus status,
      int enumerationCount,
      int independentLeafCount,
      int duplicateCount,
      String error) {
    public boolean isValid() {
      return status == AuditValidationStatus.VALID;
    }
  }
}
