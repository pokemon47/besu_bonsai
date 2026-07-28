/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

class ForestAccountEnumerationValidatorTest {
  private static final Bytes32 KEY = Bytes32.fromHexString("0x" + "11".repeat(32));
  private static final Bytes VALUE = Bytes.of(1, 2, 3);

  @Test
  void acceptsMatchingEnumerationAndIndependentCount() {
    assertThat(AccountEnumerationValidator.validate(List.of(entry(validPath())), count(1)).isValid())
        .isTrue();
  }

  @Test
  void rejectsDuplicateAndOmittedEntries() {
    final AccountEnumerationEntry entry = entry(validPath());
    assertThat(AccountEnumerationValidator.validate(List.of(entry, entry), count(2)).isValid())
        .isFalse();
    assertThat(AccountEnumerationValidator.validate(List.of(entry), count(2)).isValid()).isFalse();
  }

  @Test
  void rejectsMissingMalformedReferenceMismatchAndValueMismatch() {
    for (final AuditValidationStatus status :
        List.of(AuditValidationStatus.MISSING, AuditValidationStatus.MALFORMED, AuditValidationStatus.REFERENCE_MISMATCH)) {
      assertThat(AccountEnumerationValidator.validate(List.of(entry(path(status))), count(1)).isValid())
          .isFalse();
    }
    final AccountPathResult mismatch = validPath();
    when(mismatch.accountValueBytes()).thenReturn(Optional.of(Bytes.of(9)));
    assertThat(AccountEnumerationValidator.validate(List.of(entry(mismatch)), count(1)).isValid())
        .isFalse();
  }

  @Test
  void enumerationKeyTypeIsExactly32Bytes() {
    assertThat(KEY.size()).isEqualTo(32);
  }

  private static AccountEnumerationEntry entry(final AccountPathResult path) {
    return new AccountEnumerationEntry(KEY, VALUE, path);
  }

  private static ForestAccountLeafCounter.CountResult count(final int value) {
    return new ForestAccountLeafCounter.CountResult(AuditValidationStatus.VALID, value, "");
  }

  private static AccountPathResult path(final AuditValidationStatus status) {
    final AccountPathResult result = mock(AccountPathResult.class);
    when(result.status()).thenReturn(status);
    when(result.error()).thenReturn("fault");
    return result;
  }

  private static AccountPathResult validPath() {
    final AccountPathResult result = mock(AccountPathResult.class);
    when(result.status()).thenReturn(AuditValidationStatus.VALID);
    when(result.accountValueBytes()).thenReturn(Optional.of(VALUE));
    when(result.error()).thenReturn("");
    return result;
  }
}
