/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import org.hyperledger.besu.ethereum.trie.MerkleTrie;
import org.hyperledger.besu.ethereum.trie.TrieIterator;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/** Complete account enumeration using StoredMerkleTrie.visitLeafs. */
public final class ForestAccountEnumerator {
  private ForestAccountEnumerator() {}

  public static EnumerationResult enumerate(
      final MerkleTrie<Bytes32, Bytes> trie,
      final Function<Bytes32, AccountPathResult> authenticatedLookup) {
    return enumerate(trie, authenticatedLookup, null);
  }

  public static EnumerationResult enumerate(
      final MerkleTrie<Bytes32, Bytes> trie,
      final Function<Bytes32, AccountPathResult> authenticatedLookup,
      final Phase4FDiagnostics diagnostics) {
    final List<AccountEnumerationEntry> entries = new ArrayList<>();
    try {
      if (diagnostics != null) {
        diagnostics.stage("visitLeafs_enumeration_and_account_authentication");
        diagnostics.countOperation("visitLeafs");
      }
      trie.visitLeafs(
          (key, node) -> {
            final Bytes value = node.getValue().orElseThrow();
            if (diagnostics != null) diagnostics.enumerated();
            entries.add(new AccountEnumerationEntry(key, value, authenticatedLookup.apply(key)));
            if (diagnostics != null) diagnostics.authenticated();
            return TrieIterator.State.CONTINUE;
          });
    } catch (final RuntimeException ex) {
      return new EnumerationResult(
          AuditValidationStatus.MALFORMED,
          List.copyOf(entries),
          new ForestAccountLeafCounter.CountResult(AuditValidationStatus.MALFORMED, -1, ex.getMessage()),
          new AccountEnumerationValidator.ValidationResult(
              AuditValidationStatus.MALFORMED, -1, -1, 0, ex.getMessage()),
          java.util.Map.of(),
          java.util.Map.of(),
          ex.getMessage());
    }

    if (diagnostics != null) {
      diagnostics.stage("independent_visitAll_terminal_count");
      diagnostics.countOperation("visitAll");
    }
    final ForestAccountLeafCounter.CountResult independent = ForestAccountLeafCounter.count(trie);
    final AccountEnumerationValidator.ValidationResult validation =
        AccountEnumerationValidator.validate(entries, independent);
    if (diagnostics != null) {
      diagnostics.stage("node_form_observation");
      diagnostics.countOperation("visitAll_node_forms");
    }
    final ForestAccountEnumerationProbe.NodeFormReport nodeForms =
        ForestAccountEnumerationProbe.observeNodeForms(trie);
    return new EnumerationResult(
        validation.status(),
        List.copyOf(entries),
        independent,
        validation,
        nodeForms.nodeKinds(),
        nodeForms.referenceKinds(),
        validation.error());
  }

  public record EnumerationResult(
      AuditValidationStatus status,
      List<AccountEnumerationEntry> entries,
      ForestAccountLeafCounter.CountResult independentCount,
      AccountEnumerationValidator.ValidationResult validation,
      java.util.Map<ForestAccountEnumerationProbe.NodeKind, Integer> nodeKinds,
      java.util.Map<ForestAccountEnumerationProbe.ReferenceKind, Integer> referenceKinds,
      String error) {
    public boolean isValid() {
      return status == AuditValidationStatus.VALID;
    }
  }
}
