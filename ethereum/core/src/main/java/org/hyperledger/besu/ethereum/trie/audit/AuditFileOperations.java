/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

@FunctionalInterface
interface AuditFileOperations {
  Path move(Path source, Path target, StandardCopyOption... options) throws IOException;

  static AuditFileOperations system() {
    return FilesAdapter::move;
  }

  final class FilesAdapter {
    private FilesAdapter() {}

    private static Path move(
        final Path source, final Path target, final StandardCopyOption... options) throws IOException {
      return java.nio.file.Files.move(source, target, options);
    }
  }
}
