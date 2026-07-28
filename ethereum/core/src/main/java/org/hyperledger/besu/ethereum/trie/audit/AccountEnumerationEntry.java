/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.hyperledger.besu.ethereum.trie.audit;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/** One account leaf observed by the preferred Forest enumeration API. */
public record AccountEnumerationEntry(
    Bytes32 key, Bytes accountValue, AccountPathResult authenticatedPath) {}
