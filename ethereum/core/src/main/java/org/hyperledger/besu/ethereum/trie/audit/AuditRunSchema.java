/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package org.hyperledger.besu.ethereum.trie.audit;

/** Version constants for the account-audit persistence foundation. */
public final class AuditRunSchema {
  public static final String RUN_SCHEMA = "audit_account_run_v1";
  public static final String CHECKPOINT_SCHEMA = "audit_checkpoint_v1";
  public static final String PATH_FRAGMENT_SCHEMA = "audit_path_summary_v1";
  public static final String RETAINED_FRAGMENT_SCHEMA = "audit_retained_paths_v1";
  public static final String ERROR_FRAGMENT_SCHEMA = "audit_errors_v1";
  public static final String STATE_FRAGMENT_SCHEMA = "audit_state_summary_v1";
  public static final String CHECKPOINT_FORMAT = "checkpoint_format_v1";
  public static final String RUN_SCHEMA_V2 = "audit_account_run_v2";
  public static final String CHECKPOINT_SCHEMA_V2 = "audit_checkpoint_v2";
  public static final String PATH_FRAGMENT_SCHEMA_V2 = "audit_path_summary_v2";
  public static final String RETAINED_FRAGMENT_SCHEMA_V2 = "audit_retained_paths_v2";
  public static final String ERROR_FRAGMENT_SCHEMA_V2 = "audit_errors_v2";
  public static final String STATE_FRAGMENT_SCHEMA_V2 = "audit_state_summary_v2";
  public static final String CHECKPOINT_FORMAT_V2 = "checkpoint_format_v2";
  public static final String GLOBAL_SUMMARY_SCHEMA_V1 = "audit_global_summary_v1";
  public static final String SCHEDULE_SCHEMA_V1 = "audit_schedule_v1";

  private AuditRunSchema() {}
}
