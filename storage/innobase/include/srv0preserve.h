/*****************************************************************************

Copyright (c) 2026, Alibaba and/or its affiliates.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License, version 2.0.

*****************************************************************************/

/** @file include/srv0preserve.h
 Persisted safe-boundary + savepoint + row-lock catalog for recover_preserve_trx
 (datadir file, not DD tables — first implementation). */

#ifndef srv0preserve_h
#define srv0preserve_h

#include <vector>

#include "dict0types.h"
#include "trx0types.h"
#include "univ.i"

struct trx_t;

/** One cataloged explicit record lock (granted). */
struct preserve_cat_lock_rec_t {
  uint32_t seq;
  int32_t grant_stmt_epoch;
  undo_no_t grant_undo_no;
  space_id_t space_id;
  page_no_t page_no;
  uint32_t heap_no;
  space_index_t index_id;
  uint32_t type_mode;
};

/** Rebuild catalog lock rows from current trx locks; keep grant epochs for rows
that existed in prev. Caller must hold lock_sys global X latch and trx->mutex.
@param[in] trx          Transaction
@param[in] prev         Previous catalog rows for this trx
@param[out] out        New rows (replaces full list)
@param[out] next_seq_io First unused seq (1-based) after rebuild */
void lock_preserve_catalog_reconcile_trx_locks(
    trx_t *trx, const std::vector<preserve_cat_lock_rec_t> &prev,
    std::vector<preserve_cat_lock_rec_t> *out, uint32_t *next_seq_io);

/** Recovery: re-grant one cataloged row lock. Safe without dict mutex during IO. */
void lock_preserve_catalog_replay_row_lock(trx_t *trx, space_id_t space_id,
                                           page_no_t page_no, ulint heap_no,
                                           space_index_t index_id,
                                           ulint type_mode);

/** Init mutex; call once srv_data_home is known. */
void srv_preserve_catalog_boot();
void srv_preserve_catalog_shutdown();

/** True if this transaction should append to the catalog (user trx, preserve on).
 */
bool srv_preserve_catalog_should_track(const trx_t *trx);

/** Ensure trx has in-memory state (call before first stmt/lock/savepoint). */
void srv_preserve_catalog_touch_trx(trx_t *trx);

/** After successful SQL statement end (trx_mark_sql_stat_end). */
void srv_preserve_catalog_on_stmt_end(trx_t *trx);

/** After named SAVEPOINT created (trx_savepoint_for_mysql). */
void srv_preserve_catalog_on_savepoint(trx_t *trx, const char *savepoint_name);

/** After ROLLBACK TO / RELEASE SAVEPOINT: rebuild lock list + SP list from trx.
 */
void srv_preserve_catalog_resync_after_savepoint_op(trx_t *trx);

/** Transaction committed or rolled back fully — remove from catalog. */
void srv_preserve_catalog_on_trx_end(trx_id_t trx_id);

/** Crash recovery: rollback to safe undo + trim locks + replay row locks +
    restore savepoints. Call once after trx_resurrect_locks(all). */
void srv_preserve_catalog_recovery_apply();

#endif /* srv0preserve_h */
