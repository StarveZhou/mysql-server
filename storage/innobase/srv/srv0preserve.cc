/*****************************************************************************

Copyright (c) 2026, Alibaba and/or its affiliates.

*****************************************************************************/

#include "srv0preserve.h"

#include "fil0types.h"
#include "lock0guards.h"
#include "mem0mem.h"
#include "os0file.h"
#include "srv0srv.h"
#include "trx0roll.h"
#include "trx0trx.h"
#include "ut0byte.h"
#include "ut0ut.h"

#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <tuple>
#include <vector>

namespace {

constexpr uint32_t PRESERVE_CAT_MAGIC = 0x50424341; /* PBCA */
constexpr uint32_t PRESERVE_CAT_VERSION = 1;

struct SpRec {
  uint32_t ordinal;
  undo_no_t boundary_undo;
  std::string name;
};

struct TrxPreserveState {
  undo_no_t last_boundary_undo{0};
  int32_t last_completed_stmt_epoch{-1};
  std::vector<preserve_cat_lock_rec_t> locks;
  std::vector<SpRec> sps;
  uint32_t next_lock_seq{1};
};

std::mutex g_preserve_mutex;
std::map<trx_id_t, TrxPreserveState> g_by_trx;

std::string preserve_path() {
  std::string p;
  p.assign(srv_data_home ? srv_data_home : ".");
  p.push_back(FIL_PATH_SEPARATOR);
  p.append("ib_preserve_trx.cat");
  return p;
}

static void write_u32(std::vector<byte> &b, uint32_t v) {
  b.push_back(static_cast<byte>(v & 0xFF));
  b.push_back(static_cast<byte>((v >> 8) & 0xFF));
  b.push_back(static_cast<byte>((v >> 16) & 0xFF));
  b.push_back(static_cast<byte>((v >> 24) & 0xFF));
}

static void write_u64(std::vector<byte> &b, uint64_t v) {
  for (int i = 0; i < 8; ++i) {
    b.push_back(static_cast<byte>((v >> (8 * i)) & 0xFF));
  }
}

static bool read_u32(const byte *&p, const byte *end, uint32_t &out) {
  if (p + 4 > end) return false;
  out = mach_read_from_4(p);
  p += 4;
  return true;
}

static bool read_u64(const byte *&p, const byte *end, uint64_t &out) {
  if (p + 8 > end) return false;
  out = mach_read_from_8(p);
  p += 8;
  return true;
}

static void rewrite_catalog_file() {
  std::vector<byte> buf;
  write_u32(buf, PRESERVE_CAT_MAGIC);
  write_u32(buf, PRESERVE_CAT_VERSION);
  write_u32(buf, static_cast<uint32_t>(g_by_trx.size()));
  for (const auto &kv : g_by_trx) {
    const trx_id_t trx_id = kv.first;
    const TrxPreserveState &st = kv.second;
    write_u64(buf, static_cast<uint64_t>(trx_id));
    write_u64(buf, static_cast<uint64_t>(st.last_boundary_undo));
    write_u32(buf, static_cast<uint32_t>(st.last_completed_stmt_epoch));
    write_u32(buf, static_cast<uint32_t>(st.locks.size()));
    for (const auto &lk : st.locks) {
      write_u32(buf, lk.seq);
      write_u32(buf, static_cast<uint32_t>(lk.grant_stmt_epoch));
      write_u64(buf, static_cast<uint64_t>(lk.grant_undo_no));
      write_u32(buf, lk.space_id);
      write_u32(buf, lk.page_no);
      write_u32(buf, lk.heap_no);
      write_u64(buf, lk.index_id);
      write_u32(buf, lk.type_mode);
    }
    write_u32(buf, static_cast<uint32_t>(st.sps.size()));
    for (const auto &sp : st.sps) {
      write_u32(buf, sp.ordinal);
      write_u64(buf, static_cast<uint64_t>(sp.boundary_undo));
      write_u32(buf, static_cast<uint32_t>(sp.name.size()));
      for (char c : sp.name) {
        buf.push_back(static_cast<byte>(c));
      }
    }
  }

  const std::string path = preserve_path();
  const std::string tmp = path + ".tmp";
  int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    ib::warn() << "ib_preserve_trx: cannot open " << tmp << ": " << strerror(errno);
    return;
  }
  ssize_t w = ::write(fd, buf.data(), buf.size());
  if (w != static_cast<ssize_t>(buf.size())) {
    ib::warn() << "ib_preserve_trx: short write";
    ::close(fd);
    return;
  }
  if (fsync(fd) != 0) {
    ib::warn() << "ib_preserve_trx: fsync failed";
  }
  ::close(fd);
  if (::rename(tmp.c_str(), path.c_str()) != 0) {
    ib::warn() << "ib_preserve_trx: rename failed: " << strerror(errno);
  }
}

static void load_catalog_file_into(std::map<trx_id_t, TrxPreserveState> *dst) {
  dst->clear();
  const std::string path = preserve_path();
  int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    return;
  }
  std::vector<byte> data;
  for (;;) {
    byte chunk[4096];
    ssize_t n = ::read(fd, chunk, sizeof(chunk));
    if (n <= 0) break;
    data.insert(data.end(), chunk, chunk + n);
  }
  ::close(fd);
  if (data.size() < 12) return;
  const byte *p = data.data();
  const byte *end = data.data() + data.size();
  uint32_t magic, ver, n_trx;
  if (!read_u32(p, end, magic) || magic != PRESERVE_CAT_MAGIC) return;
  if (!read_u32(p, end, ver) || ver != PRESERVE_CAT_VERSION) return;
  if (!read_u32(p, end, n_trx)) return;
  for (uint32_t ti = 0; ti < n_trx; ++ti) {
    uint64_t trx_id_u, last_boundary_u;
    uint32_t last_completed_u, n_locks, n_sps;
    if (!read_u64(p, end, trx_id_u)) return;
    if (!read_u64(p, end, last_boundary_u)) return;
    if (!read_u32(p, end, last_completed_u)) return;
    if (!read_u32(p, end, n_locks)) return;
    TrxPreserveState st;
    st.last_boundary_undo = static_cast<undo_no_t>(last_boundary_u);
    st.last_completed_stmt_epoch = static_cast<int32_t>(last_completed_u);
    for (uint32_t li = 0; li < n_locks; ++li) {
      uint32_t seq, gse, sid, pno, heap, tm;
      uint64_t gu, iid;
      if (!read_u32(p, end, seq) || !read_u32(p, end, gse) || !read_u64(p, end, gu) ||
          !read_u32(p, end, sid) || !read_u32(p, end, pno) || !read_u32(p, end, heap) ||
          !read_u64(p, end, iid) || !read_u32(p, end, tm))
        return;
      preserve_cat_lock_rec_t lk{};
      lk.seq = seq;
      lk.grant_stmt_epoch = static_cast<int32_t>(gse);
      lk.grant_undo_no = static_cast<undo_no_t>(gu);
      lk.space_id = sid;
      lk.page_no = pno;
      lk.heap_no = heap;
      lk.index_id = static_cast<space_index_t>(iid);
      lk.type_mode = tm;
      st.locks.push_back(lk);
      if (seq >= st.next_lock_seq) st.next_lock_seq = seq + 1;
    }
    if (!read_u32(p, end, n_sps)) return;
    for (uint32_t si = 0; si < n_sps; ++si) {
      uint32_t ord;
      uint64_t bud;
      uint32_t nlen;
      if (!read_u32(p, end, ord) || !read_u64(p, end, bud) || !read_u32(p, end, nlen))
        return;
      if (p + nlen > end) return;
      SpRec sp;
      sp.ordinal = ord;
      sp.boundary_undo = static_cast<undo_no_t>(bud);
      sp.name.assign(reinterpret_cast<const char *>(p), nlen);
      p += nlen;
      st.sps.push_back(sp);
    }
    (*dst)[static_cast<trx_id_t>(trx_id_u)] = std::move(st);
  }
}

} /* namespace */

void srv_preserve_catalog_boot() {
  std::lock_guard<std::mutex> g(g_preserve_mutex);
  g_by_trx.clear();
}

void srv_preserve_catalog_shutdown() {
  std::lock_guard<std::mutex> g(g_preserve_mutex);
  g_by_trx.clear();
  const std::string path = preserve_path();
  ::unlink(path.c_str());
}

bool srv_preserve_catalog_should_track(const trx_t *trx) {
  if (!srv_recover_preserve_trx) return false;
  if (trx == nullptr || trx->mysql_thd == nullptr) return false;
  if (trx->ddl_operation) return false;
  if (trx->dict_operation != TRX_DICT_OP_NONE) return false;
  if (!trx_is_started(trx)) return false;
  if (trx->state.load(std::memory_order_relaxed) != TRX_STATE_ACTIVE) return false;
  return true;
}

void srv_preserve_catalog_touch_trx(trx_t *trx) {
  std::lock_guard<std::mutex> g(g_preserve_mutex);
  if (!srv_preserve_catalog_should_track(trx)) return;
  const trx_id_t id = trx_get_id_for_print(trx);
  if (id == 0) return;
  if (g_by_trx.find(id) == g_by_trx.end()) {
    g_by_trx[id] = TrxPreserveState{};
    trx->preserve_stmt_epoch = 0;
  }
}

void srv_preserve_catalog_on_stmt_end(trx_t *trx) {
  std::lock_guard<std::mutex> g(g_preserve_mutex);
  if (!srv_preserve_catalog_should_track(trx)) return;
  const trx_id_t id = trx_get_id_for_print(trx);
  if (id == 0) return;
  auto it = g_by_trx.find(id);
  if (it == g_by_trx.end()) {
    g_by_trx[id] = TrxPreserveState{};
    trx->preserve_stmt_epoch = 0;
    it = g_by_trx.find(id);
  }
  std::vector<preserve_cat_lock_rec_t> new_locks;
  uint32_t next_seq = 1;
  {
    locksys::Global_exclusive_latch_guard lg{UT_LOCATION_HERE};
    trx_mutex_enter(trx);
    lock_preserve_catalog_reconcile_trx_locks(trx, it->second.locks, &new_locks,
                                                &next_seq);
    trx_mutex_exit(trx);
  }
  it->second.locks = std::move(new_locks);
  it->second.next_lock_seq = next_seq;
  it->second.last_boundary_undo = trx->undo_no;
  it->second.last_completed_stmt_epoch = trx->preserve_stmt_epoch;
  trx->preserve_stmt_epoch++;
  rewrite_catalog_file();
}

void srv_preserve_catalog_on_savepoint(trx_t *trx, const char *savepoint_name) {
  std::lock_guard<std::mutex> g(g_preserve_mutex);
  if (!srv_preserve_catalog_should_track(trx) || savepoint_name == nullptr) {
    return;
  }
  const trx_id_t id = trx_get_id_for_print(trx);
  if (id == 0) return;
  auto it = g_by_trx.find(id);
  if (it == g_by_trx.end()) {
    g_by_trx[id] = TrxPreserveState{};
    trx->preserve_stmt_epoch = 0;
    it = g_by_trx.find(id);
  }
  const std::string spn(savepoint_name);
  it->second.sps.erase(std::remove_if(it->second.sps.begin(), it->second.sps.end(),
                                      [&](const SpRec &r) { return r.name == spn; }),
                       it->second.sps.end());

  trx_named_savept_t *last = UT_LIST_GET_LAST(trx->trx_savepoints);
  ut_ad(last != nullptr);
  ut_ad(ut_strcmp(last->name, savepoint_name) == 0);

  SpRec rec;
  rec.ordinal = static_cast<uint32_t>(it->second.sps.size() + 1);
  rec.boundary_undo = last->savept.least_undo_no;
  rec.name = spn;
  it->second.sps.push_back(rec);
  rewrite_catalog_file();
}

void srv_preserve_catalog_resync_after_savepoint_op(trx_t *trx) {
  std::lock_guard<std::mutex> g(g_preserve_mutex);
  if (!srv_preserve_catalog_should_track(trx)) return;
  const trx_id_t id = trx_get_id_for_print(trx);
  if (id == 0) return;
  auto it = g_by_trx.find(id);
  if (it == g_by_trx.end()) {
    g_by_trx[id] = TrxPreserveState{};
    trx->preserve_stmt_epoch = 0;
    it = g_by_trx.find(id);
  }

  std::vector<preserve_cat_lock_rec_t> new_locks;
  uint32_t next_seq = 1;
  {
    locksys::Global_exclusive_latch_guard lg{UT_LOCATION_HERE};
    trx_mutex_enter(trx);
    lock_preserve_catalog_reconcile_trx_locks(trx, it->second.locks, &new_locks,
                                                &next_seq);
    trx_mutex_exit(trx);
  }
  it->second.locks = std::move(new_locks);
  it->second.next_lock_seq = next_seq;

  it->second.sps.clear();
  uint32_t ord = 1;
  for (trx_named_savept_t *sp = UT_LIST_GET_FIRST(trx->trx_savepoints);
       sp != nullptr; sp = UT_LIST_GET_NEXT(trx_savepoints, sp)) {
    SpRec r;
    r.ordinal = ord++;
    r.boundary_undo = sp->savept.least_undo_no;
    r.name = sp->name;
    it->second.sps.push_back(r);
  }
  rewrite_catalog_file();
}

void srv_preserve_catalog_on_trx_end(trx_id_t trx_id) {
  if (trx_id == 0) return;
  std::lock_guard<std::mutex> g(g_preserve_mutex);
  g_by_trx.erase(trx_id);
  rewrite_catalog_file();
}

void srv_preserve_catalog_recovery_apply() {
  if (!srv_recover_preserve_trx) {
    return;
  }

  std::map<trx_id_t, TrxPreserveState> snapshot;
  {
    std::lock_guard<std::mutex> g(g_preserve_mutex);
    load_catalog_file_into(&snapshot);
  }
  if (snapshot.empty()) {
    return;
  }

  ib::info() << "ib_preserve_trx: applying catalog for " << snapshot.size()
             << " transaction(s)";

  std::vector<trx_t *> candidates;
  trx_sys_mutex_enter();
  for (trx_t *trx : trx_sys->rw_trx_list) {
    if (!trx->is_recovered || trx->ddl_operation) continue;
    if (trx_state_eq(trx, TRX_STATE_PREPARED) ||
        trx_state_eq(trx, TRX_STATE_COMMITTED_IN_MEMORY) ||
        !trx_state_eq(trx, TRX_STATE_ACTIVE)) {
      continue;
    }
    const trx_id_t id = trx_get_id_for_print(trx);
    if (snapshot.find(id) == snapshot.end()) {
      continue;
    }
    candidates.push_back(trx);
  }
  trx_sys_mutex_exit();

  for (trx_t *trx : candidates) {
    const trx_id_t id = trx_get_id_for_print(trx);
    auto sit = snapshot.find(id);
    ut_a(sit != snapshot.end());
    TrxPreserveState &st = sit->second;

    trx_savept_t sp{};
    sp.least_undo_no = st.last_boundary_undo;
    trx_rollback_to_savepoint(trx, &sp);

    std::vector<preserve_cat_lock_rec_t> locks_kept;
    for (const auto &lk : st.locks) {
      if (lk.grant_stmt_epoch > st.last_completed_stmt_epoch) {
        continue;
      }
      locks_kept.push_back(lk);
    }

    for (const auto &lk : locks_kept) {
      lock_preserve_catalog_replay_row_lock(trx, lk.space_id, lk.page_no,
                                            lk.heap_no, lk.index_id,
                                            static_cast<ulint>(lk.type_mode));
    }

    trx_roll_savepoints_free(trx, UT_LIST_GET_FIRST(trx->trx_savepoints));

    for (const auto &sr : st.sps) {
      if (sr.boundary_undo > st.last_boundary_undo) {
        continue;
      }
      trx_named_savept_t *news =
          static_cast<trx_named_savept_t *>(ut::malloc_withkey(
              UT_NEW_THIS_FILE_PSI_KEY, sizeof(trx_named_savept_t)));
      news->name = mem_strdup(sr.name.c_str());
      news->savept.least_undo_no = sr.boundary_undo;
      news->mysql_binlog_cache_pos = 0;
      UT_LIST_ADD_LAST(trx->trx_savepoints, news);
    }

    uint32_t rseq = 1;
    for (auto &lk : locks_kept) {
      lk.seq = rseq++;
    }
    st.locks = std::move(locks_kept);
    st.next_lock_seq = rseq;
  }

  {
    std::lock_guard<std::mutex> g(g_preserve_mutex);
    g_by_trx.swap(snapshot);
    rewrite_catalog_file();
  }
}
