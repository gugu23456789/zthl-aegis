#!/usr/bin/env python3
"""gk_state_wal.py — state 写路径的 WAL + checkpoint（M1，2026-11-03）。

背景（`docs/analysis/2026-11-03-bench-408-research.md` 实测）：
  `update_state` 每次逻辑写都整份序列化 + `os.replace` ⟹ 写放大 = state 大小 / payload
  （128 KB 读 128.2x、512 KB 读 512.2x，512 KB × 32 writers 出现 5s 锁超时）。
  主线 §2-M1 把写路径改为「追加 WAL 记录 + 周期 checkpoint」。

形态
====
  · WAL：`<state>.wal`（`{seq, pid, ts, ops, crc}` 一行一条逻辑写；`ops` = 该次写的增量集合）
  · checkpoint：每 `CHECKPOINT_RECORDS` 条或 `CHECKPOINT_BYTES` 字节，整份 `dump_state` 后截断 WAL
  · 读路径：**先读 WAL、再读 state**，按 `state._wal_seq` 跳过已入 checkpoint 的记录
  · `_wal_seq` 写在 state 顶层（`_checksum` 只覆盖 `gate_data` ⟹ 不改变校验语义）

为什么「先 WAL 后 state」：checkpoint = 先原子换 state、再截断 WAL。读侧若先拿 WAL
再做旧 state，恰好是「旧快照 + 新记录」= 正确；反之（先 state 后 WAL）会读到「新
state + 旧 WAL」，而 `_wal_seq` 只能挡住 seq ≤ checkpoint 的记录，挡不住这一组合。
两者叠加才构成安全读序。

幂等性：记录是**绝对赋值**（`set` / `del` / `extend`），重放同一 seq 结果不变。
失败语义：WAL 追加失败 **fail-loud**（返回 `{"error": "wal_write_failed: ..."}`），
不静默降级为整份写；checkpoint 失败则保留 WAL（记录仍可重放）。

进程退出：本进程写过的 state 在 atexit 时若 WAL 里仍有**本 pid** 的记录，则做一次
checkpoint —— 保证「CLI 子进程退出后，磁盘上的 state 就是最新完整 JSON」，不改变
bash / 外部工具「直接 json.load state」的既有契约。
"""
import atexit
import copy
import glob
import hashlib
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import gk_json_utils as J

WAL_SUFFIX = ".wal"

# checkpoint 触发（保守取值：先保证正确性，再按实测调优；见计划 §2-M1）
CHECKPOINT_RECORDS = 200
CHECKPOINT_BYTES = 1 << 20          # 1 MB
# 长驻进程的**陈旧上限**：最老的未 checkpoint 记录超过此秒数，下一次写就顺手 checkpoint。
# 目的：把「bash / 外部 raw 读者看到旧 checkpoint」的窗口限制在数秒内（配合退出 flush）。
CHECKPOINT_MAX_AGE_S = 5.0
# S2：后台周期 tick（idle 长驻进程也要把超龄 WAL 折回 state；不再依赖「下一次写」）。
IDLE_TICK_S = 2.0
# idle 折盘的年龄门限：**刻意大于** `CHECKPOINT_MAX_AGE_S`。原因（实测）：短命 writer 写几笔就
# 停手，若沿用 5s，32 writers 基准里多个进程会各做一次整份 checkpoint ⟹ 锁争用把 p99 从
# ~0.9s 推到 1.1–1.4s。它们本来就会在退出时 flush；长驻进程的「完全 idle」窗口用 30s 收口。
IDLE_CHECKPOINT_AGE_S = 30.0
# S2：`.tmp` 残留回收（崩溃遗留）。宽限期必须远大于一次 dump_state 的最慢耗时。
GC_TMP_GRACE_S = 600.0
GC_TMP_EVERY_S = 60.0               # 每个 state 至多每 60s 扫一次（避免每次写都 glob）

_TOUCHED: set = set()               # 本进程写过的 state（realpath）
_ATEXIT_REGISTERED = False
_GC_LAST: dict = {}                 # state key -> 上次扫 .tmp 的时刻
_LAST_WRITE: dict = {}              # state key -> 本进程最后一次追加的 monotonic 时刻
_TIMER = {"thread": None, "stop": None}

# checkpoint 解析缓存（**仅写路径**，进程内；键 = state 的 (mtime_ns, size)）。
# 为什么安全：所有 checkpoint / 截断都在 `state_lock` 内；锁外的 state 变更必然换文件
# （`os.replace`）⟹ mtime 变 ⟹ 缓存失效。读路径（`read_state`）**不走**缓存。
_CHECKPOINT_CACHE: dict = {}

# 95% 墙闸的**保守快路径**：raw 体积 ×4 仍低于 95% 水位时，才跳过精确 canon 计算
# （canon ≤ 4×raw 对 JSON 文本是宽松上界；贴近墙时仍走 `_wall_guard` 精确判据）。
_WALL_SKIP_FACTOR = 4


def wal_path(state_path) -> str:
    """WAL 单源路径：`<state>.wal`（与 `<state>.lock` 同址同级）。"""
    return str(state_path) + WAL_SUFFIX


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _age_s(ts) -> float:
    """记录时间戳到现在的秒数；解析失败 → 0（不因坏 ts 触发额外 checkpoint）。"""
    try:
        t = datetime.strptime(str(ts), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return 0.0
    return (datetime.now(timezone.utc) - t).total_seconds()


def _body(seq: int, pid: int, ts: str, ops: list) -> dict:
    return {"seq": int(seq), "pid": int(pid), "ts": ts, "ops": ops}


def _crc(body: dict) -> str:
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# ── 增量（recursive diff）────────────────────────────────────────────────────
def diff(old, new, path=None) -> list:
    """old → new 的最小赋值集合（dict 递归；list 追加走 extend，其余整段 set）。"""
    path = [] if path is None else path
    ops = []
    if isinstance(old, dict) and isinstance(new, dict):
        for k in new:
            if k not in old:
                ops.append({"op": "set", "path": path + [k], "value": new[k]})
            else:
                ops.extend(diff(old[k], new[k], path + [k]))
        for k in old:
            if k not in new:
                ops.append({"op": "del", "path": path + [k]})
        return ops
    if isinstance(old, list) and isinstance(new, list):
        n = len(old)
        if len(new) >= n and new[:n] == old:
            if len(new) > n:
                ops.append({"op": "extend", "path": path, "value": new[n:]})
            return ops
    if old != new:
        ops.append({"op": "set", "path": path, "value": new})
    return ops


def apply_ops(data: dict, ops: list) -> dict:
    """把记录里的增量应用到 data（原地）；未知 op ⟹ ValueError（fail-loud）。"""
    for o in ops or []:
        if not isinstance(o, dict):
            raise ValueError("wal: op 不是对象: %r" % (o,))
        op = o.get("op")
        path = o.get("path") or []
        if not path:
            if op != "set":
                raise ValueError("wal: 根路径只允许 set: %r" % (o,))
            data = o.get("value")
            continue
        cur = data
        for key in path[:-1]:
            cur = cur[key]
        last = path[-1]
        if op == "set":
            cur[last] = o.get("value")
        elif op == "del":
            if isinstance(cur, dict):
                cur.pop(last, None)
            else:
                del cur[last]
        elif op == "extend":
            cur[last].extend(o.get("value") or [])
        else:
            raise ValueError("wal: 未知 op=%r" % (op,))
    return data


# ── 记录 I/O ─────────────────────────────────────────────────────────────────
# 进程内文件句柄缓存（2026-11-03 M1 压测）：Windows 上每次 open/close ~1ms，而并发基准的
# 临界区只有几毫秒 ⟹ 句柄按 realpath 复用。WAL 只**截断**不替换（inode 稳定），fd 恒有效。
# 读侧**每次从 0 读全量**：checkpoint 会截断，跨进程的续读偏移无法可靠判定「是否已截断」，
# 续读会静默丢记录（实测 32 writers 丢 383 条）；WAL ≤ CHECKPOINT_BYTES，全量读是安全代价。
_READ_FD: dict = {}      # realpath -> fd
_APPEND_FD: dict = {}    # realpath -> fd
_WAL_REAL: dict = {}     # wal_path -> realpath（Windows realpath ~1ms ⟹ 缓存）


def _wal_real(state_path) -> str:
    s = wal_path(state_path)
    rp = _WAL_REAL.get(s)
    if rp is None:
        rp = os.path.realpath(s)
        _WAL_REAL[s] = rp
    return rp


def read_records(state_path) -> tuple:
    """→ (records, torn_line, wal_bytes)。torn_line > 0 表示首个坏行（JSON 坏 / crc 不符）。

    坏行之前的记录照常返回；坏行之后的记录**丢弃**（顺序语义优先于「尽量多救」）。
    尾部半行 = 崩溃时的正常形态；它会在下一次写时被 checkpoint 修复。
    """
    key = _wal_real(state_path)
    ent = _READ_FD.get(key)
    if ent is None:
        try:
            ent = os.open(key, os.O_RDONLY)
        except OSError:
            return [], 0, 0
        _READ_FD[key] = ent
    try:
        size = os.fstat(ent).st_size          # 比 getsize(path) 少一次路径解析
    except OSError:
        return [], 0, 0
    if size == 0:
        return [], 0, 0
    try:
        os.lseek(ent, 0, os.SEEK_SET)
        chunks = []
        remain = size
        while remain > 0:
            b = os.read(ent, remain)
            if not b:
                break
            chunks.append(b)
            remain -= len(b)
        raw = b"".join(chunks)
    except OSError:
        return [], 0, size
    recs, torn = [], 0
    for i, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
            body = {k: rec[k] for k in ("seq", "pid", "ts", "ops")}
        except (ValueError, KeyError, TypeError):
            torn = torn or i
            continue
        if rec.get("crc") != _crc(body):
            torn = torn or i
            continue
        if torn:
            continue
        recs.append(body)
    return recs, torn, size


def append_record(state_path, seq: int, pid: int, ops: list) -> int:
    """追加一条记录（**只 write，不 fsync**），返回 fd；失败 ⟹ OSError 上抛。

    fsync 由调用方在**释放 state_lock 之后**执行（见 `update_state`）：落盘顺序不变
    （write 已在锁内完成、顺序已定），但把 Windows 上 ~2ms 的 FlushFileBuffers 移出临界区。
    """
    body = _body(seq, pid, _now(), ops)
    body["crc"] = _crc(body)
    line = json.dumps(body, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")) + "\n"
    key = _wal_real(state_path)
    fd = _APPEND_FD.get(key)
    if fd is None:
        d = os.path.dirname(key)
        if d:
            os.makedirs(d, exist_ok=True)
        fd = os.open(key, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o644)
        _APPEND_FD[key] = fd
    os.write(fd, line.encode("utf-8"))
    return fd


def truncate(state_path) -> bool:
    """截断 WAL（checkpoint 成功后调用）；失败不抛（残留记录会被 `_wal_seq` 挡住）。"""
    key = _wal_real(state_path)
    try:
        with open(key, "r+b") as f:
            f.truncate(0)
    except OSError:
        return False
    return True


# ── S2：`.tmp` 残留回收（崩溃遗留）──────────────────────────────────────────
def gc_tmp(state_path, grace_s=GC_TMP_GRACE_S, now=None) -> int:
    """回收 `<state>.*.tmp` 中**超过宽限期**的残留，返回删除数。

    `mkstemp` 名不含 pid ⟹ 只能按 mtime 判活：宽限期必须大于一次 `dump_state` 的最慢耗时，
    正在写的 tmp 不会被误删；真正的崩溃残留（数分钟前）在下一次写/tick 时被清掉。
    """
    n = 0
    cutoff = float(now if now is not None else time.time()) - float(grace_s)
    for f in glob.glob(str(state_path) + ".*.tmp"):
        try:
            if os.path.getmtime(f) <= cutoff:
                os.unlink(f)
                n += 1
        except OSError:
            continue
    return n


def _maybe_gc_tmp(state_path, now=None) -> int:
    """节流版 gc（每 state 至多 `GC_TMP_EVERY_S` 一次）；调用方须持锁或确保无并发写。"""
    t = float(now if now is not None else time.time())
    key = J._lock_key(state_path)
    last = _GC_LAST.get(key)
    if last is not None and (t - last) < GC_TMP_EVERY_S:
        return 0
    _GC_LAST[key] = t
    return gc_tmp(state_path, now=t)


def _replay(data: dict, recs: list, base: int) -> tuple:
    last = int(base or 0)
    for r in recs:
        s = int(r.get("seq", 0) or 0)
        if s <= last:
            continue
        apply_ops(data, r.get("ops") or [])
        last = s
    return data, last


def read_state(state_path) -> dict:
    """WAL-aware 读：state（checkpoint）+ WAL replay。缺失/损坏 → `{"error": ...}`。"""
    recs, torn, _ = read_records(state_path)
    d = J.read_json_file(state_path)          # 顺序：先 WAL、后 state（见模块头）
    if "error" in d:
        return d
    base = int(d.get("_wal_seq", 0) or 0)
    # checkpoint 自身的完整性只在「确有新记录要重放」时先判一次（重放会合法地改 gate_data）。
    stale_sum = d.get("_checksum")
    has_new = any(int(r.get("seq", 0) or 0) > base for r in recs)
    tampered = bool(stale_sum and has_new) and stale_sum != J._state_checksum(d)
    try:
        d, last = _replay(d, recs, base)
    except (KeyError, IndexError, TypeError, ValueError) as e:
        return {"error": "wal_replay_failed: %s: %s" % (type(e).__name__, e)}
    if last > base:
        # WAL 记录带 crc；重放后的 gate_data 才是权威值 ⟹ 刷新 `_checksum`。
        d["_checksum"] = J._state_checksum(d)
        if tampered:
            d["_checksum_warning"] = "checkpoint checksum mismatch（重放前已检出）"
        d["_wal_seq"] = last
    if torn:
        d["_wal_warning"] = ("wal: line %d 非法（JSON/crc），其后的记录未重放" % torn)
    return d


def _checkpoint(state_path, data: dict, seq: int, checksum_fn) -> bool:
    """整份落盘（重算 `_checksum`）并把 `_wal_seq` 推进到 seq；成功后截断 WAL。"""
    data = dict(data)
    data["_checksum"] = checksum_fn(data)
    data["_wal_seq"] = int(seq)
    if not J.dump_state(state_path, data):
        return False                            # WAL 保留 ⟹ 记录仍可重放
    truncate(state_path)
    _CHECKPOINT_CACHE.pop(J._lock_key(state_path), None)
    return True


def _load_checkpoint(state_path) -> tuple:
    """→ (checkpoint dict, 磁盘字节数)。进程内按 mtime/size 缓存解析结果（返回可变副本）。"""
    key = J._lock_key(state_path)
    try:
        st = os.stat(key)
        sig = (st.st_mtime_ns, st.st_size)
    except OSError:
        return J.read_json_file(state_path), 0
    ent = _CHECKPOINT_CACHE.get(key)
    if ent and ent.get("st") == sig:
        return copy.deepcopy(ent["data"]), st.st_size
    d = J.read_json_file(state_path)
    if "error" not in d:
        _CHECKPOINT_CACHE[key] = {"st": sig, "data": copy.deepcopy(d)}
    return d, st.st_size


def _near_wall(state_size: int, wal_bytes: int) -> bool:
    """是否贴近 95% 水位（否则跳过精确 canon 计算）；读不到体积 ⟹ 按贴近处理。"""
    raw = int(state_size) + int(wal_bytes)
    if raw <= 0:
        return True
    return raw * _WALL_SKIP_FACTOR >= J.STATE_SIZE_WALL * J.WALL_BLOCK_PCT // 100


# ── 写路径 ───────────────────────────────────────────────────────────────────
def update_state(path, mutator, checksum_fn) -> dict:
    """`gk_json_utils.update_state` 的 WAL 实现（调用方已持有/将持有 state_lock）。"""
    fd = None
    result = None
    with J.state_lock(path):
        recs, torn, wal_bytes = read_records(path)
        d, state_size = _load_checkpoint(path)
        if "error" in d:
            return d
        _maybe_gc_tmp(path)                     # S2：顺手回收崩溃遗留的陈旧 .tmp
        base = int(d.get("_wal_seq", 0) or 0)
        d, last = _replay(d, recs, base)
        if torn:
            # 坏行之后的记录已丢弃 ⟹ 先 checkpoint 修好 WAL，再追加新记录。
            if not _checkpoint(path, d, last, checksum_fn):
                return {"error": "wal_repair_failed: %s" % path}

        old = copy.deepcopy(d)                  # 增量基线（mutator 会原地改 d）
        out = mutator(d)
        if out is not None:
            d = out
        # `_checksum` **不**逐条重算：WAL 记录自带 crc，checkpoint 时统一重算（O(S) 摊销）。
        if _near_wall(state_size, wal_bytes):
            J._wall_guard(path, d, old_data=old)    # 贴近 95% 时保持原拦截语义

        seq = last + 1
        try:
            fd = append_record(path, seq, os.getpid(), diff(old, d, []))
        except OSError as e:
            return {"error": "wal_write_failed: %s: %s" % (type(e).__name__, e)}

        d["_wal_seq"] = seq
        _TOUCHED.add(J._lock_key(path))
        _LAST_WRITE[J._lock_key(path)] = time.monotonic()
        _ensure_atexit()
        _ensure_timer()                         # S2：idle 长驻进程也要周期 checkpoint

        pending = sum(1 for r in recs if int(r.get("seq", 0) or 0) > base) + 1
        # 陈旧上限：只看**最老**的一条未 checkpoint 记录（seq 递增 ⟹ 首条即最老）。
        stale = False
        for _r in recs:
            if int(_r.get("seq", 0) or 0) > base:
                stale = _age_s(_r.get("ts")) >= CHECKPOINT_MAX_AGE_S
                break
        try:
            wal_bytes = os.path.getsize(wal_path(path))
        except OSError:
            pass
        if pending >= CHECKPOINT_RECORDS or wal_bytes >= CHECKPOINT_BYTES or stale:
            _checkpoint(path, d, seq, checksum_fn)  # 失败 ⟹ 保留 WAL（数据仍可重放）
        result = {"ok": True, "data": d}

    try:
        os.fsync(fd)                            # 锁外落盘：顺序已由锁内 write 决定
    except OSError as e:
        return {"error": "wal_fsync_failed: %s: %s" % (type(e).__name__, e)}
    return result


# ── 进程退出：把「本进程留下的 WAL」折回 state ────────────────────────────────
def flush_pending(state_path) -> dict:
    """本进程在 WAL 里还有记录 ⟹ checkpoint 一次；否则零写盘。"""
    key = J._lock_key(state_path)
    if not os.path.isfile(state_path):        # state 已被删除 ⟹ 不重建目录/锁文件
        _TOUCHED.discard(key)
        return {"ok": True, "flushed": False}
    try:
        with J.state_lock(state_path):
            recs, _, _ = read_records(state_path)
            mine = [r for r in recs if int(r.get("pid", 0) or 0) == os.getpid()]
            if not mine:
                _TOUCHED.discard(key)
                return {"ok": True, "flushed": False}
            d = J.read_json_file(state_path)
            if "error" in d:
                return {"ok": False, "flushed": False, "error": d["error"]}
            base = int(d.get("_wal_seq", 0) or 0)
            d, last = _replay(d, recs, base)
            ok = _checkpoint(state_path, d, last, J._state_checksum)
            _TOUCHED.discard(key)
            _LAST_WRITE.pop(key, None)
            return {"ok": bool(ok), "flushed": True, "seq": last}
    except TimeoutError as e:
        return {"ok": False, "flushed": False, "error": "lock_timeout: %s" % e}


def checkpoint_if_stale(state_path, max_age_s=None) -> dict:
    """**无新写**也要把超龄 WAL 折回 state（后台 tick / 外部调用）。

    与 `flush_pending` 的区别：不要求记录属于本进程 —— 只按「最老未 checkpoint 记录是否超龄」
    判定。取锁用短超时（1s）：拿不到就下一次 tick 再试，不阻塞调用方。
    """
    max_age_s = IDLE_CHECKPOINT_AGE_S if max_age_s is None else max_age_s
    key = J._lock_key(state_path)
    if not os.path.isfile(state_path):
        _TOUCHED.discard(key)
        return {"ok": True, "flushed": False}
    try:
        with J.state_lock(state_path, timeout=1.0):
            _maybe_gc_tmp(state_path)
            recs, _, _ = read_records(state_path)
            pending = [r for r in recs
                       if _age_s(r.get("ts")) >= float(max_age_s)]
            if not pending:
                return {"ok": True, "flushed": False}
            d = J.read_json_file(state_path)
            if "error" in d:
                return {"ok": False, "flushed": False, "error": d["error"]}
            base = int(d.get("_wal_seq", 0) or 0)
            d, last = _replay(d, recs, base)
            ok = _checkpoint(state_path, d, last, J._state_checksum)
            return {"ok": bool(ok), "flushed": True, "seq": last}
    except TimeoutError as e:
        return {"ok": False, "flushed": False, "error": "lock_timeout: %s" % e}


def _own_pending_stale(state_path, max_age_s) -> bool:
    """**锁外**轻量判定：本进程是否有超龄未 checkpoint 记录。

    32 writers 场景下每个进程都有 tick；若 tick 直接抢锁（旧实现）会与写路径争锁，
    实测把 512 KB × 32 writers 的 p99 从 ~700ms 推到 ~1100ms。这里先无锁读 WAL
    （只读、不写、不改状态），**只有**确有本进程超龄记录时才进锁 checkpoint。
    """
    try:
        recs, _, _ = read_records(state_path)
    except OSError:
        return False
    pid = os.getpid()
    return any(int(r.get("pid", 0) or 0) == pid
               and _age_s(r.get("ts")) >= float(max_age_s) for r in recs)


def _timer_tick() -> None:                      # pragma: no cover - 后台线程
    stop = _TIMER.get("stop")
    while stop is not None and not stop.is_set():
        now = time.monotonic()
        for key, last in list(_LAST_WRITE.items()):
            if (now - last) < IDLE_CHECKPOINT_AGE_S:
                continue                        # 仍在写 ⟹ 零 I/O、零锁
            try:
                if _own_pending_stale(key, IDLE_CHECKPOINT_AGE_S):
                    r = checkpoint_if_stale(key)
                    if r.get("ok") and r.get("flushed"):
                        _LAST_WRITE.pop(key, None)
            except Exception as e:              # noqa: BLE001 — tick 不得打死线程
                sys.stderr.write("WARN[state-wal] idle checkpoint 异常: %s (%s: %s)\n"
                                 % (key, type(e).__name__, e))
        stop.wait(IDLE_TICK_S)


def _ensure_timer() -> None:
    if _TIMER.get("thread") is not None:
        return
    stop = threading.Event()
    t = threading.Thread(target=_timer_tick, name="gk-state-wal-idle", daemon=True)
    _TIMER["stop"] = stop
    _TIMER["thread"] = t
    t.start()


def shutdown_timer(timeout=2.0) -> None:
    """停后台 tick（测试 / 显式收尾用）；幂等。"""
    stop = _TIMER.get("stop")
    if stop is not None:
        stop.set()
    t = _TIMER.get("thread")
    if t is not None:
        t.join(timeout=timeout)
    _TIMER["stop"] = None
    _TIMER["thread"] = None


def _ensure_atexit() -> None:
    global _ATEXIT_REGISTERED
    if _ATEXIT_REGISTERED:
        return
    _ATEXIT_REGISTERED = True
    atexit.register(_flush_at_exit)


def _flush_at_exit() -> None:                   # pragma: no cover - 退出钩子
    for path in list(_TOUCHED):
        try:
            r = flush_pending(path)
            if not r.get("ok"):
                sys.stderr.write("WARN[state-wal] 退出 checkpoint 未完成: %s (%s)\n"
                                 % (path, r.get("error", "dump_state=False")))
        except Exception as e:                  # noqa: BLE001 — 退出路径不得抛
            sys.stderr.write("WARN[state-wal] 退出 checkpoint 异常: %s (%s: %s)\n"
                             % (path, type(e).__name__, e))
