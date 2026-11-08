#!/usr/bin/env python3
"""gk_json_utils.py — 专业 JSON 工具（解析/读取/写，2026-09-01）

背景（用户质询"cypher 多行 JSON 解析有 bug"+"是不是需要配几个和 json 解析、
读取、写的专业工具"）：gk_gitnexus_pdg_check / gk_pr_review_check / gk_doc_align
三处各自实现了"行首 `{` 定位 + raw_decode"的重复逻辑，且边界不全：
  - warn 行在结果之后 → 行首 `{` 定位取到 warn 而非结果
  - 多个 JSON 混杂（FTS warn + 结果）→ 只认最后一个行首 `{`
  - 无 JSON / 非 dict JSON → 靠调用方二次兜底
本模块收敛为唯一事实源，提供三类专业工具：

  1. extract_last_json(text)  — 从任意文本提取最后一个完整 JSON 对象
     （按所有 `{` 候选 raw_decode，取跨度最大者 = 结果而非 warn）
  2. read_json_file(path)     — 容错读文件（缺失/损坏 → 结构化 error，不抛）
  3. write_json_file(path)    — 原子写（tmp + os.replace，含 encoding/权限）
  4. json_get(obj, path)      — 点路径取字段（数字=列表索引），缺失 → default
  5. extract_markdown_table   — 专业 markdown 表格解析（跳表头/分隔行，支持多列）
  6. extract_markdown_int     — 从 cypher markdown 表提取计数（表解析版，多列可容）

确定性：0 API。纯标准库。
"""
import contextlib
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
from pathlib import Path

try:                        # 非 POSIX 无 fcntl ⟹ 锁退化为无锁（不新增失败面，与升级前一致）
    import fcntl
except ImportError:         # pragma: no cover
    fcntl = None

try:                        # [ECC-CA93145A1E67] Windows 宿主用 msvcrt 提供**跨进程**文件锁
    import msvcrt           #   —— 原式在非 POSIX 直接退化为**无锁** ⟹ 并发 RMW 丢写（Windows 实测）
except ImportError:         # pragma: no cover
    msvcrt = None

# state 序列化缩进档位（R2，2026-09-22 用户裁定：indent=1）。
# 单一事实源 —— `dump_state` 消费；改此值即改全局 state 形态。
STATE_INDENT = 1


def extract_last_json(text: str) -> dict | None:
    """从混合文本提取结果 JSON 对象（dict）。

    策略：扫描所有 `{` 位置，对每个候选位置 raw_decode；保留**解析跨度最大**
    的完整 dict（结果 JSON 是多行/大对象，FTS warn 是单行小对象——无论 warn 在
    结果前还是后，结果跨度恒大于 warn）。跨度相同时取结束位置更靠后者。
    返回 None 表示无可解析 dict（纯文本输出）。
    """
    if not text:
        return None
    decoder = json.JSONDecoder()
    best = None
    best_span = -1
    best_end = -1
    pos = 0
    while True:
        start = text.find("{", pos)
        if start == -1:
            break
        try:
            obj, end = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            pos = start + 1
            continue
        if isinstance(obj, dict):
            span = end  # end 为对象自身长度
            if span > best_span or (span == best_span and start + end > best_end):
                best = obj
                best_span = span
                best_end = start + end
        pos = start + 1
    return best


def read_json_file(path: str | os.PathLike) -> dict:
    """容错读 JSON 文件：返回 dict；缺失/解码/解析失败 → {"error": ...}（不抛）。"""
    p = Path(path)
    if not p.exists():
        return {"error": f"no such file: {p}"}
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {"error": f"non-dict JSON: {p}"}
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        return {"error": f"read {p}: {e}"}


# ── 瞬态 replace 有界重试（2026-10-07 压测长尾修复）────────────────────────────
# 病象（300 路并发压测，卫星片压力测试）：state 原子写在 `os.replace(tmp, p)` 处偶发
#   `PermissionError([WinError 5] 拒绝访问)` —— 与 state_lock 无关（锁内串行；压测 0 超时），
#   系 Windows 上**目标被另一句柄瞬时占用**（安全软件扫描窗 / 短暂读者）⟹ 瞬态。
#   原实现把瞬态当永久（返回 False）⟹ `cmd_set_nested` 报 `write_failed` ⟹
#   `gk_satellite.append` 报「索引登记失败（片已落）」—— 片已落、per-arm 索引叶子缺失 =
#   卫星计划 §8/§10 的对接断裂面（实测基线 300 组并发 0.3%~1.7% 索引叶子丢失，片行数恒零丢失）。
#   有界重试（仅瞬态码）即可消此长尾（实测 3/3 轮 300/300）。持续失败仍 **fail-loud**
#   （重试耗尽 → 原样抛 → 外层 catch → 返回 False，只毁 tmp）。
_REPLACE_RETRY_MAX = 10
_REPLACE_RETRY_SLEEP_S = 0.01          # 线性退避：第 n 次前睡 n*10ms（上限 ~550ms）


def _replace_with_retry(tmp, p) -> None:
    """`os.replace` 有界重试（仅瞬态：WinError 5/32 → PermissionError 子类）。

    非瞬态错误（目录不存在 / 只读 FS 等）**不重试**，立即抛（保持 fail-loud 与低延迟）。
    """
    import time as _t
    for _i in range(_REPLACE_RETRY_MAX):
        try:
            os.replace(tmp, p)
            return
        except OSError as e:
            transient = (isinstance(e, PermissionError)
                         or getattr(e, "winerror", None) in (5, 32))
            if not transient or _i == _REPLACE_RETRY_MAX - 1:
                raise
            _t.sleep(_REPLACE_RETRY_SLEEP_S * (_i + 1))


def write_json_file(path: str | os.PathLike, data: dict, mode: int = 0o600,
                    indent: int = 2) -> bool:
    """原子写 JSON（tmp + os.replace）：避免半写文件被并发读取。

    encoding=utf-8 + ensure_ascii=False（保留中文），新文件权限 mode（POSIX）。
    indent 默认 2（通用 JSON）；**写 state 请用 dump_state**（indent=STATE_INDENT）。
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=p.name + ".", suffix=".tmp", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, ensure_ascii=False, indent=indent)
            f.flush()
            os.fsync(f.fileno())
        if os.name != "nt":
            os.chmod(tmp, mode)
        _replace_with_retry(tmp, p)
        return True
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False


# ══════════ 跨进程 state 锁（选项 A，2026-09-25 用户裁定：唯一锁持有者 = python）══════════
# 背景（实测，计划 §4.13.1 RC2）：锁资源 `<state>.lock` 此前**只由 bash `_with_state_lock`
#   （flock(1)）获取**，而 python 侧 ~15 个写通道（`dump_state`/`_write_state`/`gk_finding` …）
#   **全无锁** ⟹ 多会话并发下「读-改-写」丢更新（实测：`used=2` 而 `remaining` 只由 8→7 ——
#   两笔都记了账、只扣了一次）。用户裁定**选项 A**：唯一持有者改为 python —— 锁资源不变
#   （仍是 `<state>.lock`，fcntl.flock 与 flock(1) 同一底层锁），但统一由本模块获取；
#   bash `_with_state_lock` **已拆除**，其调用点改由 python 侧持锁。
# 可重入（**必须**）：`_state_write` 会在锁内调用 `dump_state`，而 `dump_state` 自身也取锁；
#   Linux flock 对**同文件不同 fd**互斥 ⟹ 二次 fcntl.flock 会**自锁**。故按 realpath 记深度，
#   同进程重复进入只加计数、不重复 flock（跨进程仍严格互斥）。
_LOCKS: dict = {}                 # realpath -> [fd, depth]
_LOCK_FDS: dict = {}              # lock 文件 realpath -> 常驻 fd（跨 acquire 复用）
_LOCK_FD_CACHE_MAX = 64           # 常驻 fd 上限（防「每个 tmp state 一个 fd」的无界泄漏）
LOCK_TIMEOUT = 5.0
# 2026-11-03（M1）：`realpath` / `makedirs` 是 Windows 上取锁的主要固定开销（实测 ~2ms）。
# 路径在进程生命周期内稳定 ⟹ 缓存结果；目录被外部删除时 `os.open` 失败会重建（见下）。
_REALPATH_CACHE: dict = {}
_READY_DIRS: set = set()


def _lock_key(path) -> str:
    s = str(path)
    k = _REALPATH_CACHE.get(s)
    if k is None:
        k = os.path.realpath(s)
        _REALPATH_CACHE[s] = k
    return k


def _lock_fd(key) -> int:
    """锁文件的常驻 fd（2026-11-03 M1：Windows 上 open/close 各 ~0.3ms，压在临界区外沿）。

    2026-11-03 收尾：加**上限 + 逐出**。首版无界缓存 ⟹ pytest 每 worker 累积 100+ 个
    `.lock` fd（全量压测实测），长跑会撞 `EMFILE`。逐出跳过**当前仍持有**的 fd（`_LOCKS`）。
    """
    p = state_lock_path(key)
    fd = _LOCK_FDS.get(p)
    if fd is not None:
        return fd
    fd = os.open(p, os.O_CREAT | os.O_RDWR, 0o644)
    _LOCK_FDS[p] = fd
    if len(_LOCK_FDS) > _LOCK_FD_CACHE_MAX:
        held = {v[0] for v in _LOCKS.values()}
        for _p, _fd in list(_LOCK_FDS.items()):
            if _p == p or _fd in held:        # 不逐出刚建的 / 正在持有的
                continue
            try:
                os.close(_fd)
            except OSError:
                pass
            _LOCK_FDS.pop(_p, None)
            if len(_LOCK_FDS) <= _LOCK_FD_CACHE_MAX:
                break
    return fd


def _unlock_fd(fd) -> None:
    """显式释放（fd 常驻 ⟹ 不能靠 close 释放）。失败不抛（fd 复用不改变互斥语义）。"""
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
        elif msvcrt is not None:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    except OSError:
        pass

# ── 锁观测（A2，2026-10-28）──────────────────────────────────────────────────
# A2 裁定明写：「state lock timeout=0 命中**不可**当无瓶颈证据（BLOCK 路径吞异常）」。
# 原实现里超时只抛 `TimeoutError`，谁 try/except 吞掉谁就看不见 —— 于是「0 次超时」既可能
# 是真无争用，也可能是被吞了。本计数把**每一次**取锁尝试与**每一次**超时都记账（含
# `timeout=0` 的试探调用），供体检/审计取用；**不改**任何阻塞/抛出语义。
_LOCK_STATS = {"acquired": 0, "reentrant": 0, "timeouts": 0,
               "last_timeout_path": "", "last_timeout_s": 0.0}


def state_lock_stats() -> dict:
    """取锁统计快照（进程内累计）：`acquired` / `reentrant` / `timeouts` + 末次超时现场。"""
    return dict(_LOCK_STATS)


def reset_state_lock_stats() -> None:
    """清零统计（测试/长驻进程分段观测用）。"""
    for k in ("acquired", "reentrant", "timeouts"):
        _LOCK_STATS[k] = 0
    _LOCK_STATS["last_timeout_path"] = ""
    _LOCK_STATS["last_timeout_s"] = 0.0


def state_lock_path(path) -> str:
    """锁文件路径（单源）：`<path>.lock` —— 与拆除前的 bash `_with_state_lock` 同名同资源。"""
    return str(path) + ".lock"


def _flock_wait(fd: int, timeout: float) -> None:
    """带超时的排他 flock（LOCK_NB 轮询）；超时 → TimeoutError（fail-loud，不静默降级）。"""
    import time as _t
    deadline = _t.monotonic() + max(0.0, timeout)
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError:
            if _t.monotonic() >= deadline:
                raise TimeoutError("state lock timeout (%.1fs): %s" % (timeout, fd))
            # 2026-11-03（M1）：20ms → 2ms。32 writers 压测下 20ms 的轮询粒度把 p99 抬到
            # 1.2s（锁本身只持有几 ms）；2ms 让等待-唤醒延迟与临界区同量级。
            _t.sleep(0.002)


def _win_lock_wait(fd: int, timeout: float) -> None:
    """带超时的排他锁（Windows `msvcrt.locking`，锁文件首字节）；超时 → TimeoutError。

    [ECC-CA93145A1E67] 与 `_flock_wait` **同契约**（`LK_NBLCK` = 非阻塞 + 轮询 + fail-loud）。
    `msvcrt.locking` 从**当前文件位置**起锁 ⟹ 每次先 `lseek(0)`；fd 关闭即释放
    （`os.close` 在 `state_lock` 的 finally）。
    """
    import time as _t
    deadline = _t.monotonic() + max(0.0, timeout)
    while True:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return
        except OSError:
            if _t.monotonic() >= deadline:
                raise TimeoutError("state lock timeout (%.1fs): %s" % (timeout, fd))
            _t.sleep(0.002)


@contextlib.contextmanager
def state_lock(path, timeout: float = LOCK_TIMEOUT):
    """跨进程 state 排他锁（**可重入**）。唯一锁持有者 = python（选项 A，2026-09-25）。

    POSIX → `fcntl.flock`；Windows → `msvcrt.locking`（[ECC-CA93145A1E67]：原式在非 POSIX
    **退化为无锁** ⟹ 并发 `set-nested`/`append-list` 读-改-写丢写，Windows 实测 6 进程仅 3~4 落地）。
    仅当两者皆不可用（罕见平台）才无锁 —— 与升级前行为一致，不新增失败面。
    """
    key = _lock_key(path)
    ent = _LOCKS.get(key)
    if ent is not None:                       # 本进程已持锁 ⟹ 只加深度（防自锁）
        ent[1] += 1
        _LOCK_STATS["reentrant"] += 1
        try:
            yield
        finally:
            ent[1] -= 1
        return
    d = os.path.dirname(key)
    if d and d not in _READY_DIRS:
        os.makedirs(d, exist_ok=True)
        _READY_DIRS.add(d)
    try:
        fd = _lock_fd(key)
    except OSError:
        if not d:                             # 目录被外部删除 ⟹ 重建一次（不缓存失败）
            raise
        os.makedirs(d, exist_ok=True)
        _READY_DIRS.add(d)
        fd = _lock_fd(key)
    try:
        try:
            if fcntl is not None:
                _flock_wait(fd, timeout)
            elif msvcrt is not None:              # [ECC-CA93145A1E67] Windows：真锁，不再退化为无锁
                _win_lock_wait(fd, timeout)
        except TimeoutError:
            # A2：超时**必记账**（含 timeout=0 的试探）—— 「0 命中」不得再被当无瓶颈证据
            _LOCK_STATS["timeouts"] += 1
            _LOCK_STATS["last_timeout_path"] = key
            _LOCK_STATS["last_timeout_s"] = float(timeout)
            raise
        _LOCKS[key] = [fd, 1]
        _LOCK_STATS["acquired"] += 1
        try:
            yield
        finally:
            _LOCKS.pop(key, None)
    finally:
        _unlock_fd(fd)                        # fd 常驻 ⟹ 显式 LOCK_UN（异常路径也安全）


def _state_checksum(d: dict) -> str:
    """state `_checksum`（canon）：`sha256(json.dumps(gate_data, sort_keys=True))[:16]`。

    与 bash `_state_write` / `_state_checksum_write`、`gk_gate_checksum.py`、
    `gk_state._write_state`、`gk_task_gate._checksum` **同算法**（默认 `ensure_ascii=True`）。
    本函数为收敛后的 python 侧单源 —— 新增写点不得再各算一份。
    """
    gd = json.dumps(d.get("gate_data", {}), sort_keys=True)
    return hashlib.sha256(gd.encode()).hexdigest()[:16]


def update_state(path, mutator) -> dict:
    """原子「读-改-写」（锁内）：`mutator(d) -> d'`（返回 None 表示原地修改 d）。

    返回 `{"ok": True, "data": d}`；读失败 → `{"error": ...}`（不写盘，fail-closed）。
    **python 侧并发安全的唯一 RMW 形态** —— 调用方不得再「先 read 后 dump」（有丢更新窗口）。
    落盘前重算 `_checksum`（state canonical，单源）⟹ 迁移来的调用点不会留 TAMPERED 假阳。

    2026-11-03（M1）：写路径改为 WAL 追加（`gk_state_wal.update_state`），不再每次整份重写；
    读侧 = checkpoint state + WAL replay（等价语义：`data` 仍是完整 state dict）。
    """
    import gk_state_wal as W                    # 惰性：避免 gk_state_wal → 本模块的导入环
    return W.update_state(path, mutator, _state_checksum)


def read_state_file(path) -> dict:
    """**state 专用**容错读（WAL-aware）：checkpoint state + `<path>.wal` replay。

    与 `read_json_file` 的区别：后者是通用 JSON 读，**不**知道 WAL；读 state 必须走本函数，
    否则会读到 checkpoint 之前的旧快照。返回契约与 `read_json_file` 相同（不抛）。
    """
    import gk_state_wal as W                    # 惰性：同上
    return W.read_state(path)


def _wall_guard(path, data, old_data=None) -> None:
    """**95% 水位写拦截**（2026-11-01 owner 裁定）：整墙占用 ≥`WALL_BLOCK_PCT` ⟹ 拒写。

    三条纪律：
      ① **收缩写放行** —— 新体积 < 磁盘现有体积 ⟹ 是改善（裁剪/清理正在生效），不得自锁；
      ② 逃生舱 `GK_STATE_WALL_BLOCK=0`（运维显式放行，**留 stderr 痕迹**，不静默）；
      ③ 判据口径 = `canon_bytes`（`dump_state` 同参），与 `state_size_report` **同源**。

    `old_data`（2026-11-03 M1）：WAL 写路径的旧体积来自**重放后的内存快照**（磁盘上的
    checkpoint 可能落后于 WAL）⟹ 由 `update_state` 显式传入，避免把「已增长」误判成收缩写。
    """
    if str(os.environ.get("GK_STATE_WALL_BLOCK", "1")).strip() == "0":
        return
    n = canon_bytes(data)
    limit = int(STATE_SIZE_WALL * WALL_BLOCK_PCT // 100)
    if n < limit:
        return
    old = 0
    try:
        if old_data is not None:
            old = canon_bytes(old_data)
        elif os.path.isfile(path):
            old = canon_bytes(read_json_file(path))
    except Exception:  # noqa: BLE001 — 边界：读不到旧体积 ⇒ 按「非收缩」处理（保守拦截）
        old = 0
    if old and n < old:
        sys.stderr.write("WARN[state-wall] 收缩写放行: %d -> %d B（仍超 %d%% 水位 %d）\n"
                         % (old, n, int(WALL_BLOCK_PCT), limit))
        return
    raise ValueError(
        "STATE_WALL_BLOCK: canon=%d B ≥ %d%% wall=%d（%d B）—— 先裁剪再写："
        "`finding archive-closed` / `state --satellite --apply` / history 截断；"
        "确需放行请 `GK_STATE_WALL_BLOCK=0`（会留痕）"
        % (n, int(WALL_BLOCK_PCT), STATE_SIZE_WALL, limit))


def dump_state(path, data) -> bool:
    """state 序列化**单一事实源**（R2，2026-09-22 用户裁定形态）。

    形态 = `ensure_ascii=False` + `indent=STATE_INDENT(1)` + `encoding='utf-8'`
         + `newline='\\n'`；写盘复用 `write_json_file`（fsync + os.replace，原子、无半写）。

    背景（实测 2026-09-21/22，同一 state 对象在不同写点）：
      - 磁盘字节随「末位写者」在 158,000 / 161,759 / 181,323 / 224,977 / 244,541 /
        251,683 / 289,835 / 314,527 (B) 之间漂移，而 `gk_narrow_route._NT_MAX_TOTAL_BYTES*4`
        = 262,144 ⟹ **撞不撞墙取决于最后一个写点**（F-REV-51 的减重成果被形态切换吃掉）；
      - `ensure_ascii=True` 把每个 CJK 字符逃逸成 `\\uXXXX`（3B→6B），实测 21,055 处、
        纯浪费 63,165 B；
      - 多个写点 `open(...,'w')` 未指定 encoding —— 现能跑纯属 ascii=True 使输出恒为 ASCII
        的副作用；一旦 ascii=False，非 UTF-8 locale 即 UnicodeEncodeError。

    **改此处即改全局 state 形态；勿再内联 `json.dump` 直写 state。**
    （bash 侧无法 import，其调用点以同参数字面量对齐，见 test_r2_state_serialization.py。）
    2026-09-25（选项 A）：本函数**内置取锁**（`state_lock`，可重入 ⟹ 锁内再调用不自锁）
    —— 写侧互斥的唯一实现点；调用方若需「读-改-写」原子性，须用 `update_state`。
    """
    with state_lock(path):
        _wall_guard(path, data)
        return write_json_file(path, data, indent=STATE_INDENT)


# ══════════ 异步单写者（A2，2026-10-28）══════════════════════════════════════
# A2 裁定：「热路径只读（内存/卫星），写路径保持**单写者**但**异步化**」。
#
# 适用范围（**故意收窄**）：只用于**非权威、且调用方不需要立即回读**的写 —— 典型是长驻
# 进程的遥测接收（`sniffnet_webhook` 的 per-request 落 state）。这些写原来在 HTTP 线程里
# 同步抢 `state_lock`，多请求并发时互相排队。
#
# **不适用**于治理权威面（`.gatekeeper.state` 的预算/阶段/台账）：下一次工具调用是**另一个
# 进程**，必须读到自己刚写的预算；异步化会把「本进程已扣费」变成「下一个进程还没看见」的
# 越权窗口。故 `dump_state`/`update_state` **保持同步**，没有任何生产治理写点改走本队列。
#
# 语义保证：① 单写者（一个后台线程串行执行任务，任务内部仍持 `state_lock` ⟹ 跨进程亦互斥）；
# ② 任务内抛错**不吞**，进 `_WRITE_ERRORS`，`flush_state_writes()` 默认 fail-loud 抛出；
# ③ 进程正常退出时 atexit 自动 flush；④ `flush` 在写者线程自身调用时不自锁（直接返回）。
_WRITE_Q: list = []
_WRITE_COND = threading.Condition()
_WRITE_THREAD = None
_WRITE_ERRORS: list = []
_WRITING = False


def _writer_loop() -> None:
    global _WRITING
    while True:
        with _WRITE_COND:
            while not _WRITE_Q:
                _WRITE_COND.wait()
            path, fn = _WRITE_Q.pop(0)
            _WRITING = True
        try:
            fn()
        except Exception as e:  # noqa: BLE001 — 边界：错误入队，由 flush 决定是否抛出
            _WRITE_ERRORS.append({"path": str(path),
                                  "error": "%s: %s" % (type(e).__name__, e)})
        finally:
            with _WRITE_COND:
                _WRITING = False
                _WRITE_COND.notify_all()


def _ensure_writer() -> None:
    global _WRITE_THREAD
    if _WRITE_THREAD is not None and _WRITE_THREAD.is_alive():
        return
    with _WRITE_COND:
        if _WRITE_THREAD is None or not _WRITE_THREAD.is_alive():
            _WRITE_THREAD = threading.Thread(target=_writer_loop,
                                             name="gk-state-writer", daemon=True)
            _WRITE_THREAD.start()


def submit_state_write(path, fn) -> int:
    """把一个**写任务**交给单写者队列（`fn()` 无参，内部自行持 `state_lock`）。

    返回当前排队数。这是异步通道的唯一入口 —— 需要「整份 state 落盘」用 `dump_state_async`，
    需要「读-改-写」自己包一个闭包传进来。
    """
    _ensure_writer()
    with _WRITE_COND:
        _WRITE_Q.append((path, fn))
        n = len(_WRITE_Q)
        _WRITE_COND.notify_all()
    return n


def dump_state_async(path, data) -> int:
    """异步版 `dump_state`（**仅限非权威写**；权威面必须用同步 `dump_state`/`update_state`）。

    返回排队数。落盘失败在 `flush_state_writes()` 时以 `RuntimeError` 暴露（不静默）。
    """
    return submit_state_write(path, lambda: dump_state(path, data))


def pending_state_writes() -> int:
    """尚未执行的写任务数（不含正在执行中的那一个）。"""
    with _WRITE_COND:
        return len(_WRITE_Q)


def flush_state_writes(timeout: float = 30.0, strict: bool = True) -> dict:
    """等待队列排空（含正在执行的任务）；`strict=True` 且有写失败 ⟹ 抛 `RuntimeError`。

    返回 `{"errors": [...], "error_count": N, "pending": M}`。错误列表**取出即清空**
    （下次 flush 只反映新的失败，不无限累积）。
    """
    import time as _t
    if threading.current_thread() is _WRITE_THREAD:   # 写者自身调用 ⟹ 不自锁
        return {"errors": list(_WRITE_ERRORS), "error_count": len(_WRITE_ERRORS),
                "pending": pending_state_writes()}
    deadline = _t.monotonic() + max(0.0, timeout)
    with _WRITE_COND:
        while _WRITE_Q or _WRITING:
            remain = deadline - _t.monotonic()
            if remain <= 0:
                break
            _WRITE_COND.wait(remain)
    errs = list(_WRITE_ERRORS)
    _WRITE_ERRORS.clear()
    pending = pending_state_writes()
    if strict and errs:
        raise RuntimeError("state 异步写失败 %d 条: %s" % (len(errs), errs[:3]))
    return {"errors": errs, "error_count": len(errs), "pending": pending}


def _flush_at_exit() -> None:                          # pragma: no cover - 退出钩子
    try:
        flush_state_writes(timeout=10.0, strict=False)
    except Exception:
        pass


import atexit as _atexit                              # noqa: E402  仅用于本区块的退出 flush
_atexit.register(_flush_at_exit)


# ══════════ state 体积体检（L5 仪表，2026-09-25 · `ECC-75DAED1C537C`）══════════
# 背景（实测 2026-09-25）：state 240,377 B / 硬墙 262,144 B ⟹ 余量仅 8.3%；而体积由若干
# **各自独立定价**的字节配额（`gatekeeper-cli.sh` `_HIST_MAX_BYTES=98304`、narrow_tasks 预留
# 64KB）＋**无配额的**子系统（`ecc_findings` 实测 94,696 B 且单调增长）共同决定 ⟹ 任一子系统
# 膨胀即吃掉他人预留。
# 本函数 = **唯一计量口径**（逐键 `json.dumps` 字节），供体检臂 / 报告 / 配额汇总消费。
# 2026-10-16 owner 裁定「审计署 state 应当只存元数据 ⟹ 给 state 加个0」：硬墙 ×10
# （262144 → 2621440），且**单源** —— `gk_narrow_route.validate_narrow_tasks` 的
# `state_oversized` 判据改为**运行时读**本常量（原内联 `_NT_MAX_TOTAL_BYTES * 4` 是第二份
# 字面量，改一处必漂移 ⟹ 裁定无法单点生效）。
STATE_SIZE_WALL = 65536 * 40       # = 2,621,440（2026-10-16 裁定 ×10；**整文件墙唯一事实源**）
STATE_SIZE_RESERVE = 16 * 1024     # 预警预留（绝对量）：余量低于此值应先裁体积再裁决
_SINGLE_KEY_PCT_WARN = 30.0        # 单键占全文件比例告警线（%）

# ── 水位线（2026-11-01 owner 裁定：50 过半 / 80 警告 / 90 需裁剪 / 95 拦截）────
# 纪律：阈值**只在此处**定义（bash / 各体检臂经 `wall_level()` 消费，禁第二份字面量）。
# 95% 不只是提示 —— `dump_state` 在此水位**拒写**（`_wall_guard`，收缩写除外）。
WALL_NOTICE_PCT = 50.0
WALL_WARN_PCT = 80.0
WALL_TRIM_PCT = 90.0
WALL_BLOCK_PCT = 95.0
WALL_LEVELS = ((WALL_BLOCK_PCT, "block"), (WALL_TRIM_PCT, "trim"),
               (WALL_WARN_PCT, "warn"), (WALL_NOTICE_PCT, "notice"))
_WALL_LEVEL_LABEL = {
    "ok": "正常",
    "notice": "过半（≥50%）：开始关注体积",
    "warn": "警告（≥80%）：接近上限",
    "trim": "需裁剪（≥90%）：先裁再裁决",
    "block": "拦截（≥95%）：写入口拒绝",
}


def wall_level(used, wall=None) -> dict:
    """state 体积水位（**只读纯函数**）：`{used, wall, pct, level, label}`。

    `level ∈ ok|notice|warn|trim|block`；阈值单源 = `WALL_LEVELS`。供体检臂 / CLI / 文档对表，
    禁各处自写「50/80/90/95」字面量（漂移即告警口径分裂）。
    """
    w = int(wall or STATE_SIZE_WALL)
    pct = round(100.0 * float(used) / w, 2) if w > 0 else 0.0
    level = "ok"
    for th, name in WALL_LEVELS:
        if pct >= th:
            level = name
            break
    return {"used": int(used), "wall": w, "pct": pct, "level": level,
            "label": _WALL_LEVEL_LABEL[level]}


# ── `ecc_findings` 配额（`ECC-03F2EB7D6607` 计量半，2026-09-28）────────────────
# 病象（实测 2026-09-28）：`ecc_findings` 是 state 里**唯一无配额**且单调增长的分量
# （154,626 B = 硬墙 59%、canon_total 88.5%），而 `_SINGLE_KEY_PCT_WARN` 只查**顶层键**
# ⟹ 实测只报 `SINGLE_KEY_HEAVY: gate_data = 164,536 B (94.0%)`，**指不到**真重键
# `gate_data.ecc_findings`（154,626 B）—— 这是**归因**盲区，非「无预警」。
#
# ── 三条腿按**墙的比例**定价（2026-11-02 owner 裁定「收紧 payload 配额」）──────────
# 背景：墙在 2026-10-16 已 ×10（262,144 → 2,621,440）。2026-11-01 曾按「10 轮 × 6 臂」
#   把三腿抬到 45%/20%/20%（合计 85%）；但 satellite 冷侧车/分片已承接 bulk ⟹ 该口径
#   会把主 state 继续推向墙。2026-11-02 收紧为三腿各 5%、合计 15%，其余 85% 留给其它 key。
#   卫星片 / 冷索引侧车已承接 bulk；history 一窗只需一轮（6 臂 ≈118KB）。
#   · `subagent_history` → 墙 × 5% = 131,072（128KB，一轮 6 臂 × 16KB × 1.2 ≈ 118KB）
#   · `task_pipeline`    → 墙 × 5% = 131,072（128KB）
#   · `ecc_findings`     → 墙 × 5% = 131,072（128KB）
# 单源：本模块 = 唯一数值源；`gk_task_gate` **import** 本常量，bash `_HIST_MAX_BYTES` 为
#   同值字面量（bash 不可 import），漂移由 `test_gk_state_trim_lines.py` 逐值守。
HIST_MAX_BYTES = STATE_SIZE_WALL * 5 // 100       # 131,072 = 128KB（一轮 6 臂 ≈118KB）
TASK_PIPE_MAX_BYTES = STATE_SIZE_WALL * 5 // 100  # 131,072 = 128KB
ECC_MAX_BYTES = TASK_PIPE_MAX_BYTES               # 131,072 = 128KB
ECC_MAX_ENTRIES = 256
ECC_MAX_OPEN = 96
_ECC_WARN_RATIO = 0.8              # 单轴 used/cap 达此比例即 warn（先预警后撞墙）


def ser_bytes(obj) -> int:
    """对象 canon 序列化字节（与 state 落盘同参：`ensure_ascii=False`）。

    **公开出口**：供台账（`gk_finding.archive_closed`）等按**同一口径**计量 —— 避免出现
    第二份计量实现（单源纪律）。
    """
    return len(json.dumps(obj, ensure_ascii=False).encode("utf-8"))


def canon_bytes(obj) -> int:
    """对象 **canonical 形态字节**（`ensure_ascii=False` + `indent=STATE_INDENT`）—— **形态无关**口径。

    这是「state 的**内容**有多大」的单一事实源（区别于 `len(磁盘原始字节)`：后者随**末位写者
    的形态**（`ensure_ascii`/`indent`）漂移 —— 一次 legacy 写（如 `ensure_ascii=True`）把每个
    CJK 逃逸成 `\\uXXXX`（3B→6B）就凭空 "长大"，而内容一字未变）。
    L4（2026-09-25）起硬墙/体检判据统一走本口径（`gk_narrow_route` / `state_size_report` 同源）。
    """
    return len(json.dumps(obj, ensure_ascii=False, indent=STATE_INDENT).encode("utf-8"))


BANK_PROJECTION_CAP = 120


def _projection_cap() -> int:
    """投影切片长度 = `gk_advance.REJECTED_CAP`（同源，禁第二份数字；惰性 import 防循环）。

    2026-11-01（质询臂 d）：原实现 `BANK_PROJECTION_CAP=120` 是第二份字面量，与计划自述的
    「禁第二份数字」纪律相悖；本函数让唯一事实源留在 `REJECTED_CAP`，常量只作兜底。
    """
    try:
        from gk_advance import REJECTED_CAP
        return int(REJECTED_CAP)
    except Exception:
        return BANK_PROJECTION_CAP


def view_bank_actions(gd: dict) -> list:
    """`bank_actions` 的**读时投影**（T3，2026-11-01）：从事件流过滤 `source=="bank"`。

    背景：事件单写后 `bank_actions` 不再落盘（唯一正本 = `gate_data.rejected_edits`）；
    旧看板仍读该字段 ⟹ 用投影兜底，**不落第二份**、不参与 checksum。字段形状沿用旧写法
    （`kind/stage/transition/score/ts/forced`），使既有消费者的取值路径不变。
    """
    out = []
    # 2026-11-01（质询臂 d）：**存量兼容**。旧 state 里已落盘的 `bank_actions`（旧 cap 100）
    #   既不在事件流里、也不会被回收 ⟹ 单读事件流时它们「消失且永不可见」。这里把存量
    #   **并入视图**（`legacy=true` 标记），不改盘、不删数据；后续由 `state --archive-isolated`
    #   或下轮迁移统一裁掉。
    for a in ((gd or {}).get("bank_actions") or []):
        if not isinstance(a, dict):
            continue
        out.append({"kind": a.get("kind", "monitor_local_block"),
                    "stage": a.get("stage", ""),
                    "transition": a.get("transition") or a.get("to_stage", ""),
                    "score": a.get("score"),
                    "ts": a.get("ts", ""),
                    "forced": bool(a.get("forced")),
                    "legacy": True})
    for e in ((gd or {}).get("rejected_edits") or []):
        if not isinstance(e, dict) or e.get("source") != "bank":
            continue
        out.append({"kind": "monitor_local_block",
                    "stage": e.get("stage", ""),
                    "transition": e.get("to_stage", ""),
                    "score": e.get("score"),
                    "ts": e.get("timestamp", ""),
                    "forced": str(e.get("outcome") or "") == "forced"})
    return out[-_projection_cap():]


def two_legs_report(path, reserve: int = STATE_SIZE_RESERVE) -> dict:
    """**只读**仪表：两条腿（`subagent_history` / `ecc_findings`）字节 + 占比 + 余量（C2③，2026-09-28）。

    口径与 `state_size_report` 同源（`canon_bytes` = ensure_ascii=False + indent）。余量 < `reserve`
    即 `warn=True` —— 供 `advance` / `commit` 前预警，防「撞墙才发现」（实测余量曾低至 1.2%）。
    """
    p = Path(path)
    if not p.is_file():
        return {"ok": False, "error": "no such state: %s" % p}
    d = read_state_file(p)
    if "error" in d:
        return {"ok": False, "error": d["error"]}
    gd = d.get("gate_data", {}) or {}
    legs = {k: ser_bytes(gd.get(k)) for k in ("subagent_history", "ecc_findings")}
    total = canon_bytes(d)
    margin = STATE_SIZE_WALL - total
    lvl = wall_level(total)
    return {"ok": True, "wall": STATE_SIZE_WALL, "total": total, "margin": margin,
            "reserve": reserve, "warn": margin < reserve, "legs": legs,
            "pct": lvl["pct"], "level": lvl["level"], "level_label": lvl["label"],
            "legs_share_pct": round(100.0 * sum(legs.values()) / total, 1) if total else 0.0}


def _cap_axis(used: int, cap: int) -> dict:
    """单轴配额判据：`used`/`cap`/`ratio`/`over`（`cap<=0` 视为不设限）。"""
    return {"used": used, "cap": cap,
            "ratio": round(float(used) / cap, 3) if cap > 0 else 0.0,
            "over": cap > 0 and used > cap}


def ecc_cap_report(path) -> dict:
    """`ecc_findings` 配额体检（**只读**，0 写盘）—— `ECC-03F2EB7D6607` 计量半。

    三轴逐报 used/cap/ratio/over（**bytes** / **entries** / **open**），`over_axes` 供审计定位；
    `open` 单列的理由：`archive_closed` **只动 closed**，open **无回收通路** ⟹ 它是唯一
    「只能靠闭环消化、体积裁不动」的轴。`reclaimable_closed` = 可被 `archive_closed` 回收的条数。
    ⚠ 只读：**不**改 state、不写盘（对照 `test_gk_ecc_cap.py::test_readonly_zero_write`）。
    """
    p = Path(path)
    if not p.is_file():
        return {"ok": False, "error": "no such state: %s" % p}
    d = read_state_file(p)
    if "error" in d:
        return {"ok": False, "error": d["error"]}
    gd = d.get("gate_data") if isinstance(d.get("gate_data"), dict) else {}
    fs = gd.get("ecc_findings") if isinstance(gd.get("ecc_findings"), list) else []
    n_open = sum(1 for f in fs if isinstance(f, dict) and f.get("status") == "open")
    n_closed = sum(1 for f in fs if isinstance(f, dict) and f.get("status") == "closed")
    ax = {"bytes": _cap_axis(ser_bytes(fs), ECC_MAX_BYTES),
          "entries": _cap_axis(len(fs), ECC_MAX_ENTRIES),
          "open": _cap_axis(n_open, ECC_MAX_OPEN)}
    over_axes = [k for k in ("bytes", "entries", "open") if ax[k]["over"]]
    return {
        "ok": True,
        "path": str(p),
        "bytes": ax["bytes"]["used"], "bytes_cap": ECC_MAX_BYTES,
        "bytes_ratio": ax["bytes"]["ratio"], "bytes_over": ax["bytes"]["over"],
        "entries": ax["entries"]["used"], "entries_cap": ECC_MAX_ENTRIES,
        "entries_ratio": ax["entries"]["ratio"], "entries_over": ax["entries"]["over"],
        "open": ax["open"]["used"], "open_cap": ECC_MAX_OPEN,
        "open_ratio": ax["open"]["ratio"], "open_over": ax["open"]["over"],
        "closed": n_closed,
        "reclaimable_closed": n_closed,
        "over": bool(over_axes),
        "warn": any(ax[k]["ratio"] >= _ECC_WARN_RATIO for k in ax),
        "over_axes": over_axes,
    }


def state_size_report(path, reserve: int = STATE_SIZE_RESERVE, top: int = 12) -> dict:
    """state 体积体检（**只读**，0 写盘）—— L5 仪表的结构化数据。

    双口径并报（L4 待裁定项）：`disk_bytes` = 磁盘原始字节（**现硬墙判据口径**，见
    `gk_narrow_route.py`）vs `canon_bytes` = dump_state 形态字节（**形态无关口径**）；
    二者不等即 `form_diverged=True` ⟹ 一次 legacy 形态写就让硬墙判据提前命中。
    """
    p = Path(path)
    if not p.is_file():
        return {"ok": False, "error": "no such state: %s" % p}
    raw = p.read_bytes()
    try:
        d = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return {"ok": False, "error": "unreadable state: %s" % e}
    canon = canon_bytes(d)
    total = canon or 1
    gd = d.get("gate_data") if isinstance(d.get("gate_data"), dict) else {}
    top_keys = sorted(((ser_bytes(v), k) for k, v in d.items()), reverse=True)[:top]
    gd_sub = sorted(((ser_bytes(v), k) for k, v in gd.items()), reverse=True)[:top]
    warnings = []
    if canon > STATE_SIZE_WALL:
        warnings.append("OVER_WALL: canon %d > wall %d" % (canon, STATE_SIZE_WALL))
    elif canon > STATE_SIZE_WALL - reserve:
        warnings.append("LOW_MARGIN: canon %d > wall-reserve %d"
                        % (canon, STATE_SIZE_WALL - reserve))
    lvl = wall_level(canon)
    if lvl["level"] != "ok":
        warnings.append("WALL_%s: canon %d = %.1f%% wall —— %s"
                        % (lvl["level"].upper(), canon, lvl["pct"], lvl["label"]))
    for b, k in top_keys:
        pct = 100.0 * b / total
        if pct >= _SINGLE_KEY_PCT_WARN:
            warnings.append("SINGLE_KEY_HEAVY: %s = %d B (%.1f%%)" % (k, b, pct))
    return {
        "ok": canon <= STATE_SIZE_WALL,
        "path": str(p),
        "disk_bytes": len(raw),
        "canon_bytes": canon,
        "wall": STATE_SIZE_WALL,
        "reserve": reserve,
        "margin": STATE_SIZE_WALL - canon,
        "over_wall": canon > STATE_SIZE_WALL,
        "pct": lvl["pct"], "level": lvl["level"], "level_label": lvl["label"],
        "block_pct": WALL_BLOCK_PCT,
        "form_diverged": len(raw) != canon,
        "gate_data_bytes": ser_bytes(gd),
        "top_keys": [{"key": k, "bytes": b, "pct": round(100.0 * b / total, 1)}
                     for b, k in top_keys],
        "gate_data_sub": [{"key": k, "bytes": b, "pct": round(100.0 * b / total, 1)}
                          for b, k in gd_sub],
        "warnings": warnings,
    }


def json_get(obj, path: str, default=None):
    """点路径取字段：dict 用键，list 用数字索引，缺失返回 default。空路径 → obj。"""
    node = obj
    for part in [p for p in path.split(".") if p]:
        if isinstance(node, dict):
            node = node.get(part)
        elif isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError, TypeError):
                return default
        else:
            return default
        if node is None:
            return default
    return node


def extract_markdown_table(md: str) -> list[list[str]]:
    """专业 markdown 表格解析：返回数据行（list[list[str]]）。

    跳过表头行、分隔行（|---|）、空行；单元格 strip。无表格 → []。
    比"末行纯数字"更通用：支持多列、中文、`{` 等特殊字符单元格。
    """
    if not isinstance(md, str):
        return []
    rows: list[list[str]] = []
    for line in md.splitlines():
        s = line.strip()
        if not s.startswith("|") or not s.endswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if all(re.fullmatch(r":?-+:?", c or "-") for c in cells):
            continue  # 分隔行（|---| / |:--| / |:-:| 变体）
        rows.append(cells)
    return rows[1:] if rows else []  # 跳表头


def extract_markdown_int(d: dict) -> int | None:
    """从 cypher markdown 表提取计数（None = 无数字）。

    升级（2026-09-01 用户质询"_count 是否需要 markdown 表格解析函数"）：
    原实现只找"末行 isdigit"单列数字，多列/含前缀时失效。现用
    extract_markdown_table 解析，从**最后一行数据**向后找第一个整数单元格
    （count 查询表恒为单行数据；多行时取末行 = 结果行）。
    """
    md = d.get("markdown", "")
    if not isinstance(md, str):
        return None
    rows = extract_markdown_table(md)
    for row in reversed(rows):
        for cell in reversed(row):
            if cell.lstrip("-").isdigit():
                return int(cell)
    # 兜底：非表格 markdown 文本里的末尾数字（原逻辑）
    for line in reversed(md.splitlines()):
        s = line.strip().strip("|").strip()
        if s.lstrip("-").isdigit():
            return int(s)
    return None


# ── CLI（2026-10-26，锚 RED-MIGRATE-INLINE）──────────────────────────────────
# `gatekeeper-cli.sh` 实测 212 处 `python3 -c`，其中**严格「纯取字段」形态**
# （load → 单 `.get(k, d)` → print）30 处：转义地狱 + 不可单测。本 CLI = 公共收敛点，
# 语义逐项对齐旧 `try: ... except Exception: print(default)`。
_MISSING = object()


def _cli_lookup(obj, path: str):
    """CLI 专用取字段：**区分「缺键」与「值恰为 null」**（对齐旧 `d.get(k, X)`）。

    `json_get` 遇 None 即回 default —— 对内部消费者合理，但 CLI 要对齐 shell 里的
    旧式 `d.get('k', 0)`：显式 `{"k": null}` 会返回 None ⟹ `print` 出 "None"，**不**取默认。
    """
    node = obj
    for part in [p for p in path.split(".") if p]:
        if isinstance(node, dict):
            if part not in node:
                return _MISSING
            node = node[part]
        elif isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError, TypeError):
                return _MISSING
        else:
            return _MISSING
    return node


def _cli_field(argv: list) -> int:
    """`field <点路径> [--default X] [--default-invalid Y] [--default-falsy Z]
    [--file P] [--env VAR] [--strict-path] [--len|--len-list|--bool-tf|--first-json]
    [--join SEP [--subkey K]] [--keys-join SEP] [--b64]`。

    读 stdin/文件/env → 取字段 → 单行输出。**exit 0**（不炸调用方，与旧实现等价）。
    值一律按 `print(val)` 输出（dict/list 走 Python repr），与旧式 `print(d.get(k, X))` 逐字节一致。

    三档默认值（对齐旧实现的三种写法）：
      - 缺字段 / 空容器 ⟹ `--default`（旧 `d.get(k, X)`）
      - 非法 JSON / IO 失败 / 根非 dict ⟹ `--default-invalid`（旧 `except: print(Y)`；缺省回落 `--default`）
      - 取到 falsy（None/False/0/""/[]/{}）⟹ `--default-falsy`（旧 `d.get(k, X) or Z`）
    `--env VAR`：从环境变量读 JSON（空/未设 ⟹ `{}`，对齐 `os.environ.get(VAR) or '{}'`）。

    派生投影（B7，2026-10-27）：
      - `--len`：缺键/falsy ⟹ 0，否则 `len(val)`（对齐 `len(d.get(k) or [])`）
      - `--len-list`：仅 list 计数，其他类型 ⟹ 0（对齐 `len(a) if isinstance(a, list) else 0`）
      - `--bool-tf`：真值 ⟹ `true`，假值/缺键 ⟹ `false`（对齐 `'true' if d.get(k) else 'false'`）
      - `--join SEP [--subkey K]`：list 逐项 join；给 `--subkey` 则取 `item.get(K, '')`
        （非 dict 项 ⟹ 解析失败档）；**根可为 list**（此时 path 传空串）
      - `--keys-join SEP`：dict 键 join（缺键/非 dict ⟹ 空）
      - `--first-json`：`json.dumps(list[0])`（缺键/空 ⟹ 解析失败档）
      - `--b64`：base64 解码后**原样写 stdout**（无尾换行；解码失败 ⟹ 空）
      - `--strict-path`：中间节点缺失/非容器 ⟹ 解析失败档（对齐旧 `['a']['b']` 的 KeyError）
    """
    path = argv[0] if argv else ""
    default = ""
    invalid_default = None
    falsy_default = None
    src = None
    env_var = None
    strict_path = False
    len_mode = None          # "any" | "list"
    bool_tf = False
    join_sep = None
    subkey = None
    keys_join = None
    first_json = False
    b64 = False
    i = 1
    while i < len(argv):
        if argv[i] == "--default" and i + 1 < len(argv):
            default = argv[i + 1]
            i += 2
        elif argv[i] == "--default-invalid" and i + 1 < len(argv):
            invalid_default = argv[i + 1]
            i += 2
        elif argv[i] == "--default-falsy" and i + 1 < len(argv):
            falsy_default = argv[i + 1]
            i += 2
        elif argv[i] == "--file" and i + 1 < len(argv):
            src = Path(argv[i + 1])
            i += 2
        elif argv[i] == "--env" and i + 1 < len(argv):
            env_var = argv[i + 1]
            i += 2
        elif argv[i] == "--strict-path":
            strict_path = True
            i += 1
        elif argv[i] == "--len":
            len_mode = "any"
            i += 1
        elif argv[i] == "--len-list":
            len_mode = "list"
            i += 1
        elif argv[i] == "--bool-tf":
            bool_tf = True
            i += 1
        elif argv[i] == "--join" and i + 1 < len(argv):
            join_sep = argv[i + 1]
            i += 2
        elif argv[i] == "--subkey" and i + 1 < len(argv):
            subkey = argv[i + 1]
            i += 2
        elif argv[i] == "--keys-join" and i + 1 < len(argv):
            keys_join = argv[i + 1]
            i += 2
        elif argv[i] == "--first-json":
            first_json = True
            i += 1
        elif argv[i] == "--b64":
            b64 = True
            i += 1
        else:
            print("usage: gk_json_utils.py field <dotted.path> [--default X] "
                  "[--default-invalid Y] [--default-falsy Z] [--file P] "
                  "[--env VAR] [--strict-path] [--len|--len-list|--bool-tf|--first-json] "
                  "[--join SEP [--subkey K]] [--keys-join SEP] [--b64]", file=sys.stderr)
            return 2
    if env_var is not None and src is not None:
        print("field: --env 与 --file 互斥", file=sys.stderr)
        return 2
    invalid_text = default if invalid_default is None else invalid_default
    try:
        if env_var is not None:
            obj = json.loads(os.environ.get(env_var) or "{}")
        elif src:
            obj = json.loads(src.read_text(encoding="utf-8"))
        else:
            obj = json.load(sys.stdin)
    except (OSError, ValueError, UnicodeDecodeError):
        if b64:
            return 0      # 旧式 `2>/dev/null > file` ⟹ 解析失败时文件为空
        print(invalid_text)
        return 0
    if not isinstance(obj, dict):
        # 根非 dict ⟹ 旧式 `d.get(...)` 必抛 AttributeError，落 except 档（差分对拍实测）。
        # 例外：`--join` 的根可以是 list（旧式 `for a in d` 直接迭代根列表）。
        if not (isinstance(obj, list) and join_sep is not None and path == ""):
            if b64:
                return 0
            print(invalid_text)
            return 0
    if strict_path:
        node = obj
        val = node
        parts = [p for p in path.split(".") if p]
        for idx, part in enumerate(parts):
            last = idx == len(parts) - 1
            if isinstance(node, dict):
                if part not in node:
                    if not last:
                        print(invalid_text)
                        return 0
                    val = _MISSING
                    break
                node = node[part]
            elif isinstance(node, list):
                try:
                    node = node[int(part)]
                except (ValueError, IndexError, TypeError):
                    if not last:
                        print(invalid_text)
                        return 0
                    val = _MISSING
                    break
            else:
                print(invalid_text)
                return 0
            val = node
    else:
        val = _cli_lookup(obj, path)
    if b64:
        # 旧式 `sys.stdout.buffer.write(base64.b64decode(d.get('sig','')))`：无尾换行。
        try:
            sys.stdout.buffer.write(
                base64.b64decode("" if val is _MISSING else str(val)))
        except Exception:  # noqa: BLE001 — 解码失败 ⟹ 空输出（旧式 rc≠0 但文件为空）
            pass
        return 0
    if len_mode == "list":
        print(0 if (val is _MISSING or not isinstance(val, list)) else len(val))
        return 0
    if len_mode == "any":
        print(0 if (val is _MISSING or not val) else len(val))
        return 0
    if bool_tf:
        print("false" if (val is _MISSING or not val) else "true")
        return 0
    if join_sep is not None:
        if val is _MISSING or not isinstance(val, list):
            print(invalid_text)
            return 0
        out = []
        for item in val:
            if subkey is not None:
                if not isinstance(item, dict):
                    print(invalid_text)
                    return 0
                out.append(str(item.get(subkey, "")))
            else:
                out.append(str(item))
        print(join_sep.join(out))
        return 0
    if keys_join is not None:
        if val is _MISSING:
            print("")
        elif not isinstance(val, dict):
            print(invalid_text)
        else:
            print(keys_join.join(str(k) for k in val.keys()))
        return 0
    if first_json:
        if val is _MISSING or not isinstance(val, list) or not val:
            print(invalid_text)
            return 0
        print(json.dumps(val[0]))
        return 0
    if val is _MISSING:
        print(default)
    elif falsy_default is not None and not val:
        print(falsy_default)
    else:
        # 一律 `print(val)`（= str）：dict/list 出 Python repr（`{'a': 1}`），
        # 与旧 `print(d.get('k', X))` **逐字节**一致（json.dumps 会变双引号 ⟹ 差分对拍实测 98 处不符）。
        print(val)
    return 0


def _cli_test(argv: list) -> int:
    """`test <点路径> [--is TYPE|--not-is TYPE] [--as T:F] [--first-line]`。

    谓词通道（替代 `python3 -c "sys.exit(0 if d.get(k) else 1)"`）：
      - 默认：根为 dict 且值 truthy ⟹ exit 0；否则（解析失败 / 根非 dict / 缺键）exit 1
      - `--is TYPE` / `--not-is TYPE`：改用 isinstance 判定（str|int|bool|list|dict|num）
        —— 注意 `""` 是 str ⟹ `--is str` 对空串判真（对齐旧 `isinstance`，不是真值判定）
      - `--as T:F`：改打印 T / F 且 **exit 0**（对齐旧 `print('1' if ... else '0')`）
      - `--first-line`：只解析 stdin 第一行（对齐旧 `json.loads(sys.stdin.readline())`）
    """
    _usage = ("usage: gk_json_utils.py test <dotted.path> [--is TYPE|--not-is TYPE] "
              "[--as T:F] [--first-line]")
    if not argv:
        print(_usage, file=sys.stderr)
        return 2
    path = argv[0]
    want_type = None
    negate_type = False
    as_pair = None
    first_line = False
    i = 1
    while i < len(argv):
        if argv[i] in ("--is", "--not-is") and i + 1 < len(argv):
            want_type = argv[i + 1]
            negate_type = argv[i] == "--not-is"
            i += 2
        elif argv[i] == "--as" and i + 1 < len(argv):
            as_pair = argv[i + 1]
            i += 2
        elif argv[i] == "--first-line":
            first_line = True
            i += 1
        else:
            print(_usage, file=sys.stderr)
            return 2
    type_map = {"str": str, "int": int, "bool": bool, "list": list, "dict": dict,
                "num": (int, float)}
    if want_type is not None and want_type not in type_map:
        print("test: unknown type %r (str|int|bool|list|dict|num)" % want_type,
              file=sys.stderr)
        return 2
    if as_pair is not None and ":" not in as_pair:
        print("test: --as requires T:F", file=sys.stderr)
        return 2
    try:
        obj = json.loads(sys.stdin.readline() if first_line else sys.stdin.read())
    except (ValueError, UnicodeDecodeError):
        obj = _MISSING
    if obj is _MISSING or not isinstance(obj, dict):
        ok = False
    else:
        val = _cli_lookup(obj, path)
        if want_type is None:
            ok = val is not _MISSING and bool(val)
        elif negate_type:
            # 解析失败/根非 dict 已在上支落 False（对齐旧 `except: sys.exit(1)`）
            ok = not (val is not _MISSING and isinstance(val, type_map[want_type]))
        else:
            ok = val is not _MISSING and isinstance(val, type_map[want_type])
    if as_pair is not None:
        true_txt, _, false_txt = as_pair.partition(":")
        print(true_txt if ok else false_txt)
        return 0
    return 0 if ok else 1


def _cli_valid(argv: list) -> int:
    """`valid`：stdin 是否为合法 JSON（任意根类型）；exit 0/1，零输出（对齐旧 `json.load`）。"""
    if argv:
        print("usage: gk_json_utils.py valid", file=sys.stderr)
        return 2
    try:
        json.load(sys.stdin)
    except (ValueError, UnicodeDecodeError):
        return 1
    return 0


def _cli_escape(argv: list) -> int:
    """`escape [--limit N] [--strip]`：stdin 原文 → `json.dumps` 单行转义串。

    对齐旧 `print(json.dumps(sys.stdin.read()[:N]))` / `... .strip()`：
    顺序 = 先 strip（若给）后截断（若给）；`json.dumps` 用默认 `ensure_ascii=True`
    （与旧式逐字节一致：中文出 `\\uXXXX`）。
    """
    limit = None
    strip = False
    i = 0
    while i < len(argv):
        if argv[i] == "--limit" and i + 1 < len(argv):
            try:
                limit = int(argv[i + 1])
            except ValueError:
                print("escape: --limit requires int", file=sys.stderr)
                return 2
            i += 2
        elif argv[i] == "--strip":
            strip = True
            i += 1
        else:
            print("usage: gk_json_utils.py escape [--limit N] [--strip]", file=sys.stderr)
            return 2
    text = sys.stdin.read()
    if strip:
        text = text.strip()
    if limit is not None:
        text = text[:limit]
    print(json.dumps(text))
    return 0


def main(argv: list) -> int:
    if not argv:
        print("usage: gk_json_utils.py {field|test|valid|escape} ...", file=sys.stderr)
        return 2
    if argv[0] == "field":
        return _cli_field(argv[1:])
    if argv[0] == "test":
        return _cli_test(argv[1:])
    if argv[0] == "valid":
        return _cli_valid(argv[1:])
    if argv[0] == "escape":
        return _cli_escape(argv[1:])
    print("unknown subcommand: %s" % argv[0], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
