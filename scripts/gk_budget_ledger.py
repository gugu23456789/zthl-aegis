#!/usr/bin/env python3
"""提额**旁挂账本** —— 读写**单源**（P2/P12/P13/P14；owner 裁定 C1–C4，2026-09-30）。

来源：`docs/plans/2026-09-18-edit-budget-dual-track-plan.md` §15.7c（P12–P14）/ §16。

载体
  · `<state>.budget-log.jsonl` —— append-only 记录（不参与 `state-patch` 整体替换）；
  · `<state>.budget-log.jsonl.seal` —— 完整性**封印**（Ed25519 有键则签；无键降级 sha256-only）。

四项裁定（owner 2026-09-30）
  · **C1 就地过滤**：每条记录带 `kind`（`raise` / `degrade` / `charge`；`charge` 为 2026-10-23 新增的
    扣款交易行）；读侧只把 `kind == raise` 计为**提额**。
  · **C2 补 seal**：每次 `append` 后重算封印；`mode` 显式标注（`ed25519` / `sha256`）。
  · **C3 fail-loud**：写失败**不再静默**（`append` 返 `{ok:false,error}`，CLI 侧 rc≠0 + 落 `GK_DBG_LOG`）。
  · **C4 坏行不计入**：JSON 解析失败的行，**写侧不参与链、读侧不计入**（两侧同口径）。

单一实现：`gatekeeper-cli.sh::_budget_log_append` / `gk_advance.budget_log_append`（写侧）
与 `gk_gate_entropy._raises_today` / `gk_audit_state._edit_budget_raises`（读侧）**全部委托本模块**。
"""
import argparse
import contextlib
import datetime
import hashlib
import json
import os
import sys
from pathlib import Path

SUFFIX = ".budget-log.jsonl"
SEAL_SUFFIX = ".budget-log.jsonl.seal"
KIND_RAISE = "raise"
KIND_DEGRADE = "degrade"
# 编辑级事件（T4′/T6 载体；2026-10-08）—— **独立**旁挂文件，避免污染提额账本及其封印。
KIND_EDIT = "edit"
EDIT_SUFFIX = ".edit-log.jsonl"
EDIT_SEAL_SUFFIX = ".edit-log.jsonl.seal"
# D3a（审计署 §26.6 owner 裁「该做」，2026-10-27）：**本地封印链**（append-only）。
# 缺口：原封印只覆盖「当前账本摘要」⟹ 旧账本 + 旧封印成对回放时 digest 与签名自洽，验签照绿。
# 链记录 `{seq, prev, seal, ledger, ...}`：`prev` = 上一条 `seal`，`seal` = 该次封印记录的规范 JSON 摘要。
# 检出面 = 部分回放（封印回退但链未退）/ 链截断 / prev 篡改；**三件套整体回放仍不可检出**（单机防呆已知盲区，
# 见 `test_gk_seal_chain.py::test_full_triple_rollback_is_known_blind_spot`；不靠 state 钉头掩盖）。
CHAIN_SUFFIX = ".seal-chain.jsonl"
EDIT_ARCHIVE_SUFFIX = ".edit-log-archive.jsonl"
EDIT_LOCK_SUFFIX = ".edit-log.lock"
EDIT_MAX_LINES = 2000                                     # 轮转阈值（§23.3 对策②）
# edit 事件 `result` 三态（ED3/§23.8.1；2026-10-08）：allow=放行、reject=门禁拒绝、override=逃生舱放行。
# 原内联 printf 硬编码 "allow" ⟹ T4′「同文件第 3 次被拒」结构上不可测（6/6 臂收敛缺陷 ED3）。
EDIT_RESULTS = ("allow", "reject", "override")
# verify 事件（T6 信号源；2026-10-08 §25）：识别到的**验证动作**（pytest/ctest/audit/run_verify 等）
# 只**采集**、不判罚（T6 先 telemetry）。与 edit 同载体（`<state>.edit-log.jsonl`），靠 `kind` 区分。
KIND_VERIFY = "verify"
# 步事件（2026-10-23）：**每条 RunCommand 一行**，只采集、不判罚。
#   动机（owner：「限制整体动刀额度而不管步数……业界管步数应该是经过长期探索的产物」）：
#   现计费面只数「唯一改动文件」，`RunCommand` 完全免费 ⟹ 空转 200 次 bash 的额度代价为零。
#   步数正是业界单位（Agents SDK 10 / LangGraph 25 / SWE-agent 250 / OpenHands 500），
#   但**本仓无历史步数数据** ⟹ 先 telemetry 再谈阈值（与 T6 同一纪律）。
#   **独立载体**（`<state>.step-log.jsonl`，不复用 edit-log）：步事件量级 ≫ 编辑事件，混进
#   edit-log 会 ① 稀释 T4′ 的 `EDIT_SPAM_WINDOW` 窗口（窗口按**记录数**切）；② 加速
#   `EDIT_MAX_LINES` 轮转，把 T6 尚需累积的编辑事件挤进 archive（读侧只看主文件）。
#   落点：`pre_tool_hook.py` 的**两条**放行分支（范围内 + scope_out）—— 只补一条会重演
#   T6 的「采样点够不着」缺陷。kill switch：`GK_STEP_LOG=0`（或 `GK_EDIT_LOG=0` 全关）。
KIND_STEP = "step"
STEP_SUFFIX = ".step-log.jsonl"
# 步数**告警**阈值（不阻断，仅统计面标注）：SWE-agent 250 / OpenHands 500 是**整任务**步数；
#   本仓按节点给额度，取 200 作「单节点疑似空转」软线 —— 先看分布，再定硬阈值。
STEP_WARN_PER_NODE = 200
# T4′ spam 判据（§3 T4′ / §25）：窗口 `N` 内同一 `path` 的「spam 事件」计数 ≥ `K` ⟹ `cost=2`。
# spam 事件 = 该 path 在**最近一次 verify 之后**的 edit 事件（T6 信号源复用）。
# 2026-10-23（owner 令「把 T4′ 的验证要求也加上」）：`result=reject` 由「无条件计数」降为
#   **诊断读数** —— 旧式 `reject or 未验证` 使「撞墙 3 次后补跑验证」仍被加价（只罚不兑付）。
# [ASSUMPTION-10] 窗口 N=50：**无真实 edit-log 分布可标定**（载体新落，历史零数据）⟹ 用**下界论证**取值 ——
#   节点 edit_budget 上限 = `min(lr×4, 16)` 个**触及文件数**，而 edit **事件数** ≥ 该值（同文件重复落刀
#   不计费但**逐条记事件**）⟹ N=20 可能 < 单节点活动量 ⟹ 看不清「同文件 K 次」的节点内累积。取 50 跨数节点。
#   kill switch `GK_EDIT_LOG_N`（窗口）/ `GK_EDIT_LOG_K`（阈值）/ `GK_EDIT_LOG=0`（整体关）。
EDIT_SPAM_WINDOW = 50
EDIT_SPAM_K = 3
# 单文件硬上限（REV-23；owner 2026-10-23 裁定 A + N=**10**）：同 path 自**最近一次 verify** 以来的
#   编辑数 ≥ N ⟹ 门禁**BLOCK**（不是加价）。病象：计费按「唯一改动文件」去重 ⟹ 反复改同一文件
#   只把 `cost` 抬到 2（T4′），**没有上限**；而「改崩」最典型的形态恰恰是同文件反复落刀。
#   取值依据（本机实测 edit 分布）：per-file `p90=8 / p99=29 / max=71` ⟹ 10 落在 p90 与 p99 之间，
#   挡得住 thrash 尾巴、不误伤常规迭代（6–8 会拦到正常改法）。
#   kill switch：`GK_EDIT_FILE_CAP=0` 关；`GK_EDIT_FILE_CAP=<n>` 覆盖 N。
FILE_EDIT_CAP = 10
# K/N **标定**参数（§23.6-2；2026-10-08 finding `ECC-6A0F7E9F0F5C`）——取数器 `calibrate` 用：
#   `EDIT_CALIB_PERCENTILE` = 取分布分位（默认 90 ⟹ 判罚最 thrash 的 10% 节点）；
#   `EDIT_CALIB_MIN_NODES` = 最小样本（`(session,node)` 组数），不足则**不下结论**（禁少量外推）。
EDIT_CALIB_PERCENTILE = 90
EDIT_CALIB_MIN_NODES = 20
# 降级早警来源（R2 §15.3 落刀后写入）；此处**预先登记**以免落刀时再改读侧口径。
DEGRADE_SOURCES = ("degrade", "r2-degrade")
TTL_DEFAULT = 1800


@contextlib.contextmanager
def _budget_lock(state_file: str):
    """budget-log 跨进程互斥（2026-11-09，修封印链重复 seq 根因）。

    病象：`append` = 「读记录 → 追加行 → `seal_now`（读链尾 → 写 seal → 追加链）」整段
    **无锁** ⟹ 两个并发 append 各自 seal 同一份账本摘要 ⟹ 链上出现**同 seq 的重复条目**
    （实测 `seq=1582` 逐字重复；`_verify_chain` 因此判 `seq_mismatch`，advance 被
    `RAISE_LEDGER_SEAL_INVALID` 拦下）。本锁把「追加行 + 重算封印 + 推链」串行化。
    载体 = `<state>.budget-log.lock`（独立于 edit-log / state 锁）；`fcntl` 不可用
    （裸 Windows python）⟹ 降级为无锁（同 `_edit_lock` 的既有口径，由单写者纪律兜）。
    """
    lp = Path(str(state_file) + ".budget-log.lock")
    try:
        f = open(lp, "a+")
    except OSError:
        yield
        return
    try:
        try:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        except Exception:
            pass
        yield
    finally:
        try:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        f.close()


def _logical_path(state_file: str) -> Path:
    return Path(str(state_file) + SUFFIX)


def _seal_path(state_file: str) -> Path:
    return Path(str(state_file) + SEAL_SUFFIX)


def _edit_path(state_file: str) -> Path:
    return Path(str(state_file) + EDIT_SUFFIX)


def _step_path(state_file: str) -> Path:
    return Path(str(state_file) + STEP_SUFFIX)


def _edit_seal_path(state_file: str) -> Path:
    return Path(str(state_file) + EDIT_SEAL_SUFFIX)


@contextlib.contextmanager
def _edit_lock(state_file: str):
    """edit-log 跨进程互斥（ED5/§23.8.1）：`flock` 串行化 append/rotate/seal 的读-改-写。

    `fcntl` 不可用（非 POSIX，如裸 Windows python）⟹ **降级为无锁**（不阻断；语义回退到修前，
    由「单写者」纪律兜）。锁文件 = `<state>.edit-log.lock`（**独立**于 budget-log / state 锁）。
    """
    lp = Path(str(state_file) + EDIT_LOCK_SUFFIX)
    try:
        f = open(lp, "a+")
    except OSError:
        yield
        return
    try:
        try:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        except Exception:
            pass
        yield
    finally:
        try:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        f.close()


KIND_CHARGE = "charge"        # 2026-10-23：**扣款交易**（区外差额记账；见 gatekeeper-cli.sh `_budget_snap`）
# 2026-10-31（数据层，standard §12.4.2 / edit-budget §12.7）：`to_max <= from_max` 的写入
#   （`state-patch --set-nested` 改 used/remaining、或降额）**不是提额**。原实现只要 source
#   不是 degrade/charge 就记 `raise` ⟹ 全仓 429 行 raise 中 97.7% 是 no-op，熵第三支与
#   audit「提额频次」同时失真。本 kind 只做**分类**，不改变封印/链语义。
KIND_BOOKKEEPING = "bookkeeping"


def _is_true_raise(rec: dict) -> bool:
    """`kind=raise` 且额度**真的上调**（`to_max > from_max`）。

    兼容历史行：`from_max` / `to_max` 缺失（旧行/首条）⇒ 按提额计（零回归，C1/C4 口径不变）。
    """
    if (rec.get("kind") or KIND_RAISE) != KIND_RAISE:
        return False
    fm, tm = rec.get("from_max"), rec.get("to_max")
    if fm is None or tm is None:
        return True
    try:
        return int(tm) > int(fm)
    except (TypeError, ValueError):
        return True   # 坏值按旧口径计入，坏行由 C4 的 ts 规则处理，不在此静默丢弃


def classify_source(source: str) -> str:
    """C1：来源 → `kind`。

    `charge` = 扣款交易行（2026-10-23）；`degrade` 族 = 降级早警；其余（提额/人工抬额/覆盖放行）
    为 `raise`。**charge 必须独立成 kind** —— 否则会被计入「提额频次」（`_edit_budget_raises`），
    把「花掉多少」读成「抬了多少」。
    """
    src = str(source or "")
    if src == KIND_CHARGE:
        return KIND_CHARGE
    return KIND_DEGRADE if src in DEGRADE_SOURCES else KIND_RAISE


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _now_str() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────── D3a：本地封印链（单源）───────────────────────
def _chain_path(seal_path) -> Path:
    return Path(str(seal_path) + CHAIN_SUFFIX)


def _chain_tail(seal_path):
    """读链日志**最后一条**（尾读 4 KiB）；无链 / 空链 / 坏行 ⟹ `None`。"""
    p = _chain_path(seal_path)
    try:
        with open(p, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size <= 0:
                return None
            f.seek(max(0, size - 4096))
            tail = f.read().decode("utf-8", "replace")
    except OSError:
        return None
    for line in reversed([x for x in tail.splitlines() if x.strip()]):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and isinstance(rec.get("seq"), int):
            return rec
    return None


def _seal_with_chain(seal_path, raw: bytes, key_dir: str = "") -> tuple:
    """写封印 + 链（**单源**；`seal_now` / `seal_edits` 共用）。→ `(rec, error)`。"""
    digest = hashlib.sha256(raw).hexdigest()
    mode, sig, fp = _sign(digest, _key_dir(key_dir))
    prev = _chain_tail(seal_path) or {}
    seq = int(prev.get("seq") or 0) + 1
    rec = {"alg": "sha256", "mode": mode, "sha256": digest,
           "key": ("audit_ed25519" if mode == "ed25519" else ""),
           "key_fp": fp, "sig": sig, "bytes": len(raw), "sealed_at": _now_str(),
           "seq": seq, "prev_seal": str(prev.get("seal") or "")}
    try:
        seal_path.write_text(json.dumps(rec, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as e:
        return None, "seal_write_failed: %s" % e
    entry = {"seq": seq, "prev": rec["prev_seal"],
             "seal": hashlib.sha256(_canonical(rec)).hexdigest(),
             "ledger": digest, "bytes": len(raw), "mode": mode, "at": rec["sealed_at"]}
    try:
        with open(_chain_path(seal_path), "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as e:
        return None, "chain_write_failed: %s" % e
    return rec, ""


def _verify_chain(seal_path, seal: dict, digest: str) -> dict:
    """链完整性 + 当前封印必须是链头。→ `{ok, reason, seq}`。"""
    p = _chain_path(seal_path)
    if not p.exists():
        return {"ok": False, "reason": "chain_missing"}
    try:
        lines = [x for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]
    except OSError as e:
        return {"ok": False, "reason": "chain_unreadable: %s" % e}
    if not lines:
        return {"ok": False, "reason": "chain_missing"}
    entries = []
    for i, line in enumerate(lines, 1):
        try:
            ent = json.loads(line)
        except json.JSONDecodeError:
            return {"ok": False, "reason": "chain_unreadable"}
        if not isinstance(ent, dict) or ent.get("seq") != i:
            return {"ok": False, "reason": "seq_mismatch"}
        if i > 1 and ent.get("prev") != entries[-1].get("seal"):
            return {"ok": False, "reason": "chain_prev_mismatch"}
        entries.append(ent)
    head = entries[-1]
    if head.get("seal") != hashlib.sha256(_canonical(seal)).hexdigest():
        return {"ok": False, "reason": "seal_not_head"}
    if head.get("ledger") != digest:
        return {"ok": False, "reason": "seal_not_head"}
    if seal.get("seq") not in (None, head.get("seq")):
        return {"ok": False, "reason": "seq_mismatch"}
    return {"ok": True, "reason": "ok", "seq": head.get("seq")}


def _parse_ts(ts):
    try:
        return datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def read_records(state_file: str) -> tuple:
    """读全部记录 + 完整性统计 `(records, stat)`。

    `stat` = `{"lines", "bad", "raises", "degrades", "seal_ok", "seal_mode"}`。
    **C4**：JSON 解析失败的行走 `bad`，**不进** `records`（也不参与任何计数）。
    """
    p = _logical_path(state_file)
    records, bad = [], 0
    if p.exists():
        try:
            for line in p.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    bad += 1                      # C4：坏行不计入
                    continue
                if isinstance(rec, dict):
                    records.append(rec)
                else:
                    bad += 1
        except OSError:
            pass
    st = verify_seal(state_file)
    return records, {
        "lines": len(records) + bad,
        "bad": bad,
        # C1（2026-10-23 订正）：**只算 `kind=raise`**。原判据 `!= degrade` 在新增 `charge` 后
        #   会把**扣款交易**读成提额 ⟹ `audit` 的 `raises_today>阈值` 每天必红（假红）。
        "raises": sum(1 for r in records if (r.get("kind") or KIND_RAISE) == KIND_RAISE),
        # 2026-10-31：`raises` 保留**行数**（审计对账用）；`true_raises` = 额度真上调的行
        "true_raises": sum(1 for r in records if _is_true_raise(r)),
        "bookkeeping": sum(1 for r in records if (r.get("kind") or KIND_RAISE) == KIND_BOOKKEEPING),
        "degrades": sum(1 for r in records if (r.get("kind") or KIND_RAISE) == KIND_DEGRADE),
        "charges": sum(1 for r in records if (r.get("kind") or KIND_RAISE) == KIND_CHARGE),
        "unlocks": sum(1 for r in records if (r.get("kind") or "") == KIND_UNLOCK),
        "seal_ok": st.get("ok"),
        "seal_reason": st.get("reason"),
        "seal_mode": st.get("mode"),
    }


def _econ_baseline(state_file: str) -> str:
    """激活基线时间戳 —— **单源解析** = `gk_econ_baseline.resolve`（credit 签名基线权威，
    `econ_enabled_at` 仅 legacy 回退；不一致由 N 门出 drift finding）。缺失 ⟹ `""`（零回归）。
    """
    try:
        from gk_econ_baseline import resolve
        return str(resolve(state_file).get("ts") or "")
    except Exception:
        try:
            d = json.loads(Path(state_file).read_text(encoding="utf-8"))
            return str((d.get("gate_data") or {}).get("econ_enabled_at") or "")
        except (OSError, json.JSONDecodeError, TypeError, AttributeError):
            return ""


class LedgerSealInvalid(RuntimeError):
    """提额账本封印缺失/失效 —— **具名 fail-loud**（2026-10-31，§9.4 额外缺口①）。

    原 `count_raises` 调 `verify_seal` 却不因 `seal_ok=False` 拒算 ⟹ 直接编辑/删
    `<state>.budget-log.jsonl` 可把熵与 CAP 计数**清零**而门禁照绿。现读侧统一抛本异常，
    由 entropy / cap / advance 转成具名错误，禁止按 0 静默放行。
    """
    code = "RAISE_LEDGER_SEAL_INVALID"


KIND_UNLOCK = "human_unlock"


def count_unlocks_today(state_file: str) -> int:
    """当日（UTC）`kind=human_unlock` 条数 —— 人工解锁的**唯一**消费面（CAP 抵扣）。

    2026-10-31（§6 臂 8）：非 LLM、append-only、可复算；封印失效 ⟹ 与提额计数同口径 fail-loud。
    """
    if not state_file:
        return 0
    records, st = read_records(state_file)
    if not st.get("seal_ok"):
        raise LedgerSealInvalid(
            "提额账本封印缺失/失效（%s）：%s" % (state_file, st.get("seal_reason") or "seal_missing"))
    today = datetime.datetime.now(datetime.timezone.utc).date()
    n = 0
    for rec in records:
        if (rec.get("kind") or "") != KIND_UNLOCK:
            continue
        dt = _parse_ts(rec.get("ts"))
        if dt is not None and dt.date() == today:
            n += 1
    return n


def record_unlock(state_file: str, operator: str, reason: str, key_dir: str = "") -> dict:
    """记录一次人工解锁（公开入口；**持 `_budget_lock`**，与 append 同锁串行）。"""
    if not state_file:
        return {"ok": False, "error": "UNLOCK_ARG_REQUIRED", "detail": "state required"}
    with _budget_lock(state_file):
        return _record_unlock_unlocked(state_file, operator, reason, key_dir)


def _record_unlock_unlocked(state_file: str, operator: str, reason: str, key_dir: str = "") -> dict:
    """记录一次**人工解锁**（调用方**已持锁**），供 CAP 抵扣一次提额。

    - 非 LLM：只收人类可核验的 `operator` + `reason`，不接受任何模型分数；
    - append-only：只追加，不改历史、不改额度；写完重算封印（可复算/可验签）；
    - fail-loud：无账本 / 封印失效 / 缺字段 ⟹ 具名错误，不静默成功。
    """
    if not state_file:
        return {"ok": False, "error": "UNLOCK_ARG_REQUIRED", "detail": "state required"}
    operator, reason = str(operator or "").strip(), str(reason or "").strip()
    if not operator or not reason:
        return {"ok": False, "error": "UNLOCK_ARG_REQUIRED",
                "detail": "operator 与 reason 均为必填（人工解锁必须可追责）"}
    p = _logical_path(state_file)
    if not p.exists():
        return {"ok": False, "error": "UNLOCK_NO_LEDGER",
                "detail": "尚无提额账本；先有真实提额事件才需要解锁"}
    records, st = read_records(state_file)
    if not st.get("seal_ok"):
        return {"ok": False, "error": "RAISE_LEDGER_SEAL_INVALID",
                "detail": "封印缺失/失效（%s）" % (st.get("seal_reason") or "seal_missing"),
                "hint": "先 verify/恢复封印，再走人工解锁"}
    rec = {"ts": _now_str(), "kind": KIND_UNLOCK, "source": "human_unlock",
           "operator": operator, "reason": reason, "scope": "raise_cap"}
    try:
        with open(p, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        return {"ok": False, "error": "UNLOCK_WRITE_FAILED", "detail": str(e)}
    sealed = _seal_now_unlocked(state_file, key_dir=key_dir)
    if not sealed.get("ok", True):
        return {"ok": False, "error": "UNLOCK_SEAL_FAILED", "detail": sealed}
    return {"ok": True, "unlock": rec, "unlocks_today": count_unlocks_today(state_file)}


def count_raises(state_file: str) -> tuple:
    """→ `(total_raise, today_raise_utc)`：**只算真提额**（C1 + 2026-10-31 分类），**坏行不计**（C4）。

    2026-10-31（数据层）：判据从「`kind == raise`」收紧为「`kind == raise` **且额度真的上调**」
    （`_is_true_raise`）——原口径把 `state-patch --set-nested` 改 `used/remaining` 的 no-op 也算
    提额（全仓 97.7%），导致熵第三支与 F/K/CAP 的分子失真。历史行按 `to_max > from_max` 兼容，
    无需改数据。**行数**统计仍在 `read_records` 的 `raises` 字段（审计对账用）。

    2026-10-31（激活基线）：`gate_data.econ_enabled_at` 之前的行**不计入**（转当日不自锁）。

    保留既有约定：`ts` 缺失的（旧行/裸计数行）计入当日；`ts` 解析失败的按坏行**不计**。
    """
    if not state_file:
        return (0, 0)
    records, _st = read_records(state_file)
    if not _st.get("seal_ok"):
        raise LedgerSealInvalid(
            "提额账本封印缺失/失效（%s）：%s" % (state_file, _st.get("seal_reason") or "seal_missing"))
    today = datetime.datetime.now(datetime.timezone.utc).date()
    _base_dt = _parse_ts(_econ_baseline(state_file))
    total = today_n = 0
    for rec in records:
        if not _is_true_raise(rec):
            continue                                  # C1：降级/扣款不是提额；no-op 字段更新也不是
        ts = str(rec.get("ts", "") or "")
        if not ts:
            total += 1
            today_n += 1
            continue
        dt = _parse_ts(ts)
        if dt is None:
            continue                                  # C4：坏时戳不计入
        if _base_dt is not None and dt < _base_dt:
            continue                                  # 激活基线之前的行不计（econ_enabled_at）
        total += 1
        if dt.date() == today:
            today_n += 1
    return (total, today_n)


# ─────────────── 编辑级事件（T4′/T6 载体；2026-10-08，owner 裁定 A）───────────────
# 载体 = **独立**旁挂 `<state>.edit-log.jsonl`（append-only；**不**参与 state-patch 整体替换）。
# 动机（实读核实）：`billed_files` 是 dedup 集合（重复被折叠、无 ts）、`rejected_edits` 语义错配
#   （= `gk_advance._monitor_eval` 的 advance 阻断窗口）⟹ 二者均不可测「同文件重复 / 编辑后无验证」。
# 性能（§23.3 对策①）：编辑是高频 ⟹ **裸追加**、**不**逐条 seal（seal 由区外侧在节点/审计边界低频重算）。
def _node_seq(edits: list, session: str, node: str) -> int:
    """同会话的**节点实例序**（ED6/§23.8.1）：`node` 是 `NODE_REGISTRY` **类型**（同批可多次进入），
    `node_seq` = 该会话内「节点连续段」的序号（节点变化即 +1）⟹ `(node, node_seq)` 唯一定位一次进入。

    取「下一段序号」：当前 `node` == 上一段节点 ⟹ 同段（返回段数）；否则新段（段数 +1）；无历史 ⟹ 1。
    """
    last_node, seg = None, 0
    for e in edits:
        if str(e.get("session") or "") != str(session or ""):
            continue
        n = str(e.get("node") or "")
        if n != last_node:
            seg += 1
            last_node = n
    if seg == 0:
        return 1
    return seg if str(node or "") == str(last_node or "") else seg + 1


def append_edit(state_file: str, session: str = "", node: str = "", path: str = "",
                result: str = "allow") -> dict:
    """追加一条编辑事件（`kind=edit`）。**裸追加**：不 seal、不碰 `eb` ⟹ 零计费副作用。

    ED1/ED8：本函数是 edit-log 的**唯一写侧单源**（CLI 经 `edit-append` 子命令委托）；
    `ts` 一律 `_now_str()`（UTC）—— 消原 CLI 内联 `printf` 的**本地时区 + 字面 Z** 双源。
    ED3：`result ∈ EDIT_RESULTS`（`allow`/`reject`/`override`），非法值降 `allow`。
    ED5：整段（读已有 + 追加 + 算 `node_seq`）在 `_edit_lock` 内 ⟹ 消并发 RMW 丢事件。
    ED6：`node_seq` = 同会话节点实例序（`(node, node_seq)` 定位一次进入）。
    """
    if not state_file:
        return {"ok": False, "error": "no_state_file"}
    _res = str(result or "allow")
    if _res not in EDIT_RESULTS:
        _res = "allow"
    try:
        with _edit_lock(state_file):
            edits = read_edits(state_file)
            rec = {"ts": _now_str(), "kind": KIND_EDIT, "source": "edit",
                   "session": str(session or ""), "node": str(node or ""),
                   "node_seq": _node_seq(edits, session, node),
                   "path": str(path or ""), "result": _res}
            with open(_edit_path(state_file), "a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        return {"ok": False, "error": "append_failed: %s" % e}
    return {"ok": True, "record": rec}


def _int_or(v, d: int) -> int:
    """`v` 可转 int ⟹ 该值；否则回退 `d`（容忍 env 空串 / 非法值）。"""
    try:
        return int(v)
    except (TypeError, ValueError):
        return d


def append_verify(state_file: str, session: str = "", node: str = "", cmd: str = "") -> dict:
    """追加一条**验证动作**事件（`kind=verify`）。**裸追加**：不 seal、不碰 `eb` ⟹ 零计费副作用。

    T6 信号源（§23.6-3；2026-10-08 §25）：把「编辑之后是否发生验证动作」变成可观测事实
    （pytest / ctest / audit / run_verify 等，由 hook 侧识别）。本批**只采集不判罚**（T6 先 telemetry）。
    单源写者：与 `append_edit` 同走 `_edit_lock`（ED5），同载体靠 `kind` 区分。
    """
    if not state_file:
        return {"ok": False, "error": "no_state_file"}
    try:
        with _edit_lock(state_file):
            rec = {"ts": _now_str(), "kind": KIND_VERIFY, "source": "verify",
                   "session": str(session or ""), "node": str(node or ""),
                   "cmd": str(cmd or "")[:240]}
            with open(_edit_path(state_file), "a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        return {"ok": False, "error": "append_failed: %s" % e}
    return {"ok": True, "record": rec}


def append_step(state_file: str, session: str = "", node: str = "", cmd: str = "") -> dict:
    """追加一条**步事件**（`kind=step`）到**独立**载体 `<state>.step-log.jsonl`。

    2026-10-23：步数是业界（Agents SDK / LangGraph / SWE-agent / OpenHands）的**主计量单位**，
    而本仓此前只数「唯一改动文件」、`RunCommand` 免费 ⟹ 空转无法观测。本批**只采集不判罚**，
    由 `step_stats` 出分布后再定阈值（与 T6 同一纪律）。写侧单源、同 `_edit_lock`（跨进程串行）。
    ⚠ **不进 edit-log**：步事件量级 ≫ 编辑事件，混入会稀释 T4′ 窗口并按记录数加速轮转。
    """
    if not state_file:
        return {"ok": False, "error": "no_state_file"}
    try:
        with _edit_lock(state_file):
            rec = {"ts": _now_str(), "kind": KIND_STEP, "source": "step",
                   "session": str(session or ""), "node": str(node or ""),
                   "cmd": str(cmd or "")[:240]}
            with open(_step_path(state_file), "a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        return {"ok": False, "error": "append_failed: %s" % e}
    return {"ok": True, "record": rec}


def read_steps(state_file: str) -> list:
    """**文件序**读全部 `kind=step` 事件（坏行/异 kind 跳过；纯 telemetry ⟹ 不计数告警）。"""
    if not state_file:
        return []
    p = _step_path(state_file)
    out = []
    if not p.exists():
        return out
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and rec.get("kind") == KIND_STEP:
                out.append(rec)
    except OSError:
        pass
    return out


def read_events_stat(state_file: str) -> tuple:
    """`(events, stat)`；`events` = **文件序**全部合法事件（`kind ∈ {edit, verify}`）。

    `stat = {"lines", "bad", "edits", "verifies"}`。ED4：坏行**显式计数**（JSON 解析失败 /
    未知 kind / 非法形状），不再静默跳过 ⟹ 消「0 条」歧义（原「专表专用」升格为「本事件表专用」）。
    ⚠ 步事件（`kind=step`）在**独立**载体 `.step-log.jsonl`，不进本函数（见 `read_steps`）。
    """
    if not state_file:
        return [], {"lines": 0, "bad": 0, "edits": 0, "verifies": 0}
    p = _edit_path(state_file)
    out, bad, ne, nv, lines = [], 0, 0, 0, 0
    if p.exists():
        try:
            for line in p.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                lines += 1
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    bad += 1                          # ED4：坏行计入（原静默跳过 ⟹「0 条」歧义）
                    continue
                k = rec.get("kind") if isinstance(rec, dict) else None
                if k == KIND_EDIT:
                    out.append(rec); ne += 1
                elif k == KIND_VERIFY:
                    out.append(rec); nv += 1
                else:
                    bad += 1                          # 未知 kind / 非法形状亦计入（本事件表专用）
        except OSError:
            pass
    return out, {"lines": lines, "bad": bad, "edits": ne, "verifies": nv}


def read_edits_stat(state_file: str) -> tuple:
    """`(edits, stat)`；仅 `kind=edit`（`stat` 保留旧键子集 `{lines,bad,edits}`；委托 `read_events_stat`）。"""
    evs, stat = read_events_stat(state_file)
    edits = [r for r in evs if r.get("kind") == KIND_EDIT]
    return edits, {"lines": stat["lines"], "bad": stat["bad"], "edits": stat["edits"]}


def read_edits(state_file: str) -> list:
    """只取 `kind == edit` 的事件（委托 `read_edits_stat` 单源）。"""
    return read_edits_stat(state_file)[0]


def read_events(state_file: str) -> list:
    """**文件序**取全部事件（`kind ∈ {edit, verify}`）—— T4′/T6 窗口判据用。"""
    return read_events_stat(state_file)[0]


def count_edits(state_file: str, window: int = None) -> int:
    """编辑事件数；`window` 非 None ⟹ 只数**最近 N 条**（T4′ 窗口判据用）。"""
    ed = read_edits(state_file)
    if window is not None:
        try:
            ed = ed[-int(window):]
        except (TypeError, ValueError):
            pass
    return len(ed)


def edit_spam_flag(state_file: str, path: str, window=None, k=None, session: str = "") -> dict:
    """T4′（§3 T4′ / §25）：窗口 `N` 内同一 `path` 的**spam 事件**计数 ≥ `K` ⟹ 本次编辑 `cost=2`。

    spam 事件（**判罚腿统一**；2026-10-23 owner 令「把 T4′ 的验证要求也加上」）：
      同 `path` 在**最近一次 verify 事件之后**的编辑事件数（T6 信号源复用）。
      · `result=reject` **不**再无条件计数 —— 旧式 `reject 或 未验证` 使「同文件撞墙 3 次后补跑
        验证」仍被加价（下一刀照样 `cost=2`）= **只罚不兑付**；现仅作**诊断读数**返回。
      · 守卫：验证**之后**再撞墙仍计（验证不是永久免罪符）。

    `session` 非空 ⟹ 只计该会话事件；空 ⟹ **全局**窗口（对齐 §3「窗口内同一 file_path」字面）。
    只读。→ `{"flagged", "reject", "unverified", "count", "window", "k", "path"}`。
    """
    _w = _int_or(window, EDIT_SPAM_WINDOW)
    _k = _int_or(k, EDIT_SPAM_K)
    evs = read_events(state_file)
    if session:
        evs = [e for e in evs if str(e.get("session") or "") == str(session)]
    if _w > 0:
        evs = evs[-_w:]
    last_v = -1
    for i, e in enumerate(evs):
        if e.get("kind") == KIND_VERIFY:
            last_v = i
    reject = unver = count = 0
    for i, e in enumerate(evs):
        if e.get("kind") != KIND_EDIT:
            continue
        if str(e.get("path") or "") != str(path or ""):
            continue
        is_rej = str(e.get("result") or "") == "reject"
        is_unv = i > last_v
        if is_rej:
            reject += 1                                    # 诊断读数（**不**参与判罚）
        if is_unv:
            unver += 1
        # 2026-10-23（owner 令「把 T4′ 的验证要求也加上」）：判罚腿**统一**为
        #   「最近一次 verify 之后的编辑」—— 被拒腿不再**无条件**计数（旧式 `is_rej or is_unv`
        #   ⟹ 撞墙 3 次后即使补跑验证仍 flagged，下一刀照样 cost=2 = 罚得下去、兑付不了）。
        #   `reject` 保留为**诊断读数**，供 `edit-flag` / 审计解释「为什么被加价」。
        if is_unv:
            count += 1
    return {"flagged": count >= _k, "reject": reject, "unverified": unver,
            "count": count, "window": _w, "k": _k, "path": str(path or "")}


def file_cap_flag(state_file: str, path: str, k=None, session: str = "",
                  node: str = "") -> dict:
    """单文件硬上限判据（REV-23，2026-10-23；**只读**）。

    计数面 = 同 `(session,node)` 内、**最近一次 verify 之后**、同 `path` 的**放行**编辑数
    （`result=reject` 不计 —— 与 T4′/T6 同口径：被门禁拒掉的尝试不是「实际改动」，
    否则「撞墙一次 ⟹ 计数 +1 ⟹ 更撞墙」会自我强化）。
    与 T4′ 的分工：T4′ 数「窗口内 spam 事件」并**加价**（`cost=2`）；本判据数「自上次验证以来
    的同文件落刀」并**阻断** —— 因为「反复改同一文件」正是改崩的典型形态，加价拦不住
    （额度还够就一直改下去）。

    销账通道 = `kind=verify`（同 `session`+`node`），与 T6 同一信号源：先证明没改崩再继续。
    `k` 缺省 `FILE_EDIT_CAP`；`k <= 0` ⟹ 停用（恒不 flagged）。
    `session`/`node` 为空 ⟹ 该维度不筛（手工调 CLI 时的全局口径）。
    → `{"flagged", "count", "k", "path", "session", "node"}`。
    """
    _k = _int_or(k, FILE_EDIT_CAP)
    evs = read_events(state_file)
    if session:
        evs = [e for e in evs if str(e.get("session") or "") == str(session)]
    if node:
        evs = [e for e in evs if str(e.get("node") or "") == str(node)]
    last_v = -1
    for i, e in enumerate(evs):
        if e.get("kind") == KIND_VERIFY:
            last_v = i
    count = 0
    for i, e in enumerate(evs):
        if i <= last_v or e.get("kind") != KIND_EDIT:
            continue
        if str(e.get("result") or "allow") == "reject":
            continue
        if str(e.get("path") or "") == str(path or ""):
            count += 1
    return {"flagged": bool(_k > 0 and count >= _k), "count": count, "k": _k,
            "path": str(path or ""), "session": str(session or ""),
            "node": str(node or "")}


def batch_open(state_file: str, session: str = "", node: str = "") -> bool:
    """**批次计价**（REV-24，2026-10-23；只读）：本批是否**尚未开账**。

    批次边界 = **verify**（owner 2026-10-23 裁定口径）：
      · 同 `(session,node)` 内自**最近一次 verify** 以来**放行**编辑数 == 0 ⟹ 本刀 = **本批第一刀**
        ⟹ 扣 1 单位；`False` = 本批已开账 ⟹ 本刀不另计。
      · `reject` 不计（同 T4′/T6 口径：被拒尝试不是实际改动）。
      · 语义边界（如实）：同一批内改**不同**文件不再逐个计费 —— 这是「批次作单位」的**代价**；
        兜底 = `file_cap_flag`（同文件 ≤ N）+ 节点额度（12 批）。
    """
    evs = read_events(state_file)
    if session:
        evs = [e for e in evs if str(e.get("session") or "") == str(session)]
    if node:
        evs = [e for e in evs if str(e.get("node") or "") == str(node)]
    last_v = -1
    for i, e in enumerate(evs):
        if e.get("kind") == KIND_VERIFY:
            last_v = i
    for i, e in enumerate(evs):
        if i <= last_v or e.get("kind") != KIND_EDIT:
            continue
        if str(e.get("result") or "allow") == "reject":
            continue
        return False                      # 已有放行编辑 ⟹ 本批已开账
    return True


def _t6_groups(evs: list) -> dict:
    """T6 分组**单源**（读数面 + 判据共用）：→ `{"<session>/<node>": {"edits","verifies","unverified"}}`。

    `unverified` = 该 `(session,node)` 内**最近一次 verify 之后**的**放行**编辑数
    （`reject` 归 T4′ 被拒腿，**不**计入）。（§25.7 / §25.8）
    """
    lastv, out = {}, {}
    for i, e in enumerate(evs):
        if e.get("kind") == KIND_VERIFY:
            lastv["%s/%s" % (e.get("session") or "", e.get("node") or "")] = i
    for i, e in enumerate(evs):
        key = "%s/%s" % (e.get("session") or "", e.get("node") or "")
        d = out.setdefault(key, {"edits": 0, "verifies": 0, "unverified": 0})
        if e.get("kind") == KIND_EDIT:
            d["edits"] += 1
            if str(e.get("result") or "allow") != "reject" and i > lastv.get(key, -1):
                d["unverified"] += 1
        elif e.get("kind") == KIND_VERIFY:
            d["verifies"] += 1
    return out


def node_unverified_flag(state_file: str, session: str = "", node: str = "",
                         k=None) -> dict:
    """T6 判据（§3 T6 / §25.8）：同一 `(session,node)` 内**未验证编辑**累计 ≥ `K` ⟹ 本节点后续编辑 `cost=2`。

    只读。→ `{"flagged", "unverified", "k", "session", "node"}`。阈值 `K` 缺省 `EDIT_SPAM_K`
    （kill switch `GK_T6_K` 覆盖，见 CLI）。跨文件散点 thrash 的约束（T4′ 只管同文件）。
    """
    _k = _int_or(k, EDIT_SPAM_K)
    key = "%s/%s" % (session or "", node or "")
    unv = _t6_groups(read_events(state_file)).get(key, {}).get("unverified", 0)
    return {"flagged": unv >= _k, "unverified": unv, "k": _k,
            "session": str(session or ""), "node": str(node or "")}


def seal_edits(state_file: str, key_dir: str = "") -> dict:
    """edit-log 的**节点级封印**（低频；镜像 `seal_now`，但作用于 EDIT_SUFFIX/EDIT_SEAL_SUFFIX）。

    `append_edit` **不**逐条 seal（高频）⟹ 由区外低频边界（审计）调本函数重算（§23.3 对策①）。
    ED5：读字节 + 写 seal 在 `_edit_lock` 内 ⟹ 消与并发 append 的竞态（原可产生 digest_mismatch 误红）。
    """
    p = _edit_path(state_file)
    try:
        with _edit_lock(state_file):
            raw = p.read_bytes() if p.exists() else b""
            rec, err = _seal_with_chain(_edit_seal_path(state_file), raw, key_dir)
    except OSError as e:
        return {"ok": False, "error": "seal_failed: %s" % e}
    if err:
        return {"ok": False, "error": err}
    return {"ok": True, **rec}


def verify_edits_seal(state_file: str, key_dir: str = "") -> dict:
    """edit-log 封印校验（委托**单源** `verify_seal_at`；无账本 ⟹ ok=True）。"""
    return verify_seal_at(_edit_path(state_file), _edit_seal_path(state_file), key_dir)


def rotate_edits(state_file: str, max_lines: int = EDIT_MAX_LINES, keep: int = None) -> dict:
    """**轮转归档**（§23.3 对策②）：主文件超 `max_lines` ⟹ 旧行移入 `<state>.edit-log-archive.jsonl`，
    主文件保留**最近 `keep`**（默认 `max_lines // 2`）行。→ `{ok, archived, kept}`。

    单源纪律：只动 edit-log 与其 archive；**不碰** budget-log / state。
    ED5：整段读-改-写在 `_edit_lock` 内 ⟹ 消并发丢事件（原为无锁 RMW）。
    """
    p = _edit_path(state_file)
    if not p.exists():
        return {"ok": True, "archived": 0, "kept": 0}
    try:
        with _edit_lock(state_file):
            lines = [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if len(lines) <= int(max_lines):
                return {"ok": True, "archived": 0, "kept": len(lines)}
            k = int(keep) if keep is not None else max(1, int(max_lines) // 2)
            old, tail = lines[:-k], lines[-k:]
            with open(Path(str(state_file) + EDIT_ARCHIVE_SUFFIX), "a", encoding="utf-8", newline="\n") as f:
                for ln in old:
                    f.write(ln + "\n")
            p.write_text("\n".join(tail) + "\n", encoding="utf-8", newline="\n")
    except OSError as e:
        return {"ok": False, "error": "rotate_failed: %s" % e}
    return {"ok": True, "archived": len(old), "kept": len(tail)}


def edit_log_stats(state_file: str) -> dict:
    """edit-log 只读摘要（ED2/§23.8.1）——**生产读取面**（审计消费），治「只写不读 / 空转闸机」。

    → `{"edits", "verifies", "bad", "lines", "archived", "last_ts", "by_result", "by_kind", "t6"}`。
    `verifies`/`by_kind`/`t6` 为 **T6 telemetry** 读数面（2026-10-08 §25）。
    """
    evs, estat = read_events_stat(state_file)
    edits = [e for e in evs if e.get("kind") == KIND_EDIT]
    arch = 0
    ap = Path(str(state_file) + EDIT_ARCHIVE_SUFFIX)
    if ap.exists():
        try:
            arch = sum(1 for ln in ap.read_text(encoding="utf-8").splitlines() if ln.strip())
        except OSError:
            arch = 0
    by_result = {r: 0 for r in EDIT_RESULTS}
    for e in edits:
        _r = str(e.get("result") or "allow")
        by_result[_r] = by_result.get(_r, 0) + 1
    # T6 读数面（§25.7）：分组**单源** `_t6_groups`（与判据 `node_unverified_flag` **同源**，禁第二实现）。
    _t6 = _t6_groups(evs)
    return {"edits": estat["edits"], "verifies": estat["verifies"], "bad": estat["bad"],
            "lines": estat["lines"], "archived": arch,
            "last_ts": (evs[-1].get("ts") if evs else ""),
            "by_result": by_result,
            "by_kind": {KIND_EDIT: estat["edits"], KIND_VERIFY: estat["verifies"]},
            "t6": {"by_node": _t6, "k": EDIT_SPAM_K, "window": EDIT_SPAM_WINDOW}}


def step_stats(state_file: str) -> dict:
    """步数分布（2026-10-23，**只读**）：`{(session,node): n}` + 分位 + 疑似空转节点。

    数据源 = **独立**载体 `.step-log.jsonl`（`read_steps`），与 T4′/T6 的 edit-log 完全隔离 ⟹
    读本面**不会**改变任何判罚（本批只采集，不判罚）。
    用途 = 标定「单节点步数」阈值（`over_warn` 仅表示 ≥ `STEP_WARN_PER_NODE`，纯标注）。
    """
    per = {}
    for e in read_steps(state_file):
        k = "%s/%s" % (e.get("session") or "-", e.get("node") or "-")
        per[k] = per.get(k, 0) + 1
    vals = sorted(per.values())
    warn = STEP_WARN_PER_NODE
    return {"total": sum(vals), "nodes": len(vals),
            "p50": _pct(vals, 50), "p90": _pct(vals, 90), "p99": _pct(vals, 99),
            "max": (vals[-1] if vals else 0),
            "warn_at": warn,
            "over_warn": {k: v for k, v in per.items() if v >= warn},
            "by_node": per}


def _pct(sorted_vals, p) -> int:
    """**最近秩**分位（确定性、零依赖；`sorted_vals` 须升序）。空 ⟹ 0。"""
    n = len(sorted_vals)
    if n == 0:
        return 0
    rank = -(-(int(p) * n) // 100)                    # ceil(p/100 × n)
    rank = max(1, min(rank, n))
    return int(sorted_vals[rank - 1])


def _dist(sorted_vals) -> dict:
    """分布摘要（把「依据」显式化，供人工核 K 取值）：`n / min / p25 / p50 / p75 / p90 / max`。"""
    return {"n": len(sorted_vals),
            "min": (int(sorted_vals[0]) if sorted_vals else 0),
            "p25": _pct(sorted_vals, 25), "p50": _pct(sorted_vals, 50),
            "p75": _pct(sorted_vals, 75), "p90": _pct(sorted_vals, 90),
            "max": (int(sorted_vals[-1]) if sorted_vals else 0)}


def calibrate(state_file: str, percentile=None, min_nodes=None) -> dict:
    """K/N **标定取数器**（§23.6-2；2026-10-08 finding `ECC-6A0F7E9F0F5C`）。

    **只读**、**确定性**：从**真实** `edit-log` 事件（`kind ∈ {edit,verify}`）派生阈值建议值。
    **禁合成** —— 合成序列掩盖真实 thrash 形态，据此取的 K 无据（§23.6-2）。

    取数面（分组单源 `_t6_groups`，与判据 `node_unverified_flag` **同源**，禁第二实现）：
      · **K**（T4′/T6 共享，与 `EDIT_SPAM_K` 同源） = `percentile` 分位（默认 90）的**每 `(session,node)`
        `unverified`** —— 即「只判罚最 thrash 的 (100−p)% 节点」；
      · **N**（T4′ 窗口） = 同分位的**每节点 `edits` 数**（承 §25.6 下界论证：事件数 ≥ 触及文件数）。
    样本不足（`nodes < min_nodes`，默认 20）⟹ `suggest=None` + `need`（**禁少量样本外推**）。
    `EDIT_MAX_LINES` **本载体不可派生**（edit 事件不含行数；须 diff 尺寸另采）⟹ 恒 `None`。

    → `{"ok", "sample", "suggest", "basis", "insufficient_data", "need", "note"}`。
    """
    _p = _int_or(percentile, EDIT_CALIB_PERCENTILE)
    _min = _int_or(min_nodes, EDIT_CALIB_MIN_NODES)
    evs = read_events(state_file)
    groups = _t6_groups(evs)
    unv = sorted(int(d.get("unverified", 0)) for d in groups.values())
    epn = sorted(int(d.get("edits", 0)) for d in groups.values())
    nodes = len(groups)
    insufficient = nodes < _min
    suggest = None
    if not insufficient:
        suggest = {"K": max(2, _pct(unv, _p)), "N": max(1, _pct(epn, _p)),
                   "EDIT_MAX_LINES": None}
    return {"ok": True,
            "sample": {"events": len(evs), "edits": sum(epn), "nodes": nodes,
                       "sessions": len({str(e.get("session") or "") for e in evs})},
            "suggest": suggest,
            "basis": {"t6_unverified": _dist(unv), "edits_per_node": _dist(epn),
                      "percentile": _p},
            "insufficient_data": insufficient,
            "need": {"min_nodes": _min, "have_nodes": nodes},
            "note": "仅用真实 edit-log 标定；禁合成（§23.6-2 / ECC-6A0F7E9F0F5C）"}


# ─────────────────────────── 封印（C2）───────────────────────────
def _key_dir(explicit: str = "") -> str:
    if explicit:
        return explicit
    # 2026-10-18（6 臂质询 `ECC-458FA591E582`）：与 ember `pubkey_path` 同源读 `_AUDIT_KEY_DIR`
    #   —— 原实现只认显式入参，外置钥部署下签侧（ember 读 env）与验侧（本模块读仓内默认）
    #   可能落到不同钥目录 ⟹ 封印恒验不过或误判。
    env_dir = os.environ.get("_AUDIT_KEY_DIR", "")
    if env_dir:
        return env_dir
    return str(Path(__file__).resolve().parent.parent / ".keys")


def _sign(digest: str, key_dir: str):
    """→ `(mode, sig, key_fp)`。有 audit key 则 ed25519 签；否则降级 `sha256`（**显式标注**）。"""
    priv_p = os.path.join(key_dir, "audit_ed25519.pem")
    pub_p = os.path.join(key_dir, "audit_ed25519.pub")
    if os.path.isfile(priv_p) and os.path.isfile(pub_p):
        try:
            import base64
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            priv = load_pem_private_key(open(priv_p, "rb").read(), password=None)
            fp = hashlib.sha256(open(pub_p, "rb").read()).hexdigest()[:32]
            return "ed25519", base64.b64encode(priv.sign(digest.encode("utf-8"))).decode(), fp
        except Exception:
            pass
    return "sha256", "", ""          # 降级：封印 = 摘要本身（完整性弱，仅供本机篡改侦测）


def seal_now(state_file: str, key_dir: str = "") -> dict:
    """重算封印（公开入口；**持 `_budget_lock`**，防并发 seal 产生重复 seq）。"""
    with _budget_lock(state_file):
        return _seal_now_unlocked(state_file, key_dir)


def _seal_now_unlocked(state_file: str, key_dir: str = "") -> dict:
    """重算封印（调用方**已持锁**）。D3a：同时推进本地封印链（`seq` + `prev_seal`）。"""
    p = _logical_path(state_file)
    try:
        raw = p.read_bytes() if p.exists() else b""
    except OSError as e:
        return {"ok": False, "error": "read_failed: %s" % e}
    rec, err = _seal_with_chain(_seal_path(state_file), raw, key_dir)
    if err:
        return {"ok": False, "error": err}
    return {"ok": True, **rec}


def verify_seal_at(logical_path, seal_path, key_dir: str = "",
                   require_ed25519: bool = False, require_chain: bool = False) -> dict:
    """账本封印校验（**单源**，2026-10-07；审计署计划 §9/§11 C-5）——摘要完整性 + Ed25519 **真验签**。

    `mode == "ed25519"` ⟹ **必须**真验签通过（复用唯一原语 `gk_ember_replay.verify_ed25519`，
    **禁第三实现**）；`mode != "ed25519"`（签时无键降级）⟹ 默认仅摘要完整性（弱，显式回标 `mode`）；
    **`require_ed25519=True`**（2026-10-18，判据4b）⟹ 弱模式直接判红 `weak_mode`，不再假绿。

    **D3a（2026-10-27）**：`require_chain=True` ⟹ 无链判红 `chain_missing`（审计门用）；
    默认容忍 legacy（无链 ⟹ `chain="legacy"`）。链**存在即校验**（部分回放/截断/prev 篡改必红）。
    → `{"ok","mode","reason","chain","seq"}`。
    """
    p, sp = Path(logical_path), Path(seal_path)
    if not p.exists():
        return {"ok": True, "mode": "", "reason": "no_ledger"}
    if not sp.exists():
        return {"ok": False, "mode": "", "reason": "seal_missing"}
    try:
        seal = json.loads(sp.read_text(encoding="utf-8"))
        raw = p.read_bytes()
    except (OSError, json.JSONDecodeError) as e:
        return {"ok": False, "mode": "", "reason": "unreadable: %s" % e}
    mode = seal.get("mode", "")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != seal.get("sha256"):
        return {"ok": False, "mode": mode, "reason": "digest_mismatch"}
    if mode != "ed25519":
        if require_ed25519:
            return {"ok": False, "mode": mode, "reason": "weak_mode"}
        return _chain_verdict(sp, seal, digest, mode, require_chain)
    from gk_ember_replay import verify_ed25519                 # 单源原语（懒加载，避重依赖）
    r = verify_ed25519(os.path.join(_key_dir(key_dir), "audit_ed25519.pub"),
                       seal.get("sig", ""), digest.encode("utf-8"))
    if r.get("status") == "verified":
        return _chain_verdict(sp, seal, digest, "ed25519", require_chain)
    _st = str(r.get("status"))
    return {"ok": False, "mode": "ed25519",
            "reason": "sig_invalid" if _st == "invalid" else "sig_" + _st}


def _chain_verdict(seal_path, seal: dict, digest: str, mode: str, require_chain: bool) -> dict:
    """D3a：链校验的**出口单源**（legacy 容忍 / 严格判红 / 已验证）。"""
    ch = _verify_chain(seal_path, seal, digest)
    if not ch["ok"]:
        if ch["reason"] == "chain_missing" and not require_chain:
            return {"ok": True, "mode": mode, "reason": "ok", "chain": "legacy"}
        return {"ok": False, "mode": mode, "reason": ch["reason"]}
    return {"ok": True, "mode": mode, "reason": "ok", "chain": "verified", "seq": ch.get("seq")}


def verify_seal(state_file: str, key_dir: str = "",
                require_ed25519: bool = False, require_chain: bool = False) -> dict:
    """→ `{"ok": bool, "mode": str, "reason": str}`。无账本 ⟹ `ok=True`（无可验）。

    委托 `verify_seal_at`（单源；Ed25519 真验签，2026-10-07）。
    `require_ed25519=True` ⟹ 无键降级（sha256-only）判红 `weak_mode`（判据4b）。
    `require_chain=True` ⟹ 无本地封印链判红 `chain_missing`（D3a）。
    """
    return verify_seal_at(_logical_path(state_file), _seal_path(state_file), key_dir,
                          require_ed25519=require_ed25519, require_chain=require_chain)


# ─────────────────────────── 写入（C1/C2/C3）───────────────────────────
def append(state_file: str, source: str, reason: str = "", eb: dict = None,
           ttl: int = None, key_dir: str = "", cost: int = None) -> dict:
    """追加一条记录并重算封印（公开入口；**持 `_budget_lock`** 串行化追加+封印）。"""
    if not state_file:
        return {"ok": False, "error": "no_state_file"}
    with _budget_lock(state_file):
        return _append_unlocked(state_file, source, reason=reason, eb=eb,
                                ttl=ttl, key_dir=key_dir, cost=cost)


def _rollback_ledger(p, prev_size, sp, prev_seal, cp, prev_chain) -> None:
    """C3：把账本/封印/链恢复到 append 前状态（调用方持 `_budget_lock`；尽力而为）。"""
    try:
        if prev_size:
            os.truncate(p, prev_size)
        elif p.exists():
            p.unlink()
    except OSError:
        pass
    try:
        if prev_seal is None:
            if sp.exists():
                sp.unlink()
        else:
            sp.write_bytes(prev_seal)
        if prev_chain is None:
            if cp.exists():
                cp.unlink()
        else:
            cp.write_bytes(prev_chain)
    except OSError:
        pass


def _append_unlocked(state_file: str, source: str, reason: str = "", eb: dict = None,
                     ttl: int = None, key_dir: str = "", cost: int = None) -> dict:
    """追加一条记录并重算封印（调用方**已持锁**）。**C3：失败返 `{ok:false}`，不静默吞。**

    2026-10-23（账本凭证，owner 裁定「按顺序做」）：
      · `kind` 新增 `charge`（扣款交易）——`from_max` 链**只跟提额行**，扣款/降级不扰动链；
      · 记录补 `session` / `scope` / `session_max|used|remaining`（会话域快照，取自
        `gate_data.edit_budget.sessions.<sid>`）。原实现**只记全局** `max=4`，而实际扣的是
        会话域 `max=8` ⟹ 留痕与余额不符、审计无法复算；
      · `cost`（可选）= 本次扣款额度（差额记账，由 CLI 区外侧传入）。
    """
    if not state_file:
        return {"ok": False, "error": "no_state_file"}
    if eb is None:
        try:
            eb = ((json.loads(Path(state_file).read_text(encoding="utf-8")).get("gate_data") or {})
                  .get("edit_budget") or {})
        except (OSError, json.JSONDecodeError):
            eb = {}
    kind = classify_source(source)
    sid = str(os.environ.get("GK_SESSION_ID", "") or "")
    _box = (eb.get("sessions") or {}).get(sid) if sid else None
    _box = _box if isinstance(_box, dict) else None
    # 扣款/降级行不带 max 语义（提额幅度只对提额行成立）
    to_max = eb.get("max") if kind == KIND_RAISE else None
    # C1：链式 `from_max` 只跟**提额行**（降级早警/扣款交易不扰动提额链）
    _recs, _ = read_records(state_file)
    from_max = None
    for rec in _recs:
        if (rec.get("kind") or KIND_RAISE) == KIND_RAISE:
            from_max = rec.get("to_max")
    # 2026-10-31（数据层）：额度**没有真的上调**（`to_max <= from_max`）就不是提额 ——
    #   `state-patch --set-nested` 改 `used`/`remaining` 也会走到本函数，原实现一律记 raise
    #   ⟹ 全仓 97.7% 的 raise 行是 no-op（standard §12.4.2 实测）。改记 `bookkeeping`：
    #   不进提额链、不进 `count_raises`、不抬高熵；行仍保留（审计可对账）。
    if kind == KIND_RAISE and from_max is not None and to_max is not None and to_max <= from_max:
        kind = KIND_BOOKKEEPING
    # 2026-10-31（owner 签 §8 #4）：每日真提额硬上限 `RAISE_DAILY_CAP`（默认 6）——
    #   命中即**具名 fail-loud**，不静默放行。计数与熵第三支同源（`count_raises`，
    #   已排除 no-op/降级/扣款，且遵守激活基线 `econ_enabled_at`）。
    if kind == KIND_RAISE:
        try:
            from gk_econ_params import CAP as _CAP
        except Exception:
            _CAP = 6
        try:
            _used_today = count_raises(state_file)[1]
            _unlocks_today = count_unlocks_today(state_file)
        except LedgerSealInvalid as e:
            # §9.4 额外缺口①：封印失效不得按 0 计 ⟹ 拒绝写提额（更不得绕过 CAP）
            return {"ok": False, "error": "RAISE_LEDGER_SEAL_INVALID",
                    "detail": str(e),
                    "hint": "提额账本封印缺失/失效；先用 `budget-ledger verify --state ...` 定位，"
                            "恢复封印后才能继续提额"}
        _used_today = max(0, _used_today - _unlocks_today)   # 人工解锁抵扣（一次解锁抵一次提额）
        if _used_today >= _CAP:
            return {"ok": False, "error": "RAISE_DAILY_CAP_HIT",
                    "cap": _CAP, "used_today": _used_today,
                    "hint": "当日真提额已达上限（UTC 日切）；等下一个 UTC 日或走人工解锁，"
                            "不得静默放行"}
    try:
        _ttl = int(ttl if ttl is not None else (os.environ.get("GK_SESSION_TTL") or TTL_DEFAULT))
    except (TypeError, ValueError):
        _ttl = TTL_DEFAULT
    now = datetime.datetime.now(datetime.timezone.utc)
    # 余额字段跟 `scope` 走：提额/降级行沿用历史口径（全局）；**扣款行**取被扣的那个域，
    #   否则「transaction 记 session 域扣了 1，余额却报全局 remaining=0」自相矛盾。
    _bal = _box if (kind == KIND_CHARGE and _box) else eb
    rec = {"ts": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "source": str(source or ""),
           "kind": kind,
           "from_max": from_max, "to_max": to_max, "max": to_max,
           "used": _bal.get("used"), "remaining": _bal.get("remaining"),
           "session": sid, "scope": "session" if _box else "global",
           "expires_at": datetime.datetime.fromtimestamp(now.timestamp() + _ttl, datetime.timezone.utc)
                                 .strftime("%Y-%m-%dT%H:%M:%SZ"),
           "reason": str(reason or "")[:200]}
    if _box:
        # 会话域快照：提额/降级行的 `used/remaining` 仍是**全局**（向后兼容），审计读这三个。
        rec.update({"session_max": _box.get("max"), "session_used": _box.get("used"),
                    "session_remaining": _box.get("remaining")})
    if cost is None:
        # 2026-10-23：区外差额记账通道（CLI `_budget_log_append charge` 以 env 传 cost）。
        try:
            cost = int(os.environ.get("GK_CHARGE_COST") or 0) or None
        except (TypeError, ValueError):
            cost = None
    if cost is not None:
        try:
            rec["cost"] = int(cost)
        except (TypeError, ValueError):
            pass
    # C3（2026-11-09）：append + seal 是**一个事务**。失败时回滚账本/封印/链，避免
    #   「追加行已落盘、封印失效」的半写状态（原实现只返回错误、不回滚）。
    _p = _logical_path(state_file)
    try:
        _prev_size = _p.stat().st_size
    except OSError:
        _prev_size = 0
    _sp = _seal_path(state_file)
    _cp = _chain_path(_sp)
    try:
        _prev_seal = _sp.read_bytes() if _sp.exists() else None
        _prev_chain = _cp.read_bytes() if _cp.exists() else None
    except OSError:
        _prev_seal = _prev_chain = None
    try:
        with open(_p, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        _rollback_ledger(_p, _prev_size, _sp, _prev_seal, _cp, _prev_chain)
        return {"ok": False, "error": "append_failed: %s" % e, "rolled_back": True}
    st = _seal_now_unlocked(state_file, key_dir=key_dir)
    if not st.get("ok"):
        _rollback_ledger(_p, _prev_size, _sp, _prev_seal, _cp, _prev_chain)
        return {"ok": False, "error": st.get("error"), "record": rec, "rolled_back": True}
    return {"ok": True, "record": rec, "seal": {"mode": st.get("mode"), "sha256": st.get("sha256")}}


# ── D4（审计署 §21.8-a，2026-10-24）：`code-fix` 额度兑换的总量上限 / 冷却 ─────────
#   缺口：`_grant_node_budget` 原先只有「单次 ≤ 硬顶」，**次数/总量无上限、无冷却**
#   ⟹ 反复 `--code-fix` 可无限抬 max（实测 budget-log 已有 13 次、单日峰值 5 次）。
#   默认值依据（2026-10-24 实测 13 条 code-fix 记录）：单日峰值 5、最小间隔 23s、中位 2.7h。
#   判据只看**当日**（UTC）记录；`add` = 本次拟授予量（用于总量上限的预判）。
CODE_FIX_SOURCE = "code-fix"
CODE_FIX_MAX_GRANTS_DEFAULT = 16
CODE_FIX_TOTAL_CAP_DEFAULT = 192
CODE_FIX_COOLDOWN_S_DEFAULT = 10


def _day_of(ts):
    d = _parse_ts(ts)
    return d.date().isoformat() if d else ""


def _opt_int(v):
    """可空整数（缺字段/坏值 ⟹ `None`，不把坏值当 0 累加）。"""
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def code_fix_quota(state_file: str, max_grants=None, total_cap=None,
                   cooldown_s=None, add: int = 0, now=None) -> dict:
    """**额度兑换总量上限 / 冷却判据**（D4，只读）。

    计数面 = `<state>.budget-log.jsonl` 中 `source == "code-fix"` 的**当日**记录：
      · `grants_today` = 次数；`total_today` = Σ(`to_max - from_max`)（缺字段按 0）；
      · `seconds_since_last` = 距**最近一次** code-fix 的秒数（跨日也算，冷却不分天）。
    拒付优先级：`max_grants` > `total_cap` > `cooldown`（一次只报首个原因）。
    三个阈值任一 ≤0 ⟹ 该项**不启用**（kill switch 走调用侧 `GK_CODE_FIX_CAP=0`）。
    """
    mg = _int_or(max_grants, CODE_FIX_MAX_GRANTS_DEFAULT)
    tc = _int_or(total_cap, CODE_FIX_TOTAL_CAP_DEFAULT)
    cd = _int_or(cooldown_s, CODE_FIX_COOLDOWN_S_DEFAULT)
    _now = now or datetime.datetime.now(datetime.timezone.utc)
    today = _now.date().isoformat()
    recs, _ = read_records(state_file)
    fx = [r for r in recs if str(r.get("source") or "") == CODE_FIX_SOURCE]
    grants_today = 0
    total_today = 0
    for r in fx:
        if _day_of(r.get("ts")) != today:
            continue
        grants_today += 1
        fm, tm = _opt_int(r.get("from_max")), _opt_int(r.get("to_max"))
        if fm is not None and tm is not None and tm > fm:
            total_today += tm - fm
    last_ts = ""
    for r in fx:
        t = str(r.get("ts") or "")
        if t > last_ts:
            last_ts = t
    secs = None
    if last_ts:
        d = _parse_ts(last_ts)
        if d is not None:
            secs = max(0, int((_now - d).total_seconds()))
    reason = ""
    if mg > 0 and grants_today >= mg:
        reason = "max_grants"
    elif tc > 0 and total_today + max(0, _int_or(add, 0)) > tc:
        reason = "total_cap"
    elif cd > 0 and secs is not None and secs < cd:
        reason = "cooldown"
    return {"ok": reason == "", "reason": reason, "day": today,
            "n_total": len(fx), "grants_today": grants_today,
            "total_today": total_today, "add": max(0, _int_or(add, 0)),
            "last_ts": last_ts, "seconds_since_last": secs,
            "max_grants": mg, "total_cap": tc, "cooldown_s": cd}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_budget_ledger.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("append")
    a.add_argument("--state", required=True)
    a.add_argument("--source", required=True)
    a.add_argument("--reason", default="")
    a.add_argument("--ttl", type=int, default=None)
    a.add_argument("--key-dir", default="")
    s = sub.add_parser("seal"); s.add_argument("--state", required=True); s.add_argument("--key-dir", default="")
    v = sub.add_parser("verify"); v.add_argument("--state", required=True)
    v.add_argument("--key-dir", default="")
    v.add_argument("--require-ed25519", action="store_true")
    v.add_argument("--require-chain", action="store_true")
    c = sub.add_parser("count"); c.add_argument("--state", required=True)
    # 2026-10-31（§6 臂 8）：人工解锁（非 LLM、append-only、写完重算封印）
    u = sub.add_parser("unlock")
    u.add_argument("--state", required=True)
    u.add_argument("--operator", required=True)
    u.add_argument("--reason", required=True)
    u.add_argument("--key-dir", default="")
    # ED1/ED2（2026-10-08）：edit-log 写侧单源 + 只读摘要（CLI `_edit_log_append` / 审计消费）。
    ea = sub.add_parser("edit-append")
    ea.add_argument("--state", required=True)
    ea.add_argument("--session", default="")
    ea.add_argument("--node", default="")
    ea.add_argument("--path", default="")
    ea.add_argument("--result", default="allow")
    es = sub.add_parser("edit-stats"); es.add_argument("--state", required=True)
    # 2026-10-08 §25：T6 telemetry = verify 事件（只采集）；T4′ 判据查询（只读）。
    va = sub.add_parser("verify-append")
    va.add_argument("--state", required=True)
    va.add_argument("--session", default="")
    va.add_argument("--node", default="")
    # ⚠ dest 必须**避开** `cmd`：子命令 dest 也叫 `cmd`（`add_subparsers(dest="cmd")`），
    #   同名 `--cmd` 会把子命令名覆写成命令串 ⟹ 分发落到 `else` 分支（实测：rc=0 但什么都没写）。
    va.add_argument("--cmd", dest="event_cmd", default="")
    # 2026-10-23：步事件（只采集）+ 步数分布（只读）。
    sa = sub.add_parser("step-append")
    sa.add_argument("--state", required=True)
    sa.add_argument("--session", default="")
    sa.add_argument("--node", default="")
    sa.add_argument("--cmd", dest="event_cmd", default="")   # 同上：dest 避开子命令 dest
    ss = sub.add_parser("step-stats"); ss.add_argument("--state", required=True)
    ef = sub.add_parser("edit-flag")
    ef.add_argument("--state", required=True)
    ef.add_argument("--path", required=True)
    ef.add_argument("--session", default="")
    ef.add_argument("--window", default=None)
    ef.add_argument("--k", default=None)
    # 2026-10-23（REV-23）：单文件硬上限判据（只读；`--node` 为空 ⟹ 不筛节点）。
    fc = sub.add_parser("file-cap")
    fc.add_argument("--state", required=True)
    fc.add_argument("--path", required=True)
    fc.add_argument("--session", default="")
    fc.add_argument("--node", default="")
    fc.add_argument("--k", default=None)
    # 2026-10-24（D4 / §21.8-a）：code-fix 额度兑换的当日总量上限 + 冷却（只读）。
    cq = sub.add_parser("code-fix-quota")
    cq.add_argument("--state", required=True)
    cq.add_argument("--max-grants", default=None)
    cq.add_argument("--total-cap", default=None)
    cq.add_argument("--cooldown", default=None)
    cq.add_argument("--add", default=0)
    # §23.6-2（2026-10-08，finding ECC-6A0F7E9F0F5C）：K/N **标定取数**（只读、确定性、禁合成）。
    cb = sub.add_parser("calibrate")
    cb.add_argument("--state", required=True)
    cb.add_argument("--percentile", default=None)
    cb.add_argument("--min-nodes", default=None)
    ns = ap.parse_args(argv)
    if ns.cmd == "append":
        out = append(ns.state, ns.source, ns.reason, ttl=ns.ttl, key_dir=ns.key_dir)
    elif ns.cmd == "seal":
        out = seal_now(ns.state, key_dir=ns.key_dir)
    elif ns.cmd == "verify":
        out = verify_seal(ns.state, key_dir=ns.key_dir,
                          require_ed25519=ns.require_ed25519,
                          require_chain=ns.require_chain)
    elif ns.cmd == "edit-append":
        out = append_edit(ns.state, ns.session, ns.node, ns.path, ns.result)
    elif ns.cmd == "edit-stats":
        out = edit_log_stats(ns.state)
    elif ns.cmd == "verify-append":
        out = append_verify(ns.state, ns.session, ns.node, ns.event_cmd)
    elif ns.cmd == "step-append":
        out = append_step(ns.state, ns.session, ns.node, ns.event_cmd)
    elif ns.cmd == "step-stats":
        out = step_stats(ns.state)
    elif ns.cmd == "edit-flag":
        out = edit_spam_flag(ns.state, ns.path, window=ns.window, k=ns.k,
                             session=ns.session)
    elif ns.cmd == "file-cap":
        out = file_cap_flag(ns.state, ns.path, k=ns.k, session=ns.session, node=ns.node)
    elif ns.cmd == "code-fix-quota":
        out = code_fix_quota(ns.state, max_grants=ns.max_grants, total_cap=ns.total_cap,
                             cooldown_s=ns.cooldown, add=ns.add)
    elif ns.cmd == "calibrate":
        out = calibrate(ns.state, ns.percentile, ns.min_nodes)
    elif ns.cmd == "unlock":
        out = record_unlock(ns.state, ns.operator, ns.reason, key_dir=ns.key_dir)
    else:
        try:
            total, today = count_raises(ns.state)
            out = {"total_raise": total, "today_raise": today,
                   "unlocks_today": count_unlocks_today(ns.state)}
        except LedgerSealInvalid as e:
            out = {"ok": False, "error": "RAISE_LEDGER_SEAL_INVALID", "detail": str(e)}
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())
