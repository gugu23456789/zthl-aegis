#!/usr/bin/env python3
"""R1-b **信用分旁挂账本** —— 读写**单源**（跨会话累积；append-only + 封印）。

来源：`docs/plans/2026-09-18-edit-budget-dual-track-plan.md` §13.5b（R1-b）/ §18。

载体（与 `gk_budget_ledger` 同族，**不参与** `state-patch` 整体替换）
  · `<state>.credit-ledger.jsonl` —— append-only 记录；
  · `<state>.credit-ledger.jsonl.seal` —— 完整性**封印**（封印实现**单源**复用 `gk_budget_ledger`）。

语义
  · **跨会话累积**：账本按 **state 文件**（非会话）计 ⟹ `score = Σ delta` 天然跨会话；
  · **非对称定价**（Sovereign-OS §14.1-11）：`success +5` / `fail −15` / `overspend −10`；
    `raise` = **中性事件**（`delta=0`，仅登记「何时提了额」），其**成败分**由审计署（R1-b 的
    outcome producer，见 §13.5c）后续以 `success` / `fail` 行回填；
  · **C4 同口径**：JSON 解析失败 / 非对象 / `delta` 非整数的行 ⟹ `bad`，**不计入** score。

单一实现：写侧 `gatekeeper-cli.sh::_credit_log_append` 委托本模块；读侧同样委托本模块。
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from gk_budget_ledger import (  # noqa: E402 — 封印实现单源（禁第二实现）
    _canonical, _key_dir, _now_str, _seal_with_chain, _sign, verify_seal_at)

SUFFIX = ".credit-ledger.jsonl"
SEAL_SUFFIX = ".credit-ledger.jsonl.seal"
# 历史债**签名基线** sidecar（owner 方案 a，2026-10-19）：记录 cutoff raise id，
# `reconcile` 把 `id <= cutoff_id` 的 raise 划为 legacy（不进待审债）。
BASELINE_SUFFIX = ".credit-ledger.baseline.json"
BOOKKEEPING_KIND = "bookkeeping"

# outcome 行（审计署 outcome producer 回填）：判据4a 的三参数落点（owner 裁 A1，2026-10-07）。
OUTCOME_KINDS = ("success", "fail", "overspend")

# D7-B J1（2026-10-28 质询 E3）：**finding id 形态**（= 审计产物，不得进 `outcome.ref`）。
#   原实现只拒 `startswith("ECC-")` ⟹ 红队入账 id 族（`RED-CONSTRAINTS-01` / `RED-SCOPE-02`
#   / `RED-MIGRATE-*`，见审计署计划 §21.1 `shared_ids` 实证）仍可双边计价（I-2 一债一票被绕）。
#   形态来源：`gk_finding.register` = `"ECC-" + uuid4().hex[:12].upper()`；红队 = `RED-<PHASE>[-NN]`。
#   `raise` 行 id = `<UTC 时间戳>-<序号>`（本模块 append 生成），不匹配任一形态（负臂钉死）。
# E25 B（2026-10-30，一轮六臂质询）：原 `RED-[A-Z][A-Z0-9]*` 只收**全大写段** ⟹
#   `RED-SURFACE-audit` / `RED-Scope-02` / `RED-migrate-X` 等**混合大小写**红队 id 可绕过写侧闸
#   （双边计价 I-2 一债一票被绕）。现 RED 族各段放宽到 `[A-Za-z0-9]+`，**首段仍须字母开头**
#   （防纯数字段误吞 `raise` 行 id `YYYYMMDDTHHMMSS-NNNN` —— 负臂在
#   `test_gk_credit_ledger` / `test_gk_audit_e25_mech` 钉死）。`ECC-` 分支不变。
_FINDING_ID_RE = re.compile(
    r"^(?:ECC-[0-9A-Fa-f]{6,}|RED-[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)$")

# 非对称定价（Sovereign-OS §14.1-11）
# 2026-10-05（用户令「给豁免加惩罚机制」）：`exempt` = L2 入站门 `--acknowledge-injected` 逐项豁免的
#   代价（−1/项；调用方按豁免项数显式传 delta）⟹ 使「整表豁免」不再零代价。
# 2026-10-19（owner 选方案 a）：`bookkeeping` = 预算记账（提额/覆盖留痕），**不是**审计事件；
#   `reconcile` 不计债。原实现复用 `raise` 记账 ⟹ 224 条机械待审债。
DELTA = {"raise": 0, "success": 5, "fail": -15, "overspend": -10, "exempt": -1,
         "bookkeeping": 0}



def _logical_path(state_file: str) -> Path:
    return Path(str(state_file) + SUFFIX)


def _seal_path(state_file: str) -> Path:
    return Path(str(state_file) + SEAL_SUFFIX)


def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def read_records(state_file: str) -> tuple:
    """读全部记录 + 统计 `(records, stat)`。

    `stat` = `{"lines","bad","count","bookkeeping","score","seal_ok","seal_mode","ref_violations"}`。
    `ref_violations`（E25 B 读侧，2026-10-30）= `kind ∈ OUTCOME_KINDS` 且 `ref` 命中 finding-id
    形态的行数（**只检测**，不改 `ok` / 不计入 `bad` / 不影响 `score`）。
    **C4 同口径**：坏行（解析失败 / 非对象 / `delta` 非整数）走 `bad`，**不进** `records`、不计分。
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
                    bad += 1
                    continue
                if not isinstance(rec, dict) or _as_int(rec.get("delta")) is None:
                    bad += 1
                    continue
                records.append(rec)
        except OSError:
            pass
    st = verify_seal(state_file)
    return records, {
        "lines": len(records) + bad,
        "bad": bad,
        "count": len(records),
        "bookkeeping": sum(1 for r in records if r.get("kind") == BOOKKEEPING_KIND),
        "score": sum(_as_int(r.get("delta")) or 0 for r in records),
        "seal_ok": st.get("ok"),
        "seal_mode": st.get("mode"),
        # E25 B 读侧（2026-10-30）：finding id 形态的 `ref` 计数 —— 只抓**绕过 append 闸**
        #   落进账本的行（存量历史行 / 篡改行），原读侧零检测 ⟹ 不可见。
        #   ⚠ **只检测、不改 `ok`**（存量历史行翻 ok 属另一项裁定，本轮不做）。
        "ref_violations": sum(1 for r in records
                              if r.get("kind") in OUTCOME_KINDS
                              and _FINDING_ID_RE.match(str(r.get("ref") or ""))),
    }


def score(state_file: str) -> int:
    """跨会话累积信用分 = 账本全部有效行 `delta` 之和。"""
    if not state_file:
        return 0
    records, _ = read_records(state_file)
    return sum(_as_int(r.get("delta")) or 0 for r in records)


def _parse_iso(ts):
    try:
        return datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def delta_since(state_file: str, cutoff_ts: str = "", cutoff_id: str = ""):
    """基线（`cutoff_ts` 优先，回退 `cutoff_id`）之后的 score 增量。

    N 门的**唯一取数面**（2026-10-31）：无基线 / 找不到 cutoff ⟹ `None` ⟹ 调用方只能
    advisory，**禁止**退化成 `score()` 绝对值（否则一开即永久锁）。
    """
    records, _ = read_records(state_file)
    if cutoff_ts:
        cut = _parse_iso(cutoff_ts)
        if cut is None:
            return None
        total = 0
        for r in records:
            dt = _parse_iso(r.get("ts"))
            if dt is not None and dt > cut:
                total += _as_int(r.get("delta")) or 0
        return total
    if cutoff_id:
        idx = next((i for i, r in enumerate(records)
                    if str(r.get("id")) == str(cutoff_id)), None)
        if idx is None:
            return None
        return sum(_as_int(r.get("delta")) or 0 for r in records[idx + 1:])
    return None


# ─────────────────────── 历史债签名基线（方案 a）───────────────────────
# 复审 BLOCK（2026-10-19）后收紧：
#   · 只接受 Ed25519（无钥拒绝写、弱模式拒绝读）；
#   · 正文绑定 state 身份 + cutoff 行号 + 前缀摘要 + 当时的账本行数 ⟹
#     跨 state 重放 / 截断 / 前缀改写一律 fail-closed（不抵扣任何债）。
_BASELINE_SIGN_KEYS = ("alg", "mode", "key_fp", "state_id", "cutoff_id", "cutoff_ts",
                       "cutoff_line", "prefix_sha256", "ledger_lines", "reason",
                       "created_at")


def _baseline_path(state_file: str) -> Path:
    return Path(str(state_file) + BASELINE_SUFFIX)


def _state_id(state_file: str) -> str:
    """state 身份（路径摘要）：基线跨 state 复制即失效。"""
    try:
        real = str(Path(state_file).resolve())
    except OSError:
        real = str(state_file)
    return hashlib.sha256(real.encode("utf-8")).hexdigest()[:32]


def _ledger_raw_lines(state_file: str):
    """账本原始行（bytes）——绑定/校验用；不可读 ⟹ None。"""
    try:
        return _logical_path(state_file).read_bytes().splitlines()
    except OSError:
        return None


def _prefix_sha(lines, upto: int) -> str:
    """前 `upto` 行的摘要（不含尾换行，确定可复算）。"""
    return hashlib.sha256(b"\n".join(lines[:upto])).hexdigest()


def _find_cutoff_line(lines, cid: str):
    """最后一条 `kind=raise` 且 `id==cid` 的 **1-based 行号**；无 ⟹ None。"""
    idx = None
    for i, ln in enumerate(lines):
        try:
            rec = json.loads(ln)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if isinstance(rec, dict) and rec.get("kind") == "raise" \
                and str(rec.get("id") or "") == cid:
            idx = i + 1
    return idx


def _key_fp(key_dir: str) -> str:
    pub_p = os.path.join(_key_dir(key_dir), "audit_ed25519.pub")
    if not os.path.isfile(pub_p):
        return ""
    try:
        return hashlib.sha256(open(pub_p, "rb").read()).hexdigest()[:32]
    except OSError:
        return ""


def _has_audit_keys(key_dir: str) -> bool:
    d = _key_dir(key_dir)
    return (os.path.isfile(os.path.join(d, "audit_ed25519.pem"))
            and os.path.isfile(os.path.join(d, "audit_ed25519.pub")))


def _id_key(v):
    """raise id 排序键：`YYYYMMDDTHHMMSS-NNNN` ⟹ `(ts, seq)`；其它 ⟹ `(字面, -1)`。"""
    s = str(v or "")
    m = re.match(r"^(\d{8}T\d{6})-(\d+)$", s)
    if m:
        return (m.group(1), int(m.group(2)))
    return (s, -1)


def write_baseline(state_file: str, cutoff_id: str, cutoff_ts: str = "",
                   reason: str = "", key_dir: str = "") -> dict:
    """写**签名基线**：`id <= cutoff_id` 的 raise 视为历史债（legacy），不再计入待审债。

    **强模式 only**：无 audit 私钥/公钥 ⟹ 拒绝写（`baseline_requires_ed25519`）。
    **绑定**：正文含 `state_id` / `cutoff_line` / `prefix_sha256` / `ledger_lines`，
    读取时校验 append-only 前缀与行数不回退 ⟹ 跨 state 复制、截断、改写均失效。
    """
    if not state_file:
        return {"ok": False, "error": "no_state_file"}
    cid = str(cutoff_id or "").strip()
    if not cid:
        return {"ok": False, "error": "cutoff_id_required"}
    lines = _ledger_raw_lines(state_file)
    if lines is None:
        return {"ok": False, "error": "ledger_unreadable"}
    cutoff_line = _find_cutoff_line(lines, cid)
    if not cutoff_line:
        return {"ok": False, "error": "cutoff_not_found"}
    if not _has_audit_keys(key_dir):
        return {"ok": False, "error": "baseline_requires_ed25519",
                "hint": "基线必须由 audit_ed25519 私钥签名；无钥环境不得写基线"}
    body = {"alg": "sha256", "mode": "ed25519", "key_fp": _key_fp(key_dir),
            "state_id": _state_id(state_file), "cutoff_id": cid,
            "cutoff_ts": str(cutoff_ts or ""), "cutoff_line": cutoff_line,
            "prefix_sha256": _prefix_sha(lines, cutoff_line),
            "ledger_lines": len(lines), "reason": str(reason or "")[:200],
            "created_at": _now_str()}
    digest = hashlib.sha256(_canonical(body)).hexdigest()
    mode, sig, fp = _sign(digest, _key_dir(key_dir))
    if mode != "ed25519" or fp != body["key_fp"] or not sig:
        return {"ok": False, "error": "baseline_requires_ed25519",
                "hint": "签名失败或钥不匹配 ⟹ 拒绝落盘（禁弱模式基线）"}
    rec = {**body, "sha256": digest, "sig": sig}
    try:
        _baseline_path(state_file).write_text(
            json.dumps(rec, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as e:
        return {"ok": False, "error": "baseline_write_failed: %s" % e}
    return {"ok": True, **rec}


def read_baseline(state_file: str, key_dir: str = "") -> dict:
    """读并**验签 + 绑定校验**基线 → `{"present","ok","reason","mode",...}`。

    **fail-closed**：缺失 / 弱模式 / 摘要失配 / 签名无效 / state 不符 / 截断 /
    前缀改写 / cutoff 不存在 ⟹ `ok=False`；调用方此时**不得**抵扣任何债。
    """
    p = _baseline_path(state_file)
    base = {"present": False, "ok": False, "reason": "baseline_missing",
            "mode": "", "cutoff_id": "", "cutoff_ts": "",
            "cutoff_line": None, "ledger_lines": None}
    if not p.exists():
        return base
    base["present"] = True
    try:
        rec = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return {**base, "reason": "unreadable: %s" % e}
    if not isinstance(rec, dict):
        return {**base, "reason": "unreadable: not_object"}
    body = {k: rec.get(k) for k in _BASELINE_SIGN_KEYS}
    out = {**base, "mode": str(rec.get("mode") or ""),
           "cutoff_id": str(rec.get("cutoff_id") or ""),
           "cutoff_ts": str(rec.get("cutoff_ts") or ""),
           "cutoff_line": rec.get("cutoff_line"),
           "ledger_lines": rec.get("ledger_lines")}
    if out["mode"] != "ed25519":
        return {**out, "reason": "weak_mode"}
    if not out["cutoff_id"]:
        return {**out, "reason": "cutoff_id_missing"}
    digest = hashlib.sha256(_canonical(body)).hexdigest()
    if digest != rec.get("sha256"):
        return {**out, "reason": "digest_mismatch"}
    from gk_ember_replay import verify_ed25519        # 单源验签原语（懒加载）
    r = verify_ed25519(os.path.join(_key_dir(key_dir), "audit_ed25519.pub"),
                       rec.get("sig", ""), digest.encode("utf-8"))
    if r.get("status") != "verified":
        _st = str(r.get("status"))
        return {**out, "reason": "sig_invalid" if _st == "invalid" else "sig_" + _st}
    if str(rec.get("state_id") or "") != _state_id(state_file):
        return {**out, "reason": "state_mismatch"}
    lines = _ledger_raw_lines(state_file)
    if lines is None:
        return {**out, "reason": "ledger_unreadable"}
    try:
        cutoff_line = int(rec.get("cutoff_line"))
        ledger_lines = int(rec.get("ledger_lines"))
    except (TypeError, ValueError):
        return {**out, "reason": "binding_fields_invalid"}
    if not (1 <= cutoff_line <= ledger_lines):
        return {**out, "reason": "binding_fields_invalid"}
    if len(lines) < ledger_lines:
        return {**out, "reason": "ledger_truncated"}
    if _prefix_sha(lines, cutoff_line) != rec.get("prefix_sha256"):
        return {**out, "reason": "prefix_mismatch"}
    try:
        cut = json.loads(lines[cutoff_line - 1])
    except (json.JSONDecodeError, UnicodeDecodeError, IndexError):
        return {**out, "reason": "cutoff_not_found"}
    if not (isinstance(cut, dict) and cut.get("kind") == "raise"
            and str(cut.get("id") or "") == out["cutoff_id"]):
        return {**out, "reason": "cutoff_not_found"}
    return {**out, "ok": True, "reason": "ok"}


def reconcile(state_file: str, key_dir: str = "", require_seal=None) -> dict:
    """**对账**（审计署 §19 ②b）：每笔 `raise`（= **待审债**）须有引用其 `id` 的 outcome 行。

    outcome 行 = `kind ∈ {success, fail, overspend}` 且带 `ref`（引用 raise 的 `id`）。
    → `{"ok", "raises", "audited", "unreconciled", "legacy_raises", "debt_raises",
       "baseline", "duplicate_refs", "ref_violations", "seal"}`；
    `ok=False` 即存在**未审债 / 重票 / 命名空间违规 ref / 坏封印**。
    ⚠ 无 `id` 的历史行（本字段引入前）**不参与**对账（不误报为未审）。
    ⚠ `bookkeeping` 行（预算记账）**不是** raise ⟹ 天然不计债（owner 方案 a）。
    ⚠ 签名基线 `cutoff_id`：其前的 raise 计 `legacy_raises`、不计债；基线无效 ⟹ 不抵扣（fail-closed）。

    **D5（2026-10-24）读侧补两项**（原实现「消费面恒真」：`reconcile` 从不看封印）：
      · `duplicate_refs`：同 `ref` 多条 outcome ⟹ `ok=False`（一债一票，§21.8-b）；
      · `seal`：`require_seal=None`（默认）= **auto** —— 封印文件存在则强制（坏 ⟹ `ok=False`），
        缺失只标 `enforced=False`（不误伤无封印的历史夹具）；传 `key_dir` ⟹ 按
        `require_ed25519` 真验签；`require_seal=True` ⟹ 缺失也算失败。
    """
    records, _ = read_records(state_file)
    raise_ids = [str(r.get("id")) for r in records
                 if r.get("kind") == "raise" and r.get("id")]
    audited = {str(r.get("ref")) for r in records
               if r.get("kind") in OUTCOME_KINDS and r.get("ref")}
    base = read_baseline(state_file, key_dir=key_dir)
    cutoff = ""
    if base.get("present") and base.get("ok"):
        cid = base.get("cutoff_id") or ""
        if cid in raise_ids:
            cutoff = cid
        else:
            base = {**base, "ok": False, "reason": "cutoff_not_found"}
    legacy = [i for i in raise_ids if cutoff and _id_key(i) <= _id_key(cutoff)]
    debt = [i for i in raise_ids if i not in legacy]
    unreconciled = [i for i in debt if i not in audited]
    # D5-① 一债一票：同 ref 多 outcome = 双重计价
    _cnt = {}
    for r in records:
        if r.get("kind") in OUTCOME_KINDS and r.get("ref"):
            k = str(r["ref"])
            _cnt[k] = _cnt.get(k, 0) + 1
    duplicate_refs = sorted(k for k, v in _cnt.items() if v > 1)
    # E25 B 读侧（2026-10-30）：finding id ref **明细**（按出现序）—— 命名空间污染的可见性面。
    #   2026-10-30 收口（owner「遗留边界清理完」）：原「只检测、不进 ok」会让违规账本仍被判
    #   `ok=True`（读侧可被当作「对账通过」）。现**进 ok 判据**；实测存量账本零违规 ⟹ 无迁移风险。
    ref_violations = [str(r.get("ref")) for r in records
                      if r.get("kind") in OUTCOME_KINDS
                      and _FINDING_ID_RE.match(str(r.get("ref") or ""))]
    # D5-② 读侧封印：auto 模式下只在封印**存在**时强制
    seal = verify_seal(state_file, key_dir=key_dir, require_ed25519=bool(key_dir))
    _missing = seal.get("reason") == "seal_missing"
    seal_enforced = bool(require_seal) or (require_seal is None and not _missing)
    ok = (not unreconciled) and (not duplicate_refs) and (not ref_violations) \
        and (not (seal_enforced and not seal.get("ok")))
    return {"ok": ok, "raises": len(raise_ids),
            "audited": len(audited), "unreconciled": unreconciled,
            "legacy_raises": len(legacy), "debt_raises": len(debt),
            "duplicate_refs": duplicate_refs,
            "ref_violations": ref_violations,
            "seal": {"ok": seal.get("ok"), "mode": seal.get("mode", ""),
                     "reason": seal.get("reason", ""), "enforced": bool(seal_enforced)},
            "baseline": {"present": base.get("present", False),
                         "ok": base.get("ok"), "reason": base.get("reason", ""),
                         "mode": base.get("mode", ""),
                         "cutoff_id": base.get("cutoff_id", ""),
                         "cutoff_ts": base.get("cutoff_ts", ""),
                         "cutoff_line": base.get("cutoff_line"),
                         "ledger_lines": base.get("ledger_lines")}}




# ─────────────────────────── 封印 ───────────────────────────
def seal_now(state_file: str, key_dir: str = "") -> dict:
    """D3a：委托 `gk_budget_ledger._seal_with_chain`（封印 + 本地链**单源**）。"""
    p = _logical_path(state_file)
    try:
        raw = p.read_bytes() if p.exists() else b""
    except OSError as e:
        return {"ok": False, "error": "read_failed: %s" % e}
    rec, err = _seal_with_chain(_seal_path(state_file), raw, key_dir)
    if err:
        return {"ok": False, "error": err}
    return {"ok": True, **rec}


def verify_seal(state_file: str, key_dir: str = "",
                require_ed25519: bool = False, require_chain: bool = False) -> dict:
    """→ `{"ok","mode","reason"}`。无账本 ⟹ `ok=True`（无可验）。

    **单源委托** `gk_budget_ledger.verify_seal_at`（摘要完整性 + Ed25519 真验签，
    2026-10-07；审计署计划 §9/§11 C-5）。`require_ed25519=True` ⟹ 弱模式判红。
    `require_chain=True` ⟹ 无本地封印链判红 `chain_missing`（D3a）。
    """
    return verify_seal_at(_logical_path(state_file), _seal_path(state_file), key_dir,
                          require_ed25519=require_ed25519, require_chain=require_chain)


# ─────────────────────────── D6a 离线回放报告 ───────────────────────────
REPLAY_SCHEMA = "gk-replay-report/v1"


def replay_report(state_file: str, key_dir: str = "", out_path: str = "",
                  require_seal: bool = True) -> dict:
    """D6a 离线回放报告（**只读**）：复用 `reconcile` 单源，产出可入库的报告 artifact。

    纪律（审计署 §27.2，第三轮质询 G6）：
      · 本函数**零写**账本 / state / 封印，只另存报告；
      · `chain` 取封印实况（无 `seq`/`prev_seal` ⟹ `legacy`），**不得**据此宣称链保护；
      · 只证「可回放」，**不**证「唯一消费方」⟹ 不解锁 §17.3 ①。
    """
    if not state_file:
        return {"ok": False, "error": "no_state_file"}
    lp = _logical_path(state_file)
    sp = _seal_path(state_file)
    if not lp.exists():
        return {"ok": False, "error": "ledger_missing: %s" % lp}
    rec = reconcile(state_file, key_dir=key_dir,
                    require_seal=True if require_seal else None)
    seal = verify_seal(state_file, key_dir=key_dir, require_ed25519=bool(key_dir))
    raw = lp.read_bytes()
    rep = {
        "schema": REPLAY_SCHEMA,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "state_file": str(Path(state_file).resolve()),
        "ledger_path": str(lp.resolve()),
        "ledger_sha256": hashlib.sha256(raw).hexdigest(),
        "seal_path": str(sp.resolve()) if sp.exists() else "",
        "chain": seal.get("chain", ""),
        "seal": {"mode": seal.get("mode", ""), "ok": seal.get("ok"),
                 "reason": seal.get("reason", "")},
        "reconcile": rec,
        "ok": bool(rec.get("ok")),
    }
    out = Path(out_path) if out_path else Path(str(lp) + ".replay-report.json")
    out.write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
    rep["report_path"] = str(out.resolve())
    return rep


# ─────────────────────────── 写入 ───────────────────────────
def append(state_file: str, kind: str, delta=None, source: str = "",
           reason: str = "", key_dir: str = "", ref: str = "",
           model_version: str = "", temperature=None, seed=None) -> dict:
    """追加一条记录并重算封印。`delta=None` ⟹ 取 `DELTA[kind]`（未知 kind 默认 0）。

    `id` 自动生成（`<ts>-<序号>`）：`raise` 行的 `id` = **待审债号**；outcome 行（`success`/`fail`/
    `overspend`）用 `ref` **引用**其审计的 raise `id`（审计署 §19 的对账配对面，见 `reconcile`）。
    **判据4a**（owner 裁 A1）：outcome 行**必带** `model_version` / `temperature` / `seed`
    （离线可复算三参数），非 outcome 行不带。
    **fail-loud**：写失败返 `{ok:false,error}`，不静默吞。
    """
    if not state_file:
        return {"ok": False, "error": "no_state_file"}
    k = str(kind or "").strip() or "raise"
    # 判据4a fail-loud（2026-10-18，6 臂质询 `ECC-458FA591E582`）：outcome 行三参数任一为空
    #   ⟹ 拒绝写入（原实现写空值仍 ok=True，等于「空参数也进签名域」）。必须在**落盘前**判，
    #   避免写完账本再报错留下半条 outcome。
    if k in OUTCOME_KINDS:
        _missing = [name for name, val in (
            ("model_version", model_version),
            ("temperature", temperature),
            ("seed", seed),
        ) if val is None or (isinstance(val, str) and not val.strip())]
        if _missing:
            return {"ok": False,
                    "error": "outcome_row_missing_model_params: " + ",".join(_missing),
                    "hint": "outcome 行须带 model_version / temperature / seed（判据4a：离线可复算）"}
    d = _as_int(delta)
    if d is None:
        d = DELTA.get(k, 0)
    if k == BOOKKEEPING_KIND and d != 0:
        return {"ok": False, "error": "bookkeeping_delta_must_be_zero",
                "hint": "预算记账是中性事件（delta=0）；计分请用 outcome 行"}
    recs, _ = read_records(state_file)
    # ── D5（审计署 §21.8-b，2026-10-24）：**一债一票** ─────────────────────────
    #   缺口：原 `append` 不查重、`reconcile` 只查「有没有」⟹ 同一 `ref` 可落多条
    #   `success`（= 双重计价，5×2=+10 却只偿还一笔）。判据 = 同一 `ref` 至多**一个**
    #   outcome 行（跨 kind 也算，避免 fail 后再 success 把一次审计记两遍）。
    #   ⚠ 仅当 `ref` 非空时判 —— 历史/测试里的无 ref outcome 不参与对账（语义不变）。
    if k in OUTCOME_KINDS and ref:
        _dup = next((r for r in recs
                     if str(r.get("ref") or "") == str(ref)
                     and str(r.get("kind") or "") in OUTCOME_KINDS), None)
        if _dup is not None:
            return {"ok": False, "error": "duplicate_outcome_ref: %s" % (str(ref),),
                    "existing": {"id": _dup.get("id"), "kind": _dup.get("kind")},
                    "hint": "一债一票（§21.8-b / D5）：同一 ref 至多一个 outcome 行；改判须先冲销"}
    # ── D7-B J1（2026-10-27 落刀 / 2026-10-28 质询 E3 扩命名空间）：**账务命名空间隔离** ──
    #   审计产物（finding id）≠ 额度债（raise id）⟹ 禁把 finding id 写进 outcome.ref，
    #   否则 finding 直接影响额度分 = 恒真判据（Q-1 破）。审计产物用 finding.id + batch_id 关联。
    #   形态覆盖 `ECC-*`（gk_finding）与 `RED-*`（红队入账）——原只拒前者，后者可绕。
    if k in OUTCOME_KINDS and _FINDING_ID_RE.match(str(ref or "")):
        return {"ok": False, "error": "outcome_ref_namespace_violation: %s" % (str(ref),),
                "hint": "J1：credit-ledger.ref 只接 raise.id；finding id（ECC-* / RED-*）走 "
                        "finding.id + batch_id（两本账）"}
    _ts = datetime.datetime.now(datetime.timezone.utc)
    rec = {"ts": _ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
           "id": "%s-%04d" % (_ts.strftime("%Y%m%dT%H%M%S"), len(recs) + 1),
           "kind": k, "delta": d, "source": str(source or ""), "reason": str(reason or "")[:200]}
    if ref:
        rec["ref"] = str(ref)
    if k in OUTCOME_KINDS:                       # 判据4a：三参数入 outcome 行（离线可复算）
        rec["model_version"] = str(model_version or "")
        rec["temperature"] = temperature
        rec["seed"] = seed
    try:
        with open(_logical_path(state_file), "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        return {"ok": False, "error": "append_failed: %s" % e}
    st = seal_now(state_file, key_dir=key_dir)
    if not st.get("ok"):
        return {"ok": False, "error": st.get("error"), "record": rec}
    return {"ok": True, "record": rec, "score": score(state_file),
            "seal": {"mode": st.get("mode"), "sha256": st.get("sha256")}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_credit_ledger.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("append")
    a.add_argument("--state", required=True)
    a.add_argument("--kind", required=True)
    a.add_argument("--delta", type=int, default=None)
    a.add_argument("--source", default="")
    a.add_argument("--reason", default="")
    a.add_argument("--ref", default="")
    a.add_argument("--key-dir", default="")
    a.add_argument("--model-version", default="")
    a.add_argument("--temperature", type=float, default=None)
    a.add_argument("--seed", type=int, default=None)
    s = sub.add_parser("seal"); s.add_argument("--state", required=True); s.add_argument("--key-dir", default="")
    v = sub.add_parser("verify"); v.add_argument("--state", required=True); v.add_argument("--key-dir", default="")
    v.add_argument("--require-ed25519", action="store_true")
    v.add_argument("--require-chain", action="store_true")
    c = sub.add_parser("score"); c.add_argument("--state", required=True)
    r = sub.add_parser("reconcile"); r.add_argument("--state", required=True)
    r.add_argument("--key-dir", default="")
    # D5（2026-10-24）：缺失封印也算失败（默认 auto = 只在封印存在时强制）
    r.add_argument("--require-seal", action="store_true")
    # D6a（2026-10-28）：离线回放报告（只读；默认强制封印，报告落账本同目录）
    rr = sub.add_parser("replay-report")
    rr.add_argument("--state", required=True)
    rr.add_argument("--key-dir", default="")
    rr.add_argument("--out", default="")
    rr.add_argument("--no-require-seal", action="store_true")
    bw = sub.add_parser("baseline-write")
    bw.add_argument("--state", required=True)
    bw.add_argument("--cutoff-id", required=True)
    bw.add_argument("--cutoff-ts", default="")
    bw.add_argument("--reason", default="")
    bw.add_argument("--key-dir", default="")
    bv = sub.add_parser("baseline-verify")
    bv.add_argument("--state", required=True)
    bv.add_argument("--key-dir", default="")
    ns = ap.parse_args(argv)
    if ns.cmd == "append":
        out = append(ns.state, ns.kind, ns.delta, ns.source, ns.reason, ns.key_dir, ns.ref,
                     model_version=ns.model_version, temperature=ns.temperature, seed=ns.seed)
    elif ns.cmd == "seal":
        out = seal_now(ns.state, key_dir=ns.key_dir)
    elif ns.cmd == "verify":
        out = verify_seal(ns.state, key_dir=ns.key_dir,
                          require_ed25519=ns.require_ed25519,
                          require_chain=ns.require_chain)
    elif ns.cmd == "reconcile":
        out = reconcile(ns.state, key_dir=ns.key_dir,
                        require_seal=True if ns.require_seal else None)
    elif ns.cmd == "replay-report":
        out = replay_report(ns.state, key_dir=ns.key_dir, out_path=ns.out,
                            require_seal=not ns.no_require_seal)
    elif ns.cmd == "baseline-write":
        out = write_baseline(ns.state, ns.cutoff_id, ns.cutoff_ts, ns.reason,
                             key_dir=ns.key_dir)
    elif ns.cmd == "baseline-verify":
        out = read_baseline(ns.state, key_dir=ns.key_dir)
    else:
        out = {"ok": True, "score": score(ns.state)}
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())
