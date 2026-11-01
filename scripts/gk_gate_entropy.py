#!/usr/bin/env python3
"""Gate: Entropy rate computation — shared by standing + standard branches.

Usage: python3 gk_gate_entropy.py <state_file> <stage>
Output: 0.00-1.00 (float string)

Data source routing (design intent, gatekeeper-cli.sh L2085):
  ECO-* stages → human_calibration_log verdicts WARN/FAIL ratio (plan quality)
  All others (standard STAGE_*, RED-*, AUDIT-*) → rejected_edits (code edit violations)

Replaces the inline python3 heredoc at gatekeeper-cli.sh L2086-2118.
Phase 7 (gk_advance.py) reuses this as final form.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── REV-3 §12.7 熵**第三支**：提额频次（旁挂账本，append-only）────────────────────────
# 病灶（结构性，非实现 bug）：额度耗尽记录落 `block_log(kind:"budget")`，**不在任何既有熵源内**
# ⟹「耗尽 → 提额 → 再耗尽」循环**零熵信号** ⟹ 熵监视器失明、monitor 永不升级 `--api`。
# 处置：把旁挂 `<state>.budget-log.jsonl`（不参与 `state-patch` 整体替换）的**当日提额条数**并入熵。
_RAISE_LOG_SUFFIX = ".budget-log.jsonl"
# K 的单源 = `gk_econ_params.K`（2026-10-31 owner 签 §8 #4：F=1/K=4）；本模块不再另立常量。
#   保留别名仅供旧测试/diag 读取（值随单源走，恒等于 K）。
sys.path.insert(0, str(Path(__file__).resolve().parent))
from gk_econ_params import K as _ECON_K  # noqa: E402
_RAISE_SATURATION = float(_ECON_K)


def _raises_today(state_file: str) -> int:
    """旁挂账本**当日（UTC）提额**条数 —— 单源 = `scripts/gk_budget_ledger.py::count_raises`。

    owner 裁定 C1（只算 `kind=raise`，降级早警行不计）/ C4（坏行**不计入**）；
    缺文件 / 导入失败 ⟹ `0`（与既有「第三支=0」零回归路径一致）。
    """
    if not state_file:
        return 0
    try:
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).resolve().parent))
        from gk_budget_ledger import count_raises as _cr
        return int(_cr(state_file)[1])
    except Exception as e:
        # 2026-10-31（§9.4 额外缺口①）：封印失效**不得**吞成 0（否则熵被清零、门禁照绿）
        if getattr(e, "code", "") == "RAISE_LEDGER_SEAL_INVALID":
            raise
        return 0


def _raise_entropy(state_file: str) -> float:
    """第三支取值 ∈ [0,1]：`min(1, max(0, 当日提额数 − F) / K)`（单源 = gk_econ_params）。

    `state_file=""` ⟹ 0（零回归）。2026-10-31：从 `n/K` 改为**分段成本**（免费额度 F），
    参数见 `gk_econ_params.py`（owner 已签）。
    """
    n = _raises_today(state_file)
    if n <= 0:
        return 0.0
    from gk_econ_params import raise_entropy as _re
    return _re(n)


def _rejected_window() -> int:
    """熵窗口长度 = `gk_advance.REJECTED_CAP`（**同源**，禁第二份常量，T4）。

    原状写死 `[-20:]` 与 cap 构成双源：改 cap 一处不生效、窗口与截断错位。惰性 import
    （`gk_advance` 亦惰性 import 本模块）避免模块级循环。
    """
    try:
        from gk_advance import REJECTED_CAP
        return int(REJECTED_CAP)
    except Exception:
        return 120


def compute_entropy_from_dict(d: dict, stage: str, state_file: str = "") -> float:
    """纯内存 dict 版本（2026-08-23: 消除 gk_advance.py 内联重复实现）。
    compute_entropy(state_file, stage) 先 load 后调本函数；gk_advance.py 直接调本函数。

    REV-3：新增**第三支**（提额频次）；需 `state_file` 定位旁挂账本 —— 缺省 `""` ⟹ 第三支为 0
    ⟹ 与既有两支**逐字零回归**。
    """
    gd = d.get("gate_data", {})
    if stage.startswith("ECO-"):
        # ECO phases: entropy from human_calibration_log verdicts (plan quality)
        cl = gd.get("human_calibration_log") or []
        # S-02: Sliding window — use last 5 entries instead of just last 1
        window = cl[-5:]
        rates = []
        for entry in window:
            vj = entry.get("verdicts_json", {})
            if not vj:
                continue
            total = len(vj)
            if total == 0:
                continue
            non_pass = sum(1 for v in vj.values() if str(v).upper() not in ("PASS", "OK"))
            rates.append(non_pass / total)
        base = (sum(rates) / len(rates)) if rates else 0.0
        return min(1.0, base + _raise_entropy(state_file))
    # Standard pipeline: entropy from rejected_edits (code edit violations)
    rej = gd.get("rejected_edits") or []
    # 2026-11-01（质询臂 a，20 条证据）：forced 必须**先过滤、再切片**。原实现仅在
    #   `is_violation` 里把 forced 从**分子**排除，却仍占 `len(w)` **分母**位置 ⟹ 120 条
    #   forced 可把熵压到 0（与 C3b「洗窗失明」同型）；外部 SLO 口径要求 excluded 类
    #   同时退出分子与分母。`is_violation` 的 forced 早退保留作**防御**（双保险）。
    rej = [e for e in rej
           if isinstance(e, dict) and str(e.get("outcome") or "") != "forced"]
    w = rej[-_rejected_window():]
    if not w:
        return min(1.0, _raise_entropy(state_file))

    def is_violation(r):
        # 2026-09-22（R22 / 红队 C3b 修复）：原实现只把 `source=="monitor"` 判为无条件违规，
        #   而 `source=="gate"`（= gk_advance.py 阶段门 FAIL 追加的记录，构造上即违规，
        #   见 gk_advance.py:1116-1119 `score:None, source:"gate"`）**落进 `score is None`
        #   分支被误判为非违规** ⟹ 两个后果叠加成"洗窗失明"：
        #   ① 熵被低估（阶段门失败不计违规）；
        #   ② 连续 20 条 gate-FAIL 会把 monitor 记录挤出 cap=20 窗口，
        #      而它们自身贡献 0 违规 ⟹ 熵归零、monitor 停留 `--local`（不再升级 `--api`）。
        #   修法：`source == "gate"` 一律违规（该写入点只在失败时追加）。
        # 2026-10-31（M1 裁定，owner 已签）：**审计侧测量不进熵** —— `source="monitor"` 的
        #   测量/留痕记录一律不计违规，否则「finding → 熵 → 下次 advance 写阻断」= 二次 BLOCK，
        #   M1「审计只监管不直接 BLOCK」名存实亡。确定性阻断改由额度银行写入 `source="bank"`。
        # 2026-11-01（T2/T4）：`outcome=forced` = 人类终裁**放行**的事件，**不进熵**。
        #   原状 force 只写 bank_actions、从不进 rejected_edits ⟹ 熵天然不含它；事件单写后
        #   必须显式过滤，否则「放行」被记成违规、熵单调虚高（force 越多越像失控）。
        if str(r.get("outcome") or "") == "forced":
            return False
        src = r.get("source", "")
        if src == "monitor":
            return False
        if src in ("bank", "gate"):
            return True
        s = r.get("score", None)
        if s is None:
            return False
        return float(s) <= 0.5

    v = sum(1 for r in w if is_violation(r))
    # G7 (2026-08-13): crypto material access attempts (subagent_history.access_violations)
    # count as violations — R4 熵监视器监听 .keys/ 访问的设计缺口此前未接线
    av_count = sum(len(e.get("access_violations") or []) for e in (gd.get("subagent_history") or [])[-5:])
    v += av_count
    base = v / max(1, len(w) + av_count)
    return min(1.0, base + _raise_entropy(state_file))


def compute_entropy(state_file: str, stage: str) -> float:
    try:
        with open(state_file) as f:
            d = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return 0.0
    return compute_entropy_from_dict(d, stage, state_file)


if __name__ == "__main__":
    sf = sys.argv[1] if len(sys.argv) > 1 else ""
    st = sys.argv[2] if len(sys.argv) > 2 else ""
    rate = compute_entropy(sf, st) if sf else 0.0
    print(f"{rate:.2f}" if sf else "0.0")
    # 诊断（stderr → GK_DBG_LOG）: 熵计算输入可观测（2026-08-23 交叉审查 #1）
    # 数据源计数 + 结果 + 阈值 → "熵为什么不触发"永远可查
    if sf and st:
        try:
            with open(sf) as f:
                d = json.load(f)
            gd = d.get("gate_data", {})
            if st.startswith("ECO-"):
                cl = gd.get("human_calibration_log") or []
                print(f"[entropy] stage={st} source=human_calibration_log n={len(cl)} "
                      f"rate={rate:.2f} threshold=0.3/0.5", file=sys.stderr)
            else:
                rej = gd.get("rejected_edits") or []
                av = sum(len(e.get("access_violations", []))
                         for e in (gd.get("subagent_history") or [])[-5:])
                print(f"[entropy] stage={st} source=rejected_edits n={len(rej)} "
                      f"access_violations={av} rate={rate:.2f} threshold=0.3/0.5", file=sys.stderr)
        except Exception as e:
            print(f"[entropy] stage={st} ERROR {e}", file=sys.stderr)
