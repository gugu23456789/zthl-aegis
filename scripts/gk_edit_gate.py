#!/usr/bin/env python3
"""gk_edit_gate.py — 写类判定的**唯一实现**（单源），供 `gatekeeper-cli.sh` 两个消费点委派。

背景（2026-09-28，用户实测报告）：同一 feature worktree 路径，`guard-edit` 返回 `allowed:true`
而 `pre-tool-check` 返回 `BLOCK: Path not in active write surface` —— 同一规则的两个消费点
**各写一份判定链** ⟹ 口径漂移（`cmd_guard_edit` 曾缺 活动写面 / junction / 受保护目录 /
预算 / stage=DONE 共 5 项）。本模块把「判定」收敛为**一份 python 实现**；bash 侧只保留
「文案映射 + 扣费 + 留痕」（那些天然属于 bash 侧：hook env / 审计台账）。

用法:
  python3 gk_edit_gate.py check --state <state> --path <p> [--session <sid>] [--tool <name>] [--enforce-budget]

输出（单 JSON 对象，stdout）:
  {"decision":"allow|block","reason":"<CODE|''>","checks":[{"id","verdict","detail"}...],
   "budget":{"remaining":N,"exhausted":bool,"scope":"session|global"}}

退出码: 0 = allow；1 = block；2 = 错误（fail-closed：缺 --path / state 不可读）。

判定链（各判据**互相独立**，任一 block 即 block ⟹ 与调用顺序无关）:
  NO_STATE_FILE · STATE_UNREADABLE · NO_ACTIVE_R_PHASE · REALPATH_UNRESOLVED ·
  JUNCTION_REDIRECT · PATH_NOT_IN_ACTIVE_SURFACE · PROTECTED_PATH · OVERWRITE_EXISTING_FILE ·
  EDIT_BUDGET_EXHAUSTED

⚠ **刻意不纳入** `MAIN_WORKTREE`（主仓只读）：该判据保留在 bash 两侧**内联**，由既有
  `test_main_repo_guard.py` 的「派生正则两处同形」臂保证不漂移（常量在保护区 `constants` 内）。
⚠ **刻意不纳入** `PROTECTED_REGION`：其判定含**留痕副作用**（`_pe_record` 写审计 JSONL），
  属 bash 侧共享函数 `_protected_region_check`，本模块不复制。
"""
import json
import os
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from gk_route_center import active_roots, in_active_surface  # noqa: E402 — RC1 单一 helper
# §17.8 行 397 关系不变量（E25 C，2026-10-30）：外生上限**单源**取 `gk_advance.EDIT_BUDGET_CEILING`
#   （⛔ 禁在本文件另立数值常量；亦**禁**与 `gk_route_center.DECLARED_HARD_CAP` 合并 ——
#   「计划能自我声明多少」（反棘轮，24）≠「env 逃生舱最多抬到多少」（32），语义不同）。
#   两者关系 `DECLARED_HARD_CAP ≤ EDIT_BUDGET_CEILING` 由 `test_gk_audit_e25_mech` C 臂机检。
from gk_advance import EDIT_BUDGET_CEILING  # noqa: E402 — 外生上限单源（禁第二常量）

# 与 `pre_tool_check` 的 `rg -qi "build/|\.git/|node_modules/"` **逐字同源**（含大小写不敏感）。
_RE_PROTECTED_PATH = re.compile(r"build/|\.git/|node_modules/", re.IGNORECASE)

_CLOSED_STAGES = ("IDLE", "DONE")

# 2026-10-09：**整体写**工具（归一后小写）。打在**已存在**文件上 = 整文件覆盖 ⟹ 见 OVERWRITE_EXISTING_FILE。
# 带锚工具（edit/searchreplace）与 deletefile **不在此列**（前二者本就局部；删除另有语义）。
_WHOLE_FILE_WRITE_TOOLS = ("write", "createfile")


def _budget_view(d: dict, session_id: str) -> dict:
    """预算读数 —— 与 `pre_tool_check` 同源（含会话隔离的回落语义），**除**下述夹取。

    2026-10-30（E25 C）：放行读数 `remaining` 另加外生夹取 `min(值, EDIT_BUDGET_CEILING)`。
      · `pre_tool_check` 的放行读数**本函数即单源**（它经 `gk_views.py budget-triple` 直接取本
        函数回包 `budget`，不再内联计算）⟹ 夹取自动生效；其内联读取只剩 BLOCK 文案的
        `used/max`（展示面，不参与放行判定）。
      · `-1` 哨兵 / `max` / `used` 语义与原内联口径一致。

    有会话键：读 `edit_budget.sessions.<sid>.remaining`；**条目缺失**回落 `edit_budget.max`
      （= 该会话的新鲜额度，绝不继承他人消耗）；无会话键：读全局 `edit_budget.remaining`。
    缺省 `-1` = 未配置 ⟹ 不拦（与旧行为逐字一致）。
    """
    eb = (d.get("gate_data") or {}).get("edit_budget") or {}
    if not isinstance(eb, dict):
        return {"remaining": -1, "exhausted": False, "scope": "none", "max": -1, "used": 0}
    sid = (session_id or "").strip()
    # R2-a（REV-6 §15.3；owner 2026-10-01 裁定 A1+P4-1）：同批透出 θ 的**分母**（本会话首见额度
    #   `max` —— E 裁定）与 `used`，供 bash 侧早警阈值判定与文案用。bash 侧**同一次解析**顺带取走
    #   ⟹ 正常路径**零额外子进程**（Gate 4 是 hook 唯一大额开销，见 `pre_tool_hook._run_cli` 注释）。
    if sid:
        box = (eb.get("sessions") or {}).get(sid) if isinstance(eb.get("sessions"), dict) else None
        if isinstance(box, dict) and box.get("remaining") is not None:
            rem, scope = box.get("remaining"), "session"
            mx, used = box.get("max", eb.get("max", -1)), box.get("used", 0)
        else:
            # 新会话无条目 ⟹ 新鲜额度 = 节点 `max`、消耗 0（**绝不继承他人消耗**）。
            rem, scope = eb.get("max", -1), "session-fallback-max"
            mx, used = eb.get("max", -1), 0
    else:
        rem, scope = eb.get("remaining", -1), "global"
        mx, used = eb.get("max", -1), eb.get("used", 0)
    try:
        rem_i = int(rem)
    except (TypeError, ValueError):
        rem_i = -1
    try:
        mx_i = int(mx)
    except (TypeError, ValueError):
        mx_i = -1
    try:
        used_i = int(used)
    except (TypeError, ValueError):
        used_i = 0
    # §17.8 行 397 关系不变量（E25 C，2026-10-30）：**放行读数外生夹取**。
    #   缺口：`remaining` 就是本模块 `evaluate` 的**放行面**（`exhausted = rem_i <= 0`）⟹
    #   无上界时 `sessions.<sid>.remaining` / 全局 `remaining` 可被写到 999 等任意值（假绿放行面）。
    #   现两路（会话盒 / 全局）**都**夹到 `EDIT_BUDGET_CEILING` 的关系上限（单源 import）；
    #   `-1` 哨兵（未配置 ⟹ 不拦）**原样保留**（只夹非负读数）；
    #   `max` / `used` / `exhausted` 语义**一律不动**（本夹取只收窄「可被声明的余额」）。
    #   bash 侧预算读数经 `gk_views.py budget-triple` 直接取本函数输出 ⟹ 此处即单点生效。
    if rem_i >= 0:
        rem_i = min(rem_i, EDIT_BUDGET_CEILING)
    return {"remaining": rem_i, "exhausted": rem_i >= 0 and rem_i <= 0, "scope": scope,
            "max": mx_i, "used": used_i}


def _ledger_debt(state_path: str) -> list:
    """未审债 = `credit-ledger` 中**无 outcome 回填**的 `raise` `id`（r9-2 ②a，§19.2）。

    **判据单源** = `gk_credit_ledger.reconcile()` —— 对账规则只此一份（禁在本模块复制）。
    本模块是 hook Gate 4 **已经在付**的那次子进程 ⟹ 顺带算出 = **零边际子进程**。
    账本缺失 / 不可读 / 依赖异常 ⟹ 回空表（**不误报、不阻断放行**；本字段纯可见性面）。
    """
    try:
        from gk_credit_ledger import reconcile
        return [str(x) for x in (reconcile(state_path).get("unreconciled") or [])]
    except Exception:
        return []


def evaluate(state_path: str, path: str, session_id: str = "",
             enforce_budget: bool = False, tool: str = "") -> dict:
    """返回判定 dict（不抛；state 不可读 → `STATE_UNREADABLE`，由调用方按 exit 2 处置）。"""
    checks = []
    # r9-2 ②a（`ECC-BCF60C185CBE`，2026-10-01；owner 裁定 A）：未审债**随判定一起回出**，
    #   供「下一节点门可见」。**只读** —— 不改任何放行/拦阻判据，不新增 kill switch。
    debt = []

    def _blk(reason, detail=""):
        checks.append({"id": reason, "verdict": "block", "detail": detail})
        return {"decision": "block", "reason": reason, "checks": checks,
                "budget": _budget_view(d, session_id) if isinstance(d, dict) else {},
                "unreconciled_raises": debt}

    d = None
    if not state_path or not os.path.isfile(state_path):
        checks.append({"id": "NO_STATE_FILE", "verdict": "block", "detail": state_path})
        return {"decision": "block", "reason": "NO_STATE_FILE", "checks": checks, "budget": {},
                "unreconciled_raises": []}
    try:
        with open(state_path, encoding="utf-8") as fh:
            d = json.load(fh)
    except Exception as e:  # noqa: BLE001 — CLI 边界：统一转显式错误，由调用方 fail-closed
        checks.append({"id": "STATE_UNREADABLE", "verdict": "error", "detail": str(e)[:120]})
        return {"decision": "block", "reason": "STATE_UNREADABLE", "checks": checks, "budget": {},
                "unreconciled_raises": []}
    debt = _ledger_debt(state_path)

    stage = str(d.get("stage") or "IDLE")
    if stage in _CLOSED_STAGES:
        return _blk("NO_ACTIVE_R_PHASE", "stage=%s" % stage)
    checks.append({"id": "NO_ACTIVE_R_PHASE", "verdict": "allow", "detail": "stage=%s" % stage})

    if not str(path or "").strip():
        return _blk("REALPATH_UNRESOLVED", "empty --path")
    real = os.path.realpath(path)
    if path != real and path != os.path.realpath(path):
        # 与 `pre_tool_check` 同形：`readlink -f` 与 `realpath` 双双 != 原串 ⟹ 经软链/挂载进入。
        return _blk("JUNCTION_REDIRECT", "%s -> %s" % (path, real))
    checks.append({"id": "JUNCTION_REDIRECT", "verdict": "allow", "detail": real})

    # §17-6-P4（2026-10-04）：**禁「空值 = 跳过归属校验」** —— 空 roots（键缺失 / null / ""）
    #   亦**一律不产生放行**（去原 `roots and …` legacy-skip；「非 worktree 模式」= **显式 root 集合**）。
    roots = active_roots(d)
    if not (in_active_surface(path, d) or in_active_surface(real, d)):
        return _blk("PATH_NOT_IN_ACTIVE_SURFACE", "roots=%s" % roots)
    checks.append({"id": "PATH_NOT_IN_ACTIVE_SURFACE", "verdict": "allow",
                   "detail": "roots=%d" % len(roots)})

    if _RE_PROTECTED_PATH.search(path) or _RE_PROTECTED_PATH.search(real):
        return _blk("PROTECTED_PATH", "build/|.git/|node_modules/")
    checks.append({"id": "PROTECTED_PATH", "verdict": "allow", "detail": ""})

    # 2026-10-09（用户裁定）：**整体覆盖闸** —— 归一后工具 ∈ {write, createfile} ∧ 目标**已存在** ⟹ BLOCK。
    #   背景：写闸原把所有写动词**一视同仁**（F-REV-45 只做**工具名**归一），从不区分「整体覆盖」
    #   与「带锚局部改」⟹ IDE 的 `Write` 可**整文件覆盖**已存在文件，绕过 `gk_agent_edit.apply_edit`
    #   的「old_str 非空且必命中」局部-only 纪律（现场：一次 Write 覆盖掉 ECC-74B7327230D8 的
    #   `test_gk_evidence.py`）。显式逃生舱 `GK_OVERWRITE_OK=1`（对齐 `GK_BUDGET_OVERRIDE` 惯例）。
    #   `tool` 缺省 "" ⟹ 两消费点（guard-edit / 旧调用方）行为**逐字不变**。
    _t = (tool or "").strip().lower()
    if _t in _WHOLE_FILE_WRITE_TOOLS and os.path.isfile(real) \
            and os.environ.get("GK_OVERWRITE_OK", "0") != "1":
        return _blk("OVERWRITE_EXISTING_FILE", "%s (tool=%s)" % (path, _t))
    checks.append({"id": "OVERWRITE_EXISTING_FILE", "verdict": "allow",
                   "detail": "tool=%s" % (_t or "-")})

    bv = _budget_view(d, session_id)
    override = os.environ.get("GK_BUDGET_OVERRIDE", "0") == "1"
    if enforce_budget and bv.get("exhausted") and not override:
        checks.append({"id": "EDIT_BUDGET_EXHAUSTED", "verdict": "block",
                       "detail": "remaining=%s scope=%s" % (bv.get("remaining"), bv.get("scope"))})
        return {"decision": "block", "reason": "EDIT_BUDGET_EXHAUSTED", "checks": checks,
                "budget": bv, "unreconciled_raises": debt}
    checks.append({"id": "EDIT_BUDGET_EXHAUSTED", "verdict": "allow",
                   "detail": "remaining=%s scope=%s" % (bv.get("remaining"), bv.get("scope"))})
    return {"decision": "allow", "reason": "", "checks": checks, "budget": bv,
            "unreconciled_raises": debt}


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] != "check":
        print(json.dumps({"decision": "block", "reason": "USAGE",
                          "error": "usage: gk_edit_gate.py check --state <s> --path <p> "
                                   "[--session <sid>] [--tool <name>] [--enforce-budget]"}))
        return 2
    state_path = path = session_id = tool = ""
    enforce = False
    i = 1
    while i < len(args):
        a = args[i]
        if a == "--state" and i + 1 < len(args):
            state_path, i = args[i + 1], i + 2
        elif a == "--path" and i + 1 < len(args):
            path, i = args[i + 1], i + 2
        elif a == "--session" and i + 1 < len(args):
            session_id, i = args[i + 1], i + 2
        elif a == "--tool" and i + 1 < len(args):
            tool, i = args[i + 1], i + 2
        elif a == "--enforce-budget":
            enforce, i = True, i + 1
        else:
            print(json.dumps({"decision": "block", "reason": "USAGE",
                              "error": "unknown arg: %s" % a}))
            return 2
    if not path:
        print(json.dumps({"decision": "block", "reason": "REALPATH_UNRESOLVED",
                          "error": "--path required"}))
        return 2
    out = evaluate(state_path, path, session_id, enforce, tool)
    print(json.dumps(out, ensure_ascii=True))
    if out.get("decision") == "allow":
        return 0
    return 2 if out.get("reason") == "STATE_UNREADABLE" else 1


if __name__ == "__main__":
    sys.exit(main())
