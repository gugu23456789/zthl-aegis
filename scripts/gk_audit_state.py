#!/usr/bin/env python3
"""
Gatekeeper Audit — State domain (batch8 R-T6 Phase 4a)
=========================================================
Migrates `cmd_audit --state` bash heredoc (15 deterministic checks) to a
standalone Python module, reusing `gk_state.py` for state read (incl. SHA256
checksum warning).  Plus Phase 4c-4f extension checks (hint/self/hook/red)
aggregated by `run_all()` — 45 项 total (state 19 + hint 4 + self 4 + hook 6 + red 12)。
(历史：batch8 计划 L1007-1019 为 38；2026-09-02 HOOK-05/06 提权绕过防线+实时越权监控 +2；
state 域 hook_block_log 意图记忆可审计性 +1；2026-09-27 C3③ subagent_reports +1；
2026-10-02 ② 单一权威 state_forms +1（并订正 state 域计数滞后：18→21）。
2026-10-28 A9：red 域 +RED-AIG（KVM 沙箱内的 AIG 车道）⟹ 11→12。
2026-10-29 E21/E22（A′）：state 域按生命周期收窄 `branch_cleaned`（仅 STAGE_5/DONE）
与 `ci_green`（仅 R 生命周期或已声明）的**产出范围** ⟹ 21→19。
2026-10-29 E23（owner 批准「收紧版」）：`ecc_findings` 判据由 `open == 0`（结构性不可达）
改为「无 critical open + 24h 内首次登记数 ≤ 关闭数」；`ecc_findings_closed_loop` 只修
注释-代码漂移（原文案称「WARN 不设硬门禁」，实现是 `<=3` 硬门禁），**线不动**。
2026-10-30 E24：`reopen` 计入关闭配速的「新增」分母（重开增积压却不产 `register`）。)
(2026-08-23: RED-MIGRATE 接入后 red 域 9 阶段 + report = 10 项)。

Contract (compatible with bash heredoc, see docs/analysis/2026-08-10-audit-4to5-contract-changes.md C6):
  {"state_checks":[{"field":..., "declared":..., "replay":..., "match":bool, "issues":[...]}],
   "audit_summary":{"total_fields":N, "matches":M}}

Usage:
  python3 scripts/gk_audit_state.py --state  [--state-file <f>] [--skill-dir <d>]
  python3 scripts/gk_audit_state.py --hint | --self | --hook | --red   (Phase 4c-4f)
  python3 scripts/gk_audit_state.py --all                               (45 项聚合)

Exit codes: 0 = OK (JSON on stdout), 1 = error JSON (stderr not swallowed).
2026-08-19: Phase 4a — 从 cmd_audit bash heredoc L4952-5115 迁移。
  加固点: human_resolutions 验签 cryptography 缺失时降级为存在性检查（原 heredoc 直接崩 → 空 JSON）。
  口径: 计划标 17 项，实际代码 15 项 → 以实际代码为准（batch8 plan L682 待办登记）。
"""

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

_SKILL_DIR = str(Path(__file__).resolve().parent.parent)
_sys_path_setup = False


def _load_state(state_path: str) -> dict:
    """Read state via gk_state._read_state (SHA256 checksum warning included)."""
    global _sys_path_setup
    if not _sys_path_setup:
        _script_dir = os.path.dirname(os.path.abspath(__file__))
        if _script_dir not in sys.path:
            sys.path.insert(0, _script_dir)
        _sys_path_setup = True
    try:
        from gk_state import _read_state
    except ImportError as e:
        return {"error": f"gk_state import failed: {e}"}
    s = _read_state(state_path)
    if isinstance(s, dict) and "error" not in s:
        return s
    return {"error": s.get("error", "unknown")} if isinstance(s, dict) else {}


# ---------------------------------------------------------------------------
# Phase 4a: state domain — 19 项 (迁移自 bash heredoc L4952-5115, 语义等价；
#   其中 `branch_cleaned` / `ci_green` 按生命周期**条件产出**，见 E21/E22)
# ---------------------------------------------------------------------------

# C3③（ECC-3BECE9FAD12A，2026-09-27）：subagent 报告文件 ↔ history 条目**只读对账**。
#   动机：报告已落盘但落库静默失败时无人可查（C1/C2/C4 的瘦身/外置若丢数据同样无痕）。
#   范围裁定（2026-09-27 用户「窗口内双向」）：`subagent_history` 有 96KB 字节配额（实测仅 6 条），
#   而报告文件长期累积（实测 304+）⟹ 全量双向必被「配额滑出」的旧文件淹没（恒 FAIL 噪声）。
#   故只对 **epoch ≥ 最老条目 epoch** 的窗口内文件做双向判定，更老者归 `aged_out`（仅计数）。
#   读**文件系统**而非 `git ls-files`（`.json` 被 `.gitignore` 忽略）。
_REPORT_ID_RE = re.compile(r"^sub-(\d+)-")


def _epoch_of_report_id(x: str):
    """从 `sub-<epoch>-<pid>-<rand>` 取名提取 epoch；不可解析（早期非 sub-* 命名）→ None。"""
    m = _REPORT_ID_RE.match(x or "")
    return int(m.group(1)) if m else None


def reconcile_subagent_reports(gd: dict, skill_dir: str = _SKILL_DIR) -> dict:
    """只读对账：`docs/analysis/subagent/*.json` ↔ `gate_data.subagent_history[].subagent_id`。

    返回：`entries`/`files`（两侧计数）、`window_start`（最老条目 epoch）、
    `entries_without_files`（真异常）、`files_without_entries`（窗口内 = C3 病象）、
    `aged_out`/`legacy`（仅计数）、`ok`（窗口内双向缺口皆空）、`issues`（可读摘要）。
    """
    hist = [e for e in (gd.get("subagent_history") or []) if isinstance(e, dict)]
    entry_set = {str(e.get("subagent_id") or "") for e in hist}
    entry_set.discard("")
    rdir = Path(skill_dir) / "docs" / "analysis" / "subagent"
    files = sorted(p.stem for p in rdir.glob("*.json")) if rdir.is_dir() else []
    file_set = set(files)

    entries_without_files = sorted(x for x in entry_set if x not in file_set)
    eps = [e for e in (_epoch_of_report_id(x) for x in entry_set) if e is not None]
    window_start = min(eps) if eps else None

    files_without_entries, aged_out, legacy = [], 0, 0
    for f in files:
        if f in entry_set:
            continue
        e = _epoch_of_report_id(f)
        if e is None:
            legacy += 1
        elif window_start is not None and e >= window_start:
            files_without_entries.append(f)
        else:
            aged_out += 1

    issues = []
    if entries_without_files:
        issues.append("entries_without_files=%d (e.g. %s)"
                      % (len(entries_without_files), entries_without_files[0]))
    if files_without_entries:
        issues.append("files_without_entries=%d (e.g. %s)"
                      % (len(files_without_entries), files_without_entries[0]))
    if aged_out:
        issues.append("aged_out=%d（配额滑出，非异常）" % aged_out)
    if legacy:
        issues.append("legacy_named=%d（无 epoch 命名，不参与窗口判定）" % legacy)

    return {"entries": len(entry_set), "files": len(files), "window_start": window_start,
            "entries_without_files": entries_without_files,
            "files_without_entries": files_without_entries,
            "aged_out": aged_out, "legacy": legacy,
            "ok": not entries_without_files and not files_without_entries,
            "issues": issues}


def _ledger_read(state_path: str) -> tuple:
    """委托 `gk_budget_ledger.read_records`（C1/C2/C4 **单源**）。失败 ⟹ `([], {})`。"""
    try:
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).resolve().parent))
        from gk_budget_ledger import read_records as _rr
        return _rr(state_path)
    except Exception:
        return ([], {})


# P15（2026-10-01 owner 追认「补当日 raise 阈值」）：**当日提额频次**阈值。
#   治 §12.7 的「耗尽 → 提额 → 再耗尽」循环：原口径只看 `seal_ok`/`bad` ⟹ 提额再频繁也**恒 `match=true`**。
#   ⚠ 取值 **3** 为**定标待回填**（对齐 REV-1b 对 `declared=24` 的处理）：1 次 = 节点重置常态、
#     2 次 = 可疑、≥3 次 = 当日反复提额 ⟹ 判据转红（warn 级「可失败」）。
RAISES_TODAY_MAX = 3


def _edit_budget_raises(state_path: str) -> tuple:
    """旁挂 `<state>.budget-log.jsonl` **提额**条数 → `(total_raise, today_raise_utc)`。

    单源 = `scripts/gk_budget_ledger.py`（owner 裁定 C1 只算 `kind=raise`；C4 坏行**不计入**）。
    缺文件 / 读失败 ⟹ `(0, 0)`。
    """
    try:
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).resolve().parent))
        from gk_budget_ledger import count_raises as _cr
        return _cr(state_path)
    except Exception:
        return (0, 0)


# E23（2026-10-29，owner 批准「收紧版」）：`ecc_findings` 旧判据 `open == 0` 是
#   **结构性不可达** —— 成熟台账 + 审计适配器每次自动入册 5–6 条 ⟹ 永远不可能归零，
#   该检查退化为常量红（`matches/total` 失真，且必然每天产出一条假阳性 finding）。
#   收紧为两条**可达且可判别**的线：
#     ① 无 `critical` 级 open/rejected（安全线，逐条可清）；
#     ② 窗口内「首次登记数」≤「关闭数」（台账在动）。
#   ② 的基线取自 append-only 的 finding journal（第二副本锚），**不新增 state 键**、
#   不触碰 `_AUDIT_EVIDENCE_KEYS` 三写面 —— 否则等于让被审方给自己写基线。
#   ⚠ 「本轮」用**滚动窗口**而非「上次审计以来」：`audit_state_result` 无 ts 字段，
#   补 ts 或补基线键都要动审计证据写面（另门）。
FINDING_CLOSURE_WINDOW_H = 24


def _parse_ts(v):
    """ISO8601 → aware datetime；不可解析 ⟹ `None`（不臆造时间）。"""
    if not isinstance(v, str) or not v:
        return None
    try:
        ts = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _findings_union(state_path: str, fallback_gd: dict = None) -> list:
    """本 state 的 finding 台账（**读侧 union**：主台账 ⊕ finding 溢出片）。

    遗漏⑤（`ECC-3B8AAE201343`）：open 集越线会溢出到 `<state>.finding-archive.jsonl`；只读
    `gate_data.ecc_findings` 会让审计面**看不见已溢出条目**（读分裂）。import 失败 ⟹ 回落主台账
    （不静默变 0：宁可少算溢出片，也不把台账判成空）。
    """
    try:
        _d = os.path.dirname(os.path.abspath(__file__))
        if _d not in sys.path:
            sys.path.insert(0, _d)
        from gk_finding import load_findings_union
        return load_findings_union(state_path) or []
    except Exception:  # noqa: BLE001 — 边界：单源不可用 ⟹ 回落主台账
        return list((fallback_gd or {}).get("ecc_findings") or [])


def _finding_journal_summary(state_path: str, window_h: int = FINDING_CLOSURE_WINDOW_H) -> dict:
    """`<state>.finding-journal.jsonl` 窗口统计 → `{ok, new_open, closed, events, reason}`。

    单源 = `gk_finding._journal_events`（journal 路径约定 + JSONL 解析都由它持有，本处不复制）。
      · `new_open` = 窗口内**首次**出现的 `register` 事件数（同 fid 后续 merge/重登记不计，
        防「同一问题反复登记」充作新增）**加上**窗口内的 `reopen` 事件数
      · `closed`   = 窗口内 `close` 事件数
      · `ok=False` 仅表示 **journal 不存在/读不出**；「台账有无」由调用方判定

    2026-10-30（E24）：`reopen` 计入 `new_open`。原实现只数 `register`，而 `reopen` 把
    status 拉回 `open` 却不产生 `register` ⟹ 「关闭配速」看不见积压回涨（可被用来
    在 `closed >= new` 成立的同时悄悄放大积压）。
    """
    try:
        _d = os.path.dirname(os.path.abspath(__file__))
        if _d not in sys.path:
            sys.path.insert(0, _d)
        from gk_finding import _journal_events
    except Exception:
        return {"ok": False, "reason": "import-failed", "new_open": 0, "closed": 0, "events": 0}
    events = _journal_events(state_path)
    if not events:
        return {"ok": False, "reason": "journal-missing", "new_open": 0, "closed": 0, "events": 0}
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_h)
    first_reg, closed, reopened, bad_ts = {}, 0, 0, 0
    for e in events:
        if not isinstance(e, dict):
            continue
        ts = _parse_ts(e.get("ts"))
        if ts is None:
            bad_ts += 1
            continue
        ev, fid = e.get("event"), str(e.get("fid") or "")
        if ev == "register" and fid and fid not in first_reg:
            first_reg[fid] = ts
        elif ev == "close" and ts >= cutoff:
            closed += 1
        elif ev == "reopen" and ts >= cutoff:
            reopened += 1
    new_open = sum(1 for ts in first_reg.values() if ts >= cutoff) + reopened
    return {"ok": True, "reason": ("bad_ts=%d" % bad_ts) if bad_ts else "",
            "new_open": new_open, "reopened": reopened,
            "closed": closed, "events": len(events)}


def credit_score_block(state_path: str) -> dict:
    """只读观测：额度银行信用分（owner 2026-10-30 裁 ①「只读接收」）。

    单一事实源 = `gk_credit_ledger.read_records`（禁在本文件重算计分/对账）。
    **不是 check**：不进 `state_checks` / `audit_summary.total_fields`，不改任何放行/阻断语义；
    账本不可用只降级为 `available:false`，不拖垮审计。
    """
    try:
        import gk_credit_ledger as CL
        _recs, stat = CL.read_records(state_path)
        return {"score": stat.get("score", 0), "records": stat.get("count", 0),
                "bad": stat.get("bad", 0), "seal_ok": stat.get("seal_ok"),
                "authority": "read_only",
                "note": "观测值：无门禁权威（额度银行持有额度动作；审计署只对账/回收）"}
    except Exception as e:  # 账本不可用不得拖垮审计（观测项，非判据）
        return {"score": None, "authority": "read_only", "available": False,
                "error": "credit_ledger_unavailable: %s: %s" % (type(e).__name__, e)}


def check_state_file(state_path: str, skill_dir: str = _SKILL_DIR) -> dict:
    """deterministic state checks — 输出契约与 bash heredoc 一致."""
    s = _load_state(state_path)
    gd = s.get("gate_data", {}) if isinstance(s, dict) else {}
    checks = []

    # 1. commit_shas — 声明即匹配
    cs = gd.get("commit_shas", "")
    checks.append({"field": "commit_shas", "declared": bool(cs),
                   "replay": "read from state", "match": True})

    # 2. ci_green — 复刻执行序列判定 (gatekeeper-cli.sh L2613-2616)
    #    执行序列 STAGE_2 _write_gate_data 在 main_repo 计算:
    #    ci_pushed=0 (git log origin/<branch>..HEAD 无未推送) && ci_clean=0 (git status 无未提交) → ci_green=true
    #    审计 replay 重放同判定 (git -C main_repo)，声明与 git 事实不符即 FAIL (2026-08-23 复刻;
    #    原实现仅查 git status，缺 push 历史验证，手写声明可绕过)
    #
    # 2026-10-29（E22，A′ 续）：**按生命周期收窄产出范围**。该字段唯一写方是 STAGE_2 的
    #   state-update 命令 ⟹ standing / analysis 项目（ECO-* / ECC-* / IDLE）结构性不声明。
    #   产出来只会让 `total_fields` 虚高、`matches/total` 失真，并给适配器喂假阳性 finding
    #   （E20 首轮 7 条里 `audit.state.ci_green` 即属此类）。
    #   保留 `"ci_green" in gd` 作 **or** 条件 ⟹ 已声明就必须被审（删键不能让它消失，
    #   否则等于开一个「把字段删掉即可豁免」的自助面）。
    #   ⚠ 与 E21 同口径：改的是「检查范围」，不是「通过标准」。
    _CI_SCOPE = ("STAGE_2", "STAGE_3", "STAGE_4", "STAGE_5", "DONE")
    if "ci_green" in gd or str(s.get("stage", "")) in _CI_SCOPE:
        branch = s.get("branch", "") if isinstance(s, dict) else ""
        repo = s.get("main_repo", "") if isinstance(s, dict) else ""
        # 2026-08-23 交叉审查修复 (WSL 跨环境): main_repo 是 Windows 路径 (C:/...)
        # 但 cmd_audit 在 WSL bash 跑 → python3 是 WSL python → git -C "C:/..." 失败 →
        # ci_pushed=-1 永远 FAIL。WSL (sys.platform=linux) 下转 /mnt/c/... 形态。
        if sys.platform.startswith("linux") and re.match(r"^[A-Za-z]:", repo):
            repo = "/mnt/" + repo[0].lower() + repo[2:].replace("\\", "/")
        cg = gd.get("ci_green")
        ci_pushed = ci_clean = -1
        ci_why = ""
        # E21（2026-10-29，A′）：replay 必须说清「为什么 -1」—— 原实现把所有异常吞成
        #   `pushed=-1`，把「仓库路径失效」与「没有 upstream」混为一谈（实测主 state 的
        #   `main_repo` 指向已删除目录 ⟹ 永远 -1，看上去却像「环境不可判」）。
        #   ⚠ 只加诊断文本，`match` 判定式**不变**（不造 N/A 豁免面）。
        if repo and not os.path.isdir(repo):
            ci_why = "unverifiable:repo-missing"
        else:
            try:
                import subprocess
                base = ["git", "-C", repo] if repo else ["git"]
                p = subprocess.run(base + ["log", "--oneline", f"origin/{branch}..HEAD"],
                                   capture_output=True, text=True, timeout=10)
                if p.returncode == 0:
                    ci_pushed = len([ln for ln in p.stdout.splitlines() if ln.strip()])
                else:
                    ci_why = "unverifiable:git-log-failed"
                c2 = subprocess.run(base + ["status", "--porcelain"],
                                    capture_output=True, text=True, timeout=10)
                if c2.returncode == 0:
                    ci_clean = len([ln for ln in c2.stdout.splitlines() if ln.strip()])
                elif not ci_why:
                    ci_why = "unverifiable:git-status-failed"
            except Exception:
                ci_why = "unverifiable:exec-error"
        _ci_replay = f"pushed={ci_pushed} clean={ci_clean}" + (f" {ci_why}" if ci_why else "")
        checks.append({"field": "ci_green", "declared": cg,
                       "replay": _ci_replay,
                       "match": cg is True and ci_pushed == 0 and ci_clean == 0})

    # 3. gitnexus_baseline — 存在 nodes 键
    gb = gd.get("gitnexus_baseline", {}) or {}
    checks.append({"field": "gitnexus_baseline", "declared": "nodes" in gb,
                   "replay": "re-gitnexus status", "match": True})

    # 4. branch_cleaned — F-11: None 不得通过，仅显式 True 通过
    # 2026-10-29（E21，A′）：**只在分支退休阶段产出**（STAGE_5 / DONE）。该字段的唯一写方是
    #   state-update 命令的 STAGE_5 分支 ⟹ 其余阶段结构性为 None；产出来只会让
    #   `total_fields` 虚高、`matches/total` 失真，并给适配器喂假阳性 finding。
    #   ⚠ 改的是「检查范围」，不是「通过标准」：进入该阶段后 None 仍然判失败。
    if str(s.get("stage", "")) in ("STAGE_5", "DONE"):
        bc = gd.get("branch_cleaned")
        checks.append({"field": "branch_cleaned", "declared": bc,
                       "replay": "git branch --list", "match": bc is True})

    # 5. monitor_scores — F-09/D9 单调性（非仅计数）
    ms = s.get("monitor_scores", {}) if isinstance(s, dict) else {}
    scores = [v.get("score", 0) for k, v in sorted(ms.items()) if isinstance(v, dict)]
    mono_ok = True
    if len(scores) >= 3:
        last3 = scores[-3:]
        mono_ok = not all(last3[i] > last3[i + 1] for i in range(len(last3) - 1))
    checks.append({"field": "monitor_scores", "declared": f"{len(ms)} stages scored",
                   "replay": "check monotonicity", "match": mono_ok})

    # 6. history — D9 唯一性
    h = s.get("history", []) if isinstance(s, dict) else []
    phases = [e.get("r_phase", "") for e in h if isinstance(e, dict)]
    unique_ok = len(phases) == len(set(phases))
    checks.append({"field": "history", "declared": f"{len(h)} entries",
                   "replay": "verify uniqueness", "match": unique_ok})

    # 7. subagent_history — guardrail/access_violations/confidence + G-13 连续 low
    sh = gd.get("subagent_history", []) or []
    sh_issues = []
    for entry in sh[-5:]:
        if isinstance(entry, dict):
            if entry.get("guardrail", "") not in ("passed", ""):
                sh_issues.append(f"guardrail={entry.get('guardrail', '')}")
            if entry.get("access_violations"):
                sh_issues.append(f"access_violations={entry.get('access_violations')}")
            if entry.get("confidence", "") == "low":
                sh_issues.append("confidence=low")
    consecutive_low = 0
    for entry in reversed(sh[-5:]):
        if isinstance(entry, dict) and entry.get("confidence", "") == "low":
            consecutive_low += 1
        else:
            break
    if consecutive_low >= 3:
        sh_issues.append(f"consecutive_low_confidence={consecutive_low}")
    sh_ok = len(sh_issues) == 0
    checks.append({"field": "subagent_history", "declared": f"{len(sh)} entries",
                   "replay": "check guardrail+violations+confidence", "match": sh_ok,
                   "issues": sh_issues[:5] if sh_issues else []})

    # 7c. FIFO 归档 — 窗口外事件流的**审计读面**（2026-11-01）
    #     窗口只保 20 条，出窗条目 append 到 `<state>.*-journal.jsonl`；此处只报计数 + 最近一条，
    #     不回读内容进上下文、也不并回熵窗口（熵刻意只吃 live，防旧违规复燃）。
    #     2026-11-01（T5）：`rejected-edits` 已改名 **journal**；旧名 `-archive` 仍纳入读面
    #     （存量文件不消失、不自动迁移 ⟹ 读面必须两代都认）。
    import glob as _glob
    _arch = []
    for _tag, _suffixes in (("rejected_edits", (".rejected-edits-journal.jsonl",
                                                ".rejected-edits-archive.jsonl")),
                            ("subagent_history", (".history-archive*.jsonl",))):
        _files = []
        for _suffix in _suffixes:
            _files.extend(_glob.glob(state_path + _suffix))
        _files = sorted(set(_files))
        _n, _last, _err = 0, "", ""
        for _p in _files:
            try:
                with open(_p, "r", encoding="utf-8", errors="replace") as _f:
                    for _line in _f:
                        if _line.strip():
                            _n += 1
                            _last = _line.strip()
            except OSError as _e:
                _err = str(_e)[:80]
        _arch.append({"tag": _tag, "files": len(_files), "entries": _n,
                      "last": _last[:120], "error": _err})
    checks.append({"field": "fifo_archives",
                   "declared": " ".join("%s=%d" % (a["tag"], a["entries"]) for a in _arch),
                   "replay": "count <state>.*-archive.jsonl (append-only; live window=20)",
                   "match": not any(a["error"] for a in _arch),
                   "archives": _arch})

    # 7d. bank_actions 读时投影（T3，2026-11-01）—— 事件单写后该字段不再落盘，
    #     审计面用投影兜底（唯一正本 = rejected_edits 里 source=="bank" 的事件），
    #     口径与 `gk_json_utils.view_bank_actions` 同源（禁第二份过滤实现）。
    try:
        from gk_json_utils import view_bank_actions as _view_bank
        _ba = _view_bank(gd, state_file)
    except Exception:
        _ba = []
    checks.append({"field": "bank_actions_view",
                   "declared": "bank=%d" % len(_ba),
                   "replay": "projection: rejected_edits[source=bank] + rejected-edits-journal (no on-disk bank_actions)",
                   "match": True, "entries": _ba[-5:]})

    # 7b. subagent_reports — C3③（ECC-3BECE9FAD12A）：报告文件 ↔ history 条目只读对账
    #     （窗口内双向；判据见 reconcile_subagent_reports docstring）
    _rep = reconcile_subagent_reports(gd, skill_dir)
    checks.append({"field": "subagent_reports",
                   "declared": f"{_rep['files']} files / {_rep['entries']} entries",
                   "replay": "fs docs/analysis/subagent/*.json <-> history[].subagent_id (windowed)",
                   "match": _rep["ok"],
                   "issues": _rep["issues"][:5]})

    # 8. block_log — D14 命令集中度 + G-14 频率趋势
    bl = gd.get("block_log", []) or []
    bl_ok, bl_issues = True, []
    if len(bl) >= 3:
        cmds = [e.get("command", "") for e in bl[-10:] if isinstance(e, dict)]
        freq = {}
        for c in cmds:
            freq[c] = freq.get(c, 0) + 1
        if freq:
            top_cmd = max(freq, key=freq.get)
            top_count = freq.get(top_cmd, 0)
            if top_count >= 3:
                bl_ok = False
                bl_issues.append(f"concentrated:{top_cmd}={top_count}")
        timestamps = []
        for e in bl[-20:]:
            if isinstance(e, dict):
                ts = e.get("timestamp", "")
                if ts:
                    try:
                        timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
                    except Exception:
                        pass
        if len(timestamps) >= 4:
            ts_sorted = sorted(timestamps)
            mid_ts = ts_sorted[len(ts_sorted) // 2]
            recent_count = sum(1 for t in ts_sorted if t >= mid_ts)
            older_count = len(ts_sorted) - recent_count
            if recent_count > older_count * 1.5 and recent_count >= 3:
                bl_ok = False
                bl_issues.append(f"frequency_increasing:recent={recent_count} vs older={older_count}")
    checks.append({"field": "block_log", "declared": f"{len(bl)} entries",
                   "replay": "check concentration+frequency", "match": bl_ok,
                   "issues": bl_issues[:3] if bl_issues else []})

    # 9. sealed_agent_score — D10: ECO-EDIT 完成但无密封分 = 失败
    seal = gd.get("_sealed_agent_score", {}) or {}
    seal_ok, seal_issues = True, []
    eco_edit_completed = (gd.get("eco_completions", {}).get("ECO-EDIT", {}).get("completed_at", ""))
    if seal:
        for f in ["score", "verdicts", "conclusion"]:
            if f not in seal:
                seal_ok = False
                seal_issues.append(f"missing:{f}")
    else:
        if eco_edit_completed:
            seal_ok = False
            seal_issues.append("ECO-EDIT completed but sealed_score absent")
    checks.append({"field": "sealed_agent_score", "declared": "sealed" if seal else "absent",
                   "replay": "check fields", "match": seal_ok, "issues": seal_issues})

    # 10. adjudicate_records — verdicts_json 非空 + divergence ≤ 0.2
    cl = gd.get("human_calibration_log", []) or []
    adj_ok, adj_issues = True, []
    if cl:
        last_adj = cl[-1] if cl else {}
        if not last_adj.get("verdicts_json"):
            adj_ok = False
            adj_issues.append("no verdicts")
        if (last_adj.get("divergence") or 0) > 0.2:
            adj_issues.append(f"high_divergence:{last_adj.get('divergence', 0)}")
    checks.append({"field": "adjudicate_records", "declared": f"{len(cl)} entries",
                   "replay": "check verdicts", "match": adj_ok, "issues": adj_issues})

    # 11. appeal_records — 每条须有 verdict
    ar = s.get("appeal_records", {}) if isinstance(s, dict) else {}
    ar_ok, ar_issues = True, []
    for gate, rec in (ar or {}).items():
        if not rec.get("verdict"):
            ar_ok = False
            ar_issues.append(f"{gate}:no_verdict")
    checks.append({"field": "appeal_records", "declared": f"{len(ar)} entries",
                   "replay": "check verdicts", "match": ar_ok, "issues": ar_issues[:3]})

    # 12. human_resolutions — Ed25519 真验签 (2026-08-13 升级; 加固: cryptography 缺失时降级存在性)
    hr = s.get("human_resolutions", {}) if isinstance(s, dict) else {}
    hr_ok, hr_issues, _hr_sig_keys = True, [], []
    _audit_pub = os.environ.get("_AUDIT_PUB_KEY", "")
    _context_pub = os.environ.get("_CONTEXT_PUB_KEY", "")

    def _verify_hr_sig(gate, res):
        import base64
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            from cryptography.exceptions import InvalidSignature
            _CRYPTO = True
        except ImportError:
            return ("degraded", "")
        sig = res.get("ed25519_sig", "")
        if not sig:
            return ("missing", "")
        rec = {k: v for k, v in res.items() if k not in ("ed25519_sig", "ed25519_hash")}
        payload = json.dumps(rec, sort_keys=True).encode()
        try:
            sig_bin = base64.b64decode(sig, validate=True)
        except Exception:
            return ("fake", "")
        if len(sig_bin) != 64:
            return ("fake", "")
        cands = [payload, payload + b"\n"]
        for pp, label in [(_audit_pub, "audit"), (_context_pub, "context_legacy")]:
            if not pp or not os.path.exists(pp):
                continue
            try:
                pub = load_pem_public_key(open(pp, "rb").read())
                for data in cands:
                    try:
                        pub.verify(sig_bin, data)
                        return ("ok", label)
                    except InvalidSignature:
                        continue
            except Exception:
                continue
        return ("invalid", "")

    for gate, res in (hr or {}).items():
        if isinstance(res, dict):
            st, key = _verify_hr_sig(gate, res)
            _hr_sig_keys.append(f"{gate}:{st}" + (f":{key}" if key else ""))
            if st == "missing":
                hr_ok = False
                hr_issues.append(f"{gate}:missing_signature")
            elif st == "fake":
                hr_ok = False
                hr_issues.append(f"{gate}:fake_signature")
            elif st == "invalid":
                hr_ok = False
                hr_issues.append(f"{gate}:invalid_signature")
            elif st == "ok" and key == "context_legacy":
                hr_issues.append(f"{gate}:context_legacy(WARN)")
            elif st == "degraded":
                # cryptography 缺失 → 降级为存在性检查（不崩），WARN
                if not res.get("ed25519_sig"):
                    hr_ok = False
                    hr_issues.append(f"{gate}:missing_signature")
                else:
                    hr_issues.append(f"{gate}:crypto_unavailable(WARN)")
    checks.append({"field": "human_resolutions", "declared": f"{len(hr)} entries",
                   "replay": "crypto verify ed25519", "match": hr_ok,
                   "issues": hr_issues[:5], "sig_keys": _hr_sig_keys})

    # 13. eco_ecc_link — ECO-EDIT.completed_at
    eco = gd.get("eco_completions", {}) or {}
    eco_edit = eco.get("ECO-EDIT", {}) or {}
    eco_ok = True
    if eco_edit and not eco_edit.get("completed_at"):
        eco_ok = False
    checks.append({"field": "eco_ecc_link",
                   "declared": f'ECO-EDIT:{"done" if eco_edit.get("completed_at") else "pending"}',
                   "replay": "check completed_at", "match": eco_ok})

    # 14. ecc_findings — 台账健康（E23 收紧；旧线 `open == 0` 结构性不可达，见常量注释）
    # 2026-10-31（遗漏⑤）：读侧改 union ⟹ 溢出片条目仍计入健康面（禁读分裂）。
    ecc_findings = _findings_union(state_path, gd)
    ecc_open = [f for f in ecc_findings
                if isinstance(f, dict) and f.get("status") in ("open", "rejected")]
    ecc_critical = [f for f in ecc_open
                    if str(f.get("severity") or "").lower() == "critical"]
    _js = _finding_journal_summary(state_path)
    ecc_issues = []
    if ecc_critical:
        ecc_issues.append("critical_open=%d (e.g. %s)"
                          % (len(ecc_critical), str(ecc_critical[0].get("id", "?"))))
    if not _js["ok"]:
        # 空台账 + 无事件账 = 从未登记，无账可动 ⟹ 不判失败；
        # 有台账却无事件账 = 清洗信号（`gk_finding.reconcile_pair` anomaly ①）⟹ 判失败，禁静默通过。
        if ecc_findings:
            ecc_issues.append("unverifiable:journal-missing（%d 条台账无事件账）" % len(ecc_findings))
    elif _js["closed"] < _js["new_open"]:
        ecc_issues.append("closure_lag: closed_%dh=%d < new_%dh=%d"
                          % (FINDING_CLOSURE_WINDOW_H, _js["closed"],
                             FINDING_CLOSURE_WINDOW_H, _js["new_open"]))
    checks.append({"field": "ecc_findings",
                   "declared": f"{len(ecc_findings)} total, {len(ecc_open)} open/rejected, "
                               f"{len(ecc_critical)} critical",
                   "replay": ("journal: new=%d closed=%d in %dh"
                              % (_js["new_open"], _js["closed"], FINDING_CLOSURE_WINDOW_H))
                             + ((" reopen=%d" % _js.get("reopened", 0))
                                if _js.get("reopened") else "")
                             + ((" " + _js["reason"]) if _js["reason"] else ""),
                   "match": not ecc_issues,
                   "issues": ecc_issues[:4]})

    # 15. achievements — 顶层字段存在且为 dict
    ach = s.get("achievements", {}) if isinstance(s, dict) else {}
    ach_ok = isinstance(ach, dict)
    checks.append({"field": "achievements", "declared": f"{len(ach)} unlocked",
                   "replay": "check format (dict)", "match": ach_ok})

    # 16. ecc_findings 闭环（2026-08-20, R-T8.2）— 滞留 open/rejected 的**积压上限**。
    # open/rejected 是登记在案的合法状态（技能自维护防裸跑），单条不 FAIL；
    # 积压 **> 3** 则 FAIL（`match = len(open_f) <= 3`）。
    # 2026-10-29（E23，owner 裁「以代码为准」）：原文案写「仅 WARN，match 不设硬门禁」，
    #   与实现**直接矛盾**（注释-代码漂移）。此处只**修文案、不动线** —— 该线与检查 14 的
    #   「结构性不可达」不同：积压可以真的清到 ≤3，只是要求严。
    ef = _findings_union(state_path, gd)
    open_f = [f for f in ef if isinstance(f, dict) and f.get("status") in ("open", "rejected")]
    checks.append({"field": "ecc_findings_closed_loop", "declared": f"{len(ef)} findings, {len(open_f)} open/rejected",
                   "replay": "check finding lifecycle", "match": len(open_f) <= 3,
                   "issues": [f"{f.get('id', '?')}:{str(f.get('title', '?'))[:30]}" for f in open_f[:3]]})

    # 16b. ledger_conflicts（2026-09-28，元数据中枢·全序列打通②/③ 实现缺口，ECC-95175BA03B50）——
    #   三源联邦（base + 活体域 state + archive）**同 id 状态必须一致**，且**可写源不得留真镜像**
    #   （同 id 同内容重复）。状态冲突收敛入口 = `finding conflicts --converge --apply`；真镜像归位
    #   入口 = `finding conflicts --dedupe --apply`。**代际分歧**（同 id 不同内容）须人工裁决 ⟹
    #   只报（issues）不判失败（否则机检无法自愈、恒红）。
    _conf, _dup, _mir, _div = [], [], [], []
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import gk_finding as _gf
        _conf = _gf.ledger(state_path).get("conflicts", []) or []
        _dup = _gf.writable_duplicates(state_path)
        _mir = _gf.writable_mirrors(state_path)
        _div = [i for i in _dup if i not in set(_mir)]
    except Exception:  # noqa: BLE001 — 取不到联邦视图 → 照实 WARN（不臆造 OK）
        _mir = ["<ledger unavailable>"]
    checks.append({"field": "ledger_conflicts",
                   "declared": (f"{len(_mir)} writable-mirror id(s); {len(_div)} divergent id(s); "
                                f"{len(_conf)} status conflict(s)"),
                   "replay": "one-authority-per-id invariant", "match": not _mir,
                   "issues": [str(c) for c in (_mir + _div)[:5]]})

    # 17. hook_block_log — 意图记忆可审计性 + 提权链信号 (2026-09-02)
    # 读取: 当前 gate_data.hook_block_log (TTL 窗口) + history[].hook_block_log
    #       (discover prev_entry 归档幸存 → 不随 R 切换 gate_data={} 清空被烧)。
    # match 语义: 记录格式有效（每条 dict 含 ts/tool）即可被审计读取 → 通过；
    #   记录存在≠有罪（它是"行为偏离检测"的证据源）。escalation>0 → issues 提示人工复核，
    #   与 HOOK-06 实时监控互补：此处跨 R 仍可见提权链残留证据（HOOK-06 只看当前 gate_data 快照）。
    hbl = gd.get("hook_block_log") or []
    archived_hbl = []
    for _e in (s.get("history") or []):
        if isinstance(_e, dict) and isinstance(_e.get("hook_block_log"), list):
            archived_hbl.extend(_e["hook_block_log"])
    _all_intent = [r for r in (list(hbl) + archived_hbl) if isinstance(r, dict)]
    _malformed = [r for r in _all_intent
                  if not (r.get("ts") is not None and r.get("tool"))]
    _esc_total = sum(1 for r in _all_intent if r.get("kind") == "escalation")
    hbl_issues = []
    if _esc_total > 0:
        hbl_issues.append(f"escalation_signals={_esc_total}（提权绕过尝试证据，建议人工复核）")
    if archived_hbl:
        hbl_issues.append(f"archived_cross_r={len(archived_hbl)}（R 切换归档幸存）")
    hbl_ok = len(_malformed) == 0
    checks.append({"field": "hook_block_log",
                   "declared": f"{len(_all_intent)} intents ({_esc_total} escalations)",
                   "replay": "read gate_data + history[].hook_block_log (format check)",
                   "match": hbl_ok,
                   "issues": [i for i in (hbl_issues + ([f"malformed={len(_malformed)}"] if _malformed else [])) if i][:4]})

    # 提额频次项 —— 读旁挂 `<state>.budget-log.jsonl`（append-only，不受整体替换影响）。
    # 2026-09-30 owner 裁定 C1–C4：口径单源 `gk_budget_ledger`（C1 只算 `kind=raise`；
    #   C4 坏行不计入；C2 同报**封印状态**）⟹ 本项 `match` 由**恒真**（P15）改为**可失败**判据。
    _raises_all, _raises_today = _edit_budget_raises(state_path)
    _lrecs, _lstat = _ledger_read(state_path)
    _l_issues = []
    if _lstat.get("bad"):
        _l_issues.append(f"ledger_bad_lines={_lstat['bad']}（C4：坏行不计入，需人工核）")
    if _lstat.get("seal_ok") is False:
        _l_issues.append("ledger_seal_broken（C2：封印校验失败 ⟹ 账本可能被改）")
    if _raises_today:
        _l_issues.append(f"raises_today={_raises_today}（当日提额，建议复核额度承载）")
    # P15（2026-10-01 owner 追认）：**当日提额频次**闸 —— 超阈值 ⟹ 本项可失败（治「判据恒真」）。
    _raises_over = _raises_today > RAISES_TODAY_MAX
    if _raises_over:
        _l_issues.append(f"raises_today_exceeds={_raises_today}>阈值{RAISES_TODAY_MAX}"
                         "（当日反复提额 ⟹ 复核「耗尽-提额」循环 / 额度承载是否失准）")
    checks.append({"field": "edit_budget_raises",
                   "declared": (f"{_raises_all} total ({_raises_today} today, max={RAISES_TODAY_MAX}); "
                                f"seal={_lstat.get('seal_mode') or 'n/a'}; bad={_lstat.get('bad', 0)}"),
                   "replay": "read <state>.budget-log.jsonl (+ .seal; append-only side ledger)",
                   "match": bool(_lstat.get("seal_ok") is not False and not _lstat.get("bad")
                                 and not _raises_over),
                   "issues": _l_issues[:4]})

    # 21. state_forms（② 单一权威，2026-10-02）—— 枚举面**非空**即通过；存量 legacy/worktree
    #     **只报不判失败**。挑战6：依赖不可用 / 枚举异常 ⟹ **不吞**（无 `except→空表` 兜底），
    #     否则 item 恒绿、与单源不变量目的相反。
    import gk_state_forms as _gsf        # 缺失即 ImportError（fail-loud，不吞）
    # c8（§18.2 #8）：扩多根 —— worktree 内域 state 亦可见（**加性**，标准布局外的根为 `[]`）。
    _wt_roots = _gsf.worktree_state_roots(str(skill_dir))
    _all = _gsf.iter_live_states(str(skill_dir), extra_roots=_wt_roots)
    # [P2 修 · ECC-BA39372B031D] 判据须**可证伪**：原 `match = len(_all) >= 1` 在主根存在任一
    #   state 时**恒真** ⟹ 扩根接线被回退与真通过**同形**（零痕）。现要求：worktree 根存在时，
    #   列举面**须至少命中 1** 个来自这些根的 state（接线回退 ⟹ 命中 0 ⟹ 判 False）。
    _wt_hits = [f for f in _all
                if any(os.path.dirname(os.path.abspath(f)) == os.path.abspath(r) for r in _wt_roots)]
    _sf_legacy = [f for f in _all
                  if _gsf.state_form(f, skill_root=str(skill_dir)) not in _gsf.WRITABLE_FORMS]
    checks.append({"field": "state_forms",
                   "declared": (f"{len(_all) - len(_sf_legacy)} writable / "
                                f"{len(_sf_legacy)} legacy-or-worktree"
                                f" (extra_roots={len(_wt_roots)}, worktree_hits={len(_wt_hits)})"),
                   "replay": "inventory non-empty (gate lives at write entries)",
                   "match": len(_all) >= 1 and (not _wt_roots or len(_wt_hits) >= 1),
                   "issues": [str(x) for x in _sf_legacy[:5]]})

    return {"state_checks": checks,
            "audit_summary": {"total_fields": len(checks),
                              "matches": sum(1 for c in checks if c.get("match"))},
            # 2026-10-30（裁①）：只读观测，非 check（不进 total_fields）。
            "credit_score": credit_score_block(state_path)}


# ---------------------------------------------------------------------------
# Phase 4c: AUDIT-HINT — advance hint JSON 完整性 (4 项, 计划 L1978-1983)
# ---------------------------------------------------------------------------

def check_hint(skill_dir: str = _SKILL_DIR) -> dict:
    """4 deterministic checks against cmd_advance hint_json structure."""
    checks = []
    cli_path = Path(skill_dir) / "gatekeeper-cli.sh"
    text = cli_path.read_text(encoding="utf-8", errors="replace") if cli_path.exists() else ""

    # HINT-01: checklist 覆盖所有 11 阶段 (hint_json phase 名称计数)
    phases = re.findall(r'"phase":"(STAGE_\d+|ECO-[A-Z]+|AUDIT-[A-Z]+|RED-[A-Z]+)"', text)
    unique_phases = sorted(set(phases))
    checks.append({"field": "hint_checklist_coverage", "declared": f"{len(unique_phases)} hint phases",
                   "replay": "scan hint_json phase keys", "match": len(unique_phases) >= 11,
                   "detail": unique_phases[:20]})

    # HINT-02: tool_policy 注入且含 search/review/read 三层
    # 2026-08-20: 源码内为 \"tool_policy\": 转义形式（tool_policy 后是 \ 与 "），
    # 裸引号/`\s*:` 扫描均假阴性 → 字符类 [\\" ]* 兼容转义/普通两种形态
    has_tool_policy = re.search(r"tool_policy[\\\\\" ]*:", text) is not None
    has_tool_three = all(kw in text for kw in ("\"available\"", "\"trigger\""))
    checks.append({"field": "hint_tool_policy", "declared": f"tool_policy={has_tool_policy}",
                   "replay": "scan tool_policy: (escaped/plain) + available/trigger keys", "match": has_tool_policy and has_tool_three})

    # HINT-03: post_check 注入且指向 self-check
    has_post_check = re.search(r"post_check[\\\\\" ]*:", text) is not None
    has_self_ref = "self-check" in text or "self_check" in text
    checks.append({"field": "hint_post_check", "declared": f"post_check={has_post_check}",
                   "replay": "scan post_check: + self-check ref", "match": has_post_check and has_self_ref})

    # HINT-04: gates 注入且含关键阶段过渡约束
    has_gates = re.search(r"gates[\\\\\" ]*:", text) is not None
    has_advance_trigger = "advance" in text
    checks.append({"field": "hint_gates", "declared": f"gates={has_gates}",
                   "replay": "scan gates: + advance trigger", "match": has_gates and has_advance_trigger})

    return {"hint_checks": checks,
            "audit_summary": {"total_fields": len(checks),
                              "matches": sum(1 for c in checks if c.get("match"))}}


# ---------------------------------------------------------------------------
# Phase 4d: AUDIT-SELF — gk_self_check.py 自检完整性 (4 项, 计划 L1984-1988)
# ---------------------------------------------------------------------------

def check_self(skill_dir: str = _SKILL_DIR) -> dict:
    """4 checks: run_all 注册 / try-except 隔离 / 动态提取 / gitnexus runner."""
    checks = []
    sc_path = Path(skill_dir) / "scripts" / "gk_self_check.py"
    sc_text = sc_path.read_text(encoding="utf-8", errors="replace") if sc_path.exists() else ""
    # 2026-08-20: CRLF 行尾会阻断 `\):\n` 类正则（`:` 后是 `\r` 非 `\n`）→ 归一化为 LF
    sc_text = sc_text.replace("\r\n", "\n")

    # SELF-01: 所有 check_* 函数在 run_all() 中注册
    # 2026-08-20: 签名含 `-> dict` 返回注解，`\(.*?\):` 因 `:` 不紧跟 `)` 而失配 → `\(.*?\)[^:]*:`
    funcs = re.findall(r"^def (check_\w+)\(.*?\)[^:]*:", sc_text, re.MULTILINE)
    run_all_body = sc_text.split("def run_all(")[1].split("def main(")[0] if "def run_all(" in sc_text else ""
    registered = [f for f in funcs if f in run_all_body]
    checks.append({"field": "self_registered", "declared": f"{len(funcs)} check funcs",
                   "replay": "verify run_all() calls each", "match": len(registered) == len(funcs),
                   "detail": f"registered {len(registered)}/{len(funcs)}"})

    # SELF-02: 每个 check 函数体含 try/except 隔离
    # 2026-08-20: body 捕获须容忍函数体内空行（`(?:    .*\n?)*` 在空行截断 → try 在空行后漏检）
    func_bodies = re.findall(r"^def (check_\w+)\(.*?\)[^:]*:\n((?:    .*\n?|\n)*)", sc_text, re.MULTILINE)
    no_try = [name for name, body in func_bodies if "try" not in body]
    checks.append({"field": "self_try_except", "declared": f"{len(func_bodies)} check funcs",
                   "replay": "each body has try", "match": len(no_try) == 0,
                   "issues": [f"{n}:no_try" for n in no_try]})

    # SELF-03: cmd_self_check 动态提取 python check 名称
    # 2026-08-15 RED-PY-BASH 修复: 原硬编码 bash for loop 弃用（新增 python 检查需手动加循环项 → 静默丢输出），
    # 改为自动提取 python 输出全部 check、仅排除 gitnexus（bash-native _run_gitnexus 统一生成）。
    # 2026-08-20: 原 self_bash_loop 检查假设 bash 循环覆盖，与修复后设计不符 → 改验动态提取逻辑。
    cli_path = Path(skill_dir) / "gatekeeper-cli.sh"
    cli_text = cli_path.read_text(encoding="utf-8", errors="replace") if cli_path.exists() else ""
    has_dyn_extract = "data.get('checks',[])" in cli_text
    has_gitnexus_excl = "!='gitnexus'" in cli_text
    self_dyn_ok = has_dyn_extract and has_gitnexus_excl
    checks.append({"field": "self_dyn_extract", "declared": f"dyn_extract={has_dyn_extract} excl_gitnexus={has_gitnexus_excl}",
                   "replay": "cmd_self_check 动态提取 python checks (RED-PY-BASH 修复)",
                   "match": self_dyn_ok,
                   "issues": [] if self_dyn_ok else ["dynamic extraction missing"]})

    # SELF-04: gitnexus check 使用项目本地 runner (R-T5.6 弃用 node.exe+全局 JS 路径 → .gitnexus/run.cjs)
    gn_check = ""
    for name, body in func_bodies:
        if name == "check_gitnexus":
            gn_check = body
            break
    has_run_cjs = ".gitnexus/run.cjs" in gn_check
    has_fallback = "gitnexus" in gn_check  # 全局 gitnexus fallback 分支
    gn_ok = has_run_cjs and has_fallback
    checks.append({"field": "self_gitnexus_runner", "declared": f"run_cjs={has_run_cjs} fallback={has_fallback}",
                   "replay": "scan check_gitnexus body (.gitnexus/run.cjs runner)", "match": gn_ok,
                   "issues": [] if gn_ok else ["project-local runner missing"]})

    return {"self_checks": checks,
            "audit_summary": {"total_fields": len(checks),
                              "matches": sum(1 for c in checks if c.get("match"))}}


# ---------------------------------------------------------------------------
# Phase 4e: AUDIT-HOOK — .trae/settings.json hook 配置 (4 项, 计划 L1990-1994)
# ---------------------------------------------------------------------------

def _hook_settings_candidates(skill_dir: str, state_path: str = "") -> list:
    """Resolve hook 配置候选路径（Windows 与 WSL python 双兼容）。

    hook 实际部署在 Trae 全局根目录 ~/.trae-cn/hooks.json（87d044c catch-all 单入口），
    项目级 .trae/settings.json 已废弃清理。候选顺序: HOOK_SETTINGS 环境变量(逗号分隔)
    → Trae 全局 hooks.json → skill 目录 → state main_repo (Windows 原始 + WSL /mnt/c 映射)
    → ~/.trae/worktrees/* 扫描。
    """
    cands = []
    env = os.environ.get("HOOK_SETTINGS", "").strip()
    if env:
        cands += [c.strip() for c in env.split(",") if c.strip()]
    cands.append(str(Path.home() / ".trae-cn" / "hooks.json"))
    try:  # 用户目录不写死用户名（2026-10-29 去硬编码）
        from gk_host_paths import user_home as _user_home
        cands.append(str(Path(_user_home()) / ".trae-cn" / "hooks.json"))
    except Exception:
        pass
    cands.append(str(Path(skill_dir) / ".trae" / "settings.json"))
    if state_path:
        st = _load_state(state_path)
        main_repo = st.get("main_repo", "") if isinstance(st, dict) else ""
        if main_repo:
            win_p = main_repo.replace("\\", "/")
            win_c = str(Path(win_p) / ".trae" / "settings.json")
            if win_c not in cands:
                cands.append(win_c)
            wsl_p = re.sub(r"^[A-Za-z]:", lambda m: "/mnt/" + m.group(0)[0].lower(), win_p)
            wsl_c = str(Path(wsl_p) / ".trae" / "settings.json")
            if wsl_c not in cands:
                cands.append(wsl_c)
    # worktree 根扫描（Windows 与 WSL 双 home；用户目录单源推导，不写死用户名）
    _homes = [str(Path.home())]
    try:
        from gk_host_paths import user_home as _uh
        if _uh() not in _homes:
            _homes.append(_uh())
    except Exception:
        pass
    for home in _homes:
        wt_base = Path(home) / ".trae" / "worktrees"
        if wt_base.is_dir():
            for wd in sorted(wt_base.iterdir()):
                c = wd / ".trae" / "settings.json"
                if c.exists() and str(c) not in cands:
                    cands.append(str(c))
    return cands


def check_hook(skill_dir: str = _SKILL_DIR, state_path: str = "") -> dict:
    """6 checks against deployed .trae/settings.json PreToolUse hook config.

    2026-08-20: 原实现只读 skill 目录 .trae/settings.json（不存在）→ 全 MISS 假阴性。
    现按 _hook_settings_candidates 解析实际部署位置；exit code 2 在 pre_tool_hook.py 内。
    2026-09-02: +HOOK-05（提权绕过防线源码覆盖）/ HOOK-06（hook_block_log 实时越权监控）。
    """
    checks = []
    cfg_text = ""
    used = ""
    for c in _hook_settings_candidates(skill_dir, state_path):
        p = Path(c)
        if p.exists():
            cfg_text = p.read_text(encoding="utf-8", errors="replace")
            used = str(p)
            break

    # HOOK-01: PreToolUse hook 存在且 matcher 覆盖编辑工具
    has_pre_tool = "PreToolUse" in cfg_text
    matchers = re.findall(r'"matcher"\s*:\s*"([^"]+)"', cfg_text)
    catch_all = any(m.strip() == "*" for m in matchers)
    all_tools = catch_all or all(t in " ".join(matchers) for t in ("Edit", "Write", "SearchReplace", "CreateFile", "DeleteFile"))
    checks.append({"field": "hook_pre_tool_matcher", "declared": f"PreToolUse={has_pre_tool} settings={used or 'NONE'}",
                   "replay": "matcher covers 5 edit tools", "match": has_pre_tool and all_tools,
                   "issues": [] if all_tools else ["missing matcher coverage"]})

    # HOOK-02: hook command 经过 WSL 路由
    has_wsl = "wsl" in cfg_text.lower() or "wslsh" in cfg_text.lower()
    checks.append({"field": "hook_wsl_route", "declared": f"wsl={has_wsl}",
                   "replay": "scan wsl/wslsh in hook command", "match": has_wsl})

    # HOOK-03: hook 超时 >= 10s
    timeout_m = re.findall(r'"timeout"\s*:\s*(\d+)', cfg_text)
    timeout_ok = any(int(t) >= 10 for t in timeout_m)
    checks.append({"field": "hook_timeout", "declared": f"{timeout_m}",
                   "replay": "timeout >= 10s", "match": timeout_ok})

    # HOOK-04: hook exit code 2 正确阻断（实现于 pre_tool_hook.py，非 settings.json）
    hook_py = Path(skill_dir) / "scripts" / "pre_tool_hook.py"
    py_text = hook_py.read_text(encoding="utf-8", errors="replace") if hook_py.exists() else ""
    has_exit_code_2 = re.search(r"sys\.exit\(\s*2\s*\)|exit\(\s*2\s*\)", py_text) is not None
    checks.append({"field": "hook_exit_code", "declared": f"exit2={has_exit_code_2}",
                   "replay": "scan pre_tool_hook.py exit(2) handling", "match": has_exit_code_2})

    # HOOK-05: 工具失效→提权绕过 防线源码覆盖（2026-09-02）——回归删门禁（R0.5/意图记忆）即失守
    has_esc_def = all(k in py_text for k in ("hook_block_log", "_record_block_intent",
                                             "_escaped_write_after_block", "_block_log_snapshot"))
    checks.append({"field": "hook_escalation_defense", "declared": f"coverage={has_esc_def}",
                   "replay": "scan hook_block_log/_record_block_intent/_escaped_write_after_block/_block_log_snapshot",
                   "match": has_esc_def})

    # HOOK-06: hook 提权绕过实时监控（2026-09-02）——state hook_block_log TTL 窗口内
    # 存在 kind=escalation（编辑被 BLOCK 后 RunCommand 直写同文件）= 行为偏离未决 → 不健康
    snap = {"escalations": 0}
    try:
        import sys as _hs
        _hs.path.insert(0, str(Path(skill_dir) / "scripts"))
        import pre_tool_hook as _hp
        snap = _hp._block_log_snapshot(state_path)
    except Exception:
        pass
    esc_n = int(snap.get("escalations", 0) or 0)
    checks.append({"field": "hook_live_escalation", "declared": f"escalations_in_window={esc_n}",
                   "replay": "block_log_snapshot(state).escalations==0",
                   "match": esc_n == 0,
                   "issues": [] if esc_n == 0 else ["检测到工具提权绕过链（编辑被 BLOCK 后 RunCommand 直写同文件），须人工复核"]})

    return {"hook_checks": checks,
            "audit_summary": {"total_fields": len(checks),
                              "matches": sum(1 for c in checks if c.get("match"))}}


# ---------------------------------------------------------------------------
# Phase 4f: AUDIT-RED — RED 引擎完整性 (9 项, 计划 L1995-1998)
# ---------------------------------------------------------------------------

def check_red(skill_dir: str = _SKILL_DIR) -> dict:
    """RED 引擎语义/覆盖回归（2026-09-05 S10 升级，替代原纯文本 `^def`+return 存在性检查）。

    每阶段验证：① def 实存；② dispatcher 分发实调（_red_attacks __main__ 链）；③ 属 red route
    车站（node_guard _ROUTES['red']）→ registry 已登记。
    顶层额外输出 red_registry_stations / red_registry_gap（registry 各站 vs 引擎分发对拍——
    独立两源交叉验证，防 registry 缺站静默盲区）。
    实跑非空回归由 test_red_attacks + `audit --red` 实跑承担（check_red 保持确定性快速，
    不进 env 依赖扫描）。
    """
    checks = []
    ra_path = Path(skill_dir) / "scripts" / "_red_attacks.py"
    ra_text = ra_path.read_text(encoding="utf-8", errors="replace") if ra_path.exists() else ""
    # node_guard red route registry（独立源：引擎分发的车站面锚点）
    try:
        import gk_node_guard as _ng  # noqa: PLC0415 — 同 scripts 目录，函数内 lazy import 防耦合
        _red_stations = list(_ng._ROUTES.get("red", {}).get("nodes", []))
    except Exception:  # noqa: BLE001
        _red_stations = []
    registry_unreadable = not _red_stations

    fields = [
        ("red_scope", "RED-SCOPE"),
        ("red_surface", "RED-SURFACE"),
        ("red_constraints", "RED-CONSTRAINTS"),
        ("red_exploit", "RED-EXPLOIT"),
        ("red_postex", "RED-POSTEX"),
        ("red_hint", "RED-HINT"),
        ("red_hook", "RED-HOOK"),
        ("red_py", "RED-PY"),
        ("red_migrate", "RED-MIGRATE"),   # 引擎内部阶段（非 red route 车站）
        ("red_integrity", "RED-INTEGRITY"),
        ("red_aig", "RED-AIG"),           # A9（2026-10-28）：AIG 车道（只在 KVM 沙箱内跑）
    ]

    def _dispatch_wired(fn: str) -> bool:
        if fn == "red_report":
            return "red_report(all_findings)" in ra_text  # report 收口形态特殊（聚合 all_findings）
        return f"all_findings.extend({fn}())" in ra_text

    # registry 各站 ↔ 引擎分发对拍（gap = 已登记车站但引擎无 def/无分发 → 证据盲区）
    registry_gap = []
    for node in _red_stations:
        fn = "red_" + node[4:].lower()
        def_ok = re.search(rf"^def {fn}\(", ra_text, re.MULTILINE) is not None
        if not (def_ok and _dispatch_wired(fn)):
            registry_gap.append(node)

    for fn, phase in fields:
        def_ok = re.search(rf"^def {fn}\(", ra_text, re.MULTILINE) is not None
        dispatch_ok = _dispatch_wired(fn)
        # 车站阶段要求 registry 覆盖（防 registry 缺站/引擎多跑无站可守）；内部阶段（migrate）豁免
        station = phase in _red_stations
        registry_ok = (not station) or (phase not in registry_gap)
        checks.append({"field": f"red_{fn}", "declared": phase,
                       "replay": "def + dispatcher + registry 车站覆盖 (S10 语义回归)",
                       "match": def_ok and dispatch_ok and registry_ok})

    # RED-REPORT（红队序列终站闭环；registry RED-REPORT 车站 + dispatcher report 收口）
    report_def = re.search(r"^def red_report\(", ra_text, re.MULTILINE) is not None
    report_dispatch = _dispatch_wired("red_report")
    checks.append({"field": "red_report", "declared": "RED-REPORT",
                   "replay": "def red_report() + dispatcher 收口", "match": report_def and report_dispatch})

    return {"red_checks": checks,
            "red_registry_stations": _red_stations,
            "red_registry_gap": registry_gap,
            "red_registry_unreadable": registry_unreadable,
            "audit_summary": {"total_fields": len(checks),
                              "matches": sum(1 for c in checks if c.get("match"))}}


# ---------------------------------------------------------------------------
# Aggregator — 43 项全量 (Phase 4a state 18 + hint 4 + self 4 + hook 6 + red 11)
# ---------------------------------------------------------------------------

def run_all(state_path: str, skill_dir: str = _SKILL_DIR) -> dict:
    """Aggregate all Phase 4a-4f checks into one dict (41 checks total:
    state 17 + hint 4 + self 4 + hook 6 + red 10)."""
    out = {}
    out.update(check_state_file(state_path, skill_dir))
    out.update(check_hint(skill_dir))
    out.update(check_self(skill_dir))
    out.update(check_hook(skill_dir, state_path))
    out.update(check_red(skill_dir))
    all_checks = (out.get("state_checks", []) + out.get("hint_checks", [])
                  + out.get("self_checks", []) + out.get("hook_checks", [])
                  + out.get("red_checks", []))
    out["audit_summary"] = {"total_fields": len(all_checks),
                            "matches": sum(1 for c in all_checks if c.get("match"))}
    out["domains"] = ["state", "hint", "self", "hook", "red"]
    return out


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    state_path = os.environ.get("STATE_FILE", "")
    skill_dir = os.environ.get("SKILL_DIR", _SKILL_DIR)
    mode = "state"

    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--state", "--hint", "--self", "--hook", "--red", "--all"):
            mode = a.lstrip("-")
        elif a == "--state-file" and i + 1 < len(args):
            state_path = args[i + 1]
            i += 1
        elif a == "--skill-dir" and i + 1 < len(args):
            skill_dir = args[i + 1]
            i += 1
        i += 1

    if not state_path:
        from gk_state import DEFAULT_STATE_FILE
        state_path = DEFAULT_STATE_FILE

    try:
        if mode == "state":
            result = check_state_file(state_path, skill_dir)
        elif mode == "hint":
            result = check_hint(skill_dir)
        elif mode == "self":
            result = check_self(skill_dir)
        elif mode == "hook":
            result = check_hook(skill_dir, state_path)
        elif mode == "red":
            result = check_red(skill_dir)
        elif mode == "all":
            result = run_all(state_path, skill_dir)
            # 2026-10-08（§23.3 对策①②）：edit-log 维护 = **区外低频**边界（审计）。
            # 轮转归档（防无界增长）+ 节点级封印（`append_edit` 为裸追加、**不**逐条 seal）。
            # ED14（2026-10-08）：本维护是**写侧效** —— 原「不并入 result」使「只读审计」自述与实况不符；
            #   现**显式声明**：`edit_log_maintenance` 如实登记（审计带维护权限，口径显式，非暗改）。
            # ED2（2026-10-08）：`edit_log` = 只读摘要 ⟹ 本载体的**生产读取面**（治「只写不读 / 空转闸机」）。
            try:
                from gk_budget_ledger import edit_log_stats, rotate_edits, seal_edits
            except Exception as _ie:
                print(json.dumps({"edit_log_import_error": str(_ie)}), file=sys.stderr)
            else:
                try:
                    result["edit_log_maintenance"] = {"rotate": rotate_edits(state_path),
                                                      "seal": seal_edits(state_path)}
                except Exception as _me:
                    print(json.dumps({"edit_log_maintenance_error": str(_me)}), file=sys.stderr)
                    result["edit_log_maintenance"] = {"error": str(_me)}
                try:
                    result["edit_log"] = edit_log_stats(state_path)
                except Exception as _se:
                    print(json.dumps({"edit_log_stats_error": str(_se)}), file=sys.stderr)
            # 2026-10-31（§9.7 待决③）：审计署聚合后**触发** outcome producer。
            #   未配置 `GK_AUDIT_OUTCOME_ENDPOINT` ⟹ 只落 advisory（不伪造 success）。
            try:
                from gk_audit_outcome import sweep as _outcome_sweep
                result["outcome_sweep"] = _outcome_sweep(
                    state_path,
                    endpoint=os.environ.get("GK_AUDIT_OUTCOME_ENDPOINT", ""),
                    key_dir=os.environ.get("GK_AUDIT_OUTCOME_KEY_DIR", ""))
            except Exception as _oe:
                result["outcome_sweep"] = {"ok": False, "error": str(_oe)}
        else:
            print(json.dumps({"error": f"unknown mode: {mode}",
                              "valid": ["--state", "--hint", "--self", "--hook", "--red", "--all"]}))
            sys.exit(1)
        print(json.dumps(result, ensure_ascii=False))
        sys.exit(0)
    except Exception as e:
        # 2026-08-13 教训: heredoc 异常被 2>/dev/null 吞 → 空 JSON。此处显式报错。
        err = {"error": str(e), "mode": mode, "trace": __import__("traceback").format_exc()}
        print(json.dumps(err, ensure_ascii=False), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
