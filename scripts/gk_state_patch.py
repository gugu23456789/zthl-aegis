#!/usr/bin/env python3
"""gk_state_patch.py — state 文件增量写入安全网（batch8 批次 2 写入类，2026-08-25）。

复用 gk_state.py 的 _read_state/_write_state（SHA256 checksum 单一事实，杜绝两处算法漂移）。
覆盖三个内联模式（gatekeeper-cli.sh 迁移前 L2529/L2762/L3109 语义等价）：

- update-best:      gate_data.best 增量更新——仅当新 score 更优才写（L2529 语义，r_phase 用
                    正则对原文提取，消除对 /usr/bin/rg 的依赖）
- update-gate-data: gate_data 顶层键批量 update + _write_state 自动重算 checksum（L2762 语义）
- subset:           读 state 子集（outer[inner] 过滤排除键，L3109 语义，签名数据剔除 ed25519_*）

只读模式（查询）走 gk_state_query.py；本模块只做**受 checksum 保护的写入**。
"""
import base64
import datetime
import hashlib
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import gk_state  # noqa: E402
from gk_json_utils import state_lock, update_state  # noqa: E402

_BEST_DEFAULTS = {"score": 0.0, "stage": "", "r_phase": "", "timestamp": ""}
# 对齐原内联 `rg -oP 'r_phase.:.(\S+)\s'`：取 r_phase 键后的第一个非空白 token
_R_PHASE_RE = re.compile(r'r_phase["\s]*:\s*["\']?([^\s"\'",}]+)')


def _extract_r_phase(state_path: str) -> str:
    """从 state 文件原文提取 r_phase（对齐 rg -oP 语义，去掉外部 rg 依赖）。"""
    try:
        text = Path(state_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    m = _R_PHASE_RE.search(text)
    return m.group(1).strip().strip(",").strip('"') if m else ""


def cmd_update_best(state_path: str, score: str, stage: str,
                    r_phase: str, timestamp: str) -> dict:
    """gate_data.best 增量更新：cur > best.score 才写（L2529 语义）。

    r_phase 为空时自动从 state 原文提取（消除 rg 依赖）。
    """
    # 2026-09-25（选项 A）：读-改-写整体持 `state_lock`（条件写：不更优则不落盘）。
    with state_lock(state_path):
        data = gk_state._read_state(state_path)
        if "error" in data:
            return {"ok": False, "error": data["error"]}
        best = data.setdefault("gate_data", {}).setdefault("best", dict(_BEST_DEFAULTS))
        cur = float(score) if score not in ("", None) else 0.0
        rp = r_phase or _extract_r_phase(state_path)
        if cur > 0 and cur > float(best.get("score", 0.0)):
            best.update({"score": cur, "stage": stage, "r_phase": rp, "timestamp": timestamp})
            w = gk_state._write_state(data, state_path)
            return {"ok": w.get("ok", False), "new_best": True,
                    "score": cur, "checksum": w.get("checksum")}
        return {"ok": True, "new_best": False, "score": float(best.get("score", 0.0))}


def cmd_update_gate_data(state_path: str, fragment: str, *,
                         allow_narrow_tasks: bool = False) -> dict:
    """gate_data 顶层键批量 update（L2762 语义），checksum 由 _write_state 重算。

    fragment 约定（2026-09-05 S7 容错化）——两种形态皆接受：
      A) JSON 对象片段（形如 `"a":1,"b":true`，可含前导逗号/空格）——原自裹约定；
      B) 完整 JSON 对象（`{"a":1,"b":true}`）——调用方误带外花括号亦容错。
    解析失败 → ok:false + guidance（exit 2），不静默；非对象 → 同样拒绝。

    ⚠ **闸外边界（§9-7 方案 B，2026-10-07）**：fragment 含 `ecc_findings` 时，本命令经 `update(obj)`
    浅合并**整份替换**该台账，**不经** `gk_finding._guard_precheck`（处置前强制回环闸）。即经本命令
    改 `ecc_findings` 对 finding 标题锚**不做**预检 —— **显式声明的已知边界**，非疏漏。
    """
    # 早失败（错误优先级/提示不变）；真正的读-改-写在下方 `update_state` 的锁内重做。
    fragment = _resolve_at_file(fragment)  # 2026-10-04：`@<file>` 文件通道（消大/中文内联 argv）
    _pre = gk_state._read_state(state_path)
    if "error" in _pre:
        return {"ok": False, "error": _pre["error"]}
    raw = (fragment or "").strip()
    # 2026-09-23（**ECC-66B6FB76CA65 修复**）：原判据 `raw.startswith("[") or raw.endswith("]")`
    # 把**末字符**也当数组信号 ⟹ 合法对象片段而其**值恰为数组**（如 `"subagent_history":[]`）
    # 被误报「疑似数组/标量输入」。数组判据只应看**首字符**（`[` 开头才可能是数组）；
    # 标量/畸形输入由下方 `json.loads` + `isinstance(obj, dict)` 兜底（那才是真判据，本已存在）。
    if raw.startswith("["):
        return {"ok": False,
                "error": "update-gate-data fragment 必须是 JSON 对象（疑似数组输入）",
                "hint": "fragment 应为 JSON 对象片段（形如 \"ci_status\":\"green\"）或完整 {...} 对象"}
    try:
        if raw.startswith("{") and raw.endswith("}"):
            obj = json.loads(raw)  # B) 已带外花括号 → 直接解析
        else:
            obj = json.loads("{" + raw.lstrip(",").strip() + "}")  # A) 片段自裹
        if not isinstance(obj, dict):
            raise ValueError("fragment 必须是 JSON 对象")
    except Exception as e:  # noqa: BLE001 — CLI 边界，fail with guidance
        return {"ok": False,
                "error": f"update-gate-data fragment 解析失败（{type(e).__name__}: {e}）",
                "hint": "fragment 应为 JSON 对象片段（不带外花括号，形如 \"ci_status\":\"green\"）"
                        "或完整 {...} 对象；注意 shell 引号转义（单引号包裹防展开）"}
    # 2026-10-18（6 臂质询 `ECC-458FA591E582`）：**第二写面**不得整份替换载荷键/审计证据键。
    #   原实现只挡 wt_domain / edit_budget / satellite_index ⟹ `update-gate-data` 可整份换掉
    #   `ecc_findings`（绕过 `_guard_precheck`），也可重置 `rejected_edits` / `human_calibration_log`
    #   ⟹ 「host 写面无旁路」是假全称。现与 set-nested/append-list 同口径 fail-loud。
    _bad_payload = sorted(k for k in obj if k in _PAYLOAD_KEYS)
    if _bad_payload:
        return {"ok": False,
                "error": f"update-gate-data 拒绝整份替换载荷键 {_bad_payload} —— 载荷由唯一写入者落库",
                "hint": "载荷键（subagent_history/subagent_last/task_pipeline/ecc_findings）"
                        "禁经任何 state-patch 写面；请走对应唯一写入者（落库块 / gk_task_gate / gk_finding）"}
    # 2026-10-28（窄任务门治理，P4 实测）：`narrow_tasks` 的唯一写通路 = `--narrow-register`
    #   （gk_narrow_route.register：G2 covers 派生 + schema/体积 + 投毒 + 三组语义约束，违规零写盘）。
    #   原实现允许本命令整表替换 ⟹ 实测可把 6 条合格清单换成 2 条 junk，而读侧只数条数
    #   ⟹ 语义门被完全绕过。内部放行面 = register 自身（`allow_narrow_tasks=True`），禁第二写者。
    if _NARROW_TASKS_KEY in obj and not allow_narrow_tasks:
        return {"ok": False,
                "error": "update-gate-data 拒绝整表替换 narrow_tasks —— 唯一写通路是 "
                         "`state-patch --narrow-register <json>`",
                "hint": "窄任务须过 gk_narrow_route.register（派生 G2 covers / schema / 投毒 / "
                        "三组语义约束），违规则 fail-closed 且零写盘"}
    _bad_evidence = sorted(k for k in obj if k in _AUDIT_EVIDENCE_KEYS)
    if _bad_evidence:
        return {"ok": False,
                "error": f"update-gate-data 拒绝写入审计证据键 {_bad_evidence} —— 审计证据由审计侧单一写者落库",
                "hint": "human_calibration_log / audit_*_result / audit_result（遗留别名）"
                        "只由审计器与人类裁决写入；禁经 state-patch 重置"}
    _bad_telemetry = sorted(k for k in obj if k in _SUBJECT_TELEMETRY_KEYS)
    if _bad_telemetry:
        return {"ok": False,
                "error": f"update-gate-data 拒绝写入受审侧遥测键 {_bad_telemetry} —— 受审侧遥测由 gk_advance 落库（visibility-level）",
                "hint": "rejected_edits / entropy_history 由 gk_advance 直写；禁经 state-patch 重置"}
    # §17-2：`wt_domain` 顶层浅合并会整份换掉域桶（丢其它 token 的域 roots）⟹ 单点拒写，
    #   指引专用写通路 `wt-domain`（防活动写面允许集被自助放宽 / 丢更新）。
    if "wt_domain" in obj:
        return {"ok": False,
                "error": "update-gate-data 拒绝整体替换 gate_data.wt_domain",
                "hint": "域桶请用 `state-patch wt-domain <state> bind|unbind <token> <path>`"
                        "（§17-2 域桶单一写通路）"}
    # 2026-10-27（方案 B）：`dispatch_tickets` 整份替换可把 `used_at` 清空（单次票退化为重放票）。
    if _DISPATCH_TICKET_KEYS & set(obj):
        return {"ok": False,
                "error": "update-gate-data 拒绝整体替换 gate_data.dispatch_tickets —— 票据由唯一写入者落库",
                "hint": "签发请用 `state-patch --dispatch-issue <query|@file> [--ttl N]`"
                        "（票据单一签发/消费通路 = gk_dispatch_ticket.py）"}
    # 2026-10-01（提额逃生通道「全局替换拦截」，Option1 条件式）：`gate_data` 顶层是**浅合并**
    #   （`update(obj)`）⟹ fragment 里一个 `edit_budget` 对象把**整份** `edit_budget`（含 `sessions.*`）
    #   换掉 —— 实测并发会话提额即由此把其它会话盒砸空（lost-update；账本 `<state>.budget-log.jsonl`
    #   两条 `source=state_patch` 可查）。故在**同一把锁内**先定点校验：若本次替换会**丢失**任何既有
    #   会话盒（或把 `edit_budget` 降级为非对象）⟹ fail-loud 拒写，指引改用叶子级写 `set-nested`。
    #   既有会话盒全被保留（或本就无 `sessions`）⟹ 照常放行（零回归）。
    #   ⚠ 外层 `state_lock` 与 `update_state` 内层锁**同源可重入** ⟹「读-判-写」对本进程外原子。
    with state_lock(state_path):
        _g = gk_state._read_state(state_path)
        if "error" in _g:
            return {"ok": False, "error": _g["error"]}
        _cur_eb = (_g.get("gate_data") or {}).get("edit_budget")
        if "edit_budget" in obj and isinstance(_cur_eb, dict):
            _cur_sess = _cur_eb.get("sessions")
            if isinstance(_cur_sess, dict) and _cur_sess:
                _new_eb = obj.get("edit_budget")
                _new_sess = _new_eb.get("sessions") if isinstance(_new_eb, dict) else None
                _kept = set(_new_sess.keys()) if isinstance(_new_sess, dict) else set()
                _dropped = sorted(set(_cur_sess.keys()) - _kept)
                if _dropped:
                    return {"ok": False,
                            "error": "update-gate-data 拒绝整体替换 edit_budget：会丢失既有会话盒",
                            "dropped_sessions": _dropped,
                            "hint": "顶层浅合并会整份换掉 edit_budget（含 sessions）；请改用叶子级写 "
                                    "state-patch --set-nested <state> gate_data.edit_budget.<…> <json>"
                                    "（或 --append-list）；确需整份替换，请在 fragment 中显式带全 sessions"}
        # 2026-10-04（§18.2 判据 c4 / 遗漏⑤）：`satellite_index` 同理 —— 顶层浅合并（`update(obj)`）
        #   会把**整份**卫星索引换掉 ⟹ 与前台并发时丢更新（G4 lost-update）。若本次替换会**丢失**
        #   任何既有索引项（`batch_id`）⟹ fail-loud 拒写，指引改用叶子级写
        #   `set-nested gate_data.satellite_index.<batch_id>`。既有序全保留 ⟹ 照常放行（零回归）。
        _cur_si = (_g.get("gate_data") or {}).get("satellite_index")
        if "satellite_index" in obj and isinstance(_cur_si, dict) and _cur_si:
            _new_si = obj.get("satellite_index")
            _kept_si = set(_new_si.keys()) if isinstance(_new_si, dict) else set()
            _dropped_si = sorted(set(_cur_si.keys()) - _kept_si)
            if _dropped_si:
                return {"ok": False,
                        "error": "update-gate-data 拒绝整体替换 satellite_index：会丢失既有索引项",
                        "dropped_batch_ids": _dropped_si,
                        "hint": "顶层浅合并会整份换掉 satellite_index；请改用叶子级写 "
                                "state-patch --set-nested <state> gate_data.satellite_index.<batch_id> <json>"}
            # 2026-10-21（审计署交付门 D1「丢叶面」）：上面只比 **batch 层** ⟹ 同 batch 内
            #   per-arm 叶子整段替换不被拦（`{b1:{A,B}} → {b1:{A}}` 中 b1 仍在 ⟹ 原判据放行）。
            #   卫星索引 append-only ⟹ 既有臂**消失**、被**改内容**、或被降级为非对象，
            #   都是丢叶（片在盘上但读面无从回溯）⟹ fail-loud。
            _leaf_issues = {}
            for _bid, _cur_arms in _cur_si.items():
                if not isinstance(_cur_arms, dict):
                    continue
                _new_arms = _new_si.get(_bid) if isinstance(_new_si, dict) else None
                if not isinstance(_new_arms, dict):
                    _leaf_issues[_bid] = {"dropped": sorted(_cur_arms.keys()), "replaced": []}
                    continue
                _lost = sorted(set(_cur_arms.keys()) - set(_new_arms.keys()))
                _changed = sorted(a for a, v in _cur_arms.items()
                                  if a in _new_arms and _new_arms[a] != v)
                if _lost or _changed:
                    _leaf_issues[_bid] = {"dropped": _lost, "replaced": _changed}
            if _leaf_issues:
                return {"ok": False,
                        "error": "update-gate-data 拒绝整体替换 satellite_index："
                                 "会丢失或改写既有 per-arm 叶子",
                        "dropped_arms": {b: v["dropped"] for b, v in _leaf_issues.items()
                                         if v["dropped"]},
                        "replaced_arms": {b: v["replaced"] for b, v in _leaf_issues.items()
                                          if v["replaced"]},
                        "hint": "per-arm 索引叶子是 append-only；新臂请写 "
                                "state-patch --set-nested <state> "
                                "gate_data.satellite_index.<batch_id>.<arm> <json>"}
        # 2026-10-31（M1 / §9.3）：审计测量键不得经 fragment 整体替换（与 set-top/set-nested 同口径）。
        if "monitor_scores" in obj:
            return {"ok": False,
                    "error": "update-gate-data 拒绝写入 monitor_scores（审计侧测量键）",
                    "hint": "monitor_scores 唯一写者 = monitor / 审计侧；被审方不得自造测量"}
        # §17.2 路③（owner 裁定 2026-10-07）：fragment 若带**节点** `edit_budget.{max,remaining}`
        #   亦夹取（与 set-nested 同口径；fragment 会话盒不夹）。
        _eb_frag = obj.get("edit_budget")
        if isinstance(_eb_frag, dict):
            for _k in _CEILING_NODE_LEAVES:
                if _k in _eb_frag:
                    _eb_frag[_k] = _ceiling_clamp(["gate_data", "edit_budget", _k], _eb_frag[_k])
        # 2026-09-25（选项 A）：`update_state` 在锁内重读-改-写（锁可重入，外层已持有）。
        w = update_state(state_path, lambda d: d.setdefault("gate_data", {}).update(obj) or d)
    if "error" in w:
        return {"ok": False, "error": w["error"]}
    return {"ok": True, "checksum": w["data"].get("_checksum")}


# 顶层键黑名单（`set-top` 不得触碰）：`gate_data` 走 update-gate-data（带 fragment 校验）；
# `worktrees_extra` 走 `apply-worktree --bind/--unbind`（RC1 单一写通路，`ECC-D21AFB35DC1E`）；
# `_` 前缀内部键由 _write_state 单点维护。
_TOP_DENY = {
    "gate_data": "顶层 gate_data 请用 update-gate-data（含 fragment 校验）",
    "worktrees_extra": "worktrees_extra 请用 `apply-worktree --bind/--unbind`"
                       "（RC1 单一写通路；防活动写面允许集被自助放宽）",
    # 2026-10-31（M1 / §9.3 第三写点）：`monitor_scores` = **审计侧测量**（唯一写者 =
    #   `_monitor_finalize` / `_monitor_api` / `gk_monitor_api`）。若被审方可 `set-top` 改写，
    #   就能自造「测量已通过」并抹掉 FAIL 记录 ⟹ 分权不变量（审计只测量、不看被审方脸色）失效。
    "monitor_scores": "monitor_scores 是审计侧测量键（唯一写者 = monitor / 审计侧）；"
                      "被审方不得改写",
}

# host 写面：**载荷键**单点登记（§18.2 / §19.7 host-3，2026-10-04）。
# 语义：`set-nested`/`append-list` = host 唯一写面 ⟹ **不得**命中载荷键写入（大体积臂输出）；
# host 只许写**索引键**（`satellite_index`）。载荷由**唯一写入者**（落库块 / `gk_task_gate`）
# 落盘。此处 = 「名单 + 写点断言」的代码载体：名单本常量、断言在 `_path_denied`。
_PAYLOAD_KEYS = frozenset({"subagent_history", "subagent_last", "task_pipeline", "ecc_findings"})
# 窄任务清单：唯一写通路 = `state-patch --narrow-register`（`gk_narrow_route.register`）。
# 通用写面（update-gate-data / set-nested / append-list）一律拒（2026-10-28 实测 P4 整表替换绕过）。
_NARROW_TASKS_KEY = "narrow_tasks"

# 审计证据键（2026-10-19，6 臂质询 `ECC-0C394FD226F7`）：**审计器 / 人类裁决的自身产物**。
#   被审方若经 state-patch 改写，可重置「篡改可检测」与「推进面可见」。
#   唯一写者 = 审计侧（`gk_audit_*` / `gk_gate_adjudicate`）；被审侧 `gk_advance` 零写点。
_AUDIT_EVIDENCE_KEYS = frozenset({
    "human_calibration_log",
    "audit_state_result", "audit_docs_result", "audit_memory_result",
    "audit_crossr_result",
    # 2026-10-28（6 臂质询 E1，`ECC-` 待登记）：**遗留别名** `audit_result`。
    #   病象：`gk_node_guard.audit_all_recorded` 首条采信 `gd["audit_result"]`
    #   （`gk_node_guard.py:468`），而该键此前**不在任何 deny 集合** ⟹ 被审方可
    #   `state-patch --set-nested gate_data.audit_result …` 自造「审计证据已落盘」，
    #   满足 ECO-VERIFY 前置 / ECO-DOC 出口 / `audit --report` 签发前置（判据2a 旁路）。
    #   纳入本集合 = 与 `audit_*_result` 同口径（唯一写者 = 审计侧），旁路关闭。
    "audit_result",
})

# 受审侧遥测键（同批拆分）：`gk_advance` 的拒绝缓冲 / 熵窗口。被审方写这些键是
#   **正常功能**，故不属「审计证据」；state-patch 仍全拒（防自助改写），但只记
#   visibility-level，不宣称 control 级 —— control 级需判据2b（host 进程分离）。
_SUBJECT_TELEMETRY_KEYS = frozenset({"rejected_edits", "entropy_history"})

# 派发票据键（2026-10-27，方案 B）：`dispatch_tickets[]` 由 `gk_dispatch_ticket.py` **唯一**
#   读写（签发 + 原子消费）。若经 state-patch 整份替换，被审方可把 `used_at` 重置为 null
#   ⟹ 单次票据退化为可重放票。故三写面一并拒绝，指引专用 `--dispatch-issue` 通路。
_DISPATCH_TICKET_KEYS = frozenset({"dispatch_tickets"})

# state-patch 三写面的统一拒绝集（名单单源；禁第二份名清单）。
_STATE_PATCH_DENY_KEYS = (_PAYLOAD_KEYS | _AUDIT_EVIDENCE_KEYS
                          | _SUBJECT_TELEMETRY_KEYS | _DISPATCH_TICKET_KEYS)


def cmd_set_top(state_path: str, key: str, value_json: str) -> dict:
    """顶层键设值（2026-09-23，ECC-089658238011 / ECC-A91DC4562198 修复的**正规通路**）。

    背景：`update-gate-data` 只能写 `gate_data` 内部；顶层键（如 `worktree`）此前**无任何
    CLI 通路** —— 唯一会重写它的是 `cmd_discover`（但那里会归档并清空 `gate_data`）
    ⟹ `apply-worktree` 无法把 worktree 落到被 `pre_tool_check` 强制消费的字段，
    这正是「隔离只产不消」的一半根因（另一半 = 单一全局字段同时充当两个活动面）。

    拒绝面（fail-loud，不静默）：
      · 空 key
      · `_` 前缀内部键（`_checksum` 等由 `_write_state` 单点重算）
      · `gate_data`（禁成为绕过 update-gate-data fragment 校验的后门）
      · value 非合法 JSON（禁静默当字符串写）
    写回走 `gk_state._write_state`（SHA256 checksum 单一事实）。
    """
    k = (key or "").strip()
    if not k:
        return {"ok": False, "error": "set-top key 不能为空",
                "hint": "usage: state-patch --set-top <key> <json-value>"}
    if k.startswith("_"):
        return {"ok": False,
                "error": f"set-top 拒绝内部键 {k!r}（`_` 前缀由 _write_state 维护）"}
    if k in _TOP_DENY:
        return {"ok": False,
                "error": f"set-top 拒绝 {k!r} —— {_TOP_DENY[k]}"}
    _pre = gk_state._read_state(state_path)
    if "error" in _pre:
        return {"ok": False, "error": _pre["error"]}
    try:
        val = json.loads(value_json)
    except Exception as e:  # noqa: BLE001 — CLI 边界，fail with guidance
        return {"ok": False,
                "error": f"set-top value 解析失败（{type(e).__name__}: {e}）",
                "hint": "value 须为合法 JSON 字面量；字符串要带引号（如 '\"/path\"'）"}
    # 2026-09-25（选项 A）：`update_state` 在锁内重读-改-写（`_pre` 只是早失败快路径）。
    w = update_state(state_path, lambda d: d.__setitem__(k, val) or d)
    if "error" in w:
        return {"ok": False, "error": w["error"]}
    # §17-4 A 步②：写顶层 `worktree` 叶 ⟹ 同步 claim 生命周期（fail-soft / sid-gated / 主树排除）。
    #   best-effort：台账同步**绝不**阻断 state 写入（异常一律吞掉）。
    if k == "worktree" and isinstance(val, str) and val.strip():
        try:
            import gk_write_claims as _wc
            _wc.sync_state_worktree(worktree=val, sid=os.environ.get("GK_SESSION_ID", ""),
                                    source="state-patch")
        except Exception:  # noqa: BLE001
            pass
    return {"ok": True, "key": k, "value": val, "checksum": w["data"].get("_checksum")}


def cmd_del_top(state_path: str, key: str) -> dict:
    """顶层键**删除**（2026-10-01，清顶层误写残留的**正规删除通路**）。

    背景：`set-top` 只有设值、无删除 ⟹ 误写出的顶层键（如漏 `gate_data.` 前缀造出的顶层
    `edit_budget`）**无正规通路可清**（§16.4-3 登记为「须归档/清理，且禁再手写 state 顶层」）。
    本命令 = 该键的删除面，与 `set-top` **对称**且**同黑名单**（拒 `_` 前缀 / `gate_data` /
    `worktrees_extra`，防成越权后门）。

    语义：**幂等** —— 键不存在 ⟹ `deleted:false` 且**零写盘**；存在则删并走 `_write_state`
    重算 checksum（SHA256 单一事实）。
    """
    k = (key or "").strip()
    if not k:
        return {"ok": False, "error": "del-top key 不能为空",
                "hint": "usage: state-patch --del-top <key>"}
    if k.startswith("_"):
        return {"ok": False,
                "error": f"del-top 拒绝内部键 {k!r}（`_` 前缀由 _write_state 维护）"}
    if k in _TOP_DENY:
        return {"ok": False, "error": f"del-top 拒绝 {k!r} —— {_TOP_DENY[k]}"}
    _pre = gk_state._read_state(state_path)
    if "error" in _pre:
        return {"ok": False, "error": _pre["error"]}
    with state_lock(state_path):
        data = gk_state._read_state(state_path)
        if "error" in data:
            return {"ok": False, "error": data["error"]}
        if k not in data:
            return {"ok": True, "deleted": False, "key": k}
        del data[k]
        w = gk_state._write_state(data, state_path)
    if not w.get("ok", False):
        return {"ok": False, "error": w.get("error", "state 写入失败")}
    return {"ok": True, "deleted": True, "key": k, "checksum": w.get("checksum")}


def cmd_worktrees_extra(state_path: str, op: str, path: str,
                        dry_run: bool = False) -> dict:
    """`worktrees_extra[]` 的**唯一写通路**（RC1，2026-09-27，`ECC-D21AFB35DC1E` 收口）。

    背景：`set-top` 原只挡 `gate_data` / `_` 前缀 ⟹ `worktrees_extra` 可被**自助写入**
    （绕开 `apply-worktree --bind`）⟹ 活动写面允许集能被自助放宽。本命令 = 该键的正规写入面
    （`set-top worktrees_extra` 已入 `_TOP_DENY`，fail-loud 拒绝）。

    语义：
      · `op` ∈ {bind, unbind}；`path` 归一（`\\`→`/` + 盘符→`/mnt/`；复用 `gk_route_center._as_norm` 单源）
      · **幂等**：bind 已在集内 / unbind 不在集内 ⟹ `changed:false` 且**零写盘**
      · **fail-loud**：空 path / 非法 op ⟹ ok:false（exit 2），不静默
      · `dry_run` ⟹ 只回计划值，**零写盘**
      · 读-改-写整体持 `state_lock`；`gk_state._write_state` 重算 checksum（单一事实）
    """
    try:
        from gk_route_center import _as_norm  # noqa: E402 — 单源归一（RC1）
    except Exception as e:  # noqa: BLE001 — CLI 边界，显式失败
        return {"ok": False,
                "error": f"归一单源不可用（gk_route_center._as_norm）：{type(e).__name__}: {e}"}
    if op not in ("bind", "unbind"):
        return {"ok": False, "error": f"worktrees-extra op 只接受 bind|unbind，得 {op!r}"}
    p = _as_norm(path)
    if not p:
        return {"ok": False, "error": "worktrees-extra 需要非空 path",
                "hint": "usage: worktrees-extra <state> bind|unbind <path> [--dry-run]"}
    with state_lock(state_path):
        data = gk_state._read_state(state_path)
        if "error" in data:
            return {"ok": False, "error": data["error"]}
        cur = data.get("worktrees_extra")
        norm = []
        if isinstance(cur, list):
            for e in cur:
                n = _as_norm(e) if isinstance(e, str) else ""
                if n and n not in norm:
                    norm.append(n)
        new = list(norm)
        if op == "bind":
            if p not in new:
                new.append(p)
        else:
            new = [x for x in new if x != p]
        changed = new != norm
        if not changed:
            return {"ok": True, "changed": False, "op": op, "path": p,
                    "worktrees_extra": norm}
        if dry_run:
            return {"ok": True, "changed": True, "dry_run": True, "op": op,
                    "path": p, "worktrees_extra": new}
        data["worktrees_extra"] = new
        w = gk_state._write_state(data, state_path)
        if not w.get("ok", False):
            return {"ok": False, "error": w.get("error", "state 写入失败")}
        return {"ok": True, "changed": True, "op": op, "path": p,
                "worktrees_extra": new, "checksum": w.get("checksum")}


def cmd_wt_domain(state_path: str, op: str, token: str, path: str,
                  dry_run: bool = False) -> dict:
    """`gate_data.wt_domain[<token>][]` 的**唯一写通路**（§17-2 域化活动写面）。

    背景：§17-2「state 去具体化」——默认 base state 不再承载单个具体 worktree；活动
    worktree 由**域化解析**承载（token ← env `GK_SESSION_ID`，读侧见
    `gk_route_center.active_roots` / `_domain_roots`）。本命令 = 域桶的正规写入面
    （`set-nested` / `append-list` / `update-gate-data` 触达该路径均 fail-loud 拒绝，
    防活动写面允许集被自助放宽，对齐 `cmd_worktrees_extra` 的 RC1 收口先例）。

    语义（对齐 `cmd_worktrees_extra`）：
      · `op` ∈ {bind, unbind}；`token` 经 `gk_finding._DOMAIN_TOKEN_RE` **单源**校验 + 长度 ≤64
        （键文法定形：`^[A-Za-z0-9][A-Za-z0-9._-]*$`）
      · `path` 归一（复用 `gk_route_center._as_norm` 单源）
      · **幂等**：bind 已在集内 / unbind 不在集内 ⟹ `changed:false` 且**零写盘**
      · **fail-loud**：空 / 非法 token / 空 path / 非法 op ⟹ ok:false（exit 2），不静默
      · `dry_run` ⟹ 只回计划值，**零写盘**
      · 读-改-写整体持 `state_lock`；`gk_state._write_state` 重算 checksum（单一事实）
    """
    try:
        from gk_route_center import _as_norm  # noqa: E402 — 单源归一（RC1）
        from gk_finding import _DOMAIN_TOKEN_RE  # noqa: E402 — 键文法单源（§17-2）
    except Exception as e:  # noqa: BLE001 — CLI 边界，显式失败
        return {"ok": False,
                "error": f"单源不可用（_as_norm / _DOMAIN_TOKEN_RE）：{type(e).__name__}: {e}"}
    if op not in ("bind", "unbind"):
        return {"ok": False, "error": f"wt-domain op 只接受 bind|unbind，得 {op!r}"}
    tok = (token or "").strip()
    if not tok or len(tok) > 64 or not _DOMAIN_TOKEN_RE.match(tok):
        return {"ok": False, "error": f"wt-domain token 非法：{token!r}",
                "hint": "token 须匹配 ^[A-Za-z0-9][A-Za-z0-9._-]*$ 且长度 ≤64"
                        "（单源 gk_finding._DOMAIN_TOKEN_RE）"}
    p = _as_norm(path)
    if not p:
        return {"ok": False, "error": "wt-domain 需要非空 path",
                "hint": "usage: wt-domain <state> bind|unbind <token> <path> [--dry-run]"}
    with state_lock(state_path):
        data = gk_state._read_state(state_path)
        if "error" in data:
            return {"ok": False, "error": data["error"]}
        gd = data.get("gate_data")
        if not isinstance(gd, dict):
            gd = {}
            data["gate_data"] = gd
        bucket = gd.get("wt_domain")
        if not isinstance(bucket, dict):
            bucket = {}
        cur = bucket.get(tok)
        norm = []
        if isinstance(cur, list):
            for e in cur:
                n = _as_norm(e) if isinstance(e, str) else ""
                if n and n not in norm:
                    norm.append(n)
        new = list(norm)
        if op == "bind":
            if p not in new:
                new.append(p)
        else:
            new = [x for x in new if x != p]
        changed = new != norm
        if not changed:
            return {"ok": True, "changed": False, "op": op, "token": tok, "path": p,
                    "wt_domain": norm}
        if dry_run:
            return {"ok": True, "changed": True, "dry_run": True, "op": op,
                    "token": tok, "path": p, "wt_domain": new}
        bucket[tok] = new
        gd["wt_domain"] = bucket
        w = gk_state._write_state(data, state_path)
        if not w.get("ok", False):
            return {"ok": False, "error": w.get("error", "state 写入失败")}
        return {"ok": True, "changed": True, "op": op, "token": tok, "path": p,
                "wt_domain": new, "checksum": w.get("checksum")}


# 命名族单源（G2b 收口）：`<state>.<kind>-archive.jsonl` —— 与 `.finding-archive.jsonl` 同族。
_SESSION_ARCHIVE_SUFFIX = ".session-state-archive.jsonl"


def _session_archive_path(state_path: str) -> str:
    return state_path + _SESSION_ARCHIVE_SUFFIX


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cmd_session_state_archive(state_path: str, wt_state_path: str,
                              session: str = "", worktree: str = "",
                              dry_run: bool = False) -> dict:
    """会话副本 state 的**幂等归档**（序④-A v5 / A5 口径：**有 diff 才归档**）。

    背景（组3 审查 G2b 收口）：序④-A「甲」废除 `--session` 的 state 副本，但旧版跑出的
    副本残留（`<worktree>/.gatekeeper.state`）须在迁移步内以**可回溯**方式处置，不得静默删。

    语义（判据见 `test_gk_session_state_landing.py`）：
      · 副本不存在 ⟹ no-op（`present:false`，**零写盘**）。
      · 副本与 base **逐字节相同** ⟹ 仅删（`archived:false`）——无唯一内容可归档。
      · 副本有唯一内容 ⟹ append 一条到旁挂 `<base>.session-state-archive.jsonl`
        （`epoch` / `session` / `worktree` / `state_sha256` / `bytes` / `content_b64`，
        可从 base64 **逐字节复原** ⟹ 「可核对」有明确判据）→ **再删**。
      · `dry_run` ⟹ 只回计划值，**零写盘**（不 append、不 rm）。

    写盘次序 = **旁挂先、删除后**（对齐本仓「归档前置」硬约束）：旁挂写失败则**不删**副本
    （fail-loud 上抛），绝不出现「删了但没归档」。
    """
    wt = Path(wt_state_path)
    if not wt.exists():
        return {"ok": True, "present": False, "archived": False, "removed": False,
                "dry_run": bool(dry_run)}
    try:
        wt_bytes = wt.read_bytes()
    except OSError as e:  # noqa: BLE001 — CLI 边界，显式失败
        return {"ok": False, "error": f"会话副本读取失败: {type(e).__name__}: {e}"}
    base_bytes = b""
    if Path(state_path).exists():
        try:
            base_bytes = Path(state_path).read_bytes()
        except OSError:
            base_bytes = b""
    differs = wt_bytes != base_bytes
    out = {"ok": True, "present": True, "archived": differs, "removed": not dry_run,
           "differs": differs, "bytes": len(wt_bytes), "dry_run": bool(dry_run)}
    if dry_run:
        return out
    if differs:
        rec = {"epoch": _now_iso(), "session": session, "worktree": worktree,
               "state_sha256": hashlib.sha256(wt_bytes).hexdigest(),
               "bytes": len(wt_bytes),
               "content_b64": base64.b64encode(wt_bytes).decode("ascii")}
        try:
            with open(_session_archive_path(state_path), "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError as e:  # noqa: BLE001
            return {"ok": False, "archived": False, "removed": False,
                    "error": f"旁挂归档写失败（副本**未删**，fail-loud）: {type(e).__name__}: {e}"}
    try:
        wt.unlink()
    except OSError as e:  # noqa: BLE001
        return {"ok": False, "archived": differs, "removed": False,
                "error": f"会话副本删除失败: {type(e).__name__}: {e}"}
    return out


def cmd_subset(state_path: str, outer: str, inner: str,
               exclude: str) -> dict:
    """读 state 子集：outer[inner] 过滤 exclude 键（L3109 语义，签名数据剔除）。

    输出 {ok, data}；inner 不存在 → {ok, data: {}}。
    """
    data = gk_state._read_state(state_path)
    if "error" in data:
        return {"ok": False, "error": data["error"]}
    node = (data.get(outer) or {}).get(inner) or {}
    exclude_set = {k for k in exclude.split(",") if k}
    filtered = {k: v for k, v in node.items() if k not in exclude_set}
    return {"ok": True, "data": filtered}


def cmd_append_achievements(state_path: str, unlocked_json: str, config_json: str) -> dict:
    """achievements 追加（L2564/L2646 语义）：unlocked 中未在 existing 的追加 + 写回。
    checksum 由 _write_state 重算（算法与 ach 内联 hashlib sha256[:16] 一致，单一事实）。
    输出 {ok, achievements:[{id,label,msg}]}（调用方拼 ach_output）。"""
    results = []
    # 2026-09-25（选项 A）：读-改-写整体持锁（`results` 依赖锁内读到的 `existing`）。
    with state_lock(state_path):
        data = gk_state._read_state(state_path)
        if "error" in data:
            return {"ok": False, "error": data["error"]}
        existing = data.setdefault("achievements", [])
        config = json.loads(config_json or "{}")
        try:
            unlocked = json.loads(unlocked_json or "[]")
        except ValueError:
            unlocked = []
        for a in unlocked:
            if a not in existing:
                existing.append(a)
                cfg = config.get(a, {})
                results.append({"id": a, "label": cfg.get("label", a), "msg": cfg.get("msg", "")})
        w = gk_state._write_state(data, state_path)
    return {"ok": w.get("ok", False), "achievements": results, "checksum": w.get("checksum")}


# ── 叶子级写 / 只追加（G4：治 state 面 lost-update，2026-09-30）──────────────
# 背景（实测 2026-09-29）：`update-gate-data` 是 `gate_data.update(obj)` **浅合并** ⟹ 调用方
#   若把**锁外读到的整份** `edit_budget` / `overrides` 当片段回写 = **last-writer-wins**
#   （实测：并发会话额度互打到 0；`overrides` 10→3–4 = 审计留痕被抹；`MU_BACKCAST_NEGATIVE`）。
# 修法：本二命令 = **锁内定点**写 ⟹ 调用方**不再**需要「读整份 → 回写整份」。
# 计划：`docs/plans/2026-09-28-git-concurrency-lease-declare-plan.md` §1.3-G4 / §5。
# 臂：`scripts/test_gk_state_patch_nested.py`（arm1a..arm1g）。
_PATH_SEP = "."


def _split_path(path: str) -> list:
    return str(path or "").split(_PATH_SEP)


# 顶层允许键：`set-nested`/`append-list` 首段若**不在**此集 ⟹ 视为漏 `gate_data.` 前缀，自动归位。
# 顶层键的正规写面 = `set-top`（2026-10-04 消除漏前缀流程摩擦，见 `_normalize_gate_path`）。
_TOP_LEVEL_KEYS = {"gate_data", "worktree", "branch"}


def _normalize_gate_path(segs: list) -> list:
    """漏 `gate_data.` 前缀 ⟹ 自动归位到 `gate_data.` 下（消除顶层误写残留）。

    病象（实测 2026-10-03）：`set-nested edit_budget.sessions…`（漏前缀）被写到**顶层** ⟹
    只读残留，须 `--del-top` 补清（edit-budget-dual-track-plan §17.1 附带病象 / §16.4-3）。
    现：首段非顶层允许键（`_TOP_LEVEL_KEYS`）时**自动补** `gate_data.`；显式前缀与顶层键
    （`worktree`/`branch`）语义不变。⚠ deny 判据须在**原始** segs 上先跑（防 `worktrees_extra`
    被前缀后绕过 RC1 单源）。
    """
    if segs and segs[0] not in _TOP_LEVEL_KEYS:
        return ["gate_data"] + segs
    return segs


# §17.2 路③（owner 裁定 2026-10-07）：`state_patch` 抬额路径**夹取** —— 写**节点**
# `gate_data.edit_budget.{max,remaining}` 时 `x_effective = min(候选, EDIT_BUDGET_CEILING)`。
#   · 单源 = `gk_advance.EDIT_BUDGET_CEILING`（与 ①② 同源；本文件**不另立**常量）。
#   · 只夹**节点**：`sessions.*.max` 是各会话盒、非 `max_effective` 面 ⟹ 不在③。
#   · `remaining` 一并夹：节点可花费量由 `max`/`remaining` 共同界定（CLI 消费读 `remaining`，
#     见 gatekeeper-cli.sh 预算段）⟹ 只夹 `max` 会被 `remaining=999` 旁路，等于没夹。
_CEILING_NODE_LEAVES = ("max", "remaining")


def _ceiling_clamp(segs: list, val):
    """节点额度字段的外生夹取（非该面 → 原样返回；非整数形态 → 原样，交消费侧 fail-loud）。"""
    if (len(segs) == 3 and segs[0] == "gate_data" and segs[1] == "edit_budget"
            and segs[2] in _CEILING_NODE_LEAVES):
        if isinstance(val, bool) or not isinstance(val, int):
            return val
        from gk_advance import EDIT_BUDGET_CEILING  # 单源；同族 import，缺失即 fail-loud
        return min(val, EDIT_BUDGET_CEILING)
    return val


def _resolve_at_file(raw: str) -> str:
    """`@<path>` 约定：值/条目/片段从文件读（消除大/中文内联 argv 的稳健通道）。

    病象：`state-patch` 的值与片段只能**内联 argv**，长/中文内容过宿主 `wsl -e bash -lc`
    会在宿主 argv 边界被截断（review-runtime-subplan:1868 已登记）⟹ 与 `monitor --task-file`
    同构的文件通道：argv 只留 **ASCII 路径**。非 `@` 开头或文件不可读 ⟹ **原样返回**，
    由下游 `json.loads` 给 fail-loud（不静默当字符串写入）。
    """
    if raw.startswith("@"):
        try:
            return Path(raw[1:]).read_text(encoding="utf-8")
        except OSError:
            return raw
    return raw


def _path_denied(segs: list) -> str:
    """路径级 fail-loud 判据（空段 / `_` 前缀 / RC1 的 `worktrees_extra` / host-3 载荷键 / §17-2 的 `wt_domain`）。"""
    if not segs or any(not s for s in segs):
        return "路径为空或含空段"
    for s in segs:
        if s.startswith("_"):
            return f"`_` 前缀内部键禁写：{s}"
    if segs[0] == "worktrees_extra":
        return "worktrees_extra 请用 `apply-worktree --bind/--unbind`（RC1 单一写通路）"
    # host-3（§19.7）：载荷键禁经定点写面（set-nested/append-list）写入。含**漏前缀**形态
    # （原始 segs 首段即载荷键 ⟹ 归位后成 `gate_data.<载荷键>`），故两侧都在判据面内。
    _head = segs[1] if (segs[0] == "gate_data" and len(segs) >= 2) else segs[0]
    if _head in _PAYLOAD_KEYS:
        return (f"载荷键 `gate_data.{_head}` 禁经定点写面（set-nested/append-list）写入 —— "
                "host 只许写索引键 `satellite_index`（§19.7 host-3）；载荷由唯一写入者落库")
    if _head in _AUDIT_EVIDENCE_KEYS:
        return (f"审计证据键 `gate_data.{_head}` 禁经定点写面（set-nested/append-list）写入 —— "
                "审计证据由审计侧单一写者落库（防被审方重置人类裁决源 / 审计结果）")
    if _head == _NARROW_TASKS_KEY:
        return ("窄任务清单 `gate_data.narrow_tasks` 的唯一写通路 = "
                "`state-patch --narrow-register <json>`（gk_narrow_route.register："
                "派生 G2 covers / schema / 投毒 / 三组语义约束；违规零写盘）")
    if _head in _SUBJECT_TELEMETRY_KEYS:
        return (f"受审侧遥测键 `gate_data.{_head}` 禁经定点写面（set-nested/append-list）写入 —— "
                "该键由 gk_advance 落库，仅 visibility-level（control 级需判据2b）")
    if _head in _DISPATCH_TICKET_KEYS:
        return (f"派发票据键 `gate_data.{_head}` 禁经定点写面（set-nested/append-list）写入 —— "
                "票据由 gk_dispatch_ticket.py 唯一签发/消费（防重置 used_at 重放）")
    # 2026-10-31（M1 / §9.3）：审计侧测量键，顶层与 `gate_data.monitor_scores` 两种形态
    #   （bash 写顶层 / `gk_monitor_api` 写 gate_data）都不得经被审方写面篡改。
    if _head == "monitor_scores":
        return ("审计测量键 `monitor_scores` 禁经 state-patch 写入 —— "
                "唯一写者 = monitor / 审计侧（M1 分权：被审方不得自造测量）")
    # §17-2：域桶唯一写通路 = `wt-domain`；`set-nested`/`append-list` 触达均拒（防自助放宽活动写面）。
    #   两形态皆拦：漏前缀的 `wt_domain.…` 与显式 `gate_data.wt_domain.…`（deny 跑在归一前）。
    if segs[0] == "wt_domain" or (segs[0] == "gate_data" and len(segs) > 1
                                  and segs[1] == "wt_domain"):
        return "gate_data.wt_domain 请用 `state-patch wt-domain`（§17-2 域桶单一写通路）"
    return ""


def _walk_to_parent(data: dict, segs: list):
    """下探到 `segs[:-1]`（缺失的中间段自动建为 dict）；返回 (父容器, 错误串)。"""
    cur = data
    for s in segs[:-1]:
        nxt = cur.get(s) if isinstance(cur, dict) else None
        if nxt is None:
            nxt = {}
            cur[s] = nxt
        if not isinstance(nxt, dict):
            return None, f"中间段 `{s}` 不是对象，无法下探"
        cur = nxt
    return cur, ""


def cmd_set_nested(state_path: str, path: str, value_json: str) -> dict:
    """锁内只改**定点叶子**（缺失中间段自动建 dict）；**禁**把已存在的 dict/list 整体替换。

    只写面：不触碰兄弟键、不触碰同层的其它会话 ⟹ 从根上消除「锁外读整份 → 回写整份」的丢更新。
    负臂（`test_arm1d`）：空路径 / `_` 前缀 / `worktrees_extra` / 目标已是容器
    （如 `gate_data`、`gate_data.edit_budget.sessions`）⟹ fail-loud。
    """
    segs = _split_path(path)
    deny = _path_denied(segs)
    if deny:
        return {"ok": False, "error": deny, "path": path,
                "hint": "usage: set-nested <state> <a.b.c> <json-value>"}
    segs = _normalize_gate_path(segs)          # 2026-10-04：漏 `gate_data.` 前缀自愈（消顶层残留）
    value_json = _resolve_at_file(value_json)  # 2026-10-04：`@<file>` 文件通道（消大/中文内联 argv）
    try:
        val = json.loads(value_json)
    except Exception as e:  # noqa: BLE001 — CLI 边界
        return {"ok": False, "error": f"value 非合法 JSON（{type(e).__name__}: {e}）",
                "hint": "usage: set-nested <state> <a.b.c> <json-value|@file>"}
    val = _ceiling_clamp(segs, val)            # §17.2 路③：节点额度字段夹取
    with state_lock(state_path):
        data = gk_state._read_state(state_path)
        if "error" in data:
            return {"ok": False, "error": data["error"]}
        parent, err = _walk_to_parent(data, segs)
        if parent is None:
            return {"ok": False, "error": err, "path": ".".join(segs)}
        leaf = segs[-1]
        if isinstance(parent.get(leaf), (dict, list)):
            return {"ok": False, "path": ".".join(segs),
                    "error": f"目标 `{'.'.join(segs)}` 已是容器（dict/list）⟹ 整键替换被禁（G4），"
                             "请写到更深的叶子"}
        parent[leaf] = val
        w = gk_state._write_state(data, state_path)
    if not w.get("ok", False):
        return {"ok": False, "error": w.get("error", "state 写入失败")}
    return {"ok": True, "path": ".".join(segs), "value": val, "checksum": w.get("checksum")}


def cmd_append_list(state_path: str, path: str, item_json: str) -> dict:
    """锁内**只追加**一个元素到定点列表（列表缺失则建）；**禁**整表替换（保审计留痕）。"""
    segs = _split_path(path)
    deny = _path_denied(segs)
    if deny:
        return {"ok": False, "error": deny, "path": path,
                "hint": "usage: append-list <state> <a.b.c> <json-item>"}
    segs = _normalize_gate_path(segs)          # 2026-10-04：漏 `gate_data.` 前缀自愈（消顶层残留）
    item_json = _resolve_at_file(item_json)    # 2026-10-04：`@<file>` 文件通道（消大/中文内联 argv）
    try:
        item = json.loads(item_json)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"item 非合法 JSON（{type(e).__name__}: {e}）",
                "hint": "usage: append-list <state> <a.b.c> <json-item|@file>"}
    with state_lock(state_path):
        data = gk_state._read_state(state_path)
        if "error" in data:
            return {"ok": False, "error": data["error"]}
        parent, err = _walk_to_parent(data, segs)
        if parent is None:
            return {"ok": False, "error": err, "path": ".".join(segs)}
        leaf = segs[-1]
        lst = parent.get(leaf)
        if lst is None:
            lst = []
            parent[leaf] = lst
        if not isinstance(lst, list):
            return {"ok": False, "error": f"目标 `{'.'.join(segs)}` 不是列表，禁止 append",
                    "path": ".".join(segs)}
        lst.append(item)
        n = len(lst)
        w = gk_state._write_state(data, state_path)
    if not w.get("ok", False):
        return {"ok": False, "error": w.get("error", "state 写入失败")}
    return {"ok": True, "path": ".".join(segs), "appended": item, "len": n,
            "checksum": w.get("checksum")}


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.splitlines()[0])
        return 1
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "update-best" and len(rest) >= 5:
            out = cmd_update_best(rest[0], rest[1], rest[2], rest[3], rest[4])
        elif cmd == "update-gate-data" and len(rest) >= 2:
            out = cmd_update_gate_data(rest[0], rest[1])
        elif cmd == "append-achievements" and len(rest) >= 3:
            out = cmd_append_achievements(rest[0], rest[1], rest[2])
            if out.get("ok"):
                # 输出新增成果列表（调用方直接拼 ach_output，零管道内联）
                print(json.dumps(out["achievements"], ensure_ascii=False))
                return 0
        elif cmd == "set-top" and len(rest) >= 3:
            out = cmd_set_top(rest[0], rest[1], rest[2])
        elif cmd == "del-top" and len(rest) >= 2:
            out = cmd_del_top(rest[0], rest[1])
        elif cmd == "set-nested" and len(rest) >= 3:
            out = cmd_set_nested(rest[0], rest[1], rest[2])
        elif cmd == "append-list" and len(rest) >= 3:
            out = cmd_append_list(rest[0], rest[1], rest[2])
        elif cmd == "worktrees-extra" and len(rest) >= 3:
            out = cmd_worktrees_extra(rest[0], rest[1], rest[2],
                                      "--dry-run" in rest[3:])
        elif cmd == "wt-domain" and len(rest) >= 4:
            out = cmd_wt_domain(rest[0], rest[1], rest[2], rest[3],
                                "--dry-run" in rest[4:])
        elif cmd == "session-state-archive" and len(rest) >= 2:
            _opt = rest[2:]
            _sess = ""
            _work = ""
            _i = 0
            while _i < len(_opt):
                if _opt[_i] == "--session" and _i + 1 < len(_opt):
                    _sess = _opt[_i + 1]; _i += 2
                elif _opt[_i] == "--worktree" and _i + 1 < len(_opt):
                    _work = _opt[_i + 1]; _i += 2
                else:
                    _i += 1
            out = cmd_session_state_archive(rest[0], rest[1], _sess, _work,
                                            "--dry-run" in _opt)
        elif cmd == "subset" and len(rest) >= 4:
            out = cmd_subset(rest[0], rest[1], rest[2], rest[3])
            if out.get("ok"):
                # 数据查询直接输出 data（调用方零解析，避免管道内联）
                print(json.dumps(out["data"], ensure_ascii=False, sort_keys=True))
                return 0
        else:
            out = {"ok": False,
                   "error": "usage: update-best <state> <score> <stage> <r_phase> <ts> | "
                            "update-gate-data <state> <json-fragment|@file> | "
                            "set-top <state> <key> <json-value> | "
                            "del-top <state> <key> | "
                            "set-nested <state> <a.b.c> <json-value|@file> | "
                            "append-list <state> <a.b.c> <json-item|@file> | "
                            "worktrees-extra <state> bind|unbind <path> [--dry-run] | "
                            "wt-domain <state> bind|unbind <token> <path> [--dry-run] | "
                   "session-state-archive <state> <worktree-state> [--session S] [--worktree W] [--dry-run] | "
                   "append-achievements <state> <unlocked-json> <config-json> | "
                            "subset <state> <outer> <inner> <exclude:csv>"}
    except Exception as e:  # noqa: BLE001 — CLI 边界，显式失败不裸抛
        out = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("ok", False) else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
