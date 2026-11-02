#!/usr/bin/env python3
"""gk_views.py — 多字段派生 / 格式化投影（B9b，2026-10-27，锚 RED-MIGRATE-INLINE）

逐个显式动词（拒绝泛化派发），每站**逐字对齐**旧内联的输出与失败面：

  conflict-view        {"conflict":true,...}（ensure_ascii=False）
  budget-triple        `remaining max used`（默认 -1/-1/0）
  violations-summary   `violations=N max=Ns pending=Ns threshold=Ns`
  doc-code-summary     列表→长度折叠；旧式 `except: print('{}')` ⟹ 解析失败 rc=0
  audit-summary-view   {"total":total_fields,"matches":matches}
  push-check-summary   四键原值（缺键 KeyError ⟹ rc≠0，调用方 `|| echo '{}'`）
  balance              BAL_RESP → balance_infos[0].total_balance（异常 ⟹ 空行）
  tier-action          tier_recommendation.action（空 ⟹ 空行）
  tier-prediction      `from->to b=budget pays=bool`

B9c（2026-10-27）追加：
  cross-r-context      state.history 末 3 条 → markdown（缺 state ⟹ rc≠0）
  key-meta-tail        key meta JSON ⊕ KL_TAIL → key_rotation_log_tail
  depth-merge          depth_result ⊕ PY_DEPTH → python_depth/_summary

B9d（2026-10-27）追加：
  ci-runs-table        workflow_runs → 90 宽定宽表（空 ⟹ 'No CI runs found'）
  gn-has-results       gitnexus 结果判真（无 processes/definitions ⟹ rc=1）
  gn-query-results     gitnexus 结果 → `[process]` / `path:l-l [name] module` 行
  release-tag          release 响应 tag_name（需 id 存在；旧式全捕获 ⟹ 恒 rc=0）

B9e（2026-10-27）追加：
  station-projection   node_guard announce → station/route/prev/next/gate/checklist/safety
  selfcheck-py-checks  python 检查逐条 json.dumps 逗号拼接（排除 gitnexus）
  audit-link           state 的 audit_state_result 摘要（缺失/异常 ⟹ 'NOT_RUN'）

B9f（2026-10-28）追加：
  gn-context-summary     gitnexus context incoming/outgoing **calls 列表**计数
  gn-context-summary-sym `<sym>: calls=N called_by=M`（N/M 取**字典** len — 旧式怪癖）
  gn-impact-line        `<name> impact=N risk=R`（解析失败 ⟹ 零输出）
  monitor-fail-items    检查片段串 → 仅 FAIL 项逐行 {item,evidence}
  gitnexus-baseline     state.gitnexus 六字段子集（nodes 空/unavailable ⟹ 空行）
  llm-analysis-merge    LLM_ANALYSIS 并入 result（非 JSON ⟹ {text:raw}）
  redteam-summary       redteam findings 摘要（缺键 ⟹ rc≠0）
  depth-result          audit --depth 的 env 驱动组装
  attribution-prompt    `json.dumps(prompt)[:7000]`（先转义再截断）
  attribution-report    logprobs 响应 → 归因报告
  achievements-config   成就默认 ⊕ state 覆盖

B9g（2026-10-28）追加（audit 模板类）：
  audit-summary         audit 主摘要（state 读 + audit_id/audit_type 注入；坏 state ⟹ 空底）
  redteam-findings      state 三域 → findings + severity_counts + ATT&CK 映射
  redteam-report        六段模板报告（stdin=findings；state 仅取 stage）
  audit-report-assemble §1-§3 拼装（SUBAGENT_RESULT/RESULT_DATA env；date 由 shell 注入）

B10a（2026-10-28）追加（写面）：
  monitor-dump          monitor 全文转储文件 ⊕ `_meta`（score 按 python 字面量解析）
  context-cache         state → `.gatekeeper.context.json` 投影（自校验 `_checksum`）
  achievements-check    `_check_achievements`（10 判据 + dict 持久化 / list 归一）
  achievements-record   `cmd_achievements`（配置投影；原样保留 list-append 死分支）

失败面纪律：除 doc-code-summary / balance（旧式在 python 内捕获）外，
解析失败一律**不吞**（rc≠0），保持调用方 `2>/dev/null || echo <fallback>` 语义。
"""
import argparse
import ast
import datetime
import hashlib
import json
import math
import os
import sys


def _read_stdin_json():
    return json.load(sys.stdin)


def cmd_conflict_view(_args) -> int:
    d = _read_stdin_json()
    print(json.dumps({
        "conflict": True,
        "corrected": d.get("corrected", False),
        "candidates": d.get("candidates", []),
        "warning": d.get("warning", ""),
    }, ensure_ascii=False))
    return 0


def cmd_budget_triple(_args) -> int:
    b = _read_stdin_json().get("budget", {})
    print(b.get("remaining", -1), b.get("max", -1), b.get("used", 0))
    return 0


def cmd_violations_summary(_args) -> int:
    d = _read_stdin_json()
    print("violations=%d max=%ss pending=%ss threshold=%ss" % (
        len(d.get("violations", [])), d.get("max_s", 0),
        d.get("pending_s", 0), d.get("threshold_s", 0)))
    return 0


def cmd_doc_code_summary(_args) -> int:
    try:
        d = _read_stdin_json()
        dc = d.get("doc_changes")
        if isinstance(dc, list):
            dc = len(dc)
        cc = d.get("code_changes")
        if isinstance(cc, list):
            cc = len(cc)
        print(json.dumps({
            "doc_changes": dc, "code_changes": cc,
            "unpushed_commits": d.get("unpushed_commits", 0),
            "entropy_rate": d.get("entropy_rate"),
            "push_needed": d.get("push_needed", False),
        }))
    except Exception:  # noqa: BLE001 — 旧式 `except Exception: print('{}')`
        print("{}")
    return 0


def cmd_audit_summary_view(_args) -> int:
    d = _read_stdin_json()
    r = d.get("result", {})
    s = r.get("audit_summary", {})
    print(json.dumps({"total": s.get("total_fields", 0),
                      "matches": s.get("matches", 0)}))
    return 0


def cmd_push_check_summary(_args) -> int:
    d = _read_stdin_json()
    # 旧式 `d['k']` 直接下标 ⟹ 缺键 KeyError（rc≠0），由调用方兜底
    print(json.dumps({
        "doc_changes": d["doc_changes"],
        "code_changes": d["code_changes"],
        "unpushed_commits": d["unpushed_commits"],
        "push_needed": d["push_needed"],
    }))
    return 0


def cmd_balance(_args) -> int:
    try:
        d = json.loads(os.environ.get("BAL_RESP", "") or "{}")
        print((d.get("balance_infos") or [{}])[0].get("total_balance", "") or "")
    except Exception:  # noqa: BLE001 — 旧式 `except Exception: print('')`
        print("")
    return 0


def cmd_tier_action(_args) -> int:
    d = _read_stdin_json()
    print(((d.get("tier_recommendation") or {}).get("action")) or "")
    return 0


def cmd_tier_prediction(_args) -> int:
    d = _read_stdin_json()
    p = (d.get("tier_recommendation") or {}).get("prediction") or {}
    print("%s->%s b=%s pays=%s" % (
        p.get("from_tier"), p.get("to_tier"),
        p.get("last_budget_status"), p.get("predicted_raise_pays")))
    return 0


def cmd_cross_r_context(args) -> int:
    """cmd_reflect：把 state.history 末 3 条渲染成 markdown（旧式失败 `|| echo ""`）。"""
    path = args[0] if args else ""
    with open(path, encoding="utf-8") as f:
        s = json.load(f)
    history = s.get("history", [])
    out = ""
    if history:
        out = "## Cross-R Phase History\n"
        for h in history[-3:]:
            rp = h.get("r_phase", "?")
            b = h.get("best", {})
            rc = h.get("rejection_count", 0)
            mss = h.get("monitor_scores_summary", {})
            out += "- %s: best_score=%s, rejections=%s, scores=%s\n" % (
                rp, b.get("score", "N/A"), rc, mss)
    print(out)
    return 0


def cmd_key_meta_tail(_args) -> int:
    """key status：向 key meta JSON 注入 key_rotation_log_tail（旧式失败 `|| cat meta`）。"""
    d = _read_stdin_json()
    d["key_rotation_log_tail"] = json.loads(os.environ.get("KL_TAIL", "") or "[]")
    print(json.dumps(d, indent=2, ensure_ascii=False))
    return 0


def cmd_depth_merge(_args) -> int:
    """audit --depth：把 gk_audit_depth 结果并入 depth_result（旧式失败 `|| echo "$depth_result"`）。"""
    d = _read_stdin_json()
    pd = json.loads(os.environ.get("PY_DEPTH", "") or "{}")
    d["python_depth"] = pd.get("depth_checks", [])
    d["python_depth_summary"] = pd.get("summary", {})
    print(json.dumps(d))
    return 0


def cmd_ci_runs_table(args) -> int:
    """ci-diagnose list：workflow_runs → 定宽表（count 非数字时末尾 int() 抛错，同旧式）。"""
    count = args[0] if args else "0"
    data = _read_stdin_json()
    runs = data.get("workflow_runs", [])
    if not runs:
        print("No CI runs found")
        return 0
    fmt = "{:<12} {:<8} {:<8} {:<30} {}"
    print(fmt.format("RUN_ID", "STATUS", "RESULT", "BRANCH", "TITLE"))
    print("-" * 90)
    for r in runs:
        sid = str(r["id"])[-8:]
        status = r["status"][:7]
        result = (r.get("conclusion") or "...")[:7]
        branch = r.get("head_branch", "?")[:28]
        title = r.get("display_title", "?")[:40]
        icon = "\u2713" if result == "success" else "\u2717" if result == "failure" else "\u2026"
        print(fmt.format(sid, status, "%s %s" % (icon, result), branch, title))
    if len(runs) >= int(count):
        print("\nUse: ci-diagnose fetch <RUN_ID>  to download logs locally")
    return 0


def cmd_gn_has_results(_args) -> int:
    """search：gitnexus query 结果判真（旧式 assert ⟹ 失败走 rg 退化）。"""
    d = _read_stdin_json()
    return 0 if (d.get("processes") or d.get("definitions")) else 1


def cmd_gn_query_results(_args) -> int:
    """search：gitnexus query → 结构化行（processes 5 / process_symbols 10 / definitions 10）。"""
    d = _read_stdin_json()
    out = []
    for p in d.get("processes", [])[:5]:
        out.append("[process] %s (priority=%.3f)" % (
            p.get("summary", ""), p.get("priority", 0)))
    for s in d.get("process_symbols", [])[:10]:
        out.append("%s:%s-%s [%s] %s" % (
            s.get("filePath", ""), s.get("startLine", 0), s.get("endLine", 0),
            s.get("name", ""), s.get("module", "")))
    for s in d.get("definitions", [])[:10]:
        out.append("%s:%s-%s [%s:%s]" % (
            s.get("filePath", ""), s.get("startLine", 0), s.get("endLine", 0),
            s.get("type", ""), s.get("name", "")))
    print("\n".join(out) if out else "")
    return 0


def cmd_release_tag(_args) -> int:
    """release-check：GitHub release 响应的 tag_name（旧式全捕获 ⟹ 恒 rc=0）。"""
    try:
        d = _read_stdin_json()
        tag = d.get("tag_name", "")
        if d.get("id") and tag:
            print(tag)
    except Exception:  # noqa: BLE001 — 旧式 `except: pass`
        pass
    return 0


def cmd_station_projection(_args) -> int:
    """cmd_advance：node_guard announce 结果 → station 投影（调用处已先经 valid 判过）。"""
    d = _read_stdin_json()
    print(json.dumps({
        "station": d.get("station", ""),
        "route": d.get("route", ""),
        "prev": d.get("prev", ""),
        "next": d.get("next", ""),
        "gate": d.get("gate", ""),
        "checklist": d.get("checklist", []),
        "safety": d.get("safety", []),
    }))
    return 0


def cmd_selfcheck_py_checks(_args) -> int:
    """self-check：python 检查逐条 json.dumps 后逗号拼接（旧式全捕获 rc=0）。"""
    try:
        data = _read_stdin_json()
        # 2026-11-01（提速+去伪红）：不再排除 `gitnexus` —— 判定已改由 python 侧
        # `check_gitnexus`（读索引元数据、0 子进程）产出；bash-native 的 status 探针在本机
        # 会挂起（实测 90s 无进展）且只落 `unavailable` WARN，已删除（防双写 + 防伪红）。
        out = [json.dumps(c) for c in data.get("checks", [])]
        print(",".join(out))
    except Exception:  # noqa: BLE001 — 旧式 `except: pass`
        pass
    return 0


def _registry_display(path: str, gd) -> dict:
    """**显示面双读**（B3b 收口，2026-10-30）：登记 sidecar 存在时返回 `dual_read` 摘要。

    纪律：只**透出**核验态，不改任何判定（判定面 = `gk_audit_registry.dual_read` 的既有消费方）；
    登记缺失 / 依赖不可用 ⟹ 返回 `{}`（退回单读标注 `state(unverified)`，零回归）。
    """
    try:
        from gk_audit_registry import dual_read
        dv = dual_read(path, gd if isinstance(gd, dict) else {})
    except Exception:  # noqa: BLE001 — 显示面：依赖不可用不得影响视图可用性
        return {}
    return {} if dv.get("absent") else dv


def _evidence_source(dv: dict) -> str:
    """显示面证据来源标注（与 `audit-link` / `redteam-findings` 同口径）。"""
    if not dv:
        return "state(unverified)"
    if dv.get("ok"):
        return "state+registry(verified)"
    return "state+registry(mismatch:%s)" % (dv.get("reason") or "?")


def cmd_audit_link(args) -> int:
    """self-check：引用 audit --state 摘要（旧式异常 ⟹ 'NOT_RUN'）。

    E19（2026-10-29）：输出末尾带 `evidence_source=...` —— 显式标注来源 ⟹ 人看到的数
    不会被误当成「已核验证据」。
    2026-10-30（B3b 显示面收口，E25 遗留边界）：登记 sidecar **存在**时做双读并标
    `state+registry(verified|mismatch:…)`；缺失仍标 `state(unverified)`（auto 口径，不拦）。
    """
    path = args[0] if args else ""
    try:
        with open(path, encoding="utf-8") as f:
            s = json.load(f)
        gd = s.get("gate_data", {})
        r = gd.get("audit_state_result", {})
        if not r:
            print("NOT_RUN")
        else:
            m = r.get("audit_summary", {}).get("matches", 0)
            t = r.get("audit_summary", {}).get("total_fields", 0)
            print("audit_state matches=%d/%d evidence_source=%s"
                  % (m, t, _evidence_source(_registry_display(path, gd))))
    except Exception:  # noqa: BLE001 — 旧式 `except: print('NOT_RUN')`
        print("NOT_RUN")
    return 0


def cmd_gn_context_summary(_args) -> int:
    """guard-edit：gitnexus context 的 incoming/outgoing **calls 列表**计数。"""
    try:
        d = _read_stdin_json()
        inc = d.get("incoming", {}).get("calls", [])
        out = d.get("outgoing", {}).get("calls", [])
        print("called_by=%d calls=%d" % (len(inc), len(out)))
    except Exception:  # noqa: BLE001 — 旧式 `except: print('')`
        print("")
    return 0


def cmd_gn_context_summary_sym(args) -> int:
    """monitor：`<sym>: calls=N called_by=M`。

    ⚠ 逐字保留旧式怪癖：N/M 是 incoming/outgoing **字典的 len**（非 calls 列表长）。
    """
    sym = args[0] if args else ""
    try:
        d = _read_stdin_json()
        callers = d.get("incoming", {})
        callees = d.get("outgoing", {})
        print("%s: calls=%d called_by=%d" % (sym, len(callees), len(callers)))
    except Exception:  # noqa: BLE001 — 旧式 `except: print('')`
        print("")
    return 0


def cmd_gn_impact_line(_args) -> int:
    """monitor：`<name> impact=N risk=R`（旧式 except ⟹ 零输出）。"""
    try:
        d = _read_stdin_json()
        print("%s impact=%s risk=%s" % (
            d.get("target", {}).get("name", ""), d.get("impactedCount", 0),
            d.get("risk", "")))
    except Exception:  # noqa: BLE001 — 旧式 `except: pass`
        pass
    return 0


def cmd_monitor_fail_items(_args) -> int:
    """monitor：检查片段串（`{...},{...},`）→ 仅 FAIL 项逐行 {item,evidence}。"""
    raw = sys.stdin.read()
    checks = "[" + raw.rstrip(",") + "]"
    try:
        cl = json.loads(checks)
    except Exception:  # noqa: BLE001 — 旧式 `except: cl=[]`
        cl = []
    for c in cl:
        if c.get("status") == "FAIL":
            print(json.dumps({"item": c.get("item", ""), "evidence": c.get("evidence", "")}))
    return 0


def cmd_gitnexus_baseline(args) -> int:
    """monitor：state 里 gitnexus 六字段子集（nodes 空/unavailable ⟹ 空行）。"""
    path = args[0] if args else ""
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    gn = d.get("gate_data", {}).get("gitnexus", {})
    nodes = gn.get("nodes", "")
    if nodes and nodes != "unavailable":
        print(json.dumps({
            "nodes": gn.get("nodes"), "edges": gn.get("edges"),
            "clusters": gn.get("clusters"), "flows": gn.get("flows"),
            "stage": gn.get("stage"), "timestamp": gn.get("timestamp"),
        }))
    else:
        print("")
    return 0


def cmd_llm_analysis_merge(_args) -> int:
    """audit --crossr：llm_analysis 并入 result（解析失败 ⟹ {text:raw}）。"""
    d = _read_stdin_json()
    raw = os.environ.get("LLM_ANALYSIS", "")
    try:
        d["llm_analysis"] = json.loads(raw)
    except Exception:  # noqa: BLE001 — 旧式 `except Exception`
        d["llm_analysis"] = {"text": raw}
    print(json.dumps(d, ensure_ascii=False))
    return 0


def cmd_redteam_summary(args) -> int:
    """audit --report（redteam）：findings 摘要（缺键 KeyError ⟹ rc≠0）。"""
    audit_id = args[0] if args else ""
    state_path = args[1] if len(args) > 1 else ""
    d = _read_stdin_json()
    with open(state_path, encoding="utf-8") as f:
        stage = json.load(f).get("stage", "")
    print(json.dumps({
        "audit_id": audit_id, "type": "redteam", "current_stage": stage,
        "total": d["total_findings"], "by_severity": d["severity_counts"],
        "mitre": len(d["mitre_mappings"]),
    }))
    return 0


def cmd_depth_result(_args) -> int:
    """audit --depth：env 驱动组装（旧式失败 ⟹ 调用方兜底 error JSON）。"""
    g = lambda k, d="": os.environ.get(k, d)  # noqa: E731 — 与旧式同名同义
    prod = g("GN_PROD")
    print(json.dumps({
        "ok": True,
        "audit_mode": "depth",
        "target": g("GN_TARGET"),
        "gitnexus_context": g("GN_CTX"),
        "detect_changes": g("GN_DET"),
        "production_consumer": prod,
        "dead_code_risk": "low" if prod == "true" else ("high" if prod == "false" else "unknown"),
    }))
    return 0


def cmd_attribution_prompt(_args) -> int:
    """attribution：prompt → `json.dumps(prompt)[:7000]`（**先转义再截断**，与 escape --limit 不同）。"""
    prompt = sys.stdin.read()
    print(json.dumps(prompt)[:7000])
    return 0


def cmd_attribution_report(_args) -> int:
    """attribution：logprobs 响应 → 归因报告（旧式失败 ⟹ 调用方兜底 error JSON）。"""
    resp = _read_stdin_json()
    choice = resp.get("choices", [{}])[0]
    content = choice.get("message", {}).get("content", "")
    logprobs = choice.get("logprobs", {})
    tokens = logprobs.get("content", [])
    attr = []
    for i, t in enumerate(tokens[:30]):
        tops = t.get("top_logprobs", [])
        if tops and tops[0].get("logprob", -100) > -2:
            attr.append({"pos": i, "token": t.get("token", ""),
                         "confidence": round(math.exp(tops[0].get("logprob", -10)), 4)})
    print(json.dumps({"ok": True, "model": resp.get("model", ""),
                      "content": content[:300], "total_tokens": len(tokens),
                      "attr_points": len(attr), "attribution": attr[:15]},
                     indent=2, ensure_ascii=False))
    return 0


def cmd_achievements_config(args) -> int:
    """成就配置：默认（ACH_DEFAULTS env）⊕ state 覆盖（旧式失败 ⟹ 调用方兜底默认）。"""
    path = args[0] if args else ""
    try:
        with open(path, encoding="utf-8") as f:
            s = json.load(f)
    except Exception:  # noqa: BLE001 — 旧式 `except: s={}`
        s = {}
    defaults = json.loads(os.environ.get("ACH_DEFAULTS", "") or "{}")
    user = s.get("achievement_config", {})
    merged = {}
    for aid, d in defaults.items():
        merged[aid] = {**d, **user.get(aid, {})}
    print(json.dumps(merged))
    return 0


def cmd_audit_summary(args) -> int:
    """audit 主摘要：state 底 + audit_id/audit_type 注入（坏 state ⟹ 空底，旧式 `except: s={}`）。"""
    audit_id = args[0] if args else ""
    audit_type = args[1] if len(args) > 1 else ""
    state_path = args[2] if len(args) > 2 else ""
    try:
        with open(state_path, encoding="utf-8") as f:
            s = json.load(f)
    except Exception:  # noqa: BLE001 — 旧式 `except: s={}`
        s = {}
    gd = s.get("gate_data", {})
    h = s.get("history", [])
    cl = s.get("gate_data", {}).get("human_calibration_log", [])
    summary = {
        "audit_id": audit_id,
        "audit_type": audit_type,
        "history_count": len(h),
        "edit_count": gd.get("edit_count", 0),
        "rejected_count": len(gd.get("rejected_edits", [])),
        "calibration_count": len(cl),
        "best_score": gd.get("best", {}).get("score"),
        "current_stage": s.get("stage"),
        "project_type": gd.get("project_type"),
    }
    ms = s.get("monitor_scores", {})
    summary["monitor_scores"] = {k: {"score": v.get("score"), "verdict": v.get("verdict")}
                                 for k, v in ms.items()}
    # 2026-09-02 意图记忆（报告 §3 Audit Data）：当前 TTL 窗口 + history[] 跨 R 归档
    hbl = gd.get("hook_block_log", [])
    hbl = [r for r in hbl if isinstance(r, dict)]
    arch = []
    for _e in h:
        if isinstance(_e, dict) and isinstance(_e.get("hook_block_log"), list):
            arch.extend([r for r in _e["hook_block_log"] if isinstance(r, dict)])
    summary["intent_log"] = {
        "current_intents": len(hbl),
        "current_escalations": sum(1 for r in hbl if r.get("kind") == "escalation"),
        "archived_cross_r_intents": len(arch),
        "archived_escalations": sum(1 for r in arch if r.get("kind") == "escalation"),
        "latest_chains": [{"tool": r.get("tool", ""), "target": str(r.get("target", ""))[:60]}
                          for r in (hbl + arch)[-5:] if r.get("kind") == "escalation"],
    }
    print(json.dumps(summary))
    return 0


def cmd_redteam_findings(args) -> int:
    """redteam findings：state 三域（state_checks / docs_checks / gitnexus 缺口）。"""
    path = args[0] if args else ""
    try:
        with open(path, encoding="utf-8") as f:
            s = json.load(f)
    except Exception:  # noqa: BLE001 — 旧式 `except: s={}`
        s = {}
    gd = s.get("gate_data", {})
    findings = []
    for c in gd.get("audit_state_result", {}).get("state_checks", []):
        key = json.dumps(c, sort_keys=True)
        findings.append({
            "id": "VLN-%03d" % (len(findings) + 1),
            "title": "State check: %s" % c.get("field", "?"),
            "severity": "Medium" if not c.get("match") else "Low",
            "attack_tech": "TA0005",
            "attack_name": "Defense Evasion",
            "evidence_hash": hashlib.sha256(key.encode()).hexdigest()[:16],
            "detail": json.dumps(c),
            "match": c.get("match", False),
        })
    for c in gd.get("audit_docs_result", {}).get("docs_checks", []):
        key = json.dumps(c, sort_keys=True)
        findings.append({
            "id": "VLN-%03d" % (len(findings) + 1),
            "title": "Doc alignment: %s - %s" % (c.get("doc", "?"), c.get("check", "?")),
            "severity": "High" if not c.get("match") else "Info",
            "attack_tech": "TA0007",
            "attack_name": "Discovery",
            "evidence_hash": hashlib.sha256(key.encode()).hexdigest()[:16],
            "detail": json.dumps(c),
            "match": c.get("match", False),
        })
    gn = gd.get("gitnexus", {})
    for key in ["nodes", "edges", "context", "impact", "query"]:
        if gn.get(key, "unavailable") == "unavailable":
            ehash = hashlib.sha256(
                json.dumps({"gitnexus_missing": key}).encode()).hexdigest()[:16]
            findings.append({
                "id": "VLN-%03d" % (len(findings) + 1),
                "title": "GitNexus %s unavailable" % key,
                "severity": "Medium",
                "attack_tech": "TA0007",
                "attack_name": "Discovery",
                "evidence_hash": ehash,
                "detail": "gitnexus.%s is unavailable" % key,
                "match": False,
            })
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    # 2026-10-30（B3b 显示面收口）：登记存在时同口径双读透出（只标注、不改 findings 判定）。
    dv = _registry_display(path, gd) if path else {}
    payload = {
        "findings": findings,
        "severity_counts": sev_counts,
        "total_findings": len(findings),
        # E19（2026-10-29）：本视图只读 state；登记存在时升级为 state+registry 标注。
        "evidence_source": _evidence_source(dv),
        "mitre_mappings": [
            {"id": "TA0001", "name": "Initial Access",
             "desc": "advance phase jump, --force abuse"},
            {"id": "TA0004", "name": "Privilege Escalation",
             "desc": "--force from non-privileged state"},
            {"id": "TA0005", "name": "Defense Evasion",
             "desc": "state tamper, signature replay, type injection"},
            {"id": "TA0007", "name": "Discovery",
             "desc": "gitnexus probe, path traversal"},
        ],
    }
    if dv:
        payload["registry"] = {"ok": dv.get("ok"), "reason": dv.get("reason", ""),
                               "mismatch": dv.get("mismatch") or []}
    print(json.dumps(payload))
    return 0


def cmd_redteam_report(args) -> int:
    """redteam 六段模板报告（stdin=findings；state 仅取 stage，缺文件 ⟹ rc≠0）。"""
    audit_id = args[0] if args else ""
    state_path = args[1] if len(args) > 1 else ""
    d = _read_stdin_json()
    fs = d["findings"]
    chain_steps = []
    for i, f in enumerate(fs[:5]):
        chain_steps.append("Step %d: %s (%s)" % (i + 1, f["title"], f["attack_name"]))
    chain = " -> ".join(chain_steps) if chain_steps else "No attack chain"
    ev_table = "\n".join(["  - %s: `sha256:%s`" % (f["id"], f["evidence_hash"])
                          for f in fs[:10]])
    with open(state_path, encoding="utf-8") as fh:
        stage = json.load(fh).get("stage", "?")
    sev = d["severity_counts"]
    rating = ("Critical" if sev.get("Critical", 0) > 0
              else "High" if sev.get("High", 0) > 0 else "Medium")
    report_lines = []
    report_lines.append("# ECC-REDTEAM: " + audit_id)
    report_lines.append("")
    report_lines.append("## 1. Executive Summary")
    report_lines.append("- Target: " + stage)
    report_lines.append("- Total Findings: %d" % d["total_findings"])
    report_lines.append("- Risk Rating: " + rating)
    report_lines.append("- Summary: Red team assessment of standing plan security controls")
    report_lines.append("")
    report_lines.append("## 2. Scope & Methodology")
    report_lines.append("- Methodology: PTES + MITRE ATT&CK")
    report_lines.append("- Tools: gatekeeper-cli.sh (audit/advance/guard-edit/gitnexus)")
    report_lines.append(
        "- Phases: RED-SCOPE -> RED-SURFACE -> RED-CONSTRAINTS -> RED-EXPLOIT -> RED-POSTEX"
        " -> RED-REPORT -> RED-HINT -> RED-HOOK -> RED-PY -> RED-POISON -> RED-REGISTRY"
        " -> RED-GHOST -> RED-COVERAGE -> RED-DIFF -> RED-INTEGRITY")
    report_lines.append("")
    report_lines.append("## 3. Findings by Severity")
    report_lines.append("| Severity | Count |")
    report_lines.append("|----------|-------|")
    for s in ["Critical", "High", "Medium", "Low", "Info"]:
        report_lines.append("| %s | %s |" % (s, sev.get(s, 0)))
    report_lines.append("")
    report_lines.append("## 4. Detailed Findings")
    for f in fs:
        report_lines.append("")
        report_lines.append("### %s: %s" % (f["id"], f["title"]))
        report_lines.append(
            "**Severity:** %s | **ATT&CK:** %s (%s) | **Evidence Hash:** `sha256:%s`"
            % (f["severity"], f["attack_tech"], f["attack_name"], f["evidence_hash"]))
        report_lines.append("**Description:** %s" % f["detail"][:200])
        report_lines.append("**Impact:** Exploitable gap in standing plan controls")
        report_lines.append("**Remediation:** Address in corresponding RED phase")
    report_lines.append("")
    report_lines.append("## 5. Attack Chain")
    report_lines.append("```")
    report_lines.append(chain)
    report_lines.append("```")
    report_lines.append("")
    report_lines.append("## 6. Appendix")
    report_lines.append("### Evidence Hashes")
    report_lines.append(ev_table)
    report_lines.append("")
    report_lines.append("### MITRE ATT&CK Mappings")
    for m in d["mitre_mappings"]:
        report_lines.append("- %s (%s): %s" % (m["id"], m["name"], m["desc"]))
    report_lines.append("")
    report_lines.append("### Public Key")
    report_lines.append("*Embedded in §9 Integrity section*")
    print("\n".join(report_lines))
    return 0


def cmd_audit_report_assemble(args) -> int:
    """§1-§3 拼装：SUBAGENT_RESULT/RESULT_DATA env + audit_id/audit_type/date 三参。"""
    audit_id = args[0] if args else ""
    audit_type = args[1] if len(args) > 1 else ""
    date = args[2] if len(args) > 2 else ""
    try:
        r = json.loads(os.environ.get("SUBAGENT_RESULT", ""))
        content = r.get("conclusion", "") or str(r)
    except Exception:  # noqa: BLE001 — 旧式 `except Exception: content=原始串`
        content = os.environ.get("SUBAGENT_RESULT", "")
    sections = []
    sections.append("# ECC-AUDIT: " + audit_id)
    sections.append("")
    sections.append("## §1 Header")
    sections.append("- Audit ID: " + audit_id)
    sections.append("- Audit Type: " + audit_type)
    sections.append("- Date: " + date)
    sections.append("- Generator: subagent_runner.py (auditor role)")
    sections.append("")
    sections.append("## §2 Executive Summary")
    sections.append(content[:2000])
    sections.append("")
    sections.append("## §3 Audit Data")
    sections.append("```json")
    sections.append(os.environ.get("RESULT_DATA", ""))
    sections.append("```")
    print("\n".join(sections))
    return 0


def cmd_monitor_dump(args) -> int:
    """monitor 全文转储：stdin 响应 ⊕ `_meta`（score 按 **python 字面量**解析 —— 旧式内插）。"""
    out = args[0] if args else ""
    stage = args[1] if len(args) > 1 else ""
    provider = args[2] if len(args) > 2 else ""
    model = args[3] if len(args) > 3 else ""
    score = ast.literal_eval(args[4] if len(args) > 4 else "0")
    verdict = args[5] if len(args) > 5 else ""
    timestamp = args[6] if len(args) > 6 else ""
    d = _read_stdin_json()
    d["_meta"] = {"stage": stage, "provider": provider, "model": model,
                  "score": score, "verdict": verdict, "timestamp": timestamp}
    with open(out, "w") as f:
        json.dump(d, f, indent=2)
    return 0


def cmd_context_cache(args) -> int:
    """Context Projector：state → `.gatekeeper.context.json`（自校验 `_checksum`）。

    读侧沿用 `gk_state._read_state`（含 checksum 警告）；坏/缺 state ⟹ rc=1（不落盘）。
    """
    from gk_state import _read_state
    state_path = args[0] if args else ""
    out = args[1] if len(args) > 1 else ""
    s = _read_state(state_path)
    if s.get("error"):
        raise SystemExit(1)
    s.pop("_checksum_warning", None)
    gd = s.get("gate_data", {})
    ctx = {
        "stage": s.get("stage", "?"),
        "r_phase": s.get("r_phase", "?"),
        "branch": s.get("branch", "?"),
        "worktree": s.get("worktree", "?"),
        "entropy_rate": gd.get("entropy_rate", "?"),
        "edit_budget": gd.get("edit_budget", {}),
        "previous_rejections": len(gd.get("rejected_edits", [])),
        "updated_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    payload = json.dumps(ctx, sort_keys=True, ensure_ascii=False)
    ctx["_checksum"] = hashlib.sha256(payload.encode()).hexdigest()[:16]
    with open(out, "w") as f:
        json.dump(ctx, f, indent=2, ensure_ascii=False)
    return 0


def cmd_achievements_check(args) -> int:
    """`_check_achievements`：10 项判据 → 打印 unlocked；有解锁则写 state（dict 形态）。

    ⚠ 逐字保留旧式：list 形态先**归一为 dict**（count=1 / granted_at=''），
    已解锁者只递增 `count`。
    """
    path = args[0] if args else ""
    with open(path, encoding="utf-8") as f:
        s = json.load(f)
    history = s.get("history", [])
    gd = s.get("gate_data", {})
    achievements = s.get("achievements", {})
    if isinstance(achievements, list):
        achievements = {k: {"granted_at": "", "count": 1} for k in achievements}
        s["achievements"] = achievements
    unlocked = []
    checks = {
        "eco-first-cycle": lambda: len(history) >= 1,
        "eco-10-cycles": lambda: len(history) >= 10,
        "ecc-impact-done": lambda: any(h.get("r_phase", "").startswith("ECC")
                                       for h in history),
        "redteam-first-find": lambda: len(gd.get("redteam_findings", [])) > 0,
        "redteam-clean": lambda: len(history) >= 1
        and len(gd.get("redteam_findings", [])) == 0,
        "key-rotate-first": lambda: any("rotate" in str(h.get("advance_log", ""))
                                        for h in history),
        "cron-100-runs": lambda: s.get("cron_run_count", 0) >= 100,
        "audit-perfect": lambda: any("13/13" in str(h.get("advance_log", ""))
                                     or "10/10" in str(h.get("advance_log", ""))
                                     for h in history),
        "human-review-first": lambda: len(s.get("human_resolutions", {})) > 0,
        "resolve-first": lambda: len(s.get("human_resolutions", {})) > 0,
    }
    for aid, check in checks.items():
        try:
            if check():
                if aid in achievements:
                    achievements[aid]["count"] = achievements[aid].get("count", 0) + 1
                else:
                    unlocked.append(aid)
        except Exception:  # noqa: BLE001 — 旧式 `except: pass`
            pass
    if unlocked:
        now = datetime.datetime.utcnow().isoformat() + "Z"
        for aid in unlocked:
            achievements[aid] = {"granted_at": now, "count": 1}
        s["achievements"] = achievements
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(s, f, ensure_ascii=False, indent=1)
    print(json.dumps(unlocked))
    return 0


def cmd_achievements_record(args) -> int:
    """`cmd_achievements`：配置 × existing/unlocked → 列表投影。

    ⚠ 逐字保留旧式 list-append 分支（无 `|` 兜底 ⟹ 恒 AttributeError 被 `except: pass`
    吞掉；仅在 state.achievements 为 list 时真正 append）。
    """
    path = args[0] if args else ""
    config = json.loads(os.environ.get("ACH_RAW", "") or "{}")
    unlocked = json.loads(os.environ.get("ACH_UNLOCKED", "") or "[]")
    try:
        with open(path, encoding="utf-8") as f:
            s = json.load(f)
        existing = s.get("achievements", [])
    except Exception:  # noqa: BLE001 — 旧式 `except: existing=[]`
        existing = []
    results = []
    for aid, cfg in config.items():
        results.append({
            "id": aid,
            "label": cfg["label"],
            "msg": cfg["msg"],
            "unlocked": aid in existing or aid in unlocked,
        })
    new_unlocks = [a for a in unlocked if a not in existing]
    if new_unlocks:
        try:
            with open(path, encoding="utf-8") as f:
                s = json.load(f)
            s.setdefault("achievements", [])
            for a in new_unlocks:
                if a not in s["achievements"]:
                    s["achievements"].append(a)
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                json.dump(s, f, ensure_ascii=False, indent=1)
        except Exception:  # noqa: BLE001 — 旧式 `except: pass`
            pass
        for r in results:
            if r["id"] in new_unlocks:
                r["just_unlocked"] = True
    print(json.dumps({"achievements": results, "new_unlocks": new_unlocks},
                     ensure_ascii=False))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="gk_views.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    for verb, fn in (
            ("conflict-view", cmd_conflict_view),
            ("budget-triple", cmd_budget_triple),
            ("violations-summary", cmd_violations_summary),
            ("doc-code-summary", cmd_doc_code_summary),
            ("audit-summary-view", cmd_audit_summary_view),
            ("push-check-summary", cmd_push_check_summary),
            ("balance", cmd_balance),
            ("tier-action", cmd_tier_action),
            ("tier-prediction", cmd_tier_prediction),
            ("key-meta-tail", cmd_key_meta_tail),
            ("depth-merge", cmd_depth_merge),
            ("gn-has-results", cmd_gn_has_results),
            ("gn-query-results", cmd_gn_query_results),
            ("release-tag", cmd_release_tag),
            ("station-projection", cmd_station_projection),
            ("selfcheck-py-checks", cmd_selfcheck_py_checks),
            ("gn-context-summary", cmd_gn_context_summary),
            ("gn-impact-line", cmd_gn_impact_line),
            ("monitor-fail-items", cmd_monitor_fail_items),
            ("llm-analysis-merge", cmd_llm_analysis_merge),
            ("depth-result", cmd_depth_result),
            ("attribution-prompt", cmd_attribution_prompt),
            ("attribution-report", cmd_attribution_report)):
        sub.add_parser(verb).set_defaults(fn=fn)
    # 带位置参数的显式动词（逐一登记，禁泛化派发）
    positional = [
        ("cross-r-context", cmd_cross_r_context, ["state_file"]),
        ("ci-runs-table", cmd_ci_runs_table, ["count"]),
        ("audit-link", cmd_audit_link, ["state_file"]),
        ("gn-context-summary-sym", cmd_gn_context_summary_sym, ["sym"]),
        ("gitnexus-baseline", cmd_gitnexus_baseline, ["state_file"]),
        ("redteam-summary", cmd_redteam_summary, ["audit_id", "state_file"]),
        ("achievements-config", cmd_achievements_config, ["state_file"]),
        ("audit-summary", cmd_audit_summary, ["audit_id", "audit_type", "state_file"]),
        ("redteam-findings", cmd_redteam_findings, ["state_file"]),
        ("redteam-report", cmd_redteam_report, ["audit_id", "state_file"]),
        ("audit-report-assemble", cmd_audit_report_assemble,
         ["audit_id", "audit_type", "date"]),
        ("monitor-dump", cmd_monitor_dump,
         ["out", "stage", "provider", "model", "score", "verdict", "timestamp"]),
        ("context-cache", cmd_context_cache, ["state_file", "out"]),
        ("achievements-check", cmd_achievements_check, ["state_file"]),
        ("achievements-record", cmd_achievements_record, ["state_file"]),
    ]
    for verb, fn, names in positional:
        sp = sub.add_parser(verb)
        for n in names:
            sp.add_argument(n, nargs="?")
        sp.set_defaults(fn=fn)
    ns = p.parse_args(argv)
    names = next((n for v, _f, n in positional if v == ns.cmd), None)
    if names is None:
        return ns.fn(ns)
    return ns.fn([v for v in (getattr(ns, n) for n in names) if v is not None])


if __name__ == "__main__":
    sys.exit(main())
