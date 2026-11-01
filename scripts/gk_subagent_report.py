#!/usr/bin/env python3
"""Subagent ECC → 可读报告（Markdown）。

2026-08-15: 计划质询 subagent 输出黑盒 → 生成供人类直接评分的结构化报告。
2026-10-01（`ECC-1951EFAD9CDF`）：原实现**恒**套「计划质询报告」模板 ⟹ 非质询臂
  （default / 红队 / 审计…）得到**全 "—" 的 F1-F7 与 7 维空表 + 撒谎标题**；且全篇
  **不呈现机检面**（verification / evidence_anchor / gx_status）⟹ F-REV-74/81/97 的
  机检结论对人不可见。现按 **ECC 形态**（`ecc_form()`，**非** `mode` 单源）分流：
    · plan-refinement ⟹ 双盲质询报告（F1-F7 + 7 维 + 挑战/砍留）
    · default        ⟹ 通用 ECC 报告（结论 / 证据 / 发现 / 下一步）
  两者**都**附「机检面」小节。

Usage: cat ecc.json | python3 gk_subagent_report.py > report.md
"""
import json
import re
import sys
from datetime import datetime

F1_LABELS = {
    "F1": "范围", "F2": "依赖", "F3": "验证", "F4": "设施",
    "F5": "假设", "F6": "回退", "F7": "框架",
}
DIM_LABELS = {
    "scope": "范围控制", "evidence": "证据链", "assumptions": "假设消解率",
    "recovery": "回退", "references": "参考完整性", "bias": "偏差检测", "cost": "成本",
}


# 「冒号 + 数字」= 行号锚的分隔符；盘符冒号后跟 `/`（或 `\`）⟹ 不命中
_DIGIT_COLON = re.compile(r":(?=[0-9])")


def normalize_evidence(evidence) -> list:
    """字符串型 evidence → `{file, lines, status:'confirmed'}`（`ECC-74B7327230D8`，2026-09-27）。

    缺陷（`gatekeeper-cli.sh` 落库块原式 `e.split(':')[0]/[1]`）：字符串型 evidence 若为 Windows
    盘符路径（`C:/Users/…/x.py:13 —— desc`），**盘符冒号被当分隔符** ⟹ `file='C'`、`lines` 塞入
    全路径（行号/描述错位）；渲染侧 `file + ':' + lines` 又拼回原样 ⟹ 症状被掩盖，但 `file`
    已不可单独消费（按文件聚合/链接失效），F-REV-97 的锚检也因复合 `file:lines` 而放过。

    修法：按**首个「冒号 + 数字」**切分 —— 盘符 `C:` 后跟 `/` 非数字 ⟹ 不误切；`x.py:13` /
    `x.py:13,14` / `x.py:13 —— desc` 均正确；无 `:数字` 者整体作 `file`、`lines` 空。

    逐项判定：字符串走归一，**非字符串原样保留**（不吞不抛 —— 混合形态在原式下会在 `e.split`
    处 AttributeError，进而被落库块的 `2>/dev/null || true` 静默吞掉，致整条 history 不写）。
    """
    out = []
    for e in (evidence or []):
        if isinstance(e, str):
            m = _DIGIT_COLON.search(e)
            out.append({
                "file": e[:m.start()] if m else e,
                "lines": e[m.end():] if m else "",
                "status": "confirmed",
            })
        else:
            out.append(e)
    return out


def _norm_verdict(v) -> str:
    """Agent 裁决值归一化显示：ok→PASS, suspect→WARN, fail→FAIL，其余原样。"""
    if not isinstance(v, str):
        return str(v)
    m = {"ok": "PASS", "pass": "PASS", "suspect": "WARN", "warn": "WARN", "fail": "FAIL"}
    return m.get(v.strip().lower(), v)


# ─── ECC 形态判定（报告分流的单源，禁拿 `mode` 当依据）───────────────────────
# `EccOutput.mode` 恒为 "subagent"（runner 未把真实 mode 落进去）⟹ 拿它分流必错。
# 判据 = **SCR 专有面**：raw payload 含 f1_f7 / constraint_matrix / verification_checklist /
# coupled_constraints / plan_type / determinacy，或 verdicts / seven_dim_score 非空。
_PLAN_PAYLOAD_KEYS = ("f1_f7", "constraint_matrix", "verification_checklist",
                      "coupled_constraints", "plan_type", "determinacy")


def ecc_form(d: dict) -> str:
    """ECC 形态：'plan-refinement' | 'default'。"""
    ap = d.get("agent_payload")
    ap = ap if isinstance(ap, dict) else {}
    if (any(k in ap for k in _PLAN_PAYLOAD_KEYS)
            or d.get("verdicts") or d.get("seven_dim_score")):
        return "plan-refinement"
    # 2026-10-04（极限压力修复）：第三路信号 —— 上游 `_extract_llm_json` 对畸形外层 JSON
    #   fail-closed 为 {} 后，SCR 面可能**只存活在 `conclusion` 文本里**（agent_payload 退化、
    #   verdicts/score 恒空）。两形态都补：① conclusion 是**合法** JSON 对象（取键判）；② 是
    #   **畸形** JSON（如缺逗号 —— 实测 sub-1791075048-21915-31873）⟹ 退化为「键面嗅探」。
    c = d.get("conclusion")
    if isinstance(c, str) and c:
        if c.lstrip().startswith("{"):
            try:
                obj = json.loads(c)
            except Exception:  # noqa: BLE001 — 非 JSON / 畸形 ⟹ 落到键面嗅探
                obj = None
            if isinstance(obj, dict) and any(k in obj for k in _PLAN_PAYLOAD_KEYS):
                return "plan-refinement"
        if any(re.search(r'"' + re.escape(k) + r'"\s*:', c) for k in _PLAN_PAYLOAD_KEYS):
            return "plan-refinement"
    return "default"


def _meta_block(d: dict) -> list:
    ts = d.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    budget = d.get("budget_status", "ok")
    tb = d.get("token_budget") or 0
    tt = d.get("total_tokens") or 0
    ib = d.get("item_budget") or 0
    ti = d.get("total_items") or 0
    L = ["| 字段 | 值 |", "|:--|:--|"]
    L.append(f"| subagent_id | `{d.get('subagent_id','')}` |")
    L.append(f"| 时间 | {ts} |")
    L.append(f"| 模式 | {d.get('mode','')} |")
    L.append(f"| 置信度 | {d.get('confidence','')} |")
    L.append(f"| 任务 | {(d.get('task','') or '')[:300]} |")
    if tb or tt:
        L.append(f"| 预算消耗 | {tt}/{tb} tokens · {ti}/{ib} items · `{budget}` |")
    L.append("")
    return L


def _machine_check_section(d: dict) -> list:
    """机检面（F-REV-74/81/97 结论的**人读面**）：缺字段显式标 unknown，不伪绿。"""
    def _sub(key, sub):
        x = d.get(key)
        return x.get(sub, "") if isinstance(x, dict) else ""

    ea = d.get("evidence_anchor") if isinstance(d.get("evidence_anchor"), dict) else {}
    L = ["## 机检面（runner 侧确定性写入）\n"]
    L.append("| 字段 | 值 |")
    L.append("|:--|:--|")
    L.append(f"| `verification` | {_sub('verification', 'status') or 'unknown'} |")
    L.append(f"| `evidence_anchor` | {ea.get('status') or 'unknown'}"
             f"（unanchored {len(ea.get('unanchored') or [])}） |")
    L.append(f"| `gx_status` | {_sub('gx_status', 'verdict') or 'unknown'} |")
    L.append(f"| `token_usage.rounds` | {_sub('token_usage', 'rounds')} |")
    L.append(f"| `guardrail` | {d.get('guardrail', '')} |")
    L.append("")
    return L


def _render_generic(d: dict) -> str:
    """通用 ECC 报告（default 形态；**不**出质询专表）。"""
    L = ["# Subagent ECC 报告（default 形态）\n"]
    L += _meta_block(d)

    L.append("## 一、结论\n")
    L.append((d.get("conclusion", "") or "—").strip())
    L.append("")

    ev = d.get("evidence") or []
    if ev:
        L.append("## 二、证据\n")
        for e in ev:
            if isinstance(e, dict):
                L.append(f"- `{e.get('file','')}:{e.get('lines','')}` ({e.get('status','')})")
            else:
                L.append(f"- {e}")
        L.append("")

    f = d.get("findings") or {}
    if isinstance(f, dict) and (f.get("worked") or f.get("failed") or f.get("not_tried")):
        L.append("## 三、发现\n")
        for t in ("worked", "failed", "not_tried"):
            for x in f.get(t, [])[:5]:
                L.append(f"- [{t}] {x}")
        L.append("")

    ns = d.get("next_steps") or []
    if ns:
        L.append("## 四、下一步\n")
        for x in ns[:5]:
            L.append(f"- {x}")
        L.append("")

    L += _machine_check_section(d)

    L.append("## 人类评分区\n")
    L.append("```\n")
    L.append('adjudicate --score 0.90 --decision "<仲裁结论>" --impact references/ecc-impact-*.md')
    L.append("\n```\n")
    return "\n".join(L)


def _render_plan(d: dict) -> str:
    """计划质询报告（plan-refinement 形态；双盲评分表）。"""
    L = ["# Subagent 计划质询报告（双盲评分表）\n"]
    L += _meta_block(d)

    L.append("## 一、Agent 结论（供主 agent 勘误 / 人类参考，非评分锚）\n")
    L.append((d.get("conclusion", "") or "—").strip())
    L.append("")

    verdicts = d.get("verdicts")
    verdicts = verdicts if isinstance(verdicts, dict) else {}   # 2026-10-04：类型守卫（非 dict 不崩）
    L.append("## 二、F1-F7 裁决（左=Agent 盲评 / 右=人类评分，双盲两方）\n")
    L.append("| 约束 | 检查要点 | Agent 裁决 | 人类评分（待填） |")
    L.append("|:--|:--|:--|:--|")
    for k in [f"F{i}" for i in range(1, 8)]:
        ag = _norm_verdict(verdicts.get(k, "—"))
        L.append(f"| {k} {F1_LABELS.get(k,'')} | — | {ag} | ☐ PASS ☐ WARN ☐ FAIL |")
    L.append("")

    seven = d.get("seven_dim_score") or {}
    L.append("## 三、Agent 7维评分（1-100，人类勘误栏）\n")
    L.append("| 维度 | Agent 分 | 人类勘误 |")
    L.append("|:--|:--|:--|")
    for k, label in DIM_LABELS.items():
        sc = seven.get(k, "—") if isinstance(seven, dict) else "—"
        L.append(f"| {k} {label} | {sc} |  |")
    L.append("")

    _ch = d.get("challenges")
    if isinstance(_ch, list) and _ch:
        L.append("## 四、Agent 挑战\n")
        for c in _ch:
            L.append(f"- {c}")
        L.append("")
    _sl = d.get("slashed")
    _kp = d.get("kept")
    _sl = _sl if isinstance(_sl, list) else []   # 2026-10-04：类型守卫
    _kp = _kp if isinstance(_kp, list) else []
    if _sl or _kp:
        L.append("## 五、砍掉 / 保留\n")
        L.append("**建议砍掉**: " + ("；".join(_sl) or "—"))
        L.append("")
        L.append("**必须保留**: " + ("；".join(_kp) or "—"))
        L.append("")

    ev = d.get("evidence") or []
    if ev:
        L.append("## 六、证据\n")
        for e in ev:
            if isinstance(e, dict):
                L.append(f"- `{e.get('file','')}:{e.get('lines','')}` ({e.get('status','')})")
            else:
                L.append(f"- {e}")
        L.append("")

    f = d.get("findings") or {}
    if isinstance(f, dict) and (f.get("worked") or f.get("failed") or f.get("not_tried")):
        L.append("## 七、发现\n")
        for t in ("worked", "failed", "not_tried"):
            for x in f.get(t, [])[:5]:
                L.append(f"- [{t}] {x}")
        L.append("")

    L += _machine_check_section(d)

    L.append("## 八、人类评分区（双盲第二方 — 填后 adjudicate 密封）\n")
    L.append("```\n")
    L.append("adjudicate --verdicts '{\"F1\":\"PASS\",\"F2\":\"WARN\",\"F3\":\"PASS\",\"F4\":\"PASS\",\"F5\":\"WARN\",\"F6\":\"PASS\",\"F7\":\"PASS\"}' \\\n")
    L.append("  --score 0.90 --decision \"<仲裁结论>\" --impact references/ecc-impact-*.md\n")
    L.append("```\n")
    return "\n".join(L)


def render(d: dict) -> str:
    """按 ECC 形态分流（plan-refinement / default）。"""
    return _render_plan(d) if ecc_form(d) == "plan-refinement" else _render_generic(d)


if __name__ == "__main__":
    try:
        data = json.load(sys.stdin)
    except Exception as e:
        print(f"# 报告生成失败: {e}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(data, dict):
        print(f"# 报告生成失败: ECC 非对象形态（{type(data).__name__}）", file=sys.stderr)
        sys.exit(1)
    print(render(data))
