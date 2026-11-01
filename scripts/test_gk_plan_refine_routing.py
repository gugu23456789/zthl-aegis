"""
test_gk_plan_refine_routing.py — 红先臂：`plan-refinement <plan>` 的 **state 路由**
================================================================================
finding：`ECC-0DBB2CBB5461`（`plan-refinement-ignores-plan-state-domain`）

病象（2026-10-17 实测）：`cmd_plan_refinement` 全程用 CLI **启动期** `$STATE_FILE`
（未设 env `GK_PLAN_FILE` 时恒 base）。结果：
  · 窄任务登记在**域 state**（审计署域 `narrow_tasks` n=6）⟹ 派发仍读 base（n=0）
    ⟹ fail-closed `narrow_tasks_insufficient`；
  · 批次记录写进 base ⟹ **跨计划污染**；
  · 而 `GK_PLAN_FILE` 路由本身是通的（`resolve-state --derive-domain` 已能解析域 state）
    ⟹ 缺口只在「**计划参数未参与路由**」。

修法：`cmd_plan_refinement` 在参数解析后、**所有下游分支之前**，按 `<plan>` 的
`META.state_domain` 解析域 state（单源 = `gk_route_center.meta_state_domain` +
`gk_finding.resolve_domain_state`），命中即把 `STATE_FILE` 切到域 state；
沿用既有 kill switch `GK_STATE_DOMAIN_ROUTE=0`（**不新造开关**）。

红先性质：两臂在 HEAD 必红 —— ① 静态：路由块不存在；② 行为：`--list-pending`
读 base（空队列），域内 pending 记录不可见。
"""
import json
import os
import subprocess
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _src() -> str:
    return CLI.read_text(encoding="utf-8")


def _cmd_plan_refinement_seg() -> str:
    """`cmd_plan_refinement` 整函数体（切到列 0 的 `}`，与函数长度解耦）。"""
    s = _src()
    i = s.find("cmd_plan_refinement()")
    assert i >= 0, "未找到 cmd_plan_refinement 定义"
    seg = s[i:]
    j = seg.find("\n}\n")
    return seg[:j] if j >= 0 else seg


# ── ① 形态臂：计划参数参与路由 ────────────────────────────────────────────────
def test_plan_refinement_routes_state_by_plan_domain():
    """`cmd_plan_refinement` 须按计划 META.state_domain 解析域 state（单源，不新造开关）。"""
    seg = _cmd_plan_refinement_seg()
    assert "meta_state_domain" in seg, "未见按计划读 META.state_domain（路由源仍只有启动期 $STATE_FILE）"
    assert "resolve_domain_state" in seg, "未见域 state 解析（应复用 gk_finding.resolve_domain_state 单源）"
    assert "GK_STATE_DOMAIN_ROUTE" in seg, "未见既有域 kill switch（禁新造开关）"


# ── ② 行为臂：`--list-pending` 读域 state ────────────────────────────────────
def test_plan_refinement_list_pending_reads_domain_state(tmp_path):
    """计划声明域 + 域 state 存在 ⟹ `--list-pending` 必须读到**域**队列。"""
    base = tmp_path / ".gatekeeper.state"
    base.write_text(json.dumps({"gate_data": {"task_pipeline": []}}), encoding="utf-8")
    dom = tmp_path / ".gatekeeper.state.test.plan-x"
    dom.write_text(json.dumps({"gate_data": {"task_pipeline": [
        {"id": "DOMAIN-ONLY-TASK", "status": "pending", "target": "x.md"}]}}),
        encoding="utf-8")
    plan = tmp_path / "p.md"
    plan.write_text(
        "<!-- META\nphases: T\ntarget_repo: skill\nproject_type: standing\n"
        "state_domain: test.plan-x\n-->\n\n# p\n", encoding="utf-8")
    env = dict(os.environ, STATE_FILE=str(base), STATE_FILE_EXPLICIT="1")
    env.pop("GK_STATE_DOMAIN_ROUTE", None)
    r = subprocess.run(
        ["bash", str(CLI), "plan-refinement", str(plan), "--list-pending"],
        cwd=str(CLI.parent), capture_output=True, text=True, env=env, timeout=120)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    lines = [ln for ln in r.stdout.strip().splitlines() if ln.startswith("{")]
    assert lines, f"未回 JSON：{r.stdout[:400]}{r.stderr[:400]}"
    d = json.loads(lines[-1])
    assert any(x.get("id") == "DOMAIN-ONLY-TASK" for x in (d.get("all") or [])), (
        f"`--list-pending` 未读域 state（跨计划污染未修）：{d}")
