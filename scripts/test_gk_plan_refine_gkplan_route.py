# -*- coding: utf-8 -*-
"""红先臂：plan-refinement 域路由须同步 export `GK_PLAN_FILE`（环境一致性）。

病灶（2026-11-01 实锤，诊断域 skill.w2a-3v-diag 正规链现场）：
  `cmd_plan_refinement` 域路由块只把 `STATE_FILE` export 为域 state，
  **未同步 `GK_PLAN_FILE`** ⟹ 下游取数中枢 `_conv_state_path` 的域来源仍是
  CLI 启动期默认 `PLAN_FILE`（L565 硬编码 `2026-05-19-...md`，文件常已不存在）⟹
  `resolve_plan` 走 5 层金字塔搜索按 mtime **命中撞库计划**（现场：
  `2026-10-31-standard-t2-t6-roadmap`）⟹ 派生 domain 与已路由的域 state 冲突 ⟹
  `FINDING_DOMAIN_MISMATCH` → `STATE_DOMAIN_MISMATCH` fail-closed，正规链必挂。
  手工复现（显式传正确 GK_PLAN_FILE）恒成功 ⟹ CLI 环境差异型 bug。

判据：域路由成功块（`STATE_FILE="$_pr_dom_state"` → INFO 日志行）内必须
export `GK_PLAN_FILE`（域来源与域落点同源）。
"""
from pathlib import Path

_CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _src() -> str:
    return _CLI.read_text(encoding="utf-8", errors="replace")


def _near(anchor: str, window: int) -> str:
    src = _src()
    i = src.find(anchor)
    assert i >= 0, f"锚点缺失: {anchor!r}"
    return src[i:i + window]


def test_domain_route_exports_gk_plan_file():
    """臂1（红）：域路由成功块内 export GK_PLAN_FILE（域来源=域落点同源）。"""
    seg = _near('STATE_FILE="$_pr_dom_state"', 2000)
    assert "export GK_PLAN_FILE" in seg, (
        "plan-refinement 域路由只改 STATE_FILE、未同步 GK_PLAN_FILE ⟹ "
        "下游 _conv_state_path 用启动期默认 PLAN_FILE 派生域（金字塔搜索撞库计划）"
        "→ FINDING_DOMAIN_MISMATCH fail-closed（正规链必挂）。"
        "须在域路由成功块内 export GK_PLAN_FILE=\"$_pr_plan\"。"
    )


def test_domain_route_exports_gk_plan_file_from_resolved_plan():
    """臂2（红）：export 的值必须来自已解析的真实计划 `_pr_plan`（非 target 裸名）。"""
    seg = _near('STATE_FILE="$_pr_dom_state"', 2000)
    assert 'GK_PLAN_FILE="$_pr_plan"' in seg, (
        "GK_PLAN_FILE 须赋值为 `_pr_plan`（已验证存在的真实计划路径）；"
        "裸名会再次触发 resolve_plan 金字塔搜索撞库。"
    )
