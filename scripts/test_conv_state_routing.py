"""n4-L1 红先臂：收敛取数链「CLI 拿得到计划信息」。

**根因（2026-10-05 实测）**：`_conv_state_path` 给 `resolve-state` 传 `PLAN_FILE=...`，
但 `resolve-state --derive-domain` 读的是 env **`GK_PLAN_FILE`** ⟹ 计划**传不进中枢** ⟹ 域
不可派生 ⟹ 回落 base（跨代混账 = F-REV-63）。实测：`GK_PLAN_FILE=<本议题计划>` 时中枢能正确
派生域 `…skill.2026-10-04-plan-refine-group-dispatch-plan`（缺失则具名 fail-closed
`STATE_DOMAIN_MISSING`），**不设则静默读 base**。

判据（HEAD 必红）：
  1) `_conv_state_path` 须把计划 env（`GK_PLAN_FILE`）交给中枢。
  2) `pre-check convergence` 须有 `--show-state`（打印**解析到的 state + 归因**，终结取数黑箱）。
"""
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _conv_fn_src():
    src = CLI.read_text(encoding="utf-8")
    seg = src[src.find("_conv_state_path() {"):]
    return seg[:seg.find("\n}\n")]


def test_conv_state_path_passes_plan_env_to_center():
    """L1：resolve-state 须收到计划 env ⟹ 域可派生（否则回落 base）。"""
    seg = _conv_fn_src()
    assert "GK_PLAN_FILE" in seg, (
        "`_conv_state_path` 未把计划 env（GK_PLAN_FILE）交给 resolve-state ⟹ "
        "`--derive-domain` 收不到计划 ⟹ 域不可派生 ⟹ 回落 base（F-REV-63）")


def test_conv_state_path_keeps_fail_closed_on_domain_missing():
    """零回归守卫：域缺失仍须 fail-closed（禁静默回 base）。"""
    seg = _conv_fn_src()
    assert "STATE_ROUTE_UNPARSABLE" in seg, "取数链 fail-closed 分支丢失"


def test_precheck_convergence_has_show_state():
    """L1：须能观测「解析到哪个 state」，否则取数是黑箱。"""
    src = CLI.read_text(encoding="utf-8")
    assert "--show-state" in src, "缺 `pre-check convergence --show-state`（取数不可观测）"
