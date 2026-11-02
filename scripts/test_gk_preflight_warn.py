"""
test_gk_preflight_warn.py -- Tests for gk_preflight_warn.py（preflight 软告警判定核心）
================================================================================
覆盖：① 密钥缺失优先（短路，不产余额告警）；② 探测未启用 ⟹ 不产余额告警（开关关闭/provider 无 endpoint）；
③ 探测启用但未取到 ⟹ `balance_unavailable`；④ 低于阈值 ⟹ `balance_low:<v>`（含**边界** `==` 不报）；
⑤ 退出码恒 0 + stdout 为 JSON 数组（fail-soft：任何输入都不抛）。

回归重点（对齐「WARN 不阻断」纪律）：**本模块不得返回任何"阻断"语义**（无 blocked/exit!=0 通道）。
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from gk_preflight_warn import DEFAULT_MIN_CNY, build_warnings  # noqa: E402

_SCRIPT = Path(__file__).parent / "gk_preflight_warn.py"


# ── ① 密钥缺失 ─────────────────────────────────────────────────────────
def test_key_missing_short_circuits():
    """密钥空 ⟹ 只报 api_key_missing（余额探测无意义，短路）。"""
    assert build_warnings(False, True, 999.0, 2.0) == ["api_key_missing"]


def test_key_missing_wins_over_balance():
    """密钥空 + 余额低 ⟹ 仍只报 api_key_missing（不叠加余额告警）。"""
    assert build_warnings(False, True, 0.0, 2.0) == ["api_key_missing"]


# ── ② 探测未启用 ───────────────────────────────────────────────────────
def test_balance_disabled_is_silent():
    """探测未启用（GK_PREFLIGHT_BALANCE=0 / provider 无 endpoint）⟹ 无余额类告警。"""
    assert build_warnings(True, False, None, 2.0) == []
    assert build_warnings(True, False, 0.0, 2.0) == []


# ── ③ 探测失败 ─────────────────────────────────────────────────────────
def test_balance_unavailable_when_unfetched():
    """探测已启用但未取到 ⟹ balance_unavailable（不阻断）。"""
    assert build_warnings(True, True, None, 2.0) == ["balance_unavailable"]


# ── ④ 阈值判定（含边界）─────────────────────────────────────────────────
def test_balance_low_reports_value():
    assert build_warnings(True, True, 1.5, 2.0) == ["balance_low:1.5"]


def test_balance_equal_threshold_not_low():
    """边界：余额 == 阈值 ⟹ **不报**（判据为严格 `<`）。"""
    assert build_warnings(True, True, 2.0, 2.0) == []


def test_balance_above_threshold_is_silent():
    assert build_warnings(True, True, 13.21, 2.0) == []


def test_negative_balance_is_low():
    assert build_warnings(True, True, -1.0, 2.0) == ["balance_low:-1"]


# ── CLI 契约：恒 0 退出 + JSON 数组 ────────────────────────────────────
def _run(*args):
    return subprocess.run([sys.executable, str(_SCRIPT), *args],
                          capture_output=True, text=True, timeout=30)


def test_cli_emits_json_array_and_exit0():
    r = _run("--key-present", "1", "--balance-enabled", "1", "--balance", "13.21")
    assert r.returncode == 0
    assert json.loads(r.stdout) == []
    r2 = _run("--key-present", "0")
    assert r2.returncode == 0
    assert json.loads(r2.stdout) == ["api_key_missing"]


def test_cli_garbage_balance_degrades_to_unavailable():
    """非数值余额（endpoint 变体/脏数据）不得抛 ⟹ 降级 balance_unavailable + exit 0。"""
    r = _run("--key-present", "1", "--balance-enabled", "1", "--balance", "n/a")
    assert r.returncode == 0
    assert json.loads(r.stdout) == ["balance_unavailable"]


def test_default_min_matches_doc():
    """默认阈值与文档口径一致（1 轮质询实测成本下界）。"""
    assert DEFAULT_MIN_CNY == 2.0


# ── 集成：preflight 接线（WARN **不阻断**契约）────────────────────────────
_SKILL_DIR = Path(__file__).parent.parent
_CLI = _SKILL_DIR / "gatekeeper-cli.sh"


def _meta_plan_rel():
    """取一份**仓内相对路径**、含 `<!-- META` 的计划文档（bash 侧 CWD=仓根，故须相对路径）。"""
    for p in sorted((_SKILL_DIR / "docs" / "plans").glob("*.md")):
        if "<!-- META" in p.read_text(encoding="utf-8", errors="replace"):
            return str(p.relative_to(_SKILL_DIR)).replace("\\", "/")
    return None


def _check_only(rel_plan, env_extra):
    """在**同一个 bash 内** export 后再跑 CLI —— 规避 Windows↔WSL 子进程环境不跨越。

    `GK_BUDGET_OVERRIDE=1`（`ECC-1F6514B84334`，2026-09-26 实测）：本调用是**接线探测**
    （验 preflight WARN 契约），**不是一次用户编辑** ⟹ 与生产面 `gk_agent_edit._cli_gate_ok`
    **同一口径**。修前本文件每次 pytest 会扣**真** state 的主 agent 节点额度
    （实测 2 次/验收轮；`plan-refinement` 属写类子命令 ⟹ 经 `_bill_edit` 按次计）。
    """
    exports = "; ".join(f"export {k}={v}" for k, v in env_extra.items())
    # 2026-10-29：本类只验 **balance WARN 契约**（不阻断）；preflight 现已接入 PW-SN 机检
    #   （high/medium ⟹ 阻断），而本臂取的是仓内**存量计划**（含历史 L-ANCHOR 漂移）——
    #   不关该门会让「余额告警语义」被计划历史债遮蔽（测的不是本臂主题）。显式关，留痕于本注释。
    inner = ("export GK_BUDGET_OVERRIDE=1; export GK_PLAN_LINT_GATE=0; "
             "bash gatekeeper-cli.sh plan-refinement " + rel_plan + " --check-only")
    cmd = f"{exports}; {inner}" if exports else inner
    return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                          cwd=str(_SKILL_DIR), timeout=120)


@pytest.mark.skipif(shutil.which("bash") is None or _meta_plan_rel() is None,
                    reason="需 bash + 含 META 的计划文档")
class TestPreflightWiring:
    """用户定案「balance 接入 preflight 作为 WARN 不阻断项」的端到端契约。"""

    def _preflight(self, env_extra):
        r = _check_only(_meta_plan_rel(), env_extra)
        assert r.returncode == 0, r.stderr[-400:]
        d = json.loads(r.stdout)
        assert d["ok"] is True  # ★ WARN 不阻断：无论有无告警，ok 恒 true
        pf = d["preflight"]
        assert isinstance(pf.get("warnings"), list)
        return pf["warnings"]

    def test_warn_never_blocks(self):
        """极端阈值（余额必然 < 阈值）⟹ 出告警但 **ok 仍 true**、退出码 0（不阻断）。"""
        w = self._preflight({"GK_BALANCE_MIN_CNY": "999999"})
        if "api_key_missing" in w:
            # 无密钥环境：探测按设计关闭 ⟹ 不得出现余额类告警
            assert not any(x.startswith("balance_") for x in w)
        else:
            # 有密钥 ⟹ 探测启用 ⟹ 必出余额告警（余额必然 < 999999 或查询失败）
            assert any(x.startswith("balance_low:") or x == "balance_unavailable" for x in w), w

    def test_balance_switch_off_silences_balance(self):
        """`GK_PREFLIGHT_BALANCE=0` ⟹ 无任何余额类告警（开关生效），且仍不阻断。"""
        w = self._preflight({"GK_PREFLIGHT_BALANCE": "0", "GK_BALANCE_MIN_CNY": "999999"})
        assert not any(x.startswith("balance_") for x in w), w
