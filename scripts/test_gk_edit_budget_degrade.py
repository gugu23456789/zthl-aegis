#!/usr/bin/env python3
"""R2-a 优雅降级早警回归（REV-6 §15.3；owner 2026-10-01 裁定 **A1 + P4-1 + C1**）。

来源：`docs/plans/2026-09-18-edit-budget-dual-track-plan.md` §15（REV-6 设计）+ §13.4（单列）
+ §15.7b/c（两轮 8 臂质询吸收，P1–P19）。

**病象（§15.1 实测）**：预算耗尽**唯一动作 = fail-closed 硬阻断**，只有 `remaining ≤ 0` 一个断点
⟹ 从「完全放行」直接跳到「完全阻断」= **cost cliff**（五元组 D 分量退化为单值）。

**R2-a 落刀形态（本文件钉住）**：
  ① 触发 `0 < remaining ≤ θ`；θ 分母 = **本会话首见额度** `sessions.<sid>.max`（E 裁定；
     无会话条目/无会话键回落节点 `max`）；`max ≤ 0`（未配置预算）⟹ 不降级；
  ② 动作 = stdout 早警一行（复用 **`GATEKEEPER-WARN`** 族，见 P5）+ 旁挂账本一笔
     （`source=degrade` ⟹ C1 `kind=degrade`，**不污染**提额频次/熵/`from_max` 链）；
  ③ **rc 不变**（早警不得被 hook Gate 4 当 BLOCK —— 否则比不降级更硬，与 R2 目的相反）；
  ④ 底线不放松：`remaining ≤ 0` 的 BLOCK **一字不改**；
  ⑤ **降级不得免计费**（θ 不是免费额度）；
  ⑥ kill switch（**P4-1 单开关**）：`GK_DEGRADE=0` ⟹ 逐字回到今日；省略 ⟹ θ = `max(1, ceil(max×0.2))`；
     `=<n>`（n≥1）⟹ θ = n。
     ⚠ 已知边界（如实登记）：`=1` 口径 = **默认公式**（非 θ=1）⟹ θ=1 **不可显式表达**。

⚠ hysteresis（`θ_hi` 复位）**本批不做**：`remaining` 在节点内**单调递减** ⟹ 无阈值抖动可言；
  它属 R2-b（收缩面）前置，随二期另裁（免引 `gate_data` 载体写入）。

harness 复用：沙箱 / 预算读取取自 `test_gk_edit_budget_metering.py`（同子系统、同沙箱契约，
**避免两份 harness 漂移**）。
"""
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from test_gk_edit_budget_metering import _budget, _mk_sandbox, _wsl  # noqa: E402

LEDGER_SUFFIX = ".budget-log.jsonl"
_WARN_FAMILY = "GATEKEEPER-WARN"


def _ledger(sb: Path) -> list:
    """读旁挂账本（append-only）全部记录；缺文件 ⟹ `[]`。"""
    p = sb / (".gatekeeper.state" + LEDGER_SUFFIX)
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def _consume(sb: Path, env_prefix: str = ""):
    """走一次 `pre-tool-check edit <file>`（= hook Gate 4 的真实消费点）。"""
    w = _wsl(sb)
    return subprocess.run(
        ["bash", "-lc",
         '%scd "%s" && bash gatekeeper-cli.sh pre-tool-check edit "%s/note.md"' % (env_prefix, w, w)],
        capture_output=True, text=True, timeout=120)


def _mk(p: Path) -> Path:
    """`_mk_sandbox` 要求父目录已存在（其内部 `mkdir()` 不带 `parents`）。"""
    p.mkdir()
    return p


def _degrade_lines(out: str) -> list:
    """早警行（`GATEKEEPER-WARN` 族 + `degraded` 标记）。"""
    return [l for l in out.splitlines() if _WARN_FAMILY in l and "degraded" in l]


def _degrade_rows(sb: Path) -> list:
    return [r for r in _ledger(sb) if r.get("kind") == "degrade" or "degrade" in str(r.get("source"))]


# ── 臂① 正臂（**红先**）：到达 θ ⟹ 早警 + 留痕，且 rc 不变 ─────────────────────
def test_arm1_early_warning_fires_at_theta(tmp_path):
    """`max=10 / remaining=2`（=θ=ceil(10/5)）⟹ rc=0、stdout 早警、账本留 `degrade` 一笔。

    HEAD 无早警实现 ⟹ 本臂必红（§15.5 正臂）。
    """
    sb = _mk_sandbox(tmp_path, {"max": 10, "used": 8, "remaining": 2})
    r = _consume(sb)
    out = r.stdout + r.stderr
    assert r.returncode == 0, (
        f"早警**不得改 rc**（改了则 hook Gate 4 会把它当 BLOCK，比不降级更硬）：rc={r.returncode} {out[:300]}")
    assert "OK" in out, f"放行契约（末行 `OK`）被早警破坏：{out[:300]}"
    assert _degrade_lines(out), f"remaining=2 ≤ θ=2 未触发早警（HEAD 必红）：{out[:400]}"
    rows = _degrade_rows(sb)
    assert rows, f"早警未在旁挂账本留痕（§15.3 动作②）：{_ledger(sb)}"


# ── 臂② 阈值边界：未到 θ ⟹ 无早警（防「全程预警」= 反例③）───────────────────
def test_arm2_no_warning_above_theta(tmp_path):
    """`max=10 / remaining=3` > θ=2 ⟹ **无**早警（θ 不得取到 max 附近，否则早警失效）。"""
    sb = _mk_sandbox(tmp_path, {"max": 10, "used": 7, "remaining": 3})
    r = _consume(sb)
    out = r.stdout + r.stderr
    assert r.returncode == 0, f"未到 θ 竟被拦：rc={r.returncode} {out[:300]}"
    assert not _degrade_lines(out), f"未到 θ 却早警（噪声，反例③）：{out[:400]}"
    assert not _degrade_rows(sb), f"未到 θ 却留痕：{_ledger(sb)}"


# ── 臂③ 守底线：remaining=0 仍 BLOCK（降级不得吞掉硬阻断）────────────────────
def test_arm3_zero_remaining_still_blocks(tmp_path):
    """`remaining=0` ⟹ `BLOCK` + rc≠0 + **无**早警（底线一字不改）。"""
    sb = _mk_sandbox(tmp_path, {"max": 10, "used": 10, "remaining": 0})
    r = _consume(sb)
    out = r.stdout + r.stderr
    assert r.returncode != 0, f"耗尽竟被降级放行（底线失守）：rc={r.returncode} {out[:300]}"
    assert "BLOCK: edit_budget exhausted" in out, f"耗尽 BLOCK 文案变了：{out[:400]}"
    assert not _degrade_lines(out), f"耗尽态不应报早警（应先 BLOCK）：{out[:400]}"


# ── 臂④ kill switch：`GK_DEGRADE=0` ⟹ 逐字零回归 ─────────────────────────
def test_arm4_kill_switch_disables_warning(tmp_path):
    """`GK_DEGRADE=0` ⟹ 无早警、无 `degrade` 账本行，rc 仍 0（逐字回到今日）。"""
    sb = _mk_sandbox(tmp_path, {"max": 10, "used": 8, "remaining": 2})
    r = _consume(sb, env_prefix="export GK_DEGRADE=0; ")
    out = r.stdout + r.stderr
    assert r.returncode == 0, f"kill switch 下被拦：rc={r.returncode} {out[:300]}"
    assert not _degrade_lines(out), f"kill switch 未生效（仍早警）：{out[:400]}"
    assert not _degrade_rows(sb), f"kill switch 未生效（仍留痕）：{_ledger(sb)}"


# ── 臂⑤ θ 覆盖：`GK_DEGRADE=<n>` ⟹ θ=n（P4-1 单开关的覆盖面）──────────────
def test_arm5_theta_override(tmp_path):
    """`GK_DEGRADE=5` + `remaining=4` ⟹ 早警（默认 θ=2 时不触发，证明覆盖生效）。"""
    sb0 = _mk_sandbox(_mk(tmp_path / "base"), {"max": 10, "used": 6, "remaining": 4})
    r0 = _consume(sb0)
    assert not _degrade_lines(r0.stdout + r0.stderr), (
        f"默认 θ=2 时 remaining=4 不应早警（对照组失效）：{r0.stdout[:300]}")
    sb = _mk_sandbox(_mk(tmp_path / "over"), {"max": 10, "used": 6, "remaining": 4})
    r = _consume(sb, env_prefix="export GK_DEGRADE=5; ")
    assert _degrade_lines(r.stdout + r.stderr), (
        f"`GK_DEGRADE=5` 未把 θ 覆盖为 5：{r.stdout[:400]}")


# ── 臂⑥ 防洗白：降级态**不得免计费**（θ 不是免费额度）──────────────────────
def test_arm6_degrade_still_bills(tmp_path):
    """降级态一次放行 ⟹ `remaining` 2→1、`used` 8→9，且 `edit_count` +1。"""
    sb = _mk_sandbox(tmp_path, {"max": 10, "used": 8, "remaining": 2})
    before = _budget(sb)
    r = _consume(sb)
    assert r.returncode == 0, f"降级态未放行：rc={r.returncode} {r.stdout[:300]}"
    after = _budget(sb)
    assert after.get("remaining") == before.get("remaining") - 1, (
        f"降级态**免计费**（θ 变免费额度，反例①）：{before} → {after}")
    assert after.get("used") == before.get("used") + 1, (
        f"降级态 used 未自增：{before} → {after}")
    st = json.loads((sb / ".gatekeeper.state").read_text(encoding="utf-8"))
    assert st["gate_data"].get("edit_count", 0) >= 1, (
        f"edit_count 未自增：{st['gate_data'].get('edit_count')}")
