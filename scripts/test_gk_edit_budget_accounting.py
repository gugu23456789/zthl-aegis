#!/usr/bin/env python3
"""F3b 子族红先臂：`ECC-1E6BFDD7A207` —— `edit_budget` 计费口径（**Q14 裁定 B 后重写**）。

裁定（2026-09-23，用户裁定 = B「计入 · 限门禁观察点」；正典 `2026-09-21-review-runtime-subplan.md` §4.12.4 Q14）：
  `edit_budget` = 「**agent 经门禁观察点的写动作次数**」；观察点 =
    ① hook 的 `EDIT_TOOLS`（现状，经 `pre_tool_check`）
    ② CLI `_dispatch()` 分派的写类子命令（`_CMD_REG` 的 `side_effects ∈ {state_write, git_write, key_write}`）
  **不计**：门禁**内部**调用（`_log_block`→`_state_write`、`advance`、`_budget_override_record` —— 均不经 `_dispatch`）、
            `GK_BUDGET_OVERRIDE=1`、以及 `state-patch` 且 fragment 触及 `edit_budget` 的**逃生舱自身**。

**独立子族**：与直写收敛族 `F3a-state-write-convergence` **文件级互斥**（两族各独占一个测试文件，
且互为对方 `forbidden_paths`；契约由 `test_gk_agent_family.py::test_f3_subfamilies_are_file_level_disjoint` 守护）。

落点（族定义）：`gatekeeper-cli.sh` 的 `pre_tool_check()` 计费段 **+ `_dispatch()`**（后者在 `PROTECTED_REGION::gate` 内）。

**⚠ 2026-09-30 口径变更（REV-5 §13.2 / G4-d）**：计费判据由**统一模型**（凡
`side_effects=state_write` 一律计费）改为**分流模型**（记账通道免 / 工程通道计费）。
臂① 的**代表命令**随之由 `state-patch`（记账通道，现已在 `_BILL_EXEMPT_CMDS` 内、**免计费**）
换为 `apply-worktree --bind --path`（`side_effects=state_write` 的**真工程写**，**仍计费**）。
**臂的判据（used +1 / remaining −1）不变**，仅换夹具。分流模型口径正本见
`scripts/test_gk_bill_channel.py`。

三臂（**红先 = 落刀前臂①必红**）：
  ① `test_cli_write_class_subcommand_counts_toward_edit_budget`（**正臂 = 本族红先**）：跑一条
     `side_effects=state_write` 的**工程通道**子命令（`apply-worktree --bind --path`）后
     `gate_data.edit_budget.used` 必须 **+1**、`remaining` 必须 **−1**。
     **修前实测：`used` 不变 ⟹ FAILED**（即 Q14 口径缺口本身）。
  ② `test_gate_internal_write_does_not_count`（**负臂 · 守「不误计」边界**）：触发门禁**内部**写
     （IDLE 下 `pre-tool-check` 走 `_log_block` 落 `block_log`）后 `used` 必须**不变**。
     修前亦 PASS —— 本臂专防「把计费挂进 `_state_write` 本体」这一诱惑性实现（一挂上去
     `_log_block`/`advance` 就会被一并计价 ⟹ 本条转红）。
  ③ `test_state_patch_touching_edit_budget_is_exempt`（**负臂 · 逃生舱不自噬**）：`state-patch` 且
     fragment **触及** `edit_budget` 时**不**扣减（否则 `remaining=0` 时连重置它自己都会被 BLOCK）。
     修前亦 PASS。（2026-09-30 G4-e：其判别力前置断言由 `overrides[]` 改读旁挂账本行数。）

沙箱：`scripts` 软链 + CLI 实拷 + 最小 state（**不触真实 `.gatekeeper.state`**），stage=`IDLE`。
"""
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = SKILL_DIR / "gatekeeper-cli.sh"


def _wsl(p) -> str:
    """Windows 路径 → WSL 路径（`C:\\a\\b` → `/mnt/c/a/b`）。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _canon(state: dict) -> str:
    """CLI 单一事实源的 canon：`sha256(json.dumps(gate_data, sort_keys=True))[:16]`。"""
    gd = json.dumps(state.get("gate_data", {}), sort_keys=True)
    return hashlib.sha256(gd.encode()).hexdigest()[:16]


def _sandbox(root: Path, stage: str = "IDLE") -> Path:
    """最小技能根 + 合法 checksum state（stage=IDLE ⟹ `_log_block` 可触发）。"""
    sb = (root / "sb").resolve()
    sb.mkdir(parents=True)
    w = _wsl(sb)
    r = subprocess.run(
        ["bash", "-lc", 'ln -s "%s" "%s/scripts" && cp "%s" "%s/gatekeeper-cli.sh"'
         % (_wsl(SCRIPT_DIR), w, _wsl(CLI_SRC), w)],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, f"沙箱搭建失败：{r.stdout}{r.stderr}"
    state = {
        "stage": stage, "r_phase": "R1", "branch": "master", "worktree": _wsl(sb),  # §17-6-P4：显式 root
        "gate_data": {
            "project_type": "standing",
            "edit_budget": {"max": 4, "used": 0, "remaining": 4, "overrides": []},
            "scheduler": {"mode": "constant", "max_lr": 4, "min_lr": 1,
                          "total_steps": 6, "current_step": 1, "current_lr": 4},
        },
    }
    state["_checksum"] = _canon(state)
    (sb / ".gatekeeper.state").write_text(
        json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")
    (sb / "wt").mkdir()   # 2026-09-30 口径升级：写类代表命令 `apply-worktree --bind` 的目标目录
    return sb


def _seed_budget(sb: Path, used: int, max_: int = 4, remaining=None) -> None:
    """把沙箱 state 的 `edit_budget` 置为指定值（并重算合法 checksum）。"""
    st = sb / ".gatekeeper.state"
    d = json.loads(st.read_text(encoding="utf-8"))
    eb = d.setdefault("gate_data", {}).setdefault("edit_budget", {})
    eb.update({"max": max_, "used": used,
               "remaining": (max_ - used) if remaining is None else remaining})
    d["_checksum"] = _canon(d)
    st.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")


def _budget(sb: Path) -> tuple:
    """读回 `(used, remaining)`。"""
    d = json.loads((sb / ".gatekeeper.state").read_text(encoding="utf-8"))
    eb = d.get("gate_data", {}).get("edit_budget", {})
    return eb.get("used"), eb.get("remaining")


def _cli_run(sb: Path, *args: str):
    # 载荷含 `"` 的参数（如 `state-patch` 的 JSON fragment）必须转义 —— 否则被 shell 截断。
    # 首版实测：`"{"probe":1}"` 解析错乱 ⟹ 子命令**根本没跑到**，臂①红得「假」（假红）。
    w = _wsl(sb)
    argv = " ".join('"%s"' % a.replace('"', '\\"') for a in args)
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh %s' % (w, argv)],
        capture_output=True, text=True, timeout=120)


@pytest.fixture()
def idle_sandbox():
    if shutil.which("bash") is None:
        pytest.skip("本机无 bash（Windows 语义下无法执行 CLI）")
    root = Path(tempfile.mkdtemp(prefix="gk_f3b_"))
    try:
        yield _sandbox(root, "IDLE")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_cli_write_class_subcommand_counts_toward_edit_budget(idle_sandbox):
    """① 正臂（红先）：写类子命令（`side_effects=state_write`）经 `_dispatch` 必须扣 1。

    **代表命令 = `apply-worktree --bind`（工程动作）**。2026-09-30 口径升级（REV-5 §13.2）：
    计费豁免改为**按通道**白名单 —— `finding` 等**记账**命令不再计费、`state-patch` 整体豁免
    （见 `scripts/test_gk_bill_channel.py`）⟹ 本臂原用的 `state-patch` 代表已不再是计费面，
    换成仍计费的工程命令。断言不变（仍 = 扣 1）。
    """
    _seed_budget(idle_sandbox, used=0)
    wt = _wsl(idle_sandbox / "wt")
    _cli_run(idle_sandbox, "apply-worktree", "--bind", "--path", wt)
    d = json.loads((idle_sandbox / ".gatekeeper.state").read_text(encoding="utf-8"))
    assert wt in json.dumps(d.get("worktrees_extra") or [], ensure_ascii=False), (
        "`apply-worktree --bind` 未生效 ⟹ 本臂前提不成立（子命令未跑到）")
    used, remaining = _budget(idle_sandbox)
    assert (used, remaining) == (1, 3), (
        f"Q14 裁定 B：CLI 写类子命令必须计入 `edit_budget`，实测 used={used} remaining={remaining}"
        "（期望 1 / 3）—— 修前 used 恒 0 = 计费口径缺口")


def test_gate_internal_write_does_not_count(idle_sandbox):
    """② 负臂：门禁**内部**写（`_log_block`）不经 `_dispatch` ⟹ **不得**计价。"""
    _seed_budget(idle_sandbox, used=0)
    _cli_run(idle_sandbox, "pre-tool-check", "Write", _wsl(idle_sandbox / "gatekeeper-cli.sh"))
    d = json.loads((idle_sandbox / ".gatekeeper.state").read_text(encoding="utf-8"))
    assert (d.get("gate_data") or {}).get("block_log"), (
        "`block_log` 未落盘 ⟹ 内部写未发生，本臂失去判别力")
    used, remaining = _budget(idle_sandbox)
    assert (used, remaining) == (0, 4), (
        f"门禁内部写被误计了：used={used} remaining={remaining}（期望 0 / 4）—— "
        "判别面是「不经 `_dispatch`」；多半是把计费挂进了 `_state_write` 本体")


def test_state_patch_touching_edit_budget_is_exempt(idle_sandbox):
    """③ 负臂：`state-patch` 且 fragment **触及** `edit_budget` = 逃生舱自身 ⟹ **不得**自噬。

    2026-09-30 G4-e（REV-5 §13.3）：留痕面由 `edit_budget.overrides[]`（已降**只读遗留**）改为
    旁挂 append-only 账本 ⟹ 本臂的「判别力前置断言」改读**账本行数**（否则旧断言恒不成立）。
    """
    _seed_budget(idle_sandbox, used=2, remaining=2)
    _cli_run(idle_sandbox, "state-patch",
             '{"edit_budget":{"max":4,"used":2,"remaining":2,"overrides":[]}}')
    led = idle_sandbox / ".gatekeeper.state.budget-log.jsonl"
    n = len([ln for ln in led.read_text(encoding="utf-8").splitlines() if ln.strip()]) if led.exists() else 0
    assert n == 1, (
        f"逃生舱 `state-patch` 未跑到 ⟹ 本臂失去判别力（旁挂账本={n} 行，期望 1 条留痕）")
    used, remaining = _budget(idle_sandbox)
    assert (used, remaining) == (2, 2), (
        f"逃生舱自噬：重置 `edit_budget` 的那次 `state-patch` 自己被扣了："
        f"used={used} remaining={remaining}（期望 2 / 2）")
