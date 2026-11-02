#!/usr/bin/env python3
"""SKILL_DIR 租户校验回归（R-16 ⑰-11d，2026-09-18；用户裁定「加 SKILL_DIR 租户校验」）。

背景（取证实测，2026-09-18）：2026-09-15 13:53–13:54 一次**人工 J5 沙箱**用相对路径 `ln -s`
且 cwd=`/`、以 root 执行 ⟹ 沙箱落在**根目录**（`/scripts -> /scripts`、
`/gatekeeper-cli.sh -> /gatekeeper-cli.sh` 自指软链）⟹ CLI 的 SKILL_DIR 解析成 `/`
⟹ `_DEFAULT_STATE_FILE=/.gatekeeper.state`（骨架）+ 域孪生 `/.gatekeeper.state.gp.r1`
+ 夹具 `/plan.md` + `/ctx.json*` 全落根目录；两天后这批残留被 hook 的「就近 state」误领
（F5 越界误伤）⟹ **范围外编辑被误 BLOCK**。

本文件锁 `gatekeeper-cli.sh` 的 SKILL_DIR 校验（fail-loud）：
  ① **自指软链**（`scripts` 不可解析到 `scripts/gk_state.py`）→ exit 2 + `SKILL_DIR_UNSAFE`
  ② **合法沙箱**（`scripts` 软链到真 `scripts/`，= `test_gk_route_center._sandbox` 同形）
     → **不得**被误拒（反证，防过度拦截）
⚠ 未覆盖（如实登记）：`SKILL_DIR="/"` 与挂载根两个分支无法在本机安全复现（需在根目录建沙箱）
  —— 它们由同一 `case`/`if` 判据承载，集成级未覆盖。

red-first 对照臂：`GK_CLI_UNDER_TEST=<旧版 CLI 绝对路径>`（默认 = 仓内 CLI）
⟹ 用例 ① 必红（旧版无该判据、无 `SKILL_DIR_UNSAFE` 串）。
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = Path(os.environ.get("GK_CLI_UNDER_TEST") or (SKILL_DIR / "gatekeeper-cli.sh"))


def _mk_sandbox(tmp_path: Path, self_loop: bool) -> Path:
    """建沙箱技能根：`scripts` 软链 + CLI 实拷（对齐 `_sandbox`）。"""
    sb = tmp_path / "sb"
    sb.mkdir()
    if self_loop:
        # 相对自指 ⟹ 复现 `/scripts -> /scripts`（解析即 ELOOP）
        os.symlink("scripts", str(sb / "scripts"))
    else:
        os.symlink(str(SCRIPT_DIR), str(sb / "scripts"))
    shutil.copy(str(CLI_SRC), str(sb / "gatekeeper-cli.sh"))
    return sb


def _run(sb: Path, *args):
    return subprocess.run(["bash", str(sb / "gatekeeper-cli.sh"), *args],
                          capture_output=True, text=True, timeout=120, cwd=str(sb))


def test_self_loop_skill_dir_rejected(tmp_path):
    """① 自指软链沙箱 → exit 2 + SKILL_DIR_UNSAFE（事故形态）。"""
    sb = _mk_sandbox(tmp_path, self_loop=True)
    r = _run(sb, "state")
    out = r.stdout + r.stderr
    assert r.returncode == 2, out
    assert "SKILL_DIR_UNSAFE" in out, out


def test_legit_sandbox_not_rejected(tmp_path):
    """② 合法沙箱（scripts 软链到真 scripts/）→ 不得出现 SKILL_DIR_UNSAFE。"""
    sb = _mk_sandbox(tmp_path, self_loop=False)
    (sb / ".gatekeeper.state").write_text(
        json.dumps({"stage": "STAGE_0", "r_phase": "R1", "worktree": ""}), encoding="utf-8")
    r = _run(sb, "state")
    out = r.stdout + r.stderr
    assert "SKILL_DIR_UNSAFE" not in out, out
