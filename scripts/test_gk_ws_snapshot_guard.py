#!/usr/bin/env python3
"""crossfull 工作树一致性断言回归（`ECC-130ECB1ABCA4`，2026-09-28）。

病根（读码定位，非推断）：`audit --crossfull` 的 LLM 车道（L2 `--crossrev` / 后R 双独立）以
`cwd=GK_CF_CWD` = **活动工作树**运行（非 `--isolate` 时，见 runner `cwd=os.environ.get("GK_CF_CWD")`）；
车道期间若有**并发编辑**（另一会话 / 编辑器 / agent 自身）⟹ L2 **读到半写/撕裂内容**，
而该段原有并发断言**只覆盖父 state**（`_cf_src_sum` / `_cf_src_sum2`），**工作树零断言**
⟹ 结论**静默失真** —— 正是本仓自认最坏的形态（§隔离段注记原文：「假绿 —— 比显式失败更坏」）。

修法（判据**单源**，禁第二份实现）：`gk_git_concurrency_check.worktree_fingerprint`（dirty 集合
逐文件 `git hash-object --no-filters` 聚合 sha256，**只读**）+ CLI `--ws-fingerprint` +
crossfull runner 车道**前后对拍**：不等 ⟹ loud 行 + L2 步降级 `WARN(并发写)` +
JSON `worktree_fingerprint.changed_files`；不可用 ⟹ `NOT-RUN`（**不得**读作"一致"）。

本文件锁两条：
  arm（红先 · 行为）：并发改写 ⟹ 指纹**必变**且命中该文件；无改动 ⟹ 指纹**必稳**（HEAD：无该函数）。
  接线面（**非红**，不入选 `-k`）：CLI 内**确实**接线（前后对拍 + 降级 + JSON 键 + 单源转发）。
"""
import json
import subprocess
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import gk_git_concurrency_check as gcc  # noqa: E402 —— 判据单源


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, timeout=120)


def _mk_repo(tmp_path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "a.sh").write_text("#!/bin/bash\necho v1\n", encoding="utf-8")
    _git(repo, "add", "a.sh")
    _git(repo, "commit", "-qm", "init")
    return repo


def test_arm_ws_fingerprint_detects_concurrent_edit(tmp_path):
    """红先（行为）：并发改写工作树 ⟹ 指纹必变且**命中该文件**；无改动 ⟹ 指纹必稳。

    HEAD 真红：`gk_git_concurrency_check.worktree_fingerprint` 不存在。
    """
    repo = _mk_repo(tmp_path)
    stable1 = gcc.worktree_fingerprint(str(repo))
    stable2 = gcc.worktree_fingerprint(str(repo))
    assert stable1["fingerprint"] == stable2["fingerprint"], "无改动时指纹不稳（误报源头）"
    assert stable1["dirty_count"] == 0, stable1

    # 模拟「并发编辑写了一半」：直接改写工作树文件（未 commit）
    (repo / "a.sh").write_text("#!/bin/bash\necho v2-half", encoding="utf-8")
    after = gcc.worktree_fingerprint(str(repo))
    assert after["fingerprint"] != stable1["fingerprint"], "工作树被改写但指纹未变（断言失效）"
    assert "a.sh" in [f["path"] for f in after["files"]], after


def test_crossfull_wires_ws_consistency_guard():
    """接线面（**非红**，不入选 `-k`）：CLI 确把判据接到 LLM 车道前后，且失败面可机读。"""
    src = (SKILL_DIR / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    assert "_ws_pre = ws_fingerprint()" in src, "车道前未取快照"
    assert "_ws_a, _ws_b = _ws_pre, ws_fingerprint()" in src, "车道后未对拍"
    assert '"worktree_fingerprint": _ws_info' in src, "JSON 未落一致性键（不可机读）"
    assert "WARN(并发写)" in src, "并发改动时未降级 L2 步态"
    assert "--ws-fingerprint" in src, "未走判据单源（gk_git_concurrency_check --ws-fingerprint）"
    # 判据单源存在性（禁第二份实现）
    r = subprocess.run([sys.executable, str(SKILL_DIR / "scripts" / "gk_git_concurrency_check.py"),
                        "--ws-fingerprint", str(SKILL_DIR)],
                       capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stderr[:200]
    assert "fingerprint" in json.loads(r.stdout), r.stdout[:200]
