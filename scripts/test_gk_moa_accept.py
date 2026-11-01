#!/usr/bin/env python3
"""`gk_moa_aggregate.py --accept` 的红先臂（`ECC-BAB89429DFD1` / 设计 §11.5，2026-09-23）。

背景（用户裁定「一键验收器应该合并到 MoA 那边吧？MoA 职责就是聚合验收」）：
  MoA 聚合器现在**只聚合 subagent 报告**；验收器 `_accept_cli.sh` 是**独立脚本** ⟹ 并发
  coder 跑完后，主 agent 必须**手工两步**（先逐 worktree 跑子集、再合并树跑一次全量 diff）。
  目标 = `--accept` **单入口**：MoA 同时聚合「报告」与「验收」。

判据（红先，现状**必红**）：
  ① `--accept` 必须被 argparse 接受并回统一裁决封套（现状：`unrecognized arguments: --accept`）；
  ② **fail-loud**：未给 `--worktrees` 时 `accept.global.verdict` 必须为 `"unknown"`
     —— 「无输入」≠「无失败」，禁止静默判 `pass`（本仓既有纪律）。

安全网 R1：只读被测脚本；不 patch 标准库；不起子进程之外的外部依赖。
"""
import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "gk_moa_aggregate.py"


def _run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args],
                          capture_output=True, text=True, timeout=180)


def test_accept_mode_is_recognized():
    """① `--accept` 须被接受，且 stdout 是含 `accept` 封套的单行 JSON。"""
    r = _run("--accept")
    assert r.returncode == 0, (
        f"`--accept` 未被接受（rc={r.returncode}）—— argparse 尚无该参数；stderr:\n{r.stderr[-500:]}")
    obj = json.loads(r.stdout.strip().splitlines()[-1])
    assert obj.get("ok") is True, f"回包 ok 非 true：{r.stdout[:300]}"
    acc = obj.get("accept")
    assert isinstance(acc, dict), f"缺 `accept` 对象：{r.stdout[:300]}"
    assert isinstance(acc.get("per_worktree"), list), f"缺 `accept.per_worktree` 列表：{r.stdout[:300]}"
    g = acc.get("global")
    assert isinstance(g, dict), f"缺 `accept.global` 对象：{r.stdout[:300]}"
    assert "verdict" in g and "new_failures" in g, (
        f"`accept.global` 缺 verdict/new_failures：{r.stdout[:300]}")


def test_accept_without_worktrees_is_fail_loud():
    """② 未给 `--worktrees` ⟹ `verdict` 必须 `unknown`（禁止静默 pass）。"""
    r = _run("--accept")
    assert r.returncode == 0, f"rc={r.returncode}；stderr:\n{r.stderr[-500:]}"
    obj = json.loads(r.stdout.strip().splitlines()[-1])
    got = obj.get("accept", {}).get("global", {}).get("verdict")
    assert got == "unknown", (
        f"无 worktree 时 verdict 应为 'unknown'（fail-loud），实得 {got!r}：{r.stdout[:300]}")


# ── B3（`ECC-2FB0B4D0F356`，2026-09-27 定稿＝方案①）：`--accept --full-regression` ──────
# 设计 §11.7-3 / 定稿契约：在**合并树**跑 `bash <merge_tree>/scripts/_accept_cli.sh --full`，
# 结果落 `accept.full_regression:{tree,rc,verdict,new_failures,fixed,summary,error}`。
# 红先对照：HEAD 版 argparse 无 `--full-regression`（`unrecognized arguments`，rc=2）⟹ 臂①②必红。
# 臂③（单独用 `--full-regression` 须 fail-loud）在 HEAD 亦 rc≠0 ⟹ **恒绿**，不属红先臂（排除在 -k 外）。

def _stub_tree(tmp_path, rc=0):
    """桩「合并树」：`<tree>/scripts/_accept_cli.sh` 按给定 rc 退出（避免真跑全量 ~243s）。"""
    tree = tmp_path / "merge-tree"
    (tree / "scripts").mkdir(parents=True)
    stub = tree / "scripts" / "_accept_cli.sh"
    stub.write_text("#!/bin/bash\necho '[accept] FULL 0 new failure'\nexit %d\n" % rc,
                    encoding="utf-8")
    stub.chmod(0o755)
    return str(tree)


def test_full_regression_flag_recognized(tmp_path):
    """B3 臂①（红先）：`--accept --full-regression --merge-tree <tree>` 须在合并树跑全量验收
    并把结果落 `accept.full_regression`（现状：`unrecognized arguments: --full-regression`）。"""
    tree = _stub_tree(tmp_path, rc=0)
    r = _run("--accept", "--full-regression", "--merge-tree", tree)
    assert r.returncode == 0, (
        f"`--full-regression` 未被接受（rc={r.returncode}）—— argparse 尚无该参数；stderr:\n{r.stderr[-500:]}")
    obj = json.loads(r.stdout.strip().splitlines()[-1])
    fr = obj.get("accept", {}).get("full_regression")
    assert isinstance(fr, dict), f"缺 `accept.full_regression` 对象：{r.stdout[:300]}"
    assert fr.get("verdict") == "pass" and fr.get("rc") == 0, f"桩 rc=0 应判 pass：{fr}"
    assert fr.get("tree") == tree, f"未记录合并树路径：{fr}"


def test_full_regression_fail_loud_without_tree(tmp_path):
    """B3 臂②（fail-loud）：合并树/验收脚本缺失 ⟹ `verdict` 必须 `unknown`（禁静默 pass）。"""
    missing = str(tmp_path / "nope-tree")
    r = _run("--accept", "--full-regression", "--merge-tree", missing)
    assert r.returncode == 0, f"rc={r.returncode}；stderr:\n{r.stderr[-500:]}"
    obj = json.loads(r.stdout.strip().splitlines()[-1])
    fr = obj.get("accept", {}).get("full_regression") or {}
    assert fr.get("verdict") == "unknown", (
        f"缺树应判 unknown（fail-loud），实得 {fr.get('verdict')!r}：{r.stdout[:300]}")
    assert fr.get("error"), f"缺树须带 error 说明：{fr}"


def test_full_regression_requires_accept():
    """B3 臂③（负臂 / 回归护栏，HEAD 已绿故不入 -k）：`--full-regression` 单独用须 fail-loud。"""
    r = _run("--full-regression")
    assert r.returncode != 0, "`--full-regression` 单独使用未被拒（应 usage 错 / fail-loud）"

