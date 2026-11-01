"""
test_gk_apply_worktree_close_out.py -- T7 红先臂：处置链闭环出口 `apply-worktree --close-out`
================================================================================
正本：finding `ECC-21AB384F03A9`（C 计划 §3 T7「对偶关单」重定）+ `ECC-3DF26C21C3CB`（accept 并行度注释）。

缺口：coder 处置六环（下发前准备 / 派发 / 接收 / 验收 / 对偶关单 / 回收）各自孤立，无编排串成闭环；
      `moa-aggregate --accept`（+`--full-regression`）**无生产调用点**且 `--full-regression` 经 CLI **不可达**；
      gitnexus 增量刷新仅接质询通道。

本切片：① 抽 `_gitnexus_refresh_if_stale` 单一源（先查旧才刷）；② 新增 `apply-worktree --close-out`
      （验收 → 关单门禁 → 回收 → gitnexus；守 A7 不自动关）；③ 补 `--full-regression` CLI 转发。
"""
import json
import re
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
CLI = SCRIPTS.parent / "gatekeeper-cli.sh"


def _state(tmp_path) -> str:
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    return str(st)


def _close_out(tmp_path, extra=None):
    st = _state(tmp_path)
    cmd = ["bash", str(CLI), "apply-worktree", "--close-out", "--no-gitnexus", "--no-reclaim",
           "--state", st]
    cmd += (extra or [])
    return subprocess.run(cmd, capture_output=True, text=True)


# ── ① 形态臂：CLI 接线（--close-out 分派 + helper + --full-regression 转发）──────────
def test_cli_wires_close_out_and_helper():
    s = CLI.read_text(encoding="utf-8")
    assert "--close-out) closeout=" in s, "未接 --close-out 分派"
    assert "_gitnexus_refresh_if_stale() {" in s, "未抽 gitnexus 单一源 helper"
    assert "_co_dir=$(_gx_repo_dir_for_current" in s, "闭环未解析 gitnexus 目录"
    assert "_gitnexus_refresh_if_stale \"$_co_dir\" \"close-out\"" in s, "闭环未调 helper"
    assert "$full_regression && args+=(--full-regression)" in s, "--full-regression 未补 CLI 转发"


# ── ② helper：current ⟹ 直接复用（**不** analyze）─────────────────────────────
def test_helper_reuses_current_without_analyze(tmp_path):
    r = _run_helper(tmp_path, 'first=current; second=current')
    assert r.stdout.strip() == "current", r.stdout + r.stderr
    assert not (tmp_path / "marker").exists(), "current 不该触发 analyze"


# ── ③ helper：stale ⟹ 才 analyze，回刷后取新值 ───────────────────────────────
def test_helper_refreshes_when_stale(tmp_path):
    r = _run_helper(tmp_path, 'first=stale; second=current')
    assert r.stdout.strip() == "current", r.stdout + r.stderr
    assert (tmp_path / "marker").read_text(encoding="utf-8").count("CALLED") == 1, "stale 应恰好 analyze 一次"


# ── ④ helper：unavailable ⟹ 不 analyze、原样返回 ────────────────────────────
def test_helper_unavailable_no_analyze(tmp_path):
    r = _run_helper(tmp_path, 'first=unavailable; second=unavailable')
    assert r.stdout.strip() == "unavailable", r.stdout + r.stderr
    assert not (tmp_path / "marker").exists(), "unavailable 不该触发 analyze"


def _run_helper(tmp_path, plan: str):
    """抽取 CLI 内的 `_gitnexus_refresh_if_stale` 函数体，用桩 source 后调用（真实行为臂）。"""
    src = CLI.read_text(encoding="utf-8")
    m = re.search(r"_gitnexus_refresh_if_stale\(\) \{\n.*?\n\}", src, re.S)
    assert m, "未找到 helper 定义"
    body = m.group(0)
    first, second = [x.split("=", 1)[1] for x in plan.split("; ")]
    harness = tmp_path / "harness.sh"
    harness.write_text(
        "#!/bin/bash\n"
        "MARKER=\"%s/marker\"\n"
        "NF=\"%s/nfile\"\n"
        # 计数器落**文件**（命令替换是子壳 ⟹ 变量自增会丢，须跨子壳可见）
        "_gitnexus_baseline_status() { local c=0; [ -f \"$NF\" ] && c=$(cat \"$NF\"); c=$((c+1)); echo \"$c\" > \"$NF\"; "
        "if [ \"$c\" -eq 1 ]; then printf '%%s' \"%s\"; else printf '%%s' \"%s\"; fi; }\n"
        "_gx_analyze_embeddings() { echo CALLED >> \"$MARKER\"; return 0; }\n"
        "%s\n"
        "_gitnexus_refresh_if_stale /fake close-out\n"
        % (tmp_path.as_posix(), tmp_path.as_posix(), first, second, body),
        encoding="utf-8")
    return subprocess.run(["bash", str(harness)], capture_output=True, text=True)


# ── ⑤ E2E：无 --worktrees ⟹ accept fail-loud（verdict=unknown，不判 pass）────────
def test_close_out_unknown_verdict_on_no_input(tmp_path):
    r = _close_out(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    out = json.loads(r.stdout)
    assert out["mode"] == "close_out", out
    assert out["accept"]["accept"]["global"]["verdict"] == "unknown", out
    assert out["closeout"]["auto_closed"] is False, out
    assert out["closeout"]["next"] == "", out


# ── ⑥ E2E：给 --finding 但 verdict≠pass ⟹ 不可关、无 next（守 A7 不自动关）────────
def test_close_out_not_closeable_without_pass(tmp_path):
    r = _close_out(tmp_path, ["--finding", "ECC-T7TEST0001"])
    assert r.returncode == 0, r.stdout + r.stderr
    out = json.loads(r.stdout)
    assert out["closeout"]["findings"] == ["ECC-T7TEST0001"], out
    assert out["closeout"]["closeable"] is False, out
    assert out["closeout"]["next"] == "", out
