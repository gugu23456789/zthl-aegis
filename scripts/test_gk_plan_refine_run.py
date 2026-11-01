"""
test_gk_plan_refine_run.py -- F6 红先臂：`plan-refinement --run` 单入口（形态臂）
================================================================================
背景（用户令 / D §14.7 F-D）：质询下发需主 agent **手动逐步拼命令**（enqueue → adjudicate →
moa-aggregate），「手动拼接摩擦」是流程漏洞的一半。F6 = 单入口 `plan-refinement <plan> --run`：
内部 ① enqueue（既有 `--task` 路径）② **复用**统一裁决入口 `--adjudicate last-batch approve`
③ 缺省接 `moa-aggregate`（`--no-aggregate` opt-out）；输出**单一 JSON 封套**（禁伪拼接）。

本仓 CLI 判据惯例 = **形态臂**（静态断言新形态在场 ∧ 旧静默形态缺席；见 `test_gk_plan_refine_pipeline.py`
自述「行为臂另立（须真 state + 真 CLI，重）」）。行为臂见 `test_run_mutex_behavior`（轻量：互斥守卫
在 preflight 之前短路，无需真计划）。
"""
import os
import subprocess
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _src() -> str:
    return CLI.read_text(encoding="utf-8")


# ── ① `--run` 旗标已解析 ───────────────────────────────────────────────────
def test_run_flag_parsed():
    s = _src()
    assert "local run_mode=" in s, "未见 run_mode 声明"
    assert "--run) run_mode=true" in s, "--run 未解析"
    assert "--no-aggregate) no_aggregate=true" in s, "--no-aggregate 未解析"
    assert "--aggregate-out) aggregate_out=" in s, "--aggregate-out 未解析"


# ── ② 链尾 helper 已定义且被 enqueue 尾接线 ─────────────────────────────────
def test_run_tail_defined_and_wired():
    s = _src()
    assert "_plan_refine_run_tail()" in s, "链尾 helper 未定义"
    assert "_plan_refine_run_tail \"$target\" \"$_sub_out\"" in s, "链尾 helper 未被 enqueue 尾调用"


# ── ③ 链尾**复用**统一裁决入口 + 接 moa-aggregate（禁第二实现）──────────────
def test_run_tail_composes_adjudicate_and_aggregate():
    s = _src()
    seg = s[s.find("_plan_refine_run_tail()"):]
    seg = seg[:seg.find("\n}\n")]
    assert "--adjudicate last-batch --decision approve" in seg, "链尾未复用统一裁决入口（禁第二实现）"
    assert "cmd_moa_aggregate" in seg, "链尾未接 moa-aggregate"
    assert "cmd_plan_refinement" in seg, "链尾未复用统一入口（禁第二实现）"


# ── ④ 互斥 / 同用门（fail-loud，禁静默）─────────────────────────────────────
def test_run_mutex_guard():
    s = _src()
    assert "--run 与 --adjudicate/--check-only/--list-pending 互斥" in s, "未见 --run 互斥门"


def test_agg_flags_require_run():
    s = _src()
    assert "--no-aggregate/--aggregate-out/--chain 仅与 --run 同用" in s, "未见 --aggregate-* 同用门"


def test_run_requires_task():
    s = _src()
    assert "--run 需要 --task 或 --task-from-plan" in s, "未见 --run 的 task 前置门"


# ── ⑤ 行为臂（轻量）：互斥门在 preflight 之前短路 ⟹ 无需真计划即 rc=2 ────────
def test_run_mutex_behavior(tmp_path):
    st = tmp_path / ".gatekeeper.state"
    st.write_text("{}", encoding="utf-8")
    env = dict(os.environ, STATE_FILE=str(st), STATE_FILE_EXPLICIT="1")
    r = subprocess.run(
        ["bash", str(CLI), "plan-refinement", "x.md", "--run",
         "--adjudicate", "last", "--decision", "approve"],
        cwd=str(CLI.parent), capture_output=True, text=True, env=env, timeout=90)
    assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)
    assert "--run 与" in r.stdout, r.stdout


# ── ⑥ 行为臂：大载荷（E2BIG 回归）────────────────────────────────────────────
def _tail_fn_src(src: str) -> str:
    """从 CLI 原文抽 `_plan_refine_run_tail()` 整段（含闭合 `}`），不复制实现。"""
    start = src.find("_plan_refine_run_tail() {")
    assert start >= 0, "链尾 helper 未定义"
    seg = src[start:]
    end = seg.find("\n}\n")
    assert end > 0, "链尾 helper 未闭合"
    return seg[:end + 2]


def test_run_tail_survives_large_payload(tmp_path):
    """红先（2026-10-27 实测）：`_adj_json` 含多臂 full_task 时曾**直接作 argv** 传
    `python3 -c` ⟹ `Argument list too long`，聚合封套整条丢失（本轮 plan-refinement
    --run 尾部即此崩）。判据 = 2MB 裁决载荷下仍产出**单一合法 JSON 封套**且内容不丢。"""
    import json

    big_task = "A" * 2_000_000
    adj = tmp_path / "adj.json"
    adj.write_text(json.dumps({"ok": True, "full_task": big_task}), encoding="utf-8")
    enq = tmp_path / "enq.json"
    enq.write_text(json.dumps({"ok": True, "n": 6}), encoding="utf-8")

    harness = tmp_path / "fn.sh"
    harness.write_text(
        "set -uo pipefail\n"
        "GK_DBG_LOG=/dev/null; STATE_FILE=/dev/null\n"
        'cmd_plan_refinement() { cat "$ADJ_FILE"; }\n'
        'cmd_moa_aggregate() { printf \'{"ok":true}\'; }\n'
        + _tail_fn_src(_src()) + "\n"
        '_plan_refine_run_tail p.md "$(cat "$ENQ_FILE")" 6 false "" ""\n',
        encoding="utf-8")
    env = dict(os.environ, ADJ_FILE=str(adj), ENQ_FILE=str(enq))
    r = subprocess.run(["bash", str(harness)], capture_output=True, text=True,
                       env=env, timeout=180)
    assert r.returncode == 0, (r.returncode, r.stderr[-2000:])
    d = json.loads(r.stdout)
    assert d["run"] is True and d["enqueue"] == {"ok": True, "n": 6}
    assert d["adjudicate"]["full_task"] == big_task, "大载荷在封套里被截断/丢失"


def test_run_tail_fails_loud_when_assembly_fails(tmp_path):
    """守卫臂（2026-10-27）：装配段 python 非零 ⟹ **rc=3 + fail-loud JSON**。
    原实现尾句 `rm -f` 会把失败吞成 rc=0 + stdout 空（「跑成功但没结果」）。"""
    import json

    shim = tmp_path / "bin"
    shim.mkdir()
    fake = shim / "python3"
    fake.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    fake.chmod(0o755)
    adj = tmp_path / "adj.json"
    adj.write_text('{"ok": true}', encoding="utf-8")
    enq = tmp_path / "enq.json"
    enq.write_text('{"ok": true}', encoding="utf-8")

    harness = tmp_path / "fn.sh"
    harness.write_text(
        "set -uo pipefail\n"
        "GK_DBG_LOG=/dev/null; STATE_FILE=/dev/null\n"
        'cmd_plan_refinement() { cat "$ADJ_FILE"; }\n'
        'cmd_moa_aggregate() { printf \'{"ok":true}\'; }\n'
        + _tail_fn_src(_src()) + "\n"
        '_plan_refine_run_tail p.md "$(cat "$ENQ_FILE")" 6 false "" ""\n',
        encoding="utf-8")
    env = dict(os.environ, ADJ_FILE=str(adj), ENQ_FILE=str(enq),
               PATH=str(shim) + os.pathsep + os.environ.get("PATH", ""))
    r = subprocess.run(["bash", str(harness)], capture_output=True, text=True,
                       env=env, timeout=60)
    assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)
    d = json.loads(r.stdout)
    assert d["ok"] is False and d["error"] == "ENVELOPE_ASSEMBLY_FAILED"


# ── ⑦ `--chain` 透传（2026-10-27，owner 令）────────────────────────────────
def test_chain_flag_gated_to_run():
    """形态臂：`--chain` 已解析、仅随 `--run`、并被链尾实参透传。"""
    s = _src()
    assert "--chain) chain_flag=true" in s, "--chain 未解析"
    assert "--no-aggregate/--aggregate-out/--chain 仅与 --run 同用" in s, "未见 --chain 同用门"
    assert '"$no_aggregate" "$aggregate_out" "$chain_flag"' in s, "链尾未收到 chain 实参"


def _run_tail_with_chain(tmp_path, chain: str):
    import json
    adj = tmp_path / "adj.json"
    adj.write_text('{"ok": true}', encoding="utf-8")
    enq = tmp_path / "enq.json"
    enq.write_text('{"ok": true}', encoding="utf-8")
    argv_file = tmp_path / "agg.argv"
    harness = tmp_path / "fn.sh"
    harness.write_text(
        "set -uo pipefail\n"
        "GK_DBG_LOG=/dev/null; STATE_FILE=/dev/null\n"
        'cmd_plan_refinement() { cat "$ADJ_FILE"; }\n'
        'cmd_moa_aggregate() { printf "%s\\n" "$*" > "$AGG_ARGV"; printf \'{"ok":true}\'; }\n'
        + _tail_fn_src(_src()) + "\n"
        f'_plan_refine_run_tail p.md "$(cat "$ENQ_FILE")" 6 false "" "{chain}"\n',
        encoding="utf-8")
    env = dict(os.environ, ADJ_FILE=str(adj), ENQ_FILE=str(enq), AGG_ARGV=str(argv_file))
    r = subprocess.run(["bash", str(harness)], capture_output=True, text=True,
                       env=env, timeout=60)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    json.loads(r.stdout)  # 仍是单一合法封套
    return argv_file.read_text(encoding="utf-8")


def test_run_tail_passes_chain_when_enabled(tmp_path):
    argv = _run_tail_with_chain(tmp_path, "true")
    assert "--chain" in argv.split(), f"未透传 --chain：{argv!r}"
    assert "--plan" in argv.split() and "p.md" in argv.split()


def test_run_tail_omits_chain_by_default(tmp_path):
    argv = _run_tail_with_chain(tmp_path, "")
    assert "--chain" not in argv.split(), f"默认不应带 --chain：{argv!r}"
