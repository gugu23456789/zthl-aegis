#!/usr/bin/env python3
"""§17-5 并发不变量红先臂（I4 会话不相交 / 验收不变量③）。

计划：`docs/plans/2026-09-28-state-single-authority-plan.md` §17-5（L827）+ §17 验收不变量③（L776）。

**不变量③** = 「并发两会话各写各 worktree ⟹ **互不越界、互不覆盖**」，机检两条：
  ① **键单射**（键基数 == live 会话数）：N 会话并发写后，各键族键集合恰为 N（无覆盖/坍缩）；
  ② **互不越界**：A 会话的活动写面（`active_roots`）**不见** B 会话的根。

**族覆盖**（§17 会话化引入的按会话键）：
  · `gate_data.wt_domain.<token>`（域桶，§17-2 写通路 `gk_state_patch cmd_wt_domain`）—— 本文件 i4-a/b；
  · `gate_data.edit_budget.sessions.<sid>`（预算盒）—— 已由 `test_gk_state_patch_nested.py::test_arm1e` 覆盖；
  · `.gatekeeper.write-claims.jsonl`（台账，`sid` 键）—— 本文件 i4-c（`live()` 基数 == live 会话数）。

既有并发臂（不重复）：`test_gk_state_patch_nested.py`（arm1e/arm1g · 叶子级写/追加）、
`test_gk_concurrent_write.py`（arm15a/b/c · finding register / subagent_history）。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SD = Path(__file__).resolve().parent.parent
SCRIPTS = SD / "scripts"
SP = SCRIPTS / "gk_state_patch.py"
WC = SCRIPTS / "gk_write_claims.py"
PY = sys.executable

sys.path.insert(0, str(SCRIPTS))
import gk_write_claims as C  # noqa: E402


def _state(tmp: Path, gate_data=None, name=".gatekeeper.state", **top) -> Path:
    d = {"stage": "ECO-EDIT", "r_phase": "R1",
         "gate_data": gate_data if gate_data is not None else {}}
    d.update(top)
    p = tmp / name
    p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8", newline="\n")
    return p


def _load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def _active_roots(state: Path, gk_session_id) -> list:
    """子进程直调 `gk_route_center.active_roots`（显式喂 `GK_SESSION_ID`；隔离本进程 env）。"""
    child = (
        "import json,os,sys\n"
        "sys.path.insert(0, os.environ['GK_SCRIPTS'])\n"
        "import gk_route_center as R\n"
        "st=json.loads(os.environ['GK_STATE'])\n"
        "print(json.dumps(R.active_roots(st)))\n"
    )
    env = dict(os.environ, GK_SCRIPTS=str(SCRIPTS),
               GK_STATE=state.read_text(encoding="utf-8"),
               GK_SESSION_ID=gk_session_id)
    p = subprocess.run([PY, "-c", child], capture_output=True, text=True, timeout=120, env=env)
    assert p.returncode == 0, "helper 子进程失败（函数缺席/异常）：%s" % (p.stderr[-400:],)
    return json.loads(p.stdout.strip().splitlines()[-1])


# ── i4-a：键单射 · 域桶（N 会话并发 bind 各 token）─────────────────────────
def test_i4_a_wt_domain_key_injective_concurrent(tmp_path):
    """§17-5 键单射：N 会话并发 bind 各自 token ⟹ `wt_domain` **键基数 == N**。"""
    st = _state(tmp_path, {})
    n = 6
    procs = [subprocess.Popen(
        [PY, str(SP), "wt-domain", str(st), "bind", f"tok{i}", f"/mnt/c/x/wt{i}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for i in range(n)]
    rcs = [p.wait(timeout=120) for p in procs]
    assert rcs == [0] * n, "并发 wt-domain 子进程非零退出: %r" % rcs
    bucket = _load(st)["gate_data"]["wt_domain"]
    assert set(bucket) == {f"tok{i}" for i in range(n)}, (
        f"并发写丢键（键基数 {len(bucket)}/{n}）：{sorted(bucket)}")
    assert all(bucket[f"tok{i}"] == [f"/mnt/c/x/wt{i}"] for i in range(n)), bucket


# ── i4-b：互不越界 · 读隔离（A 不见 B 的根）───────────────────────────────
def test_i4_b_read_isolation_no_cross_visibility(tmp_path):
    """§17-5 互不越界：两会话各 bind 各 worktree ⟹ 各自 `active_roots` **只见己方根**。"""
    st = _state(tmp_path, {}, worktree="/mnt/c/x/base")
    for tok, wt in (("sessA", "/mnt/c/x/wtA"), ("sessB", "/mnt/c/x/wtB")):
        r = subprocess.run([PY, str(SP), "wt-domain", str(st), "bind", tok, wt],
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr[-300:]
    ra = _active_roots(st, "sessA")
    rb = _active_roots(st, "sessB")
    assert "/mnt/c/x/wtA" in ra and "/mnt/c/x/wtB" not in ra, f"会话 A 越界见 B 根：{ra}"
    assert "/mnt/c/x/wtB" in rb and "/mnt/c/x/wtA" not in rb, f"会话 B 越界见 A 根：{rb}"


# ── i4-c：键单射 · 台账（N 会话并发 append 各 sid）─────────────────────────
def test_i4_c_claims_ledger_key_injective_concurrent(tmp_path):
    """§17-5 键单射：N 会话并发 append 各 sid ⟹ `live()` **sid 基数 == N**（append-only 无损）。"""
    rp = (tmp_path / "repo").resolve()
    rp.mkdir(parents=True, exist_ok=True)
    (rp / ".git").mkdir(exist_ok=True)
    n = 6
    procs = [subprocess.Popen(
        [PY, str(WC), "append", "--repo", str(rp), "--sid", f"s{i}",
         "--worktree", f"/mnt/c/x/wt{i}", "--paths", f"/mnt/c/x/wt{i}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for i in range(n)]
    rcs = [p.wait(timeout=120) for p in procs]
    assert rcs == [0] * n, "并发 append 子进程非零退出: %r" % rcs
    sids = {c.get("sid") for c in C.live(str(rp))}
    assert sids == {f"s{i}" for i in range(n)}, f"台账丢写（sid 基数 {len(sids)}/{n}）：{sorted(sids)}"
