#!/usr/bin/env python3
"""c2 红先臂：域 state「单建者」（§18.2 判据 #2 改法；2026-10-04）。

缺陷：`<repo>.<plan>` 域 state **无任何创建路径**（`gk_finding.resolve_domain_state` 纯读 fail-closed）；
`discover` 的骨架 heredoc 先截断后写、无锁、非原子。判据（§18.2 #2 / 卫星计划 §11 改法）=
两进程**并发首建** ⟹ **恰 1 个建者** + 主文件非空且 `stage` 可读 + 无一方 fail（无互锁）。

设计（用户裁：显式单建入口 + route-center 从计划 META 派生）：
  · `gk_route_center.derive_state_seed(plan, skill_dir, …)` —— **元数据中枢派生**种子
    （phase/stage 取计划 META，**非**硬编码 IDLE）。
  · `gk_state_forms.build_domain_state_exclusive(state_file, domain, seed)` —— **单建者**：
    原子 `os.link(tmp, target)`（不存在才创建、**无空窗**），竞败返回 `built=False`（不覆盖）。
  · 显式入口 = `gk_route_center.py build-state`。

臂（HEAD 必红：`build-state` 子命令与两函数均不存在）：
  · `test_concurrent_firstbuild_single_builder` 正臂（4 进程 → 恰 1 built）
  · `test_seed_phase_from_plan_meta`（standing → stage=first_phase，非 IDLE）
  · `test_existing_target_not_overwritten`（幂等：已存在 → built=False 且内容不变）
  · `test_readonly_legacy_form_refused`（只读 legacy 形态拒写）
"""
import json
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

RC = SCRIPTS / "gk_route_center.py"
PLAN_TEXT = ("<!-- META\nphases: R-SATELLITE\ntarget_repo: skill\nproject_type: standing\n"
             "worktree_needed: false\nstate_domain: skill.sat-test-plan\n-->\n# t\n")
DOMAIN = "skill.sat-test-plan"
PLAN_NAME = "2026-01-01-sat-test-plan.md"


def _mkplan(tmp_path):
    p = tmp_path / PLAN_NAME
    p.write_text(PLAN_TEXT, encoding="utf-8")
    return str(p)


def _argv(tmp_path, plan, base):
    return [sys.executable, str(RC), "build-state", "--skill-dir", str(tmp_path),
            "--plan-file", plan, "--state-file", base]


def test_concurrent_firstbuild_single_builder(tmp_path):
    """正臂：4 进程并发首建 ⟹ 恰 1 个 built；主文件唯一、内容非空、stage 可读且非 IDLE。"""
    base = str(tmp_path / ".gatekeeper.state")
    plan = _mkplan(tmp_path)
    procs = [subprocess.Popen(_argv(tmp_path, plan, base), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, cwd=str(tmp_path))
             for _ in range(4)]
    outs = []
    for p in procs:
        o, e = p.communicate()
        assert p.returncode == 0, e
        outs.append(json.loads(o))
    assert len([x for x in outs if x.get("built")]) == 1, outs          # 恰 1 个建者（单建者）
    target = tmp_path / (".gatekeeper.state." + DOMAIN)
    assert target.is_file()
    d = json.loads(target.read_text(encoding="utf-8"))
    assert d.get("stage") and d["stage"] != "IDLE", d                   # stage 可读且非 IDLE
    leftover = [p.name for p in tmp_path.iterdir()
                if p.name not in (target.name, PLAN_NAME, ".gatekeeper.state")]
    assert not leftover, leftover                                       # 无 tmp/半成品残留


def test_seed_phase_from_plan_meta(tmp_path):
    """standing 计划：stage/r_phase 取计划 META 首相位（非 IDLE）。"""
    base = str(tmp_path / ".gatekeeper.state")
    plan = _mkplan(tmp_path)
    r = subprocess.run(_argv(tmp_path, plan, base), capture_output=True, text=True, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    d = json.loads((tmp_path / (".gatekeeper.state." + DOMAIN)).read_text(encoding="utf-8"))
    assert d["stage"] == "R-SATELLITE" and d["r_phase"] == "R-SATELLITE", d


def test_existing_target_not_overwritten(tmp_path):
    """幂等：目标已存在 ⟹ built=False 且**不覆盖**（种子的 stage 不被写掉）。"""
    base = str(tmp_path / ".gatekeeper.state")
    plan = _mkplan(tmp_path)
    target = tmp_path / (".gatekeeper.state." + DOMAIN)
    target.write_text(json.dumps({"stage": "KEEP", "gate_data": {}, "monitor_scores": {},
                                  "history": []}), encoding="utf-8")
    r = subprocess.run(_argv(tmp_path, plan, base), capture_output=True, text=True, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout).get("built") is False
    assert json.loads(target.read_text(encoding="utf-8"))["stage"] == "KEEP"


def test_readonly_legacy_form_refused(tmp_path):
    """只读形态（legacy_plan）⟹ 单建者 fail-loud 拒写（HEAD 必红：函数不存在）。"""
    import gk_state_forms as SF
    assert hasattr(SF, "build_domain_state_exclusive"), "单建者未落刀（HEAD 红）"
    base = str(tmp_path / ".gatekeeper.state")
    raised = False
    try:
        SF.build_domain_state_exclusive(base, "2026-01-01-legacy-plan", {"stage": "X"})
    except Exception:
        raised = True
    assert raised, "只读 legacy 形态须拒写"
