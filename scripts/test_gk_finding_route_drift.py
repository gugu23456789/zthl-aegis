#!/usr/bin/env python3
"""档 1 红先臂：finding **归属路由硬门**（2026-10-09 · `ECC-0319B418F9A7`）。

病象：`gk_finding.register` 写 CLI 解析到的 `STATE_FILE`（启动块跟随计划指针），**不按 finding
的归属计划路由** ⟹ 在 Y 计划活跃时登记 X 计划的 finding 必落错 state。本会话复发 2 次：
`ECC-E34434E64B82` 误落 base、`ECC-2418DB9463A2` 误落额度银行计划 state。

修法（档 1）：register 落盘前加「归属一致性」硬门 —— 复用单源 `resolve_plan_state`：
  · finding 的**裸计划锚**（`docs/plans/<X>.md`，全匹配）⟹ 读该计划 META `state_domain` → 归属 state；
  · 声明域 + 目标 state 存在 + ≠ 当前 `STATE_FILE` ⟹ 漂移候选；
  · 默认 **fail-loud** `ECC_FINDING_ROUTE_DRIFT`；`--ack-drift` 显式放行（记 `route_drift` 留痕）；
  · **仅 CLI 手工面**（`main()` register 分支 `route_hard=True`）硬拦；模块内/自动化调用跳过。

臂（HEAD 必红：无 `_route_drift_list` / 无 `ECC_FINDING_ROUTE_DRIFT`）：
  · `test_route_drift_blocks_cross_plan_register`（正臂：跨计划锚被拦）
  · `test_domain_flag_routes_to_owning_state`（正规出口：`--domain` 落归属 state）
  · `test_no_plan_anchor_no_drift`（负臂：技能级 finding 不误报）
  · `test_owning_state_no_drift`（负臂：落归属 state 本身不误报）
  · `test_target_state_missing_no_drift`（负臂：目标 state 未建 ⟹ 无法路由，零动作）
  · `test_internal_register_skips_guard`（负臂：模块内调用 `route_hard=False` 不受影响）
  · `test_ack_drift_allows_and_journals`（出口：`--ack-drift` 放行 + journal `route_drift`）
  · `test_route_drift_event_keeps_reconcile_clean`（留痕不污染 reconcile：带 fid、无假 FAIL）
"""
import json
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_finding as GF  # noqa: E402

GF_PATH = SCRIPTS / "gk_finding.py"
PLAN_REL = "docs/plans/2026-01-01-route-fixture-plan.md"
DOMAIN = "skill.2026-01-01-route-fixture-plan"


def _fixture(tmp_path, *, build_domain=True):
    """最小技能仓骨架：`docs/plans/<P>.md`（META state_domain）+ base state +（可选）域 state。"""
    plans = tmp_path / "docs" / "plans"
    plans.mkdir(parents=True, exist_ok=True)
    (plans / "2026-01-01-route-fixture-plan.md").write_text(
        "<!-- META\nphases: R9\nstate_domain: " + DOMAIN + "\n"
        "target_repo: skill\nproject_type: standing\nworktree_needed: false\n-->\n# t\n",
        encoding="utf-8", newline="\n")
    base = tmp_path / ".gatekeeper.state"
    base.write_text(json.dumps({"gate_data": {"ecc_findings": []}}),
                    encoding="utf-8", newline="\n")
    domst = tmp_path / (".gatekeeper.state." + DOMAIN)
    if build_domain:
        domst.write_text(json.dumps({"gate_data": {"ecc_findings": []}}),
                         encoding="utf-8", newline="\n")
    return str(base), str(domst)


def _run(argv):
    return subprocess.run([sys.executable, str(GF_PATH)] + argv,
                          capture_output=True, text=True)


def test_route_drift_blocks_cross_plan_register(tmp_path):
    """正臂：把「归属 P 计划」的 finding 写进 base（≠ P 域 state）⟹ fail-loud。"""
    base, _dom = _fixture(tmp_path)
    r = _run(["register", base, "跨计划锚臂", "manual", "--anchor", PLAN_REL])
    assert r.returncode != 0, r.stdout + r.stderr
    assert "ECC_FINDING_ROUTE_DRIFT" in r.stdout, r.stdout


def test_domain_flag_routes_to_owning_state(tmp_path):
    """正规出口：带 `--domain` ⟹ 落归属域 state，base 不被污染。"""
    base, domst = _fixture(tmp_path)
    r = _run(["register", base, "归属域臂", "manual", "--anchor", PLAN_REL,
              "--domain", DOMAIN])
    assert r.returncode == 0, r.stdout + r.stderr
    out = json.loads(r.stdout)
    assert out.get("ok"), out
    fid = out["finding"]["id"]
    assert fid in [f["id"] for f in GF.load_findings(domst)]
    assert not any(f.get("title") == "归属域臂" for f in GF.load_findings(base))


def test_no_plan_anchor_no_drift(tmp_path):
    """负臂：技能级 finding（只锚代码，无裸计划锚）⟹ 落 base，零动作不误报。"""
    base, _dom = _fixture(tmp_path)
    r = _run(["register", base, "技能级臂", "manual",
              "--anchor", "scripts/gk_finding.py::register"])
    assert r.returncode == 0, r.stdout + r.stderr
    assert any(f.get("title") == "技能级臂" for f in GF.load_findings(base))


def test_owning_state_no_drift(tmp_path):
    """负臂：finding 落**归属 state 本身** ⟹ 无漂移。"""
    _base, domst = _fixture(tmp_path)
    r = _run(["register", domst, "本域臂", "manual", "--anchor", PLAN_REL])
    assert r.returncode == 0, r.stdout + r.stderr
    assert any(f.get("title") == "本域臂" for f in GF.load_findings(domst))


def test_target_state_missing_no_drift(tmp_path):
    """负臂：计划声明域但目标 state **未建** ⟹ 无法路由，落 base（不误报/不臆造）。"""
    base, _dom = _fixture(tmp_path, build_domain=False)
    r = _run(["register", base, "域未建臂", "manual", "--anchor", PLAN_REL])
    assert r.returncode == 0, r.stdout + r.stderr
    assert any(f.get("title") == "域未建臂" for f in GF.load_findings(base))


def test_internal_register_skips_guard(tmp_path):
    """负臂：模块内自动化调用（`route_hard` 默认 False）**不受硬门影响**（防误伤 MoA/prose 管线）。"""
    base, _dom = _fixture(tmp_path)
    f = GF.register(base, "内部面臂", "manual", anchors=[PLAN_REL])
    assert f.get("id")
    assert any(x.get("title") == "内部面臂" for x in GF.load_findings(base))


def test_ack_drift_allows_and_journals(tmp_path):
    """出口：`--ack-drift` 显式放行 + journal 记 `route_drift`（带 fid）。"""
    base, _dom = _fixture(tmp_path)
    r = _run(["register", base, "ack放行臂", "manual", "--anchor", PLAN_REL,
              "--ack-drift"])
    assert r.returncode == 0, r.stdout + r.stderr
    fid = json.loads(r.stdout)["finding"]["id"]
    evs = [json.loads(l) for l in
           Path(base + ".finding-journal.jsonl").read_text(encoding="utf-8").splitlines()
           if l.strip()]
    assert any(e.get("event") == "route_drift" and e.get("fid") == fid for e in evs), evs


def test_route_drift_event_keeps_reconcile_clean(tmp_path):
    """零假阳：`route_drift` 事件带 fid、无 `to` ⟹ reconcile 不产假 FAIL。"""
    base, _dom = _fixture(tmp_path)
    r = _run(["register", base, "ack再臂", "manual", "--anchor", PLAN_REL, "--ack-drift"])
    assert r.returncode == 0, r.stdout + r.stderr
    fid = json.loads(r.stdout)["finding"]["id"]
    rp = GF.reconcile(base)
    assert not [a for a in rp.get("anomalies", []) if a.get("fid") == fid], rp
