#!/usr/bin/env python3
"""T1 红先臂：MoA 聚合链骨架（`gk_moa_aggregate.chain`；正本 ECC-PLAN `2026-10-14-moa-chain-automation-plan.md` §3-T1）。

2026-10-16 更名（`ECC-70A830CA42D5`）：原 `test_gk_refine_chain.py` → 本名，与 T2+ 的
`test_gk_moa_chain_tN.py` 命名统一；命令面正式名 = `moa-aggregate --chain`（`refine-chain` 为草稿名，废弃）。

判据（**HEAD 必红** —— `chain` / `latest_batch_fingerprint` / `plm_groups` 尚不存在）：
  1) **批锚自解析**：从 `subagent_history` 取**最近一轮**指纹（禁手抄）；拒流水批号（非 12-hex）；
  2) **单一封套**：`mode=moa_chain`，含 steps（aggregate / finding / plm / convergence）；
  3) **落 finding**：有锚 ⟹ 必落（B 保护锁）；
  4) **熔断只读评估器**：T* 未冻结 ⟹ verdict=UNKNOWN，且 **breaker=False**（**非默认熔断**）；
  5) **无锚 ⟹ fail-loud**（`ok=False, error=no_anchor`）。
"""
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import gk_moa_aggregate as M  # noqa: E402

PLAN = "/p/docs/plans/x-plan.md"
BATCH = "abc123def456"


def _state(tmp_path, rows, name="state.json"):
    hist = [{"subagent_id": sid, "batch_id": bid, "arm_group": g,
             "task": "plan-refinement: %s — 质询 %s" % (PLAN, sid),
             "conclusion": "结论" * 200,
             "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}
            for (sid, bid, g) in rows]
    d = {"gate_data": {"subagent_history": hist, "ecc_findings": []}}
    p = tmp_path / name
    p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    return str(p)


def _findings(sf):
    return json.loads(Path(sf).read_text(encoding="utf-8"))["gate_data"]["ecc_findings"]


def test_latest_batch_fingerprint_picks_latest(tmp_path):
    sf = _state(tmp_path, [("sub-1", "111111111111", "G1"), ("sub-2", "222222222222", "G1")])
    assert M.latest_batch_fingerprint(sf) == "222222222222"


def test_latest_batch_fingerprint_rejects_pipeline_batch(tmp_path):
    # history 里混入流水批号（非 12-hex）⟹ 不得当批锚（否则 batch_not_fingerprint）
    sf = _state(tmp_path, [("sub-1", "111111111111", "G1"),
                           ("sub-2", "pr-1791980588-8c006e93", "G1")])
    assert M.latest_batch_fingerprint(sf) == "111111111111"


def test_plm_groups_has_carrier_keys(tmp_path):
    sf = _state(tmp_path, [("sub-%d" % i, BATCH, "G1") for i in range(6)])
    agg = M.aggregate(sf, None, "plan-refinement", plan=PLAN, batch=BATCH)
    g = M.plm_groups(agg)
    assert set(g) >= {"L", "P", "M"}, g


def test_chain_no_anchor_fail_loud(tmp_path):
    sf = _state(tmp_path, [])
    r = M.chain(sf)
    assert r["ok"] is False and r["error"] == "no_anchor", r


def test_chain_auto_resolves_batch_and_lands_finding(tmp_path):
    sf = _state(tmp_path, [("sub-%d" % i, BATCH, "G1") for i in range(6)])
    r = M.chain(sf, plan=PLAN)
    assert r["ok"] is True, r
    assert r["steps"]["batch_resolved"] == BATCH, r["steps"]
    assert r["steps"]["finding"].get("ok") is True, r["steps"]["finding"]
    assert len(_findings(sf)) == 1, _findings(sf)


def test_chain_convergence_read_only_not_default_break(tmp_path):
    """T* 未冻结 ⟹ 评估器判 UNKNOWN；`breaker` **必为 False**（熔断非默认，须评估器算出 block）。"""
    sf = _state(tmp_path, [("sub-%d" % i, BATCH, "G1") for i in range(6)])
    r = M.chain(sf, plan=PLAN)
    conv = r["steps"]["convergence"]
    assert conv["breaker"] is False, conv
    assert conv["verdict"] != "block", conv


def test_chain_cli_single_envelope(tmp_path):
    import subprocess
    sf = _state(tmp_path, [("sub-%d" % i, BATCH, "G1") for i in range(6)])
    p = subprocess.run([sys.executable, str(SCRIPT_DIR / "gk_moa_aggregate.py"),
                        "--state", sf, "--plan", PLAN, "--chain"],
                       capture_output=True, text=True)
    assert p.returncode == 0, (p.returncode, p.stderr)
    out = json.loads(p.stdout)   # stdout 单封套（禁伪拼接）
    assert out["mode"] == "moa_chain" and out["ok"] is True, out
    assert out["steps"]["finding"].get("ok") is True, out
