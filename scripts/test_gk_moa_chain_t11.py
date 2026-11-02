"""
test_gk_moa_chain_t11.py -- T11 红先臂：链尾 **RC 塌缩出口**（报 `gk_finding.principal`）
================================================================================
正本：`docs/plans/2026-10-14-moa-chain-automation-plan.md` §3-T11（finding `moa-t11:principal-not-chained`）。

缺口：`gk_finding.principal`（`root_key` 精确成组 + 锚集 Jaccard + 嵌入粗筛）**零链内消费者**
—— 链尾不出 finding 级主要矛盾。本切片：链尾 `steps["principal"]` **复用** `gk_finding.principal`
（**单一源**，零新增 `_CMD_REG`）；**无合格 RC**（仅单例/孤项）⟹ `principal=None`（fail-loud）。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))


def _agg(refs: list) -> dict:
    return {
        "trace": {"count": len(refs), "attribution": {"mode": "batch_bound",
                                                      "batch_id": "66bae2b0678a"}},
        "consensus": {"n_refs": len(refs), "n_clusters": 1, "top_weight": 0.5,
                      "min_agreement": 0.66, "abstain": True, "contradictions": []},
        "clusters": [], "references": refs,
    }


def _stub(monkeypatch):
    import gk_moa_aggregate as M
    import gk_finding as F
    # 隔离主仓活体台账：principal 默认全源合并，测试须只看 tmp state。
    monkeypatch.setattr(F, "_candidate_repos",
                        lambda state_file: [str(Path(state_file).parent)])
    monkeypatch.setattr(M, "aggregate",
                        lambda *a, **k: json.loads(json.dumps(_agg([{"arm_group": "G1",
                                                                     "overall_score": 1}]))))
    monkeypatch.setattr(M, "emit_aggregate_finding", lambda *a, **k: {"ok": True, "id": "ECC-STUB"})
    monkeypatch.setattr(M, "render_html", lambda *a, **k: "<html>STUB</html>")


def _state(tmp_path, findings) -> str:
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": findings}}), encoding="utf-8")
    return str(st)


# ── ① 有根因组（size≥2）⟹ `principal` 非 None ─────────────────────────────────
def test_principal_chained_with_root_cause(tmp_path, monkeypatch):
    _stub(monkeypatch)
    finds = [{"id": "ECC-A", "root_key": "rk-1", "status": "open", "title": "同根因甲"},
             {"id": "ECC-B", "root_key": "rk-1", "status": "open", "title": "同根因乙"}]
    from gk_moa_aggregate import chain
    r = chain(_state(tmp_path, finds), batch="66bae2b0678a")
    pr = r["steps"]["principal"]
    assert pr["source"] == "gk_finding.principal", pr
    assert pr["principal"] is not None, pr
    assert pr["root_causes"] >= 1, pr


# ── ② 仅单例 ⟹ `principal=None`（fail-loud，不冒充）───────────────────────────
def test_principal_none_without_root_cause(tmp_path, monkeypatch):
    _stub(monkeypatch)
    finds = [{"id": "ECC-A", "root_key": "", "status": "open", "title": "孤项"}]
    from gk_moa_aggregate import chain
    r = chain(_state(tmp_path, finds), batch="66bae2b0678a")
    pr = r["steps"]["principal"]
    assert pr["principal"] is None, pr
    assert pr["root_causes"] == 0, pr


# ── ③ 形态臂：链接线 `gk_finding.principal`（单源 + 零新增 _CMD_REG）──────────
def test_python_wires_t11():
    src = (SCRIPTS / "gk_moa_aggregate.py").read_text(encoding="utf-8")
    assert "import gk_finding" in src, "chain 未接 RC 塌缩出口"
    assert "_F.principal(" in src, "chain 未走 gk_finding.principal（T11 单源）"
    assert '"principal"' in src, "chain 尾未落 steps.principal"
