"""
test_gk_moa_chain_t15.py -- 幂等键红先臂（③-A 聚合键去 plan / ③-B 散文键加作用域）
================================================================================
正本：`docs/plans/2026-10-14-moa-chain-automation-plan.md` §5 ③（findings
`ECC-F06E509BF5F3` 聚合键 / `ECC-08E30B02B2F1` 散文键）。

实测缺口（scratch 探针，2026-10-16）：
  · 聚合 finding：`root_key = sha256("<plan>|<batch>")` ⟹ **计划改名 = 新键 = 重复记账**
    （两条同标题、不同 id）。
  · 散文 finding：`root_key = sha256(title)` ⟹ **同句跨计划/跨批被吞成一条**。
本切片：聚合键**以批指纹为主**（plan 仅 plan-only 兜底）；散文键**含 plan|batch 作用域**
（两者皆空 ⟹ 退回仅 title，与旧直调行为逐字一致）。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_finding as F          # noqa: E402
import gk_moa_aggregate as M    # noqa: E402
import gk_prose_findings as PF  # noqa: E402

BATCH = "66bae2b0678a"
PLAN_A = "docs/plans/plan-A.md"
PLAN_B = "docs/plans/plan-A-renamed.md"   # 同一计划的**改名后**路径


def _state(tmp_path) -> str:
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": []}}), encoding="utf-8")
    return str(st)


def _agg() -> dict:
    return {"trace": {"count": 1, "suspect_count": 0,
                      "attribution": {"mode": "batch_bound", "batch_id": BATCH}},
            "consensus": {"n_refs": 1, "n_clusters": 1, "top_weight": 0.5,
                          "min_agreement": 0.66, "abstain": True, "contradictions": []},
            "clusters": [], "references": [{"arm_group": "G1", "overall_score": 1}]}


def _emit(sf: str, plan: str, batch: str = BATCH) -> str:
    """经**真实** `emit_aggregate_finding` 落一条聚合 finding（禁复制键公式）。"""
    return M.emit_aggregate_finding(sf, _agg(), plan=plan, batch=batch)["finding"]["id"]


def _reg_prose(sf: str, plan: str, batch: str = BATCH) -> str:
    """经**真实** `convert` 取键 + `register` 落一条散文 finding（禁复制键公式）。"""
    fs = PF.convert("- 散文结论甲(P)", plan=plan, batch=batch)
    assert fs, "散文未解析出条目"
    f = fs[0]
    return F.register(sf, f["title"], f["source"], root_key=f["root_key"],
                      anchors=f["anchors"], facets=f["facets"],
                      provenance="untrusted")["id"]


def _n(sf: str) -> int:
    return len(json.loads(Path(sf).read_text(encoding="utf-8"))
               ["gate_data"]["ecc_findings"])


# ── ① 回归护栏：同 plan + 同 batch ×2 ⟹ 同 id（不新增镜像）─────────────────────
def test_agg_same_plan_same_batch_idempotent(tmp_path):
    sf = _state(tmp_path)
    a, b = _emit(sf, PLAN_A), _emit(sf, PLAN_A)
    assert a == b, (a, b)
    assert _n(sf) == 1, _n(sf)


# ── ② ③-A 红先：**计划改名 + 同 batch ⟹ 同 id**（HEAD 必红：旧键含 plan）───────
def test_agg_plan_rename_same_batch_is_idempotent(tmp_path):
    sf = _state(tmp_path)
    a = _emit(sf, PLAN_A)
    b = _emit(sf, PLAN_B)   # 只改计划名，batch 不变
    assert a == b, "计划改名不应产生重复记账（ECC-F06E509BF5F3）"
    assert _n(sf) == 1, _n(sf)


# ── ③ 回归护栏：散文同句 + 同 plan ×2 ⟹ 同 id ────────────────────────────────
def test_prose_same_scope_idempotent(tmp_path):
    sf = _state(tmp_path)
    a, b = _reg_prose(sf, PLAN_A), _reg_prose(sf, PLAN_A)
    assert a == b, (a, b)
    assert _n(sf) == 1, _n(sf)


# ── ④ ③-B 红先：**散文同句 + 异 plan ⟹ 异 id**（HEAD 必红：旧键仅 title）─────
def test_prose_cross_plan_not_merged(tmp_path):
    sf = _state(tmp_path)
    a = _reg_prose(sf, PLAN_A)
    b = _reg_prose(sf, PLAN_B)
    assert a != b, "同句出现在两个计划不应被吞成一条（ECC-08E30B02B2F1）"
    assert _n(sf) == 2, _n(sf)


# ── ⑤ 兼容臂：plan/batch 皆空（`from-prose` 直调）⟹ 退回仅 title（零回归）─────
def test_prose_scope_absent_falls_back_to_title(tmp_path):
    sf = _state(tmp_path)
    a = _reg_prose(sf, "", batch="")
    b = _reg_prose(sf, "", batch="")
    assert a == b, (a, b)
    assert _n(sf) == 1, _n(sf)
