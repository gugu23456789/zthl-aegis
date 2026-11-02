"""端到端：复合 finding（真实 MoA 聚合 finding × 人评 overlay）× 释放批准硬门（2026-10-06）。

**为何新起本文件**：`test_gk_finding_release.py` 用 `register(root_key="moa-agg:x")` **手工造**
聚合 finding ⟹ 「真实 `emit_aggregate_finding` 产出 × 人评 overlay」这一**接缝**从未被 e2e 覆盖
（两半各自单测，复合点未联测）。本文件补该接缝。

**待验问题（owner 2026-10-06）**：
  · 生成一个 MoA 展示用 finding 后，再写几句（散文 finding）能否与**前一个** finding 复合叠加？
  · 若可 ⟹ 是否即「二次聚合」？是否复用双盲评分机制？
答（实测，见各用例）：
  · **散文 finding 不与 MoA finding 复合** —— root_key 命名空间不同（`prose:` vs `moa-agg:`）⟹ 不并。
  · 唯一复合通路 = 人评 `release-approve/reject` **定向同一 fid** ⟹ overlay 并入**同一条**记录（非新 finding）。
  · ⟹ **不是「聚合的聚合」**（仓内不存在 finding→finding 的二次聚合器）；双盲 `divergence` **被复用**，
    但仅作 **P-meta 硬门入参**（超阈须 `--final-ruling`），**不**重算评分。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_finding as F      # noqa: E402
import gk_moa_aggregate as M   # noqa: E402
import gk_prose_findings as P   # noqa: E402

PLAN = "docs/plans/2026-10-06-moa-aggregate-substance-plan.md"
BATCH = "abc123def456"   # 2026-10-10（ECC-0BA041A4284E）：须为聚合指纹（sha256[:12]，12 位十六进制）


def _state(dirpath, name="state.json"):
    """真态骨架：`gate_data.subagent_history[]` + 空 `ecc_findings[]`。"""
    hist = [{"subagent_id": "sub-%d" % i, "batch_id": BATCH, "arm_group": "G1",
             "task": "plan-refinement: %s — 质询 %s" % (PLAN, i),
             "conclusion": "结论" * 200,
             "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}
            for i in range(6)]
    p = Path(dirpath) / name
    p.write_text(json.dumps({"gate_data": {"subagent_history": hist,
                                           "ecc_findings": []}}, ensure_ascii=False),
                 encoding="utf-8")
    return str(p)


@pytest.fixture
def sf(tmp_path):
    return _state(tmp_path)


def _get(sf, fid):
    return [x for x in F.load_findings(sf) if x["id"] == fid][0]


def _moa_finding(sf):
    """真链路：aggregate() → emit_aggregate_finding()（非手工 root_key）。"""
    agg = M.aggregate(sf, None, "plan-refinement", plan=PLAN, batch=BATCH)
    res = M.emit_aggregate_finding(sf, agg, plan=PLAN, batch=BATCH)
    assert res.get("ok") is True, res
    return res["finding"]


# ── ① 真实 MoA finding 落 provisional（硬门：未批准不得下发）──────────────────

def test_real_moa_finding_is_provisional(sf):
    f = _moa_finding(sf)
    assert f["root_key"].startswith("moa-agg:"), f
    assert f["release_state"] == "provisional", f
    assert f["id"] in F.release_set(sf)["pending"]
    assert f["id"] not in F.release_set(sf)["approved"]


# ── ② 散文几句：**不**与前一个 MoA finding 复合（root_key 命名空间隔离）───────

def test_prose_sentences_do_not_merge_with_moa_finding(sf):
    f = _moa_finding(sf)
    prose = "\n".join([
        "- (M) 聚合一致度折扣链路对 p_art 通道无实样本，实效退化 P-in",
        "- (P) 计划 D12 声称 φ(κ) 未实装，已过时",
    ])
    fs = P.convert(prose, plan=PLAN, batch=BATCH)
    assert len(fs) == 2, fs
    for rec in fs:                        # 落库
        F.register(sf, rec["title"], rec["source"], root_key=rec["root_key"],
                   anchors=rec["anchors"], facets=rec["facets"],
                   source_note=rec["source_note"])
    ids = [x["id"] for x in F.load_findings(sf)]
    # 散文 finding 各起独立记录 ⟹ **未**并入 MoA finding（root_key: prose: ≠ moa-agg:）
    assert len(ids) == 3, ids
    assert f["id"] in ids
    rks = {x["root_key"].split(":")[0] for x in F.load_findings(sf)}
    assert rks == {"moa-agg", "prose"}, rks


# ── ③ 唯一复合通路：人评 overlay 定向同一 fid（release-approve）─────────────

def test_human_overlay_compounds_into_same_record(sf):
    f = _moa_finding(sf)
    before = len(F.load_findings(sf))
    # T5-a（2026-10-06）：真实 MoA finding 摄取逐臂外部内容 ⟹ provenance=untrusted；
    #   未 declassify 时 release_approved 被**溯源硬门**拒（这正是「检测非边界、容器才是」的落点）。
    assert f["provenance"] == "untrusted", f
    with pytest.raises(ValueError):
        F.set_release_state(sf, f["id"], "release_approved", by="owner")
    # 人评显式解密后放行 ⟹ 复合 overlay 并入**同一条**记录
    F.set_release_state(sf, f["id"], "release_approved", by="owner",
                        note="人评通过：三通道已接通，P-meta 由 divergence 派生",
                        declassify=True)
    after = F.load_findings(sf)
    assert len(after) == before, "复合 = overlay 并入同条，**不**新增 finding"
    g = _get(sf, f["id"])
    assert g["release_state"] == "release_approved"
    assert g["released_by"] == "owner"
    assert "P-meta" in g["release_note"]
    assert "release:release_approved" in g["facets"]      # overlay facet
    assert g["id"] in F.release_set(sf)["approved"]


# ── ④ 幂等再聚合 = 同 root_key 合并（仍不新增记录）──────────────────────────

def test_reaggregation_merges_same_root_key(sf):
    f1 = _moa_finding(sf)
    f2 = _moa_finding(sf)               # 同 (plan,batch) 二次聚合
    assert f1["id"] == f2["id"], "二次聚合按 root_key 合并，不得新增镜像"
    assert len(F.load_findings(sf)) == 1


# ── ⑤ 双盲 divergence **被复用**（作 P-meta 硬门入参，不重算评分）────────────

def test_pmeta_divergence_hard_gate_on_overlay(sf):
    f = _moa_finding(sf)
    # 超阈 + 无终裁 ⟹ 拒放行（人评自身亦可污染）
    with pytest.raises(ValueError):
        F.set_release_state(sf, f["id"], "release_approved", divergence=0.5)
    assert f["id"] not in F.release_set(sf)["approved"]
    # 超阈 + 显式人类终裁 ⟹ 放行
    F.set_release_state(sf, f["id"], "release_approved", divergence=0.5,
                        final_ruling=True)
    assert f["id"] in F.release_set(sf)["approved"]


# ── ⑥ 跨仓域（真态外部 repo）：同机制在**外仓 state** 上成立（非技能自身）────
def test_compound_on_external_repo_realm(tmp_path):
    """在**外部 repo**（夹具临时 git 仓，独立于技能仓）的域化 state 上跑「真 MoA finding →
    人评 overlay → 硬门」。

    2026-10-29（去存量跳过）：原实现由 env `GK_COMPOUND_REALM` 指向本机真实外仓，缺省即
    `pytest.skip`（存量跳过）。改为夹具**自建** git 仓 —— 「非技能自身」这一判据面照旧成立，
    且不依赖任何本机目录。

    真态纪律：**新建**独立域 state（`<外部仓>.moa-compound-test`），跑完**清理**自制工件
    （state / lock / journal），**不触**任何既有文件。
    """
    repo = tmp_path / "ext_realm"
    repo.mkdir()
    r = subprocess.run(["git", "init", "-q", str(repo)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, "夹具：外部仓初始化失败 %s" % r.stderr[-300:]
    token = "moa-compound-test"
    stem = ".gatekeeper.state." + token
    state = str(repo / stem)
    made = [state, state + ".lock", state + ".finding-journal.jsonl"]
    assert not Path(state).exists(), "拒绝覆盖既有 state：%s" % state
    try:
        Path(state).write_text(json.dumps({"gate_data": {"subagent_history": [
            {"subagent_id": "x-%d" % i, "batch_id": BATCH, "arm_group": "G1",
             "task": "plan-refinement: %s — 质询 x-%d" % (PLAN, i),
             "conclusion": "结论" * 200,
             "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}
            for i in range(6)], "ecc_findings": []}}, ensure_ascii=False),
            encoding="utf-8")
        # 域名与文件名一致（同仓域校验）
        assert F._state_file_domain(state) == token
        agg = M.aggregate(state, None, "plan-refinement", plan=PLAN, batch=BATCH)
        f = M.emit_aggregate_finding(state, agg, plan=PLAN, batch=BATCH)["finding"]
        assert f["release_state"] == "provisional"
        assert f["provenance"] == "untrusted"      # T5-a：外仓同域同规
        F.set_release_state(state, f["id"], "release_approved", by="owner",
                            note="外仓复验：复合通路成立", divergence=0.1, declassify=True)
        assert f["id"] in F.release_set(state)["approved"]
        assert len(F.load_findings(state)) == 1
    finally:
        for m in made:
            try:
                os.remove(m)
            except OSError:
                pass
