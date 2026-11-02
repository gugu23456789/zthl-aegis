#!/usr/bin/env python3
"""遗漏⑤「open 侧回收出口」红先臂集（卫星计划 §4 · finding `ECC-3B8AAE201343`）。

范围四面（判据 = 卫星计划 §4 遗漏⑤原文）：
  ① `register` **强制点** —— 越线时 register **仍成功**（先溢出后落盘，禁自锁）；
  ② **spillover 出口** —— 越线条目 append 到 finding 卫星片（经中枢，禁第二直写者）；
  ③ **读侧 union** —— 溢出后**透明回读**（`load_findings_union` / `status` / `gk_audit_state`）；
  ④ **TTL** —— 溢出片索引叶子带 `ttl_s>0`（回收器判据在生产上恒假的复现面）。

历史病象（本臂守）：只验「越线报出」≠ 出口存在 ⟹ 必须测**溢出 + 回读闭环**；
读侧若只读主台账 ⟹ `MU_BACKCAST_NEGATIVE` 同族读分裂（写卫星、读漏片）。
"""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_finding as F  # noqa: E402


def _mkstate(tmp_path, findings=None):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": findings or []}}),
                  encoding="utf-8")
    return str(st)


def _shard_rows(state_file):
    p = Path(str(state_file) + ".finding-archive.jsonl")
    if not p.is_file():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def _main_rows(state_file):
    return json.loads(Path(state_file).read_text(encoding="utf-8"))[
        "gate_data"]["ecc_findings"]


def _register_n(state_file, n, family="SPILL-T"):
    out = []
    for i in range(n):
        out.append(F.register(state_file, "溢出臂 finding %d（复算：echo %d）" % (i, i),
                              "manual", family=family, root_key="spill-rk-%d" % i))
    return out


def test_register_forced_spillover_still_succeeds(tmp_path, monkeypatch):
    """①② 越线时 register **不拒绝**，且溢出片真产生（出口存在，非幻影门）。"""
    import gk_json_utils as JU
    monkeypatch.setattr(JU, "ECC_MAX_OPEN", 2, raising=True)
    st = _mkstate(tmp_path)
    recs = _register_n(st, 4)
    ids = [r["id"] for r in recs]
    assert all(r.get("id") for r in recs), "越线后 register 必须仍返回 id（禁自锁）"
    main = _main_rows(st)
    assert len([f for f in main if f.get("status") == "open"]) <= 2, main
    spilled = _shard_rows(st)
    assert spilled, "越线后 finding 卫星片为空 ⟹ 无回收出口（幻影门）"
    all_ids = {f.get("id") for f in main} | {f.get("id") for f in spilled}
    assert set(ids) <= all_ids, "溢出条目丢失（既不在主台账也不在片）"
    # 索引必须与片**逐条对齐**（同秒多次溢出曾撞同一叶子 ⟹ 片已落、索引未登记）
    import gk_satellite as SAT
    leaves = SAT.index_entries(st).get("finding-spillover") or {}
    assert sum(int(v.get("records") or 0) for v in leaves.values()) == len(spilled), \
        ("索引 records 与片行数不符（漏登记）：%s vs %s" % (leaves, len(spilled)))


def test_read_side_union_after_spillover(tmp_path, monkeypatch):
    """③ 溢出后读侧透明回读：union / status / 审计面都看得见（禁读分裂）。"""
    import gk_json_utils as JU
    monkeypatch.setattr(JU, "ECC_MAX_OPEN", 1, raising=True)
    st = _mkstate(tmp_path)
    ids = {r["id"] for r in _register_n(st, 4)}
    union_ids = {f.get("id") for f in F.load_findings_union(st)}
    assert ids <= union_ids, "union 回读缺条 ⟹ 读分裂"
    assert sum(F.status(st).values()) >= len(ids), F.status(st)
    import gk_audit_state as AS
    assert ids <= {f.get("id") for f in AS._findings_union(st)}


def test_write_views_stay_main_only(tmp_path, monkeypatch):
    """写路径仍 main-only（union 回写 = `MU_BACKCAST_NEGATIVE`）：溢出条目**不得**回流主台账。"""
    import gk_json_utils as JU
    monkeypatch.setattr(JU, "ECC_MAX_OPEN", 1, raising=True)
    st = _mkstate(tmp_path)
    _register_n(st, 3)
    spilled_id = next(f["id"] for f in _shard_rows(st) if f.get("status") == "open")
    try:
        F.close(st, spilled_id, "manual")
    except Exception:  # noqa: BLE001 — 冷存条目不可写（已知边界），此处只验「未回流」
        pass
    assert spilled_id not in {f.get("id") for f in _main_rows(st)}, \
        "溢出条目被写路径复制回主台账（MU_BACKCAST_NEGATIVE）"
    assert spilled_id in {f.get("id") for f in F.load_findings_union(st)}, "片内条目被误删"


def test_spillover_leaf_has_ttl_and_reclaim_sees_finding(tmp_path, monkeypatch):
    """④ TTL 生产接活：溢出片叶子 `ttl_s>0`，回收器能识别 finding kind（判据非恒假）。"""
    import gk_json_utils as JU
    import gk_satellite as SAT
    monkeypatch.setattr(JU, "ECC_MAX_OPEN", 1, raising=True)
    st = _mkstate(tmp_path)
    _register_n(st, 3)
    leaves = SAT.index_entries(st).get("finding-spillover") or {}
    assert leaves, "溢出未登记 per-arm 索引叶子（回收器够不到）"
    assert all(int(v.get("ttl_s") or 0) > 0 for v in leaves.values()), leaves
    r = SAT.reclaim(st, now=time.time() + 10 ** 7, dry_run=True)
    if r.get("ok"):
        # 刚写的片有**live 写 claim**（判活锚）⟹ 合法归入 held；过期且无锚才进 would_reclaim。
        # 两种落点都证明「回收器看得见 finding kind」；禁的是**完全不可见**。
        seen = (r.get("would_reclaim") or []) + (r.get("held") or [])
        assert any(x.get("kind") == "finding" for x in seen), r
        assert "finding" not in (r.get("shard_reclaimable") or []), \
            "片仍被 live claim 持有却被判整片可回收（误删风险）"
    else:
        # 台账不可判 ⟹ fail-closed 拒刀（合法）；此处只要求「不误判为可回收」
        assert r.get("refused"), r


def test_spillover_dry_run_zero_write(tmp_path, monkeypatch):
    """安全网：`dry_run` 只报不移（state 逐字不变、片不新增）。"""
    import gk_json_utils as JU
    monkeypatch.setattr(JU, "ECC_MAX_OPEN", 1, raising=True)
    st = _mkstate(tmp_path, [{"id": "ECC-A", "status": "open", "created_at": "2026-01-01"},
                             {"id": "ECC-B", "status": "open", "created_at": "2026-01-02"},
                             {"id": "ECC-C", "status": "open", "created_at": "2026-01-03"}])
    before = Path(st).read_text(encoding="utf-8")
    r = F.spillover_open(st, dry_run=True)
    assert r.get("capped") is True and r.get("spilled") == 2, r
    assert Path(st).read_text(encoding="utf-8") == before
    assert not _shard_rows(st)
