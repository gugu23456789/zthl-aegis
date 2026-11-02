"""卫星存储·**遗漏③（claim 判活锚 + 独立枚举面）**红先臂（`ECC-AB36651AAA0B`）。

背景（cross-review arm 原话）：卫星片**不在 claim 台账**，且 `.jsonl` 旁挂被 `state_form` 判
artifact ⟹ `iter_live_states` **天然看不见片** ⟹ 「TTL 到归档压缩」的回收器若复用既有枚举面
将**永久漏扫**。故遗漏③ = ① **独立枚举面**（`gk_satellite.shards`）+ ② **判活锚**（片基址入
`gk_write_claims` 台账；`reclaim` 对 live-claim 覆盖的片 `held`，即便 TTL 过期）。

红先对照（HEAD）：`shards` / `claim_anchor` **不存在**；`reclaim` **不查台账** ⟹ arm1/2/3 必红。
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _mkstate(tmp_path):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    return str(st)


def test_shards_independent_enumeration(tmp_path):
    """arm1（独立枚举面）：`shards` 显式列出三 kind 的片（存在性 + 字节），
    不依赖 `iter_live_states`（后者看不见 `.jsonl` 旁挂）。HEAD 必红。"""
    import gk_satellite as SAT
    st = _mkstate(tmp_path)
    open(SAT.shard_path(st, "pipeline"), "a", encoding="utf-8").write('{"id":1}\n')
    got = {s["kind"]: s for s in SAT.shards(st)}
    assert set(got) == set(SAT.KIND_SUFFIX), "枚举面未覆盖全部 kind：%r" % (sorted(got),)
    assert got["pipeline"]["exists"] is True and got["pipeline"]["bytes"] > 0
    assert got["history"]["exists"] is False


def test_claim_anchor_registers_shard(tmp_path):
    """arm2（判活锚）：`claim_anchor` 把片基址写进 write-claims 台账（live claim whose
    paths 含片路径）。HEAD 必红（无 claim_anchor）。"""
    import gk_satellite as SAT
    import gk_write_claims as WC
    ledger = tmp_path / ".gatekeeper.write-claims.jsonl"
    os.environ["GK_WRITE_CLAIMS_PATH"] = str(ledger)
    try:
        st = _mkstate(tmp_path)
        open(SAT.shard_path(st, "history"), "a", encoding="utf-8").write("{}\n")
        r = SAT.claim_anchor(st, sid="batch-1", ttl_s=3600)
        assert r.get("ok"), r
        lives = WC.live()
        assert lives, "claim_anchor 未落 live claim"
        base = os.path.basename(SAT.shard_path(st, "history"))
        anchored = [str(p) for c in lives for p in (c.get("paths") or [])
                    if os.path.basename(str(p).replace("\\", "/")) == base]
        assert anchored, "live claim 的 paths 未含片基址：%r" % (lives,)
    finally:
        os.environ.pop("GK_WRITE_CLAIMS_PATH", None)


def test_reclaim_holds_shard_with_live_claim(tmp_path):
    """arm3（判活锚生效）：过期叶子但其片被 **live claim** 覆盖 ⟹ `held`，**不进**
    `would_reclaim`（TTL 过期不足以回收在用片）。HEAD 必红（reclaim 不查台账）。"""
    import gk_satellite as SAT
    ledger = tmp_path / ".gatekeeper.write-claims.jsonl"
    os.environ["GK_WRITE_CLAIMS_PATH"] = str(ledger)
    try:
        st = _mkstate(tmp_path)
        open(SAT.shard_path(st, "pipeline"), "a", encoding="utf-8").write('{"id":1}\n')
        d = json.load(open(st, encoding="utf-8"))
        d["gate_data"]["satellite_index"] = {
            "b1": {"A": {"kind": "pipeline", "arm": "A", "ttl_s": 60,
                         "last_ts": "2000-01-01T00:00:00+00:00"}}}
        open(st, "w", encoding="utf-8").write(json.dumps(d, ensure_ascii=False))
        SAT.claim_anchor(st, sid="live-batch", ttl_s=3600)
        r = SAT.reclaim(st, now=time.time())
        held = {("%s/%s" % (x["batch_id"], x["arm"])) for x in r.get("held", [])}
        would = {("%s/%s" % (x["batch_id"], x["arm"])) for x in r.get("would_reclaim", [])}
        assert "b1/A" in held, "live-claim 覆盖的片未被 held：%r" % (r,)
        assert "b1/A" not in would, "live-claim 覆盖的片仍被判可回收（判活锚未生效）"
    finally:
        os.environ.pop("GK_WRITE_CLAIMS_PATH", None)


def test_reclaim_without_claim_still_reports_expired(tmp_path):
    """arm4（负臂·零回归）：**无** claim 时过期叶子仍进 `would_reclaim`（不应因加判活锚而漏报）。"""
    import gk_satellite as SAT
    os.environ["GK_WRITE_CLAIMS_PATH"] = str(tmp_path / ".gatekeeper.write-claims.jsonl")
    try:
        st = _mkstate(tmp_path)
        d = json.load(open(st, encoding="utf-8"))
        d["gate_data"]["satellite_index"] = {
            "b1": {"A": {"kind": "pipeline", "arm": "A", "ttl_s": 60,
                         "last_ts": "2000-01-01T00:00:00+00:00"}}}
        open(st, "w", encoding="utf-8").write(json.dumps(d, ensure_ascii=False))
        r = SAT.reclaim(st, now=1_600_000_000.0)
        would = {("%s/%s" % (x["batch_id"], x["arm"])) for x in r.get("would_reclaim", [])}
        assert "b1/A" in would, "无 claim 时过期片漏报（%r）" % (r,)
    finally:
        os.environ.pop("GK_WRITE_CLAIMS_PATH", None)


# ═══════════ 生产者接线（`append` → 判活锚）（`ECC-078AAECF33FB`）═══════════
# 遗漏（cross-review）：`claim_anchor` 已实装但**无生产调用点** ⟹ 只有测试手调才落锚；真实生产路径
# （`gk_satellite.append`）产的片**无锚** ⟹ 一旦 `reclaim` 从 dry-run 转 live，在用片即可被误删。
# 本簇把锚**接进生产者**（片一落盘即登记），并钉住两点：① 两种模式都锚；② 锚与回收**端到端**生效。
# 红先对照（HEAD）：`append` 从不触碰台账 ⟹ arm5/6/7/8 必红。


def test_append_auto_anchors_shard(tmp_path):
    """arm5（生产者自动锚）：`append`（standalone）落片后自动登记判活锚 —— live claim 含片基址。HEAD 必红。"""
    import gk_satellite as SAT
    import gk_write_claims as WC
    os.environ["GK_WRITE_CLAIMS_PATH"] = str(tmp_path / ".gatekeeper.write-claims.jsonl")
    try:
        st = _mkstate(tmp_path)
        r = SAT.append(st, "pipeline", [{"id": 1}], batch_id="b1", arm="A")
        assert r.get("ok"), r
        base = os.path.basename(SAT.shard_path(st, "pipeline"))
        anchored = [str(p) for c in WC.live() for p in (c.get("paths") or [])
                    if os.path.basename(str(p).replace("\\", "/")) == base]
        assert anchored, "append 未自动登记判活锚（片未被 claim 覆盖）：%r" % (WC.live(),)
    finally:
        os.environ.pop("GK_WRITE_CLAIMS_PATH", None)


def test_append_in_tx_also_anchors(tmp_path):
    """arm6（in-tx 模式也锚）：`gd` 非 None ⟹ 片已落盘，锚与 state 事务无关，**同样**须登记。HEAD 必红。"""
    import gk_satellite as SAT
    import gk_write_claims as WC
    os.environ["GK_WRITE_CLAIMS_PATH"] = str(tmp_path / ".gatekeeper.write-claims.jsonl")
    try:
        st = _mkstate(tmp_path)
        gd = {}
        r = SAT.append(st, "history", [{"k": 1}], batch_id="b1", arm="A", gd=gd)
        assert r.get("ok"), r
        assert WC.live(), "in-tx append 未登记判活锚：%r" % (WC.live(),)
    finally:
        os.environ.pop("GK_WRITE_CLAIMS_PATH", None)


def test_reclaim_holds_shard_written_by_append(tmp_path):
    """arm7（端到端 · 生产者→锚→回收）：`append` 后其片即便叶子 TTL 过期也 `held`（不被回收）。HEAD 必红。"""
    import gk_satellite as SAT
    os.environ["GK_WRITE_CLAIMS_PATH"] = str(tmp_path / ".gatekeeper.write-claims.jsonl")
    try:
        st = _mkstate(tmp_path)
        SAT.append(st, "pipeline", [{"id": 1}], batch_id="b1", arm="A")
        d = json.load(open(st, encoding="utf-8"))
        d.setdefault("gate_data", {})["satellite_index"] = {
            "b1": {"A": {"kind": "pipeline", "arm": "A", "ttl_s": 60,
                         "last_ts": "2000-01-01T00:00:00+00:00"}}}
        open(st, "w", encoding="utf-8").write(json.dumps(d, ensure_ascii=False))
        r = SAT.reclaim(st, now=time.time())
        held = {("%s/%s" % (x["batch_id"], x["arm"])) for x in r.get("held", [])}
        would = {("%s/%s" % (x["batch_id"], x["arm"])) for x in r.get("would_reclaim", [])}
        assert "b1/A" in held, "生产者产的片未被判活锚 held（回收面可误删）：%r" % (r,)
        assert "b1/A" not in would, "生产者产的片仍被判可回收（锚未端到端生效）"
    finally:
        os.environ.pop("GK_WRITE_CLAIMS_PATH", None)


def test_anchor_sid_unique_per_state(tmp_path):
    """arm8（负臂 · 防跨 state 遮蔽）：两 state 各自 `append` ⟹ **两条** live claim（sid 互异）。

    `live()` 对每个 sid **只取最后一条** ⟹ 若生产者用**同一** sid（如恒定 `"satellite"`），后写者会
    顶掉先写者 ⟹ 先者片**静默失锚**。本臂钉住「每 state 一 sid」。HEAD 必红（无自动锚）。
    """
    import gk_satellite as SAT
    import gk_write_claims as WC
    os.environ["GK_WRITE_CLAIMS_PATH"] = str(tmp_path / ".gatekeeper.write-claims.jsonl")
    try:
        sa = tmp_path / ".gatekeeper.state.a"
        sb = tmp_path / ".gatekeeper.state.b"
        for p in (sa, sb):
            p.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
        SAT.append(str(sa), "history", [{}], batch_id="b1", arm="A")
        SAT.append(str(sb), "history", [{}], batch_id="b1", arm="A")
        lives = WC.live()
        sids = {c.get("sid") for c in lives}
        assert len(lives) == 2 and len(sids) == 2, (
            "两 state 的锚被同一 sid 遮蔽（后写者顶掉先写者）⟹ 先者片失锚：%r" % (lives,))
    finally:
        os.environ.pop("GK_WRITE_CLAIMS_PATH", None)

