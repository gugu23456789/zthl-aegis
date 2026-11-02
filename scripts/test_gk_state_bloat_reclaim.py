"""state 撑爆闭环 · 红先臂（`ECC-2A298C57FF7E` 回收闭环 / `ECC-43D22663EFB5` ecc 封顶）。

对 HEAD **必红**（红先对照）：
  · A1 生产 `append` 落的 per-arm 叶子 `ttl_s` 恒 0 ⟹ `reclaim` 过期判据在生产上**恒假**
    （卫星计划 §4.2「判据真、生产假活」）。
  · A2 claim 台账不可判时 `reclaim` 仍放行（`_live_claim_sids_for_shards` 现回 `{}` = fail-open）。
  · A4 `gatekeeper-cli.sh` 无卫星片回收的**生产入口**（`reclaim` 零生产调用点）。
  · A5/A6 `ecc_findings` 的 `open` 越 `ECC_MAX_OPEN` 不溢出 ⟹ open 无出口、主 state 单调撑爆
    （`gk_json_utils.ECC_MAX_*` 只读体检不强制；`load_findings` 无 archive union = 读分裂面）。
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
SKILL_DIR = os.path.dirname(HERE)
CLI = os.path.join(SKILL_DIR, "gatekeeper-cli.sh")


def _mkstate(tmp_path, gd=None):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": gd or {}}), encoding="utf-8")
    return str(st)


# ── A1（T2/R6）：生产 append 的叶子须可过期 ──────────────────────────────
def test_A1_production_append_leaf_has_nonzero_ttl(tmp_path, monkeypatch):
    """生产路径（**不显式传** `ttl_s`）落下的叶子，其 `ttl_s` 须非 0。"""
    monkeypatch.setenv("GK_CLAIM_TTL_S", "3600")
    import gk_satellite as SAT
    st = _mkstate(tmp_path)
    r = SAT.append(st, "pipeline", [{"id": 1}], batch_id="b1", arm="A")
    assert r.get("ok"), r
    leaf = SAT.index_entries(st, "b1").get("A")
    assert leaf and int(leaf.get("ttl_s", 0)) > 0, \
        "生产 append 落的叶子 ttl_s 仍为 0（过期判据在生产上恒假）：%r" % (leaf,)


# ── A2（R1/T3）：台账不可判 ⟹ 拒刀 ──────────────────────────────────────
def test_A2_reclaim_refuses_when_ledger_unavailable(tmp_path, monkeypatch):
    """claim 台账不可判 ⟹ `reclaim(dry_run=False)` 必须**拒刀**且 state 逐字不变。"""
    import gk_satellite as SAT
    import gk_write_claims as WC
    st = _mkstate(tmp_path, {"satellite_index": {
        "b1": {"A": {"kind": "pipeline", "arm": "A", "ttl_s": 60,
                     "last_ts": "2000-01-01T00:00:00+00:00"}}}})
    with open(SAT.shard_path(st, "pipeline"), "a", encoding="utf-8") as fh:
        fh.write('{"id":1}\n')

    def _boom(*a, **k):
        raise OSError("ledger unavailable")

    monkeypatch.setattr(WC, "read_all", _boom)
    before = open(st, encoding="utf-8").read()
    r = SAT.reclaim(st, now=1_600_000_000.0, dry_run=False)
    assert r.get("ok") is False or r.get("refused"), \
        "台账不可判竟未拒刀（fail-open）：%r" % (r,)
    assert open(st, encoding="utf-8").read() == before, "拒刀后 state 被改写（应逐字不变）"


# ── A3（R4）：二次 apply 幂等 ────────────────────────────────────────────
def test_A3_reclaim_apply_is_idempotent(tmp_path):
    """二次 `apply` 对同一过期叶子幂等（墓碑不因重跑改变）。"""
    import gk_satellite as SAT
    st = _mkstate(tmp_path, {"satellite_index": {
        "b1": {"A": {"kind": "pipeline", "arm": "A", "ttl_s": 60,
                     "last_ts": "2000-01-01T00:00:00+00:00"}}}})
    with open(SAT.shard_path(st, "pipeline"), "a", encoding="utf-8") as fh:
        fh.write('{"id":1}\n')
    SAT.reclaim(st, now=1_600_000_000.0, dry_run=False)
    d1 = json.load(open(st, encoding="utf-8"))["gate_data"]["satellite_index"]["b1"]["A"]["reclaimed_ts"]
    SAT.reclaim(st, now=1_600_000_100.0, dry_run=False)
    d2 = json.load(open(st, encoding="utf-8"))["gate_data"]["satellite_index"]["b1"]["A"]["reclaimed_ts"]
    assert d1 == d2, "二次 apply 改变了墓碑（非幂等）：%r != %r" % (d1, d2)


# ── A4（T1）：生产入口存在 ──────────────────────────────────────────────
def test_A4_cli_has_satellite_reclaim_entry():
    """`gatekeeper-cli.sh` 须存在卫星片回收的**可达生产入口**。"""
    src = open(CLI, encoding="utf-8").read()
    assert "satellite-reclaim" in src, \
        "gatekeeper-cli.sh 无 satellite 回收生产入口（回收器够不到片 = 幻影门）"


# ── A5（遗漏⑤）：open 越线须溢出且 register 仍成功 ────────────────────────
def test_A5_register_spills_open_over_cap(tmp_path, monkeypatch):
    """open 集越 `ECC_MAX_OPEN` ⟹ `register` 须**溢出**（主 state open 不越线）且**仍成功**。"""
    import gk_json_utils as JU
    import gk_finding as GF
    monkeypatch.setattr(JU, "ECC_MAX_OPEN", 3)
    monkeypatch.setattr(JU, "ECC_MAX_ENTRIES", 10 ** 9)
    monkeypatch.setattr(JU, "ECC_MAX_BYTES", 10 ** 9)
    st = _mkstate(tmp_path)
    for i in range(6):
        out = GF.register(st, "title-%d" % i, "manual")
        assert out and out.get("id"), "register 被拒（自锁）：%r" % (out,)
    main = json.load(open(st, encoding="utf-8"))["gate_data"]["ecc_findings"]
    n_open = sum(1 for f in main if f.get("status") == "open")
    assert n_open <= 3, "open 越线未溢出（主 state 仍撑）：n_open=%d" % n_open
    allf = GF.load_findings_union(st)
    assert len({f.get("id") for f in allf}) >= 6, "溢出后读面丢条目（读分裂）"


# ── A6：读侧 union 单源、缺片不崩 ────────────────────────────────────────
def test_A6_union_keeps_single_source(tmp_path, monkeypatch):
    """`load_findings_union` ⊇ 主 + 溢出片；条目数不丢。"""
    import gk_json_utils as JU
    import gk_finding as GF
    monkeypatch.setattr(JU, "ECC_MAX_OPEN", 1)
    monkeypatch.setattr(JU, "ECC_MAX_ENTRIES", 10 ** 9)
    monkeypatch.setattr(JU, "ECC_MAX_BYTES", 10 ** 9)
    st = _mkstate(tmp_path)
    for i in range(3):
        GF.register(st, "u-%d" % i, "manual")
    ids = {f.get("id") for f in GF.load_findings_union(st)}
    assert len(ids) == 3, "union 未覆盖溢出片：%r" % (sorted(ids),)


# ── A7（§7）：kill switch `GK_SATELLITE=0` 须有代码载体（禁幻影回退）──────────
def test_A7_killswitch_disables_reclaim(tmp_path, monkeypatch):
    """`GK_SATELLITE=0` ⟹ `reclaim` **旁路**（拒刀、不写墓碑）—— 原为零代码载体的幻影回退。"""
    import gk_satellite as SAT
    st = _mkstate(tmp_path, {"satellite_index": {
        "b1": {"A": {"kind": "pipeline", "arm": "A", "ttl_s": 60,
                     "last_ts": "2000-01-01T00:00:00+00:00"}}}})
    with open(SAT.shard_path(st, "pipeline"), "a", encoding="utf-8") as fh:
        fh.write('{"id":1}\n')
    monkeypatch.setenv("GK_SATELLITE", "0")
    before = open(st, encoding="utf-8").read()
    r = SAT.reclaim(st, now=1_600_000_000.0, dry_run=False)
    assert r.get("disabled"), "GK_SATELLITE=0 未旁路 reclaim（幻影回退）：%r" % (r,)
    assert open(st, encoding="utf-8").read() == before, "kill switch 下仍改写了 state"


# ── A8（T5）：存量片 ttl_s 回填 ─────────────────────────────────────────
def test_A8_backfill_stamps_missing_ttl(tmp_path, monkeypatch):
    """存量叶子 `ttl_s<=0` ⟹ `backfill_ttl` 须补上（否则 reclaim 永不判其过期）。"""
    monkeypatch.setenv("GK_CLAIM_TTL_S", "3600")
    import gk_satellite as SAT
    st = _mkstate(tmp_path, {"satellite_index": {
        "b1": {"A": {"kind": "pipeline", "arm": "A", "ttl_s": 0,
                     "last_ts": "2000-01-01T00:00:00+00:00"}}}})
    r = SAT.backfill_ttl(st)
    assert r.get("ok") and r.get("backfilled") == 1, r
    leaf = json.load(open(st, encoding="utf-8"))["gate_data"]["satellite_index"]["b1"]["A"]
    assert int(leaf.get("ttl_s", 0)) > 0, "存量叶 ttl_s 未回填：%r" % (leaf,)


def test_A9_backfill_is_idempotent(tmp_path, monkeypatch):
    """二次 `backfill_ttl` 幂等（不再回填）。"""
    monkeypatch.setenv("GK_CLAIM_TTL_S", "3600")
    import gk_satellite as SAT
    st = _mkstate(tmp_path, {"satellite_index": {
        "b1": {"A": {"kind": "pipeline", "arm": "A", "ttl_s": 0,
                     "last_ts": "2000-01-01T00:00:00+00:00"}}}})
    SAT.backfill_ttl(st)
    r2 = SAT.backfill_ttl(st)
    assert r2.get("backfilled") == 0, "二次回填非幂等：%r" % (r2,)


# ── A10（遗漏⑤ byte 轴）：越 ECC_MAX_BYTES 须自清 ───────────────────────
def test_A10_register_spills_over_byte_cap(tmp_path, monkeypatch):
    """`ecc_findings` 序列化**字节**越 `ECC_MAX_BYTES`（**主判据**）⟹ 须溢出（保留 ≥1 条），
    且读侧 union 不丢条目。"""
    import json as _j
    import gk_json_utils as JU
    import gk_finding as GF
    monkeypatch.setattr(JU, "ECC_MAX_OPEN", 10 ** 9)
    monkeypatch.setattr(JU, "ECC_MAX_ENTRIES", 10 ** 9)
    monkeypatch.setattr(JU, "ECC_MAX_BYTES", 2500)
    st = _mkstate(tmp_path)
    for i in range(6):
        GF.register(st, "byte-title-%d" % i, "manual")
    main = json.load(open(st, encoding="utf-8"))["gate_data"]["ecc_findings"]
    n = len(_j.dumps(main, ensure_ascii=False).encode("utf-8"))
    assert n <= 2500 or len(main) <= 1, \
        "byte 越线未溢出：size=%d n=%d（cap=2500）" % (n, len(main))
    assert len({f.get("id") for f in GF.load_findings_union(st)}) >= 6, \
        "溢出后读面丢条目（读分裂）"


# ── A11（B）：受约束的『强制 spillover』生产入口 ─────────────────────────
def test_A11_cli_has_finding_spill_entry():
    """`gatekeeper-cli.sh` 须存在 `ecc_findings` 越线的**显式** spillover 入口（单源=spillover_open）。"""
    src = open(CLI, encoding="utf-8").read()
    assert "finding-spill" in src, "CLI 无 finding-spill 生产入口（清墙只能靠 register 隐式触发）"
    assert "spillover_open" in src, "finding-spill 未接单源 spillover_open"


# ── A12（B）：spillover 的 dry-run 安全网 ────────────────────────────────
def test_A12_spillover_dry_run_writes_nothing(tmp_path, monkeypatch):
    """`spillover_open(dry_run=True)` ⟹ 只报不移（state 逐字不变）；`dry_run=False` ⟹ 真移。"""
    import gk_json_utils as JU
    import gk_finding as GF
    monkeypatch.setattr(JU, "ECC_MAX_BYTES", 10 ** 9)
    monkeypatch.setattr(JU, "ECC_MAX_ENTRIES", 10 ** 9)
    st = _mkstate(tmp_path)
    for i in range(4):
        GF.register(st, "spill-dry-%d" % i, "manual")
    before = open(st, encoding="utf-8").read()
    r = GF.spillover_open(st, max_open=2, dry_run=True)
    assert r.get("spilled") == 2 and r.get("dry_run") is True, "dry-run 未报出计划：%r" % (r,)
    assert open(st, encoding="utf-8").read() == before, "dry-run 竟改写了 state"
    r2 = GF.spillover_open(st, max_open=2)
    assert r2.get("spilled") == 2, "apply 未真移：%r" % (r2,)
    main = json.load(open(st, encoding="utf-8"))["gate_data"]["ecc_findings"]
    assert sum(1 for f in main if f.get("status") == "open") <= 2, "apply 后 open 未降至 cap"


# ── A13（ECC-A48A8204B877）：备份文件不得被当域读入 ──────────────────────
def test_A13_bak_compact_backup_not_read_as_domain(tmp_path):
    """`bak-compact-*` 备份旁挂 ⟹ **`_iter_sources`/`cross_domain_dups`** 不得把它当域读。

    根因：`_iter_sources` 用**自己的内联过滤**（`endswith((".lock",".seal",".tmp")) or ".jsonl" in name`），
    **未复用单源判据 `_is_live_ledger_name`** ⟹ 漏 `bak-*`/`corrupt-*`/`pre-budget` 等产物标记。
    """
    import gk_finding as GF
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": [
        {"id": "ECC-A1", "root_key": "rk", "status": "open"}]}}), encoding="utf-8")
    bak = tmp_path / ".gatekeeper.state.bak-compact-20261005T161823Z"
    bak.write_text(json.dumps({"gate_data": {"ecc_findings": [
        {"id": "ECC-A2", "root_key": "rk", "status": "open"}]}}), encoding="utf-8")
    # 单源判据本身须已排除（现状即绿：marker "bak-" 生效）
    assert GF._is_live_ledger_name(bak.name) is False, "备份名被判为活体域"
    srcs = [lab for lab, _fs in GF._iter_sources(str(st))]
    assert all("bak-compact" not in lab for lab in srcs), \
        "_iter_sources 把备份当域读入（虚报/假双源）：%r" % (srcs,)
    assert GF.cross_domain_dups(str(st)) == [], "备份造成假跨域双源（同 root_key 被读成两域）"


if __name__ == "__main__":
    raise SystemExit(__import__("pytest").main([__file__, "-v"]))
