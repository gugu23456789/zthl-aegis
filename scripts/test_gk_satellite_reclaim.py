"""卫星存储·**回收器 + 读面**红先臂（`ECC-0A7EBDA60149` / `ECC-2CB9AA55C53C`）。

处置目标（用户 2026-10-06「卫星存储库确保可以按预期被调用/被写入/被动态分配」）：
  · **被调用** = 卫星索引读面**单源**：消费者一律经 `gk_satellite.index_entries`，
    不再各自直读 `gate_data.satellite_index`（现网 `gk_moa_aggregate` 是第二读实现）。
  · **被动态分配** = `ttl_s` **真起作用**：`reclaim` 依 TTL 判过期；**默认 dry-run**
    （卫星基址入 claim 台账前只报不删，对齐卫星计划 §7）。
  · **被写入** = 单写者不变式（既有臂 `test_gk_satellite.py::test_converge_*` 已覆盖）。

红先对照（HEAD）：`gk_satellite.reclaim` **不存在** + `_satellite_history_union` **直读**
`satellite_index` ⟹ arm1 / arm2 必红。
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _mkstate(tmp_path):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    return str(st)


def test_read_face_is_single_source_index_entries():
    """arm1（**被调用**）：`_satellite_history_union` 须经 `gk_satellite.index_entries`
    读索引（单源单实现），**不得**直读 `gate_data.satellite_index`。HEAD 必红（直读）。"""
    import inspect
    import gk_moa_aggregate as MA
    seg = inspect.getsource(MA._satellite_history_union)
    assert "index_entries" in seg, \
        "读面未收敛到单一读源 `gk_satellite.index_entries`（第二读实现仍在）"
    # 判据 = **直读**形态（字典取值），非 docstring 里的散文提及：
    assert '.get("satellite_index")' not in seg and '["satellite_index"]' not in seg, \
        "读面仍直读 `gate_data.satellite_index`（应经中枢 index_entries）"


def test_reclaim_dry_run_reports_expired_leaf(tmp_path):
    """arm2（**被动态分配**）：`ttl_s` 过期叶子须被 `reclaim` 报为 `would_reclaim`；
    默认 dry-run ⟹ **零写盘**（state 逐字不变）。HEAD 必红（无 reclaim）。"""
    import gk_satellite as SAT
    st = _mkstate(tmp_path)
    # 直接构造一个「已过期」per-arm 叶子：last_ts 2000 年、ttl_s=60
    data = json.load(open(st, encoding="utf-8"))
    data["gate_data"]["satellite_index"] = {
        "b-old": {"A": {"kind": "pipeline", "file": "x", "arm": "A", "records": 3,
                        "bytes": 9, "first_ts": "2000-01-01T00:00:00+00:00",
                        "last_ts": "2000-01-01T00:00:00+00:00", "ttl_s": 60}}}
    open(st, "w", encoding="utf-8").write(json.dumps(data, ensure_ascii=False))
    before = open(st, encoding="utf-8").read()
    r = SAT.reclaim(st, now=1_600_000_000.0)  # 2020-09-13（远超 2000 年 + 60s）
    assert r.get("ok"), r
    assert r.get("dry_run") is True, "回收默认须 dry-run"
    got = {("%s/%s" % (x["batch_id"], x["arm"])) for x in r.get("would_reclaim", [])}
    assert "b-old/A" in got, "过期叶子未被报出：%r" % (r,)
    assert open(st, encoding="utf-8").read() == before, "dry-run 竟写了盘（应零写）"


def test_reclaim_ignores_fresh_or_no_ttl(tmp_path):
    """arm3（负臂·防假绿）：`ttl_s==0`（无 TTL）或未过期者**不得**进 `would_reclaim`。"""
    import gk_satellite as SAT
    st = _mkstate(tmp_path)
    data = json.load(open(st, encoding="utf-8"))
    data["gate_data"]["satellite_index"] = {
        "b-noTTL": {"A": {"kind": "pipeline", "arm": "A", "ttl_s": 0,
                          "last_ts": "2000-01-01T00:00:00+00:00"}},
        "b-fresh": {"B": {"kind": "history", "arm": "B", "ttl_s": 10 ** 9,
                          "last_ts": "2020-09-13T00:00:00+00:00"}}}
    open(st, "w", encoding="utf-8").write(json.dumps(data, ensure_ascii=False))
    r = SAT.reclaim(st, now=1_600_000_000.0)
    got = {("%s/%s" % (x["batch_id"], x["arm"])) for x in r.get("would_reclaim", [])}
    assert got == set(), "无 TTL / 新鲜者被误报为过期：%r" % (got,)


def test_reclaim_apply_tombstones_and_never_deletes_live_shard(tmp_path):
    """arm4（apply 面）：`dry_run=False` ⟹ 过期叶子被打**墓碑**（`reclaimed_ts`）；
    但**仍有 live 臂**的 kind 片**不得**被删（多臂共享片，单臂过期不删整片）。"""
    import gk_satellite as SAT
    st = _mkstate(tmp_path)
    shard = SAT.shard_path(st, "pipeline")
    open(shard, "a", encoding="utf-8").write('{"id":1}\n')
    data = json.load(open(st, encoding="utf-8"))
    data["gate_data"]["satellite_index"] = {
        "b1": {"OLD": {"kind": "pipeline", "arm": "OLD", "ttl_s": 60,
                       "last_ts": "2000-01-01T00:00:00+00:00"},
               "NEW": {"kind": "pipeline", "arm": "NEW", "ttl_s": 10 ** 9,
                       "last_ts": "2020-09-13T00:00:00+00:00"}}}
    open(st, "w", encoding="utf-8").write(json.dumps(data, ensure_ascii=False))
    r = SAT.reclaim(st, now=1_600_000_000.0, dry_run=False)
    assert r.get("ok") and r.get("dry_run") is False, r
    assert os.path.isfile(shard), "仍有 live 臂却删了整片（单臂过期不得删共享片）"
    d = json.load(open(st, encoding="utf-8"))
    old = d["gate_data"]["satellite_index"]["b1"]["OLD"]
    assert old.get("reclaimed_ts"), "过期叶子未打墓碑（应留可审计痕迹）"
    new = d["gate_data"]["satellite_index"]["b1"]["NEW"]
    assert not new.get("reclaimed_ts"), "live 叶子被误打墓碑"
