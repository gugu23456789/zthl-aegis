#!/usr/bin/env python3
"""红队向量登记表（数据化）红先臂（2026-11-01）。

判据：
  1. 登记表 = 单一事实源：schema/唯一 id/必填字段；
  2. **代码 ↔ 登记表双向集合等价**：代码多一条 ⟹ 「未登记」；表多一条 ⟹ 「死向量」；
  3. 动态模板（`RED-SURFACE-{cmd}` 等）双向一致；
  4. 站点覆盖：16 站序列（`gk_chain.py`）↔ 登记表站点集合等价，无向量站须有豁免理由；
  5. 复核期：`verified_at + ttl_days < today` ⟹ stale；`verified_at` 缺失也算 stale；
  6. anchor 可解析（文件存在 + 符号存在），否则 fail-loud。
"""
import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import gk_red_vectors as V  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CODE = ROOT / "scripts" / "_red_attacks.py"
CHAIN = ROOT / "scripts" / "gk_chain.py"


def _reg():
    return V.load()


def _tmp_tree(tmp_path, reg, code_text=None, chain_text=None):
    (tmp_path / "references").mkdir(exist_ok=True)
    (tmp_path / "scripts").mkdir(exist_ok=True)
    (tmp_path / "references" / "red-vectors.json").write_text(
        json.dumps(reg, ensure_ascii=False), encoding="utf-8")
    (tmp_path / "scripts" / "_red_attacks.py").write_text(
        code_text if code_text is not None else CODE.read_text(encoding="utf-8"),
        encoding="utf-8")
    (tmp_path / "scripts" / "gk_chain.py").write_text(
        chain_text if chain_text is not None else CHAIN.read_text(encoding="utf-8"),
        encoding="utf-8")
    return str(tmp_path)


def test_registry_schema_and_unique_ids():
    reg = _reg()
    assert reg["schema"] == V.SCHEMA
    ids = V.vector_ids(reg)
    assert len(ids) == len(set(ids)) > 100
    for v in reg["vectors"]:
        for k in ("id", "station", "fn", "severity", "anchor", "verified_at", "ttl_days"):
            assert k in v, (v.get("id"), k)
        assert v["severity"] in ("critical", "high", "medium", "low", "info")


def test_check_passes_on_repo():
    out = V.check()
    assert out["ok"] is True, out["errors"][:5]
    assert out["counts"]["vectors"] == out["counts"]["code_vectors"]
    assert out["counts"]["chain_stations"] == 16


def test_unregistered_vector_is_detected():
    text = CODE.read_text(encoding="utf-8").replace(
        '"RED-SCOPE-01"', '"RED-SCOPE-99"', 1)
    out = V.check(code_text=text)
    errs = "\n".join(out["errors"])
    assert out["ok"] is False
    assert "RED-SCOPE-99" in errs and "未登记" in errs
    assert "RED-SCOPE-01" in errs and "死向量" in errs


def test_dynamic_pattern_drift_is_detected():
    text = CODE.read_text(encoding="utf-8").replace(
        'f"RED-HINT-{phase}"', 'f"RED-HINT-X-{phase}"', 1)
    out = V.check(code_text=text)
    errs = "\n".join(out["errors"])
    assert "RED-HINT-X-{phase}" in errs and "未登记" in errs
    assert "RED-HINT-{phase}" in errs and "失效" in errs


def test_station_without_vectors_needs_reason(tmp_path):
    reg = _reg()
    reg["vectors"] = [v for v in reg["vectors"] if v["station"] != "RED-HOOK"]
    out = V.check(_tmp_tree(tmp_path, reg))
    assert out["ok"] is False
    assert any("RED-HOOK" in e and "无向量" in e for e in out["errors"]), out["errors"]


def test_anchor_must_resolve(tmp_path):
    reg = _reg()
    reg["vectors"][0] = dict(reg["vectors"][0],
                             anchor="scripts/_red_attacks.py::no_such_symbol")
    out = V.check(_tmp_tree(tmp_path, reg))
    assert out["ok"] is False
    assert any("anchor 符号不存在" in e for e in out["errors"]), out["errors"][:3]


def test_stale_ttl_and_missing_verified_at():
    reg = {"schema": V.SCHEMA, "stations": [], "dynamic_patterns": [], "vectors": [
        {"id": "A", "verified_at": "2026-01-01", "ttl_days": 30},
        {"id": "B", "verified_at": "2026-10-01", "ttl_days": 180},
        {"id": "C", "verified_at": None, "ttl_days": 180},
    ]}
    out = V.stale(reg, "2026-11-01")
    ids = {x["id"] for x in out}
    assert ids == {"A", "C"}, out
    # 宽限期足以让 A 暂时不过期；B/C 判据不受影响
    assert {x["id"] for x in V.stale(reg, "2026-11-01", grace_days=400)} == {"C"}


def test_coverage_reports_every_station():
    cov = V.coverage(_reg())
    assert len(cov) == 23
    assert cov["RED-SURFACE"]["dynamic_only"] is True
    assert cov["RED-REPORT"]["exempt"] is True
    assert all(v["vectors"] > 0 or v["dynamic_only"] or v["exempt"] for v in cov.values())


def test_cli_exit_codes():
    assert V.main(["check"]) == 0
    assert V.main(["bogus"]) == 2


# ── 第二期：常态化更新（锚点 reopen / 晋升防飞轮 / 复核回填）─────────────────

def test_reopen_flags_anchor_touched_after_verified_at():
    reg = _reg()
    out = V.reopen(reg, dates={"scripts/_red_attacks.py": "2026-12-01"})
    assert out["ok"] is True
    assert out["count"] == len(reg["vectors"]), out["count"]
    assert {r["last_change"] for r in out["reopened"]} == {"2026-12-01"}


def test_reopen_empty_when_anchor_older_than_review():
    out = V.reopen(_reg(), dates={"scripts/_red_attacks.py": "2026-10-01"})
    assert out["count"] == 0


def _finding(**kw):
    f = {"id": "ECC-TEST-1", "status": "confirmed", "severity": "high",
         "source": "main-agent", "title": "t", "station": "RED-HOOK",
         "anchor": "scripts/_red_attacks.py::red_hook",
         "evidence": {"repro_cmd": "pytest scripts/test_x.py -q",
                      "pre_fix_commit": "abc1234"}}
    f.update(kw)
    return f


def test_promotion_rejects_red_self_without_independent_verification():
    out = V.propose_promotion(_finding(source="red-team"), "2026-11-01")
    assert out["ok"] is False
    assert any("防飞轮" in e for e in out["errors"]), out["errors"]


def test_promotion_accepts_with_independent_verification():
    f = _finding(source="red-team")
    f["evidence"]["independent_verification"] = "https://example.org/advisory/1"
    out = V.propose_promotion(f, "2026-11-01")
    assert out["ok"] is True, out["errors"]
    c = out["candidate"]
    assert c["source"] == "finding:ECC-TEST-1" and c["external_ref"].startswith("https://")


def test_promotion_rejects_missing_repro_or_unconfirmed():
    out = V.propose_promotion(_finding(evidence={"pre_fix_commit": "abc1234"}))
    assert out["ok"] is False and any("repro_cmd" in e for e in out["errors"])
    out2 = V.propose_promotion(_finding(status="open"))
    assert out2["ok"] is False and any("confirmed" in e for e in out2["errors"])


def test_stamp_requires_explicit_ids_and_writes(tmp_path):
    assert V.stamp(_reg(), [], "2026-12-31")["ok"] is False
    p = tmp_path / "red-vectors.json"
    shutil.copy2(ROOT / "references" / "red-vectors.json", p)
    reg = V.load(str(p))
    target = reg["vectors"][0]["id"]
    out = V.stamp(reg, [target], "2026-12-31", str(p))
    assert out["ok"] is True and out["stamped"] == [target]
    again = V.load(str(p))
    hit = [v for v in again["vectors"] if v["id"] == target][0]
    assert hit["verified_at"] == "2026-12-31"


def test_registry_has_surface_and_introduced_backfilled():
    reg = _reg()
    missing_s = [v["id"] for v in reg["vectors"] if not v.get("surface")]
    missing_i = [v["id"] for v in reg["vectors"] if not v.get("introduced")]
    assert missing_s == [], missing_s[:5]
    assert missing_i == [], missing_i[:5]
    assert all(v.get("surface_kind") == "station" for v in reg["vectors"])


def test_backfill_fills_empty_fields_without_writing(tmp_path):
    reg = _reg()
    for v in reg["vectors"]:
        v["surface"] = ""
        v["introduced"] = None
    p = tmp_path / "rv.json"
    p.write_text("{}", encoding="utf-8")
    out = V.backfill(reg, dates={"RED-SCOPE-01": "2026-09-01"}, apply=False)
    assert out["applied"] is False and out["filled"]["surface"] == len(reg["vectors"])
    assert reg["vectors"][0]["surface"]
    assert p.read_text(encoding="utf-8") == "{}", "dry-run 不得写盘"


def test_external_map_covers_frameworks():
    out = V.external_map(_reg())
    assert out["ok"] is True, out["errors"]
    cov = out["coverage"]
    assert cov["OWASP-LLM-Top10-2025"]["entries"] == 10
    assert cov["MITRE-ATLAS"]["entries"] >= 10
    assert cov["MITRE-ATLAS"]["stations_covered"] > 0


def test_external_map_rejects_unknown_station():
    ext = {"schema": "gk-red-external-map/1",
           "frameworks": {"X": {"entries": [{"id": "E1", "stations": ["RED-NOPE"]}]}}}
    out = V.external_map(_reg(), ext)
    assert out["ok"] is False and "RED-NOPE" in out["errors"][0]
