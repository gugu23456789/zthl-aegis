"""`gk_monitor_fixture.py`（B2 等价夹具驱动）的机检臂，2026-11-04。

守的是**驱动本身**：夹具可建、内联载荷可逐字抽出、归一化只剥时钟派生字段、
真差异必须被判出。生产调用点不在本文件范围。
"""
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import gk_monitor_fixture as F  # noqa: E402


def test_build_writes_fixture_triplet(tmp_path):
    r = F.build(str(tmp_path / "fx"))
    assert r["hmac"] and len(r["hmac"]) == 64
    for name in ("state.json", "out.json", "env.json"):
        assert (tmp_path / "fx" / name).is_file(), name
    out = json.loads((tmp_path / "fx" / "out.json").read_text(encoding="utf-8"))
    # 夹具 HMAC 必须能自洽复算（签名公式与 runner 同构）
    assert F._sign(out) == out["hmac"]


def test_extract_returns_absent_after_migration(tmp_path):
    """内联块已下沉 ⟹ 抽取器必须报「锚点不存在」（防同一块被重复内联/回流）。"""
    p = tmp_path / "payload.py"
    assert F.extract(str(p)) == 2
    assert not p.exists()


def test_module_is_valid_python(tmp_path):
    mod = F.SCRIPTS / "gk_monitor_payload.py"
    src = mod.read_text(encoding="utf-8")
    assert len(src.splitlines()) > 250
    compile(src, str(mod), "exec")
    assert "normalize_evidence" in src


def test_norm_strips_only_time_derived_fields():
    state = {"gate_data": {
        "subagent_history": [{"ts": "t", "subagent_id": "s"}],
        "jti_store": {"n": 1.0},
        "satellite_index": {"h": {"s": {"first_ts": "a", "last_ts": "b", "n": 2}}},
        "keep": {"x": 1},
    }}
    n = F._norm(state)
    gd = n["gate_data"]
    assert "ts" not in gd["subagent_history"][0]
    assert "jti_store" not in gd
    assert gd["satellite_index"]["h"]["s"] == {"n": 2}
    assert gd["keep"] == {"x": 1}


def test_compare_detects_real_state_diff():
    a = {"rc": 0, "stdout": "x", "stderr": "", "state": {"gate_data": {"v": 1}}}
    b = {"rc": 0, "stdout": "x", "stderr": "", "state": {"gate_data": {"v": 2}}}
    r = F.compare(a, b)
    assert r["equivalent"] is False
    assert any("state" in d for d in r["diffs"])


def test_compare_detects_stdout_diff():
    a = {"rc": 0, "stdout": "x", "stderr": "", "state": {}}
    b = {"rc": 0, "stdout": "y", "stderr": "", "state": {}}
    assert F.compare(a, b)["equivalent"] is False
