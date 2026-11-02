"""test_gk_mediation.py — P2-Mediation #4 上下文构造测试（2026-08-26 批次 2 剩余）。

覆盖: sealed+calibration 摘要 / 空 log / 无 checklist / 缺失文件 {} 回退。
安全网 R1: 只读 tmp_path 文件。
"""
import json
import subprocess
import sys
from pathlib import Path

_SCRIPT = Path(__file__).parent / "gk_mediation.py"


def _run(state: dict) -> dict:
    f = Path(__file__).parent / "tmp_mediation.json"
    f.write_text(json.dumps(state), encoding="utf-8")
    r = subprocess.run([sys.executable, str(_SCRIPT), str(f)],
                       capture_output=True, text=True, encoding="utf-8", timeout=10)
    f.unlink(missing_ok=True)
    assert r.returncode == 0
    return json.loads(r.stdout)


def test_full_context():
    st = {"gate_data": {
        "_sealed_agent_score": {"score": 0.7, "verdicts": {"G1": "PASS"}},
        "human_calibration_log": [
            {"human_score": 0.6, "verdicts_json": {"G1": "PASS"},
             "divergence": 0.1, "flag": "", "change_items": 2,
             "checklist_total": 5, "checklist_passed": 4},
        ],
    }}
    d = _run(st)
    assert d["agent_score"] == 0.7
    assert d["human_score"] == 0.6
    assert d["divergence"] == 0.1
    assert d["checklist"] == "4/5"


def test_empty_log_defaults():
    st = {"gate_data": {"_sealed_agent_score": {}}}
    d = _run(st)
    assert d["agent_score"] == "N/A"
    assert d["human_score"] == "N/A"
    assert d["checklist"] == "N/A"


def test_no_checklist_total():
    st = {"gate_data": {"_sealed_agent_score": {},
                        "human_calibration_log": [{"checklist_total": 0}]}}
    d = _run(st)
    assert d["checklist"] == "N/A"


def test_missing_file_returns_empty():
    r = subprocess.run([sys.executable, str(_SCRIPT), str(Path(__file__).parent / "nope.json")],
                       capture_output=True, text=True, encoding="utf-8", timeout=10)
    assert r.returncode == 0
    assert r.stdout.strip() == "{}"
