"""
test_gk_red_stand.py -- 红队常态化攻击机单测（gk_red_stand.py，2026-11-05）
================================================================================
覆盖：① 连击（streak）只数末尾连续 HIGH；② 台账 append/读取/截尾（确定性、原子替换）；
③ 一波攻击的组装契约（向量崩溃不得吞掉其它向量；HIGH 进 ids）；④ 台账可注入（不污染真实 home）。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gk_red_stand as S  # noqa: E402


def _rows(*highs):
    return [{"ts": i, "high": h} for i, h in enumerate(highs)]


def test_streak_counts_trailing_highs():
    assert S._streak(_rows(0, 1, 1, 1)) == 3
    assert S._streak(_rows(1, 0, 1)) == 1
    assert S._streak(_rows(0, 0)) == 0
    assert S._streak([]) == 0


def test_ledger_append_and_read(tmp_path):
    p = tmp_path / "red-history.jsonl"
    S.append_history({"ts": 1, "high": 1, "ids": ["X"]}, p)
    S.append_history({"ts": 2, "high": 0, "ids": []}, p)
    rows = S.read_history(p)
    assert [r["high"] for r in rows] == [1, 0]


def test_run_assembles_wave_and_ignores_broken_vector(tmp_path, monkeypatch):
    """向量崩溃 ⟹ 记 HIGH（不静默），其它向量照跑；台账落到注入路径。"""
    ledger = tmp_path / "red.jsonl"
    monkeypatch.setenv("GK_RED_HISTORY", str(ledger))
    monkeypatch.setattr(S, "VECTORS", (
        ("V0-ok", lambda: []),
        ("V1-boom", lambda: (_ for _ in ()).throw(RuntimeError("boom"))),
    ))
    r = S.run()
    assert r["ok"] is False and r["high"] == 1
    assert any(f["id"] == "VECTORS-ERR" for f in r["findings"])
    assert ledger.is_file()
    assert json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])["high"] == 1


def test_strict_exit_code(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_RED_HISTORY", str(tmp_path / "red.jsonl"))
    monkeypatch.setattr(S, "VECTORS", (("V0-high", lambda: [
        {"id": "X", "severity": S.HIGH, "title": "t", "detail": "d"}]),))
    assert S.main(["--strict", "--json"]) == 1
    assert S.main(["--json"]) == 0        # 非 strict 不阻断


# ── 登记表驱动的动态向量（2026-11-10）──────────────────────────────────────
# 改造前 VECTORS 是手写三元组（3 项），加动态向量要改代码 ⟹ 登记表涨了也不会进常态循环。
# 现在 `vector_registry()` 直接读 red-vectors.json.dynamic_vectors 的 runner 跑 pytest。
def _registry_tree(tmp_path, body="def test_ok():\n    assert True\n"):
    (tmp_path / "references").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "references" / "red-vectors.json").write_text(json.dumps({
        "dynamic_vectors": [{
            "id": "RED-DYN-T-01",
            "runner": "scripts/test_dyn_tmp.py::test_ok",
            "runner_extra": [],
        }]}), encoding="utf-8")
    (tmp_path / "scripts" / "test_dyn_tmp.py").write_text(body, encoding="utf-8")
    return tmp_path


def test_registry_vectors_pass_is_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "ROOT", _registry_tree(tmp_path))
    assert S.vector_registry() == []


def test_registry_runner_failure_is_high(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "ROOT", _registry_tree(
        tmp_path, "def test_ok():\n    assert False\n"))
    fs = S.vector_registry()
    assert fs and fs[0]["severity"] == S.HIGH
    assert fs[0]["id"] == "V4-RED-DYN-T-01"


def test_registry_missing_is_high(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "ROOT", tmp_path)
    fs = S.vector_registry()
    assert fs and fs[0]["severity"] == S.HIGH
    assert fs[0]["id"] == "V4-NO-REGISTRY"
