#!/usr/bin/env python3
"""gk_doc_features 红先臂 —— 常驻功能 ↔ 自述文档覆盖 + 自动刷新文档一致性。

判据：
  · 登记了但文档未写 ⟹ 判红，并指出 `{id, doc}`；
  · 文档缺文件 / 登记表 schema 错 ⟹ 判红（exit 2 用于 schema）；
  · 自动刷新文档（GK-FACTS/GK-REFS/容量表）漂移 ⟹ 判红；
  · 仓内真实登记表必须全绿（防止登记表本身过期）。
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_doc_features as M  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def _write_reg(tmp_path, features):
    p = tmp_path / "reg.json"
    p.write_text(json.dumps({"schema": M.SCHEMA, "features": features},
                            ensure_ascii=False), encoding="utf-8")
    return p


def _run(tmp_path, features, docs, skip_facts=True):
    for name, text in docs.items():
        f = tmp_path / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
    reg = _write_reg(tmp_path, features)
    old_root = M.ROOT
    M.ROOT = tmp_path
    try:
        return M.main(["--registry", str(reg)] + (["--skip-facts"] if skip_facts else []))
    finally:
        M.ROOT = old_root


def test_missing_feature_is_red(tmp_path, capsys):
    rc = _run(tmp_path,
              [{"id": "bench", "doc": "README.md", "pattern": "gk_bench_state"}],
              {"README.md": "no bench here\n"})
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False
    assert out["missing"][0]["id"] == "bench"
    assert out["missing"][0]["reason"] == "文档未覆盖"


def test_present_feature_is_green(tmp_path, capsys):
    rc = _run(tmp_path,
              [{"id": "bench", "doc": "README.md", "pattern": "gk_bench_state"}],
              {"README.md": "见 scripts/gk_bench_state.py\n"})
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True and out["missing"] == []


def test_missing_doc_file_is_red(tmp_path, capsys):
    rc = _run(tmp_path,
              [{"id": "arch", "doc": "references/nope.md", "pattern": "x"}],
              {})
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["missing"][0]["reason"] == "文档不存在"


def test_bad_schema_exit_2(tmp_path, capsys):
    p = tmp_path / "reg.json"
    p.write_text(json.dumps({"schema": "wrong/0", "features": []}), encoding="utf-8")
    assert M.main(["--registry", str(p)]) == 2


def test_facts_drift_is_red(tmp_path, capsys, monkeypatch):
    # 伪造 facts 检查器：模拟 GK-FACTS 漂移
    fake = tmp_path / "fake_facts.py"
    fake.write_text("import json,sys\nprint(json.dumps({'status':'FAIL','detail':'drift'}))\n"
                    "sys.exit(2)\n", encoding="utf-8")
    monkeypatch.setattr(M, "FACTS", fake)
    rc = _run(tmp_path,
              [{"id": "bench", "doc": "README.md", "pattern": "bench"}],
              {"README.md": "bench\n"}, skip_facts=False)
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["facts"]["status"] == "FAIL" and out["ok"] is False


def test_repo_registry_is_green():
    """仓内真实登记表 + 真实文档必须全绿（登记表过期即判红）。"""
    rc = M.main(["--json"])
    assert rc == 0, "登记表或自述文档未同步"
