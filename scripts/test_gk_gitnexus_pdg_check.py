"""Test gk_gitnexus_pdg_check.py — L3/L5 交叉审查扩展实装（2026-09-01）"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_gitnexus_pdg_check as gx


@pytest.fixture(autouse=True)
def _gx_env(monkeypatch):
    """F-REV-75：`_cypher` 前置要求 GX_NODE/GX_JS/GX_REPO（消费 CLI 注入，不再自探测）。

    本文件主体测 JSON 提取契约，故给假值让前置通过；fail-loud 本身由
    test_cypher_fail_loud_* / test_resolve_repo_single_source 单独覆盖。
    """
    monkeypatch.setenv("GX_NODE", "/fake/node.exe")
    monkeypatch.setenv("GX_JS", r"C:\fake\index.js")
    monkeypatch.setenv("GX_REPO", "fake")


def test_cypher_fail_loud_no_node_env(monkeypatch):
    """F-REV-75：GX_NODE 未注入 → fail-loud（不再有硬编码路径兜底 → 不许静默空结果）。"""
    monkeypatch.delenv("GX_NODE", raising=False)
    d = gx._cypher("MATCH () RETURN count() AS c", "fake")
    assert "error" in d
    assert "GX_NODE" in d["error"]


def test_cypher_fail_loud_no_repo(monkeypatch):
    """F-REV-75：repo 不可解析（--repo 未给 + GX_REPO 未注入）→ fail-loud，不猜名。"""
    monkeypatch.delenv("GX_REPO", raising=False)
    d = gx._cypher("MATCH () RETURN count() AS c", "")
    assert "error" in d
    assert "repo" in d["error"]


def test_resolve_repo_single_source(monkeypatch):
    """repo 单源：显式 --repo 优先，否则 GX_REPO（原写死 spz-gatekeeper-r-sequence）。"""
    monkeypatch.setenv("GX_REPO", "from-env")
    assert gx._resolve_repo("") == "from-env"
    assert gx._resolve_repo("explicit") == "explicit"


def test_cypher_multi_line_json(monkeypatch):
    """stdout 含 FTS warn 行 + 多行结果 JSON → 必须解析出结果对象。"""
    out = ('{"level":40,"msg":"warn"}\n'
           '{\n  "markdown": "| c |\\n|---|\\n| 5 |",\n  "row_count": 1\n}\n')
    import subprocess
    class R:
        returncode = 0
        stdout = out
        stderr = ""
    monkeypatch.setattr(gx.gk_gitnexus, "run_raw",
                        lambda *a, **k: (True, out, "", False))
    d = gx._cypher("MATCH () RETURN count() AS c", "fake")
    assert "error" not in d
    assert d["row_count"] == 1
    assert "| 5 |" in d["markdown"]


def test_cypher_warn_after_result(monkeypatch):
    """warn 行在结果之后 → 取结果而非 warn（旧"行首 {" 定位 bug 回归）。"""
    out = ('{\n  "markdown": "| c |\\n|---|\\n| 42 |",\n  "row_count": 1\n}\n'
           '{"level":40,"msg":"FTS warn"}\n')
    import subprocess
    class R:
        returncode = 0
        stdout = out
        stderr = ""
    monkeypatch.setattr(gx.gk_gitnexus, "run_raw",
                        lambda *a, **k: (True, out, "", False))
    d = gx._cypher("MATCH () RETURN count() AS c", "fake")
    assert "error" not in d
    assert d["row_count"] == 1


def test_cypher_multiple_json_blocks(monkeypatch):
    """多个 JSON 混杂（warn + 中间态 + 结果）→ 取跨度最大完整对象。"""
    out = ('{"level":40,"msg":"warn"}\n'
           '{"progress": 0.5}\n'
           '{"markdown": "| c |\\n|---|\\n| 9 |", "row_count": 1}\n')
    import subprocess
    class R:
        returncode = 0
        stdout = out
        stderr = ""
    monkeypatch.setattr(gx.gk_gitnexus, "run_raw",
                        lambda *a, **k: (True, out, "", False))
    d = gx._cypher("MATCH () RETURN count() AS c", "fake")
    assert d["row_count"] == 1


def test_cypher_no_json_pure_text(monkeypatch):
    """纯文本输出（无 JSON）→ error 不崩溃。"""
    monkeypatch.setattr(gx.gk_gitnexus, "run_raw",
                        lambda *a, **k: (True, "变更：1 个文件\n风险等级：low\n", "", False))
    d = gx._cypher("MATCH () RETURN count() AS c", "fake")
    assert "error" in d


def test_cypher_non_dict_json(monkeypatch):
    """JSON 数组结果 → error 不崩溃。"""
    monkeypatch.setattr(gx.gk_gitnexus, "run_raw",
                        lambda *a, **k: (True, "[1, 2, 3]\n", "", False))
    d = gx._cypher("MATCH () RETURN count() AS c", "fake")
    assert "error" in d


def test_cypher_unicode_chinese(monkeypatch):
    """结果含中文 → 正常解析（UTF-8）。"""
    out = ('{"markdown": "| 风险等级 |\\n|---|\\n| high |", "row_count": 1}\n')
    import subprocess
    class R:
        returncode = 0
        stdout = out
        stderr = ""
    monkeypatch.setattr(gx.gk_gitnexus, "run_raw",
                        lambda *a, **k: (True, out, "", False))
    d = gx._cypher("MATCH () RETURN count() AS c", "fake")
    assert d["row_count"] == 1
    assert "风险等级" in d["markdown"]


def test_cypher_brace_in_markdown(monkeypatch):
    """markdown 表格内含 `{` 行 → 不误判为 JSON 起点。"""
    out = ('{\n  "markdown": "| k |\\n|---|\\n| {a:1} |",\n  "row_count": 1\n}\n')
    import subprocess
    class R:
        returncode = 0
        stdout = out
        stderr = ""
    monkeypatch.setattr(gx.gk_gitnexus, "run_raw",
                        lambda *a, **k: (True, out, "", False))
    d = gx._cypher("MATCH () RETURN count() AS c", "fake")
    assert d["row_count"] == 1


def test_cypher_timeout(monkeypatch):
    """subprocess 超时 → error 字段不崩溃。"""
    import subprocess
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(a[0], k.get("timeout", 60))
    monkeypatch.setattr(subprocess, "run", boom)
    d = gx._cypher("MATCH () RETURN count() AS c", "fake")
    assert "error" in d


def test_probe_symbol_error_tolerant(monkeypatch):
    """probe_symbol：cypher 报错 → 原样返回 error dict，不抛异常。"""
    monkeypatch.setattr(gx, "_cypher", lambda q, repo, limit=50: {"error": "boom"})
    r = gx.probe_symbol("fake", "some_fn", 20)
    assert "guards" in r and "error" in r["guards"]


def test_check_stats_partial_failure(monkeypatch):
    """check_stats：单个计数失败（None）→ 字段保留 None，不崩溃。"""
    calls = {"n": 0}
    def fake_cypher(q, repo, limit=50):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"markdown": "| c |\n|---|\n| 100 |", "row_count": 1}
        return {"error": "boom"}
    monkeypatch.setattr(gx, "_cypher", fake_cypher)
    s = gx.check_stats("fake")
    assert s["cdg_edges"] == 100
    assert s["reaching_def_edges"] is None


def test_count_extract_digit():
    """markdown 表提取数字（末行纯数字）。"""
    d = {"markdown": "| c |\n|---|\n| 42 |", "row_count": 1}
    md = d["markdown"]
    for line in reversed(md.splitlines()):
        s = line.strip().strip("|").strip()
        if s.isdigit():
            assert int(s) == 42
            break


def test_count_multi_column_table(monkeypatch):
    """_count：多列 cypher 结果表（count 查询真实输出形态）→ 提取计数（2026-09-01）。"""
    import subprocess
    out = ('{\n  "markdown": "| c |\\n|---|\\n| 1234 |",\n  "row_count": 1\n}\n')
    class R:
        returncode = 0
        stdout = out
        stderr = ""
    monkeypatch.setattr(gx.gk_gitnexus, "run_raw",
                        lambda *a, **k: (True, out, "", False))
    n = gx._count("MATCH () RETURN count() AS c", "fake")
    assert n == 1234


def test_count_no_digit_none(monkeypatch):
    """_count：表无数字（N/A）→ None 不崩溃。"""
    import subprocess
    out = ('{\n  "markdown": "| c |\\n|---|\\n| N/A |",\n  "row_count": 0\n}\n')
    class R:
        returncode = 0
        stdout = out
        stderr = ""
    monkeypatch.setattr(gx.gk_gitnexus, "run_raw",
                        lambda *a, **k: (True, out, "", False))
    assert gx._count("MATCH () RETURN count() AS c", "fake") is None


def test_pdg_layer_detection(tmp_path):
    """gitnexus.json 含 pdg 字段 → layer True。"""
    gx_json = tmp_path / ".gitnexus" / "gitnexus.json"
    gx_json.parent.mkdir(parents=True)
    gx_json.write_text('{"pdg": {"maxFunctionLines": 2000}}', encoding="utf-8")
    orig = gx.os.getcwd
    try:
        gx.os.getcwd = lambda: str(tmp_path)
        assert gx.check_pdg_layer("any") is True
    finally:
        gx.os.getcwd = orig


def test_pdg_layer_absent(tmp_path):
    """gitnexus.json 无 pdg 字段 → layer False。"""
    gx_json = tmp_path / ".gitnexus" / "gitnexus.json"
    gx_json.parent.mkdir(parents=True)
    gx_json.write_text('{"schemaVersion": 5}', encoding="utf-8")
    orig = gx.os.getcwd
    try:
        gx.os.getcwd = lambda: str(tmp_path)
        assert gx.check_pdg_layer("any") is False
    finally:
        gx.os.getcwd = orig


def test_cypher_error_on_nonzero(monkeypatch):
    """gitnexus 返回非零 → error 字段（不崩溃）。"""
    import subprocess
    class R:
        returncode = 1
        stdout = ""
        stderr = "boom"
    monkeypatch.setattr(gx.gk_gitnexus, "run_raw",
                        lambda *a, **k: (False, "", "boom", False))
    d = gx._cypher("MATCH (n) RETURN n", "fake")
    assert "error" in d


def test_main_json_contract(capsys):
    """main() 输出可解析 JSON + 契约字段齐全（pdg_layer 恒存在）。"""
    import json as _json
    old_argv = sys.argv
    sys.argv = ["gk_gitnexus_pdg_check.py"]
    try:
        gx.main()
    finally:
        sys.argv = old_argv
    out = capsys.readouterr().out
    d = _json.loads(out)
    assert "ok" in d and "repo" in d and "pdg_layer" in d
    assert "stats" in d and "recommendation" in d


def test_supply_chain_indexed_files_from_gitnexus_json(tmp_path):
    """索引文件集 = gitnexus.json fileHashes keys（相对路径）。"""
    gx_json = tmp_path / ".gitnexus" / "gitnexus.json"
    gx_json.parent.mkdir(parents=True)
    gx_json.write_text(
        '{"fileHashes": {"scripts/gk_state.py": "a", "scripts/gk_node_guard.py": "b", "scripts/pre_tool_hook.py": "c"}}',
        encoding="utf-8")
    import os as _os
    orig = _os.getcwd
    try:
        _os.getcwd = lambda: str(tmp_path)
        # 无 import 语句 → 无 unresolved
        r = gx.check_supply_chain("fake")
        assert r["status"] == "ok"
        assert r["indexed_files"] == 3
        assert r["unresolved"] == []
    finally:
        _os.getcwd = orig


def test_supply_chain_unresolved_detected(tmp_path):
    """import 目标在索引内无对应文件 → 第三方未解析（外部依赖候选）+ stdlib 分类。"""
    gx_json = tmp_path / ".gitnexus" / "gitnexus.json"
    gx_json.parent.mkdir(parents=True)
    gx_json.write_text('{"fileHashes": {"scripts/gk_state.py": "a"}}', encoding="utf-8")
    src = tmp_path / "scripts"
    src.mkdir(parents=True)
    (src / "gk_state.py").write_text("import os\nimport requests\n", encoding="utf-8")
    import os as _os
    orig = _os.getcwd
    try:
        _os.getcwd = lambda: str(tmp_path)
        r = gx.check_supply_chain("fake")
        assert r["status"] == "ok"
        mods = {u["module"] for u in r["unresolved"]}
        assert "requests" in mods   # 第三方未解析 → 供应链风险候选
        assert "os" in r["stdlib"]  # 标准库 → 独立分类（非风险）
        assert all(u["imported_by"] == ["gk_state.py"] for u in r["unresolved"])
    finally:
        _os.getcwd = orig


def test_supply_chain_no_index_skip(tmp_path):
    """gitnexus.json 缺失/无 fileHashes → status skip（不崩溃）。
    2026-09-13 契约更新：_resolve_base 三级解析（repo 路径 > cwd 含索引 > 模块锚）——
    skip 路径改由 repo 显式指向无 .gitnexus 的存在目录触发（cwd 回退语义见 _resolve_base）。"""
    r = gx.check_supply_chain(str(tmp_path))
    assert r["status"] == "skip"
