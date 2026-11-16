#!/usr/bin/env python3
"""ECC-67C0B937A54B 红先臂：诊断日志按**会话切片**（`gk_dbg.<sid>.log`）。

病象：`scripts/gk_dbg.log` 单文件、跨会话/子 agent 混写（CLI 起步变量 + 4 个 loader +
`gk_monitor_payload` 共用一个路径）⟹ 并发会话的异常行无法归属，排障只能靠猜。

修法（单一事实源 = `scripts/gk_dbg.py`）：
  · `log_path()`：env `GK_DBG_LOG` → `gk_dbg.<sid>.log` → `gk_dbg.log`（无 sid ⟹ 零回归）
  · sid 字符门同 CLI 身份门（`[A-Za-z0-9_-]`），非法 ⟹ 视为无 sid（防路径穿越）
  · `write()`：单次 `os.write`（O_APPEND），失败不抛（诊断面不打断主流程）
  · 4 个 loader + `gk_monitor_payload` + CLI 起步变量一律走该口径（**禁**第二处手写路径）
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
SKILL = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

import gk_dbg  # noqa: E402


@pytest.fixture
def clean_env(monkeypatch):
    monkeypatch.delenv("GK_DBG_LOG", raising=False)
    monkeypatch.delenv("GK_SESSION_ID", raising=False)


def test_log_path_shards_by_session(clean_env, monkeypatch):
    """有 sid ⟹ `gk_dbg.<sid>.log`（不再与他会话共用单文件）。"""
    monkeypatch.setenv("GK_SESSION_ID", "6aee8af5")
    p = gk_dbg.log_path(base="/tmp/x")
    assert p.name == "gk_dbg.6aee8af5.log", p


def test_log_path_falls_back_without_sid(clean_env):
    """无 sid（owner 手工 / 身份未解析）⟹ 仍 `gk_dbg.log`（零回归）。"""
    assert gk_dbg.log_path(base="/tmp/x").name == "gk_dbg.log"


def test_log_path_rejects_unsafe_sid(clean_env, monkeypatch):
    """路径穿越形态的 sid ⟹ 视为无 sid，不得拼进文件名。"""
    monkeypatch.setenv("GK_SESSION_ID", "../evil/x")
    assert gk_dbg.log_path(base="/tmp/x").name == "gk_dbg.log"


def test_log_path_env_override(clean_env, monkeypatch, tmp_path):
    """env `GK_DBG_LOG`（CLI 解析后显式给出 / 测试注入）优先级最高。"""
    target = tmp_path / "explicit.log"
    monkeypatch.setenv("GK_DBG_LOG", str(target))
    monkeypatch.setenv("GK_SESSION_ID", "abc")
    assert gk_dbg.log_path() == target


def test_write_appends_to_session_slice(clean_env, monkeypatch, tmp_path):
    """`write()` 落本会话切片，且单次追加不截断已有行。"""
    monkeypatch.setenv("GK_SESSION_ID", "sess01")
    assert gk_dbg.write("[t] hello", base=tmp_path) is True
    assert gk_dbg.write("[t] world", base=tmp_path) is True
    f = tmp_path / "gk_dbg.sess01.log"
    lines = f.read_text(encoding="utf-8").splitlines()
    assert lines == ["[t] hello", "[t] world"], lines
    assert not (tmp_path / "gk_dbg.log").exists(), "切片模式下不得再写共享单文件"


def _src(name):
    return (SCRIPTS / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("mod", ["gk_bashpy_loader.py", "gk_plugin_manifest.py",
                                 "gk_swe_rb_loader.py", "gk_paper_review_loader.py"])
def test_modules_delegate_to_single_source(mod):
    """4 个 loader 的 `GK_DBG_LOG` 须走 `gk_dbg.log_path()`（禁再手写 `gk_dbg.log` 常量）。"""
    src = _src(mod)
    assert "GK_DBG_LOG = gk_dbg.log_path()" in src, mod
    assert 'GK_DBG_LOG = Path(__file__).resolve().parent / "gk_dbg.log"' not in src, mod


def test_monitor_payload_delegates_to_single_source():
    """`gk_monitor_payload` 的 JTI 留痕须走 `gk_dbg.write`（原为手写 `join(...,'gk_dbg.log')`）。"""
    src = _src("gk_monitor_payload.py")
    assert "_gk_dbg.write(" in src, "JTI 留痕未走单一事实源"
    assert "'gk_dbg.log'),'a'" not in src, "仍手写共享单文件路径"


def test_cli_defines_sharded_path():
    """CLI 起步变量须按会话切片派生（单文件 225 处写点共用一个变量）。"""
    src = (SKILL / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    assert "_gk_dbg_log_path()" in src
    assert 'GK_DBG_LOG="$(_gk_dbg_log_path)"' in src
    assert 'GK_DBG_LOG="${SKILL_DIR}/scripts/gk_dbg.log"' not in src, "共享单文件常量仍在"


def test_cli_sid_sharding_behavior():
    """实跑：抽出 CLI 的 `_gk_dbg_log_path()` 源码，验三种 sid 形态的派生结果。"""
    src = (SKILL / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    start = src.index("_gk_dbg_log_path() {")
    end = src.index("\n}\n", start) + 3
    fn = src[start:end]

    def _run(sid):
        env = {**os.environ, "SKILL_DIR": "/skill", "GK_SESSION_ID": sid}
        r = subprocess.run(["bash", "-c", fn + '\n_gk_dbg_log_path'],
                           capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr[-400:]
        return r.stdout.strip()

    assert _run("abc123") == "/skill/scripts/gk_dbg.abc123.log"
    assert _run("") == "/skill/scripts/gk_dbg.log"
    assert _run("../evil") == "/skill/scripts/gk_dbg.log"


def test_cli_syntax_ok():
    """CLI 改动后语法须仍可解析（`bash -n`）。"""
    r = subprocess.run(["bash", "-n", str(SKILL / "gatekeeper-cli.sh")],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-800:]
