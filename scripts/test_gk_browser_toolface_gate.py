#!/usr/bin/env python3
"""红先臂：R0.18 octop 浏览器工具面闸（install / record 写面）。

真机 25 工具实测：`install_browser`（下载 Chromium）与 `browser_record_*`（写录像/技能）
既不出网、也不在写面动词表 ⟹ 原样可达。本闸只拦这两类；本地读/UI 保持放行。
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import pre_tool_hook as H  # noqa: E402


def _call(name, args=None):
    return H._browser_toolface_gate("run_mcp", {"tool_name": name, "args": args or {}})


def test_install_blocked_by_default(monkeypatch):
    monkeypatch.delenv("GK_MCP_ALLOW_BROWSER_INSTALL", raising=False)
    assert _call("install_browser")


def test_install_allowed_with_env(monkeypatch):
    monkeypatch.setenv("GK_MCP_ALLOW_BROWSER_INSTALL", "1")
    assert not _call("install_browser")


def test_record_write_blocked_by_default(monkeypatch):
    monkeypatch.delenv("GK_MCP_ALLOW_BROWSER_RECORD", raising=False)
    for n in ("browser_record_start", "browser_record_stop",
              "browser_record_generate_steps", "browser_record_generate_skill"):
        assert _call(n), n


def test_record_write_allowed_with_env(monkeypatch):
    monkeypatch.setenv("GK_MCP_ALLOW_BROWSER_RECORD", "1")
    assert not _call("browser_record_start")


def test_record_read_allowed(monkeypatch):
    monkeypatch.delenv("GK_MCP_ALLOW_BROWSER_RECORD", raising=False)
    for n in ("browser_record_doctor", "browser_record_status",
              "browser_record_list", "browser_record_show"):
        assert not _call(n), n


def test_local_ui_allowed(monkeypatch):
    for n in ("browser_dom_tree", "browser_screenshot", "browser_click",
              "browser_type", "browser_fill", "browser_press", "browser_wait",
              "browser_switch_tab", "browser_close_tab", "browser_list_tabs",
              "browser_close_session"):
        assert not _call(n), n


def test_non_mcp_unaffected():
    assert not H._browser_toolface_gate("Read", {"file_path": "x"})
