#!/usr/bin/env python3
"""红先臂：`gk_mcp_loader` 的最小验证逻辑（DRAFT-1 T2/T5）。

finding `ECC-CB50D6939258`（MCP 加载安全网缺失）。本文件先于实现落刀，必须**先红**；
覆盖计划 §4 的四条反例：
  C1 未登记工具必须非零退出（默认拒）；
  C2 只读面不得误拦（假设 2）；
  C3 清单条目唯一（描述符数 == 条目数的可机检代理）；
  C4 降级必须 health-only 且 `proceed=false`（不得裸放行）。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import gk_mcp_loader as L  # noqa: E402


def _manifest(servers=None):
    return {"servers": servers if servers is not None else [
        {"server": "filesystem", "version": "2026.8.31",
         "integrity": "sha512-" + "a" * 64, "scope": "official",
         "cap": ["read", "write"],
         "tools": ["read_text_file", "write_file", "edit_file", "list_directory"]},
        {"server": "windows-cli", "version": "1.0.0",
         "integrity": "sha512-" + "b" * 64, "scope": "local",
         "cap": ["exec"], "tools": ["execute_command", "ssh_execute"]},
    ]}


def _write(tmp_path, data, name="mcp_manifest.json"):
    p = tmp_path / name
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return str(p)


def test_verify_ok(tmp_path):
    r = L.verify_manifest(_manifest())
    assert r["ok"] is True and not r["errors"]
    assert r["servers"] == 2


def test_missing_manifest_fails_closed(tmp_path):
    data, err = L.load_manifest(str(tmp_path / "nope.json"))
    assert data is None and err
    plan = L.plan_load(str(tmp_path / "nope.json"))
    assert plan["action"] == "health-only" and plan["proceed"] is False


def test_unparseable_manifest_fails_closed(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    data, err = L.load_manifest(str(p))
    assert data is None and "unparseable" in err


def test_unpinned_version_rejected():
    m = _manifest()
    m["servers"][0]["version"] = "latest"
    r = L.verify_manifest(m)
    assert r["ok"] is False
    assert any("version" in e for e in r["errors"])


def test_bad_integrity_rejected():
    m = _manifest()
    m["servers"][0]["integrity"] = "md5-deadbeef"
    r = L.verify_manifest(m)
    assert r["ok"] is False
    assert any("integrity" in e for e in r["errors"])


def test_unknown_scope_and_cap_rejected():
    m = _manifest()
    m["servers"][0]["scope"] = "random"
    m["servers"][0]["cap"] = ["read", "root"]
    r = L.verify_manifest(m)
    assert r["ok"] is False
    assert any("scope" in e for e in r["errors"])
    assert any("cap" in e for e in r["errors"])


def test_duplicate_server_rejected():
    m = _manifest()
    m["servers"].append(dict(m["servers"][0]))
    r = L.verify_manifest(m)
    assert r["ok"] is False
    assert any("duplicate" in e for e in r["errors"])


def test_connect_wired_tools_ok():
    r = L.connect_manifest(_manifest())
    assert r["ok"] is True, r
    assert not r["unwired"]
    kinds = {s["server"]: s["wired"] for s in r["servers"]}
    assert kinds["filesystem"]["read_text_file"] == "read"
    assert kinds["filesystem"]["write_file"] == "write"
    assert kinds["windows-cli"]["execute_command"] == "command"


def test_unregistered_tool_default_deny_c1():
    m = _manifest()
    m["servers"][0]["tools"].append("frobnicate_everything")
    r = L.connect_manifest(m)
    assert r["ok"] is False
    assert "filesystem:frobnicate_everything" in r["unwired"]


def test_read_tools_not_blocked_c2():
    m = _manifest()
    m["servers"][0]["tools"] = ["read_text_file", "get_file_contents",
                                "list_directory", "search_files"]
    r = L.connect_manifest(m)
    assert r["ok"] is True and not r["unwired"]


def test_degrade_never_proceeds_c4():
    m = _manifest()
    m["servers"][0]["cap"] = ["root"]
    plan = L.plan_load(None, manifest=m)
    assert plan["action"] == "health-only"
    assert plan["proceed"] is False


def test_guard_off_passthrough(monkeypatch):
    monkeypatch.setenv("GK_MCP_LOAD_GUARD", "0")
    plan = L.plan_load("/nonexistent/mcp_manifest.json")
    assert plan["action"] == "passthrough"
    assert plan["proceed"] is True and plan["guard"] == "off"


def test_egress_and_sealed_are_wired():
    m = _manifest()
    m["servers"][0]["tools"] = ["browser_navigate", "browser_open", "browser_eval_js"]
    r = L.connect_manifest(m)
    assert r["ok"] is True, r
    wired = r["servers"][0]["wired"]
    assert wired["browser_navigate"] == "egress"
    assert wired["browser_open"] == "egress"
    assert wired["browser_eval_js"] == "sealed"


def test_browser_toolface_categories():
    assert L.classify_tool("browser_click") == "ui"
    assert L.classify_tool("browser_record_start") == "gated"
    assert L.classify_tool("browser_record_list") == "read"
    assert L.classify_tool("install_browser") == "gated"


def test_real_octop_face_connect_ok():
    tools = ("browser_navigate,browser_dom_tree,browser_screenshot,browser_click,"
             "browser_type,browser_eval_js,browser_fill,browser_press,browser_wait,"
             "browser_record_doctor,browser_record_start,browser_record_stop,"
             "browser_record_status,browser_record_list,browser_record_show,"
             "browser_record_generate_steps,browser_record_generate_skill,"
             "browser_replay_run,browser_new_tab,browser_switch_tab,browser_close_tab,"
             "browser_list_tabs,browser_close_session,browser_open,install_browser").split(",")
    m = {"servers": [{"server": "octop-browser", "version": "1.0.0",
                      "integrity": "sha512-" + "a" * 64, "scope": "local",
                      "cap": ["read", "write", "exec", "network"], "tools": tools}]}
    r = L.connect_manifest(m)
    assert r["ok"] is True, r["unwired"]
    assert len(r["servers"][0]["wired"]) == 25


def test_cli_exit_codes(tmp_path):
    good = _write(tmp_path, _manifest(), "good.json")
    bad = _write(tmp_path, {"servers": [{"server": "x", "version": "latest"}]}, "bad.json")
    cmd = [sys.executable, str(HERE / "gk_mcp_loader.py")]
    ok = subprocess.run(cmd + ["verify", "--manifest", good, "--json"],
                        capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    bad_rc = subprocess.run(cmd + ["verify", "--manifest", bad, "--json"],
                            capture_output=True, text=True)
    assert bad_rc.returncode == 2
    missing = subprocess.run(cmd + ["check", "--manifest",
                                    str(tmp_path / "nope.json"), "--json"],
                             capture_output=True, text=True)
    assert missing.returncode == 4


def test_cli_connect_unwired_exit_3(tmp_path):
    m = _manifest()
    m["servers"][0]["tools"].append("frobnicate_everything")
    p = _write(tmp_path, m)
    r = subprocess.run([sys.executable, str(HERE / "gk_mcp_loader.py"),
                        "connect", "--manifest", p, "--json"],
                       capture_output=True, text=True)
    assert r.returncode == 3, r.stdout + r.stderr
