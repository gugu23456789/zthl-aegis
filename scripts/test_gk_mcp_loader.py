"""test_gk_mcp_loader.py — MCP 加载安全网（声明 / 接线 / 决策 / SDK 版本适配）。

判据面（红先）：
  ① 声明面：未钉版本 / integrity 非 sha512 / 重复 server / scope 越界 / cap 越界 / tools 空
     ⟹ `verify` ok=False（fail-closed），**不得**因缺字段而放行；
  ② 接线面：工具未落 read/write/command ⟹ ok=False，并逐条列出 `server:tool`；
  ③ 决策面：任一失败 ⟹ `action=health-only` + `proceed=false`（永不裸放行）；
     `GK_MCP_LOAD_GUARD=0` 是**显式**回退，返回 passthrough；
  ④ SDK 适配：四种 `list_tools()` 载荷形态归一一致；不可识别形态抛 ValueError（不猜）；
     未安装 SDK 时 `sdk-info` 非零退出但其余子命令照常（静态面不依赖 SDK）。

安全网 R1：只写 tmp_path；不联网；不 spawn 任何 MCP server。
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_mcp_loader as L  # noqa: E402


def _manifest(**over):
    s = {"server": "filesystem", "version": "1.2.3",
         "integrity": "sha512-" + "a" * 64, "scope": "official",
         "cap": ["read"], "tools": ["read_text_file", "list_directory"]}
    s.update(over)
    return {"servers": [s]}


def _write(tmp_path, obj, name="mcp_manifest.json"):
    p = tmp_path / name
    p.write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")
    return str(p)


# ── ① 声明面 ─────────────────────────────────────────────────────────────────
def test_verify_ok():
    assert L.verify_manifest(_manifest())["ok"] is True


@pytest.mark.parametrize("over", [
    {"version": "latest"},
    {"version": ""},
    {"integrity": "md5-abc"},
    {"integrity": "sha512-short"},
    {"scope": "random"},
    {"cap": ["read", "root"]},
    {"cap": []},
    {"tools": []},
    {"server": ""},
])
def test_verify_fail_closed(over):
    assert L.verify_manifest(_manifest(**over))["ok"] is False


def test_verify_duplicate_server():
    m = _manifest()
    m["servers"].append(dict(m["servers"][0]))
    r = L.verify_manifest(m)
    assert r["ok"] is False and any("duplicate" in e for e in r["errors"])


def test_verify_empty_servers():
    assert L.verify_manifest({"servers": []})["ok"] is False


# ── ② 接线面 ─────────────────────────────────────────────────────────────────
def test_connect_wired_ok():
    r = L.connect_manifest(_manifest())
    assert r["ok"] is True and r["unwired"] == []


def test_connect_unwired_lists_each():
    r = L.connect_manifest(_manifest(tools=["read_text_file", "definitely_not_a_tool"]))
    assert r["ok"] is False
    assert r["unwired"] == ["filesystem:definitely_not_a_tool"]


# ── ③ 决策面 ─────────────────────────────────────────────────────────────────
def test_plan_load_health_only_on_bad_manifest(tmp_path):
    p = _write(tmp_path, _manifest(version="latest"))
    r = L.plan_load(p)
    assert r["action"] == "health-only" and r["proceed"] is False


def test_plan_load_ok(tmp_path):
    p = _write(tmp_path, _manifest())
    r = L.plan_load(p)
    assert r["action"] == "load" and r["proceed"] is True


def test_plan_load_missing_manifest_fails_closed(tmp_path):
    r = L.plan_load(str(tmp_path / "nope.json"))
    assert r["action"] == "health-only" and r["proceed"] is False


def test_guard_off_is_explicit_passthrough(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_MCP_LOAD_GUARD", "0")
    r = L.plan_load(str(tmp_path / "nope.json"))
    assert r["action"] == "passthrough" and r["proceed"] is True


# ── ④ SDK 版本适配 ───────────────────────────────────────────────────────────
class _ToolObj:
    def __init__(self, name, description=""):
        self.name = name
        self.description = description


@pytest.mark.parametrize("payload", [
    [_ToolObj("read_text_file", "r"), _ToolObj("write_file", "w")],          # ① 对象
    [{"name": "read_text_file", "description": "r"},
     {"name": "write_file", "description": "w"}],                            # ② dict
    {"tools": [_ToolObj("read_text_file"), _ToolObj("write_file")]},         # ③ 包装
    {"tools": [_ToolObj("read_text_file"), _ToolObj("write_file")],
     "nextCursor": "abc"},                                                   # ④ 分页
])
def test_normalize_tools_shapes(payload):
    out = L.normalize_tools(payload)
    assert [t["name"] for t in out] == ["read_text_file", "write_file"]


def test_normalize_tools_rejects_unknown_shape():
    with pytest.raises(ValueError):
        L.normalize_tools("not-a-list")


def test_normalize_tools_model_object():
    """⑤ `ListToolsResult`（pydantic 模型对象，`.tools` 属性）——不同 SDK 版本的返回形态。"""
    class _Result:
        def __init__(self, tools):
            self.tools = tools
            self.nextCursor = "abc"
    out = L.normalize_tools(_Result([_ToolObj("read_text_file"), _ToolObj("write_file")]))
    assert [t["name"] for t in out] == ["read_text_file", "write_file"]


def test_normalize_tools_rejects_unnamed():
    with pytest.raises(ValueError):
        L.normalize_tools([{"description": "no name"}])


def test_sdk_info_reports_missing(monkeypatch):
    """未安装 mcp：installed=False（不抛异常，不猜版本）。"""
    monkeypatch.setattr(L, "_probe", lambda dotted: (False, None, "ModuleNotFoundError"))
    monkeypatch.setattr("importlib.metadata.version", lambda _n: (_ for _ in ()).throw(
        __import__("importlib.metadata", fromlist=["x"]).PackageNotFoundError()))
    info = L.sdk_info()
    assert info["installed"] is False and info["major"] == "unknown"


def test_sdk_info_reports_1x_surface(monkeypatch):
    """1.x 面：mcp.ClientSession + mcp.types.Tool 可用 ⟹ installed=True, major 取包版本。"""
    def fake(dotted):
        if dotted in (("mcp", "ClientSession"), ("mcp.types", "Tool")):
            return True, object, ""
        return False, None, "missing"
    monkeypatch.setattr(L, "_probe", fake)
    monkeypatch.setattr("importlib.metadata.version", lambda _n: "1.9.4")
    info = L.sdk_info()
    assert info["installed"] is True and info["major"] == "1"
    assert "Tool" in info["surfaces"]


def test_connect_offline_tools_file(tmp_path):
    """离线接线：把 SDK（任意版本）读到的工具清单落盘后交给 connect。"""
    tf = tmp_path / "tools.json"
    tf.write_text(json.dumps({"tools": [{"name": "read_text_file"},
                                        {"name": "search_code"}]}), encoding="utf-8")
    mp = _write(tmp_path, _manifest())
    rc = L.main(["connect", "--manifest", mp, "--tools", str(tf), "--json"])
    assert rc == L._EXIT_OK


def test_cli_exit_codes(tmp_path):
    bad = _write(tmp_path, _manifest(version="latest"), "bad.json")
    assert L.main(["verify", "--manifest", bad, "--json"]) == L._EXIT_VERIFY
    good = _write(tmp_path, _manifest(tools=["read_text_file", "zzz_unknown"]), "w.json")
    assert L.main(["connect", "--manifest", good, "--json"]) == L._EXIT_CONNECT
    assert L.main(["verify", "--manifest", str(tmp_path / "nope.json"), "--json"]) \
        == L._EXIT_MANIFEST
    assert L.main(["health-only", "--json"]) == L._EXIT_OK


def test_tools_flag_rejected_outside_connect(tmp_path):
    """`--tools` 只含工具清单（无 version/integrity）⟹ 不得拿去跑 verify/check（否则恒假红）。"""
    tf = tmp_path / "tools.json"
    tf.write_text(json.dumps([{"name": "read_text_file"}]), encoding="utf-8")
    mp = _write(tmp_path, _manifest())
    assert L.main(["verify", "--manifest", mp, "--tools", str(tf), "--json"]) \
        == L._EXIT_MANIFEST
    assert L.main(["check", "--manifest", mp, "--tools", str(tf), "--json"]) \
        == L._EXIT_MANIFEST
