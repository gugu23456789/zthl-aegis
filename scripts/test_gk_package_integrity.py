"""`gk_package_integrity` 的机检臂（2026-11-02）。

守什么：
  ① 命令注册表里的函数必须真的定义（防「注册了但没实现」）；
  ② 插件 manifest 的 builtin 源必须存在，write/undo 必须配对；
  ③ **真仓**当前无 error（防止本轮就已经缺件）。
"""
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_package_integrity as G  # noqa: E402


def _bash_path(p):
    """Windows 绝对路径 → WSL 可解析的 `/mnt/<drive>/...`；非 Windows 原样（分类学 #13）。"""
    if os.name != "nt":
        return str(p)
    q = str(p).replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", q)
    return "/mnt/%s/%s" % (m.group(1).lower(), m.group(2)) if m else q


def test_cmd_registry_detects_missing_function():
    text = '_CMD_REG[a]="cmd_a|none|any|"\ncmd_b() {\n  :\n}\n'
    probs = G.cmd_registry_issues(text)
    assert [p["command"] for p in probs] == ["a"], probs
    assert probs[0]["level"] == "error"


def test_cmd_registry_accepts_defined_function():
    text = ('_CMD_REG[a]="cmd_a|none|any|"\n'
            'cmd_a() {\n  :\n}\n'
            'function cmd_b {\n  :\n}\n')
    assert G.cmd_registry_issues(text) == []


def test_monitor_schema_missing_detects(tmp_path):
    nodes = {"red": {"nodes": ["RED-A", "RED-B"]}}
    (tmp_path / "RED-A.json").write_text("{}", encoding="utf-8")
    assert G.monitor_schema_missing(nodes, tmp_path) == [("red", "RED-B")]


def test_real_repo_covers_all_route_nodes():
    root = Path(__file__).resolve().parent.parent
    assert G.monitor_schema_issues(root) == []


def test_reinstall_keeps_uninstall_coverage(tmp_path):
    """重复安装不得把 manifest 覆盖成空 ⟹ 卸载仍能按清单清干净（2026-11-02 修）。"""
    root = Path(__file__).resolve().parent.parent
    dest = tmp_path / "inst"
    env = dict(os.environ, HOME=_bash_path(tmp_path), TRAE_ENV="cn")
    for _ in range(2):
        cp = subprocess.run(["bash", _bash_path(root / "install.sh"),
                             "--dest", _bash_path(dest), "--no-hooks"],
                            cwd=str(root), env=env, capture_output=True, text=True)
        assert cp.returncode == 0, cp.stderr[-500:]
    man = (dest / ".spz-manifest").read_text(encoding="utf-8")
    entries = [ln for ln in man.splitlines() if ln and not ln.startswith("#")]
    assert "gatekeeper-cli.sh" in entries, man[:300]
    assert len(entries) > 100, len(entries)
    cp = subprocess.run(["bash", _bash_path(root / "uninstall.sh"),
                         "--dest", _bash_path(dest), "--yes"],
                        cwd=str(root), env=env, capture_output=True, text=True)
    assert cp.returncode == 0, cp.stderr[-500:]
    assert not (dest / "gatekeeper-cli.sh").exists(), "卸载后仍残留安装面文件"


def test_plugin_manifest_detects_missing_builtin(tmp_path):
    manifests = {"p": {"id": "p", "url": "builtin:${SKILL_DIR}/scripts/nope.py",
                       "intercept": ("x",), "write": False, "undo": None}}
    probs = G.plugin_manifest_issues(manifests, tmp_path, None)
    assert any(p["level"] == "error" and p["check"] == "plugin_manifest" for p in probs), probs


def test_plugin_manifest_write_requires_undo(tmp_path):
    manifests = {"p": {"id": "p", "url": "builtin:${SKILL_DIR}/scripts/nope.py",
                       "intercept": ("x",), "write": True, "undo": None}}
    probs = G.plugin_manifest_issues(manifests, tmp_path, None)
    assert any("undo" in p["detail"] for p in probs), probs


def test_hook_local_imports_extracts_gk_modules():
    text = "import os\nfrom gk_review_nodes import x\nimport gk_json_utils\n"
    assert G.hook_local_imports(text) == ["gk_review_nodes", "gk_json_utils"]


def test_real_tree_has_no_integrity_errors():
    r = G.collect(Path(__file__).resolve().parent.parent)
    errors = [i for i in r["issues"] if i["level"] == "error"]
    assert r["ok"], errors


# ── 本体随包（2026-11-05，方案 B）：vendor 载体存在即满足，不再报「外部源」 ──────────

def _manifest_with_vendor(path):
    return {"p": {"id": "p", "intercept": ("a",), "url": "pip:x",
                  "vendor": path, "write": False, "undo": None}}


def test_vendor_source_satisfies_plugin_carrier(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "x.whl").write_bytes(b"x")
    assert G.plugin_manifest_issues(_manifest_with_vendor("vendor/x.whl"), tmp_path) == []


def test_vendor_missing_is_error(tmp_path):
    issues = G.plugin_manifest_issues(_manifest_with_vendor("vendor/nope.whl"), tmp_path)
    assert any(i["level"] == "error" and i["check"] == "plugin_manifest" for i in issues)
