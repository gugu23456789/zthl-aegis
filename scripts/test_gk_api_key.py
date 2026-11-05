#!/usr/bin/env python3
"""API key 配置面红先臂（2026-11-02，开源包可用性）。

病象（owner 指出）：README 的配置表把 key 相关项写成「未设」，而 CLI 只认环境变量与
Windows 用户环境（PowerShell）。Linux/macOS 用户没有**跨平台、可持久化**的配置入口
—— `set-key` 在非 Windows 上只导出当前进程，重启即丢。

判据：
  1. key 文件单源 `gk_api_key`：`path` 支持 provider 与 `$GATEKEEPER_KEY_FILE` 覆盖；
     `read` 去空白、mimo 回退 `api_key`、缺失返回空；
  2. `_resolve_api_key` **必须**消费 key 文件，且位于 PowerShell 回退**之前**
     （否则非 Windows 永远走不到）；
  3. `set-key` **必须**以 `0600` 持久化到 key 文件（跨平台），并在输出里给路径；
  4. `set-key status` 只报来源，不回显 key；
  5. `gk_self_check.check_provider` 消费同一单源并报 `key_source`。
"""
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import gk_api_key as K  # noqa: E402

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"
TXT = CLI.read_text(encoding="utf-8")


def _func(name):
    m = re.search(r"^%s\(\) \{.*?^\}" % re.escape(name), TXT, re.S | re.M)
    assert m, "缺函数 %s" % name
    return m.group(0)


def test_key_path_provider_and_override(tmp_path, monkeypatch):
    monkeypatch.delenv("GATEKEEPER_KEY_FILE", raising=False)
    store = tmp_path / "store"
    monkeypatch.setenv("GK_KEYS_DIR", str(store))
    assert K.key_path(str(tmp_path), "deepseek") == str(store / "api_key")
    assert K.key_path(str(tmp_path), "mimo") == str(store / "mimo_key")
    monkeypatch.setenv("GATEKEEPER_KEY_FILE", str(tmp_path / "x.key"))
    assert K.key_path(str(tmp_path), "mimo") == str(tmp_path / "x.key")


def test_read_key_file_and_mimo_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv("GATEKEEPER_KEY_FILE", raising=False)
    monkeypatch.setenv("GK_KEYS_DIR", str(tmp_path / "store"))
    assert K.read_key(str(tmp_path)) == ("", "")
    (tmp_path / "store").mkdir()
    (tmp_path / "store" / "api_key").write_text("  test-key-12345678901234567890 \n",
                                               encoding="utf-8")
    key, src = K.read_key(str(tmp_path), "deepseek")
    assert (key, src) == ("test-key-12345678901234567890", "file")
    # mimo 未单独配置 ⟹ 回退 api_key（与 CLI 的 deepseek 回退同义）
    assert K.read_key(str(tmp_path), "mimo") == (key, "file")


def test_read_key_legacy_fallback(tmp_path, monkeypatch):
    """方案 A：旧落点 `<skill>/.keys` 只读兼容（source=legacy），新落点优先。"""
    monkeypatch.delenv("GATEKEEPER_KEY_FILE", raising=False)
    monkeypatch.setenv("GK_KEYS_DIR", str(tmp_path / "store"))
    (tmp_path / ".keys").mkdir()
    (tmp_path / ".keys" / "api_key").write_text("legacy-key-1234567890123456\n",
                                                encoding="utf-8")
    assert K.read_key(str(tmp_path)) == ("legacy-key-1234567890123456", "legacy")
    (tmp_path / "store").mkdir()
    (tmp_path / "store" / "api_key").write_text("new-key-12345678901234567\n",
                                                encoding="utf-8")
    assert K.read_key(str(tmp_path)) == ("new-key-12345678901234567", "file")
    # mimo 未单独配置 ⟹ 回退 api_key（含 legacy 面）
    assert K.read_key(str(tmp_path), "mimo")[0] == "new-key-12345678901234567"


def test_migrate_copies_without_deleting(tmp_path, monkeypatch):
    """migrate = 只 copy 不删、不覆盖；重复跑报 exists。"""
    monkeypatch.setenv("GK_KEYS_DIR", str(tmp_path / "store"))
    (tmp_path / ".keys").mkdir()
    (tmp_path / ".keys" / "api_key").write_text("k-123456789012345678901234\n", encoding="utf-8")
    acts = K.migrate(str(tmp_path))
    api = [a for a in acts if a["name"] == "api_key"][0]
    assert api["action"] == "copied"
    assert (tmp_path / "store" / "api_key").read_text(encoding="utf-8").strip().startswith("k-")
    assert (tmp_path / ".keys" / "api_key").is_file(), "旧落点不得被删除"
    assert [a for a in K.migrate(str(tmp_path)) if a["name"] == "api_key"][0]["action"] == "exists"


@pytest.mark.skipif(os.name == "nt", reason="Windows 不支持 POSIX 权限位")
def test_store_dir_is_0700(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_KEYS_DIR", str(tmp_path / "store"))
    d = K.ensure_store()
    assert (os.stat(d).st_mode & 0o777) == 0o700


def test_explicit_key_file_wins(tmp_path, monkeypatch):
    f = tmp_path / "explicit.key"
    f.write_text("explicit-key-abcdefghijklmnop\n", encoding="utf-8")
    monkeypatch.setenv("GATEKEEPER_KEY_FILE", str(f))
    assert K.read_key(str(tmp_path)) == ("explicit-key-abcdefghijklmnop", "explicit")


def test_mask_never_reveals_full_key():
    m = K.mask("abcdefghijklmnopqrstuvwxyz0123")
    assert "*" in m and len(m) == len("abcdefghijklmnopqrstuvwxyz0123")


def test_cli_resolve_api_key_prefers_file_before_powershell():
    i = TXT.index("_resolve_api_key() {")
    seg = TXT[i:TXT.index("\n}\n", i)]
    assert "_gk_key_file_read" in seg, "CLI 未把 key 文件纳入解析链（开源用户无配置面）"
    assert seg.index("_gk_key_file_read") < seg.index("powershell.exe"), \
        "key 文件必须在 PowerShell 回退之前（否则 Linux/macOS 永远走不到）"


def test_set_key_persists_file_with_0600():
    seg = _func("cmd_set_key")
    assert "_gk_key_file" in seg, "set-key 未使用 key 文件单源"
    assert "umask 077" in seg, "set-key 未以 0600 语义写文件"
    assert "key_file" in seg, "set-key 输出未给落点（用户无法核对）"
    assert "status" in seg, "set-key 缺 status（只报来源，不回显 key）"


def test_selfcheck_consumes_key_store():
    import gk_self_check as S
    src = Path(S.__file__).read_text(encoding="utf-8")
    assert "gk_api_key" in src, "self-check 未消费 key 文件单源"


def test_bash_key_file_read(tmp_path):
    """真跑 bash 薄壳：`_gk_key_file_read` 必须能从 `<skill>/.keys/api_key` 取到 key。"""
    (tmp_path / ".keys").mkdir()
    (tmp_path / ".keys" / "api_key").write_text("bash-read-key-1234567890\n", encoding="utf-8")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "gk_api_key.py").write_text(
        (Path(__file__).parent / "gk_api_key.py").read_text(encoding="utf-8"), encoding="utf-8")
    script = 'SKILL_DIR="%s"\n%s\n_gk_key_file_read deepseek' % (tmp_path, _func("_gk_key_file_read"))
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,
                       env={**os.environ, "PATH": os.environ.get("PATH", "")})
    assert r.returncode == 0, r.stderr
    assert r.stdout == "bash-read-key-1234567890", r.stdout
