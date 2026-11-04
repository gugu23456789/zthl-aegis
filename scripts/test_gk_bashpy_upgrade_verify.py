"""test_gk_bashpy_upgrade_verify.py — 安装钩子升级（原子落盘 / 体检 / 装包失败回滚）。

2026-11-04 用户要求：bashpy 安装钩子升级 = pin / 回滚 / 体检。
覆盖：
  - `_atomic_write`：替换内容且不留 .tmp
  - `cmd_verify`：装对 PASS / 哈希不符 FAIL / 版本未登记 FAIL / 未装 WARN / 落后 WARN
  - `cmd_upgrade(install=True)`：pip 失败 → 配置回滚；体检失败 → 配置回滚
R1 纪律：只 patch 被测模块边界，不 patch 标准库全局。
"""
import hashlib
import json
import sys
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest


sys.path.insert(0, str(Path(__file__).parent))

import gk_bashpy_upgrade as gbu


AUDIT = b"# fake audit module payload\n"
AUDIT_SHA = hashlib.sha256(AUDIT).hexdigest()


def _make_wheel(tmp_path, audit_content=AUDIT) -> Path:
    whl = tmp_path / "zthl_bashpy_migrate-0.9.9-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as z:
        z.writestr("zthl_bashpy_migrate/audit.py", audit_content)
    return whl


def _make_tgz(tmp_path) -> Path:
    p = tmp_path / "pkg-0.9.9.tgz"
    p.write_bytes(b"tarball-bytes")
    return p


def _pin_loader(tmp_path, version="0.9.9", sha=AUDIT_SHA) -> Path:
    """复制真实 loader 并注入目标版本 pin（cmd_verify/_current_pins 的读取源）。"""
    src = Path(gbu.SCRIPTS_DIR / "gk_bashpy_loader.py").read_text(encoding="utf-8")
    out = tmp_path / "gk_bashpy_loader.py"
    out.write_text(gbu._update_loader_pins(src, version, sha), encoding="utf-8")
    return out


def _release(integrity: str, whl: Path) -> dict:
    return {"tag_name": "v0.9.9", "assets": [
        {"name": "x.whl", "browser_download_url": "u/whl"},
        {"name": "x.tgz", "browser_download_url": "u/tgz"},
        {"name": "npm-integrity.json", "browser_download_url": "u/int"},
        {"name": "wheel-integrity.json", "browser_download_url": "u/wint"},
    ]}


def _install_harness(tmp_path, tgz: Path, whl: Path):
    """返回 (fake_download, wint, integrity) —— 对账可通过的下载桩。"""
    integrity = "sha512-" + hashlib.sha512(tgz.read_bytes()).hexdigest()
    wint = {"wheel": whl.name, "sha256": hashlib.sha256(whl.read_bytes()).hexdigest()}

    def _fake_download(url, dest):
        if url == "u/whl":
            dest.write_bytes(whl.read_bytes())
        elif url == "u/tgz":
            dest.write_bytes(tgz.read_bytes())
        elif url == "u/wint":
            dest.write_text(json.dumps(wint), encoding="utf-8")
        else:
            dest.write_text(json.dumps({"integrity": integrity}), encoding="utf-8")

    return _fake_download, integrity


class TestAtomicWrite:
    def test_replaces_and_leaves_no_tmp(self, tmp_path):
        p = tmp_path / "x.py"
        p.write_text("old\n", encoding="utf-8")
        gbu._atomic_write(p, "new\n")
        assert p.read_text(encoding="utf-8") == "new\n"
        assert not (tmp_path / "x.py.tmp").exists()


class TestVerify:
    def test_pass_when_version_and_hash_match(self, tmp_path):
        loader = _pin_loader(tmp_path)
        audit = tmp_path / "audit.py"
        audit.write_bytes(AUDIT)
        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade.LOADER_FILE", loader), \
             patch("gk_bashpy_upgrade._installed_dist", return_value=("0.9.9", audit)):
            out = gbu.cmd_verify()
        assert out["ok"] is True, out
        status = {c["check"]: c["status"] for c in out["checks"]}
        assert status["pin_registered"] == "PASS"
        assert status["hash_match"] == "PASS"

    def test_fail_on_hash_mismatch(self, tmp_path):
        loader = _pin_loader(tmp_path)
        audit = tmp_path / "audit.py"
        audit.write_bytes(b"tampered payload")
        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade.LOADER_FILE", loader), \
             patch("gk_bashpy_upgrade._installed_dist", return_value=("0.9.9", audit)):
            out = gbu.cmd_verify()
        assert out["ok"] is False
        assert any(c["check"] == "hash_match" and c["status"] == "FAIL" for c in out["checks"])

    def test_fail_on_unregistered_version(self, tmp_path):
        loader = _pin_loader(tmp_path)
        audit = tmp_path / "audit.py"
        audit.write_bytes(AUDIT)
        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade.LOADER_FILE", loader), \
             patch("gk_bashpy_upgrade._installed_dist", return_value=("9.9.9", audit)):
            out = gbu.cmd_verify()
        assert out["ok"] is False
        assert any(c["check"] == "pin_registered" and c["status"] == "FAIL" for c in out["checks"])

    def test_warn_not_fail_when_not_installed(self, tmp_path):
        """dev 源码模式（未 pip 装）是合法状态：WARN，不判失败。"""
        loader = _pin_loader(tmp_path)
        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade.LOADER_FILE", loader), \
             patch("gk_bashpy_upgrade._installed_dist", return_value=(None, None)):
            out = gbu.cmd_verify()
        assert out["ok"] is True, out
        assert out["checks"][0]["status"] == "WARN"

    def test_warn_when_behind_latest_pin(self, tmp_path):
        older = tmp_path / "old_loader.py"
        older.write_text(gbu._update_loader_pins(
            Path(gbu.SCRIPTS_DIR / "gk_bashpy_loader.py").read_text(encoding="utf-8"),
            "0.0.1", AUDIT_SHA), encoding="utf-8")
        audit = tmp_path / "audit.py"
        audit.write_bytes(AUDIT)
        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade.LOADER_FILE", older), \
             patch("gk_bashpy_upgrade._installed_dist", return_value=("0.0.1", audit)):
            out = gbu.cmd_verify()
        assert any(c["check"] == "freshness" and c["status"] == "WARN" for c in out["checks"])


class TestUpgradeInstall:
    def _run(self, tmp_path, pip_ok, verify_ok):
        whl = _make_wheel(tmp_path)
        tgz = _make_tgz(tmp_path)
        loader_cp = tmp_path / "gk_bashpy_loader.py"
        loader_orig = Path(gbu.SCRIPTS_DIR / "gk_bashpy_loader.py").read_text(encoding="utf-8")
        loader_cp.write_text(loader_orig, encoding="utf-8")
        man_cp = tmp_path / "gk_plugin_manifest.py"
        man_cp.write_text(Path(gbu.SCRIPTS_DIR / "gk_plugin_manifest.py").read_text(encoding="utf-8"),
                          encoding="utf-8")
        fake_dl, integrity = _install_harness(tmp_path, tgz, whl)
        chk = {"ok": verify_ok, "installed": "0.9.9", "checks": []}
        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade._fetch_json", return_value=_release(integrity, whl)), \
             patch("gk_bashpy_upgrade._download_to", side_effect=fake_dl), \
             patch("gk_bashpy_upgrade.LOADER_FILE", loader_cp), \
             patch("gk_bashpy_upgrade.MANIFEST_FILE", man_cp), \
             patch("gk_bashpy_upgrade._pip_install",
                   return_value=(pip_ok, "" if pip_ok else "pip rc=1: boom")), \
             patch("gk_bashpy_upgrade.cmd_verify", return_value=chk):
            out = gbu.cmd_upgrade(install=True)
        return out, loader_cp, loader_orig, man_cp

    def test_pip_failure_rolls_back_config(self, tmp_path):
        out, loader_cp, loader_orig, _man = self._run(tmp_path, pip_ok=False, verify_ok=False)
        assert out["ok"] is False
        assert "安装失败" in out["error"]
        assert loader_cp.read_text(encoding="utf-8") == loader_orig
        assert '"0.9.9"' not in loader_cp.read_text(encoding="utf-8")

    def test_verify_failure_rolls_back_config(self, tmp_path):
        out, loader_cp, loader_orig, _man = self._run(tmp_path, pip_ok=True, verify_ok=False)
        assert out["ok"] is False
        assert "体检不通过" in out["error"]
        assert loader_cp.read_text(encoding="utf-8") == loader_orig
        assert '"0.9.9"' not in loader_cp.read_text(encoding="utf-8")

    def test_success_path_keeps_new_pins(self, tmp_path):
        out, loader_cp, _orig, _man = self._run(tmp_path, pip_ok=True, verify_ok=True)
        assert out["ok"] is True, out
        assert '"0.9.9"' in loader_cp.read_text(encoding="utf-8")
        assert "verify" in out


class TestMainCli:
    def test_verify_command_wired(self, capsys, tmp_path):
        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade._installed_dist", return_value=(None, None)):
            assert gbu.main(["verify"]) == 0
        assert "checks" in json.loads(capsys.readouterr().out)

    def test_bad_usage_mentions_verify(self, capsys):
        assert gbu.main(["bogus"]) == 1
        assert "verify" in capsys.readouterr().out


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
