"""test_gk_bashpy_upgrade.py — bashpy-migrate 平滑升级命令测试。
R1: 只 patch 被测模块边界（模块级函数），不 patch 标准库全局。
"""
import hashlib
import json
import sys
import zipfile
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parent))

import gk_bashpy_upgrade as gbu


def _make_wheel(tmp_path, audit_content="x") -> Path:
    whl = tmp_path / "zthl_bashpy_migrate-0.9.9-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as z:
        z.writestr("zthl_bashpy_migrate/audit.py", audit_content)
    return whl


def _make_tgz(tmp_path, name="pkg-0.9.9.tgz", content=b"tarball-bytes") -> Path:
    p = tmp_path / name
    p.write_bytes(content)
    return p


def _sha512_hex(p: Path) -> str:
    return hashlib.sha512(p.read_bytes()).hexdigest()


class TestStatus:
    def test_status_reports_current_pins_offline(self, tmp_path):
        """status 无网络：输出 pins 清单 + last-check（缓存缺失时为 None）。"""
        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path):
            out = gbu.cmd_status()
        assert out["ok"] is True
        assert out["latest_known"] is None          # 无缓存
        assert "0.1.0" in {p["version"] for p in out["pins"]}  # 真实 _RELEASE_PINS 至少 v0.1.0

    def test_status_reads_cache(self, tmp_path):
        """last-check 缓存存在 → latest_known/checked_at 填充。"""
        (tmp_path / "last-check.json").write_text(
            json.dumps({"latest_version": "0.9.9", "checked_at": "2026-08-26T00:00:00Z"}),
            encoding="utf-8")
        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path):
            out = gbu.cmd_status()
        assert out["latest_known"] == "0.9.9"
        assert out["checked_at"] == "2026-08-26T00:00:00Z"

    def test_main_cli_branches(self, capsys, tmp_path):
        """main: status 退出 0；未知命令退出 1；空 argv 退出 1。"""
        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path):
            assert gbu.main(["status"]) == 0
        assert gbu.main(["bogus"]) == 1
        assert gbu.main([]) == 1


class TestCheck:
    _RELEASE = {"tag_name": "v0.9.9", "assets": [{"name": "x.whl", "browser_download_url": "https://d/x.whl"}]}

    def test_check_finds_newer_writes_cache(self, tmp_path):
        """发现更高版本 → last-check 缓存写入 latest_version。"""
        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade._fetch_json", return_value=self._RELEASE):
            out = gbu.cmd_check()
        assert out["ok"] is True
        assert out["latest_version"] == "0.9.9"
        assert out["upgrade_available"] is True
        cache = json.loads((tmp_path / "last-check.json").read_text(encoding="utf-8"))
        assert cache["latest_version"] == "0.9.9"

    def test_check_up_to_date(self, tmp_path):
        """已是最新（最新 tag 不高于登记版本）→ upgrade_available=False。"""
        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade._fetch_json",
                   return_value={"tag_name": "v0.1.0", "assets": []}):
            out = gbu.cmd_check()
        assert out["upgrade_available"] is False

    def test_check_network_failure_reports_error(self, tmp_path):
        """网络失败 → 显式报错（不写缓存，不静默）。"""
        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade._fetch_json", side_effect=RuntimeError("net down")):
            out = gbu.cmd_check()
        assert out["ok"] is False
        assert "net down" in out["error"]
        assert not (tmp_path / "last-check.json").exists()  # 失败不写缓存


class TestSemverKey:
    def test_semver_key_normalizes(self):
        """固定语义：去 v 前缀、忽略后缀、转整数元组。"""
        assert gbu._semver_key("v0.2.3") == (0, 2, 3)
        assert gbu._semver_key("0.1.0-dev") == (0, 1, 0)


class TestUpgrade:
    def test_upgrade_downloads_and_pins(self, tmp_path):
        """下载 → 对账通过 → _RELEASE_PINS 新增 + manifest 更新 + 备份落盘。"""
        whl = _make_wheel(tmp_path)
        tgz = _make_tgz(tmp_path)
        integrity = f"sha512-{_sha512_hex(tgz)}"
        loader_cp = tmp_path / "gk_bashpy_loader.py"
        loader_cp.write_text(Path(gbu.SCRIPTS_DIR / "gk_bashpy_loader.py").read_text(encoding="utf-8"))
        man_cp = tmp_path / "gk_plugin_manifest.py"
        man_cp.write_text(Path(gbu.SCRIPTS_DIR / "gk_plugin_manifest.py").read_text(encoding="utf-8"))

        rel = {"tag_name": "v0.9.9", "assets": [
            {"name": "x.whl", "browser_download_url": "u/whl"},
            {"name": "x.tgz", "browser_download_url": "u/tgz"},
            {"name": "npm-integrity.json", "browser_download_url": "u/int"},
            {"name": "wheel-integrity.json", "browser_download_url": "u/wint"},
        ]}
        # 官方 wheel 清单：与下载 wheel 一致 → 通过对账
        wint = {"wheel": whl.name, "sha256": hashlib.sha256(whl.read_bytes()).hexdigest()}

        def _fake_download(url, dest):
            src = {"u/whl": whl, "u/tgz": tgz, "u/int": None, "u/wint": None}[url]
            if src is None:
                if url == "u/wint":
                    dest.write_text(json.dumps(wint), encoding="utf-8")
                else:
                    dest.write_text(json.dumps({"integrity": integrity}), encoding="utf-8")
            else:
                dest.write_bytes(src.read_bytes())

        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade._fetch_json", return_value=rel), \
             patch("gk_bashpy_upgrade._download_to", side_effect=_fake_download), \
             patch("gk_bashpy_upgrade.LOADER_FILE", loader_cp), \
             patch("gk_bashpy_upgrade.MANIFEST_FILE", man_cp):
            out = gbu.cmd_upgrade()
        assert out["ok"] is True
        assert out["version"] == "0.9.9"
        backups = list((tmp_path / "backups").glob("*/"))
        assert len(backups) == 1
        new_text = loader_cp.read_text(encoding="utf-8")
        assert '"0.9.9"' in new_text
        man_text = man_cp.read_text(encoding="utf-8")
        assert "npm:@zthl-harness/dsh-bashpy-migrate@0.9.9" in man_text
        assert integrity in man_text

    def test_upgrade_integrity_mismatch_rejected(self, tmp_path):
        """tarball sha512 与 integrity.json 不符 → 拒绝，配置零改动。"""
        whl = _make_wheel(tmp_path)
        tgz = _make_tgz(tmp_path)
        loader_cp = tmp_path / "gk_bashpy_loader.py"
        loader_orig = Path(gbu.SCRIPTS_DIR / "gk_bashpy_loader.py").read_text(encoding="utf-8")
        loader_cp.write_text(loader_orig, encoding="utf-8")
        man_cp = tmp_path / "gk_plugin_manifest.py"
        man_orig = Path(gbu.SCRIPTS_DIR / "gk_plugin_manifest.py").read_text(encoding="utf-8")
        man_cp.write_text(man_orig, encoding="utf-8")

        rel = {"tag_name": "v0.9.9", "assets": [
            {"name": "x.whl", "browser_download_url": "u/whl"},
            {"name": "x.tgz", "browser_download_url": "u/tgz"},
            {"name": "npm-integrity.json", "browser_download_url": "u/int"},
            {"name": "wheel-integrity.json", "browser_download_url": "u/wint"},
        ]}
        wrong_integrity = "sha512-" + "0" * 128
        # 官方 wheel 清单与下载 wheel 一致 → 仅 tgz 对账失败（本用例测点）
        wint = {"wheel": whl.name, "sha256": hashlib.sha256(whl.read_bytes()).hexdigest()}

        def _fake_download(url, dest):
            src = {"u/whl": whl, "u/tgz": tgz, "u/int": None, "u/wint": None}[url]
            if src is None:
                if url == "u/wint":
                    dest.write_text(json.dumps(wint), encoding="utf-8")
                else:
                    dest.write_text(json.dumps({"integrity": wrong_integrity}), encoding="utf-8")
            else:
                dest.write_bytes(src.read_bytes())

        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade._fetch_json", return_value=rel), \
             patch("gk_bashpy_upgrade._download_to", side_effect=_fake_download), \
             patch("gk_bashpy_upgrade.LOADER_FILE", loader_cp), \
             patch("gk_bashpy_upgrade.MANIFEST_FILE", man_cp):
            out = gbu.cmd_upgrade()
        assert out["ok"] is False
        assert "integrity" in out["error"].lower()
        assert loader_cp.read_text(encoding="utf-8") == loader_orig
        assert man_cp.read_text(encoding="utf-8") == man_orig


class TestRollback:
    def test_rollback_restores_backup(self, tmp_path):
        """upgrade 后 rollback → loader/manifest 恢复备份内容。"""
        loader_cp = tmp_path / "gk_bashpy_loader.py"
        loader_orig = Path(gbu.SCRIPTS_DIR / "gk_bashpy_loader.py").read_text(encoding="utf-8")
        loader_cp.write_text(loader_orig + "\n# TAMPERED\n", encoding="utf-8")
        man_cp = tmp_path / "gk_plugin_manifest.py"
        man_orig = Path(gbu.SCRIPTS_DIR / "gk_plugin_manifest.py").read_text(encoding="utf-8")
        man_cp.write_text(man_orig, encoding="utf-8")
        bdir = tmp_path / "backups" / "20260826T000000Z"
        bdir.mkdir(parents=True)
        (bdir / "gk_bashpy_loader.py").write_text(loader_orig, encoding="utf-8")
        (bdir / "gk_plugin_manifest.py").write_text(man_orig, encoding="utf-8")
        # rollback 完整性门禁：备份必须带 backup-manifest.json（记录备份文件 sha256）
        manifest = {
            "gk_bashpy_loader.py": hashlib.sha256((bdir / "gk_bashpy_loader.py").read_bytes()).hexdigest(),
            "gk_plugin_manifest.py": hashlib.sha256((bdir / "gk_plugin_manifest.py").read_bytes()).hexdigest(),
        }
        (bdir / "backup-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade.LOADER_FILE", loader_cp), \
             patch("gk_bashpy_upgrade.MANIFEST_FILE", man_cp):
            out = gbu.cmd_rollback()
        assert out["ok"] is True
        assert "# TAMPERED" not in loader_cp.read_text(encoding="utf-8")
        assert loader_cp.read_text(encoding="utf-8") == loader_orig

    def test_rollback_no_backup_reports_error(self, tmp_path):
        """无备份 → 显式报错。"""
        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path):
            out = gbu.cmd_rollback()
        assert out["ok"] is False
