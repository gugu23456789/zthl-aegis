"""test_gk_bashpy_upgrade_redteam.py — 平滑升级模块红队测试（投毒篡改攻击面，2026-08-26）。

按攻击面分级（对齐 plugin-loading-test-framework.md 插件红队模板）：
- A（Critical）wheel self-certification：upgrade 从下载 wheel 提取 audit.py 算 sha256 登记
  _RELEASE_PINS——无独立第三方比对源，MITM 投毒 wheel 即登记投毒 pin（self-certification 缺陷）。
  防护：CI 发布 wheel-integrity.json（官方 wheel sha256 清单），upgrade 下载后比对。
- B（High）备份无完整性：篡改 backups/<ts>/ 文件 → rollback 恢复投毒配置。
  防护：备份时写 backup-manifest.json（文件→sha256），rollback 前校验。
- C（Medium）注入：恶意 version/integrity 字符串绕过正则替换（代码注入面）。
  防护：semver 白名单 + 128-hex 校验。
- D（Medium）缓存投毒：last-check.json latest_version 非字符串 → load_status 崩溃 / 误报。
  防护：_semver_key 输入防御（非 str → 忽略）。
- E（Low）失败残留：对账失败后 downloads/ 残留投毒文件污染下次升级。
  防护：失败路径清理 downloads。

R1 纪律：只 patch 被测模块边界；网络全 mock；不触碰真实 skill 配置（patch 常量到 tmp）。
"""
import hashlib
import json
import sys
import zipfile
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parent))

import gk_bashpy_upgrade as gbu
import gk_bashpy_loader as gbl


def _make_wheel(tmp_path, name="zthl_bashpy_migrate-0.2.4-py3-none-any.whl",
                audit_content="CLEAN") -> Path:
    whl = tmp_path / name
    with zipfile.ZipFile(whl, "w") as z:
        z.writestr("zthl_bashpy_migrate/audit.py", audit_content)
    return whl


def _make_tgz(tmp_path, name="pkg-0.2.4.tgz", content=b"tarball-bytes") -> Path:
    p = tmp_path / name
    p.write_bytes(content)
    return p


def _sha512_hex(p: Path) -> str:
    return hashlib.sha512(p.read_bytes()).hexdigest()


def _sha256_hex(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _fake_downloader(files: dict):
    """构造 _download_to 的 mock：files = {url: Path|None(→json 写入)}。"""

    def _dl(url, dest):
        src = files[url]
        if src is None:
            dest.write_text(json.dumps(files["_json"]), encoding="utf-8")
        else:
            dest.write_bytes(src.read_bytes())
    return _dl


# ── 攻击面 A（Critical）：wheel self-certification 缺陷 ────────────────
class TestAttackA_WheelSelfCertification:
    def test_poisoned_wheel_rejected_by_official_manifest(self, tmp_path):
        """投毒 wheel（audit.py='EVIL'）应被 wheel-integrity.json 官方清单拒绝。

        当前实现（漏洞）：wheel 无对账 → 登记投毒 pin（audit_sha256 来自投毒 wheel）。
        修复后：wheel sha256 vs 官方 wheel-integrity.json 不符 → 拒绝，配置零改动。
        """
        clean_wheel = _make_wheel(tmp_path, audit_content="CLEAN")
        poisoned_wheel = _make_wheel(tmp_path, name="poisoned.whl", audit_content="EVIL")
        tgz = _make_tgz(tmp_path)
        integrity = f"sha512-{_sha512_hex(tgz)}"
        # 官方清单：指向 CLEAN wheel 的 sha256（投毒 wheel 与其不同）
        wheel_int = tmp_path / "wheel-integrity.json"
        wheel_int.write_text(json.dumps(
            {"wheel": clean_wheel.name, "sha256": _sha256_hex(clean_wheel)}), encoding="utf-8")

        loader_cp = tmp_path / "gk_bashpy_loader.py"
        loader_orig = Path(gbu.SCRIPTS_DIR / "gk_bashpy_loader.py").read_text(encoding="utf-8")
        loader_cp.write_text(loader_orig, encoding="utf-8")
        man_cp = tmp_path / "gk_plugin_manifest.py"
        man_orig = Path(gbu.SCRIPTS_DIR / "gk_plugin_manifest.py").read_text(encoding="utf-8")
        man_cp.write_text(man_orig, encoding="utf-8")

        rel = {"tag_name": "v0.2.4", "assets": [
            {"name": "x.whl", "browser_download_url": "u/whl"},
            {"name": "x.tgz", "browser_download_url": "u/tgz"},
            {"name": "npm-integrity.json", "browser_download_url": "u/int"},
            {"name": "wheel-integrity.json", "browser_download_url": "u/wint"},
        ]}
        files = {"u/whl": poisoned_wheel, "u/tgz": tgz, "u/int": None, "u/wint": wheel_int,
                 "_json": {"integrity": integrity}}

        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade._fetch_json", return_value=rel), \
             patch("gk_bashpy_upgrade._download_to", side_effect=_fake_downloader(files)), \
             patch("gk_bashpy_upgrade.LOADER_FILE", loader_cp), \
             patch("gk_bashpy_upgrade.MANIFEST_FILE", man_cp):
            out = gbu.cmd_upgrade()
        assert out["ok"] is False, "投毒 wheel 必须被官方清单拒绝（self-certification 漏洞）"
        assert "wheel" in out["error"].lower()
        assert loader_cp.read_text(encoding="utf-8") == loader_orig   # 配置零改动
        assert man_cp.read_text(encoding="utf-8") == man_orig

    def test_clean_wheel_passes_official_manifest(self, tmp_path):
        """干净 wheel + 官方清单一致 → 通过并登记（对照正向路径）。"""
        clean_wheel = _make_wheel(tmp_path, audit_content="CLEAN")
        tgz = _make_tgz(tmp_path)
        integrity = f"sha512-{_sha512_hex(tgz)}"
        wheel_int = tmp_path / "wheel-integrity.json"
        wheel_int.write_text(json.dumps(
            {"wheel": clean_wheel.name, "sha256": _sha256_hex(clean_wheel)}), encoding="utf-8")

        loader_cp = tmp_path / "gk_bashpy_loader.py"
        loader_cp.write_text(Path(gbu.SCRIPTS_DIR / "gk_bashpy_loader.py").read_text(encoding="utf-8"))
        man_cp = tmp_path / "gk_plugin_manifest.py"
        man_cp.write_text(Path(gbu.SCRIPTS_DIR / "gk_plugin_manifest.py").read_text(encoding="utf-8"))

        rel = {"tag_name": "v0.2.4", "assets": [
            {"name": "x.whl", "browser_download_url": "u/whl"},
            {"name": "x.tgz", "browser_download_url": "u/tgz"},
            {"name": "npm-integrity.json", "browser_download_url": "u/int"},
            {"name": "wheel-integrity.json", "browser_download_url": "u/wint"},
        ]}
        files = {"u/whl": clean_wheel, "u/tgz": tgz, "u/int": None, "u/wint": wheel_int,
                 "_json": {"integrity": integrity}}

        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade._fetch_json", return_value=rel), \
             patch("gk_bashpy_upgrade._download_to", side_effect=_fake_downloader(files)), \
             patch("gk_bashpy_upgrade.LOADER_FILE", loader_cp), \
             patch("gk_bashpy_upgrade.MANIFEST_FILE", man_cp):
            out = gbu.cmd_upgrade()
        assert out["ok"] is True, out
        assert out["version"] == "0.2.4"
        assert '"0.2.4"' in loader_cp.read_text(encoding="utf-8")


# ── 攻击面 B（High）：备份无完整性校验 ──────────────────────────────────
class TestAttackB_TamperedBackup:
    def test_tampered_backup_rejected_on_rollback(self, tmp_path):
        """篡改 backups/<ts>/ 的 loader 备份 → rollback 拒绝（不恢复投毒内容）。

        当前实现（漏洞）：rollback 直接恢复备份文件 → 投毒内容被写入。
        修复后：backup-manifest.json 记录备份哈希，篡改 → 拒绝 + 配置零改动。
        """
        loader_cp = tmp_path / "gk_bashpy_loader.py"
        loader_orig = Path(gbu.SCRIPTS_DIR / "gk_bashpy_loader.py").read_text(encoding="utf-8")
        loader_cp.write_text(loader_orig, encoding="utf-8")
        man_cp = tmp_path / "gk_plugin_manifest.py"
        man_orig = Path(gbu.SCRIPTS_DIR / "gk_plugin_manifest.py").read_text(encoding="utf-8")
        man_cp.write_text(man_orig, encoding="utf-8")
        # 构造备份：备份内容 = 原始 + 投毒标记，manifest 记录的是【未投毒】哈希（篡改检测）
        bdir = tmp_path / "backups" / "20260826T000000Z"
        bdir.mkdir(parents=True)
        (bdir / "gk_bashpy_loader.py").write_text(loader_orig + "\n# POISONED\n", encoding="utf-8")
        (bdir / "gk_plugin_manifest.py").write_text(man_orig, encoding="utf-8")
        manifest = {
            "gk_bashpy_loader.py": hashlib.sha256(loader_orig.encode("utf-8")).hexdigest(),
            "gk_plugin_manifest.py": hashlib.sha256(man_orig.encode("utf-8")).hexdigest(),
        }
        (bdir / "backup-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade.LOADER_FILE", loader_cp), \
             patch("gk_bashpy_upgrade.MANIFEST_FILE", man_cp):
            out = gbu.cmd_rollback()
        assert out["ok"] is False, "投毒备份必须被 manifest 校验拒绝"
        assert loader_cp.read_text(encoding="utf-8") == loader_orig  # 配置零改动（未恢复投毒）


# ── 攻击面 C（Medium）：版本/哈希注入 ───────────────────────────────────
class TestAttackC_Injection:
    def test_malicious_version_rejected(self):
        """恶意版本号（非 semver，含引号/换行注入）→ upgrade 拒绝，不进入配置替换。"""
        for evil in ('0.2.4", "0.0.0": "evil', "0.2.4\nx", "0.2; rm -rf /", "..", ""):
            out = gbu._validate_version(evil)
            assert out is False, f"恶意版本 {evil!r} 必须被拒绝"

    def test_malicious_integrity_rejected(self):
        """非 128-hex integrity → 拒绝。"""
        for evil in ("sha512-abc", "sha512-" + "z" * 128,
                     "sha512-" + "0" * 64 + '" } code:', ""):
            out = gbu._validate_integrity(evil)
            assert out is False, f"恶意 integrity {evil[:20]!r} 必须被拒绝"

    def test_valid_inputs_accepted(self):
        """合法 semver + 128-hex sha512 → 通过。"""
        assert gbu._validate_version("0.2.3") is True
        assert gbu._validate_integrity("sha512-" + "0" * 128) is True


# ── 攻击面 D（Medium）：last-check 缓存投毒 ─────────────────────────────
class TestAttackD_PoisonedCache:
    def test_cache_non_string_latest_does_not_crash(self, tmp_path):
        """缓存 latest_version 为非字符串（int/list/dict）→ load_status 不崩（静默忽略）。

        当前实现（漏洞）：_semver_key(latest) 对 int 调 .lstrip → AttributeError 崩溃。
        修复后：非 str → latest=None 处理。
        """
        f = tmp_path / "audit.py"
        f.write_text("x")
        cache = tmp_path / "cache"
        cache.mkdir()
        for evil in (123, [], {}, None):
            (cache / "last-check.json").write_text(
                json.dumps({"latest_version": evil}), encoding="utf-8")
            with patch("gk_bashpy_loader._installed_version", return_value="0.1.0"), \
                 patch.dict("gk_bashpy_loader._RELEASE_PINS", {"0.1.0": "abc"}), \
                 patch("gk_bashpy_loader._sha256_file", return_value="abc"), \
                 patch("gk_bashpy_loader._imported_module_file", return_value=f), \
                 patch("gk_bashpy_loader._CACHE_FILE", cache / "last-check.json"):
                st = gbl.load_status()
            assert st["upgrade_pending"] is False, f"恶意缓存 {evil!r} 不得误报 upgrade_pending"
            assert st["latest_known"] is None or isinstance(st["latest_known"], str)


# ── 攻击面 E（Low）：对账失败残留 ───────────────────────────────────────
class TestAttackE_FailedDownloadResidue:
    def test_failed_upgrade_cleans_downloads(self, tmp_path):
        """对账失败 → downloads/ 目录清理，不残留投毒文件污染下次升级。

        当前实现（漏洞）：失败 return 不清理 downloads/。
        修复后：失败路径删除 dl 目录。
        """
        whl = _make_wheel(tmp_path)
        tgz = _make_tgz(tmp_path)
        wrong_integrity = "sha512-" + "0" * 128
        loader_cp = tmp_path / "gk_bashpy_loader.py"
        loader_cp.write_text(Path(gbu.SCRIPTS_DIR / "gk_bashpy_loader.py").read_text(encoding="utf-8"))
        man_cp = tmp_path / "gk_plugin_manifest.py"
        man_cp.write_text(Path(gbu.SCRIPTS_DIR / "gk_plugin_manifest.py").read_text(encoding="utf-8"))

        rel = {"tag_name": "v0.2.4", "assets": [
            {"name": "x.whl", "browser_download_url": "u/whl"},
            {"name": "x.tgz", "browser_download_url": "u/tgz"},
            {"name": "npm-integrity.json", "browser_download_url": "u/int"},
            {"name": "wheel-integrity.json", "browser_download_url": "u/wint"},
        ]}
        wint = tmp_path / "wheel-integrity.json"
        wint.write_text(json.dumps({"sha256": "0" * 64}), encoding="utf-8")
        files = {"u/whl": whl, "u/tgz": tgz, "u/int": None, "u/wint": wint,
                 "_json": {"integrity": wrong_integrity}}

        with patch("gk_bashpy_upgrade._cache_dir", return_value=tmp_path), \
             patch("gk_bashpy_upgrade._fetch_json", return_value=rel), \
             patch("gk_bashpy_upgrade._download_to", side_effect=_fake_downloader(files)), \
             patch("gk_bashpy_upgrade.LOADER_FILE", loader_cp), \
             patch("gk_bashpy_upgrade.MANIFEST_FILE", man_cp):
            out = gbu.cmd_upgrade()
        assert out["ok"] is False
        dl = tmp_path / "downloads"
        assert not dl.exists() or not any(dl.iterdir()), "对账失败必须清理 downloads/ 残留"
