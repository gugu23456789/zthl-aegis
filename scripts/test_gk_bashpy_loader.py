"""test_gk_bashpy_loader.py — bashpy-migrate 加载安全网测试（2026-08-23）。

覆盖: 发布包校验通过 / 发布包未校验 / 哈希不匹配拦截 / dev 回退 / missing / error。
安全网 R1: 只 patch 被测模块边界（_IMPORT_MODULE 注入点），不 patch 标准库全局。
"""
import json
import sys
import types
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parent))

import gk_bashpy_loader as gbl


def _fake_audit_module(bomb_scan_fn=None):
    mod = types.ModuleType("zthl_bashpy_migrate.audit")
    mod.bomb_scan = bomb_scan_fn or (lambda src: {"counts": {}})
    return mod


class TestLoadStatus:
    def test_release_verified(self, tmp_path):
        """发布包 + SHA256 命中 → source=release。"""
        f = tmp_path / "audit.py"
        f.write_text("x")
        with patch("gk_bashpy_loader._installed_version", return_value="0.1.0"), \
             patch.dict("gk_bashpy_loader._RELEASE_PINS", {"0.1.0": "abc123"}), \
             patch("gk_bashpy_loader._sha256_file", return_value="abc123"), \
             patch("gk_bashpy_loader._imported_module_file", return_value=f):
            st = gbl.load_status()
        assert st["source"] == "release"
        assert st["hash_verified"] is True

    def test_release_unverified(self, tmp_path):
        """发布包已装但无固定哈希 → release_unverified（WARN 语义）。

        _RELEASE_PINS 已被真实登记（v0.1.0），故此处 patch 为空 dict 模拟"未登记"。
        """
        f = tmp_path / "audit.py"
        f.write_text("x")
        with patch("gk_bashpy_loader._installed_version", return_value="0.1.0"), \
             patch.dict("gk_bashpy_loader._RELEASE_PINS", {}, clear=True), \
             patch("gk_bashpy_loader._imported_module_file", return_value=f):
            st = gbl.load_status()
        assert st["source"] == "release_unverified"
        assert st["hash_verified"] is None

    def test_hash_mismatch(self, tmp_path):
        """发布包 SHA256 不匹配 → hash_mismatch（误加载拦截）。"""
        f = tmp_path / "audit.py"
        f.write_text("x")
        with patch("gk_bashpy_loader._installed_version", return_value="0.1.0"), \
             patch.dict("gk_bashpy_loader._RELEASE_PINS", {"0.1.0": "expected"}), \
             patch("gk_bashpy_loader._sha256_file", return_value="tampered"), \
             patch("gk_bashpy_loader._imported_module_file", return_value=f):
            st = gbl.load_status()
        assert st["source"] == "hash_mismatch"
        assert st["hash_verified"] is False

    def test_dev_fallback(self, tmp_path):
        """未安装发布包 → 本地 dev 源码回退（dev 分支不调用 import_module，只取模块文件路径）。"""
        f = tmp_path / "audit.py"
        f.write_text("x")
        with patch("gk_bashpy_loader._installed_version", return_value=None), \
             patch("gk_bashpy_loader._import_dev", return_value=True), \
             patch("gk_bashpy_loader._imported_module_file", return_value=f):
            st = gbl.load_status()
        assert st["source"] == "dev"
        assert st["hash_verified"] is None

    def test_missing(self):
        """发布包未装且无 dev 源码 → missing（漏加载显式报告）。"""
        with patch("gk_bashpy_loader._installed_version", return_value=None), \
             patch("gk_bashpy_loader._import_dev", return_value=False):
            st = gbl.load_status()
        assert st["source"] == "missing"

    def test_error(self, tmp_path):
        """本地源码存在但导入失败 → error。"""
        f = tmp_path / "audit.py"
        f.write_text("x")

        def _boom(*a, **k):
            raise ImportError("boom")
        with patch("gk_bashpy_loader._installed_version", return_value=None), \
             patch("gk_bashpy_loader._import_dev", return_value=True), \
             patch("gk_bashpy_loader._IMPORT_MODULE", side_effect=_boom):
            st = gbl.load_status()
        assert st["source"] == "error"


class TestLoadBombScan:
    def test_release_returns_callable(self, tmp_path):
        """release 路径返回可调用 bomb_scan + 状态。"""
        f = tmp_path / "audit.py"
        f.write_text("x")
        with patch("gk_bashpy_loader._installed_version", return_value="0.1.0"), \
             patch.dict("gk_bashpy_loader._RELEASE_PINS", {"0.1.0": "abc"}), \
             patch("gk_bashpy_loader._sha256_file", return_value="abc"), \
             patch("gk_bashpy_loader._imported_module_file", return_value=f), \
             patch("gk_bashpy_loader._IMPORT_MODULE", return_value=_fake_audit_module()):
            fn, st = gbl.load_bomb_scan()
        assert callable(fn)
        assert st["source"] == "release"

    def test_hash_mismatch_falls_to_dev(self, tmp_path):
        """哈希不匹配 → 拒绝发布包，回退 dev。

        注意: _IMPORT_MODULE 的 patch 必须放在 with 最后一位 ——
        注入点 patch 目标由 pkgutil.resolve_name 解析，且其副作用半径最小。
        """
        f = tmp_path / "audit.py"
        f.write_text("x")
        with patch("gk_bashpy_loader._installed_version", return_value="0.1.0"), \
             patch.dict("gk_bashpy_loader._RELEASE_PINS", {"0.1.0": "expected"}), \
             patch("gk_bashpy_loader._sha256_file", return_value="tampered"), \
             patch("gk_bashpy_loader._imported_module_file", return_value=f), \
             patch("gk_bashpy_loader._import_dev", return_value=True), \
             patch("gk_bashpy_loader._IMPORT_MODULE", return_value=_fake_audit_module()):
            fn, st = gbl.load_bomb_scan()
        assert st["source"] == "dev"
        assert callable(fn)

    def test_missing_returns_none(self):
        """missing → (None, status)。"""
        with patch("gk_bashpy_loader._installed_version", return_value=None), \
             patch("gk_bashpy_loader._import_dev", return_value=False):
            fn, st = gbl.load_bomb_scan()
        assert fn is None
        assert st["source"] == "missing"


class TestUpgradePendingFields:
    def test_pending_flag_when_cache_newer(self, tmp_path):
        """last-check 缓存最新版本高于当前解析版本 → upgrade_pending=True。"""
        f = tmp_path / "audit.py"
        f.write_text("x")
        cache = tmp_path / "cache"
        cache.mkdir()
        (cache / "last-check.json").write_text(
            json.dumps({"latest_version": "0.2.4"}), encoding="utf-8")
        with patch("gk_bashpy_loader._installed_version", return_value="0.1.0"), \
             patch.dict("gk_bashpy_loader._RELEASE_PINS", {"0.1.0": "abc"}), \
             patch("gk_bashpy_loader._sha256_file", return_value="abc"), \
             patch("gk_bashpy_loader._imported_module_file", return_value=f), \
             patch("gk_bashpy_loader._CACHE_FILE", cache / "last-check.json"):
            st = gbl.load_status()
        assert st["source"] == "release"
        assert st["latest_known"] == "0.2.4"
        assert st["upgrade_pending"] is True
        assert st["pin_status"] == "pinned"

    def test_fields_backward_compat_no_cache(self, tmp_path):
        """无缓存 → 新字段 None/False，旧字段不变（向后兼容）。"""
        f = tmp_path / "audit.py"
        f.write_text("x")
        with patch("gk_bashpy_loader._installed_version", return_value="0.1.0"), \
             patch.dict("gk_bashpy_loader._RELEASE_PINS", {"0.1.0": "abc"}), \
             patch("gk_bashpy_loader._sha256_file", return_value="abc"), \
             patch("gk_bashpy_loader._imported_module_file", return_value=f), \
             patch("gk_bashpy_loader._CACHE_FILE", tmp_path / "none.json"):
            st = gbl.load_status()
        assert st["source"] == "release"
        assert st["latest_known"] is None
        assert st["upgrade_pending"] is False
        assert st["pin_status"] == "pinned"

    def test_pending_flag_dev_source(self, tmp_path):
        """dev 源 '0.1.0-dev' vs 缓存 '0.2.4' → upgrade_pending=True + pin_status=unpinned。"""
        f = tmp_path / "audit.py"
        f.write_text("x")
        cache = tmp_path / "cache"
        cache.mkdir()
        (cache / "last-check.json").write_text(
            json.dumps({"latest_version": "0.2.4"}), encoding="utf-8")
        with patch("gk_bashpy_loader._installed_version", return_value=None), \
             patch("gk_bashpy_loader._import_dev", return_value=True), \
             patch("gk_bashpy_loader._imported_module_file", return_value=f), \
             patch("gk_bashpy_loader._CACHE_FILE", cache / "last-check.json"):
            st = gbl.load_status()
        assert st["source"] == "dev"
        assert st["latest_known"] == "0.2.4"
        assert st["upgrade_pending"] is True
        assert st["pin_status"] == "unpinned"

    def test_broken_cache_silent(self, tmp_path):
        """缓存损坏（非法 JSON）→ latest_known=None 静默降级。"""
        f = tmp_path / "audit.py"
        f.write_text("x")
        cache = tmp_path / "cache"
        cache.mkdir()
        (cache / "last-check.json").write_text("{not-json", encoding="utf-8")
        with patch("gk_bashpy_loader._installed_version", return_value="0.1.0"), \
             patch.dict("gk_bashpy_loader._RELEASE_PINS", {"0.1.0": "abc"}), \
             patch("gk_bashpy_loader._sha256_file", return_value="abc"), \
             patch("gk_bashpy_loader._imported_module_file", return_value=f), \
             patch("gk_bashpy_loader._CACHE_FILE", cache / "last-check.json"):
            st = gbl.load_status()
        assert st["latest_known"] is None
        assert st["upgrade_pending"] is False
