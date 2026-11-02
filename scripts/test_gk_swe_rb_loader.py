"""test_gk_swe_rb_loader.py — swe-rb 插件加载安全网测试（2026-08-31）。

覆盖: 发布包命中 / 发布包未固定哈希（release-unpinned 降级 dev）/
哈希不匹配拦截 / dev 源码回退 / missing / error。
安全网 R1: 只 patch 被测模块边界（_IMPORT_MODULE / _DISTRIBUTION 注入点），
不 patch 标准库 importlib 全局。
"""
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_swe_rb_loader as gsl


def _fake_dist(version="0.1.0"):
    dist = types.SimpleNamespace()
    dist.version = version
    return dist


def _fake_audit_module():
    return types.ModuleType("zthl_swe_rb.audit")


class TestLoadStatus:
    def test_release_verified(self, tmp_path):
        """发布包 + SHA256 命中 → status=release。"""
        f = tmp_path / "audit.py"
        f.write_text("x", encoding="utf-8")
        with patch("gk_swe_rb_loader._DISTRIBUTION", return_value=_fake_dist("0.1.0")), \
             patch.dict("gk_swe_rb_loader._RELEASE_PINS", {"0.1.0": "abc123"}), \
             patch("gk_swe_rb_loader._sha256_file", return_value="abc123"), \
             patch("gk_swe_rb_loader._IMPORT_MODULE", return_value=_fake_audit_module()):
            st = gsl.load_status()
        assert st["status"] == "release"
        assert st["source"] == "release"

    def test_release_unpinned_dev_fallback(self, tmp_path):
        """发布包已装但哈希未登记 → 降级 dev（release-unpinned）。"""
        f = tmp_path / "audit.py"
        f.write_text("x", encoding="utf-8")
        with patch("gk_swe_rb_loader._DISTRIBUTION", return_value=_fake_dist("0.1.0")), \
             patch.dict("gk_swe_rb_loader._RELEASE_PINS", {}, clear=True):
            st = gsl.load_status()
        assert st["status"] == "dev"
        assert st["source"] == "release-unpinned"

    def test_hash_mismatch(self, tmp_path):
        """发布包 SHA256 不匹配 → error + hash_mismatch（误加载拦截）。"""
        f = tmp_path / "audit.py"
        f.write_text("x", encoding="utf-8")
        with patch("gk_swe_rb_loader._DISTRIBUTION", return_value=_fake_dist("0.1.0")), \
             patch.dict("gk_swe_rb_loader._RELEASE_PINS", {"0.1.0": "expected"}), \
             patch("gk_swe_rb_loader._sha256_file", return_value="tampered"), \
             patch("gk_swe_rb_loader._IMPORT_MODULE", return_value=_fake_audit_module()):
            st = gsl.load_status()
        assert st["status"] == "error"
        assert st["source"] == "hash_mismatch"

    def test_dev_fallback(self, tmp_path):
        """未安装发布包 → 本地 dev 源码回退。"""
        f = tmp_path / "audit.py"
        f.write_text("x", encoding="utf-8")
        with patch("gk_swe_rb_loader._DISTRIBUTION", side_effect=importlib_metadata_not_found()), \
             patch("gk_swe_rb_loader._DEV_SOURCE_DIRS", (str(tmp_path),)), \
             patch("gk_swe_rb_loader._IMPORT_MODULE", return_value=_fake_audit_module()):
            st = gsl.load_status()
        assert st["status"] == "dev"
        assert st["source"] == "dev"

    def test_missing(self):
        """发布包未装且无 dev 源码 → missing（漏加载显式报告）。"""
        with patch("gk_swe_rb_loader._DISTRIBUTION", side_effect=importlib_metadata_not_found()), \
             patch("gk_swe_rb_loader._DEV_SOURCE_DIRS", ()):
            st = gsl.load_status()
        assert st["status"] == "missing"
        assert st["source"] == "missing"

    def test_error(self, tmp_path):
        """本地源码存在但导入失败 → error。"""
        f = tmp_path / "audit.py"
        f.write_text("x", encoding="utf-8")

        def _boom(*a, **k):
            raise ImportError("boom")
        with patch("gk_swe_rb_loader._DISTRIBUTION", side_effect=importlib_metadata_not_found()), \
             patch("gk_swe_rb_loader._DEV_SOURCE_DIRS", (str(tmp_path),)), \
             patch("gk_swe_rb_loader._IMPORT_MODULE", side_effect=_boom):
            st = gsl.load_status()
        assert st["status"] == "error"
        assert st["source"] == "dev-import"


def importlib_metadata_not_found():
    """构造与 PackageNotFoundError 等价的异常工厂（不直接 import 抛错路径外行为）。"""
    from importlib.metadata import PackageNotFoundError
    def _raise(name):
        raise PackageNotFoundError(name)
    return _raise


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
