#!/usr/bin/env python3
"""test_gk_review_pins.py — Review-channel pin 表 (D-lite) 测试（2026-09-04）。

对齐加载安全网 R1（测试只 patch 模块级注入点/本地临时文件，不依赖真实仓库组件）：
真实 source 存在性用 SKILL 内 subagent_runner.py；sha256 dev 语义用 monkeypatch。
"""
import json
import subprocess
import sys
from pathlib import Path


import gk_review_pins as rp

SKILL = Path(__file__).resolve().parent.parent


class TestChannels:
    def test_known_channels(self):
        assert "plan-refinement" in rp._CHANNELS
        assert "crossrev" in rp._CHANNELS

    def test_unknown_channel_fail(self):
        out = rp.verify_channel("nope")
        assert out["ok"] is False
        assert "UNKNOWN_CHANNEL" in out["error"]

    def test_contract_fields(self):
        for ch in ("plan-refinement", "crossrev"):
            c = rp.contract_fields(ch)
            assert c["ok"] is True
            assert "conclusion" in c["contract"]

    def test_source_missing_fail(self, monkeypatch, tmp_path):
        monkeypatch.setattr(rp, "SKILL", tmp_path)  # 无 scripts/subagent_runner.py
        out = rp.verify_channel("crossrev")
        assert out["ok"] is False
        assert any(c["status"] == "FAIL" and "source_missing" in c["reason"] for c in out["checks"])

    def test_sha256_mismatch_fail(self, monkeypatch, tmp_path):
        runner = tmp_path / "scripts" / "subagent_runner.py"
        runner.parent.mkdir(parents=True)
        runner.write_text("print(1)", encoding="utf-8")
        monkeypatch.setattr(rp, "SKILL", tmp_path)
        monkeypatch.setattr(rp, "_REVIEW_PINS", {
            "subagent_runner": {"source": "scripts/subagent_runner.py", "sha256": "0" * 64,
                                "output_contract": []}})
        out = rp.verify_channel("crossrev")
        assert out["ok"] is False
        assert any("source_sha256_mismatch" in c["reason"] for c in out["checks"])

    def test_dev_unpinned_warns(self):
        """sha256=None → dev WARN 非 FAIL（真实 SKILL 组件存在性验证）。"""
        out = rp.verify_channel("plan-refinement")
        assert out["ok"] is True
        assert any("dev_unpinned" in w["reason"] for w in out["warnings"])

    def test_cli_exit2_unknown_channel(self):
        r = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "gk_review_pins.py"),
             "verify", "--channel", "bogus"],
            capture_output=True, text=True, timeout=30)
        assert r.returncode == 2
        assert json.loads(r.stdout)["ok"] is False

    def test_cli_verify_known(self):
        r = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "gk_review_pins.py"),
             "verify", "--channel", "crossrev"],
            capture_output=True, text=True, timeout=30)
        assert r.returncode == 0
        d = json.loads(r.stdout)
        assert d["ok"] is True
