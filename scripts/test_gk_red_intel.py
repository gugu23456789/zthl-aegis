#!/usr/bin/env python3
"""红队情报源准入闸红先臂（2026-11-01，第二期）。

判据：
  1. 登记表自检通过（id/hosts 小写/url https/风险等级/只读不下载/日期）；
  2. `gate_url`：仅 https + 宿主白名单 + 禁下载后缀；
  3. `risk_tier=high` ⟹ 必须沙箱（`GK_RED_INTEL_SANDBOX=1` + KVM probe），否则 fail-closed；
  4. `plan` 产出确定性查询串 + 策略横幅；
  5. 不新建出网口：取数仍委托 `gk_web_tools`（测试只验闸门，不发网络请求）。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import gk_red_intel as I  # noqa: E402


def _reg():
    return I.load()


def test_registry_check_ok():
    out = I.check(_reg())
    assert out["ok"] is True, out["errors"][:5]
    assert out["counts"]["sources"] >= 15
    assert out["counts"]["high_risk"] >= 1
    assert out["counts"]["sandbox"] == out["counts"]["high_risk"]


def test_every_source_is_read_only_and_no_download():
    for s in _reg()["sources"]:
        assert s.get("download") is False, s["id"]
        assert s.get("hosts"), s["id"]
        assert all(h == h.lower() for h in s["hosts"]), s["id"]


def test_plan_builds_deterministic_queries():
    out = I.plan("usenix-security", "prompt injection")
    assert out["ok"] and out["source"] == "usenix-security"
    assert out["queries"] and "site:www.usenix.org" in out["queries"][0]
    assert out["read_only"] is True and out["download"] is False
    assert "RED_INTEL_POLICY" in out["policy"]


def test_plan_unknown_source_fails():
    assert I.plan("no-such-source", "x")["ok"] is False


def test_gate_rejects_non_https():
    g = I.gate_url("http://www.usenix.org/x")
    assert g["allowed"] is False and "https" in g["reason"]


def test_gate_rejects_host_outside_registry():
    g = I.gate_url("https://evil.example.com/x")
    assert g["allowed"] is False and "白名单" in g["reason"]


def test_gate_rejects_download_suffix():
    g = I.gate_url("https://www.usenix.org/paper.pdf")
    assert g["allowed"] is False and "禁下载" in g["reason"]
    g2 = I.gate_url("https://github.com/Tencent/AI-Infra-Guard/archive.zip")
    assert g2["allowed"] is False and "禁下载" in g2["reason"]


def test_gate_is_source_scoped():
    url = "https://www.usenix.org/conference/x"
    assert I.gate_url(url, "usenix-security")["allowed"] is True
    g = I.gate_url(url, "ndss")
    assert g["allowed"] is False and "白名单" in g["reason"]


def test_high_risk_requires_sandbox(monkeypatch):
    monkeypatch.delenv(I.SANDBOX_ENV, raising=False)
    g = I.gate_url("https://nvd.nist.gov/vuln/search", "nvd")
    assert g["allowed"] is False
    assert I.SANDBOX_ENV in g["reason"]


def test_high_risk_allows_when_sandbox_ready(monkeypatch):
    monkeypatch.setattr(I, "sandbox_ready", lambda: (True, "sandbox ready"))
    g = I.gate_url("https://nvd.nist.gov/vuln/search", "nvd")
    assert g["allowed"] is True and g["sandbox_required"] is True


def test_low_risk_needs_no_sandbox(monkeypatch):
    monkeypatch.delenv(I.SANDBOX_ENV, raising=False)
    g = I.gate_url("https://www.usenix.org/conference/usenixsecurity25/technical-sessions",
                   "usenix-security")
    assert g["allowed"] is True and g["sandbox_required"] is False


def test_red_fetch_blocks_before_network(monkeypatch):
    """闸门拒绝时**不得**触网（monkeypatch 让 gk_web_tools.fetch 一被调用就炸）。"""
    import gk_web_tools as W

    def _boom(url):
        raise AssertionError("gate 未拦住就触网了")

    monkeypatch.setattr(W, "fetch", _boom)
    out = json.loads(I.red_fetch("https://evil.example.com/x"))
    assert out["ok"] is False and "RED_INTEL_GATE" in out["error"]


def test_cli_exit_codes():
    assert I.main(["check"]) == 0
    assert I.main(["bogus"]) == 2
