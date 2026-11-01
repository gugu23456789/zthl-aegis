"""
test_gk_prior_art_egress.py — 受治联网补强（B/§9.7 Q3a/Q3b/Q3e）测试
====================================================================
红先：本批改动前 `_prior_art_get` 无 egress 留痕、无 https 门、urllib 默认跟随 302
（下列用例在旧实现上全红）。

覆盖：
  · egress 留痕 append-only JSONL（host / url_sha256 / ts / ok）
  · 非白名单域 → ValueError + 留痕 ok=False
  · 非 https → ValueError + 留痕 ok=False
  · 无重定向 opener（build_opener 替换默认 HTTPRedirectHandler）
  · 成功取数 → 留痕 ok=True
"""
import json
import sys
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import subagent_runner as sr


@pytest.fixture
def egress_log(tmp_path, monkeypatch):
    p = tmp_path / "egress.jsonl"
    monkeypatch.setenv(sr._EGRESS_LOG_ENV, str(p))
    return p


def _read_log(p):
    if not p.exists():
        return []
    return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


class TestEgressLog:
    def test_record_writes_jsonl(self, egress_log):
        sr._record_egress("api2.openreview.net", "https://api2.openreview.net/x?a=1", ok=True)
        recs = _read_log(egress_log)
        assert len(recs) == 1
        r = recs[0]
        assert r["host"] == "api2.openreview.net"
        assert r["ok"] is True
        assert len(r["url_sha256"]) == 16 and all(c in "0123456789abcdef" for c in r["url_sha256"])
        assert isinstance(r["ts"], int)

    def test_non_allowlisted_host_logs_and_raises(self, egress_log):
        with pytest.raises(ValueError):
            sr._prior_art_get("https://evil.example.com/x")
        recs = _read_log(egress_log)
        assert recs and recs[-1]["ok"] is False
        assert recs[-1]["err"] == "host_not_allowlisted"

    def test_non_https_scheme_rejected_and_logged(self, egress_log):
        with pytest.raises(ValueError):
            sr._prior_art_get("http://api2.openreview.net/x")
        recs = _read_log(egress_log)
        assert recs and recs[-1]["ok"] is False
        assert recs[-1]["err"] == "scheme_not_https"


class TestNoRedirect:
    def test_strict_opener_replaces_default_redirect_handler(self):
        op = sr._strict_opener()
        assert all(type(h) is not urllib.request.HTTPRedirectHandler for h in op.handlers), \
            "默认 HTTPRedirectHandler 未被替换 ⟹ 仍会跟随 302"

    def test_redirect_request_blocked(self):
        op = sr._strict_opener()
        h = next(h for h in op.handlers
                 if isinstance(h, urllib.request.HTTPRedirectHandler))
        with pytest.raises(Exception):
            h.redirect_request(None, None, 302, "Found", {}, "https://evil.example.com/")


class TestSuccessPath:
    def test_successful_fetch_logs_ok(self, egress_log, monkeypatch):
        class _FakeResp:
            def read(self):
                return b"ok-body"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class _FakeOpener:
            def open(self, req, timeout=None):
                return _FakeResp()

        monkeypatch.setattr(sr, "_strict_opener", lambda: _FakeOpener())
        body = sr._prior_art_get("https://api2.openreview.net/notes/search?term=x")
        assert body == "ok-body"
        recs = _read_log(egress_log)
        assert recs and recs[-1]["ok"] is True


class TestSingleEgress:
    """2026-10-09（受治联网缩减版）：单出网口 `_prior_art_fetch` + egress id 回指。"""

    def test_record_egress_returns_id_and_writes_it(self, egress_log):
        eid = sr._record_egress("api2.openreview.net", "https://api2.openreview.net/x", ok=True)
        assert isinstance(eid, str) and eid.startswith("eg-")
        recs = _read_log(egress_log)
        assert recs and recs[-1]["id"] == eid

    def test_prior_art_fetch_returns_structured(self, egress_log, monkeypatch):
        class _FakeResp:
            def read(self):
                return b"abcdef"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class _FakeOpener:
            def open(self, req, timeout=None):
                return _FakeResp()

        monkeypatch.setattr(sr, "_strict_opener", lambda: _FakeOpener())
        url = "https://api2.openreview.net/notes/search?term=x"
        r = sr._prior_art_fetch(url)
        assert r["body"] == "abcdef"
        assert r["source_id"] == url
        assert r["egress_ref"].startswith("eg-")
        assert r["content_len"] == 6
        assert isinstance(r["fetched_at"], int)

    def test_prior_art_get_still_returns_body(self, egress_log, monkeypatch):
        class _FakeResp:
            def read(self):
                return b"hi"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class _FakeOpener:
            def open(self, req, timeout=None):
                return _FakeResp()

        monkeypatch.setattr(sr, "_strict_opener", lambda: _FakeOpener())
        assert sr._prior_art_get("https://api2.openreview.net/z") == "hi"

    def test_openreview_output_carries_egress_ref(self, monkeypatch):
        payload = '{"notes": []}'
        monkeypatch.setattr(sr, "_prior_art_fetch",
                            lambda url, timeout=20: {"body": payload, "source_id": url,
                                                     "egress_ref": "eg-xyz", "fetched_at": 1,
                                                     "content_len": len(payload)})
        out = sr.openreview_search.__wrapped__("q", "WWW", 5)
        assert "egress_ref=eg-xyz" in out


# ── 单源契约头同步（`ECC-BF1B8AF95332`）────────────────────────────────────────────
# 病象：`gk_evidence.py` 头注仍称「**单出网口** —— 一切出网走 `_prior_art_fetch`」，而 R0.14
#   已把浏览器 MCP 扩为**受治车道**（白名单域放行 + **同一** egress JSONL）⟹ 单源契约头**口径
#   不一**（照契约读会以为浏览器出网这条通道不存在）。本臂 = **静态源码切片**：HEAD 头注无
#   受治车道表述 ⟹ 必红；补正后必绿。
def test_gk_evidence_contract_header_names_governed_lane():
    import gk_evidence
    head = gk_evidence.__doc__ or ""
    assert "受治车道" in head, "gk_evidence 头注未声明「受治车道」（单源契约头未同步 R0.14 扩面）"
    assert "MCP" in head, "头注未点名受治车道的载入面（MCP 浏览器）"

