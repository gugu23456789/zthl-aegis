"""test_gk_red_guard.py — 红队本地确定性护栏（红先，2026-11-09）。

边界：公开只读检索（PRIOR_ART_HOSTS / GOVERNED_SEARCH_HOSTS）放行；其余目标必须命中
**自维护授权范围**（red-scope.json，带哈希、窗口、动作面），否则 deny；enforce 抛
`RedGuardDenied` 并写审计。无 scope / 篡改 / 过期 / 非自维护 / 非只读动作 → 全 deny（fail-closed）。
"""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import gk_red_guard as G


def _scope(tmp_path, **kw):
    d = {
        "authorization_id": "RED-SELF-TEST",
        "owner": "tester",
        "self_maintained": True,
        "window": {"from": "2026-01-01T00:00:00+08:00", "to": "2099-01-01T00:00:00+08:00"},
        "assets": [{"host": "self.example.test", "path_prefix": "/", "actions": ["read"]}],
        "legal_basis": "self-maintained test asset",
    }
    d.update(kw)
    p = tmp_path / "red-scope.json"
    p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    G.seal_scope(str(p))
    return str(p)


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_RED_GUARD_LOG", str(tmp_path / "guard.jsonl"))
    monkeypatch.delenv("GK_RED_SCOPE", raising=False)


def test_public_readonly_allowed_without_scope():
    r = G.check("https://export.arxiv.org/abs/1234", "read")
    assert r["ok"] is True and r["reason"] == "public_read_only"


def test_external_without_scope_denied():
    r = G.check("https://evil.example.test/x", "read")
    assert r["ok"] is False and "no_scope" in r["reason"]


def test_self_asset_allowed_with_scope(tmp_path, monkeypatch):
    p = _scope(tmp_path)
    monkeypatch.setenv("GK_RED_SCOPE", p)
    r = G.check("https://self.example.test/x", "read")
    assert r["ok"] is True and r["reason"] == "scope_allow"


def test_expired_denied(tmp_path, monkeypatch):
    p = _scope(tmp_path, window={"from": "2020-01-01T00:00:00+08:00",
                                 "to": "2020-01-02T00:00:00+08:00"})
    monkeypatch.setenv("GK_RED_SCOPE", p)
    assert G.check("https://self.example.test/x", "read")["ok"] is False


def test_action_denied(tmp_path, monkeypatch):
    p = _scope(tmp_path)
    monkeypatch.setenv("GK_RED_SCOPE", p)
    r = G.check("https://self.example.test/x", "exploit")
    assert r["ok"] is False and "action" in r["reason"]


def test_tamper_denied(tmp_path, monkeypatch):
    p = _scope(tmp_path)
    monkeypatch.setenv("GK_RED_SCOPE", p)
    d = json.loads(Path(p).read_text(encoding="utf-8"))
    d["assets"][0]["host"] = "other.example.test"
    Path(p).write_text(json.dumps(d), encoding="utf-8")
    assert G.check("https://other.example.test/x", "read")["ok"] is False


def test_not_self_maintained_denied(tmp_path, monkeypatch):
    p = _scope(tmp_path, self_maintained=False)
    monkeypatch.setenv("GK_RED_SCOPE", p)
    assert G.check("https://self.example.test/x", "read")["ok"] is False


def test_enforce_raises_and_logs():
    with pytest.raises(G.RedGuardDenied):
        G.enforce("https://evil.example.test/x", "read")
    log = Path(os.environ["GK_RED_GUARD_LOG"])
    assert log.exists() and "evil.example.test" in log.read_text(encoding="utf-8")


def test_egress_identity_blocks_external():
    import pre_tool_hook as H
    name, _url = H._egress_identity("mcp__octop-browser__browser_navigate",
                                    {"url": "https://evil.example.test/x"})
    # 域外导航 ⟹ 归 `McpEgress`（域外档）；`McpEgressSealed` 专指 evaluate/eval_js 的工具封禁。
    assert name == H.MCP_EGRESS


def test_egress_identity_allows_public_readonly():
    import pre_tool_hook as H
    name, _url = H._egress_identity("mcp__octop-browser__browser_navigate",
                                    {"url": "https://export.arxiv.org/abs/1"})
    assert name == H.MCP_EGRESS_ALLOWED
