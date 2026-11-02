"""H1a 回归臂：降级链「ms 级切换 + 安全防护加固」（ECC 无——本文件随 H1a 落刀）。

覆盖（全部**零网络**：monkeypatch `requests.post` / 状态面）：
  1. **连接类失败立即降级**：首跳 `ConnectTimeout` ⟹ 只试 1 次即切下一跳（原实现会白等 60s ×2）
  2. **断路器跨进程生效**：连续失败达阈值后，下一次调用**零网络**直接跳过该 provider（ms 级）
  3. **双超时 + 禁重定向**：`timeout` 为 (connect, read) 元组、`allow_redirects=False`
  4. **安全：base 白名单**：白名单外 base 被拒（防域名投毒 / SSRF）
  5. **安全：错误脱敏**：错误串不含 api key / Bearer 凭据
  6. **安全：响应体上限**：超限响应判失败并降级
  7. 成功 ⟹ 断路器计数清零（恢复健康）
"""

import json
import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).parent))
import gk_monitor_api as m  # noqa: E402


def _ok_payload(score=0.9):
    inner = json.dumps({
        "overall_score": score, "checks": [], "violations": [],
        "next_action": "", "reasoning": "ok",
    })
    return {"choices": [{"message": {"content": inner}}]}


class _Resp:
    def __init__(self, payload=None, size=None):
        self._payload = payload if payload is not None else _ok_payload()
        self.content = b"x" * (size or 0) if size else json.dumps(self._payload).encode()

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


@pytest.fixture
def iso(monkeypatch, tmp_path):
    """隔离外部面：state / 证据 / gitnexus / state 写盘。"""
    st = tmp_path / "s.state"
    st.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(m, "_read_state", lambda *a, **k: {})
    monkeypatch.setattr(m, "_collect_hard_evidence", lambda *a, **k: {})
    monkeypatch.setattr(m, "_inject_gitnexus", lambda *a, **k: "")
    monkeypatch.setattr(m, "update_state", lambda *a, **k: None)
    return str(st)


def _calls_recorder(fail_provider=None, exc=None, resp_factory=None):
    calls = []

    def fake_post(url, **kw):
        calls.append({"url": url, "timeout": kw.get("timeout"), "allow_redirects": kw.get("allow_redirects")})
        if fail_provider and fail_provider in url:
            raise exc
        return (resp_factory or _Resp)()

    return calls, fake_post


def test_connect_failure_switches_immediately(iso, monkeypatch):
    """① 连接类失败 ⟹ 同跳不重试，立即切下一跳。"""
    calls, fake = _calls_recorder(
        "deepseek", requests.exceptions.ConnectTimeout("dead domain"))
    monkeypatch.setattr(m.requests, "post", fake)
    out = m.monitor_api(stage="S", api_key="k", state_path=iso)
    assert out.get("ok") is True and out.get("provider") == "mimo", out
    ds = [c for c in calls if "deepseek" in c["url"]]
    assert len(ds) == 1, f"连接类失败不应同跳重试（实际 {len(ds)} 次）"


def test_double_timeout_and_no_redirect(iso, monkeypatch):
    """③ 双超时元组 + allow_redirects=False。"""
    calls, fake = _calls_recorder()
    monkeypatch.setattr(m.requests, "post", fake)
    m.monitor_api(stage="S", api_key="k", state_path=iso)
    assert calls, "应至少发起一次请求"
    assert calls[0]["timeout"] == (m.FAILOVER_CONNECT_TIMEOUT, m.FAILOVER_READ_TIMEOUT)
    assert calls[0]["allow_redirects"] is False


def test_breaker_skips_with_zero_network(iso, monkeypatch):
    """② 达阈值后，下一次调用对已 open 的 provider **零网络**跳过（ms 级）。"""
    calls, fake = _calls_recorder(
        "deepseek", requests.exceptions.ConnectTimeout("dead domain"))
    monkeypatch.setattr(m.requests, "post", fake)
    for _ in range(m.FAILOVER_BREAKER_FAILS):
        m.monitor_api(stage="S", api_key="k", state_path=iso)
    ok, why = m._breaker_allows(iso, "deepseek")
    assert ok is False and "circuit open" in why, why

    calls.clear()
    out = m.monitor_api(stage="S", api_key="k", state_path=iso)
    assert out.get("ok") is True, out
    assert [c for c in calls if "deepseek" in c["url"]] == [], "断路器 open 时应零网络跳过"


def test_breaker_recovers_on_success(iso, monkeypatch):
    """⑦ 成功 ⟹ 计数清零。"""
    monkeypatch.setattr(m, "_breaker_record_fail", m._breaker_record_fail)
    m._breaker_record_fail(iso, "deepseek")
    assert m._breaker_read(iso).get("deepseek", {}).get("fails") == 1
    m._breaker_record_ok(iso, "deepseek")
    assert "deepseek" not in m._breaker_read(iso)


def test_allowlist_rejects_foreign_base():
    """④ 白名单外 base 被拒。"""
    with pytest.raises(ValueError):
        m._ensure_allowed_base({"base": "https://evil.example.com/v1"})
    for p in m.PROVIDERS.values():
        m._ensure_allowed_base(p)   # 内置 provider 必须全部通过


def test_redact_scrubs_credentials():
    """⑤ 错误脱敏。"""
    msg = "API error on deepseek: 401 for url https://x/y?k=SECRETKEY (Bearer SECRETKEY)"
    out = m._redact(msg, "SECRETKEY")
    assert "SECRETKEY" not in out and "***" in out


def test_response_size_cap(iso, monkeypatch):
    """⑥ 响应体超限 ⟹ 判失败并降级（不解析）。"""
    big = m.FAILOVER_MAX_RESP_BYTES + 1
    calls, fake = _calls_recorder(
        None, None, resp_factory=lambda: _Resp(size=big))
    # 首跳返回超大响应 → 记失败并切下一跳；构造「所有跳都超大」⟹ 最终 ok=False
    monkeypatch.setattr(m.requests, "post", fake)
    out = m.monitor_api(stage="S", api_key="k", state_path=iso)
    assert out.get("ok") is False and "too large" in out.get("error", ""), out
