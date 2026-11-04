#!/usr/bin/env python3
"""Red-first tests for the governed DeepSeek Search/Fetch lane (2026-10-18).

Network is never touched: `_post_json` is either stubbed or `urllib.request.urlopen`
is replaced by a scripted fake.  The tests pin the contract that matters before the
real Web batch:
  * untrusted banner + source_id/hash/token-L evidence
  * kill switch / per-process budget
  * 402/403/404 fail fast; 408/429/5xx retry
  * egress target host/hash is recorded
  * tool registry / role / paper-review wiring
"""
import json
import os
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_evidence as ge
import gk_web_tools as wt


def _envelope(out: str) -> dict:
    assert out.startswith(wt.BANNER), out[:120]
    return json.loads(out.split("\n", 1)[1])


def test_search_success_has_evidence_fields(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("GK_WEB_TOOLS", "1")
    wt.reset_state()
    seen = {}

    def fake_post(path, payload, *, via, target=""):
        seen.update({"path": path, "payload": payload, "via": via, "target": target})
        return {"results": [{
            "url": "https://example.com/a", "title": "A", "snippet": "snip",
            "summary": "sum", "date": "2026-01-01", "authority": "high"}]}, "eg-1"

    monkeypatch.setattr(wt, "_post_json", fake_post)
    monkeypatch.setattr(wt, "_token_len", lambda text: 7)

    obj = _envelope(wt.search("q", count=3))
    assert obj["ok"] is True and obj["count"] == 1
    r = obj["results"][0]
    assert r["source_id"] == "https://example.com/a"
    assert r["provenance"] == ge.PROVENANCE_UNTRUSTED
    assert r["content_len_tokens"] == 7
    assert len(r["content_sha256"]) == 64
    assert r["phase"] is None
    assert seen["path"] == wt.SEARCH_PATH
    assert seen["via"] == "deepseek-search"


def test_search_empty_not_billable(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    wt.reset_state()
    monkeypatch.setattr(wt, "_post_json", lambda *a, **k: ({"results": []}, "eg-0"))
    obj = _envelope(wt.search("nothing"))
    assert obj["ok"] is True and obj["count"] == 0
    assert obj["billable"] is False and obj["cost_yuan"] == 0.0


def test_fetch_success(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    wt.reset_state()
    monkeypatch.setattr(wt, "_post_json",
                        lambda *a, **k: ({"title": "T", "content": "hello"}, "eg-2"))
    monkeypatch.setattr(wt, "_token_len", lambda text: 2)
    obj = _envelope(wt.fetch("https://example.com/a"))
    assert obj["ok"] is True and obj["content"] == "hello"
    assert obj["evidence"]["content_len_tokens"] == 2
    assert obj["evidence"]["source_id"] == "https://example.com/a"


def test_kill_switch(monkeypatch):
    monkeypatch.setenv("GK_WEB_TOOLS", "0")
    wt.reset_state()
    obj = _envelope(wt.search("q"))
    assert obj["ok"] is False and "kill switch" in obj["error"]


def test_budget_exhausted(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("GK_WEB_SEARCH_MAX_CALLS", "1")
    wt.reset_state()
    monkeypatch.setattr(wt, "_post_json",
                        lambda *a, **k: ({"results": []}, "eg-0"))
    assert _envelope(wt.search("q"))["ok"] is True
    obj = _envelope(wt.search("q"))
    assert obj["ok"] is False and "budget exhausted" in obj["error"]


def test_url_validation_blocks_local():
    for bad in ("http://127.0.0.1/x", "http://localhost/x", "file:///etc/passwd",
                "http://10.0.0.1/x", "http://[::1]/x"):
        with pytest.raises(wt.WebToolError):
            wt._validate_url(bad)
    assert wt._validate_url("https://example.com/a") == "https://example.com/a"


class _Resp:
    def __init__(self, body):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


def test_post_json_402_fails_fast(monkeypatch, tmp_path):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("GK_EGRESS_LOG", str(tmp_path / "eg.jsonl"))
    monkeypatch.setattr(wt, "_throttle", lambda: None)
    calls = []

    def fake_urlopen(req, timeout=30):
        calls.append(req)
        raise urllib.error.HTTPError(req.full_url, 402, "payment", {}, None)

    monkeypatch.setattr(wt.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(wt.WebToolError):
        wt._post_json(wt.SEARCH_PATH, {"query": "q"}, via="deepseek-search")
    assert len(calls) == 1, "402 must not be retried"
    rec = json.loads((tmp_path / "eg.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert rec["ok"] is False and rec["via"] == "deepseek-search"


def test_post_json_429_retries_then_succeeds(monkeypatch, tmp_path):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("GK_EGRESS_LOG", str(tmp_path / "eg.jsonl"))
    monkeypatch.setattr(wt, "_throttle", lambda: None)
    monkeypatch.setattr(wt.time, "sleep", lambda *_: None)
    calls = []

    def fake_urlopen(req, timeout=30):
        calls.append(req)
        if len(calls) < 3:
            raise urllib.error.HTTPError(req.full_url, 429, "rate", {}, None)
        return _Resp(b'{"results": []}')

    monkeypatch.setattr(wt.urllib.request, "urlopen", fake_urlopen)
    data, ref = wt._post_json(wt.SEARCH_PATH, {"query": "q"}, via="deepseek-search")
    assert data == {"results": []} and ref.startswith("eg-")
    assert len(calls) == 3


def test_egress_records_target_host_and_hash(monkeypatch, tmp_path):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("GK_EGRESS_LOG", str(tmp_path / "eg.jsonl"))
    monkeypatch.setattr(wt, "_throttle", lambda: None)
    monkeypatch.setattr(wt.urllib.request, "urlopen",
                        lambda req, timeout=30: _Resp(b'{"title":"T","content":"x"}'))
    wt._post_json(wt.FETCH_PATH, {"url": "https://example.com/a"},
                  via="deepseek-fetch", target="https://example.com/a")
    rec = json.loads((tmp_path / "eg.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert rec["via"] == "deepseek-fetch"
    assert rec["target_host"] == "example.com"
    assert len(rec["target_sha256"]) == 16


def test_egress_ids_unique_within_same_second(monkeypatch, tmp_path):
    """pilot 实测回归：3 臂并发同秒同端点曾撞 id（eg-252a91555420 ×2）。"""
    monkeypatch.setenv("GK_EGRESS_LOG", str(tmp_path / "eg.jsonl"))
    args = dict(host="api.deepseek.com", url="https://api.deepseek.com/v1/tools/fetch",
                ok=True, via="deepseek-fetch", target="https://example.com/a")
    a = ge.record_egress(**args)
    b = ge.record_egress(**args)
    assert a != b and a.startswith("eg-") and b.startswith("eg-")


def test_egress_chain_links_prev_and_binds_response_hash(monkeypatch, tmp_path):
    """链升级（2026-10-22）：resp_sha256 入账，第二条 prev == 第一条 chain。"""
    monkeypatch.setenv("GK_EGRESS_LOG", str(tmp_path / "eg.jsonl"))
    ge.record_egress("api.deepseek.com", "u1", True, via="deepseek-search",
                     resp_sha256="a" * 64)
    ge.record_egress("api.deepseek.com", "u2", True, via="deepseek-search",
                     resp_sha256="b" * 64)
    recs = [json.loads(x) for x in
            (tmp_path / "eg.jsonl").read_text(encoding="utf-8").splitlines()]
    assert recs[0]["prev"] == ""
    assert recs[0]["resp_sha256"] == "a" * 64
    assert recs[1]["prev"] == recs[0]["chain"]
    assert ge.verify_egress_chain(str(tmp_path / "eg.jsonl"))["ok"] is True


def test_egress_chain_detects_field_tamper(monkeypatch, tmp_path):
    monkeypatch.setenv("GK_EGRESS_LOG", str(tmp_path / "eg.jsonl"))
    for i in range(3):
        ge.record_egress("api.deepseek.com", "u%d" % i, True, resp_sha256="c" * 64)
    p = tmp_path / "eg.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["resp_sha256"] = "d" * 64          # 改内容哈希，chain 不跟着改
    lines[0] = json.dumps(rec, ensure_ascii=False)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    res = ge.verify_egress_chain(str(p))
    assert res["ok"] is False and res["bad_at"] == 1


def test_egress_chain_rejects_backdated_legacy_row(monkeypatch, tmp_path):
    """链升级后插入一条 `ts` 早于上一条带链行的无 chain 行 = **回填伪造**，必须判失败。

    2026-10-23 策略变更（`verify_egress_chain` 按位置分三态）：位置无法区分「混版尾部写入」
    与「中段插入」（旧 checkout 与当前进程写同一 `~/.gatekeeper.egress.jsonl` 时形态相同），
    故改用 **`ts` 单调**识别回填。判据：`ts` 早于上一条带链行 ⟹ FAIL（`bad_at` = 该无链行）。
    """
    monkeypatch.setenv("GK_EGRESS_LOG", str(tmp_path / "eg.jsonl"))
    ge.record_egress("h", "u1", True)
    ge.record_egress("h", "u2", True)
    p = tmp_path / "eg.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    lines.insert(1, json.dumps({"id": "eg-legacy", "host": "h", "ok": True, "ts": 1}))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    res = ge.verify_egress_chain(str(p))
    assert res["ok"] is False and res["bad_at"] == 2, res


def test_egress_chain_tolerates_unsigned_tail_and_resumes(monkeypatch, tmp_path):
    """混版写入（链后**尾部**无链行）不判断链，且下一条带链记录须接在最后一条带链记录后。

    红先对照（修复前）：`_tail_chain` 只读末行 ⟹ 末行为无链 ⟹ 新记录 `prev=""` ⟹ 第 4 行断链
    （实测线上账本 604 行即此形态：581 无链前缀 + 11 带链 + 12 链后无链 ⟹ 自检 #29 永久红）。
    """
    monkeypatch.setenv("GK_EGRESS_LOG", str(tmp_path / "eg.jsonl"))
    ge.record_egress("h", "u1", True)
    ge.record_egress("h", "u2", True)
    p = tmp_path / "eg.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    lines.append(json.dumps({"id": "eg-old-writer", "host": "h", "ok": True}))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ge.record_egress("h", "u3", True)
    recs = [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()]
    assert recs[-1]["prev"] == recs[1]["chain"], recs[-1]
    res = ge.verify_egress_chain(str(p))
    assert res["ok"] is True and res["legacy"] == 1 and res["unsigned_tail"] is True, res


def test_self_check_egress_chain_warns_on_unsigned_tail(monkeypatch, tmp_path):
    """自检 #29 接线：尾部无链行 ⟹ WARN（不阻断），且 detail 标注混版写入。"""
    import gk_self_check as gsc
    monkeypatch.setenv("GK_EGRESS_LOG", str(tmp_path / "eg.jsonl"))
    ge.record_egress("h", "u1", True)
    p = tmp_path / "eg.jsonl"
    p.write_text(p.read_text(encoding="utf-8")
                 + json.dumps({"id": "eg-old-writer", "host": "h", "ok": True}) + "\n",
                 encoding="utf-8")
    r = gsc.check_egress_chain()
    assert r["status"] == "WARN", r
    assert "mixed-version" in r["detail"], r


def test_post_json_binds_response_hash(monkeypatch, tmp_path):
    import hashlib
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("GK_EGRESS_LOG", str(tmp_path / "eg.jsonl"))
    monkeypatch.setattr(wt, "_throttle", lambda: None)
    body = b'{"results": []}'
    monkeypatch.setattr(wt.urllib.request, "urlopen",
                        lambda req, timeout=30: _Resp(body))
    wt._post_json(wt.SEARCH_PATH, {"query": "q"}, via="deepseek-search")
    rec = json.loads((tmp_path / "eg.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert rec["resp_sha256"] == hashlib.sha256(body).hexdigest()


def test_self_check_egress_chain_states(monkeypatch, tmp_path):
    """#29 自检接线：缺账本 SKIP / 自洽 PASS / 改字段 FAIL。"""
    import gk_self_check as gsc
    monkeypatch.setenv("GK_EGRESS_LOG", str(tmp_path / "eg.jsonl"))
    assert gsc.check_egress_chain()["status"] == "SKIP"

    ge.record_egress("h", "u1", True)
    assert gsc.check_egress_chain()["status"] == "PASS"

    p = tmp_path / "eg.jsonl"
    rec = json.loads(p.read_text(encoding="utf-8").splitlines()[0])
    rec["ok"] = False                      # 改字段，chain 不跟着改
    p.write_text(json.dumps(rec, ensure_ascii=False) + "\n", encoding="utf-8")
    assert gsc.check_egress_chain()["status"] == "FAIL"


def test_self_check_egress_legacy_prefix_warns(monkeypatch, tmp_path):
    """升级前的无链记录只允许作前缀：WARN，不阻断日常出网。"""
    import gk_self_check as gsc
    monkeypatch.setenv("GK_EGRESS_LOG", str(tmp_path / "eg.jsonl"))
    p = tmp_path / "eg.jsonl"
    p.write_text(json.dumps({"id": "eg-old", "host": "h", "ok": True}) + "\n",
                 encoding="utf-8")
    ge.record_egress("h", "u2", True)
    assert gsc.check_egress_chain()["status"] == "WARN"


def test_evidence_token_phase_and_hash():
    r = ge.new_evidence(source_id="u", content="abc", content_len_tokens=7,
                        phase_modulus_tokens=3)
    assert r["phase"] == 1 and r["content_len_tokens"] == 7
    assert len(r["content_sha256"]) == 64
    r2 = ge.new_evidence(source_id="u", content="abc", content_len_tokens=None,
                         phase_modulus_tokens=3)
    assert r2["phase"] is None, "missing token length must be UNKNOWN, not char fallback"


def test_subagent_registry_and_role_wiring():
    import subagent_runner as sr
    for name in ("web_search", "web_fetch"):
        assert name in sr.TOOL_REGISTRY, name
        assert sr.TOOL_REGION_MAP.get(name) == ["evidence"], name
    assert "web_search" in sr.ROLE_TOOLS["plan-refinement"]
    assert "web_fetch" in sr.ROLE_TOOLS["plan-refinement"]
    known, unknown = sr.validate_tool_names("web_search,web_fetch")
    assert not unknown and set(known) == {"web_search", "web_fetch"}


def test_paper_review_requests_web_tools(monkeypatch, tmp_path):
    # 2026-11-04（导出面）：`gk_paper_review` 属排除面（公开包不随附）⟹ 具名 skip，
    # 不再让公开树全量跑出 ModuleNotFoundError；私仓照常跑真断言。
    gpr = pytest.importorskip("gk_paper_review", reason="paper-review 不随公开包")

    captured = {}

    # 2026-10-22 修红：_run_subagent 在「AC 单点故障」修复后已由 subprocess.run 改为
    # Popen（要拿 pid 写 progress 探针），本臂仍 patch run ⟹ 捕获不到 env，恒红。
    # 对齐实现打 Popen；断言意图不变（工具面必须含两只联网检索工具）。
    class _P:
        pid = 4242
        returncode = 1

        def __init__(self, *a, **k):
            captured.update(k.get("env") or {})

        def communicate(self, *a, **k):
            return "", "x"

    monkeypatch.setattr(gpr.subprocess, "Popen", _P)
    gpr._run_subagent("t", "k", "b", "m", tmp_path)
    tools = captured.get("SUBAGENT_TOOLS") or ""
    assert "web_search" in tools and "web_fetch" in tools
    assert "openreview_search" in tools and "arxiv_search" in tools


def test_search_default_count_is_api_default(monkeypatch):
    """官方 §Search API：count 默认 10（本车道原先默认 5，人为收窄检索宽度）。"""
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    wt.reset_state()
    seen = {}

    def fake_post(path, payload, *, via, target=""):
        seen.update(payload)
        return {"results": []}, "eg-0"

    monkeypatch.setattr(wt, "_post_json", fake_post)
    _envelope(wt.search("q"))
    assert seen["count"] == 10


def test_search_count_clamped_to_api_max(monkeypatch):
    """官方 §Search API：count 合法域 1..50（本车道原上限 10）。"""
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    wt.reset_state()
    seen = {}

    def fake_post(path, payload, *, via, target=""):
        seen.update(payload)
        return {"results": []}, "eg-0"

    monkeypatch.setattr(wt, "_post_json", fake_post)
    _envelope(wt.search("q", count=99))
    assert seen["count"] == 50


def test_subagent_web_search_default_count_matches_api_default():
    import inspect
    import subagent_runner as sr
    sig = inspect.signature(sr.web_search.__wrapped__)
    assert sig.parameters["count"].default == 10


@pytest.mark.skipif(os.name == "nt", reason="POSIX flock only")
def test_throttle_is_account_level_via_shared_lock_file(monkeypatch, tmp_path):
    """官方 §Rate Limits：QPS 是**账号级每秒请求数**，不是并发数。

    多进程各自 `time.sleep` 只是 per-process 限流，聚合会超过 5 req/s；
    本测试钉住：限流状态经共享文件 + flock 跨进程串行。
    """
    qfile = tmp_path / "qps.lock"
    monkeypatch.setenv("GK_WEB_QPS_FILE", str(qfile))
    monkeypatch.setenv("GK_WEB_QPS", "5")
    wt.reset_state()
    slept = []
    monkeypatch.setattr(wt.time, "sleep", lambda s: slept.append(s))
    wt._throttle()
    wt._throttle()
    assert qfile.exists() and qfile.read_text(encoding="utf-8").strip()
    assert slept and 0 < slept[0] <= 0.21, slept


# ── 计费口径（红先，2026-10-18）─────────────────────────────────────────────
# 官方 §Billing：**按成功请求**计费（$0.75/1,000），不是 token；
# 免费窗口只覆盖 DeepSeek Harness / Claude Code / Codex 的 server-side 工具调用。
# 直连 /v1/tools/search 不属于该通道 ⟹ 默认按 list price 计费。
from datetime import datetime, timezone


def test_billing_quote_per_request_and_route():
    t = datetime(2026, 10, 18, tzinfo=timezone.utc)
    q = wt.billing_quote(3, now=t, route="direct")
    assert q["basis"] == "per_successful_request"
    assert q["successful_requests"] == 3
    assert q["unit_cost_yuan"] == 0.005
    assert q["list_cost_yuan"] == 0.015
    assert q["route"] == "direct"
    assert q["free_window"] is False and q["cost_yuan"] == 0.015

    q2 = wt.billing_quote(3, now=t, route="harness")
    assert q2["route"] == "harness"
    assert q2["free_window"] is True and q2["cost_yuan"] == 0.0
    assert q2["free_until"] == "2026-11-01T00:00:00+08:00"


def test_envelope_carries_billing_block(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("GK_WEB_BILLING_ROUTE", "direct")
    monkeypatch.setattr(wt, "_now_utc",
                        lambda: datetime(2026, 10, 18, tzinfo=timezone.utc))
    wt.reset_state()
    monkeypatch.setattr(wt, "_post_json", lambda *a, **k: (
        {"results": [{"url": "https://example.com/a", "title": "A"}]}, "eg-1"))
    obj = _envelope(wt.search("q"))
    assert obj["billing"]["basis"] == "per_successful_request"
    assert obj["billing"]["route"] == "direct"
    assert obj["billing"]["list_cost_yuan"] == 0.005
    assert obj["free_window"] is False
    assert obj["cost_yuan"] == 0.005


def test_circuit_breaker_opens_after_consecutive_failures(monkeypatch):
    """F2：连续失败达到阈值 ⟹ `_cb_before` fail-closed；成功一次即复位。"""
    monkeypatch.setattr(wt, "_CB_MAX", 3)
    monkeypatch.setattr(wt, "_CB_COOLDOWN", 60.0)
    wt._CB_FAILS.update({"n": 0, "until": 0.0})
    for _ in range(3):
        wt._cb_record(False)
    with pytest.raises(wt.WebToolError, match="circuit open"):
        wt._cb_before()
    wt._cb_record(True)
    assert wt._CB_FAILS["n"] == 0 and wt._CB_FAILS["until"] == 0.0
