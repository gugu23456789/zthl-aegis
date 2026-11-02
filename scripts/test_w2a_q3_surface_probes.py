#!/usr/bin/env python3
"""W2A §9.6 Q3a–Q3d **残留面判别臂**（探针补登，2026-10-11；`ECC-6B1505BB1FEC`）。

背景：§9.6 第一轮回填 + §9.7 表写于 **B 落刀之前**；B 之后 `_strict_opener` / egress JSONL /
`_prior_art_fetch` / `gk_evidence` 已实装，但表未回填 ⟹ 记成"无留痕/无落点"= **表陈旧**。
逐臂对 HEAD 复核后的**真红残留** = Q3a 出站阻断门 / Q3b 浏览器车道 allowlist / Q3c 相位出口绑定 /
Q3d 无缓存不变式 —— 本文件 = 这四面的**探针**（前三条 `xfail(strict=True)` 登记"当前必然红"，
第四条断言"无缓存"不变式成立）。

纪律（对齐 `test_gk_monitor_parity.py`）：`xfail(strict=True)` ⟹ 对应护栏落地后**变 XPASS 失败**
⟹ 强制移除该 `xfail`（**自动退役**，不会静默滞留）。

2026-10-11 方案 A 落刀（`ECC-BB4E8FF782F0`）：Q3a（`_prior_art_fetch` URL/query 内容门）+ Q3b
（浏览器**受治车道** allowlist）已落 ⟹ 两臂由 xfail 转**实臂**；另增 evaluate/eval_js **封禁臂**
与浏览器出网**记账臂**。Q3c（相位绑出口 L）亦转实臂（`ECC-B23D80C0545D`）。
"""
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import subagent_runner as sr  # noqa: E402


def _src(name: str) -> str:
    return (SCRIPT_DIR / name).read_text(encoding="utf-8")


# ── Q3a：出站阻断门（URL/query 内容面）──────────────────────────────────────────

def test_q3a_outstation_gate_caps_query_length(tmp_path, monkeypatch):
    """Q3a：出网 URL/query 内容门 —— 超长 URL（含 query）须 fail-loud（`ValueError`）。"""
    monkeypatch.setenv(sr._EGRESS_LOG_ENV, str(tmp_path / "e.jsonl"))

    class _FakeResp:
        def read(self):
            return b"x"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _FakeOpener:
        def open(self, req, timeout=None):
            return _FakeResp()

    monkeypatch.setattr(sr, "_strict_opener", lambda: _FakeOpener())
    long_q = "a" * 5000
    with pytest.raises(ValueError):
        sr._prior_art_fetch("https://api2.openreview.net/x?q=" + long_q)


# ── Q3b：浏览器车道域 allowlist ────────────────────────────────────────────────

def test_q3b_browser_lane_has_domain_allowlist(monkeypatch):
    """Q3b：浏览器**受治车道** allowlist —— 白名单域 → 放行哨兵；域外 → 仍 BLOCK。"""
    import pre_tool_hook as h
    t_ok, _ = h._egress_identity("mcp__Puppeteer__navigate", {"url": "https://api2.openreview.net/x"})
    assert t_ok == "McpEgressAllowed", (
        "Q3b：白名单域须走受治车道（放行+记账），实得 %r" % t_ok)
    t_blk, _ = h._egress_identity("mcp__Puppeteer__navigate", {"url": "https://evil.example.com/x"})
    assert t_blk == "McpEgress", "Q3b：域外须仍 BLOCK（不得放行），实得 %r" % t_blk


def test_arm_egress_evaluate_sealed():
    """③：`puppeteer_evaluate`/`eval_js`（JS 内 fetch = 出网残余）须被**封**（非放行）。"""
    import pre_tool_hook as h
    t, _ = h._egress_identity("mcp__Puppeteer__evaluate", {"script": "fetch('https://evil/x')"})
    assert t != "mcp__Puppeteer__evaluate", "evaluate 未封（JS 内 fetch 仍可出网）"
    assert t == "McpEgressSealed", "evaluate 须归 `McpEgressSealed`（封），实得 %r" % t


def test_arm_browser_egress_recorded(tmp_path, monkeypatch):
    """④：受治车道放行的出网须进 egress JSONL（`via=mcp-browser`）。"""
    import json as _json
    import pre_tool_hook as h
    log = tmp_path / "eg.jsonl"
    monkeypatch.setenv("GK_EGRESS_LOG", str(log))
    h._record_mcp_egress("api2.openreview.net", "https://api2.openreview.net/x")
    assert log.exists(), "浏览器出网未落 egress JSONL"
    rec = _json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
    assert rec.get("via") == "mcp-browser" and rec.get("ok") is True
    assert rec.get("host") == "api2.openreview.net"


# ── Q3c：相位不变门绑出口侧 L ──────────────────────────────────────────────────

def test_q3c_phase_gate_binds_egress_len():
    """Q3c：相位门**出口侧绑定** —— 相位输入取**出口留痕回指证据记录**的 L（`content_len`），
    非本地正文长度（防「构造 L 使 `L mod S` 落已知翻转相位」）。取不到 ⟹ `None`（fail-loud）。"""
    import gk_evidence as E
    recs = [{"egress_ref": "eg-abc", "content_len": 37}]
    assert E.phase_from_egress(recs, "eg-abc", 16) == 37 % 16
    assert E.phase_from_egress(recs, "eg-missing", 16) is None


def test_q3c_per_arm_phase_offset_shifts_residue():
    """R2（W2A §6.3(3)，`ECC-00739E179486`）：arm i 的相位 = `(L + i·Δ) mod S` —— 错相臂；
    `Δ=0` = 同相控制臂。相位入参仍走**出口侧绑定**（`offset` 只做平移、不改 `L` 的来源 ⟹ 不破 T1 防篡改）。"""
    import gk_evidence as E
    recs = [{"egress_ref": "eg-arm", "content_len": 37}]
    assert E.phase_from_egress(recs, "eg-arm", 16) == 37 % 16              # Δ=0 同相控制臂
    assert E.phase_from_egress(recs, "eg-arm", 16, offset=3) == (37 + 3) % 16
    assert E.per_arm_phases(37, 6, 1, 16) == [(37 + i) % 16 for i in range(6)]
    assert E.phase_from_egress(recs, "eg-missing", 16, offset=3) is None   # 平移不破 fail-loud


# ── Q3d：无缓存不变式（现状成立 ⟹ 绿臂）────────────────────────────────────────

def test_q3d_no_persistent_web_cache_invariant():
    """Q3d：纪律 = **禁无 TTL 缓存** ⟹ 现状「无缓存」（不变量成立）。
    若将来引入缓存，须同时带 TTL + 隔离 + untrusted 标记（本臂随之改为断言 TTL 存在）。"""
    s = _src("gk_evidence.py").lower()
    assert ("cache" not in s) or ("ttl" in s), \
        "Q3d：gk_evidence 引入缓存须带 TTL + 隔离 + untrusted 标记"


# ── Q3e 残项：egress JSONL 只读审计（`audit --egress`；`ECC-DF7FC6860957`）──────────

def test_q3e_audit_egress_summarizes(tmp_path, monkeypatch):
    """Q3e：egress 留痕须有**只读审计**入口（`gk_evidence.summarize_egress`）。"""
    import gk_evidence as E
    log = tmp_path / "eg.jsonl"
    monkeypatch.setenv("GK_EGRESS_LOG", str(log))
    E.record_egress("api2.openreview.net", "https://api2.openreview.net/x", ok=True, via="prior-art")
    E.record_egress("evil.example.com", "https://evil.example.com/y", ok=False,
                    err="host_not_allowlisted", via="mcp-browser")
    s = E.summarize_egress()
    assert s["total"] == 2 and s["ok"] == 1, s
    assert s["by_via"].get("mcp-browser") == 1, s
    assert s["failures"] and s["failures"][0]["err"] == "host_not_allowlisted", s


def test_q3e_audit_egress_cli_wired():
    """Q3e：CLI `audit --egress` 须接线（`cmd_audit` 增 `--egress` 分支，委托 `summarize_egress`）。"""
    cli = (SCRIPT_DIR.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8", errors="replace")
    seg = cli.split("cmd_audit()", 1)[1].split("\n}", 1)[0]
    assert "--egress|egress)" in seg, "cmd_audit 缺 --egress 分支"
    assert "summarize_egress" in seg, "分支未委托 summarize_egress（禁第二实现）"
