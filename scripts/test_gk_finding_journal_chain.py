"""C 接线红先臂（2026-10-16，owner 裁定「开单/关单事件级签名 + 哈希链」）。

`gk_finding._append_journal` 每行升级为 `{**entry, journal_v:2, prev, sig, sig_alg}`：
  · `prev` = 上一行原始文本的 sha256 ⟹ **哈希链**（改/删/插一行 ⟹ 断链可机检）；
  · `sig`  = HMAC-SHA256(prev + canonical)（需 `GK_JOURNAL_KEY`/`GATEKEEPER_HMAC_KEY`）；
  · 无钥 ⟹ `sig=""`/`sig_alg="none"`（**显式降级**，不冒充已签）。
只读验链入口 = `gk_finding.verify_journal`（CLI: `finding journal-verify`）。

HEAD 必红：`_append_journal` 只写裸 entry（无 `journal_v`/`prev`/`sig`）、且 `verify_journal` 不存在。
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_finding as gf

KEY = "a" * 64


def _lines(sf):
    with open(gf._journal_path(sf), encoding="utf-8") as f:
        return [ln.rstrip("\n") for ln in f if ln.strip()]


def test_arm1_appended_line_has_chain_and_sig(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_JOURNAL_KEY", KEY)
    sf = str(tmp_path / "state")
    gf._append_journal(sf, {"ts": "t", "event": "register", "fid": "ECC-X", "to": "open"})
    rec = json.loads(_lines(sf)[0])
    assert rec.get("journal_v") == 2, "C 未接：缺 journal_v 版本标"
    assert "prev" in rec and rec["prev"] == "", "链头 prev 应为空串"
    assert rec.get("sig_alg") == "hmac-sha256" and len(rec.get("sig") or "") == 64, "事件未签名"


def test_arm2_chain_links_and_verifies_ok(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_JOURNAL_KEY", KEY)
    sf = str(tmp_path / "state")
    for i in range(3):
        gf._append_journal(sf, {"ts": "t%d" % i, "event": "register", "fid": "ECC-%d" % i})
    import hashlib
    lines = _lines(sf)
    assert json.loads(lines[1])["prev"] == hashlib.sha256(lines[0].encode()).hexdigest()
    assert json.loads(lines[2])["prev"] == hashlib.sha256(lines[1].encode()).hexdigest()
    v = gf.verify_journal(sf)
    assert v["ok"] and v["signed"] == 3 and not v["broken"], ("链应完好", v)


def test_arm3_tampered_line_breaks_chain(tmp_path, monkeypatch):
    """篡改第 1 行内容 ⟹ 第 2 行 `prev` 失配 ⟹ 断链（机检）。"""
    monkeypatch.setenv("GK_JOURNAL_KEY", KEY)
    sf = str(tmp_path / "state")
    for i in range(3):
        gf._append_journal(sf, {"ts": "t%d" % i, "event": "register", "fid": "ECC-%d" % i})
    lines = _lines(sf)
    rec = json.loads(lines[1]); rec["fid"] = "ECC-TAMPERED"
    lines[1] = json.dumps(rec, ensure_ascii=False)
    with open(gf._journal_path(sf), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    v = gf.verify_journal(sf)
    assert not v["ok"], "篡改未被检出"
    assert any(b["reason"] in ("chain_break", "bad_sig") for b in v["broken"]), v["broken"]


def test_arm4_bad_sig_detected(tmp_path, monkeypatch):
    """只改 `sig`（内容不动）⟹ bad_sig。"""
    monkeypatch.setenv("GK_JOURNAL_KEY", KEY)
    sf = str(tmp_path / "state")
    gf._append_journal(sf, {"ts": "t", "event": "close", "fid": "ECC-Y"})
    rec = json.loads(_lines(sf)[0]); rec["sig"] = "0" * 64
    with open(gf._journal_path(sf), "w", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    v = gf.verify_journal(sf)
    assert not v["ok"] and any(b["reason"] == "bad_sig" for b in v["broken"]), v


def test_arm5_no_key_is_explicitly_degraded(tmp_path, monkeypatch):
    """无钥 ⟹ `sig=""` + `sig_alg="none"` + `verify.degraded=True`（**显式降级，不冒充已签**）。"""
    monkeypatch.delenv("GK_JOURNAL_KEY", raising=False)
    monkeypatch.delenv("GATEKEEPER_HMAC_KEY", raising=False)
    sf = str(tmp_path / "state")
    gf._append_journal(sf, {"ts": "t", "event": "register", "fid": "ECC-Z"})
    rec = json.loads(_lines(sf)[0])
    assert rec.get("sig") == "" and rec.get("sig_alg") == "none", "无钥未显式降级"
    v = gf.verify_journal(sf)
    assert v["degraded"] is True and v["ok"] is True, v


def test_arm6_legacy_lines_counted_not_broken(tmp_path, monkeypatch):
    """向后兼容：旧式裸行（无 `journal_v`）计 `legacy`，**不计断裂**。"""
    monkeypatch.setenv("GK_JOURNAL_KEY", KEY)
    sf = str(tmp_path / "state")
    with open(gf._journal_path(sf), "w", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "old", "event": "register", "fid": "ECC-L"}, ensure_ascii=False) + "\n")
    gf._append_journal(sf, {"ts": "new", "event": "close", "fid": "ECC-L"})
    v = gf.verify_journal(sf)
    assert v["legacy"] == 1 and v["signed"] == 1 and v["ok"], v


def test_arm7_cli_subcommand_registered():
    """机检：CLI 面 `finding journal-verify`（不新增 _CMD_REG；经 cmd_finding 转发）。"""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(root, "scripts", "gk_finding.py"), encoding="utf-8").read()
    assert 'cmd == "journal-verify"' in src
    assert '"journal-verify": "finding journal-verify' in src
