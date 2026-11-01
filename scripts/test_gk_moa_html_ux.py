#!/usr/bin/env python3
"""人评页 UX 修复红先（2026-10-09，owner 裁定）：
  A 系统默认打开（单路 + 存在护栏，去 explorer 兜底）—— 治「莫名其妙的谷歌」；
  B 页面流体满宽（去固定 1180px 封顶）—— 治宽屏「小小一块」；
  C 页面计数须由 Python 单源注入（中文序号/自然段兼容）；
  D 一键提交一次性回环服务（点提交 ⟹ 自动跑三步链 ⟹ 回执）。
"""
import json
import os
import sys
import threading
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_moa_aggregate as M  # noqa: E402


def _agg(tmp_path):
    hist = [{"subagent_id": "a1", "batch_id": "B", "arm_group": "G1",
             "task": "plan-refinement: /p/x.md — 质询",
             "conclusion": "本轮改动范围蔓延超出计划边界" * 8,
             "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}]
    sf = tmp_path / "s.json"
    sf.write_text(json.dumps({"gate_data": {"subagent_history": hist, "ecc_findings": []}},
                             ensure_ascii=False), encoding="utf-8")
    return M.aggregate(str(sf), None, "plan-refinement", plan="/p/x.md", batch="B")


# ── A：系统默认打开 ──────────────────────────────────────────────
def test_open_candidates_system_default_no_explorer():
    """候选链只用系统默认处理器（cmd start / xdg-open），**不得再有 explorer.exe 兜底**。"""
    c = M._open_candidates("<home>/a.html")
    assert c == [["cmd.exe", "/c", "start", "", "<home>\\a.html"],
                 ["xdg-open", "<home>/a.html"]], c
    assert all("explorer.exe" not in cmd for cmd in c), "explorer 兜底须删（可能落到非默认处理器）"


def test_open_candidates_non_wsl_only_xdg_open():
    assert M._open_candidates("/home/u/a.html") == [["xdg-open", "/home/u/a.html"]]


def test_open_in_browser_missing_target_is_noop(monkeypatch, tmp_path):
    """目标不存在 ⟹ 必须**零发起**（防 `start`/浏览器把坏路径当 URL/搜索页打开 = 莫名谷歌）。"""
    calls = []
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: calls.append(a))
    assert M._open_in_browser(tmp_path / "nope.html") is False
    assert calls == [], "目标不存在时不得发起任何打开"


# ── B：流体满宽 ─────────────────────────────────────────────────
def test_wrap_fluid_full_width():
    assert "max-width:1180px" not in M._CSS, "固定 1180px 封顶 ⟹ 宽屏「小小一块」"
    assert ".wrap{width:100%".replace(" ", "") in M._CSS.replace(" ", ""), "须改流体满宽"


# ── C：页面计数单源注入 ─────────────────────────────────────────
def test_countitems_pattern_injected_from_python_single_source(tmp_path):
    """页面 countItems 标记/标题正则须由 Python **单源注入**（禁手工二写第二套判据）。"""
    html = M.render_html(_agg(tmp_path))
    assert M._json_embed(M._MARKER_RE.pattern) in html, "未注入单源 marker 正则"
    assert M._json_embed(M._HEAD_RE.pattern) in html, "未注入单源 heading 正则"
    assert "countItems" in html, "缺计数函数（既有护栏不变量）"


# ── D：一键提交一次性回环服务 ───────────────────────────────────
def test_serve_html_injects_submit_widget(tmp_path):
    page = M.render_serve_html(M.render_html(_agg(tmp_path)))
    assert 'id="gk-submit"' in page, "服务页缺提交按钮"
    assert "/submit" in page, "服务页未接 /submit 端点"


def test_chain_commands_match_cli_contract(tmp_path):
    """三步链须与 CLI 契约一致（--file / --out-dir / --direction / --score / --blind）。"""
    d = str(tmp_path)
    c1 = M._cmd_from_prose(d, d + "/prose.txt", "")
    c2 = M._cmd_score(d, "reject")
    c3 = M._cmd_adjudicate(d, "0.88")
    assert c1[:2] == ["finding", "from-prose"] and "--file" in c1 and "--out" in c1, c1
    assert c2[:2] == ["finding", "score"] and "--out-dir" in c2
    assert c2[c2.index("--direction") + 1] == "reject", c2
    assert c3[0] == "adjudicate" and c3[c3.index("--score") + 1] == "0.88", c3
    assert "--blind" in c3 and "--verdicts-file" in c3 and "--concessions-file" in c3, c3


def test_serve_submit_runs_origin_chain_and_returns_receipt(tmp_path):
    """POST /submit ⟹ 服务端**自动**按序跑 三步链（无需用户手敲）⟹ 回执含换算后 score。"""
    html = M.render_html(_agg(tmp_path))
    calls = []

    def runner(argv):
        calls.append(argv)
        if argv[:2] == ["finding", "from-prose"]:
            return 0, json.dumps({"ok": True, "count": 2,
                                  "out": argv[argv.index("--out") + 1]})
        if argv[:2] == ["finding", "score"]:
            return 0, json.dumps({"ok": True, "score": 88})
        return 0, json.dumps({"ok": True})

    h = M._make_server(M.render_serve_html(html), 0, str(tmp_path), runner)
    port = h.server_address[1]
    res = {}
    t = threading.Thread(target=lambda: res.update({"r": M._serve_loop(h)}))
    t.start()
    body = json.dumps({"prose": "- (P) x\n- (M) y\n", "mode": "reject",
                       "ctx": "", "dir": str(tmp_path)}).encode("utf-8")
    req = urllib.request.Request("http://127.0.0.1:%d/submit" % port, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    t.join(timeout=10)
    assert payload["ok"] is True, payload
    assert [c[:2] for c in calls[:2]] == [["finding", "from-prose"],
                                          ["finding", "score"]], calls
    assert calls[2][0] == "adjudicate", calls
    assert payload["score"] == "0.88", payload
    assert (tmp_path / "prose.txt").read_text(encoding="utf-8").startswith("- (P)"), \
        "须先把散文落 prose.txt（链第一步契约）"
    assert res["r"]["score"] == "0.88", "回执（stdout 交付通道）须含换算后 score"


def test_serve_flag_registered():
    src = Path(M.__file__).read_text(encoding="utf-8")
    assert '"--serve"' in src, "缺 --serve 旗标"
    assert '"--port"' in src, "缺 --port 旗标"


# ── §3 G1/G3（OSS 前置计划，2026-10-26）：跨批缺省不得静默显示最大批读数 ──────────
def _agg_mixed(tmp_path):
    hist = []
    for bid, n in (("B_BIG", 3), ("B_SMALL", 1)):
        for i in range(n):
            hist.append({"subagent_id": "%s-%d" % (bid, i), "batch_id": bid, "arm_group": "G1",
                         "task": "plan-refinement: /p/x.md — 质询",
                         "conclusion": "本轮改动范围蔓延超出计划边界" * 8,
                         "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]})
    sf = tmp_path / "s.json"
    sf.write_text(json.dumps({"gate_data": {"subagent_history": hist, "ecc_findings": []}},
                             ensure_ascii=False), encoding="utf-8")
    return M.aggregate(str(sf), None, "plan-refinement", plan="/p/x.md")


def test_mixed_batches_html_shows_gate_banner_and_largest_batch_label(tmp_path):
    agg = _agg_mixed(tmp_path)
    assert agg.get("error") == "cross_batch_requires_ack", agg.get("error")
    html = M.render_html(agg)
    assert "cross_batch_requires_ack" in html, "缺跨批门 banner（静默）"
    assert "本页共识 = 最大批" in html and "B_BIG" in html, "缺最大批归属标签"
    assert "批分节" in html, "缺批分节卡"


def test_single_batch_html_has_no_batch_card(tmp_path):
    html = M.render_html(_agg(tmp_path))
    assert "批分节" not in html and "cross_batch_requires_ack" not in html


def test_render_md_has_per_batch_rows(tmp_path):
    md = M.render_md(_agg_mixed(tmp_path))
    assert "批分节逐批读数" in md and "B_BIG" in md and "B_SMALL" in md


# ── §3 G2：链尾 HTML 必须带跨轮趋势（原 chain 未传 trend）────────────────────
def test_chain_html_includes_trend(tmp_path):
    hist = [{"subagent_id": "a1", "batch_id": "B", "arm_group": "G1",
             "task": "plan-refinement: /p/x.md — 质询",
             "conclusion": "本轮改动范围蔓延超出计划边界" * 8,
             "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}]
    finding = {"id": "ECC-MOA1", "root_key": "moa-agg:deadbeef", "status": "open",
               "facets": ["refs:6", "weight:0.667"], "anchors": ["plan:/p/x.md"],
               "source_note": "引用=6 簇=4 一致度=0.667"}
    sf = tmp_path / "s.json"
    sf.write_text(json.dumps({"gate_data": {"subagent_history": hist,
                                            "ecc_findings": [finding]}},
                             ensure_ascii=False), encoding="utf-8")
    hp = tmp_path / "c.html"
    out = M.chain(str(sf), plan="/p/x.md", html_path=str(hp))
    assert out["steps"]["html"]["status"] == "written", out["steps"].get("html")
    assert "跨轮趋势" in hp.read_text(encoding="utf-8"), "链尾 HTML 缺跨轮趋势（trend 未传）"
