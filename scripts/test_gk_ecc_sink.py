#!/usr/bin/env python3
"""`gk_ecc_sink` 红先臂 —— 审计内嵌 LLM 车道的 ECC 落盘（文件 + 卫星片 + 索引）。

缺口（落刀前 HEAD）：`audit --crossr` / `audit --report` 直调 `subagent_runner.py`，
只取 `conclusion`，**原始 EccOutput 整份丢弃** ⟹ 无文件/无片/无索引（不可复盘、
MoA 聚合器看不见这些臂）。红队四角色走 `monitor --subagent`，该路径已有落盘，不在此列。

判据（红先）：HEAD 无 `gk_ecc_sink.py` ⟹ 全部 ImportError 必红。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _mkstate(tmp_path):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    return str(st)


def _sidecar_entries(st):
    """索引侧车条目（`<state>.satellite-index.jsonl`）。

    2026-11-08（既有债，合并 perf 后暴露）：`gk_satellite` 的 **S3 写侧**已停写内联热索引
    （`append` 返回 `inline_skipped: true`，reason「写侧只落片 + 侧车」）⟹
    `gate_data.satellite_index` 不再是落点，索引唯一落点 = 侧车 jsonl（读面由 `gk_satellite`
    合并侧车兜住）。原断言查内联键 ⟹ 恒 `KeyError`（`test_gk_satellite` 早已按 S3 更新，
    本文件漏改）。断言强度不降：仍验证「索引真实落盘 + per-arm 不覆盖」。
    """
    p = Path(str(st) + ".satellite-index.jsonl")
    if not p.is_file():
        return []
    return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _ecc(**kw):
    d = {
        "mode": "subagent", "subagent_id": "sub-audit-1", "nonce": "n1",
        "timestamp": "2026-10-31T00:00:00+00:00", "task": "audit --report",
        "conclusion": "审计结论", "evidence": ["gatekeeper-cli.sh:100-120 —— anchor"],
        "findings": {"worked": [], "failed": [], "not_tried": []},
        "next_steps": ["s"], "confidence": "medium", "tools_used": ["audit"],
        "kept": ["k1"], "challenges": ["c1"],
        "verification": {"status": "n/a"}, "evidence_anchor": {"status": "ok"},
        "gx_status": {"verdict": "not_called"}, "token_usage": {"rounds": 2},
    }
    d.update(kw)
    return d


def test_persist_writes_file_shard_and_index(tmp_path):
    """①文件 ②卫星片 ③索引，三面齐全（与质询同构）。"""
    import gk_ecc_sink as SINK
    import gk_satellite as SAT
    st = _mkstate(tmp_path)
    root = str(tmp_path)
    r = SINK.persist(st, json.dumps(_ecc(), ensure_ascii=False), domain="audit",
                     batch_id="AUDIT-20261031-abc", arm="report", root=root)
    assert r.get("ok"), r
    f = Path(r["file"])
    assert f.is_file() and f.parent == tmp_path / "docs/analysis/audit/AUDIT-20261031-abc"
    assert json.loads(f.read_text(encoding="utf-8"))["conclusion"] == "审计结论"
    shard = SAT.shard_path(st, "history")
    lines = [l for l in Path(shard).read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["domain"] == "audit" and rec["arm"] == "report"
    assert rec["batch_id"] == "audit-AUDIT-20261031-abc", rec["batch_id"]
    assert rec["output_file"] == str(f)
    # findings 回填口径（与 CLI 落库段一致）：三键全空 → kept/challenges 回填
    assert rec["findings"] == {"worked": ["k1"], "failed": ["c1"], "not_tried": []}
    leaf = [e["leaf"] for e in _sidecar_entries(st)
            if e.get("batch_id") == "audit-AUDIT-20261031-abc" and e.get("arm") == "report"][-1]
    assert leaf["kind"] == "history" and leaf["records"] == 1


def test_invalid_json_fail_loud_keeps_raw(tmp_path):
    """非法 ECC：ok:false（fail-loud）但原文落 `.invalid.txt`（不丢证据），且不落片。"""
    import gk_ecc_sink as SINK
    st = _mkstate(tmp_path)
    r = SINK.persist(st, "not-json-at-all", domain="audit", batch_id="b1",
                     arm="a1", root=str(tmp_path))
    assert r.get("ok") is False and "非法 JSON" in r.get("error", "")
    p = Path(r["invalid_file"])
    assert p.is_file() and p.read_text(encoding="utf-8") == "not-json-at-all"
    assert not os.path.isfile(str(st) + ".history-archive.jsonl"), "非法输入不应落片"


def test_unknown_domain_and_bad_segment_rejected(tmp_path):
    """domain 白名单 + 索引段语法（`.'` 会切深路径）—— 均 fail-loud 且零落盘。"""
    import gk_ecc_sink as SINK
    st = _mkstate(tmp_path)
    r = SINK.persist(st, json.dumps(_ecc()), domain="nope", batch_id="b1",
                     arm="a1", root=str(tmp_path))
    assert r.get("ok") is False and "未知 domain" in r.get("error", "")
    r2 = SINK.persist(st, json.dumps(_ecc()), domain="audit", batch_id="a.b",
                      arm="a1", root=str(tmp_path))
    assert r2.get("ok") is False and "非法 batch_id" in r2.get("error", "")
    assert not (tmp_path / "docs").exists(), "被拒输入不得建目录"


def test_full_conclusion_in_file_but_bounded_in_shard(tmp_path):
    """全量在文件、有界在片（片是摘要投影，禁止撑爆 128KB 窗口）。"""
    import gk_ecc_sink as SINK
    st = _mkstate(tmp_path)
    big = "x" * (SINK.CONCLUSION_MAX * 3)
    r = SINK.persist(st, json.dumps(_ecc(conclusion=big), ensure_ascii=False),
                     domain="red", batch_id="RED-1", arm="exploiter", root=str(tmp_path))
    assert r.get("ok"), r
    assert json.loads(Path(r["file"]).read_text(encoding="utf-8"))["conclusion"] == big
    rec = json.loads(Path(str(st) + ".history-archive.jsonl")
                     .read_text(encoding="utf-8").splitlines()[0])
    assert len(rec["conclusion"]) == SINK.CONCLUSION_MAX
    assert rec["conclusion_len"] == len(big)


def test_two_arms_same_batch_do_not_clobber(tmp_path):
    """c5 同构：同批两臂 ⟹ 两份文件 + 两个 per-arm 索引叶子（互不覆盖）。"""
    import gk_ecc_sink as SINK
    st = _mkstate(tmp_path)
    for arm in ("crossr", "report"):
        r = SINK.persist(st, json.dumps(_ecc(subagent_id="sub-" + arm)),
                         domain="audit", batch_id="B9", arm=arm, root=str(tmp_path))
        assert r.get("ok"), r
    arms = {e["arm"] for e in _sidecar_entries(st) if e.get("batch_id") == "audit-B9"}
    assert arms == {"crossr", "report"}, arms
    shard = Path(str(st) + ".history-archive.jsonl").read_text(encoding="utf-8")
    assert len([l for l in shard.splitlines() if l.strip()]) == 2


def test_md_report_optional(tmp_path):
    """`--md` 产人读报告（复用 gk_subagent_report 分流，禁第二套模板）。"""
    import gk_ecc_sink as SINK
    st = _mkstate(tmp_path)
    r = SINK.persist(st, json.dumps(_ecc(), ensure_ascii=False), domain="audit",
                     batch_id="b1", arm="report", root=str(tmp_path), render_md=True)
    assert r.get("ok") and r.get("md_file"), r
    md = Path(r["md_file"]).read_text(encoding="utf-8")
    assert "Subagent ECC 报告" in md and "机检面" in md


def test_cli_stdin_roundtrip(tmp_path):
    """CLI 入口（stdin）可用；rc 与 ok 同步（0 / 3）。"""
    st = _mkstate(tmp_path)
    mod = str(Path(__file__).with_name("gk_ecc_sink.py"))
    p = subprocess.run([sys.executable, mod, "persist", "--state", st,
                        "--domain", "audit", "--batch", "b1", "--arm", "a1",
                        "--root", str(tmp_path)],
                       input=json.dumps(_ecc()), capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["ok"] is True
    p2 = subprocess.run([sys.executable, mod, "persist", "--state", st,
                         "--domain", "audit", "--batch", "b1", "--arm", "a2",
                         "--root", str(tmp_path)],
                        input="broken-json", capture_output=True, text=True)
    assert p2.returncode == 3 and json.loads(p2.stdout)["ok"] is False


def test_cli_audit_llm_lanes_wired_to_sink():
    """接线面：审计两条内嵌 LLM 车道（crossr / report）都必须经本中枢落盘。"""
    src = CLI.read_text(encoding="utf-8")
    assert src.count("gk_ecc_sink.py") >= 2, "审计 LLM 车道未接落盘中枢"
    assert "--domain audit" in src
    # 红队四角色走 monitor --subagent（既有落盘），此处只锚定其仍未改道
    assert "RED-SCOPE: 红队扫描" in src
