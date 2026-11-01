#!/usr/bin/env python3
"""doc-align 人读视图 **红先臂**（`ECC-F2BDAFB8899C`）。

缺陷：`doc-align` 只吐全量 JSON（2026-10-12 实测逾 1.7 万行）⟹ 人 / agent 一次读不完，
只能落 tmp 文件再检索。修法 = 加 `--summary`：每检查一行 `check / status / detail(截断)`。

落刀前必红：`gk_doc_align.summarize` 缺席 + `cmd_doc_align` 未解析 `--summary`。
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _cmd_seg():
    """`cmd_doc_align` 整函数体（切到下一个列 0 的 `}`，与函数长度解耦）。"""
    src = CLI.read_text(encoding="utf-8")
    rest = src[src.find("cmd_doc_align() {"):]
    m = re.search(r"(?m)^\}$", rest)
    return rest[: m.end()] if m else rest


def test_doc_align_summary_renders_one_line_per_check():
    import gk_doc_align as D

    payload = {"issues": 1, "checks": [
        {"check": "cli_protocol_commands", "status": "PASS", "detail": "declared=50 actual=50"},
        {"check": "audit_docs_cli_entries", "status": "FAIL", "detail": "missing=['x']"},
    ]}
    out = D.summarize(payload)
    lines = out.splitlines()
    assert len(lines) == 3, "应 1 头行 + 2 检查行；实得 %d" % len(lines)
    assert "issues=1" in lines[0]
    assert "cli_protocol_commands" in out and "PASS" in out
    assert "audit_docs_cli_entries" in out and "FAIL" in out


def test_doc_align_summary_truncates_long_detail():
    import gk_doc_align as D

    payload = {"issues": 0, "checks": [{"check": "c", "status": "WARN", "detail": "x" * 5000}]}
    out = D.summarize(payload)
    assert max(len(l) for l in out.splitlines()) < 400, "超长 detail 未截断"


def test_doc_align_cli_registers_summary_flag():
    seg = _cmd_seg()
    assert "--summary" in seg, "cmd_doc_align 未解析/转发 --summary（人读视图不可达）"
