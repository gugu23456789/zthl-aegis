#!/usr/bin/env python3
"""FIFO 归档读面红先臂（2026-11-01）。

判据：
  1. `audit --state` 的 `fifo_archives` 报两个归档的条数（append-only，窗口外）；
  2. 归档缺失时为 0 且不报错（干净仓库也 PASS）；
  3. 余烬 `archive_digest` 只含摘要（files/lines/bytes/sha256），不回读正文。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import gk_audit_state as A  # noqa: E402
import gk_discover_archive as D  # noqa: E402


def _row(out, field):
    return [c for c in out["state_checks"] if c["field"] == field][0]


def test_fifo_archives_counted(tmp_path):
    st = tmp_path / "s.state"
    st.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    (tmp_path / "s.state.rejected-edits-journal.jsonl").write_text('{"a":1}\n{"a":2}\n')
    (tmp_path / "s.state.history-archive.jsonl").write_text('{"b":1}\n')
    out = A.check_state_file(str(st), str(tmp_path))
    row = _row(out, "fifo_archives")
    assert "rejected_edits=2" in row["declared"], row
    assert "subagent_history=1" in row["declared"], row
    assert row["match"] is True
    assert row["archives"][0]["last"].startswith('{"a"'), row["archives"]


def test_fifo_archives_absent_is_clean(tmp_path):
    st = tmp_path / "s.state"
    st.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    row = _row(A.check_state_file(str(st), str(tmp_path)), "fifo_archives")
    assert "rejected_edits=0" in row["declared"] and row["match"] is True


def test_ember_digest_is_summary_only(tmp_path):
    st = tmp_path / "s.state"
    st.write_text("{}", encoding="utf-8")
    (tmp_path / "s.state.rejected-edits-journal.jsonl").write_text('{"secret":"x"}\n')
    d = D._archive_digest(str(st))
    assert d["rejected_edits"]["lines"] == 1
    assert set(d["rejected_edits"]) == {"files", "lines", "bytes", "sha256"}
    assert "secret" not in json.dumps(d)
    assert d["subagent_history"] == {"files": 0, "lines": 0, "bytes": 0, "sha256": ""}


def test_legacy_archive_name_still_counted(tmp_path):
    """T5：旧名 `-archive` 不自动迁移 ⟹ 读面必须两代都认（否则存量证据「假装 0 条」）。"""
    st = tmp_path / "s.state"
    st.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    (tmp_path / "s.state.rejected-edits-archive.jsonl").write_text('{"old":1}\n')
    (tmp_path / "s.state.rejected-edits-journal.jsonl").write_text('{"new":1}\n')
    row = _row(A.check_state_file(str(st), str(tmp_path)), "fifo_archives")
    assert "rejected_edits=2" in row["declared"], row
    d = D._archive_digest(str(st))
    assert d["rejected_edits"]["lines"] == 2 and d["rejected_edits"]["files"] == 2, d
