#!/usr/bin/env python3
"""`force_teaching` 机检回归臂（2026-10-31）。

背景：`references/stage-6-r6-flow.md` 曾自相矛盾（header 写「无 force」，正文三处教
`advance --force DONE`），而 `--force` 会同时短路 monitor 与熵门。本检查为防复发：
命中行 ±2 行内须有豁免语境（仅当/门禁/人工终裁/兜底/反例/历史/红队/正常路径/禁止/禁用/不要）。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_doc_align as D  # noqa: E402


def _mk(root: Path, text: str) -> Path:
    ref = root / "references"
    ref.mkdir(parents=True, exist_ok=True)
    p = ref / "flow.md"
    p.write_text(text, encoding="utf-8")
    return p


def test_annotated_force_is_pass(tmp_path):
    _mk(tmp_path, "正常路径用 advance DONE。\n"
                  "# 仅当门禁拦下且已有人类终裁时才用 advance --force DONE\n")
    r = D.check_force_teaching(str(tmp_path))
    assert r["check"] == "force_teaching" and r["status"] == "PASS", r


def test_unannotated_force_is_warn(tmp_path):
    _mk(tmp_path, "第一步：\nbash gatekeeper-cli.sh advance --force DONE\n")
    r = D.check_force_teaching(str(tmp_path))
    assert r["status"] == "WARN", r
    assert r["findings"] and r["findings"][0]["line"] == 2, r


def test_historical_redteam_record_is_exempt(tmp_path):
    _mk(tmp_path, "红队历史记录：\n原始 prompt: \"advance --force bypass\"\n")
    r = D.check_force_teaching(str(tmp_path))
    assert r["status"] == "PASS", r


def test_missing_references_dir_is_warn(tmp_path):
    r = D.check_force_teaching(str(tmp_path))
    assert r["status"] == "WARN" and "not found" in r["detail"]


def test_registered_in_run_all_and_docstring_count_matches(tmp_path):
    """注册面：docstring 计数须与 run_all 静态 append 数一致（comment_code_mismatch ④）。"""
    r = D.check_comment_code_mismatch(str(Path(__file__).resolve().parent.parent))
    assert r["status"] in ("PASS", "WARN"), r
    # 强判据：④ 计数类问题不得出现
    assert not any("检查器" in str(p) and "项" in str(p) for p in (r.get("problems") or [])), r
