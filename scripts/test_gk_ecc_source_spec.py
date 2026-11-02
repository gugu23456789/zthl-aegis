#!/usr/bin/env python3
"""ECC 写入规范 · `source` 分面（B 类安全网）红先/行为臂（2026-09-28）。

规范正本：`references/ecc-write-spec.md`；计划：`docs/plans/2026-09-28-edit-gate-ecc-convergence-plan.md` §3。

现场（实测 base state 92 条）：`source` 曾**零校验** ⟹ 散文/时间线/私名被灌入
（规范值仅 `manual` 37 / `red` 7 / `review` 4 / 空 15，其余 ≈29 条非规范）
⟹ 机器无法按来源分面统计。本批纪律（用户裁定）：**存量 WARN、新写 fail-loud**。

臂清单：
  · `register` 写入边界：空 / 超长 / 含空白 / 非白名单 → **fail-loud**；白名单 token 全接受
  · `source_note`：长文本出处与 `source` token **显式分离**
  · `--from-report`：只抽允许字段（**禁**整份 subagent 报告入册）
  · `check_ecc_form`：存量非规范 `source` → **WARN（不 FAIL）**
"""
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_finding as GF  # noqa: E402
import gk_self_check as SC  # noqa: E402


def _mk_state(tmp_path, findings=None):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"stage": "ECO-EDIT", "worktree": str(tmp_path),
                              "gate_data": {"ecc_findings": findings or []}},
                             ensure_ascii=False), encoding="utf-8", newline="\n")
    return st


PROSE = "2026-09-28 实测（F7 族落刀期间）；复算命令见 /tmp/x.py，结论：两消费点口径不一致"


# ── register 边界：fail-loud ────────────────────────────────────────────────
def test_source_blank_rejected(tmp_path):
    st = _mk_state(tmp_path)
    with pytest.raises(ValueError, match="source 不能为空"):
        GF.register(str(st), "t", "")


def test_source_prose_rejected(tmp_path):
    """散文 `source`（含空白）必须 fail-loud —— 这正是本轮实测的污染形态。"""
    st = _mk_state(tmp_path)
    with pytest.raises(ValueError, match="source 非法"):
        GF.register(str(st), "t", PROSE)


def test_source_over_length_rejected(tmp_path):
    st = _mk_state(tmp_path)
    with pytest.raises(ValueError, match="source 非法"):
        GF.register(str(st), "t", "x" * (GF._SOURCE_MAX + 1))


def test_source_unknown_token_rejected(tmp_path):
    st = _mk_state(tmp_path)
    with pytest.raises(ValueError, match="不在白名单"):
        GF.register(str(st), "t", "R25.9")


@pytest.mark.parametrize("tok", GF._ECC_SOURCES)
def test_source_whitelist_all_accepted(tmp_path, tok):
    st = _mk_state(tmp_path)
    out = GF.register(str(st), "t-" + tok, tok)
    assert out["source"] == tok
    assert out["source_note"] == ""


# ── source_note：长文本出处与 token 分离 ───────────────────────────────────
def test_source_note_kept_separate_from_source(tmp_path):
    st = _mk_state(tmp_path)
    out = GF.register(str(st), "t", "manual", source_note=PROSE)
    assert out["source"] == "manual", "token 不得被长文本污染"
    assert out["source_note"] == PROSE, "长文本须落 source_note"
    # 落盘复核（不只信返回值）
    d = json.loads(st.read_text(encoding="utf-8"))
    rec = d["gate_data"]["ecc_findings"][0]
    assert rec["source"] == "manual" and rec["source_note"] == PROSE


# ── --from-report：只抽允许字段 ────────────────────────────────────────────
def test_from_report_extracts_allowed_fields_only(tmp_path):
    """subagent `EccOutput` 形态报告：只抽白名单字段，**禁**整份入册。"""
    rep = tmp_path / "sub-1.json"
    rep.write_text(json.dumps({
        "title": "报告的标题",
        "family": "DEMO-FAMILY",
        "anchors": ["scripts/a.py:1-2"],
        "facets": ["f1"],
        # ↓ 这些是 EccOutput 的易失字段，**不得**进台账
        "conclusion": "结论正文",
        "evidence": [{"cmd": "ls"}],
        "next_steps": ["下一步"],
        "jwt_token": "xxx.yyy.zzz",
        "hmac": "deadbeef",
    }, ensure_ascii=False), encoding="utf-8")

    payload = GF._load_report_payload(str(rep))
    assert payload["title"] == "报告的标题"
    assert payload["family"] == "DEMO-FAMILY"
    assert payload["anchors"] == ["scripts/a.py:1-2"]
    for forbidden in ("conclusion", "evidence", "next_steps", "jwt_token", "hmac"):
        assert forbidden not in payload, "易失字段 %s 泄漏进提升载荷" % forbidden
    assert "sha256=" in payload["_note"]


def test_from_report_rejects_non_object(tmp_path):
    rep = tmp_path / "arr.json"
    rep.write_text("[1,2,3]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON \\*\\*对象\\*\\*"):
        GF._load_report_payload(str(rep))


def test_from_report_rejects_unreadable(tmp_path):
    with pytest.raises(ValueError, match="不可读"):
        GF._load_report_payload(str(tmp_path / "nope.json"))


# ── check_ecc_form：存量 WARN 分级 ────────────────────────────────────────
LEGACY = [{"id": "ECC-AAAAAAAAAAAA", "title": "旧条目", "source": PROSE,
           "status": "open", "closure_oracle": "mechanical", "root_key": "a.b.c"},
          {"id": "ECC-BBBBBBBBBBBB", "title": "旧条目2", "source": "",
           "status": "open", "closure_oracle": "", "root_key": ""}]


def test_check_ecc_form_legacy_source_warns_not_fails(tmp_path):
    st = _mk_state(tmp_path, LEGACY)
    out = SC.check_ecc_form(str(st))
    assert out["status"] == "WARN", (
        "存量非规范 source 必须 WARN 而非 FAIL（否则恒红 + 用新规追责历史）：%r" % out)
    assert "source" in out["detail"]


def test_check_ecc_form_clean_source_passes(tmp_path):
    good = [{"id": "ECC-CCCCCCCCCCCC", "title": "合规条目", "source": "manual",
             "status": "open", "closure_oracle": "mechanical", "root_key": "a.b.c"}]
    out = SC.check_ecc_form(str(_mk_state(tmp_path, good)))
    assert out["status"] == "PASS", out


def test_check_ecc_form_bad_root_key_still_fails(tmp_path):
    """回归：`source` 分级**不得**把既有的 `root_key` FAIL 判据降级。"""
    bad = [{"id": "ECC-DDDDDDDDDDDD", "title": "指纹含空白", "source": "manual",
            "status": "open", "root_key": "has space here"}]
    assert SC.check_ecc_form(str(_mk_state(tmp_path, bad)))["status"] == "FAIL"
