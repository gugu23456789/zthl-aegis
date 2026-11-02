#!/usr/bin/env python3
"""host-3 红先臂：载荷键不得经定点写面写入（§18.2 / §19.7 host-3，2026-10-04）。

缺陷（二轮质询 `sub-1791095585-1450-12` 驳回「host-3 可执行」②）：判据 host-3「host 只许写
索引键、禁写载荷键」**无代码载体** —— `set-nested`/`append-list`（host 唯一写面）此前**只**挡
空段 / `_` 前缀 / `worktrees_extra` ⟹ host 可自助写 `gate_data.<载荷键>`
（`subagent_history`/`subagent_last`/`task_pipeline`/`ecc_findings`）= 大体积臂输出绕过唯一
写入者落库 ⟹ 判据对**空代码路径**执行 = **幻影判据**。

修法：① `gk_state_patch._PAYLOAD_KEYS` **单点登记**（名单）；② `_path_denied` 增**写点断言**
（含**漏 `gate_data.` 前缀**形态 —— 原始 segs 首段即载荷键，归位后成 `gate_data.<载荷键>`）。

臂（HEAD 必红：无 `_PAYLOAD_KEYS` ⟹ `AttributeError`）：
  · `payload_keys_single_source` 静态：名单存在且恰为 4 键（单一事实源）
  · `set_nested_rejects_payload_key` 行为：含前缀 → 拒（fail-loud）
  · `set_nested_rejects_payload_key_bare` 行为：漏前缀 → 拒
  · `append_list_rejects_payload_key` 行为：append-list → 拒
  · `allows_index_key` **负臂**：索引键 `satellite_index` **须**仍可写（防过度收紧成「全禁」）
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_state_patch as SP  # noqa: E402

PAYLOAD = ("subagent_history", "subagent_last", "task_pipeline", "ecc_findings")


def _state(tmp: Path) -> Path:
    p = tmp / ".gatekeeper.state"
    p.write_text(json.dumps({"stage": "ECO-EDIT", "r_phase": "R1", "worktree": "",
                             "gate_data": {}}, ensure_ascii=False),
                 encoding="utf-8", newline="\n")
    return p


def test_payload_keys_single_source():
    """静态：载荷键名单须为**单点登记**的 4 键（防第二份名清单漂移）。"""
    assert SP._PAYLOAD_KEYS == frozenset(PAYLOAD), "载荷键名单须恰为 %r" % (PAYLOAD,)


def test_set_nested_rejects_payload_key(tmp_path):
    out = SP.cmd_set_nested(str(_state(tmp_path)), "gate_data.subagent_history", "[]")
    assert out["ok"] is False and "载荷键" in out["error"], out


def test_set_nested_rejects_payload_key_bare(tmp_path):
    """漏 `gate_data.` 前缀形态（归位后即 `gate_data.task_pipeline`）也须被拒。"""
    out = SP.cmd_set_nested(str(_state(tmp_path)), "task_pipeline", "[]")
    assert out["ok"] is False and "载荷键" in out["error"], out


def test_append_list_rejects_payload_key(tmp_path):
    out = SP.cmd_append_list(str(_state(tmp_path)), "gate_data.ecc_findings", "{}")
    assert out["ok"] is False and "载荷键" in out["error"], out


def test_allows_index_key(tmp_path):
    """负臂：索引键（`satellite_index`）须**仍可**写 —— 防判据退化成「全禁」。"""
    out = SP.cmd_set_nested(str(_state(tmp_path)),
                            "gate_data.satellite_index", '{"b1":{"file":"x"}}')
    assert out["ok"] is True, out


# ── 2026-10-18 / 2026-10-19（6 臂质询 `ECC-458FA591E582` / `ECC-0C394FD226F7`）──
# 审计证据键 = 审计器/人类裁决的**自身产物**；受审侧遥测键 = gk_advance 的
# 拒绝缓冲/熵窗口。两者都禁经 state-patch 三写面；但只有前者记 control 级，
# 后者仅 visibility-level（control 级需 BLOCKED 的判据2b）。
EVIDENCE = ("human_calibration_log", "audit_state_result", "audit_docs_result",
            "audit_memory_result", "audit_crossr_result",
            # 2026-10-28（6 臂质询 E1）：遗留别名 `audit_result` 被 `audit_all_recorded`
            #   采信（gk_node_guard.py:468）却不在任何 deny 集合 ⟹ 被审方可自造「审计证据
            #   已落盘」。纳入证据键名单 = 关闭该旁路（判据2a 在该别名面恢复 control 级）。
            "audit_result")
TELEMETRY = ("rejected_edits", "entropy_history")


def test_audit_evidence_keys_single_source():
    """静态：审计证据键须为单点登记（仅审计器/人类裁决写）。"""
    assert SP._AUDIT_EVIDENCE_KEYS == frozenset(EVIDENCE), \
        "审计证据键名单须恰为 %r" % (EVIDENCE,)


def test_subject_telemetry_keys_single_source():
    """静态：受审侧遥测键须为单点登记（gk_advance 写；不冒充审计证据）。"""
    assert SP._SUBJECT_TELEMETRY_KEYS == frozenset(TELEMETRY), \
        "受审侧遥测键名单须恰为 %r" % (TELEMETRY,)


def test_audit_evidence_and_telemetry_disjoint():
    assert SP._AUDIT_EVIDENCE_KEYS.isdisjoint(SP._SUBJECT_TELEMETRY_KEYS)


def test_update_gate_data_rejects_payload_key(tmp_path):
    """第二写面不得整份替换载荷键（`ecc_findings`）。"""
    out = SP.cmd_update_gate_data(str(_state(tmp_path)), '"ecc_findings":[]')
    assert out["ok"] is False and "载荷键" in out["error"], out


def test_update_gate_data_rejects_audit_evidence_key(tmp_path):
    """第二写面不得重置审计证据（`human_calibration_log`）。"""
    out = SP.cmd_update_gate_data(str(_state(tmp_path)), '"human_calibration_log":[]')
    assert out["ok"] is False and "审计证据" in out["error"], out


def test_audit_result_alias_denied_on_both_write_surfaces(tmp_path):
    """E1（2026-10-28，6 臂质询）：遗留别名 `audit_result` 是两个写面都不得写的**审计证据键**。

    病象：`audit_all_recorded` 采信 `gd["audit_result"]`，但该键不在 `_PAYLOAD_KEYS` /
    `_AUDIT_EVIDENCE_KEYS` / `_SUBJECT_TELEMETRY_KEYS` 任一集合 ⟹ 被审方 `state-patch`
    自写即可满足 ECO-AUDIT 前置 / ECO-DOC 出口 / `audit --report` 签发前置（判据2a 旁路）。
    """
    st = _state(tmp_path)
    out = SP.cmd_set_nested(str(st), "gate_data.audit_result", '{"ok":true}')
    assert out["ok"] is False and "审计证据" in out["error"], out
    out = SP.cmd_update_gate_data(str(st), '"audit_result":{"ok":true}')
    assert out["ok"] is False and "审计证据" in out["error"], out


def test_update_gate_data_rejects_subject_telemetry_key(tmp_path):
    """第二写面也不得重置受审侧遥测（`rejected_edits`），文案须区分。"""
    out = SP.cmd_update_gate_data(str(_state(tmp_path)), '"rejected_edits":[]')
    assert out["ok"] is False and "受审侧遥测" in out["error"], out


def test_update_gate_data_allows_normal_key(tmp_path):
    """负臂：普通 gate_data 键须仍可经第二写面写（防过度收紧）。"""
    out = SP.cmd_update_gate_data(str(_state(tmp_path)), '"ci_status":"green"')
    assert out["ok"] is True, out


def test_set_nested_rejects_audit_evidence_key(tmp_path):
    """叶子写面也不得重置审计证据。"""
    out = SP.cmd_set_nested(str(_state(tmp_path)),
                            "gate_data.human_calibration_log", "[]")
    assert out["ok"] is False and "审计证据" in out["error"], out


def test_set_nested_rejects_subject_telemetry_key(tmp_path):
    """叶子写面也不得重置受审侧遥测。"""
    out = SP.cmd_set_nested(str(_state(tmp_path)),
                            "gate_data.rejected_edits", "[]")
    assert out["ok"] is False and "受审侧遥测" in out["error"], out
