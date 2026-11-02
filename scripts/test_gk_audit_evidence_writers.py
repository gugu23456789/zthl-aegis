#!/usr/bin/env python3
"""2a/3 合并后的**写者不变量**红先臂（2026-10-19，batch `55c3ef94cc6d`）。

缺陷（六臂质询）：判据2a 与判据3 共用同一 pytest 文件/命令；且 2a 的
「审计证据键无旁路」只在三个 state-patch 子命令成立，而 `gk_advance`
直写 `rejected_edits` / `entropy_history` —— 被审侧可重置熵窗口。

修法：把键集拆成
  · `_AUDIT_EVIDENCE_KEYS` = 审计器/人类裁决的自身产物（仅审计侧写）；
  · `_SUBJECT_TELEMETRY_KEYS` = `gk_advance` 的拒绝缓冲/熵窗口（受审侧写，
    state-patch 仍全拒，但只记 visibility-level）。
本文件 = 与 `test_gk_host_write_surface.py` **不同**的载体命令：静态证明
`gk_advance.py` 对审计证据键**零写点**（读点允许）。
"""
import re
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_state_patch as SP  # noqa: E402


def _write_patterns(key: str):
    """LHS/写法模式：下标赋值、setdefault、update(dict)。读点（.get / 文案）不命中。"""
    k = re.escape(key)
    return (
        re.compile(r"\[\s*[\"']%s[\"']\s*\]\s*=" % k),
        re.compile(r"setdefault\(\s*[\"']%s[\"']" % k),
        re.compile(r"update\(\s*\{[^}]*[\"']%s[\"']" % k),
    )


def _has_write(src: str, key: str) -> bool:
    return any(p.search(src) for p in _write_patterns(key))


def test_regex_positive_control():
    """正控：gk_advance 确实写受审侧遥测；否则下面的零写点测试是空真。"""
    src = (SCRIPTS / "gk_advance.py").read_text(encoding="utf-8")
    assert _has_write(src, "rejected_edits"), "正控失败：未识别 rejected_edits 写点"
    assert _has_write(src, "entropy_history"), "正控失败：未识别 entropy_history 写点"


def test_gk_advance_has_no_audit_evidence_write_points():
    """被审侧 gk_advance 对审计证据键零写点（读点允许）。"""
    src = (SCRIPTS / "gk_advance.py").read_text(encoding="utf-8")
    hits = sorted(k for k in SP._AUDIT_EVIDENCE_KEYS if _has_write(src, k))
    assert not hits, "gk_advance.py 出现审计证据键写点 %r —— 违反 2a 写者不变量" % (hits,)


def test_audit_evidence_and_telemetry_are_disjoint():
    assert SP._AUDIT_EVIDENCE_KEYS.isdisjoint(SP._SUBJECT_TELEMETRY_KEYS)


def test_state_patch_deny_set_covers_payload_evidence_telemetry():
    deny = SP._STATE_PATCH_DENY_KEYS
    assert SP._PAYLOAD_KEYS <= deny
    assert SP._AUDIT_EVIDENCE_KEYS <= deny
    assert SP._SUBJECT_TELEMETRY_KEYS <= deny


# ─── E2 覆盖率不变量（2026-10-28）：**声明为审计证据的键必须有生产者** ───
# 病象（审计署 §26.10-C-2）：deny 集合声明 `audit_memory_result` / `audit_crossr_result`
# 是「审计侧单一写者落库」的证据键，但 `cmd_audit --memory/--crossr` 只把结果 echo 到
# stdout（`gatekeeper-cli.sh:10536/10551`），**从未落盘** ⟹ 判据侧永远读不到它们，
# 而「声明 ≠ 有生产者」不会被既有臂发现（旧臂只查「非审计侧不得写」的旁路面）。
# 不变量：`_AUDIT_EVIDENCE_KEYS` 中每个 `*_result` 键（除遗留别名 `audit_result`）都必须
# 在 CLI 侧存在**真落盘**写法 `_state_write "...['<key>']=..."`。
_CLI = SCRIPTS.parent / "gatekeeper-cli.sh"


def _producer_keys() -> list[str]:
    return sorted(k for k in SP._AUDIT_EVIDENCE_KEYS
                  if k.endswith("_result") and k != "audit_result")


def _cli_src() -> str:
    return _CLI.read_text(encoding="utf-8", errors="replace")


def test_每一声明的审计证据键都有真落盘生产者():
    """E2 红先臂：`audit_memory_result` / `audit_crossr_result` 此前零生产者。"""
    src = _cli_src()
    missing = [k for k in _producer_keys()
               if not re.search(r"_state_write[^\n]*\[['\"]%s['\"]\]\s*=" % re.escape(k), src)]
    assert not missing, (
        "以下审计证据键无真落盘生产者（只被 deny 集合「声明」）: %r —— "
        "要么在 `cmd_audit` 对应分支补 `_state_write`，要么从 `_AUDIT_EVIDENCE_KEYS` 移除"
        % (missing,))


def test_生产者不变量正控():
    """正控：已落盘的 state/docs 两域须被识别（防正则退化成空真）。"""
    src = _cli_src()
    for k in ("audit_state_result", "audit_docs_result"):
        assert re.search(r"_state_write[^\n]*\[['\"]%s['\"]\]\s*=" % re.escape(k), src), k
