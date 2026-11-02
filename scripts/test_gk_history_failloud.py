#!/usr/bin/env python3
"""C3（`ECC-3BECE9FAD12A`）红先臂 —— subagent 落库块 fail-loud + 指针 + 报告对账（2026-09-27）。

C3① 病象（计划 §十一-C3）：`cmd_monitor` 的 subagent 落库块（`GK_HMAC_VALID` 锚 → python -c 收尾行）
以 `2>/dev/null || true` 收尾 ⟹ `dump_state` 写失败 / 载荷异常**全被吞** ⟹ `subagent_history`
不写而无人知（ECO-EDIT→ECO-AUDIT 门禁链静默断裂；亦使 C1/C2/C4 的瘦身/外置若失败同样静默）。

C3②：落库条目此前**只有摘要**，审核 / 评分须凭 `subagent_id` 去 `docs/analysis/subagent/` 反查
（隐式约定）⟹ 补 `output_file`/`report_file` 指针。

C3③ 病象：`docs/analysis/subagent/*.json` 与 `gate_data.subagent_history[]` **无一致性校验**
（报告已落盘但落库静默失败时无人可查）。

判据（红先，HEAD **必红**）：
  ① 落库段**收尾行**不得含 `2>/dev/null`（丢弃 stderr = 吞错形态）；
  ② 落库段须含 fail-loud 标记 `HISTORY_WRITE_FAILED`（失败显式报错 + 留痕）；
  ③ 落库段须对 `dump_state` 返回值设防（`if not dump_state(`）⟹ 写失败不得静默 exit 0；
  ④ 落库段须把落盘指针经 env 传入（`GK_OUTPUT_FILE`/`GK_REPORT_FILE`）并存进入口；
  ⑤ 只读对账面 `reconcile_subagent_reports`（**窗口内双向**，2026-09-27 用户裁定）：
     `subagent_history` 有 96KB 字节配额（实测仅 6 条），报告文件长期累积（实测 304+）⟹ 全量双向
     必被「配额滑出」的旧文件淹没（恒 FAIL 噪声）。故只对 **epoch ≥ 最老条目 epoch** 的窗口内文件
     做双向判定，更老者归 `aged_out`（仅计数，不判 FAIL）；⑥ 该面对须挂进 `audit --state` 检查链。

静态臂（①②③④）+ 行为臂（⑤⑥，import 既有 tracked 模块 `gk_audit_state`）。红先性：HEAD 的
`gk_audit_state` **无** `reconcile_subagent_reports` ⟹ ⑤⑥ 必红；CLI 收尾仍是吞错形态 ⟹ ①②③④ 必红。
"""
import json
import sys
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"
SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


# ───────────────────────── C3①/C3②：落库段形态臂 ─────────────────────────

def _hist_region() -> str:
    """subagent 落库段：`GK_HMAC_VALID=` 锚 → python -c 的**收尾行**（列 0 的 `"`）末。

    切片止于收尾行，**不含**其后的 bash `_state_checksum_write` 注释区 —— HEAD 实测
    `_state_checksum_write` 在注释（L4129）里先于真调用（L4137）出现，若切到首个 token
    会**在注释处误截**（收尾行 4126 恰好仍在内，故臂不假绿，但语义边界不清）。
    """
    txt = CLI.read_text(encoding="utf-8")
    i = txt.index("GK_HMAC_VALID=")
    j = txt.index('\n"', i) + 1          # 收尾行行首 `"`
    k = txt.index("\n", j + 1)
    return txt[i:k]


def _terminator(seg: str) -> str:
    """落库段里以列 0 `"` 开头的那一行（闭合 python -c 双引号 + 其后重定向）。"""
    lines = [ln for ln in seg.splitlines() if ln.startswith('"')]
    assert lines, "落库段未见 python -c 收尾行（锚漂移？）"
    return lines[-1]


def test_history_block_terminator_not_silent():
    """① 落库段收尾行不得丢弃 stderr（HEAD = `" 2>/dev/null || true` ⟹ 本臂必红）。"""
    term = _terminator(_hist_region())
    assert "2>/dev/null" not in term, (
        "subagent 落库段收尾行仍丢弃 stderr（%r）⟹ dump_state 写失败/载荷异常无痕（C3① 未落）"
        % term.strip())


def test_history_block_fail_loud_marker():
    """② 落库段失败须 fail-loud（含 `HISTORY_WRITE_FAILED` 标记）。"""
    seg = _hist_region()
    assert "HISTORY_WRITE_FAILED" in seg, (
        "subagent 落库段失败未 fail-loud（缺 `HISTORY_WRITE_FAILED`）⟹ history 丢失不可观测")


def test_history_block_dump_failure_guarded():
    """③ 落库段须对 `dump_state` 返回值设防（写失败须非零退出，不静默 exit 0）。"""
    seg = _hist_region()
    assert "if not dump_state(" in seg, (
        "subagent 落库段未对 dump_state 返回值设防（缺 `if not dump_state(`）⟹ 写失败静默退出 0")


def test_history_entry_carries_file_pointers():
    """④ 落库段须把 ECC JSON / 双盲报告落盘路径经 env 传入入口（C3② 指针）。"""
    seg = _hist_region()
    assert "GK_OUTPUT_FILE" in seg and "GK_REPORT_FILE" in seg, (
        "subagent 落库段未带 output_file/report_file 指针（缺 GK_OUTPUT_FILE/GK_REPORT_FILE）"
        "⟹ 审核须按隐式约定反查目录")


# ─────────────────── C3③：报告文件 ↔ history 条目只读对账臂 ───────────────────

def _recon():
    import gk_audit_state
    return gk_audit_state.reconcile_subagent_reports


def _mk(tmp_path, entries, files):
    """造 skill_dir：`docs/analysis/subagent/` 放给定 `.json`；返回 (skill_dir, gate_data)。"""
    rdir = tmp_path / "docs" / "analysis" / "subagent"
    rdir.mkdir(parents=True, exist_ok=True)
    for f in files:
        (rdir / (f + ".json")).write_text("{}", encoding="utf-8")
    gd = {"subagent_history": [{"subagent_id": x} for x in entries]}
    return str(tmp_path), gd


def test_reconcile_detects_entry_without_file(tmp_path):
    """⑤a entry→file：history 条目缺对应报告文件 ⟹ 判 FAIL（真异常）。"""
    sd, gd = _mk(tmp_path, ["sub-1000-1-1", "sub-1001-1-2"], ["sub-1000-1-1"])
    r = _recon()(gd, sd)
    assert r["entries_without_files"] == ["sub-1001-1-2"], r
    assert r["ok"] is False, r


def test_reconcile_detects_file_without_entry_in_window(tmp_path):
    """⑤b file→entry（窗口内）：报告已落盘但 history 无条目 = C3 病象 ⟹ 判 FAIL。"""
    sd, gd = _mk(tmp_path, ["sub-1000-1-1"], ["sub-1000-1-1", "sub-1001-1-2"])
    r = _recon()(gd, sd)
    assert r["files_without_entries"] == ["sub-1001-1-2"], r
    assert r["ok"] is False, r


def test_reconcile_ignores_aged_out_files(tmp_path):
    """⑤c 窗口外（epoch < 最老条目）：配额滑出的旧文件 ⟹ 仅计 `aged_out`，不判 FAIL。"""
    sd, gd = _mk(tmp_path, ["sub-2000-1-1"], ["sub-2000-1-1", "sub-1000-1-9"])
    r = _recon()(gd, sd)
    assert r["files_without_entries"] == [], r
    assert r["aged_out"] == 1, r
    assert r["ok"] is True, r


def test_audit_state_emits_subagent_reports_check(tmp_path):
    """⑥ 接线：`audit --state` 的检查链须含 `subagent_reports` 只读对账面。"""
    import gk_audit_state
    import gk_state
    sd, gd = _mk(tmp_path, ["sub-2000-1-1"], ["sub-2000-1-1"])
    sp = str(tmp_path / ".gatekeeper.state")
    gk_state._write_state({"gate_data": gd, "monitor_scores": {}, "history": [],
                           "appeal_records": {}, "human_resolutions": {},
                           "achievements": {}}, sp)
    out = gk_audit_state.check_state_file(sp, skill_dir=sd)
    fields = [c.get("field") for c in out["state_checks"]]
    assert "subagent_reports" in fields, fields
