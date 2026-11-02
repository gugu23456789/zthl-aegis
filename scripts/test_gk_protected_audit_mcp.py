#!/usr/bin/env python3
"""保护区审计留痕缺口红先臂（`ECC-317C82A14DE8`，2026-10-13）。

两处缺口（2026-10-13 实测，非推测）：
  ① **`_protected_target_line` 不认 MCP 写形态**：该函数只读**顶层** `old_str`/`content`，而 MCP 写
     （`run_mcp` / `mcp__<server>__<tool>`）参数据在 `args` 下（`_mcp_inner_tool` 自证）⟹ 恒退
     `"0"`（文件级）⟹ **行级判定与 `_pe_record` 留痕对 MCP 写路径不可达**。与 2026-09-22
     `ECC-BFE933526D0B`（"恒 target_line=0 ⟹ 行级不可达"）**同型复活**。
  ② **文件级分支只 WARN 不留痕**：`_protected_region_check` 无有效行号时仅 echo WARN 后 `return 0`，
     **不写审计** ⟹ 行号不可得时（MCP 形态 / 宿主载荷键名不符）**静默无留痕**。

修法 = ① `_protected_target_line` 复用 `_mcp_inner_tool` 剥 `args`，并支持 `edits[].oldText`
（filesystem MCP `edit_file` 真实形态）；② 文件级分支亦 `_pe_record`（消除静默窗口）。
"""
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

SKILL_DIR = Path(__file__).resolve().parent.parent
CLI = SKILL_DIR / "gatekeeper-cli.sh"

_spec = importlib.util.spec_from_file_location(
    "_pt_hook", Path(__file__).resolve().parent / "pre_tool_hook.py")
H = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(H)


def _gate_anchor_line() -> int:
    return CLI.read_text(encoding="utf-8").split("\n").index("cmd_model_probe() {") + 1


# ── ① MCP 写形态：行级线索须可提取 ──────────────────────────────────
def test_protected_line_mcp_run_mcp_edit_file():
    """红先 ①（`ECC-317C82A14DE8`）：`run_mcp` 包裹的 filesystem `edit_file`
    （`args.edits[].oldText`）须能提出行号（HEAD 恒 "0"）。"""
    anchor = "cmd_model_probe() {"
    res = H._protected_target_line(
        "run_mcp",
        {"tool_name": "edit_file",
         "args": {"path": str(CLI), "edits": [{"oldText": anchor, "newText": "x"}]}},
        str(CLI))
    assert res != "0", "MCP run_mcp/edit_file 形态未提出行号（保护区行级留痕失效）"
    assert str(_gate_anchor_line()) in res.split(","), "未命中 banner 落点行：%s" % res


def test_protected_line_mcp_run_mcp_write_file():
    """红先 ①：`run_mcp` 包裹的 filesystem `write_file`（`args.content`）须能提出差异行。"""
    txt = CLI.read_text(encoding="utf-8")
    altered = txt.replace("cmd_model_probe() {", "cmd_model_probe() {  # probe", 1)
    res = H._protected_target_line(
        "run_mcp",
        {"tool_name": "write_file", "args": {"path": str(CLI), "content": altered}},
        str(CLI))
    assert res != "0", "MCP run_mcp/write_file 形态未提出差异行（保护区行级留痕失效）"
    assert str(_gate_anchor_line()) in res.split(","), "未命中 banner 落点行：%s" % res


def test_protected_line_mcp_direct_form():
    """红先 ①：直呼 `mcp__filesystem__edit_file` 形态（参数同样在 `args` 下）须能提出行号。"""
    anchor = "cmd_model_probe() {"
    res = H._protected_target_line(
        "mcp__filesystem__edit_file",
        {"args": {"path": str(CLI), "edits": [{"oldText": anchor, "newText": "x"}]}},
        str(CLI))
    assert res != "0", "MCP 直呼形态未提出行号（保护区行级留痕失效）"
    assert str(_gate_anchor_line()) in res.split(","), "未命中 banner 落点行：%s" % res


# ── ② 文件级分支亦须留痕 ────────────────────────────────────────────
def test_protected_file_level_branch_records():
    """红先 ②（`ECC-317C82A14DE8`）：`_protected_region_check` 的**文件级分支**（无有效行号）
    亦须 `_pe_record`（HEAD 只 echo WARN ⟹ 静默无审计）。

    判据：函数体内 `_pe_record "` 调用数 ≥ 2（行级分支 + 文件级分支）。
    """
    src = CLI.read_text(encoding="utf-8")
    body = src[src.index("_protected_region_check() {"):]
    body = body[: body.index("\n}\n")]
    n = body.count('_pe_record "')
    assert n >= 2, "文件级分支未落留痕（函数体内 `_pe_record \"` 调用数=%d < 2）" % n


# ── ③ MCP 写工具身份粒度：`edit_file` 须按**局部编辑**语义 ─────────────
def test_mcp_edit_file_identity_is_partial_edit():
    """红先 ③（`ECC-317C82A14DE8` G3）：`_write_identity` 须把 filesystem MCP `edit_file` 归成
    **局部编辑**（`SearchReplace`），而非整文件写（`Write`）。

    HEAD：一律归 `Write` ⟹ CLI `pre-tool-check` 以「整文件覆盖」拦**已存在文件**（2026-10-13 实测
    hook BLOCK「禁止整体覆盖已存在文件 '…red-arm-templates.json'（Write/CreateFile 为整文件写）——
    请改用 Edit/SearchReplace 做局部改」）⟹ **MCP 写工具对已存在文件实际不可用**。
    """
    name, path = H._write_identity(
        "run_mcp", "", {"tool_name": "edit_file", "args": {"path": str(CLI), "edits": []}})
    assert name == "SearchReplace", "edit_file 被归成 %s（局部编辑当整文件覆盖 ⟹ 被 CLI 拦）" % name
    assert path.endswith("gatekeeper-cli.sh")
    assert H._write_identity(
        "run_mcp", "", {"tool_name": "write_file", "args": {"path": str(CLI)}})[0] == "Write", \
        "write_file 应保持整文件写语义（Write）"
