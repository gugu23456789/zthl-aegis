#!/usr/bin/env python3
"""r9-2 ②a「未审债 ⟹ **下一节点门可见**」可见性回归（`ECC-BCF60C185CBE`，2026-10-01，**红先**）。

判据来源：`docs/plans/2026-09-18-edit-budget-dual-track-plan.md` §19.2/§19.3（`pre_tool_check` /
`PROTECTED_REGION::gate`；owner 裁定 A；**不新增 kill switch**）。

方案 i-b（零边际子进程 + 判据单源）三点：
  ① `scripts/gk_edit_gate.py check` 输出加 `unreconciled_raises`（判据单源 =
     `gk_credit_ledger.reconcile()`，**禁**在门禁侧复制对账逻辑）；
  ② `pre_tool_check()` 放行面**透传**该字段（复用本分支**已付**的那次 `gk_edit_gate.py` 调用）；
  ③ `pre_tool_hook.py` Gate 4 放行面据此发 `GATEKEEPER-WARN`（**不改判定**，只做可见性）。

各臂（落刀前全红）：
  A1 `gk_edit_gate.py` 对「有 raise / 无 outcome」的账本回出该 `id`；
  A2 账本已对账（outcome 带 `ref`）⟹ 回空（防恒报）；
  A3 `pre-tool-check edit <f>` 放行面 stdout 带 `{"ok":true,…unreconciled_raises…}`；
  A4 hook 的 WARN 文案（正/负）；A5 无 `edit_gate` 面（非写类/旧 CLI）⟹ 不误报。
"""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = Path(os.environ.get("GK_CLI_UNDER_TEST") or (SKILL_DIR / "gatekeeper-cli.sh"))
EDIT_GATE = SCRIPT_DIR / "gk_edit_gate.py"


def _wsl(p) -> str:
    """Windows 路径 → WSL 路径（`C:\\a\\b` → `/mnt/c/a/b`）。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _write_ledger(sb: Path, records) -> None:
    """写 `credit-ledger`（append-only 形态；封印缺失不影响 `reconcile` 读面）。"""
    lines = [json.dumps(r, ensure_ascii=False) for r in records]
    (sb / ".gatekeeper.state.credit-ledger.jsonl").write_text(
        "\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def _sandbox(tmp_path: Path) -> Path:
    """最小技能根：`scripts` 软链 + CLI 实拷 + 最小 standing state + 待编辑目标。

    刻意与 `test_gk_edit_budget_metering._mk_sandbox` 同形：`stage` 非 IDLE/DONE、
    `worktree` 留空（跳过 worktree 归属检查）⟹ 可达 `pre_tool_check` 的放行面。
    """
    sb = (tmp_path / "sb").resolve()
    sb.mkdir()
    w = _wsl(sb)
    r = subprocess.run(
        ["bash", "-lc", 'ln -s "%s" "%s/scripts" && cp "%s" "%s/gatekeeper-cli.sh"'
         % (_wsl(SCRIPT_DIR), w, _wsl(CLI_SRC), w)],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, f"沙箱搭建失败：{r.stdout}{r.stderr}"
    (sb / ".gatekeeper.state").write_text(json.dumps({
        "stage": "STAGE_0", "r_phase": "R1", "worktree": _wsl(sb),  # §17-6-P4：显式 root
        "gate_data": {
            "project_type": "standing",
            "edit_budget": {"max": 4, "used": 0, "remaining": 4},
            "scheduler": {"mode": "constant", "max_lr": 4, "min_lr": 1,
                          "total_steps": 6, "current_step": 1, "current_lr": 4},
        },
    }, ensure_ascii=False), encoding="utf-8", newline="\n")
    (sb / "note.md").write_text("x", encoding="utf-8", newline="\n")
    return sb


@pytest.fixture()
def sandbox():
    if shutil.which("bash") is None:
        pytest.skip("本机无 bash（Windows 语义下 pre_tool_check 无法执行）")
    root = Path(tempfile.mkdtemp(prefix="gk_debt_"))
    try:
        yield _sandbox(root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _edit_gate(sb: Path) -> dict:
    """直调判据单源 `gk_edit_gate.py check`（不经 CLI 文案层）。"""
    w = _wsl(sb)
    r = subprocess.run(
        ["bash", "-lc", 'cd "%s" && python3 "%s" check --state "%s/.gatekeeper.state" '
                        '--path "%s/note.md"' % (w, _wsl(EDIT_GATE), w, w)],
        capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, f"gk_edit_gate check 未放行：rc={r.returncode} {r.stdout}{r.stderr}"
    return json.loads(r.stdout.strip().splitlines()[-1])


def _cli_run(sb: Path):
    w = _wsl(sb)
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh pre-tool-check edit "%s/note.md"' % (w, w)],
        capture_output=True, text=True, timeout=180)


def _json_line(stdout: str):
    for ln in (stdout or "").splitlines():
        if ln.strip().startswith("{"):
            return json.loads(ln.strip())
    return None


# ══════════════════ A1/A2：判据单源面（`gk_edit_gate.py`）══════════════════════════════════
def test_arm1_edit_gate_reports_unreconciled_raise(sandbox):
    """A1：账本有 `raise` 无 outcome ⟹ `unreconciled_raises` 必须**在场且含该 id**。"""
    _write_ledger(sandbox, [
        {"ts": "2026-10-01T00:00:00Z", "id": "20261001T000000-0001",
         "kind": "raise", "delta": 0, "source": "test", "reason": ""},
    ])
    out = _edit_gate(sandbox)
    assert out.get("decision") == "allow", f"判据面应放行（本缺陷只做可见性）：{out}"
    assert "unreconciled_raises" in out, (
        "`gk_edit_gate.py check` 未输出 `unreconciled_raises` ⟹ 未审债对门不可见（r9-2 ②a 未落刀）：%s"
        % sorted(out.keys()))
    assert out["unreconciled_raises"] == ["20261001T000000-0001"], (
        "未审债取值错误：%r" % (out["unreconciled_raises"],))


def test_arm2_edit_gate_empty_when_reconciled(sandbox):
    """A2（反臂）：outcome 行以 `ref` 回填 ⟹ 对账通过、**不得**恒报未审。"""
    _write_ledger(sandbox, [
        {"ts": "2026-10-01T00:00:00Z", "id": "20261001T000000-0001",
         "kind": "raise", "delta": 0, "source": "test", "reason": ""},
        {"ts": "2026-10-01T00:10:00Z", "id": "20261001T001000-0002",
         "kind": "success", "delta": 5, "ref": "20261001T000000-0001",
         "source": "audit", "reason": ""},
    ])
    out = _edit_gate(sandbox)
    assert "unreconciled_raises" in out, "字段缺席（红）：%s" % sorted(out.keys())
    assert out["unreconciled_raises"] == [], "已对账却仍报未审债：%r" % (out["unreconciled_raises"],)


# ══════════════════ A3：CLI 放行面透传（零边际子进程）═══════════════════════════════════════
def test_arm3_cli_passthrough_carries_debt(sandbox):
    """A3：`pre-tool-check edit` 放行面须带 `{"ok":true,…}` 行（hook 据此发 WARN）。

    契约：首行 `OK` 保留（既有消费点按 rc / `OK` 判）；债面另起一行 JSON。
    """
    _write_ledger(sandbox, [
        {"ts": "2026-10-01T00:00:00Z", "id": "20261001T000000-0001",
         "kind": "raise", "delta": 0, "source": "test", "reason": ""},
    ])
    r = _cli_run(sandbox)
    assert r.returncode == 0, f"放行面被破坏：rc={r.returncode} {r.stdout}{r.stderr}"
    assert "OK" in r.stdout, f"既有 `OK` 契约被破坏：{r.stdout[:200]}"
    j = _json_line(r.stdout)
    assert isinstance(j, dict) and j.get("ok") is True, (
        "放行面未透传机检 JSON 行（hook `_run_cli` 取不到债面）：%r" % (r.stdout[:300],))
    debt = (j.get("edit_gate") or {}).get("unreconciled_raises")
    assert debt == ["20261001T000000-0001"], "透传的未审债取值错误：%r" % (debt,)


# ══════════════════ A4/A5：hook 可见性文案（`GATEKEEPER-WARN`）══════════════════════════════
def test_arm4_hook_warn_text_positive(sandbox):
    """A4：有债 ⟹ 文案含未审债笔数与其 id（`GATEKEEPER-WARN` 通道，不改判定）。"""
    import pre_tool_hook as p
    txt = p._unreconciled_debt_warn(
        {"ok": True, "edit_gate": {"unreconciled_raises": ["A-1", "B-2", "C-3"]}})
    assert txt.startswith("GATEKEEPER-WARN:"), f"未走既有 WARN 通道：{txt!r}"
    assert "3" in txt and "A-1" in txt, f"文案缺笔数/id：{txt!r}"


def test_arm5_hook_warn_text_negative(sandbox):
    """A5（反臂）：无债 / 非写类面（旧 CLI 无 `edit_gate`）⟹ **不得**出 WARN。"""
    import pre_tool_hook as p
    assert p._unreconciled_debt_warn({"ok": True, "raw": "OK"}) == ""
    assert p._unreconciled_debt_warn({"ok": True, "edit_gate": {"unreconciled_raises": []}}) == ""
