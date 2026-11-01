#!/usr/bin/env python3
"""test_gk_coder_scaffold_net.py — coder 加载安全网红先臂（ECC-835E2928497D，2026-09-26）
================================================================================================
缺陷：`--role coder` 的唯一落刀能力 = `edit` → 入口 `gk_agent_family.load_family(<family>)`。
族脚手架（`references/agent-families/*.json`）或红先臂登记表（`references/red-arm-templates.json`）
**缺失/不可解析**时，`load_family` 只在 coder **首次 edit 调用**才 `FamilyError`，且失败只回给 agent
⟹ 表现「零落刀 + 报告像在分析」= `references/plugin-loading-test-framework.md` §1 三失败模式的
**漏加载静默**（该协议红线：漏/误/错加载必须显式报告）。

修法：`gk_agent_family.scaffold_status()`（单一事实源，三失败模式显式）+ `cmd_monitor` 在
`--subagent --role coder` 处设**派发前置闸**（脚手架不可加载 ⟹ `CODER_SCAFFOLD_MISSING` fail-loud）。

臂：
  arm61  `scaffold_status(<健康目录>)` → `ok=True / source=ready`
  arm62  三失败模式显式：漏加载（目录缺）/ 错误加载（JSON 坏）/ 误加载（family 字段与文件名不符）
  arm63  行为臂：`monitor --subagent --role coder` + 脚手架不可加载 ⟹ rc≠0 + `CODER_SCAFFOLD_MISSING`
  arm64  接线守门臂（负向）：闸须在 `cmd_monitor` 体内且**只**对 `--role coder` 生效
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL = SCRIPT_DIR.parent
CLI = SKILL / "gatekeeper-cli.sh"
sys.path.insert(0, str(SCRIPT_DIR))

_REQ = {"family": "F-demo", "match": {"any": ["x"]}, "tier": 3, "edit_quota": 3,
        "allowed_paths": ["a.py"], "forbidden_paths": ["b.py"],
        "narrow_task_template": "{anchor} 判据自检 {verify_cmd} 禁止越界",
        "test_first": "scripts/test_x.py::t", "verify_cmd": "pytest -q",
        "affected_tests": ["scripts/test_x.py"]}


def _write_family(d: Path, fid: str, **over) -> None:
    fam = dict(_REQ, family=fid)
    fam.update(over)
    d.mkdir(parents=True, exist_ok=True)
    (d / (fid + ".json")).write_text(json.dumps(fam, ensure_ascii=False), encoding="utf-8")


def _monitor_seg() -> str:
    """`cmd_monitor` 整函数体（切到下一个列 0 的 `}`，与函数长度解耦）。"""
    src = CLI.read_text(encoding="utf-8")
    rest = src[src.index("cmd_monitor() {"):]
    m = re.search(r"(?m)^\}$", rest)
    return rest[: m.end()] if m else rest


# ── arm61：健康脚手架 ⟹ ready ─────────────────────────────────────────────
def test_arm61_scaffold_status_healthy_is_ready(tmp_path):
    import gk_agent_family as af
    d = tmp_path / "agent-families"
    _write_family(d, "F-demo")
    st = af.scaffold_status(str(d))
    assert st["ok"] is True, st
    assert st["source"] == "ready", st
    assert "F-demo" in st["families"], st
    assert st["errors"] == [], st


# ── arm62：三失败模式全部显式（禁静默）────────────────────────────────────
def test_arm62_scaffold_status_reports_three_failure_modes(tmp_path):
    import gk_agent_family as af
    # 漏加载：族目录不存在
    miss = af.scaffold_status(str(tmp_path / "nope"))
    assert miss["ok"] is False and miss["source"] == "missing", miss
    assert miss["errors"], miss
    # 错误加载：JSON 坏
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "F-broken.json").write_text("{not json", encoding="utf-8")
    err = af.scaffold_status(str(bad))
    assert err["ok"] is False and err["source"] == "error", err
    assert any("F-broken" in e for e in err["errors"]), err
    # 误加载：`family` 字段与文件名不符（= 加载到错误版本/被篡改）
    mism = tmp_path / "mism"
    _write_family(mism, "F-mism", family="F-other")
    tam = af.scaffold_status(str(mism))
    assert tam["ok"] is False and tam["source"] == "tampered", tam
    assert any("F-mism" in e for e in tam["errors"]), tam
    # 空目录（0 族）= 无落刀脚手架可下发 ⟹ 亦 missing
    empty = tmp_path / "empty"
    empty.mkdir()
    e2 = af.scaffold_status(str(empty))
    assert e2["ok"] is False and e2["source"] == "missing", e2


# ── arm63：派发前置闸（行为臂）─────────────────────────────────────────────
def test_arm63_coder_dispatch_blocked_when_scaffold_missing(tmp_path):
    """脚手架不可加载 ⟹ `monitor --subagent --role coder` 在**派发前** fail-loud。

    `SUBAGENT_TOOLS` 故意含未知工具：修前（无闸）runner 会因 UNKNOWN_TOOL 早退 —— 保证本臂
    **不触达任何 LLM 调用**，且「不出现 CODER_SCAFFOLD_MISSING」正是修前的红判据。
    """
    tf = tmp_path / "task.txt"
    tf.write_text("family: F-demo\n仅允许改动 allowed_paths 内文件。\n", encoding="utf-8")
    env = dict(os.environ, GK_AGENT_FAMILIES_DIR=str(tmp_path / "nope"),
               SUBAGENT_TOOLS="edit,totally-unknown-tool")
    r = subprocess.run(["bash", str(CLI), "monitor", "--subagent", "--role", "coder",
                        "--task-file", str(tf)],
                       capture_output=True, text=True, timeout=180, env=env)
    out = r.stdout + r.stderr
    assert r.returncode != 0, out[:300]
    assert "CODER_SCAFFOLD_MISSING" in out, out[:300]


# ── arm64：接线守门臂（闸在 cmd_monitor 内 + 只对 coder 生效）──────────────
def test_arm64_coder_gate_wired_and_scoped_to_coder():
    seg = _monitor_seg()
    assert "CODER_SCAFFOLD_MISSING" in seg
    assert "scaffold-status" in seg
    # 负向：闸须以显式角色判定为条件（不得对非 coder 角色生效）
    assert re.search(r'role_override"?\s*=\s*"coder"', seg), seg[:400]
