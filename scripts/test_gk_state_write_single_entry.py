#!/usr/bin/env python3
"""F3a 子族端到端红先臂集（`ECC-9F21304266C5` / `ECC-3FE14977FC55`）+ 全局单调守卫。

设计依据：`docs/plans/2026-09-22-coding-agent-slice-design.md` §8（F3 首切片）+ 实施计划 T10 Step 1。

**2026-09-23 族拆分**（用户裁定）：原 F3 单一族拆为两个**互补**子族 ——
  · `F3a-state-write-convergence`（直写收敛）= `ECC-9F21304266C5` + `ECC-3FE14977FC55`（本文件）
  · `F3b-edit-budget-accounting`（计费口径）= `ECC-1E6BFDD7A207`（臂已移至
    `scripts/test_gk_edit_budget_accounting.py`，两族**文件级互斥**）
  · `ECC-81B0861B3349`（F-REV-7 内联解析重复 + checksum 同文件存储，**读侧**）
    ⟹ 两族均**不受理**（无族命中即 fail-loud）；归 R18 / 全面收敛面，待第三族。

三臂（**红先**：修前必红；红先名单存档到设计文档 §R25）：
  ① `ECC-9F21304266C5`（F3a 行为臂）：`_log_block()` 落盘后 `_checksum` 必须等于按 `gate_data`
     重算的 canon。修前 `_log_block` 用内联 `json.dump` 直写 state 且**不重算 checksum**
     ⟹ 任何 block 记录落盘后 checksum 恒失配（本臂即该主张的机器判据）。
  ② 全局单调守卫（**不隶属任何族**）：CLI 内联 state `json.load(` 站点数 ≤ 实测基线 41
     —— 「30+ 内联解析」不再恶化的防回退臂（其对应 finding `ECC-81B0861B3349` 归 R18）。
  ③ `ECC-3FE14977FC55`（F3a 收敛臂）：CLI 内联 state `json.dump(` 直写站点数 ≤ 12。修前实测 13；
     多写者各自序列化 = 「同一内容产出 328109/262906/249562 B」的根因。本切片只收敛
     `_log_block` 一处，余下 12 处属 R18 / 全面收敛面（**非本切片范围**）⟹ 判据取 12 而非 1。

沙箱：`scripts` 软链 + CLI 实拷 + 最小 state（**不触真实 `.gatekeeper.state`**）。
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = SKILL_DIR / "gatekeeper-cli.sh"

# 实测基线（2026-09-23）：`re.findall(r"json[.]load[(][^)]*STATE_FILE", txt)` / 同 dump
# 2026-09-23 第三族切片（`ECC-792E2215ABC4` / 原 `ECC-81B0861B3349`，R18 读侧）：
#   实测 40 处 ⟹ 本切片收敛目标 = 38（至少收敛 2 处）。⚠ 常数下调即**红先**：
#   收敛落刀前臂②必红（40 > 38）；落刀后转绿。回退保护不变（> 38 即报）。
_STATE_LOAD_BASELINE = 38
_STATE_DUMP_SITES_BEFORE_F3 = 13
_STATE_DUMP_SITES_TARGET = 12


def _wsl(p) -> str:
    """Windows 路径 → WSL 路径（`C:\\a\\b` → `/mnt/c/a/b`）。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _canon(state: dict) -> str:
    """CLI 单一事实源的 canon：`sha256(json.dumps(gate_data, sort_keys=True))[:16]`。"""
    gd = json.dumps(state.get("gate_data", {}), sort_keys=True)
    return hashlib.sha256(gd.encode()).hexdigest()[:16]


def _cli_text() -> str:
    return CLI_SRC.read_text(encoding="utf-8", errors="replace")


def _sandbox(root: Path, stage: str) -> Path:
    """最小技能根 + 指定 stage 的合法 checksum state（stage=IDLE ⟹ `_log_block` 可触发）。"""
    sb = (root / "sb").resolve()
    sb.mkdir(parents=True)
    w = _wsl(sb)
    r = subprocess.run(
        ["bash", "-lc", 'ln -s "%s" "%s/scripts" && cp "%s" "%s/gatekeeper-cli.sh"'
         % (_wsl(SCRIPT_DIR), w, _wsl(CLI_SRC), w)],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, f"沙箱搭建失败：{r.stdout}{r.stderr}"
    state = {
        "stage": stage, "r_phase": "R1", "branch": "master", "worktree": "",
        "gate_data": {
            "project_type": "standing",
            "edit_budget": {"max": 4, "used": 0, "remaining": 4, "overrides": []},
            "scheduler": {"mode": "constant", "max_lr": 4, "min_lr": 1,
                          "total_steps": 6, "current_step": 1, "current_lr": 4},
        },
    }
    # 播种即写入**合法** checksum ⟹ 本臂只测「写者是否维持它」，不测初始合法性。
    state["_checksum"] = _canon(state)
    (sb / ".gatekeeper.state").write_text(
        json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")
    return sb


def _cli_run(sb: Path, *args: str):
    w = _wsl(sb)
    argv = " ".join('"%s"' % a for a in args)
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh %s' % (w, argv)],
        capture_output=True, text=True, timeout=120)


def _cli_run_no_bill(sb: Path, *args: str):
    """同上，但带 `GK_BUDGET_OVERRIDE=1`（**显式人工放行**逃生舱）：该舱令 boot 期 `_bill_edit`
    提前 `return 0` ⟹ **不写 state** ⟹ 本次调用只剩被观测的 `_state_checksum_write` 一个潜在写者。

    为什么必须这样跑「未改动」臂：`_CMD_REG[finding]` 的 side_effects = `state_write` ⟹ boot 期
    恒定 `_bill_edit "$cmd"` → `_state_write`（**总会写** state，即使 `remaining<1`）⟹ 默认路径下
    `_state_checksum_write` 面对的永远是「本次已写过」的 state，其「未改动」分支不可达。逃生舱
    是**受支持的人工模式**（`_bill_edit` 首行判据）⟹ 用它跑才真正落在被观测判据上。
    """
    w = _wsl(sb)
    argv = " ".join('"%s"' % a for a in args)
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && GK_BUDGET_OVERRIDE=1 bash gatekeeper-cli.sh %s' % (w, argv)],
        capture_output=True, text=True, timeout=120)


@pytest.fixture()
def idle_sandbox():
    if shutil.which("bash") is None:
        pytest.skip("本机无 bash（Windows 语义下无法执行 CLI）")
    root = Path(tempfile.mkdtemp(prefix="gk_f3_"))
    try:
        yield _sandbox(root, "IDLE")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_log_block_write_recomputes_checksum(idle_sandbox):
    """① `ECC-9F21304266C5`：block 记录落盘后 `_checksum` 必须等于按 gate_data 重算的 canon。"""
    st = idle_sandbox / ".gatekeeper.state"
    # stage=IDLE ⟹ pre_tool_check 走 `_log_block "pre-tool-check" "stage=$stage"` 后 BLOCK
    _cli_run(idle_sandbox, "pre-tool-check", "Write", _wsl(idle_sandbox / "gatekeeper-cli.sh"))
    d = json.loads(st.read_text(encoding="utf-8"))
    assert d.get("gate_data", {}).get("block_log"), "block_log 未落盘 ⟹ 本臂前提不成立（_log_block 未触发）"
    assert d.get("_checksum") == _canon(d), (
        "block 记录落盘后 checksum 失配（应等于按 gate_data 重算的 canon）："
        f"stored={d.get('_checksum')} canon={_canon(d)}")


def _inline_sites(pattern: str) -> int:
    """数 CLI 内联 state 读写**代码站点**（**逐行跳过注释行**）。

    2026-09-23 实测判据缺陷（`ECC-3FE14977FC55` 臂首版**误报**）：原实现
    `re.findall(r"json[.]dump[(][^)]*STATE_FILE", txt)` 会把**注释文本**计入 ——
    F3a 的修复注释里写 `` `json.dump(open($STATE_FILE,'w'))` ``（反引号引用原文），
    于是「删 1 处真站点 + 注释多 1 处匹配」净持平（13 → 13）而被误判「未收敛」。
    判据意图是「直写**站点**」⟹ 逐行扫描，跳过首个非空白字符为 `#` 的注释行；
    其余行保持原语义（可出现在行内任意位置，如 `s=json.load(...)`）计数。
    `^\\s*` 锚定是**错误**的替代方案（会把行内站点 `s=json.load(...)` 一并漏掉 ⟹
    臂②恒为 0 而「真空通过」）。
    """
    rx = re.compile(pattern)
    return sum(len(rx.findall(ln)) for ln in _cli_text().splitlines()
               if not ln.lstrip().startswith("#"))


def test_state_inline_load_sites_not_regressed():
    """② `ECC-81B0861B3349`：CLI 内联 state `json.load(` 站点数 ≤ 实测基线（收敛不回退）。"""
    n = _inline_sites(r"json[.]load[(][^)]*STATE_FILE")
    assert n <= _STATE_LOAD_BASELINE, (
        f"内联 state json.load 站点增至 {n}（基线 {_STATE_LOAD_BASELINE}）⟹ 收敛回退")


def test_state_inline_dump_sites_converged():
    """③ `ECC-3FE14977FC55`：CLI 内联 state `json.dump(` 直写站点数须收敛 ≤ 12（修前 13）。"""
    n = _inline_sites(r"json[.]dump[(][^)]*STATE_FILE")
    assert n <= _STATE_DUMP_SITES_TARGET, (
        f"内联 state 直写站点 {n}（修前 {_STATE_DUMP_SITES_BEFORE_F3}，目标 ≤ {_STATE_DUMP_SITES_TARGET}）"
        " —— 多写者各自序列化 =「同一内容产出不同字节」（328109/262906/249562 B）的根因；"
        "本切片收敛 `_log_block` 一处，余下 12 处属 R18/全面收敛面")


# ④ `ECC-1E6BFDD7A207`（计费口径）已随 2026-09-23 族拆分**移出本文件** ——
# 现属子族 `F3b-edit-budget-accounting`，臂落 `scripts/test_gk_edit_budget_accounting.py`
# （两族文件级互斥：本文件被 F3b 的 forbidden_paths 屏蔽，反之亦然）。


# ── ③ 收尾 checksum **不清洗未改动的 state**（`ECC-F0F0999A3970` 区外等价加固，2026-09-26）──
# 病象：`_state_checksum_write` 原为**无条件**重算 ⟹ 调用方**根本没改动**该 state 时（如
#   `cmd_finding` 带 `--domain`：python 只写域化 state，默认 state 一个字节没动）重算等价 no-op；
#   但若默认 state **已被篡改**，重算会把 `_checksum` 改成与篡改内容相符的值 = **洗白**
#   （完整性旁路）。正常调用点在 PROTECTED_REGION::gate 内 ⟹ 走**区外等价加固**（不改 `cmd_finding`）。
# 判据 = 「本次 CLI 调用是否改动过该 state」（文件 mtime vs 本进程已运行秒数反推的调用起点）。
_WRONG = "deadbeefdeadbeef"


def _tamper_checksum(sb: Path, age: float = 3600.0) -> Path:
    """把沙箱 state 的 `_checksum` 改成错值，并把 mtime 拨到 `age` 秒前（模拟「本次调用前就已篡改」）。"""
    st = sb / ".gatekeeper.state"
    d = json.loads(st.read_text(encoding="utf-8"))
    d["_checksum"] = _WRONG
    st.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")
    t = time.time() - age
    os.utime(st, (t, t))
    return st


def test_arm65_checksum_write_refuses_to_wash_untouched_state(tmp_path):
    """未改动却失配 = 篡改 ⟹ **拒写**（不洗白）。修前：无条件重算 ⟹ 篡改被改成自洽值。"""
    if shutil.which("bash") is None:
        pytest.skip("本机无 bash（Windows 语义下无法执行 CLI）")
    sb = _sandbox(tmp_path, "IDLE")
    st = _tamper_checksum(sb)
    # `finding verify <未知 id>`：python 侧 `KeyError` **不写 state**，但 CLI 收尾仍调
    # `_state_checksum_write`（`case register|close|verify`）；`GK_BUDGET_OVERRIDE=1` 令 boot 期
    # `_bill_edit` 不写 ⟹ 正是「未改动 + 失配」通路。
    _cli_run_no_bill(sb, "finding", "verify", "ECC-DOESNOTEXIST", "false")
    d = json.loads(st.read_text(encoding="utf-8"))
    assert d.get("_checksum") == _WRONG, (
        "本次调用未改动该 state 却把篡改 checksum 重算成自洽值 ⟹ 洗白（完整性旁路未闭）："
        f"stored={d.get('_checksum')} canon={_canon(d)}")


def test_arm66_checksum_write_still_normalizes_fresh_state(tmp_path):
    """负臂（守「直写后补算」通路 + 守 **mtime 秒级粒度容差**）：本次调用**改动过**的 state
    照旧重算（零回归）。`age=0` 即「刚写过」——实现须留 ≥1s 容差，否则紧贴调用起点的样本会被
    误拒（误拒会留下陈旧 `_checksum`，比放过更糟）。"""
    if shutil.which("bash") is None:
        pytest.skip("本机无 bash（Windows 语义下无法执行 CLI）")
    sb = _sandbox(tmp_path, "IDLE")
    st = _tamper_checksum(sb, age=0.0)
    _cli_run_no_bill(sb, "finding", "verify", "ECC-DOESNOTEXIST", "false")
    d = json.loads(st.read_text(encoding="utf-8"))
    assert d.get("_checksum") == _canon(d), (
        "新鲜（本次调用时间窗内）的 state 未被重算 ⟹ 合法「直写后补算」通路退化")

