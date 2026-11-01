#!/usr/bin/env python3
"""G4-c 红先臂：`plan-refinement --check-only` 前置面须含「三步分工」后两步的**门禁证据**。

来源：`docs/plans/2026-09-28-git-concurrency-lease-declare-plan.md` §1.3-G4c / §5 落刀点表。

**缺陷（实测，非推断）**：`cmd_plan_refinement` 的 preflight 自述检查四项
（计划存在 / META / 源文档 / **subagent 点检**），但 `missing[]` 只装前三项 ——
`subagent_history` 无点检实体、`human_calibration_log` 无密封记录时**照样 `missing: []`**
⟹ `--check-only` 是**假绿灯**（下游「进入相位前查前置」据此放行，而质询链其实未闭合）。

**修法判据（行为臂，真跑 CLI）**：
  ① 二者皆缺 ⟹ `missing` 含 `subagent_pointcheck` + `adjudicate_seal`，且 **不阻断**
     （`ok:true`）—— 对齐本仓「依赖不可用不得锁死序列」fail-soft 纪律；
  ② **阳性对照**：二者皆备 ⟹ `missing` **不含**这两项（防「恒报缺失」的假绿）；
  ③ **负臂**：`plan_doc` 缺失时仍**阻断**（新检查不得放松既有阻断面）。

⚠ 语义边界（如实登记）：`adjudicate_seal` 是**存在性**校验（`human_calibration_log` 内
是否有非空 `verdicts_json`/`decision` 的条目），**不做计划归属匹配** ——
`gk_adjudicate.py` 的 entry **不含**计划路径字段（实测 entry 键：timestamp/stage/
human_score/monitor_score/divergence/flag/verdicts_json/decision/…）⟹ 归属须人工核对，
preflight 只能给「有无密封」这一必要非充分信号。
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = SKILL_DIR / "gatekeeper-cli.sh"

_PLAN_BODY = """# 测试计划

<!-- META
target_repo: skill
worktree_needed: false
project_type: standing
phases: ECO-EDIT
state_domain: skill.test-g4c
-->

正文。
"""


def _wsl(p) -> str:
    """Windows 路径 → WSL 路径（`C:\\a\\b` → `/mnt/c/a/b`）。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _sandbox(root: Path, *, pointcheck: bool, seal: bool, with_plan: bool = True) -> Path:
    """最小沙箱：一个 `STATE_FILE` + 一份含 META 的计划文档。"""
    sb = root.resolve()
    sb.mkdir(parents=True, exist_ok=True)
    gd: dict = {}
    if pointcheck:
        gd["subagent_history"] = [{"task": "plan-refinement: 测试点检", "ts": "2026-09-30T00:00:00Z"}]
    if seal:
        gd["human_calibration_log"] = [{"timestamp": "2026-09-30T00:00:01Z",
                                        "verdicts_json": {"F1": "PASS"}, "decision": "PASS"}]
    (sb / ".gatekeeper.state").write_text(
        json.dumps({"stage": "ECO-EDIT", "r_phase": "R1", "gate_data": gd},
                   ensure_ascii=False), encoding="utf-8", newline="\n")
    if with_plan:
        (sb / "plan.md").write_text(_PLAN_BODY, encoding="utf-8", newline="\n")
    return sb


def _check_only(sb: Path, target: str = "plan.md", extra_env: dict | None = None):
    """真跑 CLI 的 `plan-refinement <target> --check-only`（纯只读 preflight）。"""
    w = _wsl(sb)
    env = {**os.environ, "STATE_FILE": f"{w}/.gatekeeper.state", "GK_PREFLIGHT_BALANCE": "0"}
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh plan-refinement "%s/%s" --check-only'
         % (_wsl(SKILL_DIR), w, target)],
        capture_output=True, text=True, timeout=180, env=env)


def _check_only_bare(sb: Path, name: str, extra_env: dict | None = None):
    """`--check-only` 但 target 传**裸名**（测「按名解析」路径；与 `_check_only` 的绝对路径形态区分）。"""
    w = _wsl(sb)
    env = {**os.environ, "STATE_FILE": f"{w}/.gatekeeper.state", "GK_PREFLIGHT_BALANCE": "0"}
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh plan-refinement "%s" --check-only'
         % (_wsl(SKILL_DIR), name)],
        capture_output=True, text=True, timeout=180, env=env)


def _preflight(out: str) -> dict:
    """取 CLI 末行 JSON 的 `preflight` 块（`plan_path`/`hint` 等）。"""
    d = json.loads(out.strip().splitlines()[-1])
    return d.get("preflight") or {}


def _missing(out: str) -> list:
    d = json.loads(out.strip().splitlines()[-1])
    return (d.get("preflight") or {}).get("missing") or []


def test_g4c_missing_surfaces_pointcheck_and_seal(tmp_path):
    """臂①（红先）：二者皆缺 ⟹ `missing` 须含两项，且**不阻断**（`ok:true`）。"""
    sb = _sandbox(tmp_path / "sb", pointcheck=False, seal=False)
    r = _check_only(sb)
    out = r.stdout + r.stderr
    assert '"ok":true' in out.replace(" ", ""), f"`--check-only` 未成功：{out[:400]}"
    m = _missing(out)
    assert "subagent_pointcheck" in m, (
        f"**假绿灯**：无 subagent 点检实体却未进 `missing`（missing={m}）")
    assert "adjudicate_seal" in m, (
        f"**假绿灯**：无 adjudicate 密封却未进 `missing`（missing={m}）")


def test_g4c_positive_control_no_false_missing(tmp_path):
    """臂②（阳性对照）：二者皆备 ⟹ `missing` 不得含这两项（防「恒报缺失」）。"""
    sb = _sandbox(tmp_path / "sb", pointcheck=True, seal=True)
    r = _check_only(sb)
    out = r.stdout + r.stderr
    m = _missing(out)
    assert "subagent_pointcheck" not in m, f"已有点检实体却仍报缺：{m}"
    assert "adjudicate_seal" not in m, f"已有密封记录却仍报缺：{m}"


def test_g4c_negative_plan_doc_still_blocks(tmp_path):
    """臂③（负臂）：`plan_doc` 缺失 ⟹ 仍**阻断**（新检查不得放松既有阻断面）。"""
    sb = _sandbox(tmp_path / "sb", pointcheck=True, seal=True, with_plan=False)
    r = _check_only(sb, target="nonexistent-plan.md")
    out = r.stdout + r.stderr
    assert "preflight blocked" in out, f"计划文档缺失竟未阻断：{out[:400]}"


# ── worktree 候选（2026-10-15，C 计划 §8 漂移）────────────────────────────────────
# 病根（实测）：`_plan_try` 候选仅 `$target` / `$SKILL_DIR/docs/plans/*` / `$MAIN_REPO_WSL/docs/plans/*`
#   ⟹ **未合并**、只存在于 linked worktree 的计划，从**主树**调 CLI 时恒空 ⟹ 同一条
#   `plan-refinement <名>` 随 cwd 分裂（主树 blocked / worktree 命中）= 安全网漂移。
# 修法：补 worktree 候选，单源 = `git worktree list`（测试经 `GK_PLAN_WORKTREE_ROOTS` 注入隔离根）。

def test_worktree_plan_resolves_by_name(tmp_path):
    """臂④（红先）：计划只在**非 SKILL_DIR 的 worktree** ⟹ 按**名字**须能解析（修前 blocked）。"""
    wtroot = tmp_path / "wtroot"
    (wtroot / "docs" / "plans").mkdir(parents=True)
    (wtroot / "docs" / "plans" / "zz-wt-plan.md").write_text(
        _PLAN_BODY, encoding="utf-8", newline="\n")
    sb = _sandbox(tmp_path / "sb", pointcheck=True, seal=True, with_plan=False)
    r = _check_only_bare(sb, "zz-wt-plan.md",
                         extra_env={"GK_PLAN_WORKTREE_ROOTS": _wsl(wtroot)})
    out = r.stdout + r.stderr
    pf = _preflight(out)
    assert pf.get("plan_path") == f"{_wsl(wtroot)}/docs/plans/zz-wt-plan.md", (
        f"worktree 候选未命中（plan_path={pf.get('plan_path')!r}）—— 漂移未修：{out[:400]}")


def test_worktree_candidates_listed(tmp_path):
    """臂⑤（红先）：`已试候选` 须含注入 worktree 根的 `.md` 形态（留痕可核）。"""
    wtroot = tmp_path / "wtroot"
    wtroot.mkdir()
    sb = _sandbox(tmp_path / "sb", pointcheck=True, seal=True, with_plan=False)
    r = _check_only_bare(sb, "zz-none.md",
                         extra_env={"GK_PLAN_WORKTREE_ROOTS": _wsl(wtroot)})
    hint = _preflight(r.stdout + r.stderr).get("hint", "")
    assert f"{_wsl(wtroot)}/docs/plans/zz-none.md" in hint, f"缺 worktree 候选：{hint[:400]}"


def test_worktree_negative_missing_still_blocks(tmp_path):
    """臂⑥（负臂）：worktree 根里**没有**该计划 ⟹ 仍阻断（候选放宽不得变「恒放行」）。"""
    wtroot = tmp_path / "wtroot"
    (wtroot / "docs" / "plans").mkdir(parents=True)
    sb = _sandbox(tmp_path / "sb", pointcheck=True, seal=True, with_plan=False)
    r = _check_only_bare(sb, "zz-absent.md",
                         extra_env={"GK_PLAN_WORKTREE_ROOTS": _wsl(wtroot)})
    out = r.stdout + r.stderr
    assert "preflight blocked" in out, f"计划确实不存在却未阻断：{out[:400]}"


# ── PW-SN 写侧机检接入 preflight（2026-10-29）─────────────────────────────────────
# 病史（实测）：`plan-lint` 自 2026-09-14 实装起**无任何调用点** —— hook 没有计划写门、
#   preflight 也不调它 ⟹ 质询可以对 high/medium 未清零的计划直接开跑（安全网被跳过）。
# 判据：① high ⟹ 阻断；② `GK_PLAN_LINT_GATE=0` ⟹ 放行且回包显式标 `plan_lint_skipped:true`。

# JSON 形态 META 不被 `_parse_meta` 识别（它读 `field: value` 行）⟹ L-META high，用作「机检必红」样本。
_LINT_DIRTY_BODY = """# 测试计划

<!-- META
{"plan_id": "test-lint-dirty", "project_type": "standing"}
-->

正文。
"""


def test_pw_sn_lint_high_blocks_preflight(tmp_path):
    """臂⑦（红先）：计划机检 high ⟹ preflight **阻断**（PW-SN 不得再被跳过）。"""
    sb = _sandbox(tmp_path / "sb", pointcheck=True, seal=True, with_plan=False)
    (sb / "plan.md").write_text(_LINT_DIRTY_BODY, encoding="utf-8", newline="\n")
    r = _check_only(sb)
    out = r.stdout + r.stderr
    assert r.returncode != 0, f"机检 high 竟放行：{out[:400]}"
    assert "plan_lint high/medium" in out, out[:400]
    assert '"plan_lint_skipped":false' in out.replace(" ", ""), out[:400]


def test_pw_sn_lint_kill_switch_reports_skipped(tmp_path):
    """臂⑧（逃生舱）：`GK_PLAN_LINT_GATE=0` ⟹ 放行，但回包必须显式标 skipped（不静默）。"""
    sb = _sandbox(tmp_path / "sb", pointcheck=True, seal=True, with_plan=False)
    (sb / "plan.md").write_text(_LINT_DIRTY_BODY, encoding="utf-8", newline="\n")
    r = _check_only(sb, extra_env={"GK_PLAN_LINT_GATE": "0"})
    out = r.stdout + r.stderr
    assert r.returncode == 0, f"逃生舱未生效：{out[:400]}"
    assert '"plan_lint_skipped":true' in out.replace(" ", ""), out[:400]

