#!/usr/bin/env python3
"""设计 D **行为臂（下批补齐）**：`cmd_apply_worktree` 两处**派发登记**的真 CLI 行为。

来源：`docs/plans/2026-09-28-git-concurrency-lease-declare-plan.md` §3（设计 D 登记点①/②）
+ §12 DRAFT-5「⚠ 已登记缺口：`cmd_apply_worktree` 两处登记的**行为臂**本批未加」。

**缺口**：本批（`78fdd13`）只落了 `gk_write_claims` 的**模块级** 8 臂 + `cmd_commit` 面的
真 CLI 臂（`test_gk_write_claims.py::test_arm8`）。而「派发成功 ⟹ 台账出现 `live` 行」这条
**接线判据**落在 bash 侧的两个调用点（`--session` / `--code-fix`），此前**无人守** ⟹
后续重构可静默删掉 `_gk_claim_register` 而全绿（登记面假绿 = 设计 D 的核心失效模式）。

**手法**（零 git 副作用）：
  · 沙箱技能根（`scripts` 软链真目录 + CLI 实拷 + 最小 state）—— 同 `test_gk_commit_guard._mk_skillroot`；
  · 桩 git-workflow（只实现 `worktree create <branch> --from HEAD --json` **契约**，用 `mkdir`
    造目录，**不**真跑 `git worktree add`）—— 故不触碰任何真仓的工作树列表；
  · `GATEKEEPER_WORKTREE_ROOT` 取**白名单内**的临时根（`gk_route_center.DEV_WORKTREE_ROOTS[0]`
    前缀，`apply_worktree` 的 root 白名单是硬校验，桩路径必须落在其中），用例结束即整目录清除。

**本文件钉住的判据**：
  ① `--session` 派发成功 ⟹ 台账增一条 `{sid=<会话名>, source=session, family=session,
     paths=[worktree], state=live}`；
  ② `--code-fix` 派发成功 ⟹ 台账增一条 `{sid=<finding>, source=dispatch, family=<族>,
     paths=族的 allowed_paths, state=live}`（**与 `_fam_json` 同源**，非第二份名单）；
  ③ **负臂**：派发**失败**（族判定失败）⟹ 台账**不增**该 sid 的行（禁「失败也登记」的假阳）。
"""
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_route_center as rc  # noqa: E402

CLI_SRC = SCRIPT_DIR.parent / "gatekeeper-cli.sh"
FAMILY = "F3b-edit-budget-accounting"

# 桩 git-workflow：**只**实现 `apply_worktree` 依赖的 `worktree create <branch> --from <ref> --json`
# 契约。刻意用 `mkdir` 而非 `git worktree add` ⟹ 本臂不产生真 git 工作树（零副作用）。
_STUB_GW = """#!/bin/bash
set -e
[ "$1" = "worktree" ] && [ "$2" = "create" ] || { echo '{"ok":false}'; exit 2; }
shift 2
b=""
while [ $# -gt 0 ]; do
  case "$1" in
    --from) shift 2 ;;
    --json) shift ;;
    *) [ -z "$b" ] && b="$1"; shift ;;
  esac
done
[ -z "$b" ] && { echo '{"ok":false}'; exit 2; }
root="${GIT_WORKFLOW_WORKTREE_ROOT:-/tmp/gk-e2e-fallback}"
wt="$root/e2e/$b"
mkdir -p "$wt"
printf '{"ok":true,"worktree":"%s","branch":"%s","created":true,"reused":false}\\n' "$wt" "$b"
"""


def _wsl(p) -> str:
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _sh(cmd: str, timeout: int = 180, env=None):
    return subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True,
                          timeout=timeout, env=env)


def _wt_root_base() -> str:
    """`DEV_WORKTREE_ROOTS` 中本机可写的那个（派生自**单源常量**，禁另抄字面量）。"""
    for r in rc.DEV_WORKTREE_ROOTS:
        if r.startswith("/mnt/"):
            return r
    raise AssertionError("DEV_WORKTREE_ROOTS 无可用的 /mnt 根")


def _mk_skillroot(tmp_path: Path) -> Path:
    """沙箱技能根（目录名 = 技能名，过 `_skill_dir_trusted` 的名字校验）。"""
    sb = (tmp_path / "spz-gatekeeper-r-sequence").resolve()
    sb.mkdir()
    # `references` 软链是必需项：`gk_agent_family.DEFAULT_FAMILIES_DIR` 由 `__file__` 的
    #   `abspath` 派生（**不** resolve 软链）⟹ 沙箱缺 `references/agent-families` 时
    #   `resolve` 报「族定义不存在」（实测）。
    r = _sh('ln -s "%s" "%s/scripts" && ln -s "%s" "%s/references" && cp "%s" "%s/gatekeeper-cli.sh"'
            % (_wsl(SCRIPT_DIR), _wsl(sb), _wsl(SCRIPT_DIR.parent / "references"), _wsl(sb),
               _wsl(CLI_SRC), _wsl(sb)))
    assert r.returncode == 0, f"沙箱搭建失败：{r.stdout}{r.stderr}"
    (sb / ".gatekeeper.state").write_text(
        '{"stage":"STAGE_0","r_phase":"R1","worktree":"",'
        '"gate_data":{"project_type":"standing","edit_budget":{"max":20,"remaining":20},'
        '"ecc_findings":[]}}',
        encoding="utf-8", newline="\n")
    return sb


def _cli(sb: Path, args, env: dict, timeout: int = 180):
    return _sh('cd "%s" && bash gatekeeper-cli.sh %s' % (_wsl(sb), " ".join(args)),
               timeout=timeout, env=env)


def _last_json(out: str) -> dict:
    lines = [ln for ln in out.strip().splitlines() if ln.startswith("{")]
    assert lines, f"未回 JSON：{out[:500]}"
    return json.loads(lines[-1])


def _ledger(sb: Path) -> list:
    p = sb / ".gatekeeper.write-claims.jsonl"
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def _env(sb: Path, tmp_path: Path, root: str) -> dict:
    """干净 env：显式清掉 `GK_WRITE_CLAIMS_PATH`（否则测的是覆盖路径而非**默认落点**）。"""
    e = {k: v for k, v in os.environ.items()
         if k not in ("GK_WRITE_CLAIMS_PATH", "GK_WRITE_CLAIM_WARN")}
    e.update({
        "GATEKEEPER_WORKTREE_ROOT": root,
        "GIT_WORKFLOW_WORKTREE_ROOT": root,
        "GK_GIT_WORKFLOW_ENTRY": str(tmp_path / "stub-git-workflow.sh"),
        "GK_BUDGET_OVERRIDE": "1",
    })
    return e


def _fixture(tmp_path: Path):
    """(sandbox, env) —— 含白名单内临时根 + 桩入口；调用方负责 `_cleanup`。"""
    sb = _mk_skillroot(tmp_path)
    root = os.path.join(_wt_root_base(), "gk-e2e-%d-%s" % (os.getpid(), uuid.uuid4().hex[:8]))
    os.makedirs(root, exist_ok=True)
    stub = tmp_path / "stub-git-workflow.sh"
    stub.write_text(_STUB_GW, encoding="utf-8")
    os.chmod(str(stub), 0o755)
    return sb, root, _env(sb, tmp_path, root)


def _cleanup(root: str):
    shutil.rmtree(root, ignore_errors=True)


# ── 臂① `--session` 派发成功 ⟹ 台账出现 live 行（登记点①）──────────────────
def test_arm1_session_dispatch_records_live_claim(tmp_path):
    sb, root, env = _fixture(tmp_path)
    try:
        st = str(sb / ".gatekeeper.state")
        r = _cli(sb, ["apply-worktree", "--session", "e2e1", "--state", st], env)
        obj = _last_json(r.stdout)
        assert obj.get("ok") is True, f"--session 派发失败：{r.stdout[-400:]}{r.stderr[-400:]}"
        recs = _ledger(sb)
        hit = [x for x in recs if x.get("sid") == "e2e1"]
        assert hit, f"会话派发成功但台账**未登记**（登记点①漏接线）：{recs}"
        x = hit[-1]
        assert x.get("state") == "live", x
        assert x.get("source") == "session" and x.get("family") == "session", x
        assert x.get("paths") == [obj["worktree"]], (
            f"claim.paths 与该 worktree 不同源：{x.get('paths')} vs {obj.get('worktree')}")
        assert x.get("worktree") == obj["worktree"], x
    finally:
        _cleanup(root)


# ── 臂② `--code-fix` 派发成功 ⟹ 台账 live 行（登记点②，paths = 族 allowed_paths）──
def test_arm2_codefix_dispatch_records_live_claim(tmp_path):
    sb, root, env = _fixture(tmp_path)
    try:
        st = sb / ".gatekeeper.state"
        st.write_text(json.dumps({
            "stage": "STAGE_0", "r_phase": "R1", "worktree": "",
            "gate_data": {"project_type": "standing",
                          "edit_budget": {"max": 20, "remaining": 20},
                          "ecc_findings": [{"id": "ECC-TESTFIX",
                                            "title": "edit_budget 计费口径",
                                            "description": "计费口径 edit_budget"}]},
        }, ensure_ascii=False), encoding="utf-8", newline="\n")
        r = _cli(sb, ["apply-worktree", "--code-fix", "--finding", "ECC-TESTFIX",
                      "--family", FAMILY, "--state", str(st)], env)
        obj = _last_json(r.stdout)
        assert obj.get("ok") is True, f"--code-fix 派发失败：{r.stdout[-400:]}{r.stderr[-400:]}"
        recs = _ledger(sb)
        hit = [x for x in recs if x.get("sid") == "ECC-TESTFIX"]
        assert hit, f"coder 派发成功但台账**未登记**（登记点②漏接线）：{recs}"
        x = hit[-1]
        assert x.get("state") == "live", x
        assert x.get("source") == "dispatch" and x.get("family") == FAMILY, x
        # paths 与**族定义**同源（`_fam_json.allowed_paths`），非第二份名单
        fam = json.loads((SCRIPT_DIR / ".." / "references" / "agent-families"
                          / (FAMILY + ".json")).resolve().read_text(encoding="utf-8"))
        assert sorted(x.get("paths") or []) == sorted(fam.get("allowed_paths") or []), (
            f"claim.paths 与族 allowed_paths 不同源：{x.get('paths')} vs {fam.get('allowed_paths')}")
    finally:
        _cleanup(root)


# ── 臂③ 负臂：派发**失败**⟹ 不得登记（禁「失败也登记」假阳）──────────────────
def test_arm3_failed_dispatch_records_no_claim(tmp_path):
    sb, root, env = _fixture(tmp_path)
    try:
        st = str(sb / ".gatekeeper.state")
        r = _cli(sb, ["apply-worktree", "--code-fix", "--finding", "ECC-NOSUCH",
                      "--family", FAMILY, "--state", st], env)
        obj = _last_json(r.stdout)
        assert obj.get("ok") is False, f"未知 finding 竟派发成功：{r.stdout[-300:]}"
        recs = _ledger(sb)
        assert not [x for x in recs if x.get("sid") == "ECC-NOSUCH"], (
            f"派发失败却登记了 claim（假阳）：{recs}")
    finally:
        _cleanup(root)


# ── 臂④（设计 A · 端到端）该 finding 的**红先臂文件**须进回包与台账（三面同源）──
def test_arm4_dispatch_carries_finding_arm_file(tmp_path):
    """真 CLI：派发一个**已登记**的 finding（其臂文件不在族 `allowed_paths` 里）⟹
    回包 `allowed_paths` 与台账 claim 的 `paths` **都**须含该臂文件（与窄任务串同源）。"""
    from gk_red_arm_gen import finding_test_file
    arm = finding_test_file("ECC-F6C94D444CC6")
    assert arm == "scripts/test_gk_edit_budget_metering.py", f"取数源变了：{arm}"
    sb, root, env = _fixture(tmp_path)
    try:
        st = sb / ".gatekeeper.state"
        st.write_text(json.dumps({
            "stage": "STAGE_0", "r_phase": "R1", "worktree": "",
            "gate_data": {"project_type": "standing",
                          "edit_budget": {"max": 20, "remaining": 20},
                          "ecc_findings": [{"id": "ECC-F6C94D444CC6",
                                            "title": "编辑预算按会话隔离",
                                            "description": "计费口径 edit_budget"}]},
        }, ensure_ascii=False), encoding="utf-8", newline="\n")
        r = _cli(sb, ["apply-worktree", "--code-fix", "--finding", "ECC-F6C94D444CC6",
                      "--family", FAMILY, "--state", str(st)], env)
        obj = _last_json(r.stdout)
        assert obj.get("ok") is True, f"派发失败：{r.stdout[-400:]}{r.stderr[-400:]}"
        assert arm in (obj.get("allowed_paths") or []), (
            f"设计 A 未把该 finding 的红先臂文件带进回包：{obj.get('allowed_paths')}")
        hit = [x for x in _ledger(sb) if x.get("sid") == "ECC-F6C94D444CC6"]
        assert hit, "台账未登记"
        assert arm in (hit[-1].get("paths") or []), (
            f"台账 claim 未带该臂文件（回包/窄任务/台账三面不同源）：{hit[-1].get('paths')}")
    finally:
        _cleanup(root)
