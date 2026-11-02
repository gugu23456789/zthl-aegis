"""F7 基座：worktree 申请—分发（red-first）。真 git 仓 + 临时 root。"""
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_route_center as rc


def _git(repo, *a):
    return subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)


_STUB_GW = """#!/bin/bash
# 单测桩：只实现 `apply_worktree` 依赖的 `worktree create <branch> --from <ref> --json` 契约
# （含幂等复用）。**真** git-workflow 的等价行为由功能实测覆盖：
# `--from/--json` 新建、幂等 `reused:true`、非法名 rc=2、`--from` 不存在 rc=1、无 `--from` rc=1。
set -e
[ "$1" = "worktree" ] && [ "$2" = "create" ] || { echo '{"ok":false}'; exit 2; }
shift 2
b=""; f=""; j=0
while [ $# -gt 0 ]; do
  case "$1" in
    --from) f="$2"; shift 2 ;;
    --json) j=1; shift ;;
    *) [ -z "$b" ] && b="$1"; shift ;;
  esac
done
[ -z "$b" ] && { echo '{"ok":false}'; exit 2; }
root="${GIT_WORKFLOW_WORKTREE_ROOT:-$HOME/.config/superpowers/worktrees}"
repo=$(basename "$(git rev-parse --show-toplevel)")
wt="$root/$repo/$b"
if [ -d "$wt" ]; then
  printf '{"ok":true,"worktree":"%s","branch":"%s","created":false,"reused":true}\\n' "$wt" "$b"
  exit 0
fi
mkdir -p "$(dirname "$wt")"
git worktree add -b "$b" "$wt" "$f" >/dev/null 2>&1
printf '{"ok":true,"worktree":"%s","branch":"%s","created":true,"reused":false}\\n' "$wt" "$b"
"""


@pytest.fixture()
def origin(tmp_path, monkeypatch):
    repo = tmp_path / "origin"
    repo.mkdir()
    _git(str(repo), "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("x", encoding="utf-8")
    _git(str(repo), "add", "a.txt")
    _git(str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    root = tmp_path / "wts"
    root.mkdir()
    monkeypatch.setenv("GATEKEEPER_WORKTREE_ROOT", str(root))
    # 2026-09-23（ECC-A91DC4562198 收编）：创建已委托 git-workflow ⟹ 其根须显式注入
    # （git-workflow 的 root 语义 = **不含 repo 段**的公共根：<root>/<repo>/<branch>）。
    monkeypatch.setenv("GIT_WORKFLOW_WORKTREE_ROOT", str(root))
    # 入口缝合：单测在 worktree 内导入本模块，`DEFAULT_SKILL` 指向该 worktree ⟹ 兄弟技能不可得；
    # 生产路径经 CLI 调用（`__file__` = 真 SKILL_DIR）自然可解析。此处用桩替代真入口。
    stub = tmp_path / "stub-git-workflow.sh"
    stub.write_text(_STUB_GW, encoding="utf-8")
    stub.chmod(0o755)
    monkeypatch.setenv("GK_GIT_WORKFLOW_ENTRY", str(stub))
    monkeypatch.setattr(rc, "DEV_WORKTREE_ROOTS", [str(root)], raising=False)
    return str(repo), str(root)


def _seg():
    """`apply_worktree` 函数源码段（供机检臂断言落刀形态）。"""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "gk_route_center.py"), encoding="utf-8").read()
    rest = src[src.index("def apply_worktree("):]
    end = rest.index("\ndef ", 1)
    return rest[:end]


def test_apply_worktree_delegates_to_git_workflow():
    """C3 收编（ECC-A91DC4562198）：`apply_worktree` 必须**委托** git-workflow，禁裸 `git worktree add`。

    红先对照：HEAD 版源码含裸调用 `\"worktree\", \"add\"`（`git show HEAD:scripts/gk_route_center.py |
    grep -c '"worktree", "add"'` → 1）⟹ 本臂在 HEAD 上必红。
    """
    s = _seg()
    assert '"worktree", "add"' not in s and "'worktree', 'add'" not in s, \
        "apply_worktree 仍裸调 git worktree add ⟹ 第二套 worktree 机制未撤"
    assert 'worktree", "create"' in s or "worktree\", \"create\"" in s, \
        "apply_worktree 未委托 git-workflow worktree create"
    assert "_git_workflow_entry" in s, "入口未从 manifest 派生（禁硬编码）"


def test_apply_worktree_keeps_own_whitelist_checks():
    """负臂：白名单 / `..` 段拒绝 / family token 正则**留在门禁侧**（不下放 git-workflow）。"""
    s = _seg()
    assert "_FAMILY_RE" in s, "family token 正则被下放（安全防线降级）"
    assert "DEV_WORKTREE_ROOTS" in s and ".." in s, "白名单/`..` 段拒绝被下放（安全防线降级）"


def test_apply_worktree_creates_branch_and_dir(origin):
    repo, root = origin
    out = rc.apply_worktree(repo, "ECC-DEADBEEF", "F3-state-write-integrity")
    assert out["ok"] is True
    assert out["created"] is True
    assert os.path.isdir(out["worktree"])
    assert _git(out["worktree"], "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == out["branch"]


def test_apply_worktree_same_finding_reuses(origin):
    repo, root = origin
    a = rc.apply_worktree(repo, "ECC-DEADBEEF", "F3-state-write-integrity")
    b = rc.apply_worktree(repo, "ECC-DEADBEEF", "F3-state-write-integrity")
    assert b["ok"] is True and b["reused"] is True
    assert a["worktree"] == b["worktree"]


def test_apply_worktree_rejects_path_traversal_family(origin):
    repo, root = origin
    with pytest.raises(rc.RouteError):
        rc.apply_worktree(repo, "ECC-DEADBEEF", "../evil")


# ── ECC-DEBCB4AC53C3（2026-09-23 用户裁定「登记成 finding 然后立刻修」）──────────────
# 病灶：从 **worktree 内**调用 `apply-worktree` 时两处同源误算 —— ① `_git_workflow_entry`
# 用 `DEFAULT_SKILL.parent` 当同级插件根（worktree 下不是部署根 `.trae/skills`）⟹ 报
# `git-workflow 入口不可得`；② git-workflow 以**调用方 cwd 的目录名**当仓库段 ⟹ 落
# `…/worktrees/<当前 worktree 目录名>/…`（真机实测：`--session` 从 feature worktree 跑出
# `…/worktrees/spz-gatekeeper-agent-worktree-consolidation/agent/session/<sha8>`）。
# 正解 = 该仓的**主 worktree**（`git worktree list --porcelain` 首条，权威视图）。

def test_apply_worktree_from_inside_worktree_uses_main_repo(origin, tmp_path):
    """臂（红先 · 行为）：从 worktree 内调用，仓库段必须取**主 worktree** 名。"""
    repo, root = origin
    nested = tmp_path / "nested-wt"
    _git(repo, "worktree", "add", "-b", "feat-x", str(nested))
    assert os.path.isdir(str(nested)), "夹具未建成嵌套 worktree"
    out = rc.apply_worktree(str(nested), "ECC-DEADBEEF", "F3-state-write-integrity")
    assert out["ok"] is True
    assert out["worktree"].startswith(root + "/origin/"), (
        "仓库段取成了**调用方 worktree 的目录名** ⟹ 落错平面路径：%s" % out["worktree"])


def test_git_workflow_entry_falls_back_to_main_worktree():
    """臂（形态）：入口基址候选须含「主 worktree」回退，否则 worktree 内调用恒解析失败。"""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "gk_route_center.py"), encoding="utf-8").read()
    seg = src[src.index("def _git_workflow_entry("):]
    seg = seg[:seg.index("\ndef ", 1)]
    assert "_main_worktree(" in seg, (
        "入口未用「主 worktree」回退 ⟹ 在 worktree 内调用 apply-worktree 恒报入口不可得")


# ── 计划驱动建树（2026-10-28，owner「把手动绕路的方式堵上」）────────────────────────
# 缺口：`discover --plan` 只**探测**已有树；`apply-worktree` 只有 finding / code-fix / bind
# ⟹ 计划建树无正路 ⟹ agent 手搓 `git worktree add` + `cp`。本组钉住新入口的**命名约定**
# （`feature/<plan-stem>`，discover 的 `<root>/<repo>/feature/<basename(branch)>` 才认得出）
# 与 META 门（`worktree_needed=false` 具名拒建）。

def _write_plan(repo, name, worktree_needed="true"):
    d = os.path.join(repo, "docs", "plans")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write("<!-- META\nphases: DEMO\ntarget_repo: gatekeeper\nproject_type: standard\n"
                f"worktree_needed: {worktree_needed}\nstate_domain: gatekeeper.demo\n-->\n\n# demo\n")
    return p


def test_apply_worktree_plan_uses_feature_branch_convention(origin):
    repo, root = origin
    plan = _write_plan(repo, "2026-10-28-demo-plan.md")
    out = rc.apply_worktree_plan(repo, plan)
    assert out["ok"] is True
    assert out["branch"] == "feature/2026-10-28-demo-plan", out
    assert out["worktree"].endswith("/feature/2026-10-28-demo-plan"), (
        "目录不符 `resolve_worktree` 的 <root>/<repo>/feature/<basename(branch)> 约定 ⟹ "
        "discover 认不回该树（写面不登记）：%s" % out["worktree"])
    assert os.path.isdir(out["worktree"])
    assert _git(out["worktree"], "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == out["branch"]


def test_apply_worktree_plan_is_idempotent(origin):
    repo, root = origin
    plan = _write_plan(repo, "2026-10-28-demo-plan.md")
    a = rc.apply_worktree_plan(repo, plan)
    b = rc.apply_worktree_plan(repo, plan)
    assert b["reused"] is True and a["worktree"] == b["worktree"]


def test_apply_worktree_plan_refuses_when_meta_says_no(origin):
    repo, root = origin
    plan = _write_plan(repo, "2026-10-28-noplan.md", worktree_needed="false")
    with pytest.raises(rc.RouteError):
        rc.apply_worktree_plan(repo, plan)


def test_apply_worktree_plan_dry_run_creates_nothing(origin):
    repo, root = origin
    plan = _write_plan(repo, "2026-10-28-demo-plan.md")
    out = rc.apply_worktree_plan(repo, plan, dry_run=True)
    assert out["dry_run"] is True and out["worktree"] == ""
    assert not os.path.isdir(os.path.join(root, "origin", "feature", "2026-10-28-demo-plan"))
