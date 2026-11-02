#!/usr/bin/env python3
"""§18.2 判据 c6 红先臂：技能自指 + `worktree_needed=false` 缺域须报 **high**（2026-10-04）。

缺陷（缺口①/②）：`gk_plan_lint.check_meta` 的 `state_domain` 机检门原**只**挂
`worktree_needed=true` 或 `target_repo` 指他仓 ⟹ 技能自指（`target_repo: skill`）+
`worktree_needed=false` 的子计划**不要求域** ⟹ 并发会话共享 base state（抢锁 +
多域台账分裂，实测交集仅 21/113），且级别仅 `medium` 非阻断。

修法：新增 `self_skill` 分支 —— 技能自指 + 非 wt + 缺域 ⟹ 报 **high**。

臂（HEAD 必红：无该 high finding）：
  · `self_skill_no_wt_missing_domain_is_high` 正臂
  · `declared_domain_no_finding` 零回归：已声明域 → 不产该 finding
  · `foreign_repo_missing_domain_is_medium` 对照：跨仓仍走原 medium（不误升 high）
"""
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_plan_lint as PL  # noqa: E402


def _doc(target_repo="skill", wt="false", domain=""):
    lines = ["<!-- META", "phases: R-X", "target_repo: %s" % target_repo,
             "project_type: skill", "worktree_needed: %s" % wt]
    if domain:
        lines.append("state_domain: %s" % domain)
    lines.append("-->")
    lines.append("# x")
    return "\n".join(lines) + "\n"


def _domain_findings(doc):
    fs = []
    PL.check_meta(doc, fs)
    return [f for f in fs if "state_domain" in f[2]]


def test_self_skill_no_wt_missing_domain_is_high():
    fs = _domain_findings(_doc("skill", "false"))
    assert fs and fs[0][1] == "high", fs


def test_declared_domain_no_finding():
    assert _domain_findings(_doc("skill", "false", "skill.foo")) == []


def test_foreign_repo_missing_domain_is_medium():
    fs = _domain_findings(_doc("other-repo", "false"))
    assert fs and fs[0][1] == "medium", fs
