#!/usr/bin/env python3
"""R5 红先：审查节点判据的**键**与**单源**（2026-09-21）。

缺陷（CLI 端到端**实测**，非推断）：判据原按 `gate_data.project_type` 分支，而该键是**活动
计划的 META 声明**（单源 = `gk_route_center._META_FIELDS`），随活动计划切换而翻转 —— 0913
家族 META=standing，本会话 hook 计划 META=analysis。实测 arm1：

    stage=ECO-AUDIT + project_type=analysis → rc=1, CROSSREVIEW_NODE_BINDING
    expected: "STAGE_3 (standard) 或 AUDIT-CROSSR"

⟹ **即便把常驻序列推进到审查节点 ECO-AUDIT，仍被拦** ⟹ 正规路径被系统性堵死，逼出两条
旁路：`audit --crossfull --isolate` 把副本 state 的 stage 改写成 `AUDIT-CROSSR`（**自证式**
满足），或 `GK_DEGRADE_REVIEW=1` 降级。

五臂（`(stage, r_phase, project_type)` → 期望放行）：
  1 正臂 ("ECO-AUDIT",   "ECO-SCAN", "analysis") → True   （**修前 False = 必红**）
  2 负臂 ("ECO-EDIT",    "ECO-SCAN", "analysis") → False  （政策不变：非审查节点仍拦）
  3 回归 ("STAGE_3",     "",         "standard") → True
  4 回归 ("AUDIT-CROSSR","",         "analysis") → True
  5 fail-closed ("",     "ECO-AUDIT","analysis") → False  （stage 空 ⟹ 节点**不可判** ⟹ 拦；
                                                            命名空间仍由 r_phase 判为 ECO，见
                                                            `test_namespace_rule`）

red-first 选取集（`--expect=red` 要求**选中集全红**）：只有**消费者/接线**三例在修前必红
（沙箱按 `rev` 取 hook/CLI 的旧版实现）；`test_module_predicate` 等模块级用例在沙箱里走的是
**新模块**（未跟踪 ⟹ 回退工作树），修前天然通过，故**不纳入** red 集，只作 green 回归。

⚠ 测试面约束（探针教训）：**不得在此文件里端到端跑"放行臂"** —— 一放行就真派发 subagent、
真烧 token、真落盘（本会话已因探针设计失误付出 1 次 LLM 调用 + 主仓 1 个未跟踪件）。故四/五
臂全部在**纯函数层**覆盖，CLI 消费者只做**接线断言**。
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_review_nodes  # noqa: E402
import pre_tool_hook  # noqa: E402

ARMS = [
    # (id, stage, r_phase, project_type, expected_ok, 说明)
    ("arm1_analysis_eco_audit", "ECO-AUDIT", "ECO-SCAN", "analysis", True, "正臂：序列已到审查节点"),
    ("arm2_analysis_eco_edit", "ECO-EDIT", "ECO-SCAN", "analysis", False, "负臂：非审查节点仍拦"),
    ("arm3_standard_stage3", "STAGE_3", "", "standard", True, "回归：standard 审查节点"),
    ("arm4_analysis_auditcrossr", "AUDIT-CROSSR", "", "analysis", True, "回归：audit 审查节点"),
    ("arm5_stage_empty_failclosed", "", "ECO-AUDIT", "analysis", False, "stage 空 ⟹ 节点不可判 ⟹ 拦"),
]


class TestReviewNodeKey:
    """判据**键** = 序列命名空间（非活动计划的 project_type）。两消费者（模块 / hook）同名断言。"""

    @pytest.mark.parametrize("aid,stage,rp,pt,ok,note", ARMS, ids=[a[0] for a in ARMS])
    def test_module_predicate(self, aid, stage, rp, pt, ok, note):
        r = gk_review_nodes.review_node_ok(stage, rp, pt)
        assert r["ok"] is ok, f"{aid}（{note}）: {r}"

    @pytest.mark.parametrize("aid,stage,rp,pt,ok,note", ARMS, ids=[a[0] for a in ARMS])
    def test_hook_consumer_same_verdict(self, aid, stage, rp, pt, ok, note):
        """hook 消费者（Gate 1b）与模块**逐臂同判** —— 单源若被绕过，本臂先红。"""
        assert pre_tool_hook._review_node_ok(stage, pt, rp) is ok, f"{aid}（{note}）"

    def test_namespace_rule(self):
        assert gk_review_nodes.review_namespace("ECO-AUDIT", "") == "ECO"
        assert gk_review_nodes.review_namespace("", "ECO-SCAN") == "ECO"
        assert gk_review_nodes.review_namespace("STAGE_3", "") == "standard"
        # 混态回归：stage 已是 standard 命名空间时，残留的 ECO r_phase 不得把判据拉回 ECO 分支
        assert gk_review_nodes.review_namespace("STAGE_3", "ECO-SCAN") == "standard"

    def test_expected_payload(self):
        """`expected` 由单源产出（消费者不再各自维护白名单常量）。

        A4（2026-10-28）：standing 4 站规范名 + 旧名兼容 ⟹ expected 含 4 项。
        """
        assert (gk_review_nodes.review_node_ok("ECO-VERIFY", "", "analysis")["expected"]
                == "ECO-AUDIT|ECO-READ|ECO-RESEARCH|ECO-VERIFY")
        assert gk_review_nodes.review_node_ok("STAGE_3", "", "analysis")["expected"] == "AUDIT-CROSSR|STAGE_3"

    def test_canonical_stations_are_review_nodes(self):
        """A4 回归锁：推进到 4 站规范名后，审查车道不得恒被拦。"""
        for st in ("ECO-RESEARCH", "ECO-VERIFY"):
            assert gk_review_nodes.review_node_ok(st, "", "standing")["ok"] is True, st
            assert gk_review_nodes.review_node_ok(st, "", "analysis")["ok"] is True, st
        # 非审查站（EDIT/DOC）仍拦
        for st in ("ECO-EDIT", "ECO-DOC"):
            assert gk_review_nodes.review_node_ok(st, "", "standing")["ok"] is False, st

    def test_standing_regression(self):
        """standing 型态的既有拦/放**逐字不回退**。"""
        assert gk_review_nodes.review_node_ok("ECO-READ", "", "standing")["ok"] is True
        assert gk_review_nodes.review_node_ok("STAGE_3", "", "standing")["ok"] is False


class TestSingleSource:
    """**单源**锁定：白名单纯一份（模块），两消费者只引用不重定义。"""

    def test_hook_reuses_module_constants(self):
        assert pre_tool_hook._REVIEW_NODE_STANDARD is gk_review_nodes.REVIEW_NODE_STANDARD
        assert pre_tool_hook._REVIEW_NODE_STANDING is gk_review_nodes.REVIEW_NODE_STANDING

    def test_cli_consumer_wired_to_module(self):
        """CLI 侧（shell 消费者）无 import 面可言 ⟹ 以**接线断言**锁定：C 块改调单源模块、
        且不再内联 `ECO-READ|ECO-AUDIT` 的 case 分支（后者的行为判别已由上面五臂 + 端到端实测
        arm1 承担 —— 本断言只防"接线被回退成双源"）。"""
        cli = (pre_tool_hook.SKILL_DIR / "gatekeeper-cli.sh").read_text(encoding="utf-8", errors="replace")
        assert "gk_review_nodes" in cli
        assert "review_node_ok" in cli
        assert 'ECO-READ|ECO-AUDIT) c_ok=true' not in cli
