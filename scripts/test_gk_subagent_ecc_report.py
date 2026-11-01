#!/usr/bin/env python3
"""ECC 机检面 + 报告分流修复红先臂（2026-10-01）。

覆盖两条 finding：
  ECC-728F04A3AB48  `verification` 假绿：非 plan-refinement 模式**无条件**预填
                    `required` + `status:"ok"` ⟹ 所有 default/scanner/exploiter/auditor/
                    reporter/coder 臂都拿到「声称查了两个必需字段、判 ok」的空壳。
  ECC-1951EFAD9CDF  `gk_subagent_report.py` 单一质询模板无分流：非质询臂产出**空 F1-F7 /
                    7 维表 + 错误标题**；且报告**不呈现**机检面（verification/evidence_anchor/
                    gx_status）；`conclusion` 取**原始 llm_text**（输出纯 JSON 的臂 ⟹ 整段
                    JSON 塞进「Agent 结论」）。

判据（红先，落刀前 HEAD **必红**）：
  arm1/arm2  `_build_verification` 纯函数（HEAD 无此符号 → AttributeError）
  arm3       源码里重试判据须用 `verification.get("retried")`（HEAD 是 `verification["retried"]`）
  arm4/arm5  `ecc_form()` 形态判定 + 通用报告不再出质询专表（HEAD 无 ecc_form；render 恒质询模板）
  arm6       报告呈现机检面（HEAD 全篇无此面）
  arm7       runner `conclusion` 优先取 `llm_data["conclusion"]`（HEAD 恒取 llm_text）
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import subagent_runner as sr          # noqa: E402
import gk_subagent_report as rep      # noqa: E402

_RUNNER_SRC = Path(__file__).with_name("subagent_runner.py").read_text(encoding="utf-8")


def _default_ecc() -> dict:
    """default 形态 EccOutput（4-field ECC；臂A 实测同构）。"""
    return {
        "mode": "subagent", "subagent_id": "sub-x", "nonce": "n", "timestamp": "t",
        "task": "质询臂A(域化范围)", "conclusion": '{"task":"x","evidence":[]}',
        "evidence": [{"file": "gatekeeper-cli.sh", "lines": "144-151", "status": "confirmed"}],
        "findings": {"worked": ["w"], "failed": ["f"], "not_tried": ["n"]},
        "next_steps": ["s"], "confidence": "medium", "tools_used": ["read"],
        "verdicts": {}, "seven_dim_score": {},
        "verification": {"status": "n/a", "retried": False},
        "evidence_anchor": {"status": "ok", "unanchored": []},
        "gx_status": {"verdict": "not_called"},
        "agent_payload": {"task": "x", "evidence": [], "findings": {}},
    }


def _plan_ecc() -> dict:
    """plan-refinement 形态 EccOutput（SCR 专有面齐全）。"""
    d = _default_ecc()
    d["verdicts"] = {"F1": "PASS", "F2": "WARN"}
    d["seven_dim_score"] = {"scope": 80}
    d["challenges"] = ["c1"]
    d["agent_payload"] = {"plan_type": "path", "f1_f7": {"F1": "ok"},
                          "constraint_matrix": [{"constraint": "F1"}],
                          "verification_checklist": [{"task": "T"}]}
    return d


# ─── arm1/arm2：verification 只在 plan-refinement 构造 ───

def test_build_verification_default_does_not_claim_ok():
    """非 plan-refinement 不得虚报 required / status=ok（HEAD 无此函数 → 红）。"""
    v = sr._build_verification("default")
    assert "required" not in v, v
    assert v.get("status") != "ok", v


def test_build_verification_plan_refinement_claims_ok():
    """plan-refinement 保留原契约（required + status=ok）。"""
    v = sr._build_verification("plan-refinement")
    assert v.get("required") == list(sr._PLAN_REQUIRED_FIELDS), v
    assert v.get("status") == "ok", v


def test_runner_retry_guard_uses_get():
    """证据锚重试与 verification 互斥判据用 .get（防 n/a 形态 KeyError）。"""
    assert 'verification.get("retried")' in _RUNNER_SRC, (
        'HEAD 为 verification["retried"] ⟹ 改成 status=n/a 的瘦身 dict 后会 KeyError')


# ─── arm4/arm5/arm6：报告按 ECC 形态分流 + 呈现机检面 ───

def test_ecc_form_discriminates():
    """形态判定须可机检（HEAD 无 ecc_form）。"""
    assert rep.ecc_form(_default_ecc()) == "default"
    assert rep.ecc_form(_plan_ecc()) == "plan-refinement"


def test_generic_report_has_no_plan_only_tables():
    """default 形态不得出质询专表（F1-F7 / 7 维）与质询标题。"""
    md = rep.render(_default_ecc())
    assert "F1-F7" not in md, "default 臂仍套 F1-F7 质询表（空表 + 撒谎标题）"
    assert "7维" not in md, "default 臂仍套 7 维评分表"


def test_report_presents_machine_check_face():
    """报告须呈现机检面 —— F-REV-74/81/97 的结论必须对人可见。"""
    md = rep.render(_default_ecc())
    for key in ("verification", "evidence_anchor", "gx_status"):
        assert key in md, f"报告未呈现机检面字段 {key}"


def test_plan_report_still_has_plan_tables():
    """plan-refinement 形态零回归：F1-F7 表仍出。"""
    md = rep.render(_plan_ecc())
    assert "F1-F7" in md


# ─── arm7：conclusion 优先取模型结论字段 ───

def test_runner_conclusion_prefers_llm_field():
    """输出含 conclusion 键时取它（否则退回 llm_text），避免整段 JSON 进人读报告。"""
    assert 'llm_data.get("conclusion")' in _RUNNER_SRC, (
        "conclusion 仍恒为原始 llm_text ⟹ 输出纯 JSON 的臂把人读报告的「结论」塞成 JSON 原文")


# ─── 极限压力测试（2026-10-04）：形态判定对「已退化 ECC」也要稳 ────────────────
# 事故：上游 `_extract_llm_json` 对畸形外层 JSON 静默返回**内层**对象 ⟹ agent_payload 退化、
#   verdicts/seven_dim_score 恒空；而 SCR 面只存活在 `conclusion` 文本里。此时 ecc_form 只看
#   agent_payload/verdicts 两路信号 ⟹ 误判 default（sub-1791075048-21915-31873 报告模板错配）。
# 修法：ecc_form 增第三路信号（conclusion 内嵌 JSON 对象含 SCR 键）+ 渲染侧类型守卫。
def test_ecc_form_detects_scr_nested_in_conclusion():
    """SCR 面只在 conclusion 文本（agent_payload 退化）⟹ 仍须判 plan-refinement。"""
    d = _default_ecc()
    d["conclusion"] = '{"plan_type":"constraint_sat","f1_f7":{"F1":"ok"},"constraint_matrix":[]}'
    assert rep.ecc_form(d) == "plan-refinement"


def test_ecc_form_default_when_conclusion_non_scr():
    """conclusion 是普通 JSON 文本（非 SCR 面）⟹ 仍须 default（守零回归）。"""
    d = _default_ecc()
    d["conclusion"] = '{"task":"x"}'
    assert rep.ecc_form(d) == "default"


def test_ecc_form_detects_scr_in_malformed_conclusion():
    """**事故本体**：conclusion 是**畸形** JSON（缺逗号，json.loads 失败）但含 SCR 键 ⟹ 仍判 plan-refinement。

    实测 sub-1791075048-21915-31873：conclusion = 10,917 字畸形 SCR JSON（`challenges]` 与
    `"slashed"` 间缺逗号）⟹ 只做 json.loads 的第三信号会漏；须补「键面嗅探」。
    """
    d = _default_ecc()
    d["conclusion"] = '{"challenges":["x"]"slashed":[],"constraint_matrix":[{"c":"F1"}]}'
    assert rep.ecc_form(d) == "plan-refinement"


def test_render_survives_malformed_field_types():
    """渲染侧不得因字段类型错配崩溃（非 dict verdicts / 非 list 挑战·砍留）。"""
    d = _default_ecc()
    d["verdicts"] = ["oops"]        # 非 dict ⟹ 旧式 verdicts.get(...) 会 AttributeError
    d["seven_dim_score"] = "oops"
    d["challenges"] = 5             # 非迭代
    d["slashed"] = 7
    d["kept"] = {"k": 1}
    md = rep.render(d)
    assert isinstance(md, str)

