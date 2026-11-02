"""test_tri_consistency_gate.py — 三面一致性闸（红先，4 臂）。

背景（owner 2026-10-06「按 A8 熔断，先修基础设施」）：`anchor-verdict` 计划连续两轮
6/6 BLOCKED，第二轮缺口多为首轮修复自身引入 —— 病型 = PW-SN 的 A2 修复即改写 +
A3 单侧 red-first：同一语义在「计划文本 / 族派发契约 / 红先臂」三处分裂。

本臂集把可机检的三面固化：
  arm_a（写面枚举单源） 由 save_findings( 的**可达闭包**机械枚举（含 amend_anchors、排除 main），禁用**手抄**写面表
  arm_b（族自洽，差异臂）合法族 PASS / 矛盾族 FAIL —— 既防过度收紧也防放水
  arm_c（verdict 值域） 判决器返回值域须被 _VERDICT_ORDER 或显式例外覆盖

判据（红先，对 HEAD 3 臂全红 —— 目标模块尚不存在）：
  arm_a 写面集 ⊇ 9 面；arm_b 合法 ok / 非法 violations 非空；arm_c 值域缺口为空。

安全网 R1：只读仓内源码 + 只写 tmp_path；不 patch 标准库；不执行外部载荷；不读网络。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
SKILL = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

_REQUIRED_SURFACES = {
    "close", "verify", "reopen", "amend_title", "amend_anchors",
    "archive_closed", "prune_duplicates", "conflicts", "register",
}


# ─── arm_a：写面枚举单源（HEAD 无该模块 ⟹ 红）────────────────────────────────
def test_arm_a_write_surfaces_enumerated():
    import gk_tri_consistency as tri
    got = set(tri.enumerate_write_surfaces(str(SCRIPTS / "gk_finding.py")))
    missing = _REQUIRED_SURFACES - got
    assert not missing, "写面枚举缺: %s（禁手抄，须由 save_findings 调用点导出）" % sorted(missing)


# ─── arm_b：族自洽差异臂（合法 PASS / 矛盾 FAIL；HEAD 无该模块 ⟹ 红）────────────
def _fam(path, quota, allowed, test_first):
    path.write_text(json.dumps({
        "family": "F-fixture",
        "allowed_paths": allowed,
        "edit_quota": quota,
        "test_first": test_first,
        "affected_tests": [test_first.split("::")[0]],
    }, ensure_ascii=False), encoding="utf-8")
    return str(path)


def test_arm_b_family_self_check_differs(tmp_path):
    import gk_tri_consistency as tri
    real = _fam(tmp_path / "ok.json", 2, ["scripts/gk_finding.py", "scripts/gk_ecc_review.py"],
                "scripts/test_pre_tool_hook.py::test_x")          # 文件存在 ⟹ 合法
    bad = _fam(tmp_path / "bad.json", 1, ["scripts/gk_finding.py", "scripts/gk_ecc_review.py"],
               "scripts/test_pre_tool_hook.py::test_x")           # quota(1) < 文件数(2) ⟹ 矛盾
    r_ok = tri.check_family(real)
    r_bad = tri.check_family(bad)
    assert r_ok["ok"] is True, r_ok                       # 防过度收紧
    assert r_bad["ok"] is False and r_bad["violations"], r_bad   # 防放水
    assert bool(r_ok["ok"]) != bool(r_bad["ok"])          # 差异臂：好/坏判决必须不同


# ─── arm_c：verdict 值域（HEAD 无该模块 ⟹ 红）────────────────────────────────
def test_arm_c_verdict_domain_covered():
    import gk_tri_consistency as tri
    assert tri.check_verdict_domain() == [], "判决器返回值域须被 _VERDICT_ORDER 或显式例外覆盖"


# ─── arm_d：plan-lint 最小接线（HEAD 无 ⟹ 红）────────────────────────────────
def test_arm_d_plan_lint_wires_tri_consistency():
    import inspect
    import gk_plan_lint as pl
    src = inspect.getsource(pl.lint)
    assert "check_verdict_domain" in src, "plan-lint.lint 末尾须加性调用本闸（check_verdict_domain）"
    assert "GK_TRI_CONSISTENCY" in src, "接线须受 GK_TRI_CONSISTENCY 开关控制（默认 1）"
