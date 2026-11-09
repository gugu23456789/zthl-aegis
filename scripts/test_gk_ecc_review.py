"""test_gk_ecc_review.py — 「转发 ECC 证据包」自动化复核引擎 + 仓外计划锚根。

背景（2026-09-25/26 实测，非推测）：
  转发来的 ECC 证据包（自包含 md，落 `docs/analysis/`）此前**只能人工逐锚读码复核** ——
  实测代价：一份 8 锚的包，人工复核查出 **2 条因果反转 + 3 条行号漂移**，全部靠读码发现；
  而仓内**没有任何确定性入口**能对「包里的锚」给出逐条判定（`gk_finding.py` 无 ingest；
  `doc-align anchor_existence` 只扫**本仓** `docs/plans/`；`anchor-rebase` 同）。

  次生结构性缺口（`ECC-4D6978F042BA` **复核订正后收窄**）：仓外计划（如 `.codex/docs/plans/`）
  在机检面之外 —— `gk_anchor_rebase.py` 的 doc 解析硬绑 `<skill_dir>/docs/plans/`
  （`:55` / `:131`），前置门又要求该目录存在（`:180`）；`gk_doc_align.check_anchor_existence`
  同样只以 `skill_dir` 为根（仅 `docs_subdir` 可调）。
  ⚠ 订正：原 finding 称「`gk_plan_lint` 不管裸锚」**已过期** —— `anchor_no_assertion`
  （F-REV-69）已覆盖 `file:NNN` 无断言绑定形态，且 `gk_plan_lint.main()` **本就能吃任意路径**；
  真实缺口是「**没有任何东西去调用它 + 仓外根进不来**」。

  本批（用户裁定「先 A+B：先立复核流程」）交付：
    A · `scripts/gk_ecc_review.py` —— 逐锚判定引擎（0 API / 纯确定性）：
        `hit | line_drift | line_over_eof | file_missing | unverifiable`
        + 自动起草「⚠ 复核订正」段（把「人工读码后手写订正」机制化）。
        锚提取**复用** `gk_plan_lint.iter_anchor_refs`（单一事实源，禁第二正则）。
    B · 锚根可配 —— `gk_anchor_rebase.py --plans-root` / `gk_doc_align.check_anchor_existence(extra_roots=)`
        （默认**零改动**：不传新参 = 与既有行为逐字一致）。

判据（红先，4 臂；全部**行为臂**，API-absent / 新形参 ⟹ 落刀前必红）：
  arm53：五类锚判定分类 + `line_drift` 给出**真值行号**。
  arm54：报告必须**自动起草**订正段，且非 hit 锚逐条进草稿（漏一条 = 本轮那种「订正写漏」）。
  arm55：`gk_anchor_rebase` 在 `plans_roots` 下能**够到仓外计划**并改写其行锚（HEAD 硬绑 ⟹ 找不到）。
  arm56：`gk_doc_align.check_anchor_existence(extra_roots=...)` 能扫到仓外计划（HEAD 无形参）。

安全网 R1：只写 `tmp_path`；不 patch 标准库；不执行外部载荷；不读网络。
"""
import os
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

# 夹具用的「最小 repo + 转发包」：五类锚各一
_DEMO_CODE = "\n".join([
    "line1",
    "line2",
    "HITLIT=1",       # 3
    "line4",
    "line5",
    "DRIFTLIT=2",     # 6
    "line7",          # 7 = EOF
]) + "\n"

_DEMO_PKG = "\n".join([
    "# 转发包（夹具）",
    "",
    "| # | 锚 | 内容 |",
    "|:--|:--|:--|",
    "| 1 | `targets/demo.sh:3` | `HITLIT` |",
    "| 2 | `targets/demo.sh:4` | `DRIFTLIT` |",
    "| 3 | `targets/demo.sh:9` | `HITLIT` |",
    "| 4 | `nope/missing.sh:1` | `MISSINGLIT` |",
    "| 5 | `targets/demo.sh:3` | 本行无可校验字面值 |",
    "",
]) + "\n"


def _mk(tmp: Path):
    """建最小 repo（`targets/demo.sh`）+ 转发包 md；返回 (pkg_path, repo_root)。"""
    (tmp / "targets").mkdir(parents=True, exist_ok=True)
    (tmp / "targets" / "demo.sh").write_text(_DEMO_CODE, encoding="utf-8")
    pkg = tmp / "pkg.md"
    pkg.write_text(_DEMO_PKG, encoding="utf-8")
    return pkg, tmp


# ─── A：逐锚判定 ────────────────────────────────────────────────────────────
def test_arm53_ecc_review_verdicts_and_true_line(tmp_path):
    """arm53：五类锚各得正确 verdict；`line_drift` 必须报**真值行号**。"""
    import gk_ecc_review as er            # 惰性 import：HEAD 无此模块 ⟹ 必红
    pkg, root = _mk(tmp_path)
    rep = er.review(str(pkg), roots=[str(root)])
    vs = [a["verdict"] for a in rep["anchors"]]
    assert vs[0] == "hit", vs
    assert vs[1] == "line_drift", vs
    assert vs[2] == "line_over_eof", vs
    assert vs[3] == "file_missing", vs
    assert vs[4] == "unverifiable", vs
    assert rep["anchors"][1]["suggested_line"] == 6, rep["anchors"][1]   # DRIFTLIT 真值在 6 行
    assert rep["counts"]["line_drift"] == 1, rep["counts"]


# ─── A：订正段自动起草（把本轮「人工订正」机制化）──────────────────────────────
def test_arm54_ecc_review_drafts_correction_section(tmp_path):
    """arm54：报告须自带「复核订正」草稿，且**全部**非 hit 锚逐条列出 + 真值行号。"""
    import gk_ecc_review as er
    pkg, root = _mk(tmp_path)
    rep = er.review(str(pkg), roots=[str(root)])
    md = rep["draft_md"]
    assert "复核订正" in md, md[:200]
    assert "targets/demo.sh:4" in md and ":6" in md, md
    assert "nope/missing.sh:1" in md, md
    for a in rep["anchors"]:
        if a["verdict"] != "hit":
            assert a["ref"] in md, (a, md)


# ─── B：仓外计划锚根（anchor-rebase 侧）──────────────────────────────────────
def test_arm55_anchor_rebase_plans_root_reaches_out_of_repo(tmp_path):
    """arm55：`plans_roots` 下 `--map` 能改写**仓外**计划的行锚（HEAD 硬绑 docs/plans ⟹ 找不到）。"""
    import gk_anchor_rebase as ar
    skill = tmp_path / "skill"
    (skill / "docs" / "plans").mkdir(parents=True)          # 技能仓内计划根（空）
    ext = tmp_path / "ext" / "docs" / "plans"
    ext.mkdir(parents=True)
    doc = ext / "ext-plan.md"
    doc.write_text("见 `gatekeeper-cli.sh:3395` 一处\n", encoding="utf-8")
    p = ar.plan_edits(str(skill), ["ext-plan.md"],
                      mapping={"gatekeeper-cli.sh:3395": "gatekeeper-cli.sh:3400"},
                      plans_roots=[str(ext)])
    assert p["edits"], "仓外计划未被解析（plan root 够不到）"
    res = ar.apply_edits(str(skill), p["edits"], apply=True, plans_roots=[str(ext)])
    assert [r["status"] for r in res] == ["applied"], res
    assert "gatekeeper-cli.sh:3400" in doc.read_text(encoding="utf-8")


# ─── B：仓外计划锚根（doc-align 侧）──────────────────────────────────────────
def test_arm56_anchor_existence_extra_roots(tmp_path):
    """arm56：`extra_roots` 必须把仓外计划纳入扫描面，**且**被引文件真在 extra root 下解析成功。

    判据自检采纳（coder 疑点 1 / 2026-09-26）：只断言「roots 含 ext」是**弱判据** —— 若 rel 解析
    仍只走 `skill_dir`，被引文件会落 `file_missing`，而 `file_missing` **同样**进 `drifted`
    ⟹ 弱断言照样通过。故本臂让**被引文件只存在于 ext root**，再断 `verdict == "line_over_eof"`
    （**解析成功**才会给越界）—— 把「扫描面扩大」与「解析根真的生效」两件事分开证明。
    """
    import gk_doc_align as da
    skill = tmp_path / "skill"
    (skill / "docs" / "plans").mkdir(parents=True)
    ext = tmp_path / "ext"
    (ext / "docs" / "plans").mkdir(parents=True)
    (ext / "targets").mkdir(parents=True)
    (ext / "targets" / "demo.sh").write_text("l1\nl2\nl3\n", encoding="utf-8")
    (ext / "docs" / "plans" / "ext-plan.md").write_text(
        "锚 targets/demo.sh:999 越界\n", encoding="utf-8")
    rep = da.check_anchor_existence(str(skill), extra_roots=[str(ext)])
    assert str(ext) in [str(x) for x in (rep.get("roots") or [])], rep.get("roots")
    hit = [x for x in (rep.get("drifted") or []) if x.get("doc") == "ext-plan.md"]
    assert hit and hit[0]["verdict"] == "line_over_eof", hit


def test_symbol_anchor_preflight(tmp_path):
    """盲点修复：`file.py::symbol` 锚必须被预检看见，且缺失符号判 literal_missing。"""
    import gk_ecc_review as er
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    (root / "scripts" / "gk_finding.py").write_text(
        "def family_view(state_file):\n    return {}\n", encoding="utf-8")
    pkg = tmp_path / "pkg.md"
    pkg.write_text("`scripts/gk_finding.py::family_view`\n", encoding="utf-8")
    rep = er.review(str(pkg), roots=[str(root)])
    sym = [a for a in rep["anchors"] if a.get("kind") == "symbol"]
    assert sym and sym[0]["verdict"] == "ok", rep["anchors"]

    pkg2 = tmp_path / "pkg2.md"
    pkg2.write_text("`scripts/gk_finding.py::not_a_symbol`\n", encoding="utf-8")
    rep2 = er.review(str(pkg2), roots=[str(root)])
    sym2 = [a for a in rep2["anchors"] if a.get("kind") == "symbol"]
    assert sym2 and sym2[0]["verdict"] == "literal_missing", rep2["anchors"]


def test_symbol_anchor_class_method(tmp_path):
    """点分符号 `Class.method`：类与方法两段都存在即 ok（不要求字面连续）。"""
    import gk_ecc_review as er
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    (root / "scripts" / "gk_agent_edit.py").write_text(
        "class _StateLedger:\n    def allowed(self):\n        return 1\n", encoding="utf-8")
    pkg = tmp_path / "pkg.md"
    pkg.write_text("`scripts/gk_agent_edit.py::_StateLedger.allowed`\n", encoding="utf-8")
    rep = er.review(str(pkg), roots=[str(root)])
    sym = [a for a in rep["anchors"] if a.get("kind") == "symbol"]
    assert sym and sym[0]["verdict"] == "ok", rep["anchors"]
