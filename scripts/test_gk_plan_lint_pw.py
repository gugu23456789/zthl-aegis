"""Infra-3 红先臂：PW-SN 机检增量（PW-1/2/3/4/8/9）。

规则源 = `docs/plans/2026-10-04-plan-refine-group-dispatch-plan.md §9`（PW-1..PW-9）。
**分诊裁定（用户 2026-10-05）**：只落**可机检的 6 条**；PW-5（恒真/退化）/ PW-6（自洽性）/
PW-7（数量声明缺源）判**启发式 ⟹ 不机检**（答 §7-Q6），只登记不落码。

判据（HEAD 必红 —— 下列 CHECK/PW 检查尚不存在）：
- **PW-1**（扩 `check_switch`）：声明回退 env 仓内 0 命中 ⟹ high，**除非标「拟设」（+同批实装）**。
- **PW-2**：任务表「落刀点」列的**路径**须实存（幻影落刀点 ⟹ high）。
- **PW-3**：行含 `§N` **且**点名**带日期**的文档却**无 `.md` 路径** ⟹ medium（裸节号/错引）。
- **PW-4**：落刀点 token 出现在 **≥2 行**任务 ⟹ medium（双拆）。
- **PW-8**：`[ASSUMPTION-N]` **定义行**须含**三要素**（依据 / 可测 / 状态）⟹ 缺则 medium。
- **PW-9**：`墙/上限/常量/阈值/默认` 语境的**全大写常量名**须仓内实存 ⟹ 缺则 medium。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from gk_plan_lint import (CHECK_PW_ASSUME, CHECK_PW_CONST, CHECK_PW_FORM_SUFFIX,  # noqa: E402
                          CHECK_PW_LANDING, CHECK_PW_LANDING_DUP, CHECK_PW_SEC,
                          CHECK_PW_WRITE_IMPL, CHECK_PW_WRITE_ONLY, CHECK_SWITCH, lint)


def _mk(tmp_path, files):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return tmp_path


def _levels(findings, check):
    return sorted(lv for c, lv, _ in findings if c == check)


_LANDING = ("| # | 任务 | 落刀点 |\n|:--|:--|:--|\n%s")


# ── PW-2 幻影落刀点 ─────────────────────────────────────────────────────────

def test_pw_landing_phantom_path_is_high(tmp_path):
    repo = _mk(tmp_path, {"scripts/real.py": "x = 1\n"})
    plan = tmp_path / "plan.md"
    plan.write_text(_LANDING % "| T1 | x | `scripts/ghost_missing.py` |\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("PW-LANDING", "high") in [(c, lv) for c, lv, _ in f], f


def test_pw_landing_existing_path_ok(tmp_path):
    repo = _mk(tmp_path, {"scripts/real.py": "x = 1\n"})
    plan = tmp_path / "plan.md"
    plan.write_text(_LANDING % "| T1 | x | `scripts/real.py` |\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, CHECK_PW_LANDING) == [], f


# ── PW-3 裸节号/错引 ────────────────────────────────────────────────────────

def test_pw_bare_section_dated_doc_without_path_is_medium(tmp_path):
    repo = _mk(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("按 2026-09-28-git-concurrency-lease-declare-plan §18.1 办。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("PW-BARE-SEC", "medium") in [(c, lv) for c, lv, _ in f], f


def test_pw_section_with_md_path_ok(tmp_path):
    repo = _mk(tmp_path, {"docs/plans/2026-09-28-x-plan.md": "# x\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 `docs/plans/2026-09-28-x-plan.md` §18.1。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, CHECK_PW_SEC) == [], f


def test_pw_self_section_ok(tmp_path):
    """本文档自指 `§2`（无日期、无跨文档名）⟹ 不报（窄口径防误报）。"""
    repo = _mk(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 §2 任务表与 §3 判据。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, CHECK_PW_SEC) == [], f


# ── PW-4 落刀点重叠（双拆）──────────────────────────────────────────────────

def test_pw_landing_dup_is_medium(tmp_path):
    repo = _mk(tmp_path, {"scripts/a.py": "x = 1\n"})
    plan = tmp_path / "plan.md"
    plan.write_text(_LANDING % ("| T1 | x | `scripts/a.py` |\n"
                                "| T2 | y | `scripts/a.py` |\n"), encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("PW-LANDING-DUP", "medium") in [(c, lv) for c, lv, _ in f], f


def test_pw_landing_distinct_ok(tmp_path):
    repo = _mk(tmp_path, {"scripts/a.py": "x = 1\n", "scripts/b.py": "y = 1\n"})
    plan = tmp_path / "plan.md"
    plan.write_text(_LANDING % ("| T1 | x | `scripts/a.py` |\n"
                                "| T2 | y | `scripts/b.py` |\n"), encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, CHECK_PW_LANDING_DUP) == [], f


# ── PW-1 幻影 kill switch（扩 check_switch：拟设豁免）────────────────────────

def test_pw_switch_proposed_exempt(tmp_path):
    """标「拟设（+同批实装）」⟹ 不报（PW-1 的豁免口径）。"""
    repo = _mk(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("新增 `GK_PW_PROPOSED_X` 开关（拟设，随 T1 同批实装）。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, CHECK_SWITCH) == [], f


def test_pw_switch_unmarked_still_high(tmp_path):
    """未标拟设 ⟹ 仍 high（既有行为不回退）。"""
    repo = _mk(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("新增 `GK_PW_UNMARKED_Y` 开关。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("L-SWITCH", "high") in [(c, lv) for c, lv, _ in f], f


# ── PW-8 假设三要素 ────────────────────────────────────────────────────────

def test_pw_assume_missing_elements_is_medium(tmp_path):
    repo = _mk(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("- `[ASSUMPTION-1]` 甲\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("PW-ASSUME", "medium") in [(c, lv) for c, lv, _ in f], f


def test_pw_assume_full_elements_ok(tmp_path):
    """三要素齐备（依据 `a.py:1` + 可测 `pytest` + 状态「待消解」）⟹ 不报。"""
    repo = _mk(tmp_path, {"a.py": "x = 1\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("- `[ASSUMPTION-1]` 依据 `a.py:1`；判据 `pytest test_x.py`；待消解。\n",
                    encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, CHECK_PW_ASSUME) == [], f


def test_pw_assume_reference_line_not_judged(tmp_path):
    """**引用处**（非行首 bullet 定义）不入判（同 L-ASSUME 口径）。"""
    repo = _mk(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("- `[ASSUMPTION-1]` 依据 `a.py:1`；判据 `pytest`；待消解。\n\n"
                    "见 §7 的 [ASSUMPTION-1] 说明。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, CHECK_PW_ASSUME) == [], f


# ── PW-9 常量名实存 ────────────────────────────────────────────────────────

def test_pw_const_phantom_is_medium(tmp_path):
    repo = _mk(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("双墙口径：内壁 `PW_GHOST_WALL_LIMIT` 与总墙。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("PW-CONST", "medium") in [(c, lv) for c, lv, _ in f], f


def test_pw_const_existing_ok(tmp_path):
    repo = _mk(tmp_path, {"a.py": "PW_REAL_WALL_LIMIT = 65536\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("双墙口径：内壁 `PW_REAL_WALL_LIMIT` 与总墙。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, CHECK_PW_CONST) == [], f


# ── 接线（结构性）───────────────────────────────────────────────────────────

def test_pw_checks_wired_into_lint():
    src = (Path(__file__).parent / "gk_plan_lint.py").read_text(encoding="utf-8")
    seg = src[src.find("def lint("):]
    seg = seg[:seg.find("\n\ndef ")]
    for fn in ("check_pw_landing(", "check_pw_bare_section(", "check_pw_landing_dup(",
               "check_pw_const(", "check_pw_assume(",
               "check_pw_write_impl(", "check_pw_write_only(", "check_pw_form_suffix("):
        assert fn in seg, f"{fn} 未挂入 lint()（规则不生效）"


# ── PW-10 幻影单源（2026-10-08，承 §23.8.2 L 类）─────────────────────────────

def test_pw10_phantom_single_source_is_high(tmp_path):
    repo = _mk(tmp_path, {"scripts/gk_real.py": "def real_fn():\n    pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("本批**委托单源** `gk_real.missing_fn`（唯一实现）。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("PW-WRITE-IMPL", "high") in [(c, lv) for c, lv, _ in f], f


def test_pw10_existing_fn_ok(tmp_path):
    repo = _mk(tmp_path, {"scripts/gk_real.py": "def real_fn():\n    pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("本批**委托单源** `gk_real.real_fn`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, CHECK_PW_WRITE_IMPL) == [], f


def test_pw10_proposed_exempt(tmp_path):
    """标「拟设」的行豁免（对齐 PW-1/PW-9 口径）。"""
    repo = _mk(tmp_path, {"scripts/gk_real.py": "x = 1\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("拟设：**委托单源** `gk_real.ghost_fn`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, CHECK_PW_WRITE_IMPL) == [], f


# ── PW-11 只写不读 ─────────────────────────────────────────────────────────

def test_pw11_orphan_reader_is_medium(tmp_path):
    repo = _mk(tmp_path, {"scripts/gk_real.py": "def other():\n    pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("新增读侧 `read_ghost` 供 T4 判据。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("PW-WRITE-ONLY", "medium") in [(c, lv) for c, lv, _ in f], f


def test_pw11_consumed_reader_ok(tmp_path):
    repo = _mk(tmp_path, {"scripts/gk_real.py": "def read_real():\n    pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("新增读侧 `read_real` 供 T4 判据。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, CHECK_PW_WRITE_ONLY) == [], f


# ── PW-12 形态清单后缀覆盖 ─────────────────────────────────────────────────

def test_pw12_seal_not_registered_is_medium(tmp_path):
    repo = _mk(tmp_path, {"scripts/gk_state_forms.py": '_ARTIFACT_SUFFIXES = (".jsonl",)\n'})
    plan = tmp_path / "plan.md"
    plan.write_text("载体 = `<state>.edit-log.jsonl.seal`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("PW-FORM-SUFFIX", "medium") in [(c, lv) for c, lv, _ in f], f


def test_pw12_seal_registered_ok(tmp_path):
    repo = _mk(tmp_path, {"scripts/gk_state_forms.py": '_ARTIFACT_SUFFIXES = (".jsonl", ".seal")\n'})
    plan = tmp_path / "plan.md"
    plan.write_text("载体 = `<state>.edit-log.jsonl.seal`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, CHECK_PW_FORM_SUFFIX) == [], f
