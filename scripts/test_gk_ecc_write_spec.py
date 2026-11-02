#!/usr/bin/env python3
"""ECC 写入规范拦截（A 类 · 机械可闭合）红先臂 —— ECC-03F2EB7D6607 / ECC-FF45F426BA45。

缺口（实测）：`closure_oracle` 落刀时为**自由文本**（零校验）⟹ 标签可任意书写 = 不可机检
= 等于没判据（`--api` 语义判据与 `--local` 结构判据都无从对表）。

本臂断言：**机械可判**的写入规范必须 fail-loud 拒写；**判断类**内容不校验（留 owner）。

对照臂纪律（§8.3 ⑧/⑨ 教训：无对照臂的臂不可信）：
  · 正臂 —— 合法枚举 / 空 / 大小写归一 必须可登记且**落盘值规范化**
  · 负臂 —— 未知枚举 / 中文 / 拼写错 必须**拒写且零落盘**
  · 形态臂 —— root_key 含空白 / 超长 必须拒（否则「指纹」可被散文冒充）
  · 回归臂 —— 校验不得破坏 root_key 合并路径（同指纹仍收敛为 1 条）
"""
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout

import pytest

SC = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SC)
import gk_finding as F  # noqa: E402


def _tmp_state():
    d = tempfile.mkdtemp(prefix="gk_ecc_spec_")
    p = os.path.join(d, "state.json")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"gate_data": {"ecc_findings": []}}))
    return p


def _run(*argv):
    old = sys.argv
    sys.argv = ["gk_finding.py", *argv]
    buf = io.StringIO()
    code = 0
    try:
        with redirect_stdout(buf):
            F.main()
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    finally:
        sys.argv = old
    raw = buf.getvalue()
    try:
        return code, json.loads(raw)
    except ValueError:
        return code, {"_raw": raw}


# ── 正臂：合法枚举 / 空 ─────────────────────────────────────────────────────
@pytest.mark.parametrize("co", ["mechanical", "judgment", ""])
def test_positive_allowed_closure_oracles_are_accepted(co):
    p = _tmp_state()
    code, out = _run("register", p, "正臂 " + (co or "<空>"), "manual",
                     "--closure-oracle", co)
    assert code == 0, out
    fs = F.load_findings(p)
    assert len(fs) == 1, fs
    assert fs[0]["closure_oracle"] == co


def test_positive_case_is_normalized_not_rejected():
    """大小写归一：`Mechanical` 应被规范成 `mechanical`（单一 canon），而非报错。"""
    p = _tmp_state()
    code, out = _run("register", p, "大写臂", "manual", "--closure-oracle", "Mechanical")
    assert code == 0, out
    assert F.load_findings(p)[0]["closure_oracle"] == "mechanical"


# ── 负臂：未知枚举必须拒写 + 零落盘 ─────────────────────────────────────────
@pytest.mark.parametrize("co", ["bogus", "机械", "judgemnt", "mechanical=auto"])
def test_negative_rejects_unknown_closure_oracle(co):
    p = _tmp_state()
    code, out = _run("register", p, "负臂 " + co, "manual", "--closure-oracle", co)
    assert code != 0, (code, out)
    assert out.get("ok") is False, out
    assert F.load_findings(p) == [], "拒写必须零落盘"


# ── 形态臂：root_key 不得被散文冒充 ─────────────────────────────────────────
@pytest.mark.parametrize("rk", ["has space", "含 空白", "x" * 65])
def test_negative_rejects_malformed_root_key(rk):
    p = _tmp_state()
    code, out = _run("register", p, "指纹形态臂", "manual", "--root-key", rk)
    assert code != 0, (code, out)
    assert out.get("ok") is False, out
    assert F.load_findings(p) == [], "拒写必须零落盘"


def test_positive_root_key_merge_path_still_converges():
    """回归臂：校验不得破坏「同 root_key 收敛为 1 条」的既有行为。"""
    p = _tmp_state()
    assert _run("register", p, "面A", "manual", "--root-key", "k.ok",
                "--closure-oracle", "mechanical")[0] == 0
    assert _run("register", p, "面B 异措辞", "manual", "--root-key", "k.ok",
                "--closure-oracle", "judgment")[0] == 0
    fs = F.load_findings(p)
    assert len(fs) == 1, fs
    assert fs[0]["closure_oracle"] == "judgment", "merge 路须允许有序重判"


# ── s5：`ECC-WRITE` stage + schema（B 类 · **只判形式完备**）───────────────────
_SCHEMA = os.path.join(SC, "..", "monitor-schemas", "ECC-WRITE.json")


def _schema():
    with open(_SCHEMA, encoding="utf-8") as fh:
        return json.load(fh)


def test_ecc_write_schema_present_and_shaped():
    """`monitor --api --stage ECC-WRITE` **硬依赖** `monitor-schemas/ECC-WRITE.json`
    （`cmd_monitor`：`[ ! -f "${SCHEMA_DIR}/${stage}.json" ]` ⟹ 缺则报 no schema）。"""
    s = _schema()
    assert s["name"] == "ECC-WRITE" and s.get("stage") == "standing"
    for k in ("requires", "evidence", "must_not", "structural_checks"):
        assert s.get(k), "schema 缺 %s" % k


def test_ecc_write_schema_is_form_only_not_self_referential():
    """纪律：**只判形式**，禁让 LLM 判「判断是否正确」（自指 = LLM 判 LLM 的结论）。"""
    s = _schema()
    assert "judge_whether_the_judgement_is_correct" in s["must_not"], \
        "缺「禁判判断内容」硬约束 ⟹ 自指风险未封"
    assert "author_missing_judgement_on_behalf_of_human" in s["must_not"], \
        "缺「禁代填判断」约束 ⟹ LLM 会把缺口补成散文"
    assert "fail_solely_because_closure_oracle_is_blank" in s["must_not"], \
        "「未分类」合法（存量）；不得仅因此判 FAIL"


def test_ecc_write_schema_form_criteria_present():
    """形式判据须在场：主要矛盾**恰好 1 条** / resolution **写明条件** / **事实与判断可分**。"""
    s = _schema()
    assert "principal_singular_if_present" in s["requires"]
    assert "resolution_states_condition_if_present" in s["requires"]
    assert "facts_and_judgement_separable" in s["requires"]
