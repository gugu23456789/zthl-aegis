"""test_anchor_verdict_engine.py — 锚判决**单一源引擎**（红先，9 臂）。

拆分产物：原 `anchor-verdict-single-source-plan` 连续三轮 SCR 6/6 BLOCKED（面过大）⟹
owner 2026-10-06 裁定拆分。本臂集只覆盖**引擎单一源 + A 侧接入**（无强制闸、无 --ack-drift、
无 precheck_ack）；闸相关臂（空转闸机/接线/remedy/ack）见姊妹计划的臂集。

背景（同源双实现）：
  A = `gk_finding.scan_title_anchors`（台账标题锚，2 判决内联，**EOF 用区间右端 hi**）
  B = `gk_ecc_review.classify`（转发证据包，6 判决，**EOF 用 lo**）
  二者同走 `gk_plan_lint.iter_anchor_refs`（锚提取单一源），却各自实现判决阶梯 ⟹ 同源双实现。

判据（红先，对 HEAD 呈现「1/2/4/5/6/7/8 红、3/9 绿」）：
  arm1 引擎 API + EOF 操作数 mode 分化契约（HEAD 无 classify_anchor ⟹ 红）
  arm2 A 复用共享器（monkeypatch 哨兵；HEAD A 内联不调 ⟹ 红）
  arm3 零回归守卫（B 6 判决 + A 输出键集；HEAD 绿）
  arm4 区间跨 EOF（existence 用 hi ⟹ 报；content 用 lo ⟹ 不报 ⟹ 红）
  arm5 刷锚重钉替换（三步：收集映射→主体全量替换→删段 + 链式 + 共前缀；HEAD 无 _live_title ⟹ 红）
  arm6 import 形态守卫（顶层无环 + scan_title_anchors 函数级 import ⟹ 红）
  arm7 anchors_total 反映 live 面（HEAD 无 _live_title ⟹ 红）
  arm8 mode 分化读失败 + EOF 计数法（existence fail-soft/_lines_of；content fail-loud/splitlines ⟹ 红）
  arm9 infra 前置（"ok" in _VERDICT_ORDER；base 含 tri-consistency infra ⟹ 绿）

安全网 R1：只写 tmp_path；不 patch 标准库；不执行外部载荷；不读网络。
"""
import ast
import inspect
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

_DEMO_CODE = "\n".join(["line1", "HITLIT=1", "line3"]) + "\n"   # EOF = 3


def _mk_repo(tmp_path, rel_texts):
    repo = tmp_path / "repo"
    for rel, text in rel_texts.items():
        fp = repo / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(text, encoding="utf-8")
    return str(repo)


def _state_with(path, findings):
    path.write_text(json.dumps({"gate_data": {"ecc_findings": findings}}), encoding="utf-8")
    return str(path)


def _anchor(rel, lo, hi=None, literals=None):
    return {"ref": "%s:%d" % (rel, lo), "rel": rel, "lo": lo, "hi": hi or lo,
            "doc_line": 1, "literals": literals or []}


# ─── arm1：引擎 API + EOF 操作数 mode 分化（HEAD 无该符号 ⟹ 红）──────────────
def test_arm1_classify_anchor_mode_contract(tmp_path):
    import gk_ecc_review as er
    assert hasattr(er, "classify_anchor"), "HEAD 无 classify_anchor ⟹ 红"
    root = _mk_repo(tmp_path, {"scripts/demo.sh": _DEMO_CODE})
    target = Path(root) / "scripts" / "demo.sh"
    a = _anchor("scripts/demo.sh", 1, 1, [])
    assert er.classify_anchor(a, target, "existence")["verdict"] == "ok"
    assert er.classify_anchor(a, None, "existence")["verdict"] == "file_missing"
    r = er.classify_anchor(_anchor("scripts/demo.sh", 99, 99, []), target, "existence")
    assert r["verdict"] == "line_over_eof" and r.get("eof") == 3, r
    assert er.classify_anchor(a, target, "content")["verdict"] == "unverifiable"
    # target 类型容错：str 亦可（_resolve_path 返 str）
    assert er.classify_anchor(a, str(target), "existence")["verdict"] == "ok"
    # mode 白名单：非法 mode 须 fail-loud（禁静默落 content）
    with pytest.raises(ValueError):
        er.classify_anchor(a, target, "bogus")


# ─── arm2：A 复用共享器（HEAD：A 内联不调它 ⟹ 红）────────────────────────────
def test_arm2_scan_title_anchors_uses_shared_classifier(tmp_path, monkeypatch):
    import gk_ecc_review as er
    import gk_finding as gf

    called = {"n": 0}

    def _sentinel(anchor, target, mode="content"):
        called["n"] += 1
        return {"verdict": "file_missing"}

    monkeypatch.setattr(er, "classify_anchor", _sentinel, raising=False)
    root = _mk_repo(tmp_path, {"real.py": "a\nb\n"})
    state = _state_with(tmp_path / "s2.json",
                       [{"id": "ECC-T2", "status": "open", "title": "见 real.py:1 处"}])
    r = gf.scan_title_anchors(state, root)
    assert called["n"] >= 1, "A 未调用共享判决器 ⟹ 红"
    assert [d["verdict"] for d in r["drifted"]] == ["file_missing"], r


# ─── arm3：零回归守卫（HEAD 绿）──────────────────────────────────────────────
def test_arm3_no_regression_guard(tmp_path):
    import gk_ecc_review as er
    import gk_finding as gf
    root = _mk_repo(tmp_path, {"scripts/demo.sh": _DEMO_CODE})
    assert er.classify(_anchor("scripts/demo.sh", 2, 2, ["HITLIT"]), [root])["verdict"] == "hit"
    assert er.classify(_anchor("scripts/demo.sh", 1, 1, ["HITLIT"]), [root])["verdict"] == "line_drift"
    assert er.classify(_anchor("scripts/demo.sh", 99, 99, ["HITLIT"]), [root])["verdict"] == "line_over_eof"
    assert er.classify(_anchor("nope/x.sh", 1, 1, ["LIT"]), [root])["verdict"] == "file_missing"
    # B 全 6 判决覆盖（补 literal_missing / unverifiable）
    assert er.classify(_anchor("scripts/demo.sh", 2, 2, ["NOPE_LIT"]), [root])["verdict"] == "literal_missing"
    assert er.classify(_anchor("scripts/demo.sh", 2, 2, []), [root])["verdict"] == "unverifiable"
    state = _state_with(tmp_path / "s3.json", [])
    assert set(gf.scan_title_anchors(state, root).keys()) == {
        "anchors_total", "findings_scanned", "drifted"}, gf.scan_title_anchors(state, root)


# ─── arm4：区间跨 EOF —— EOF 操作数按 mode 分化（HEAD 无 classify_anchor ⟹ 红）──
def test_arm4_cross_eof_operand_is_mode_dependent(tmp_path):
    import gk_ecc_review as er
    import gk_finding as gf
    root = _mk_repo(tmp_path, {"f.py": "a\nb\nc\n"})     # EOF = 3
    target = Path(root) / "f.py"
    a = _anchor("f.py", 2, 9, ["LIT"])                   # lo=2 ≤ EOF=3 < hi=9 ⟹ 跨 EOF
    assert er.classify_anchor(a, target, "existence")["verdict"] == "line_over_eof", \
        "existence（A 语义）须以 hi 判 ⟹ 报越界"
    assert er.classify_anchor(a, target, "content")["verdict"] != "line_over_eof", \
        "content（B 语义）以 lo 判 ⟹ 不报越界（逐字保持 B）"
    # 端到端：A 侧对跨 EOF 区间锚仍须报漂移（零回归）
    st = _state_with(tmp_path / "ce.json",
                     [{"id": "ECC-CE", "status": "open", "title": "见 f.py:2-9 处"}])
    assert [d["verdict"] for d in gf.scan_title_anchors(st, root)["drifted"]] == ["line_over_eof"]


# ─── arm5：刷锚重钉替换（old→new 整体替换 + 链式；HEAD 无 _live_title ⟹ 红）────
def test_arm5_reanchor_marks_are_superseded(tmp_path):
    import gk_finding as gf
    root = _mk_repo(tmp_path, {"real.py": "a\nb\n"})     # EOF = 2
    assert gf._live_title("见 real.py:99 处") == "见 real.py:99 处"   # 无刷锚 ⟹ 恒等
    t = "见 real.py:99 处 [刷锚 2026-10-06] real.py:99 → real.py:1"
    live = gf._live_title(t)
    assert "real.py:99" not in live and "real.py:1" in live, live
    st = _state_with(tmp_path / "re.json", [{"id": "ECC-RE", "status": "open", "title": t}])
    assert gf.scan_title_anchors(st, root)["drifted"] == [], \
        "刷锚后旧锚须被重钉映射取代 ⟹ 不再永久报漂移"
    # 链式（a→b→c）：只余最终锚，中间锚与旧锚均不残留
    chain = "见 real.py:99 处 [刷锚 2026-10-05] real.py:99 → real.py:1 [刷锚 2026-10-06] real.py:1 → real.py:2"
    lc = gf._live_title(chain)
    assert "real.py:99" not in lc and "real.py:1" not in lc and "real.py:2" in lc, lc
    # 共前缀边界（**真判别**）：主体同含 real.py:1 与 real.py:10；old=real.py:1 ⟹ 只改前者，
    # 禁裸 str.replace（否则 real.py:10 被误改成 real.py:990）
    pre = "见 real.py:1 与 real.py:10 处 [刷锚 2026-10-06] real.py:1 → real.py:99"
    lp = gf._live_title(pre)
    assert "real.py:99" in lp, lp
    assert "real.py:10" in lp, lp          # 长锚原样保留
    assert "real.py:990" not in lp, lp     # 未发生前缀误改写
    # 后缀形态：old=`:1` 不得误吃区间 `:1-5`（裸 str.replace 会产出 `:7-5`）
    rng = "见 :1 与 :1-5 处 [刷锚 2026-10-06] :1 → :7"
    lr = gf._live_title(rng)
    assert ":7" in lr and ":1-5" in lr and ":7-5" not in lr, lr


# ─── arm6：import 形态守卫（顶层无环；HEAD 无函数级 import ⟹ 红）──────────────
def _top_level_imports(path):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    mods = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            mods.add(node.module or "")
    return tree, mods


def test_arm6_import_form_is_function_level():
    gf_path = SCRIPTS / "gk_finding.py"
    er_path = SCRIPTS / "gk_ecc_review.py"
    # (a) gk_finding **顶层**不得 import gk_ecc_review（装载期耦合）
    gtree, gtop = _top_level_imports(gf_path)
    assert "gk_ecc_review" not in gtop, "顶层 import gk_ecc_review ⟹ 装载期耦合"
    # (b) scan_title_anchors **函数体内**须 import gk_ecc_review（模块属性调用，禁置顶 from-import）
    fn = next(n for n in gtree.body
              if isinstance(n, ast.FunctionDef) and n.name == "scan_title_anchors")
    inner = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Import):
            inner.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            inner.add(node.module or "")
    assert "gk_ecc_review" in inner, "scan_title_anchors 须函数级 import gk_ecc_review（禁置顶）"
    # (c) gk_ecc_review **顶层**不得 import gk_finding（反向边）
    _etree, etop = _top_level_imports(er_path)
    assert "gk_finding" not in etop, "gk_ecc_review 顶层 import gk_finding ⟹ 环"


# ─── arm7：anchors_total 反映 live 面（HEAD 无 _live_title ⟹ 红）──────────────
def test_arm7_anchors_total_reflects_live(tmp_path):
    import gk_finding as gf
    root = _mk_repo(tmp_path, {"real.py": "a\nb\n"})
    assert hasattr(gf, "_live_title"), "HEAD 无 _live_title ⟹ 红"
    t = "见 real.py:1 处 [刷锚 2026-10-06] real.py:1 → real.py:2"
    st = _state_with(tmp_path / "at.json", [{"id": "ECC-AT", "status": "open", "title": t}])
    r = gf.scan_title_anchors(st, root)
    assert r["anchors_total"] == 1, \
        ("anchors_total 须按 _live_title 口径（旧锚 / 刷锚标记不计）", r)


# ─── arm8：mode 分化读失败 + EOF 计数法（HEAD 无 classify_anchor ⟹ 红）──────────
def test_arm8_read_failure_and_eof_count_are_mode_dependent(tmp_path):
    import gk_ecc_review as er
    assert hasattr(er, "classify_anchor"), "HEAD 无 classify_anchor ⟹ 红"
    root = _mk_repo(tmp_path, {"ff.txt": "a\fb\nc\n"})   # \f：_lines_of=2 / splitlines=3
    tgt = Path(root) / "ff.txt"
    a3 = _anchor("ff.txt", 3, 3, [])
    r_ex = er.classify_anchor(a3, tgt, "existence")
    assert r_ex["verdict"] == "line_over_eof" and r_ex.get("eof") == 2, r_ex   # 计数法 = _lines_of
    assert er.classify_anchor(a3, tgt, "content")["verdict"] != "line_over_eof", \
        "content 计数法 = splitlines（EOF=3）⟹ 不越界"
    # 读失败：existence fail-soft ⟹ ok；content fail-loud ⟹ 抛 OSError
    d = Path(root) / "adir"; d.mkdir()
    ad = _anchor("adir", 1, 1, [])
    assert er.classify_anchor(ad, d, "existence")["verdict"] == "ok", "existence 读失败须 fail-soft"
    with pytest.raises(OSError):
        er.classify_anchor(ad, d, "content")


# ─── arm9：infra 前置守卫（base 含 tri-consistency infra ⟹ 绿）────────────────
def test_arm9_infra_registers_ok_verdict():
    import gk_ecc_review as er
    assert "ok" in er._VERDICT_ORDER, "tri-consistency infra 未登记 ok ⟹ base 缺 infra"
