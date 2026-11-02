"""test_anchor_verdict_unify.py — 锚判决单一源 + 处置前强制回环闸 + A v2（红先，15 臂）。

背景（2026-10-06 owner 两条追问 + 首轮 SCR 6/6 BLOCKED）：
  A = `gk_finding.scan_title_anchors`（台账标题锚，2 判决内联，**EOF 用区间右端 hi**）
  B = `gk_ecc_review.classify`（转发证据包，6 判决，**EOF 用 lo**）
  二者同走 `gk_plan_lint.iter_anchor_refs`（锚提取单一源），却各自实现判决阶梯 ⟹ 同源双实现。
  次生：处置写入口各直写台账、不先跑预检（本会话 §14.4 九条即漏）。owner 裁定：预检是
  **处理每个 ecc 前的必要流程**，不区分处置方，必须**在写入口内强制**。

首轮 SCR 缺口 → 对应臂：
  D1 EOF 口径回归（A 用 hi / B 用 lo）⟹ **arm7**（区间跨 EOF，两 mode 必须分化）
  D2 闸覆盖面漏 4 写面 ⟹ arm6（接线臂）
  D3 `--ack-drift` python 层不可达 ⟹ **arm8**
  D4 append-only 刷锚 ⟹ 永久 drifted ⟹ **arm9**（刷锚重钉替换）
  D5 闸须按 fid 过滤、不误伤无关 fid ⟹ arm4（好 state 含 2 条 finding）

二轮 SCR 缺口 → 对应臂（2026-10-06）：
  E1 `_live_title` 语义二义（剥离 ≠ 替换）⟹ **arm9**（定死 old→new 替换）
  E5 import 形态/环风险 ⟹ **arm10**（顶层无环 + 函数级 import 守卫）
  E6 `precheck_ack` 无 schema（缺 fid ⟹ reconcile 假 FAIL；带 to ⟹ 判据串扰）⟹ **arm8**（行为 + schema）

判据（Plan-1 已落后的红先基线：**4/6/8/11 红**、**1/2/3/5/7/9/10 绿**）：
  arm1 引擎 API + EOF 操作数 mode 分化契约（Plan-1 已落 ⟹ 绿）
  arm2 A 复用共享器（Plan-1 已落 ⟹ 绿）
  arm3 零回归守卫（绿）
  arm4 空转闸机（坏 fid ⟹ fail-loud；干净 fid ⟹ 放行；好 state 含 2 条 finding ⟹ 红）
  arm5 remedy 不自锁（amend_anchors 对 drifted fid 仍成功；绿）
  arm6 接线臂（_guard_precheck 在 6 入口 + main 解析 --ack-drift ⟹ 红）
  arm7 区间跨 EOF（existence 用 hi ⟹ 报；content 用 lo ⟹ 不报；Plan-1 已落 ⟹ 绿）
  arm8 --ack-drift python 层可达 + precheck_ack 事件 schema（含 fid、不含 to、对账无 anomaly）⟹ 红
  arm9 刷锚重钉替换（Plan-1 已落 ⟹ 绿）
  arm10 import 形态守卫（Plan-1 已落 ⟹ 绿）
  arm11 reconcile_pair 回滚判据取「最后一个带 to 的事件」（ack 尾插不得掩蔽回滚 ⟹ 红）

A v2（2026-10-07 折入本计划；existence 模式加字面值匹配，无字面值仍 ok ⟹ arm1/arm7 不变）：
  arm12 标题字面值命中锚区间 ⟹ hit（不计 drifted）⟹ 红
  arm13 标题字面值漂到别处 ⟹ line_drift + suggested_line ⟹ 红
  arm14 标题字面值全文无命中 ⟹ literal_missing ⟹ 红
  arm15 闸（_scan_drift/_guard_precheck）对标题字面值漂移阻断（抛 ECC_PRECHECK_DRIFT）⟹ 红

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
    assert er.classify_anchor(_anchor("scripts/demo.sh", 99, 99, []), target, "existence")["verdict"] == "line_over_eof"
    assert er.classify_anchor(a, target, "content")["verdict"] == "unverifiable"


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
    state = _state_with(tmp_path / "s3.json", [])
    assert set(gf.scan_title_anchors(state, root).keys()) == {
        "anchors_total", "findings_scanned", "drifted"}, gf.scan_title_anchors(state, root)


# ─── arm4：空转闸机（好/坏判决须不同 + 不误伤无关 fid；HEAD 无闸 ⟹ 红）─────────
def test_arm4_disposition_gate_blocks_drifted(tmp_path, monkeypatch):
    import gk_finding as gf
    root = _mk_repo(tmp_path, {"real.py": "a\nb\n"})     # EOF = 2
    monkeypatch.setattr(gf, "DEFAULT_SKILL", root, raising=False)
    bad = _state_with(tmp_path / "bad.json",
                      [{"id": "ECC-BAD", "status": "open", "title": "见 real.py:99 处"}])
    # 好 state 含 **2 条**：目标 fid 干净 + 另一条漂移（证「只扫目标 fid、不误伤无关 fid」）
    good = _state_with(tmp_path / "good.json", [
        {"id": "ECC-OK", "status": "open", "title": "见 real.py:1 处"},
        {"id": "ECC-OTHER", "status": "open", "title": "见 real.py:99 处"}])
    with pytest.raises(ValueError) as ei:
        gf.verify(bad, "ECC-BAD", True)
    assert "ECC_PRECHECK_DRIFT" in str(ei.value), ei.value
    gf.verify(good, "ECC-OK", True)                      # 目标干净 ⟹ 须放行（不误伤）
    # 内部/自动化面 = **降级放行**（§2.4-a）：drifted ⟹ 逐条跳过（不 raise），干净 ⟹ 照做
    dup_bad = _state_with(tmp_path / "dupb.json", [
        {"id": "ECC-DB", "status": "open", "title": "见 real.py:99 处"},
        {"id": "ECC-DB", "status": "closed", "title": "见 real.py:99 处"}])
    assert gf.prune_duplicates(dup_bad)["pruned"] == 0, "drifted fid 须被跳过（不清重复），且不得 raise"
    dup_ok = _state_with(tmp_path / "dupo.json", [
        {"id": "ECC-DO", "status": "open", "title": "见 real.py:1 处"},
        {"id": "ECC-DO", "status": "closed", "title": "见 real.py:1 处"}])
    assert gf.prune_duplicates(dup_ok)["pruned"] == 1, "干净 fid 须照常清理（放行其余）"


# ─── arm5：remedy 不自锁（守卫；HEAD 绿 / 落刀后必须仍绿）────────────────────
def test_arm5_gate_remedy_not_deadlocked(tmp_path, monkeypatch):
    import gk_finding as gf
    root = _mk_repo(tmp_path, {"real.py": "a\nb\n"})
    monkeypatch.setattr(gf, "DEFAULT_SKILL", root, raising=False)
    bad = _state_with(tmp_path / "bad2.json",
                      [{"id": "ECC-BAD2", "status": "open", "title": "见 real.py:99 处"}])
    r = gf.amend_anchors(bad, {"real.py:99": "real.py:1"}, apply=True)
    assert r["applied"] >= 1, r


# ─── arm6：接线臂（闸在处置入口 + main 解析 ack；HEAD 无符号 ⟹ 红）────────────
def test_arm6_gate_is_wired_into_disposition_entries():
    import gk_finding as gf
    assert hasattr(gf, "_guard_precheck"), "HEAD 无 _guard_precheck ⟹ 红"
    for fn in ("verify", "close", "reopen", "amend_title", "conflicts", "archive_closed"):
        assert "_guard_precheck" in inspect.getsource(getattr(gf, fn)), fn
    # 2 内部/自动化面（降级放行，§2.4-a）—— 硬阻断会锁死 RED 管线 / 存量清理 ⟹ 走 _precheck_degrade
    for fn in ("prune_duplicates", "upsert_red_findings"):
        assert "_precheck_degrade" in inspect.getsource(getattr(gf, fn)), fn
    assert "ack-drift" in inspect.getsource(gf.main), "main 须解析 --ack-drift（否则出口是幻影）"


# ─── arm7：区间跨 EOF —— EOF 操作数按 mode 分化（HEAD 无 classify_anchor ⟹ 红）──
def test_arm7_cross_eof_operand_is_mode_dependent(tmp_path):
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


# ─── arm8：--ack-drift 可达 + precheck_ack **事件 schema**（HEAD 无符号 ⟹ 红）────
def test_arm8_ack_drift_reachable_and_journals(tmp_path, monkeypatch):
    import gk_finding as gf
    root = _mk_repo(tmp_path, {"real.py": "a\nb\n"})
    monkeypatch.setattr(gf, "DEFAULT_SKILL", root, raising=False)
    bad = _state_with(tmp_path / "ack.json",
                      [{"id": "ECC-AB", "status": "open", "title": "见 real.py:99 处"}])
    assert gf._guard_precheck(bad, ["ECC-AB"], ack=True) is not False   # ack ⟹ 放行（不抛）
    jp = str(bad) + ".finding-journal.jsonl"
    evs = [json.loads(l) for l in open(jp, encoding="utf-8") if l.strip()]
    acks = [e for e in evs if e.get("event") == "precheck_ack"]
    assert acks, "放行须 journal 留痕 precheck_ack"
    e = acks[-1]
    # E6 schema：**必带 fid**（否则 reconcile_pair 归入 "" ⟹ 永久假 FAIL「记录被删」）
    assert str(e.get("fid") or "") == "ECC-AB", e
    # E6 schema：**禁带 to**（非状态转移；会与 reconcile_pair 的 to==st / 末事件判据串扰）
    assert "to" not in e, e
    # 对账相容：该事件不得引出 anomaly（空 fid 或本 fid）
    rp = gf.reconcile_pair(gf.load_findings(bad), evs)
    assert not any(a.get("fid") in ("", "ECC-AB") for a in rp["anomalies"]), rp
    assert "ack-drift" in inspect.getsource(gf.main)
    # ── 端到端：`--ack-drift` 须经 `main` **真实可达**（D3 幻影出口回归臂）────────────────
    #  病象：`main` 曾只把 `--ack-drift` 置 env，而 4 个 ack 默认 `False` 的面
    #  （verify/close/reopen/amend-title）显式传 `ack=False` ⟹ `_guard_precheck` 读不到 env ⟹
    #  出口在**真实调用面不可达**（源码里有 `ack-drift` 字符串但功能是幻影）。此刻直接经 `main`
    #  调用：若仍为幻影，verify 会抛 `ECC_PRECHECK_DRIFT` ⟹ `main` `sys.exit(1)` ⟹ 本臂红。
    n0 = len(evs)
    gf.main(["verify", bad, "ECC-AB", "true", "--ack-drift"])     # 不得抛 / 不得 sys.exit
    evs2 = [json.loads(l) for l in open(jp, encoding="utf-8") if l.strip()]
    assert len(evs2) > n0, evs2[n0:]
    assert any(e.get("event") == "precheck_ack" for e in evs2[n0:]), \
        "main --ack-drift 须真实放行（否则 D3 幻影出口回归）"
    assert any(e.get("event") == "verify" for e in evs2[n0:]), evs2[n0:]


# ─── arm9：刷锚段剥离（append-only 旧锚不再计入 ⟹ 无永久漂移；HEAD 无符号 ⟹ 红）──
def test_arm9_reanchor_marks_are_superseded(tmp_path):
    import gk_finding as gf
    root = _mk_repo(tmp_path, {"real.py": "a\nb\n"})     # EOF = 2
    assert gf._live_title("见 real.py:99 处") == "见 real.py:99 处"   # 无刷锚 ⟹ 恒等
    t = "见 real.py:99 处 [刷锚 2026-10-06] real.py:99 → real.py:1"
    live = gf._live_title(t)
    assert "real.py:99" not in live and "real.py:1" in live, live
    st = _state_with(tmp_path / "re.json", [{"id": "ECC-RE", "status": "open", "title": t}])
    assert gf.scan_title_anchors(st, root)["drifted"] == [], \
        "刷锚后旧锚须被重钉映射取代 ⟹ 不再永久报漂移"
    # 链式（a→b→c）：只余最终锚，中间锚(a)与旧锚均不残留
    chain = "见 real.py:99 处 [刷锚 2026-10-05] real.py:99 → real.py:1 [刷锚 2026-10-06] real.py:1 → real.py:2"
    lc = gf._live_title(chain)
    assert "real.py:99" not in lc and "real.py:1" not in lc and "real.py:2" in lc, lc


# ─── arm10：import 形态守卫（顶层无环；HEAD 无函数级 import ⟹ 红）──────────────
def _top_level_imports(path):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    mods = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            mods.add(node.module or "")
    return tree, mods


def test_arm10_import_form_is_function_level():
    gf_path = SCRIPTS / "gk_finding.py"
    er_path = SCRIPTS / "gk_ecc_review.py"
    # (a) gk_finding **顶层**不得 import gk_ecc_review（否则与 gk_plan_lint 反哺叠加成环，E5）
    gtree, gtop = _top_level_imports(gf_path)
    assert "gk_ecc_review" not in gtop, "顶层 import gk_ecc_review ⟹ 环风险（二轮 E5）"
    # (b) scan_title_anchors **函数体内**须 import gk_ecc_review（模块属性调用，禁 from-import 早绑）
    fn = next(n for n in gtree.body
              if isinstance(n, ast.FunctionDef) and n.name == "scan_title_anchors")
    inner = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Import):
            inner.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            inner.add(node.module or "")
    assert "gk_ecc_review" in inner, "scan_title_anchors 须函数级 import gk_ecc_review（禁模块级）"
    # (c) gk_ecc_review **顶层**不得 import gk_finding（反向边）
    _etree, etop = _top_level_imports(er_path)
    assert "gk_finding" not in etop, "gk_ecc_review 顶层 import gk_finding ⟹ 环"


# ─── arm11：reconcile_pair 回滚判据须取「最后一个带 to 的事件」（三轮 G3；HEAD 红）──
def test_arm11_reconcile_rollback_not_masked_by_ack(tmp_path):
    import gk_finding as gf
    # state=open，但 journal 的末「状态转移」事件是 close（to=closed）⟹ 回滚 anomaly 须被报
    findings = [{"id": "ECC-RB", "status": "open", "title": "x"}]
    events = [
        {"ts": "2026-10-06T00:00:00", "event": "close", "fid": "ECC-RB", "to": "closed"},
        # precheck_ack 无 to，尾插在 close 之后（正是闸放行留痕的形态）
        {"ts": "2026-10-06T00:01:00", "event": "precheck_ack", "fid": "ECC-RB", "drift": ["x:9"]},
    ]
    rp = gf.reconcile_pair(findings, events)
    assert any(a.get("fid") == "ECC-RB" and "回滚" in a.get("reason", "")
               for a in rp["anomalies"]), \
        ("precheck_ack 尾插不得掩蔽回滚检测（末带 to 事件=close ⟹ 须报）；", rp)


# ─── arm12：A v2 · 标题字面值命中锚区间 ⟹ hit（不计 drifted）（HEAD 红）────────
def test_arm12_title_literal_hit_is_not_drift(tmp_path):
    import gk_ecc_review as er
    import gk_finding as gf
    root = _mk_repo(tmp_path, {"real.py": "HEADER\nMARK_OK\nMARK_MOVED\n"})
    target = Path(root) / "real.py"
    a = {"ref": "real.py:2", "rel": "real.py", "lo": 2, "hi": 2,
         "doc_line": 1, "literals": ["MARK_OK"]}
    assert er.classify_anchor(a, target, "existence")["verdict"] == "hit", \
        "A v2：标题字面值命中锚区间 ⟹ hit（HEAD 仅 existence ⟹ ok ⟹ 红）"
    st = _state_with(tmp_path / "h.json",
                     [{"id": "ECC-A12", "status": "open", "title": "见 real.py:2 处 `MARK_OK`"}])
    r = gf.scan_title_anchors(st, root)
    assert r["drifted"] == [], ("hit 不得计入 drifted；", r)


# ─── arm13：A v2 · 标题字面值漂到别处 ⟹ line_drift + suggested_line（HEAD 红）──
def test_arm13_title_literal_line_drift(tmp_path):
    import gk_ecc_review as er
    import gk_finding as gf
    root = _mk_repo(tmp_path, {"real.py": "HEADER\nMARK_OK\nMARK_MOVED\n"})
    target = Path(root) / "real.py"
    a = {"ref": "real.py:1", "rel": "real.py", "lo": 1, "hi": 1,
         "doc_line": 1, "literals": ["MARK_MOVED"]}
    v = er.classify_anchor(a, target, "existence")
    assert v["verdict"] == "line_drift" and v.get("suggested_line") == 3, v
    st = _state_with(tmp_path / "d.json",
                     [{"id": "ECC-A13", "status": "open", "title": "见 real.py:1 处 `MARK_MOVED`"}])
    r = gf.scan_title_anchors(st, root)
    assert [d["verdict"] for d in r["drifted"]] == ["line_drift"], r
    assert "3" in r["drifted"][0]["detail"], r


# ─── arm14：A v2 · 标题字面值全文无命中 ⟹ literal_missing（HEAD 红）────────────
def test_arm14_title_literal_missing(tmp_path):
    import gk_ecc_review as er
    import gk_finding as gf
    root = _mk_repo(tmp_path, {"real.py": "HEADER\nMARK_OK\nMARK_MOVED\n"})
    target = Path(root) / "real.py"
    a = {"ref": "real.py:1", "rel": "real.py", "lo": 1, "hi": 1,
         "doc_line": 1, "literals": ["ABSENT_LIT"]}
    assert er.classify_anchor(a, target, "existence")["verdict"] == "literal_missing"
    st = _state_with(tmp_path / "m.json",
                     [{"id": "ECC-A14", "status": "open", "title": "见 real.py:1 处 `ABSENT_LIT`"}])
    r = gf.scan_title_anchors(st, root)
    assert [d["verdict"] for d in r["drifted"]] == ["literal_missing"], r


# ─── arm15：A v2 · 闸（_scan_drift / _guard_precheck）对标题字面值漂移阻断（HEAD 红）──
def test_arm15_gate_blocks_on_title_literal_drift(tmp_path, monkeypatch):
    import gk_finding as gf
    root = _mk_repo(tmp_path, {"real.py": "HEADER\nMARK_OK\nMARK_MOVED\n"})
    monkeypatch.setattr(gf, "DEFAULT_SKILL", root, raising=False)
    st = _state_with(tmp_path / "g.json",
                     [{"id": "ECC-A15", "status": "open", "title": "见 real.py:1 处 `MARK_MOVED`"}])
    drifted = gf._scan_drift(st, ["ECC-A15"])
    assert [d["verdict"] for d in drifted] == ["line_drift"], drifted
    with pytest.raises(ValueError, match="ECC_PRECHECK_DRIFT"):
        gf._guard_precheck(st, ["ECC-A15"], ack=False)
