"""
test_gk_plan_lint.py -- Tests for gk_plan_lint.py（W-协议确定性层 linter）
================================================================================
覆盖 `references/plan-writing-protocol.md` 七轨对位表的机检列：
L-ANCHOR / L-ASSUME / L-SWITCH / L-CONSUMER / L-CRITERION / L-NUMBER。

回归重点（对齐 F-REV-50「自伤」三类假阳性）：
① 裸 basename 锚点须按仓内索引解出；外部文件降级 info（不得升 high）；
② ASSUMPTION 只算**定义处**（引用处不计）；
③ L-NUMBER 只判**连续编号块**（跨块重复正常）；
④ L-SWITCH **排除本文档自身**（否则"提一次即命中"恒绿）。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from gk_plan_lint import (ANCHOR_REASONS, CHECK_DEP, CHECK_LABEL,  # noqa: E402
                          CHECK_PLAN_LETTER, CHECK_VERSION, check_dep_gate, check_label,
                          check_plan_letter, check_version, lint)


def _mk_repo(tmp_path, files: dict) -> Path:
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return tmp_path


def _levels(findings, check):
    return sorted(lv for c, lv, _ in findings if c == check)


# ── §17 机械依赖门（`L-DEP-FINDING`；`ECC-57A1D39ABB4E`）红先臂 ──
_DEP_DOC = "### 依赖门\n\n```json\n%s\n```\n"


def _state_with(tmp_path, fid, status):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": [
        {"id": fid, "status": status, "title": "x"}]}, "history": []}), encoding="utf-8")
    return str(st)


def test_dep_gate_open_blocks(tmp_path):
    """臂①：依赖未 close ⟹ high（⟹ main() exit 1 = §17 拒落刀）。"""
    sf = _state_with(tmp_path, "ECC-AAA", "open")
    f = []
    check_dep_gate(_DEP_DOC % '{"gate_scope":"§17","depends_on_closed":["ECC-AAA"]}', sf, f)
    assert any(c == CHECK_DEP and lv == "high" for c, lv, _ in f), f


def test_dep_gate_closed_clean(tmp_path):
    """臂②：依赖已 close ⟹ 零 high。"""
    sf = _state_with(tmp_path, "ECC-AAA", "closed")
    f = []
    check_dep_gate(_DEP_DOC % '{"gate_scope":"§17","depends_on_closed":["ECC-AAA"]}', sf, f)
    assert not [x for x in f if x[1] == "high"], f


def test_dep_gate_missing_block_zero(tmp_path):
    """臂③：缺声明块 ⟹ 零 finding（opt-in，不追溯存量计划）。"""
    f = []
    check_dep_gate("无依赖门段落的计划正文", str(tmp_path / ".gatekeeper.state"), f)
    assert f == [], f


# ── L-VERSION 口径一致性（ECC-0F4B6863913D 防复发；2026-10-07 质询回流）──
def test_version_immiscible_is_flagged():
    """同文档并存两个不同 `DRAFT-N` ⟹ 口径互斥（audit bureau §0 DRAFT-6 vs §15 DRAFT-5）。

    info 级（非阻断，先观察误报；对齐本仓「实测零误报后方升为阻断」纪律）。"""
    doc = "**状态**: DRAFT-6（收敛口径）\n\n## 15 记录\n计划状态不变：**DRAFT-5**，未立项"
    f = []
    check_version(doc, f)
    assert any(c == CHECK_VERSION and lv == "info" for c, lv, _ in f), f


def test_version_single_is_clean():
    """单一版本号 ⟹ 零 finding（零回归）。"""
    f = []
    check_version("**状态**: DRAFT-2（初稿）", f)
    assert f == [], f


def test_dep_gate_waiver_without_authorized_by_still_high(tmp_path):
    """臂④：豁免缺 `authorized_by` ⟹ 仍 high（不静默放行）。"""
    sf = _state_with(tmp_path, "ECC-AAA", "open")
    doc = _DEP_DOC % ('{"gate_scope":"§17","depends_on_closed":["ECC-AAA"],'
                      '"waiver":[{"id":"ECC-AAA","reason":"过渡态"}]}')
    f = []
    check_dep_gate(doc, sf, f)
    assert any(c == CHECK_DEP and lv == "high" for c, lv, _ in f), f


def test_dep_gate_waiver_full_grants(tmp_path):
    """臂⑤：豁免 `reason` + `authorized_by` 齐备 ⟹ 非 high（info 留痕）。"""
    sf = _state_with(tmp_path, "ECC-AAA", "open")
    doc = _DEP_DOC % ('{"gate_scope":"§17","depends_on_closed":["ECC-AAA"],'
                      '"waiver":[{"id":"ECC-AAA","reason":"过渡态",'
                      '"authorized_by":"owner-2026-10-02"}]}')
    f = []
    check_dep_gate(doc, sf, f)
    assert not [x for x in f if x[1] == "high"], f


def test_dep_gate_wired_into_lint():
    """臂⑥（结构性）：`check_dep_gate` 已挂入 `lint()` 调用链（不新增子命令）。"""
    src = (Path(__file__).parent / "gk_plan_lint.py").read_text(encoding="utf-8")
    seg = src[src.find("def lint("):]
    seg = seg[:seg.find("\n\ndef ")]
    assert "check_dep_gate(" in seg, "check_dep_gate 未挂入 lint()（门不生效）"


# ── 同批门 co_land（C1：`status ∈ {verified, closed}`；与 depends_on_closed 解耦）红先臂 ──


def test_co_land_open_blocks(tmp_path):
    """同批门（C1）：co_land 项 status=open（修复未落）⟹ high。"""
    sf = _state_with(tmp_path, "ECC-BBB", "open")
    f = []
    check_dep_gate(_DEP_DOC % '{"gate_scope":"§17","co_land":["ECC-BBB"]}', sf, f)
    assert any(c == CHECK_DEP and lv == "high" for c, lv, _ in f), f


def _with_journal(st: str, fids) -> str:
    """给 state 配 `.finding-journal.jsonl`（§17-4：co_land 的 closed 须有前序事件配对）。"""
    with open(st + ".finding-journal.jsonl", "w", encoding="utf-8") as jf:
        for fid in fids:
            jf.write(json.dumps({"event": "status", "fid": fid, "status": "closed"}) + "\n")
    return st


def test_co_land_verified_blocks(tmp_path):
    """§17-4 红先：co_land 收窄为**仅 closed** —— status=verified 在生产状态机**无写入口**
    （幻影态），须判 high（原「verified ⟹ 零 high」为幻影臂，已删）。"""
    sf = _state_with(tmp_path, "ECC-BBB", "verified")
    f = []
    check_dep_gate(_DEP_DOC % '{"gate_scope":"§17","co_land":["ECC-BBB"]}', sf, f)
    assert any(c == CHECK_DEP and lv == "high" for c, lv, _ in f), f


def test_co_land_closed_without_journal_blocks(tmp_path):
    """§17-4 红先：status=closed 但 finding-journal **无前序事件** ⟹ high（防裸 JSON 幻影 closed）。"""
    sf = _state_with(tmp_path, "ECC-BBB", "closed")
    f = []
    check_dep_gate(_DEP_DOC % '{"gate_scope":"§17","co_land":["ECC-BBB"]}', sf, f)
    assert any(c == CHECK_DEP and lv == "high" for c, lv, _ in f), f


def test_co_land_closed_ok(tmp_path):
    """同批门（C1，§17-4）：co_land 项 status=closed **且 journal 有前序事件** ⟹ 零 high。"""
    sf = _with_journal(_state_with(tmp_path, "ECC-BBB", "closed"), ["ECC-BBB"])
    f = []
    check_dep_gate(_DEP_DOC % '{"gate_scope":"§17","co_land":["ECC-BBB"]}', sf, f)
    assert not [x for x in f if x[1] == "high"], f


def test_co_land_missing_id_blocks(tmp_path):
    """同批门（C1）：co_land 项在权威源不存在 ⟹ high（幻影 id / 已删）。"""
    sf = _state_with(tmp_path, "ECC-OTHER", "closed")
    f = []
    check_dep_gate(_DEP_DOC % '{"gate_scope":"§17","co_land":["ECC-BBB"]}', sf, f)
    assert any(c == CHECK_DEP and lv == "high" for c, lv, _ in f), f


def test_co_land_absent_no_finding(tmp_path):
    """同批门：声明块无 co_land ⟹ 零 finding（与 depends_on_closed 解耦）。"""
    sf = _state_with(tmp_path, "ECC-AAA", "closed")
    f = []
    check_dep_gate(_DEP_DOC % '{"gate_scope":"§17","depends_on_closed":["ECC-AAA"]}', sf, f)
    assert f == [], f


def _details(findings, check):
    return [d for c, _, d in findings if c == check]


def _assert_clean_anchor(f):
    """F-REV-69 之后的「无问题锚」判据：**不得**报 high/medium（阻断面不变）；
    唯一的 info 只能是 `anchor_no_assertion`（仓内锚未绑断言 ⟹ 行漂移不可见）。

    注：`lint()` 的 3 元组契约**不含** reason 码（`lint` 去重后折算进 `stats`），
    故此处按该 reason 的**专属文案**判定 —— 该文案只由 ④ 块产生，无歧义。
    """
    assert not [1 for c, lv, _ in f if c == "L-ANCHOR" and lv in ("high", "medium")]
    assert all("无可校验断言" in d for d in _details(f, "L-ANCHOR"))


# ── L-ANCHOR ──────────────────────────────────────────────────────────
def test_anchor_beyond_eof_is_high(tmp_path):
    repo = _mk_repo(tmp_path, {"a.py": "x = 1\ny = 2\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 `a.py:99`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("L-ANCHOR", "high") in [(c, lv) for c, lv, _ in f]


def test_anchor_in_repo_ok(tmp_path):
    repo = _mk_repo(tmp_path, {"a.py": "x = 1\ny = 2\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 `a.py:2`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    _assert_clean_anchor(f)


def test_anchor_bare_basename_resolves(tmp_path):
    """裸 basename（仓内子目录）须按索引解出，不得误判为外部。"""
    repo = _mk_repo(tmp_path, {"sub/deep.py": "a\nb\nc\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 `deep.py:3`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    # 解出 = 不得报「外部不可定位」；只允许 F-REV-69 的无断言 info
    _assert_clean_anchor(f)
    assert not any("外部" in d for d in _details(f, "L-ANCHOR"))


def test_anchor_external_is_info_aggregated(tmp_path):
    """仓内不可定位 ⟹ info（外部引用），且按文件**聚合**为一条。"""
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("`x.ts:10` 与 `x.ts:20` 与 `y.ts:1`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    infos = [d for c, lv, d in f if c == "L-ANCHOR" and lv == "info"]
    assert len(infos) == 2  # x.ts 一条（2 处）、y.ts 一条
    assert any("x.ts：2 处" in d for d in infos)


# ── L-ANCHOR 自校验（断言字面值须与锚点同源；D2）──────────────────────
def test_anchor_symbol_binding_ok(tmp_path):
    """`file:line sym`：sym 落在锚点行 ⟹ 通过。"""
    repo = _mk_repo(tmp_path, {"a.py": "x = 1\ndef foo(): pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 `a.py:2 foo`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, "L-ANCHOR") == []


def test_anchor_symbol_drift_is_high(tmp_path):
    """`file:line sym`：sym 不在锚点行但**在本文件**他处 ⟹ 报漂移（含 offset）。"""
    repo = _mk_repo(tmp_path, {"a.py": "x = 1\ny = 2\nz = 3\ndef foo(): pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 `a.py:2 foo`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    highs = [d for c, lv, d in f if c == "L-ANCHOR" and lv == "high"]
    assert highs and any("offset +2" in d for d in highs)


def test_anchor_symbol_absent_from_file_is_info_not_silent(tmp_path):
    """断言字面值**不在所锚文件**逐字出现 ⟹ info「不可校验」（≠ 已校验）。

    2026-09-15（F-REV-67 ①）：原行为 = 静默 return（防假阳）⟹ "断言打错字"与"真错锚"
    一并逃逸（实测 `gd['ecc_findings'] = existing` 带空格 vs 代码 `=existing` 连漂 6 轮零告警）。
    现降级为 **info**（仍不阻断）——本用例即钉定该降级，防回退成静默。
    """
    repo = _mk_repo(tmp_path, {"a.py": "x = 1\ny = 2\nz = 3\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 `a.py:2 foo`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, "L-ANCHOR") == ["info"]
    assert "不可校验" in next(d for c, _, d in f if c == "L-ANCHOR")


def test_anchor_bare_symbol_ambiguous_is_info_not_silent(tmp_path):
    """裸符号锚遇**符号多义**（同符多实现）⟹ info「不可判定」（≠ 静默）。

    2026-09-15（F-REV-67 ②）：实测 `_is_retryable` 在 `gatekeeper-cli.sh` 与 `gk_monitor_api.py`
    各有一份定义（= G5 双实现）⟹ `len(defs)==2` 触发原「防假阳」静默 return，
    遂使 `_is_retryable:336` 零告警。现降级为 info，并**点出多义**（双事实源信号）。
    """
    repo = _mk_repo(tmp_path, {"a.py": "def foo(): pass\n", "b.py": "def foo(): pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 `foo:1`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, "L-ANCHOR") == ["info"]
    d = next(d for c, _, d in f if c == "L-ANCHOR")
    assert "不可判定" in d and "2 处定义" in d
    # 多义**不得**升为 high（阻断面不变：仍只判"唯一定义"的漂移）
    assert not [1 for c, lv, _ in f if c == "L-ANCHOR" and lv in ("high", "medium")]


def test_anchor_bare_symbol_not_defined_stays_silent(tmp_path):
    """符号**仓内 0 定义**（外部/散文）⟹ 仍静默（勿造噪音；防假阳口径保留）。"""
    repo = _mk_repo(tmp_path, {"a.py": "x = 1\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 `notdefinedanywhere:3`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, "L-ANCHOR") == []


def test_iter_anchor_refs_single_source_modes():
    """锚引用提取 = **单一事实源**：strict（L-ANCHOR）认 `L123`/`#L123`，loose（doc-align）不认。"""
    from gk_plan_lint import RE_ANCHOR_LOOSE, iter_anchor_refs
    strict_txt = "见 `x.py:L487` 与 `y.sh:#L12-14` 与 `z.md:9`"
    loose_txt = "见 x.py:L487 与 y.sh:#L12-14 与 z.md:9"
    s = [m.group(0) for m in iter_anchor_refs(strict_txt)]
    assert "x.py:L487" in s and "y.sh:#L12-14" in s and "z.md:9" in s
    lo = [m.group(0) for m in iter_anchor_refs(loose_txt, loose=True)]
    assert lo == ["z.md:9"], lo  # loose 保持 2026-09-13 原语义（不收 L/# 前缀）
    # 两模式共用同一实现 ⟹ 同一对象，禁再出现第二份锚正则
    assert RE_ANCHOR_LOOSE.pattern == r"([\w\-./]+\.(?:py|sh|md|json)):(\d+)(?:-(\d+))?"


# ── R-13 载体（2026-09-15）：裸行锚段级分类 + 锚类计数 ────────────────────
def test_bare_anchor_stats_splits_ledger_sections():
    """段级分类：`### 8.x` 留痕段 = ledger（记账），其余 = delivery（落刀点面）。"""
    from gk_plan_lint import bare_anchor_stats
    doc = (
        "## §2 任务表\n"
        "落刀点 `a.py:12 foo`，夹账旧值 `:99`。\n"          # delivery 1
        "### 8.1 留痕\n"
        "原记 `:111`，实测 `:222`。\n"                        # ledger 2
        "### 9.2 任务表\n"
        "又一处 `:333`。\n"                                   # delivery 1
    )
    st = bare_anchor_stats(doc)
    assert st == {"total": 4, "delivery": 2, "ledger": 2}, st


def test_lint_stats_counts_anchor_reasons_without_changing_findings(tmp_path):
    """`stats` 只增计数、**不改 findings**（阻断面与输出契约均不变）。"""
    from gk_plan_lint import lint
    repo = _mk_repo(tmp_path, {"a.py": "def foo():\n    return 1\n\n\nx = 1\n",
                               "b.py": "def foo():\n    return 2\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("`a.py:5 nosuchliteral`；裸符号 `foo:9`；`a.py:99`。\n", encoding="utf-8")
    st = {}
    f1 = lint(str(plan), str(repo))
    f2 = lint(str(plan), str(repo), st)
    assert f1 == f2, "stats 不得改变 findings"
    cnt = st["anchor_findings"]
    assert cnt.get("literal_absent_from_file") == 1, cnt   # F-REV-67 ①（info，原静默）
    assert cnt.get("symbol_ambiguous") == 1, cnt           # F-REV-67 ②（`foo` 两处定义）
    assert cnt.get("line_over_eof") == 1, cnt              # a.py:99 越界
    assert set(cnt) <= set(ANCHOR_REASONS), cnt
    # **计数须与可见条数恒等**（去重后计）—— 初版按 append 事件计 ⟹ 曾出现 22 vs 可见 17
    assert sum(cnt.values()) == sum(1 for c, _, _ in f2 if c == "L-ANCHOR"), (cnt, f2)


def test_anchor_stats_are_post_dedup(tmp_path):
    """同一锚写两次 ⟹ 可见 1 条 ⟹ 计数也须为 1（防"计数 ≠ 显示"的第二事实源）。"""
    from gk_plan_lint import lint
    repo = _mk_repo(tmp_path, {"a.py": "".join(f"x = {i}\n" for i in range(1, 7))})
    plan = tmp_path / "plan.md"
    plan.write_text("`a.py:5 nosuchlit`\n\n`a.py:5 nosuchlit`\n", encoding="utf-8")
    st = {}
    f = lint(str(plan), str(repo), st)
    vis = [x for x in f if x[0] == "L-ANCHOR"]
    assert len(vis) == 1, vis
    assert st["anchor_findings"] == {"literal_absent_from_file": 1}, st


def test_stats_flag_prints_json_and_exits_zero(tmp_path, monkeypatch, capsys):
    """`--stats` = 只读口径：打印 JSON 且 **exit 0**（即便存在 high findings）。"""
    import json
    import gk_plan_lint as G
    repo = _mk_repo(tmp_path, {"a.py": "x = 1\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 `a.py:99` 与 `:42`。\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv",
                        ["gk_plan_lint.py", str(plan), "--repo", str(repo), "--stats"])
    rc = G.main()
    out = json.loads(capsys.readouterr().out)
    assert rc == 0, "--stats 不得把 findings 折算成非零退出码"
    assert out["bare_anchor"] == {"total": 1, "delivery": 1, "ledger": 0}, out
    assert out["anchor_findings"].get("line_over_eof") == 1, out


def test_doc_align_single_source_is_function_level_not_constant():
    """REV-11 arm-2 处置：单源须为**函数级** —— doc-align 只以 `loose=True` 调 `iter_anchor_refs`。

    原实现 `from gk_plan_lint import RE_ANCHOR_LOOSE as _ANCHOR_REF_RE`（再自跑 `finditer`）=
    **常量级**单源：`loose` 语义一旦为该收口 F-REV-68 而变，本模块即静默停在旧语义 ⟹
    与 `gk_plan_lint` 自述「两消费者只允许通过 `iter_anchor_refs()` 取锚」矛盾。
    """
    import gk_doc_align
    assert hasattr(gk_doc_align, "iter_anchor_refs")
    assert not hasattr(gk_doc_align, "_ANCHOR_REF_RE")  # 禁私有常量副本


def test_anchor_bare_symbol_def_match_ok(tmp_path):
    """裸符号锚 `sym:line`：line == 定义处 ⟹ 通过。"""
    repo = _mk_repo(tmp_path, {"a.py": "x = 1\ndef foo(): pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 `foo:2`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, "L-ANCHOR") == []


def test_anchor_bare_symbol_def_mismatch_is_high(tmp_path):
    """裸符号锚：line != 唯一定义处 ⟹ 报（行锚漂移/绑错）。"""
    repo = _mk_repo(tmp_path, {"a.py": "x = 1\ndef foo(): pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 `foo:9`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("L-ANCHOR", "high") in [(c, lv) for c, lv, _ in f]


def test_anchor_following_code_fragment_drift_is_high(tmp_path):
    """紧随括号内代码片段（含空格/运算符）也参与自校验。"""
    repo = _mk_repo(tmp_path, {"a.py": "x = 1\ny = 2\nz = 3\nbreak 2\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 `a.py:1`（**成功分支 `break 2`**）。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    highs = [d for c, lv, d in f if c == "L-ANCHOR" and lv == "high"]
    assert highs and any("offset +3" in d for d in highs)


def test_anchor_operator_only_fragment_skipped(tmp_path):
    """纯运算符片段（如 ` + `）**不得**被当作断言字面值 ⟹ 不报漂移（防假阳）。

    F-REV-69 起，此类锚因「无断言绑定」另报一条 *info*（`anchor_no_assertion`），
    但**不得**升为 high/medium —— 本测试守的正是这条边界。"""
    repo = _mk_repo(tmp_path, {"a.py": "x = 1\ny = 2\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 `a.py:1`（` + `）。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    _assert_clean_anchor(f)


def test_anchor_prose_fragment_skipped(tmp_path):
    """散文片段（如 ` vs `）**不得**被当作代码字面值 ⟹ 不报漂移（防假阳）。

    同 `test_anchor_operator_only_fragment_skipped`：只允许 F-REV-69 的 info。"""
    repo = _mk_repo(tmp_path, {"a.py": "x = 1\ny = 2\nz = 3\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("见 `a.py:1` vs `a.py`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    _assert_clean_anchor(f)


# ── L-ASSUME ──────────────────────────────────────────────────────────
def test_assume_duplicate_definition_is_high(tmp_path):
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("- `[ASSUMPTION-5]` 甲\n- `[ASSUMPTION-5]` 乙\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("L-ASSUME", "high") in [(c, lv) for c, lv, _ in f]


def test_assume_reference_not_counted(tmp_path):
    """引用处（非行首 bullet 定义）不得计入撞号。"""
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("- `[ASSUMPTION-5]` 甲\n\n见 §7 的 [ASSUMPTION-5] 说明。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, "L-ASSUME") == []


# ── L-SWITCH ──────────────────────────────────────────────────────────
def test_switch_absent_outside_doc_is_high(tmp_path):
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("新增 `GK_FOO_BAR` 开关。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("L-SWITCH", "high") in [(c, lv) for c, lv, _ in f]


def test_switch_existing_in_repo_ok(tmp_path):
    repo = _mk_repo(tmp_path, {"a.py": 'GK_FOO_BAR = "1"\n'})
    plan = tmp_path / "plan.md"
    plan.write_text("复用 `GK_FOO_BAR`。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, "L-SWITCH") == []


def test_switch_in_table_ok(tmp_path):
    """本文档 §6 显式登记（表格行）即视为有默认值 ⟹ 不报。"""
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("新增 `GK_NEW_ONE`。\n\n| 开关 | 默认 |\n|:--|:--|\n| `GK_NEW_ONE` | 0 |\n",
                    encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, "L-SWITCH") == []


# ── L-CONSUMER ────────────────────────────────────────────────────────
def test_consumer_overclaim_is_medium(tmp_path):
    repo = _mk_repo(tmp_path, {
        "gk_mod.py": "def f(): pass\n",
        "c1.py": "from gk_mod import f\n",
    })
    plan = tmp_path / "plan.md"
    plan.write_text("`gk_mod` 被 **3** 消费者消费。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("L-CONSUMER", "medium") in [(c, lv) for c, lv, _ in f]


def test_consumer_indented_import_counted(tmp_path):
    """缩进 import（函数体内）须计入，防少算。"""
    repo = _mk_repo(tmp_path, {
        "gk_mod.py": "def f(): pass\n",
        "c1.py": "def g():\n    from gk_mod import f\n    return f\n",
    })
    plan = tmp_path / "plan.md"
    plan.write_text("`gk_mod` 被 **1** 消费者消费。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, "L-CONSUMER") == []


# ── L-CRITERION ───────────────────────────────────────────────────────
def test_criterion_without_command_is_medium(tmp_path):
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("## §3 验收判据\n1. **行为正确**：系统表现良好。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("L-CRITERION", "medium") in [(c, lv) for c, lv, _ in f]


def test_criterion_with_command_ok(tmp_path):
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("## §3 验收判据\n1. **回归**：`pytest test_x.py -k foo` 全绿。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, "L-CRITERION") == []


# ── L-NUMBER ──────────────────────────────────────────────────────────
def test_number_duplicate_in_run_is_medium(tmp_path):
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("1. 甲\n2. 乙\n2. 丙\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("L-NUMBER", "medium") in [(c, lv) for c, lv, _ in f]


def test_number_cross_run_duplicate_ok(tmp_path):
    """两个独立编号块各从 1 开始 ⟹ 正常，不得报。"""
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("1. 甲\n2. 乙\n\n正文\n\n1. 丙\n2. 丁\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, "L-NUMBER") == []


# ── L-META（F8 元数据）──────────────────────────────────────────────────
_META_OK = ("<!-- META\nphases: ECO-SCAN\n"
            "target_repo: skill\nproject_type: standing\nworktree_needed: false\n"
            "state_domain: skill.plan-ok\n-->\n\n# T\n")


def test_meta_missing_block_is_high(tmp_path):
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("# 无 META 的计划\n\n正文\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("L-META", "high") in [(c, lv) for c, lv, _ in f]


def test_meta_phases_empty_is_high(tmp_path):
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("<!-- META\ntarget_repo: skill\nproject_type: standing\n"
                    "worktree_needed: false\n-->\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("L-META", "high") in [(c, lv) for c, lv, _ in f]


def test_meta_missing_field_is_medium(tmp_path):
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("<!-- META\nphases: ECO-SCAN\n-->\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    lv = [(c, l) for c, l, _ in f]
    assert ("L-META", "medium") in lv
    assert ("L-META", "high") not in lv


# ── §17-6 P2：依赖门**位置无关**（同一 commit 主树/worktree 判决一致）红先臂 ──


def _git(args):
    import subprocess
    subprocess.run(["git"] + args, check=True, capture_output=True)


def _mk_git_worktree(tmp_path):
    """建 main（含 commit）+ 其 linked worktree，返回 (main, wt)。"""
    main = tmp_path / "gmain"
    main.mkdir()
    _git(["-C", str(main), "init", "-q"])
    _git(["-C", str(main), "config", "user.email", "t@t"])
    _git(["-C", str(main), "config", "user.name", "t"])
    (main / "docs" / "plans").mkdir(parents=True)
    (main / "docs" / "plans" / "p.md").write_text("# p\n", encoding="utf-8")
    _git(["-C", str(main), "add", "-A"])
    _git(["-C", str(main), "commit", "-q", "-m", "init"])
    wt = tmp_path / "gwt"
    _git(["-C", str(main), "worktree", "add", "-q", str(wt)])
    return main, wt


def test_resolve_state_file_prefers_env(tmp_path, monkeypatch):
    st = tmp_path / "s.state"
    st.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("STATE_FILE", str(st))
    from gk_plan_lint import _resolve_state_file
    assert _resolve_state_file(str(tmp_path)) == str(st)


def test_resolve_state_file_non_git_repo_falls_back(tmp_path, monkeypatch):
    monkeypatch.delenv("STATE_FILE", raising=False)
    from gk_plan_lint import _resolve_state_file
    assert _resolve_state_file(str(tmp_path)) == str(tmp_path / ".gatekeeper.state")


def test_resolve_state_file_uses_main_worktree_root(tmp_path, monkeypatch):
    """worktree 里解析 state ⟹ 指向**主 worktree** 的 state，而非不存在的 worktree state（P2 核心）。"""
    monkeypatch.delenv("STATE_FILE", raising=False)
    main, wt = _mk_git_worktree(tmp_path)
    from gk_plan_lint import _resolve_state_file
    got = _resolve_state_file(str(wt))
    assert got == str(main / ".gatekeeper.state"), got


def test_lint_dep_verdict_position_independent(tmp_path, monkeypatch):
    """同一 plan 在**主树与 worktree** 跑 lint ⟹ `L-DEP-FINDING` 判决一致（P2 判据）。"""
    monkeypatch.delenv("STATE_FILE", raising=False)
    main, wt = _mk_git_worktree(tmp_path)
    (main / ".gatekeeper.state").write_text(
        json.dumps({"gate_data": {"ecc_findings": [{"id": "ECC-AAA", "status": "closed"}]},
                    "history": []}), encoding="utf-8")
    plan = main / "docs" / "plans" / "dep.md"
    plan.write_text(_DEP_DOC % '{"gate_scope":"§17","depends_on_closed":["ECC-AAA"]}',
                    encoding="utf-8")
    dep_main = sorted(d for c, _, d in lint(str(plan), str(main)) if c == CHECK_DEP)
    dep_wt = sorted(d for c, _, d in lint(str(plan), str(wt)) if c == CHECK_DEP)
    assert dep_main == dep_wt, (dep_main, dep_wt)
    assert not [x for x in lint(str(plan), str(wt)) if x[0] == CHECK_DEP and x[1] == "high"]


def test_meta_complete_ok(tmp_path):
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text(_META_OK, encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, "L-META") == []


def test_meta_worktree_true_without_state_domain_is_medium(tmp_path):
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text("<!-- META\nphases: ECO-SCAN\ntarget_repo: skill\n"
                    "project_type: standard\nworktree_needed: true\n-->\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("L-META", "medium") in [(c, lv) for c, lv, _ in f]


# ── P16（2026-10-01：**已撤销**）—— 原两条臂随规则一并移除。
#   撤销理由见 `gk_plan_lint.py::check_meta` 注释（① 判据重载 `worktree_needed`；② META 双清单漂移）。
#   规则本体已不存在 ⟹ 保留这两条臂只会变成**恒绿的幻影臂**（有臂无规则 = 无判别力），故删除。


# ── L-SYMBOL（符号撞车）────────────────────────────────────────────────
def _sym_doc(rows, meta=True):
    head = _META_OK if meta else ""
    tbl = ("| 符号 | 专有名称 | 定义 |\n|:--|:--|:--|\n"
           + "".join(f"| `{s}` | {n} | d |\n" for s, n in rows))
    return head + tbl


def test_symbol_table_collision_is_high(tmp_path):
    """同一符号两个专有名称 ⟹ 撞车（high）。"""
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text(_sym_doc([("ρ", "任务重叠度"), ("ρ", "缺陷衰减率")]), encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("L-SYMBOL", "high") in [(c, lv) for c, lv, _ in f]


def test_hashl_only_mode_does_not_widen_loose():
    """A2 冻结面钉子（ECC-F68E6BEE4F68）：loose 口径对 `#L` **永不**命中 —— 防日后有人顺手
    开宽 `RE_ANCHOR_LOOSE` 而抬高 doc-align 的漂移计数（会撞冻结基线）；`#L` 的可见性只走
    `hashl_only=True` 这条**新口径**，两条口径的召回面**互不重叠**（`path:L` vs `path#L`）。"""
    from gk_plan_lint import iter_anchor_refs
    assert not list(iter_anchor_refs("见 `a.py#L10`", loose=True))
    assert not list(iter_anchor_refs("见 `a.py#L10-L12`", loose=True))
    m = list(iter_anchor_refs("见 `a.py#L10-L12`", hashl_only=True))
    assert [(x.group(1), x.group(2), x.group(3)) for x in m] == [("a.py", "10", "12")]


def test_symbol_name_on_two_syms_is_medium(tmp_path):
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text(_sym_doc([("g", "净消解密度"), ("γ", "净消解密度")]), encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("L-SYMBOL", "medium") in [(c, lv) for c, lv, _ in f]


def test_symbol_unique_table_ok(tmp_path):
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text(_sym_doc([("J", "任务重叠度"), ("ρ", "缺陷衰减率")]), encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, "L-SYMBOL") == []


def test_symbol_no_table_is_quiet(tmp_path):
    """无符号表 ⟹ 不报（避免散落正文的希腊符噪声）。"""
    repo = _mk_repo(tmp_path, {"a.py": "pass\n"})
    plan = tmp_path / "plan.md"
    plan.write_text(_META_OK + "正文含 ρ 与 g，但无符号表。\n", encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert _levels(f, "L-SYMBOL") == []


def test_symbol_cross_doc_collision_is_high(tmp_path):
    """跨文档同符号异名 ⟹ high（带来源文档名）。"""
    repo = _mk_repo(tmp_path, {
        "docs/plans/peer.md": _sym_doc([("ρ", "任务重叠度")]),
        "a.py": "pass\n",
    })
    plan = tmp_path / "plan.md"
    plan.write_text(_sym_doc([("ρ", "缺陷衰减率")]), encoding="utf-8")
    f = lint(str(plan), str(repo))
    assert ("L-SYMBOL", "high") in [(c, lv) for c, lv, _ in f]


# ── 悬空标签（L-LABEL，2026-10-04）──────────────────────────────────────────
def test_dangling_label_is_medium():
    """段标题尾部「（D7）」但全文无 `D1` ⟹ medium（悬空）。"""
    f = []
    check_label("# t\n\n## §8 预算（D7）\n\n正文\n", f)
    assert any(c == CHECK_LABEL and lv == "medium" for c, lv, _ in f), f


def test_label_defined_series_ok():
    """同族基标签 `D1` 在文中出现 ⟹ 不报（编号表已定义）。"""
    f = []
    check_label("## §2.1 D1 设计\n\n## §8 预算（D7）\n", f)
    assert not [x for x in f if x[0] == CHECK_LABEL], f


def test_label_base_and_prose_quiet():
    """`（D1）` 基标签 + 散文括号 `（治四轮⑤…）` ⟹ 均不报。"""
    f = []
    check_label('## §1 范围（D1）\n\n### §2.4 x（治四轮⑤"未泛化"）\n', f)
    assert not [x for x in f if x[0] == CHECK_LABEL], f


def test_label_not_at_heading_tail_quiet():
    """标签不在标题尾部（内嵌）⟹ 不报（窄口径防误报）。"""
    f = []
    check_label("## §8 预算（D7）与其它\n", f)
    assert not [x for x in f if x[0] == CHECK_LABEL], f


# ── PW-13 下发门预演（F3，2026-10-15；D §14.7 F-D 回流）红先臂 ──
#   缺口：`plan-lint`（PW-SN）与下发门（`gk_task_gate`）此前**不在同一条链** ⟹ 计划交付
#   全绿，下发却因 novel_phrase / 语料不可读 / 状态域落错被拒，只能人工反复拼命令试。
def test_dispatch_readiness_flags_ungrounded_task(tmp_path):
    """F3 臂①：交付前以「将下发的 task」预演下发门 —— 未在语料可证的专名/长串须在
    **plan-lint** 阶段即报 `PW-DISPATCH` high（而非到 `plan-refinement --task` 才被拒）。"""
    from gk_plan_lint import CHECK_PW_DISPATCH, check_dispatch_readiness
    repo = _mk_repo(tmp_path, {"docs/a.md": "本计划只描述既有实现。\n"})
    plan = str(repo / "docs" / "a.md")
    f = []
    check_dispatch_readiness(plan, str(repo), f, task="重构并新增 MCP 兜底通道")
    assert any(c == CHECK_PW_DISPATCH and lv == "high" for c, lv, _ in f), f


def test_dispatch_readiness_opt_in_when_task_empty(tmp_path):
    """F3 臂②：`task` 缺省空 ⟹ 零 finding（opt-in，不追溯存量计划；零回归）。"""
    from gk_plan_lint import check_dispatch_readiness
    repo = _mk_repo(tmp_path, {"docs/a.md": "正文"})
    f = []
    check_dispatch_readiness(str(repo / "docs" / "a.md"), str(repo), f)
    assert f == [], f


def test_dispatch_readiness_state_domain_miss(tmp_path, monkeypatch):
    """F3 臂③：计划声明 `state_domain` 但默认路由**未命中该域** ⟹ 报 `PW-DISPATCH`
    （状态路由预演），避免「声明域却下发落基 state」静默退化。"""
    import gk_route_center as rc
    from gk_plan_lint import CHECK_PW_DISPATCH, check_dispatch_readiness
    repo = _mk_repo(tmp_path, {
        "docs/a.md": "<!-- META state_domain: skill.some-domain -->\n正文\n"})
    monkeypatch.setattr(rc, "resolve_state", lambda *a, **k: {
        "source": "current", "current": "/x/.gatekeeper.state",
        "expected": "/x/.gatekeeper.state", "domain": "skill.some-domain"})
    f = []
    check_dispatch_readiness(str(repo / "docs" / "a.md"), str(repo), f, task="正文")
    assert any(c == CHECK_PW_DISPATCH for c, _, _ in f), f


def test_dispatch_readiness_wired_into_lint():
    """F3 臂④（结构性）：`check_dispatch_readiness` 已挂入 `lint()` 调用链。"""
    src = (Path(__file__).parent / "gk_plan_lint.py").read_text(encoding="utf-8")
    seg = src[src.find("def lint("):]
    seg = seg[:seg.find("\n\ndef ")]
    assert "check_dispatch_readiness(" in seg, "check_dispatch_readiness 未挂入 lint()（门不生效）"


# ── 跨计划任务号前缀（L-PLAN-LETTER，2026-10-16；`ECC-F5255744DDD3`）红先臂 ──
#   缺口：C 计划 §5 / 归档 subagent 报告里裸写 `T13` ⟹ 读者无法判归属（C 计划？计划 B？），
#   本会话实测把**计划 B 的 T13** 误当成**C 计划 T13** 归档。判据（窄口径防误报）：同一行
#   须**同时**命中「**别的**计划文件名」与「**裸**任务号 `T<n>`」才 medium。
_OTHER_PLAN = "2026-10-12-w2a-p2-phase-experiment-plan.md"
_SELF_PLAN = "2026-10-14-moa-chain-automation-plan.md"


def test_cross_plan_bare_task_is_medium():
    """臂①（**红先**）：同行引用**别的**计划 + 裸 `` `T13` `` ⟹ medium（归属不明）。"""
    f = []
    check_plan_letter(f"见 {_OTHER_PLAN} 的 `T13`\n", f, _SELF_PLAN)
    assert any(c == CHECK_PLAN_LETTER and lv == "medium" for c, lv, _ in f), f


def test_plan_letter_prefix_quiet():
    """臂②：同行带**计划字母前缀** `` `C-T13` `` ⟹ 不报（已显式归属）。"""
    f = []
    check_plan_letter(f"见 {_OTHER_PLAN} 的 `C-T13`\n", f, _SELF_PLAN)
    assert not [x for x in f if x[0] == CHECK_PLAN_LETTER], f


def test_self_plan_bare_task_quiet():
    """臂③：同行引用**本文件自己**的文件名 + 裸 `` `T13` `` ⟹ 不报（本计划内合法）。"""
    f = []
    check_plan_letter(f"见 {_SELF_PLAN} 的 `T13`\n", f, _SELF_PLAN)
    assert not [x for x in f if x[0] == CHECK_PLAN_LETTER], f


def test_cross_plan_dash_task_quiet():
    """臂④：同行别的计划 + `§3-T13`（`T` 前为 `-`）⟹ 不报（窄口径防误报）。"""
    f = []
    check_plan_letter(f"见 {_OTHER_PLAN} 的 §3-T13\n", f, _SELF_PLAN)
    assert not [x for x in f if x[0] == CHECK_PLAN_LETTER], f


def test_plan_letter_wired_into_lint():
    """臂⑤（结构性）：`check_plan_letter` 已挂入 `lint()` 调用链。"""
    src = (Path(__file__).parent / "gk_plan_lint.py").read_text(encoding="utf-8")
    seg = src[src.find("def lint("):]
    seg = seg[:seg.find("\n\ndef ")]
    assert "check_plan_letter(" in seg, "check_plan_letter 未挂入 lint()（门不生效）"
