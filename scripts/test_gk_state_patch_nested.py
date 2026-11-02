#!/usr/bin/env python3
"""红先臂：G4 state 面 lost-update 的**叶子级写**通路。

计划：`docs/plans/2026-09-28-git-concurrency-lease-declare-plan.md` §1.3-G4 / §5 / §8 / §11。

缺陷（实测 2026-09-29）：`state-patch`(= `update-gate-data`) 在锁内做
`d["gate_data"].update(obj)` = **浅合并** ⟹ 片段里的 `edit_budget` / `overrides`
**整对象替换**；片段若取自**锁外读的陈旧快照** ⟹ **last-writer-wins**。
实测代价：并发会话额度被相互打到 0；`overrides` 由 10 条掉到 3–4（**审计留痕被抹**）。

修法（本臂钉住）：
  · `set-nested <state> <dotted-path> <json-value>`：锁内**只改定点叶子**（自动建中间对象），
    兄弟键与其它会话**一字不动**；
  · `append-list <state> <dotted-path> <json-item>`：锁内**只追加**，**不替换整表**。

HEAD 上二者皆不存在 ⟹ 七臂全**红**（断言失败，非 error）。
"""
import json
import subprocess
import sys
import threading
from pathlib import Path

SD = Path(__file__).resolve().parent.parent
SCRIPTS = SD / "scripts"
SP = SCRIPTS / "gk_state_patch.py"
PY = sys.executable


def _state(tmp: Path, edit_budget=None, overrides=None) -> Path:
    gd = {}
    if edit_budget is not None:
        gd["edit_budget"] = edit_budget
    if overrides is not None:
        gd["overrides"] = overrides
    d = {"stage": "ECO-EDIT", "r_phase": "R1", "gate_data": gd}
    p = tmp / ".gatekeeper.state"
    p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8", newline="\n")
    return p


def _run(*args):
    return subprocess.run([PY, str(SP), *args], capture_output=True, text=True, timeout=60)


def _json(p) -> dict:
    try:
        return json.loads((p.stdout or "").strip())
    except Exception:
        try:
            return json.loads((p.stdout or "").strip().splitlines()[-1])
        except Exception:
            return {}


def _load(state: Path) -> dict:
    return json.loads(state.read_text(encoding="utf-8"))


# ── arm1a：API 缺席（静态，红先）─────────────────────────────────────────────
def test_arm1a_set_nested_and_append_list_exist():
    src = SP.read_text(encoding="utf-8")
    assert "def cmd_set_nested(" in src, "缺 `cmd_set_nested`（叶子级写，G4-a）"
    assert "def cmd_append_list(" in src, "缺 `cmd_append_list`（只追加，G4-b）"
    assert "set-nested" in src, "main 派发器未注册 `set-nested`"
    assert "append-list" in src, "main 派发器未注册 `append-list`"


# ── arm1b：改叶子不动兄弟（G4 正题）────────────────────────────────────────
def test_arm1b_set_nested_does_not_clobber_siblings(tmp_path):
    st = _state(tmp_path,
                edit_budget={"sessions": {"S_A": {"max": 32, "used": 1, "remaining": 31},
                                          "S_B": {"max": 80, "used": 48, "remaining": 32}}},
                overrides=[{"k": "old-1"}, {"k": "old-2"}])
    r = _run("set-nested", str(st), "gate_data.edit_budget.sessions.S_A.max", "64")
    out = _json(r)
    assert out.get("ok") is True, f"set-nested 未生效: {out}"
    d = _load(st)
    sess = d["gate_data"]["edit_budget"]["sessions"]
    assert sess["S_A"]["max"] == 64, f"S_A.max 未改到 64: {sess['S_A']}"
    assert sess["S_A"]["used"] == 1, "**兄弟键被抹**（used 丢失）⟹ 仍是整对象替换语义"
    assert sess["S_B"] == {"max": 80, "used": 48, "remaining": 32}, \
        f"**其它会话被覆盖**（G4 本证）: {sess['S_B']}"
    assert d["gate_data"]["overrides"] == [{"k": "old-1"}, {"k": "old-2"}], \
        "overrides 被顺带替换（越权面）"


# ── arm1c：中间对象缺失时自动创建 ─────────────────────────────────────────
def test_arm1c_set_nested_creates_missing_intermediate(tmp_path):
    st = _state(tmp_path, edit_budget={"sessions": {}})
    r = _run("set-nested", str(st), "gate_data.edit_budget.sessions.S_NEW.max", "8")
    assert _json(r).get("ok") is True, f"set-nested 应自动建中间对象: {_json(r)}"
    assert _load(st)["gate_data"]["edit_budget"]["sessions"]["S_NEW"]["max"] == 8


# ── arm1d：负臂（禁碰面 fail-loud）────────────────────────────────────────
def test_arm1d_set_nested_rejects_denied_targets(tmp_path):
    st = _state(tmp_path, edit_budget={"sessions": {}})
    # 阳性对照（防假绿）：合法叶子**必须**被接受 —— 否则「全拒」也能让本臂绿。
    ok = _json(_run("set-nested", str(st), "gate_data.edit_budget.sessions.S_OK.max", "1"))
    assert ok.get("ok") is True, f"阳性对照失效：合法叶子竟被拒 → {ok}"
    for bad in ("worktrees_extra", "worktrees_extra.0",
                "_checksum", "gate_data", "gate_data.edit_budget.sessions",
                ""):
        out = _json(_run("set-nested", str(st), bad, "1"))
        assert out.get("ok") is False, f"负臂失效：`{bad}` 竟被接受 → {out}"


# ── arm1e：并发（N 进程各自写不同 sid）────────────────────────────────────
def test_arm1e_set_nested_concurrent_distinct_sessions(tmp_path):
    st = _state(tmp_path, edit_budget={"sessions": {}})
    n = 6
    procs = []

    def _spawn(i):
        procs.append(subprocess.Popen(
            [PY, str(SP), "set-nested", str(st),
             f"gate_data.edit_budget.sessions.S{i}.max", str(10 + i)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    ts = [threading.Thread(target=_spawn, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    for p in procs:
        p.wait(timeout=60)
    sess = _load(st)["gate_data"]["edit_budget"]["sessions"]
    missing = [f"S{i}" for i in range(n) if f"S{i}" not in sess]
    assert not missing, f"并发丢写（{n} 进程仅 {len(sess)} 落地）: 缺 {missing}"


# ── arm1f：append-list 只追加 ─────────────────────────────────────────────
def test_arm1f_append_list_preserves_existing(tmp_path):
    st = _state(tmp_path, overrides=[{"k": "old-1"}])
    r = _run("append-list", str(st), "gate_data.overrides", '{"k":"new-2"}')
    out = _json(r)
    assert out.get("ok") is True, f"append-list 未生效: {out}"
    ov = _load(st)["gate_data"]["overrides"]
    assert ov == [{"k": "old-1"}, {"k": "new-2"}], f"append 语义错（应只追加）: {ov}"


# ── arm1g：append-list 并发（条数 = N，留痕只增不减）──────────────────────
def test_arm1g_append_list_concurrent_no_loss(tmp_path):
    st = _state(tmp_path, overrides=[])
    n = 6
    procs = []

    def _spawn(i):
        procs.append(subprocess.Popen(
            [PY, str(SP), "append-list", str(st), "gate_data.overrides",
             json.dumps({"k": f"o{i}"})],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    ts = [threading.Thread(target=_spawn, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    for p in procs:
        p.wait(timeout=60)
    ov = _load(st)["gate_data"]["overrides"]
    got = {x.get("k") for x in ov}
    assert len(ov) == n and got == {f"o{i}" for i in range(n)}, \
        f"并发 append 丢条目（留痕被抹）: {len(ov)}/{n} → {sorted(got)}"


# ── arm-guard*：提额逃生通道「全局替换拦截」（Option1 条件式；红先）──────────────
# 缺陷（实测 2026-10-01，账本 `<state>.budget-log.jsonl` 两条 `source=state_patch`）：`update-gate-data`
#   对 `gate_data` 是**浅合并** ⟹ fragment 里一个 `edit_budget` 对象把**整份** `edit_budget`
#   （含 `sessions.*`）换掉 ⟹ 并发会话提额**砸空其它会话盒**（lost-update）。
# 修法（本臂钉住）：锁内定点校验 —— **会丢既有会话盒才拒**；无 `sessions` 或完整保留则照常。
def _two_box_budget():
    return {"max": 12, "used": 0, "remaining": 12, "overrides": [],
            "sessions": {"S_A": {"max": 4, "used": 0, "remaining": 4},
                         "S_B": {"max": 4, "used": 0, "remaining": 4}}}


def test_arm_guard_blocks_wholesale_replace_dropping_sessions(tmp_path):
    """红先①：事故复演 —— 整份替换且漏 `sessions` ⟹ 必须拒，且两盒一字不动。"""
    st = _state(tmp_path, edit_budget=_two_box_budget())
    out = _json(_run("update-gate-data", str(st),
                     '{"edit_budget":{"max":12,"used":0,"remaining":12,"overrides":[]}}'))
    assert out.get("ok") is False, f"整份替换竟被放行 ⟹ 并发会话盒被砸: {out}"
    sess = _load(st)["gate_data"]["edit_budget"]["sessions"]
    assert set(sess) == {"S_A", "S_B"}, f"会话盒丢失: {sess}"


def test_arm_guard_blocks_partial_sessions_loss(tmp_path):
    """红先②：fragment 只带部分 sessions（丢 S_B）⟹ 亦须拒。"""
    st = _state(tmp_path, edit_budget=_two_box_budget())
    out = _json(_run("update-gate-data", str(st),
                     '{"edit_budget":{"max":5,"sessions":{"S_A":{"max":4,"used":0,"remaining":4}}}}'))
    assert out.get("ok") is False, f"部分替换丢了 S_B 竟被放行: {out}"
    assert set(_load(st)["gate_data"]["edit_budget"]["sessions"]) == {"S_A", "S_B"}


def test_arm_guard_blocks_nondict_edit_budget(tmp_path):
    """红先③：把 `edit_budget` 砸成标量 ⟹ 亦须拒。"""
    st = _state(tmp_path, edit_budget=_two_box_budget())
    out = _json(_run("update-gate-data", str(st), '{"edit_budget":"oops"}'))
    assert out.get("ok") is False, f"edit_budget 被砸成标量竟放行: {out}"
    assert set(_load(st)["gate_data"]["edit_budget"]["sessions"]) == {"S_A", "S_B"}


def test_arm_guard_allows_when_no_sessions(tmp_path):
    """负臂①（守零回归）：无会话态（既有测试沙箱即此）⟹ 必须照常写入。"""
    st = _state(tmp_path, edit_budget={"max": 4, "used": 0, "remaining": 4})
    out = _json(_run("update-gate-data", str(st), '"edit_budget":{"max":9,"remaining":9}'))
    assert out.get("ok") is True, f"无会话态被误拦（回归）: {out}"
    assert _load(st)["gate_data"]["edit_budget"]["max"] == 9


def test_arm_guard_allows_empty_fragment_and_denies_list_clear(tmp_path):
    """负臂②（守既有用法 + 2026-10-18 新纪律）：`{}` 照常放行；`{"subagent_history":[]}`
    清**载荷键**列表须拒（载荷键禁经第二写面；见 `test_gk_host_write_surface.py`）。"""
    st = _state(tmp_path, edit_budget=_two_box_budget())
    assert _json(_run("update-gate-data", str(st), "{}")).get("ok") is True, "`{}` 被误拦"
    bad = _json(_run("update-gate-data", str(st), '{"subagent_history":[]}'))
    assert bad.get("ok") is False and "载荷键" in str(bad.get("error")), bad
    assert set(_load(st)["gate_data"]["edit_budget"]["sessions"]) == {"S_A", "S_B"}


def test_arm_guard_allows_explicit_full_sessions(tmp_path):
    """负臂③：fragment **显式**带全两盒 ⟹ 有意为之，放行（不得过度拦截）。

    ⚠ §17.2 路③（2026-10-07）起：**节点** `max` 受 `EDIT_BUDGET_CEILING` 夹取（单源 = gk_advance）⟹ 99 → CEILING
    （「放行」语义不变 —— `ok=True`；变的是节点值被夹取）。
    """
    st = _state(tmp_path, edit_budget=_two_box_budget())
    out = _json(_run("update-gate-data", str(st),
                     '{"edit_budget":{"max":99,"sessions":'
                     '{"S_A":{"max":4,"used":0,"remaining":4},"S_B":{"max":4,"used":0,"remaining":4}}}}'))
    assert out.get("ok") is True, f"显式带全 sessions 被误拦（过度防护）: {out}"
    assert _load(st)["gate_data"]["edit_budget"]["max"] == CEILING, "节点 max 未受 CEILING 夹取"


# ── arm-del-top*：顶层键删除通路（清误写残留；红先）──────────────────────────
# 背景：`--set-top` 只有设值、无删除 ⟹ 漏 `gate_data.` 前缀误写出的**顶层** `edit_budget`
#   （§16.4-3 残留）无正规通路可清 ⟹ 补 `del-top`（对称 set-top、同黑名单）。
def test_arm_del_top_removes_key_keeps_gate_data(tmp_path):
    """红先①：删顶层 `edit_budget` 残留 ⟹ 键消失，而 `gate_data.edit_budget` 一字不动。"""
    st = _state(tmp_path, edit_budget={"max": 4, "used": 0, "remaining": 4})
    d = _load(st)
    d["edit_budget"] = {"junk": True}          # 顶层误写残留（门不读它）
    st.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8", newline="\n")
    out = _json(_run("del-top", str(st), "edit_budget"))
    assert out.get("ok") is True and out.get("deleted") is True, f"del-top 未删除: {out}"
    after = _load(st)
    assert "edit_budget" not in after, "顶层残留未删"
    assert after["gate_data"]["edit_budget"] == {"max": 4, "used": 0, "remaining": 4}, \
        "**误删 gate_data.edit_budget**（越权面）"


def test_arm_del_top_rejects_denied_keys(tmp_path):
    """红先②：阳性对照（合法顶层键可删）+ 负臂（内部键 / gate_data / worktrees_extra / 空 必拒）。"""
    st = _state(tmp_path, edit_budget={"max": 4})
    d = _load(st)
    d["worktrees_extra"] = ["/x"]
    d["legit"] = 1
    st.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8", newline="\n")
    ok = _json(_run("del-top", str(st), "legit"))     # 阳性对照（防「全拒」也能绿）
    assert ok.get("ok") is True and ok.get("deleted") is True, f"合法顶层键竟不能删: {ok}"
    for bad in ("_checksum", "gate_data", "worktrees_extra", ""):
        out = _json(_run("del-top", str(st), bad))
        assert out.get("ok") is False, f"负臂失效：`{bad}` 竟被接受 → {out}"


def test_arm_del_top_idempotent_missing_key(tmp_path):
    """红先③：键不存在 ⟹ `deleted:false` 且**零写盘**（mtime 不变）。"""
    st = _state(tmp_path, edit_budget={"max": 4})
    before = st.stat().st_mtime_ns
    out = _json(_run("del-top", str(st), "nope_absent"))
    assert out.get("ok") is True and out.get("deleted") is False, f"缺键应幂等 no-op: {out}"
    assert st.stat().st_mtime_ns == before, "缺键竟写盘（应零写盘）"


def test_arm_del_top_cli_wired():
    """接线臂：CLI `cmd_state_patch` 必须注册 `--del-top` 并委派单源（防实现有、命令未接）。"""
    cli = (SD / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    assert "--del-top" in cli, "CLI 未注册 `state-patch --del-top` 分支"
    assert 'gk_state_patch.py" del-top' in cli, "CLI 分支未委派 `gk_state_patch.py del-top`（单源）"


# ── arm-prefix*：漏 `gate_data.` 前缀自愈（消除顶层误写残留；红先）─────────────
# 病象（实测 2026-10-03，本会话逃生舱）：`set-nested edit_budget.sessions…`（漏前缀）被写到
#   **顶层** ⟹ 只读残留，须 `--del-top` 补清（edit-budget-dual-track-plan §17.1 附带病象 /
#   §16.4-3）。修法（本臂钉住）：首段非顶层允许键（gate_data/worktree/branch）时**自动归位**
#   到 `gate_data.` 下 ⟹ 从根上消除「漏前缀 → 顶层残留 → del-top 补清」的流程摩擦。
def test_arm_prefix_selfheal_set_nested(tmp_path):
    """红先①：`set-nested edit_budget…`（漏前缀）⟹ 自愈落 `gate_data.edit_budget…`，零顶层残留。"""
    st = _state(tmp_path, edit_budget={"sessions": {}})
    r = _run("set-nested", str(st), "edit_budget.sessions.S1.max", "16")
    assert _json(r).get("ok") is True, f"漏前缀未自愈: {_json(r)}"
    d = _load(st)
    assert "edit_budget" not in d, "顶层仍残留 edit_budget（未自愈 ⟹ 须 del-top 补清）"
    assert d["gate_data"]["edit_budget"]["sessions"]["S1"]["max"] == 16


def test_arm_prefix_selfheal_append_list(tmp_path):
    """红先②：`append-list overrides`（漏前缀）⟹ 追加到 `gate_data.overrides`，零顶层残留。"""
    st = _state(tmp_path, overrides=[{"k": "old"}])
    r = _run("append-list", str(st), "overrides", '{"k":"new"}')
    assert _json(r).get("ok") is True, f"漏前缀未自愈: {_json(r)}"
    d = _load(st)
    assert "overrides" not in d, "顶层仍残留 overrides（未自愈）"
    assert d["gate_data"]["overrides"] == [{"k": "old"}, {"k": "new"}]


def test_arm_prefix_explicit_and_top_level_intact(tmp_path):
    """守回归：显式 `gate_data.` 前缀语义不变；顶层允许键（worktree）仍可写；deny 面不回退。"""
    st = _state(tmp_path, edit_budget={"sessions": {}})
    assert _json(_run("set-nested", str(st), "gate_data.edit_budget.sessions.S2.max",
                      "9")).get("ok") is True
    assert _json(_run("set-nested", str(st), "worktree", '"/w/x"')).get("ok") is True, \
        "顶层允许键 worktree 被误加前缀"
    d = _load(st)
    assert d["gate_data"]["edit_budget"]["sessions"]["S2"]["max"] == 9
    assert d["worktree"] == "/w/x"
    for bad in ("worktrees_extra", "_checksum", ""):
        assert _json(_run("set-nested", str(st), bad, "1")).get("ok") is False, \
            f"deny 面回退：`{bad}` 竟被接受"


# ── arm-file*：`@<file>` 文件通道（消除大/中文内联 argv；红先）──────────────────
# 病象：`state-patch --set-nested <a.b.c> <json>` / fragment 只能**内联 argv**，长/中文内容过
#   `wsl -e bash -lc` 会被宿主 argv 边界截断（review-runtime-subplan:1868 已登记）⟹ 稳健通道
#   = 与 `monitor --task-file` 同构的**文件读取**。约定 `@<path>`：值/条/片段从文件读（ASCII 路径）。
def test_arm_value_file_set_nested(tmp_path):
    """红先①：`@<file>` 作为 set-nested 值 ⟹ 从文件读（含中文，零内联）。"""
    st = _state(tmp_path, edit_budget={"sessions": {}})
    vf = tmp_path / "v.json"
    vf.write_text('"长中文值"', encoding="utf-8")
    r = _run("set-nested", str(st), "gate_data.edit_budget.note", "@" + str(vf))
    assert _json(r).get("ok") is True, f"@file 值未生效: {_json(r)}"
    assert _load(st)["gate_data"]["edit_budget"]["note"] == "长中文值"


def test_arm_item_file_append_list(tmp_path):
    """红先②：`@<file>` 作为 append-list 条目 ⟹ 从文件读。"""
    st = _state(tmp_path, overrides=[])
    f = tmp_path / "i.json"
    f.write_text('{"k":"中文"}', encoding="utf-8")
    r = _run("append-list", str(st), "gate_data.overrides", "@" + str(f))
    assert _json(r).get("ok") is True, f"@file item 未生效: {_json(r)}"
    assert _load(st)["gate_data"]["overrides"] == [{"k": "中文"}]


def test_arm_fragment_file(tmp_path):
    """红先③：`@<file>` 作为 update-gate-data fragment ⟹ 从文件读整份 JSON 对象。"""
    st = _state(tmp_path, edit_budget={"sessions": {}})
    f = tmp_path / "frag.json"
    f.write_text('{"ci_status":"green"}', encoding="utf-8")
    r = _run("update-gate-data", str(st), "@" + str(f))
    assert _json(r).get("ok") is True, f"@file fragment 未生效: {_json(r)}"
    assert _load(st)["gate_data"]["ci_status"] == "green"


def test_arm_file_missing_fails_loud(tmp_path):
    """守卫：`@<不存在文件>` ⟹ fail-loud（不得静默当字符串写入）。"""
    st = _state(tmp_path, edit_budget={"sessions": {}})
    out = _json(_run("set-nested", str(st), "gate_data.x", "@/no/such/file.json"))
    assert out.get("ok") is False, f"缺文件竟放行: {out}"
    assert "x" not in _load(st)["gate_data"], "缺文件竟写入残值"


# ── arm-ceiling*：§17.2 路③ state_patch 抬额夹取（owner 裁定 2026-10-07；红先）─────────
# 病象：`state-patch --set-nested gate_data.edit_budget.max 999` 逐字写入 ⟹ 在下一节点 `advance`
#   重建 `edit_budget` 之前的窗口内，CLI 预算段读 `remaining`/`max` = 999（抬额侧未夹取通道）。
# 修法：写**节点** `gate_data.edit_budget.{max,remaining}` 时 `min(候选, EDIT_BUDGET_CEILING)`。
#   · 只夹**节点**（会话盒 `sessions.*.max` 非 `max_effective` 面）；上限单源 = gk_advance。
#   ⚠ 2026-10-24：原为字面量 `24` ⟹ owner 2026-10-23 把外生上限抬到 32 后本臂 stale 红。
#     按本文件自己的接线纪律（arm 要求「禁另立常量源」）改为**导入单源**，候选 999 仍远超上限。
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
from gk_advance import EDIT_BUDGET_CEILING as CEILING  # noqa: E402


def test_arm_ceiling_set_nested_clamps_node_fields(tmp_path):
    """红先①：`set-nested` 写节点 `max`/`remaining` = 999 ⟹ 钳到 `EDIT_BUDGET_CEILING`。"""
    st = _state(tmp_path, edit_budget={"max": 4, "used": 0, "remaining": 4})
    assert _json(_run("set-nested", str(st), "gate_data.edit_budget.max", "999")).get("ok") is True
    assert _json(_run("set-nested", str(st), "gate_data.edit_budget.remaining",
                      "999")).get("ok") is True
    eb = _load(st)["gate_data"]["edit_budget"]
    assert eb["max"] <= CEILING and eb["remaining"] <= CEILING, f"节点额度未被外生上限夹取: {eb}"


def test_arm_ceiling_update_gate_data_clamps_node_fields(tmp_path):
    """红先②：`update-gate-data` fragment 带节点 `max`/`remaining` = 999 ⟹ 钳到 24。"""
    st = _state(tmp_path, edit_budget={"max": 4, "used": 0, "remaining": 4})
    out = _json(_run("update-gate-data", str(st),
                     '{"edit_budget":{"max":999,"used":0,"remaining":999}}'))
    assert out.get("ok") is True, f"无会话态被误拦（回归）: {out}"
    eb = _load(st)["gate_data"]["edit_budget"]
    assert eb["max"] <= CEILING and eb["remaining"] <= CEILING, f"节点额度未被外生上限夹取: {eb}"


def test_arm_ceiling_legal_value_and_session_untouched(tmp_path):
    """守回归：① 候选 ≤ 上限 ⟹ 逐字写入；② **会话盒** `sessions.*.max` 不在③面 ⟹ 原样。"""
    st = _state(tmp_path, edit_budget={"sessions": {}})
    _run("set-nested", str(st), "gate_data.edit_budget.max", "12")
    assert _load(st)["gate_data"]["edit_budget"]["max"] == 12, "合法节点值被误改"
    _run("set-nested", str(st), "gate_data.edit_budget.sessions.S_A.max", "64")
    assert _load(st)["gate_data"]["edit_budget"]["sessions"]["S_A"]["max"] == 64, \
        "会话盒被误夹（③ 只夹节点 max/remaining）"


def test_arm_ceiling_imports_single_source():
    """接线臂：③ 的上限须**同源** `gk_advance.EDIT_BUDGET_CEILING`（禁本文件另立数值常量）。"""
    src = SP.read_text(encoding="utf-8")
    assert "from gk_advance import EDIT_BUDGET_CEILING" in src, \
        "gk_state_patch 未从 gk_advance 取 CEILING（禁第二常量源）"
