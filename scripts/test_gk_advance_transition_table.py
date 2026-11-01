"""T9 两问的机检臂（2026-10-31 owner 裁定）。

覆盖三条**互不同源**的契约，故意放在一个文件里 —— 它们都是同一次裁定的产物，
拆开会让「删一半」在测试面也复现：

1. **转换表自洽**（`CRITICAL_TRANSITIONS ⊆ 合法转换` + `_structural_gates` 覆盖全边）
   —— owner 原话：「防以后再次『删一半』」。运行时断言只管白名单不含非法边；
   真正防「删了分支但表没改」的是本文件的 AST 臂（`:A3`）。
2. **force 必须落 finding**（不得静默免票）—— 对齐熵门 `entropy_history[forced=True]`。
3. **dry_run 零副作用但不是零判定** —— 原状 `if force or dry_run: return None`
   把 dry_run 吞成静默通过 ⟹ `--dry-run` 预演假绿（说能过，真跑被拦）。

红先说明：本文件在改动前应**全红**（`:A3` 因 `gn_stale` 仍在而绿、其余红），
改动后全绿。断言均直接读 state 落库结果，不 mock 内部分支。
"""
import ast
import hashlib
import json
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_advance  # noqa: E402
from gk_advance import _run  # noqa: E402


# ─── 夹具 ──────────────────────────────────────────────────────────────────

def _cs(gate_data):
    return hashlib.sha256(json.dumps(gate_data, sort_keys=True).encode()).hexdigest()[:16]


def _write_state(path, stage, gate_data=None, branch="feature/r1", worktree="/tmp/wt",
                 r_phase="R1", **extra):
    d = {"r_phase": r_phase, "stage": stage, "branch": branch, "worktree": worktree,
         "gate_data": gate_data or {}, "monitor_scores": {}, "history": []}
    d.update(extra)
    d["_checksum"] = _cs(d["gate_data"])
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    return str(path)


def _ok_env(**over):
    env = {"worktree_exists": True, "wt_registered": True, "uncommitted": "",
           "stash_count": 0, "ci_trigger": 1, "detect_changes": 0,
           "diff_files": "src/main.cc", "plan_backup_exists": True,
           "merge_check": True, "gn_up_to_date": True, "edit_used": 0}
    env.update(over)
    return env


def _advance(tmp_path, from_stage, to_stage, *, force=False, dry_run=False,
             score=None, env=None):
    sf = _write_state(tmp_path / "s.json", from_stage)
    mj = None if score is None else {"score": score, "mode": "local"}
    r = _run(sf, to_stage, force=force, dry_run=dry_run,
             env=env if env is not None else _ok_env(), monitor_json=mj,
             cc={}, remote="", skill_dir=str(tmp_path))
    with open(sf, encoding="utf-8") as f:
        return r, json.load(f)


# ─── A. 转换表自洽（防「删一半」）────────────────────────────────────────────

def test_a1_critical_transitions_subset_of_valid():
    """运行时断言面：`CRITICAL_TRANSITIONS ⊆ VALID_STANDARD_TRANSITIONS` 且无非法项。

    这是 owner 明确要求加的那条。`_ILLEGAL_CRITICAL` 是 module-load 断言的实际载体，
    它非空时 import 即 raise ⟹ 能跑到这一行本身就是「没漂移」的证据；仍显式断言集合关系，
    防将来有人把 raise 降级成 warning 而不报错。
    """
    assert gk_advance._ILLEGAL_CRITICAL == []
    assert set(gk_advance.CRITICAL_TRANSITIONS) <= set(gk_advance.VALID_STANDARD_TRANSITIONS)


def test_a2_valid_transitions_derived_from_route_map():
    """合法集必须**派生**自 `route_map("standard")`，不得是第二份手写清单。"""
    rm = gk_advance.route_map("standard")
    assert rm["ok"] is True
    nodes = rm["nodes"]
    expect = [f"{a}→{b}" for a, b in zip(nodes, nodes[1:])]
    assert gk_advance.VALID_STANDARD_TRANSITIONS == expect


def _explicit_branches(src: str = "") -> set:
    """AST 抽 `_structural_gates` 的显式分支 `current == X and to == Y`。

    `src` 可传入替代源码，用于 `test_a3b` 的**判别力**自证（喂一段「删掉一条边」的源码，
    断言抽取器真能报出该边缺失）—— 否则本臂可能因抽取器恒空而假绿。
    """
    if not src:
        src = (SCRIPT_DIR / "gk_advance.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_structural_gates")
    out = set()
    for node in ast.walk(fn):
        if not (isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And)):
            continue
        got = {}
        for v in node.values:
            if (isinstance(v, ast.Compare) and len(v.comparators) == 1
                    and isinstance(v.left, ast.Name) and v.left.id in ("current", "to")
                    and isinstance(v.comparators[0], ast.Constant)
                    and isinstance(v.comparators[0].value, str)):
                got[v.left.id] = v.comparators[0].value
        if "current" in got and "to" in got:
            out.add(f"{got['current']}→{got['to']}")
    assert out, "AST 未抽到任何显式分支 ⟹ 锚失效（_structural_gates 被改名/重构？）"
    return out


def test_a3b_ast_arm_detects_a_removed_branch():
    """**判别力自证**：喂一段「删掉 STAGE_5→DONE 分支」的源码，抽取器必须报出该边缺失。

    没有这一臂，`test_a3` 的绿可能只是「两边都空」—— 而空集合的相等永远成立。
    """
    src = (SCRIPT_DIR / "gk_advance.py").read_text(encoding="utf-8")
    marker = 'elif current == "STAGE_5" and to == "DONE":'
    assert marker in src, "锚失效：_structural_gates 的 5→DONE 分支写法变了"
    # 把该分支的条件改成永假（等价于删掉这条边，但保留语法结构）
    mutated = src.replace(marker,
                          'elif current == "STAGE_5" and to == "__REMOVED__":')
    got = _explicit_branches(mutated)
    assert "STAGE_5→DONE" not in got
    assert set(gk_advance.VALID_STANDARD_TRANSITIONS) - got == {"STAGE_5→DONE"}, \
        "抽取器未能把「删一条边」精确报成唯一缺失 ⟹ 判别力不足"


def test_a3_structural_gates_covers_every_valid_transition():
    """**防「删一半」的核心臂**：`_structural_gates` 的显式分支集 == 合法转换集。

    只删分支不改 `CRITICAL_TRANSITIONS`（T9 的原定动作）会让 `(STAGE_5, DONE)` 落入
    兜底 `FAIL:unknown transition` —— 该臂即在此处变红，并把缺的边名报出来。
    """
    branches = _explicit_branches()
    valid = set(gk_advance.VALID_STANDARD_TRANSITIONS)
    missing = valid - branches
    extra = branches - valid
    assert not missing, f"_structural_gates 缺分支：{sorted(missing)}（删一半？）"
    assert not extra, f"_structural_gates 有非合法分支：{sorted(extra)}"


def test_a4_done_is_still_a_registered_node():
    """owner 裁定「DONE 要留」：`DONE` 必须在 standard 节点表里（删了就没有合法出口）。"""
    assert "DONE" in gk_advance.route_map("standard")["nodes"]


# ─── B. force 必须落 finding（不得静默免票）────────────────────────────────

def test_b1_force_low_score_records_monitor_history(tmp_path):
    """force + 低分 ⟹ 放行，但 `monitor_history` 落一条 `forced=True`（对齐熵门形态）。"""
    r, st = _advance(tmp_path, "STAGE_5", "DONE", force=True, score=0.3)
    assert r.get("allowed") is True, r
    hist = st["gate_data"].get("monitor_history") or []
    assert len(hist) == 1, f"force 放行未留痕：{st['gate_data']}"
    h = hist[0]
    assert h["forced"] is True
    assert h["score"] == 0.3
    assert h["stage"] == "STAGE_5"
    assert h["transition"] == "DONE"
    assert h.get("advisory") == "monitor_low_score"   # M1：测量面只出 advisory


def test_b2_force_does_not_pollute_rejected_edits(tmp_path):
    """放行记录不得混进 `rejected_edits` —— 那是会被回灌给下一轮的「被拒」上下文。"""
    r, st = _advance(tmp_path, "STAGE_5", "DONE", force=True, score=0.3)
    assert r.get("allowed") is True
    assert not (st["gate_data"].get("rejected_edits") or []), \
        "force 放行被误记为 rejected_edits ⟹ 下一轮上下文被污染"


def test_b3_force_high_score_records_nothing(tmp_path):
    """未触发（score > 0.5）时不得留痕 —— 否则 history 全是噪声。"""
    r, st = _advance(tmp_path, "STAGE_5", "DONE", force=True, score=0.9)
    assert r.get("allowed") is True
    assert not (st["gate_data"].get("monitor_history") or [])


def test_b4_force_low_score_writes_nonstandard_history(tmp_path):
    """standing/analysis 分支（critical_only=False）同样适用 —— force 留痕不是 standard 专属。"""
    sf = _write_state(tmp_path / "s.json", "ECO-DOC", gate_data={"project_type": "standing"})
    r = _run(sf, "ECO-RESEARCH", force=True, dry_run=False, env=_ok_env(),
             monitor_json={"score": 0.1, "mode": "local"}, cc={}, remote="",
             skill_dir=str(tmp_path))
    with open(sf, encoding="utf-8") as f:
        st = json.load(f)
    # nonstandard 分支成功返回 `{"ok": True, "mode": "direct"}`（与 standard 的 `allowed`
    # 不同形 —— 这是既有契约，本臂只关心「放行 + 留痕」两件事，不统一返回形态）。
    assert r.get("ok") is True, r
    hist = st["gate_data"].get("monitor_history") or []
    assert hist and hist[-1]["forced"] is True, st["gate_data"]


# ─── C. dry_run 零副作用，但不得假绿 ───────────────────────────────────────

def test_c1_dry_run_low_score_blocks_but_writes_nothing(tmp_path):
    """dry_run + 低分 ⟹ **如实返回 block**（不假绿），但 state 文件一字未变。"""
    sf = _write_state(tmp_path / "s.json", "STAGE_5")
    with open(sf, encoding="utf-8") as f:
        before = f.read()
    r = _run(sf, "DONE", force=False, dry_run=True, env=_ok_env(),
             monitor_json={"score": 0.3, "mode": "local"}, cc={}, remote="",
             skill_dir=str(tmp_path))
    with open(sf, encoding="utf-8") as f:
        after = f.read()
    assert r.get("allowed") is False, \
        "dry_run 把 monitor 判成通过 ⟹ 预演假绿（真跑会被拦）"
    assert r.get("blocked_by_bank") is True
    assert before == after, "dry_run 改了 state 文件 ⟹ 违反零副作用"


def test_c2_dry_run_high_score_passes_without_side_effect(tmp_path):
    """dry_run + 高分 ⟹ check_only 通过，且不落任何记录。"""
    sf = _write_state(tmp_path / "s.json", "STAGE_5")
    with open(sf, encoding="utf-8") as f:
        before = f.read()
    r = _run(sf, "DONE", force=False, dry_run=True, env=_ok_env(),
             monitor_json={"score": 0.9, "mode": "local"}, cc={}, remote="",
             skill_dir=str(tmp_path))
    with open(sf, encoding="utf-8") as f:
        assert f.read() == before
    assert r.get("allowed") is True
    assert r.get("check_only") is True


# ─── D. 正常阻断路径 ───────────────────────────────────────────────────────

def test_d1_low_score_blocks_and_records_rejection(tmp_path):
    """非 force / 非 dry_run + 低分 ⟹ 阻断 + `rejected_edits` 记一条（既有 T30 契约）。"""
    r, st = _advance(tmp_path, "STAGE_5", "DONE", score=0.3)
    assert r.get("allowed") is False
    assert r.get("reason") == "BANK_MONITOR_BLOCKED"
    rej = st["gate_data"].get("rejected_edits") or []
    assert len(rej) == 1
    assert rej[0]["source"] == "bank", "确定性阻断必须由额度银行落账（不是 monitor 测量）"
    assert rej[0]["violations"] == ["BANK_MONITOR_BLOCKED"]
    # M1：阻断路径同时落**审计侧 advisory**（finding 留痕，但不进熵、不二次阻断）
    hist = st["gate_data"].get("monitor_history") or []
    assert hist and hist[-1].get("advisory") == "monitor_low_score"


def test_d2_previous_rejections_excludes_current_rejection(tmp_path):
    """`previous_rejections` 语义 = **上一次**被拒；原状在 append 之后取 ⟹ 恒含本次（自身污染）。"""
    gate = {"rejected_edits": [{"stage": "STAGE_4", "to_stage": "STAGE_5",
                                "source": "gates", "violations": ["OLD_ONE"],
                                "timestamp": "2026-10-30T00:00:00"}]}
    sf = _write_state(tmp_path / "s.json", "STAGE_5", gate_data=gate)
    r = _run(sf, "DONE", force=False, dry_run=False, env=_ok_env(),
             monitor_json={"score": 0.3, "mode": "local"}, cc={}, remote="",
             skill_dir=str(tmp_path))
    prev = r.get("previous_rejections") or []
    assert [p["violations"] for p in prev] == [["OLD_ONE"]], \
        f"previous_rejections 混入本次阻断记录：{prev}"
