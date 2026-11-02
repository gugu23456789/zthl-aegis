#!/usr/bin/env python3
"""
`gk_state_route._state_projection` 只读投影缓存（2026-10-29 · 提速①）
=============================================================================
病象（cProfile 实测，`resolve-state` 在归属冲突分支）：`_candidate_isolated_states` 对
技能目录下 **107 个** `.gatekeeper.state.*` 逐个 `json.load` —— 其中 60 个根本不是 JSON
（`.jsonl` 追加日志 / `.dispatch` / `.tmp` 拍平文本），旧代码要整份解析到抛异常才停；
随后 `_describe_candidates` 又把命中的 16 个候选**再读一遍**。合计 1.15s + 0.18s，
占 CLI 每次启动（guard-edit 3.2s）的 ~40%。

修法 = 两层：
  ① **等价短路** `_peek_json_object`：首个非空白字符非 `{` ⟹ 顶层必不是 object ⟹ 原式
     `json.load(f).get(k)` 必抛/必被 `isinstance` 挡回 ⟹ 结果恒 None。语义**逐字等价**，
     但省掉 MB 级 jsonl 的整份解析。
  ② **跨进程缓存**：投影 `{worktree,r_phase,stage}` 落 `GK_STATE_PROJ_CACHE_DIR`（缺省
     `~/.gatekeeper/state-projection`），失效 = `(st_mtime_ns,st_size,st_ctime_ns)` 不等
     **或** 落在 racy 窗口（`now - mtime < 2s`：本机 `/tmp` 时间戳只有 1s 粒度，实测同秒
     两次改写三个字段完全相同）。负结果（非 JSON 对象）也缓存。

臂清单（红先：落刀前 ③④⑤ 必红 —— 旧实现每次都整份读）：
  ① 改写即失效：内容变 ⟹ 投影跟着变（防陈旧读 = 预算/归属误判）
  ② 等价短路：jsonl / 数组 / 空文件 ⇢ None；**前导空白 + `{`** ⇢ 正常解析（peek 不得漏空白）
  ③ 命中不重解析：第二次调用对该 state 文件 0 次 open
  ④ 负结果也缓存：非 JSON 文件第二次调用 0 次 open
  ⑤ `_describe_candidates` 复用同一投影（扫描已预热 ⟹ 描述阶段 0 次 open）
  ⑥ racy：同秒改写不得被命中（stamp 全等时只能靠窗口兜住，否则 = 陈旧读）
"""
import builtins
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_state_route as gsr


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _age(path: Path, secs: int = 10) -> None:
    """把 mtime 前移（**仅测试手法**：真实写者不会回拨）。

    必要性：racy 窗口内缓存**不读不写**（见实现注释），刚写完的文件永远 miss。要让「命中」
    可测，必须先把文件做旧到窗口外。
    """
    st = os.stat(path)
    t = st.st_mtime_ns - secs * 10 ** 9
    os.utime(path, ns=(t, t))


def _state_json(worktree: str, r_phase: str = "R-T1", stage: str = "STAGE_0") -> str:
    return json.dumps({"r_phase": r_phase, "stage": stage,
                       "worktree": worktree, "gate_data": {}})


def _spy_opens(monkeypatch, target: str) -> dict:
    """统计对 `target` 的 `builtins.open` 次数（`os.stat` 不计 —— 命中的收益就是「不重解析」）。"""
    real = builtins.open
    hits = {"n": 0}

    def _open(file, *a, **kw):
        if str(file) == target:
            hits["n"] += 1
        return real(file, *a, **kw)

    monkeypatch.setattr(builtins, "open", _open)
    return hits


class TestProjectionSemantics:
    def test_rewrite_invalidates(self, tmp_path, monkeypatch):
        """① 内容改写 ⟹ 投影必须跟着变（否则 = 陈旧读，会把 worktree 归属判错）。"""
        monkeypatch.setenv("GK_STATE_PROJ_CACHE_DIR", str(tmp_path / "proj"))
        p = tmp_path / "skill" / ".gatekeeper.state.a"
        _write(p, _state_json("/repo/one"))
        _age(p)
        assert gsr._load_worktree(str(p)) == "/repo/one"
        _write(p, _state_json("/repo/two"))
        assert gsr._load_worktree(str(p)) == "/repo/two", "缓存未失效 ⟹ 陈旧 worktree"

    def test_short_circuit_equivalence(self, tmp_path, monkeypatch):
        """② 非 JSON 对象 ⟹ None；前导空白 + `{` ⟹ 正常解析（短路不得误伤空白前缀）。"""
        monkeypatch.setenv("GK_STATE_PROJ_CACHE_DIR", str(tmp_path / "proj"))
        d = tmp_path / "skill"
        cases_none = {
            "journal.jsonl": '{"a": 1}\n{"b": 2}\n',
            "array": "[]",
            "empty": "",
            "dispatch": "plan-a\nplan-b\n",
        }
        for name, text in cases_none.items():
            p = d / name
            _write(p, text)
            assert gsr._state_projection(str(p)) is None, name
            assert gsr._load_worktree(str(p)) is None, name
        ws = d / "leading_ws"
        _write(ws, "\n\t  " + _state_json("/repo/ws"))
        assert gsr._load_worktree(str(ws)) == "/repo/ws", "peek 未跳过前导空白 ⟹ 等价性破"

    def test_projection_parity_with_full_load(self, tmp_path, monkeypatch):
        """投影三字段与整份 `json.load` 逐字同源。"""
        monkeypatch.setenv("GK_STATE_PROJ_CACHE_DIR", str(tmp_path / "proj"))
        p = tmp_path / "skill" / ".gatekeeper.state.p"
        _write(p, _state_json("/repo/p", r_phase="R7", stage="STAGE_2"))
        proj = gsr._state_projection(str(p))
        full = json.loads(p.read_text(encoding="utf-8"))
        for k in ("worktree", "r_phase", "stage"):
            assert proj[k] == full.get(k), k

    def test_racy_same_second_rewrite_not_stale(self, tmp_path, monkeypatch):
        """⑥ 刚改过的文件（racy 窗口内）**不得**被缓存命中 —— 1s 粒度下 stamp 可能全等。"""
        monkeypatch.setenv("GK_STATE_PROJ_CACHE_DIR", str(tmp_path / "proj"))
        p = tmp_path / "skill" / ".gatekeeper.state.r"
        _write(p, _state_json("/repo/old"))
        _age(p)
        assert gsr._load_worktree(str(p)) == "/repo/old"
        _write(p, _state_json("/repo/new"))   # 同秒改写：mtime 可能与上一条缓存同秒
        assert gsr._load_worktree(str(p)) == "/repo/new", \
            "racy 窗口缺失 ⟹ 同秒改写被吃成陈旧读"


class TestProjectionCacheHit:
    def test_hit_does_not_reopen(self, tmp_path, monkeypatch):
        """③ 命中 ⟹ 对该 state 文件 0 次 open（stat 仍在，但那只是 1 次元数据查询）。"""
        monkeypatch.setenv("GK_STATE_PROJ_CACHE_DIR", str(tmp_path / "proj"))
        p = tmp_path / "skill" / ".gatekeeper.state.h"
        _write(p, _state_json("/repo/h"))
        _age(p)
        assert gsr._load_worktree(str(p)) == "/repo/h"
        hits = _spy_opens(monkeypatch, str(p))
        assert gsr._load_worktree(str(p)) == "/repo/h"
        assert hits["n"] == 0, "命中仍重开 state 文件 ⟹ 缓存没生效"

    def test_negative_result_cached(self, tmp_path, monkeypatch):
        """④ 非 JSON 对象（jsonl 日志等）也缓存 ⟹ 第二次 0 次 open（否则每次白解析 MB 级文件）。"""
        monkeypatch.setenv("GK_STATE_PROJ_CACHE_DIR", str(tmp_path / "proj"))
        p = tmp_path / "skill" / ".gatekeeper.state.x.finding-journal.jsonl"
        _write(p, '{"a": 1}\n' * 200)
        _age(p)
        assert gsr._load_worktree(str(p)) is None
        hits = _spy_opens(monkeypatch, str(p))
        assert gsr._load_worktree(str(p)) is None
        assert hits["n"] == 0, "负结果未缓存 ⟹ jsonl 每次都要整份解析到抛异常"

    def test_describe_candidates_reuses_projection(self, tmp_path, monkeypatch):
        """⑤ `_describe_candidates` 复用扫描阶段已预热的投影 ⟹ 描述阶段 0 次 open。"""
        monkeypatch.setenv("GK_STATE_PROJ_CACHE_DIR", str(tmp_path / "proj"))
        sd = tmp_path / "skill"
        sd.mkdir()
        p = sd / ".gatekeeper.state.batch8"
        _write(p, _state_json(str(sd), r_phase="R-T1", stage="STAGE_0"))
        _age(p)
        assert gsr._candidate_isolated_states(str(sd)) == [str(p)]
        hits = _spy_opens(monkeypatch, str(p))
        desc = gsr._describe_candidates([str(p)])
        assert hits["n"] == 0, "描述阶段又整份重读了一遍（旧实现的重复 I/O）"
        assert ".gatekeeper.state.batch8(R-T1/STAGE_0)" in desc, desc


class TestCollectSkipsArtifacts:
    """⑦⑧ `_collect_state_files` 按 `gk_state_forms` 的**权威形态**剔除旁挂件（禁第二份）。

    病象：glob `.gatekeeper.state.*` 把 `.jsonl` journal/ledger/archive、`.tmp`、`.lock` 全收，
    并对每项各打一次 stat（CIFS ~2ms × 131 项 ⟹ ~0.28s/次，每次 CLI 启动都付）。
    判据 = **候选集不变**（artifact 的 `_load_worktree` 恒 None，本就会被下游过滤）+ 名字判定
    不触 scopes 读取（纯字符串）。
    """

    def test_artifacts_excluded_from_candidates(self, tmp_path):
        """⑦ 真 state 进候选；journal.jsonl / .tmp / .lock / 非 state 名 都不进。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        _write(sd / ".gatekeeper.state.r7", _state_json(str(sd)))
        _write(sd / ".gatekeeper.state.batch8", _state_json(str(sd)))
        for junk in (".gatekeeper.state.budget-log.jsonl",
                     ".gatekeeper.state.lp7bqxqw.tmp",
                     ".gatekeeper.state.r7.lock",
                     ".gatekeeper.state.bak-20260101",
                     "unrelated.txt"):
            _write(sd / junk, '{"x": 1}\n')
        got = [p.name for p in gsr._collect_state_files(str(sd))]
        assert got == [".gatekeeper.state.batch8", ".gatekeeper.state.r7"], got

    def test_is_artifact_name_is_single_source(self, tmp_path):
        """⑧ 名字判据单点；legacy/domain 形态**不得**被误判成 artifact（否则候选会漏）。"""
        import gk_state_forms as gsf
        for junk in (".gatekeeper.state.budget-log.jsonl",
                     ".gatekeeper.state.x.tmp",
                     ".gatekeeper.state.r7.lock",
                     ".gatekeeper.state.corrupt-20260101",
                     "not-a-state.txt",
                     ".gatekeeper"):
            assert gsf.is_artifact_name(junk) is True, junk
        for live in (".gatekeeper.state.r7",
                     ".gatekeeper.state.skill.2026-10-04-audit-bureau-plan",
                     ".gatekeeper.state.2026-07-26-zthl-harness-adapter-plan"):
            assert gsf.is_artifact_name(live) is False, live
        # `state_form` 的 artifact 支必须与单点判定同源（禁第二份）
        assert gsf.state_form(str(tmp_path / ".gatekeeper.state.x.tmp")) == "artifact"
