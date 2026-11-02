"""
test_pre_tool_hook.py — Tests for pre_tool_hook.py (stdin-based Hook protocol)
================================================================================
Tests by direct function call (no subprocess), using monkeypatch for STATE_FILE.
"""
import hashlib
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import pre_tool_hook
from pre_tool_hook import resolve_path


def run_hook_inline(stdin_data: dict) -> int:
    """Run hook logic inline, return exit code."""
    old_stdin = sys.stdin
    sys.stdin = io.StringIO(json.dumps(stdin_data))
    try:
        pre_tool_hook.main()
    except SystemExit as e:
        return e.code
    finally:
        sys.stdin = old_stdin
    return 0


class TestN9DispatchParallelGate:
    """N9 机检（Gate R0.10）：质询派发并行闸（2026-09-30，复发洞补机检）。

    口径源 docs/plans/2026-09-14-convergence-evaluator-subplan.md §0.1（并行 = & + sleep 3 + wait）/ N7。
    """

    def test_serial_for_loop_flagged(self):
        bad = ('for a in "--adjudicate pr-1 --decision approve" '
               '"--adjudicate pr-2 --decision approve"; do '
               "bash gatekeeper-cli.sh plan-refinement P $a >/dev/null 2>&1; done")
        assert pre_tool_hook._n9_parallel_dispatch(bad) is not None, \
            "命中 `for` 串行派发却未拦"

    def test_consumer_merge_flagged(self):
        bad = ("bash gatekeeper-cli.sh plan-refinement P --adjudicate pr-1 "
               "--decision approve 2>&1 | tail -n 5")
        assert pre_tool_hook._n9_parallel_dispatch(bad) is not None, \
            "命中消费端 `2>&1` 并流却未拦"

    def test_parallel_dispatch_allowed(self):
        good = ("bash gatekeeper-cli.sh plan-refinement P --adjudicate pr-1 --decision approve "
                "> /tmp/a.out 2>/tmp/a.err & sleep 3; "
                "bash gatekeeper-cli.sh plan-refinement P --adjudicate pr-2 --decision approve "
                "> /tmp/b.out 2>/tmp/b.err & wait")
        assert pre_tool_hook._n9_parallel_dispatch(good) is None, "并行派发被误拦"

    def test_unrelated_loop_allowed(self):
        assert pre_tool_hook._n9_parallel_dispatch("for f in a b; do echo $f; done") is None, \
            "无 `--adjudicate` 的命令被误拦（窄面失守）"

    # ── V3（2026-10-01 补；堵 `;` 链式串行缝）───────────────────────────────
    # 病象（复发，实测）：6 条 `--adjudicate last` 以 `;` 直接连写 = 串行派发，
    #   而 V1 只抓 `for`/`while` ⟹ 漏网（owner：「你又在胡乱串行是吧」）。
    def test_multi_arm_semicolon_chain_flagged(self):
        bad = ("wsl.exe -e bash gatekeeper-cli.sh plan-refinement "
               "--adjudicate last --decision approve ; "
               "wsl.exe -e bash gatekeeper-cli.sh plan-refinement "
               "--adjudicate last --decision approve ; "
               "wsl.exe -e bash gatekeeper-cli.sh plan-refinement "
               "--adjudicate last --decision approve")
        assert pre_tool_hook._n9_parallel_dispatch(bad) is not None, \
            "命中 `;` 链式串行派发（≥2 条 --adjudicate 无 &/wait）却未拦"

    def test_multi_arm_and_and_chain_flagged(self):
        bad = ("bash gatekeeper-cli.sh plan-refinement --adjudicate pr-1 --decision approve "
               "&& bash gatekeeper-cli.sh plan-refinement --adjudicate pr-2 --decision approve")
        assert pre_tool_hook._n9_parallel_dispatch(bad) is not None, \
            "命中 `&&` 串行派发（≥2 条 --adjudicate 无 &/wait）却未拦"

    def test_two_arm_background_and_wait_allowed(self):
        good = ("bash gatekeeper-cli.sh plan-refinement --adjudicate pr-1 --decision approve "
                "> /tmp/a.out 2>/tmp/a.err & sleep 3; "
                "bash gatekeeper-cli.sh plan-refinement --adjudicate pr-2 --decision approve "
                "> /tmp/b.out 2>/tmp/b.err & wait")
        assert pre_tool_hook._n9_parallel_dispatch(good) is None, "规范并行派发被误拦"

    def test_single_adjudicate_chained_is_allowed(self):
        ok = ("bash gatekeeper-cli.sh plan-refinement P --task 'x' ; "
              "bash gatekeeper-cli.sh plan-refinement --adjudicate pr-1 --decision approve")
        assert pre_tool_hook._n9_parallel_dispatch(ok) is None, \
            "单条 `--adjudicate` 与其它命令串接被误拦（窄面失守：V3 只在 ≥2 条时触发）"

    def test_kill_switch(self, monkeypatch):
        monkeypatch.setenv("GK_N9_DISPATCH_GATE", "0")
        bad = ("for a in 1; do bash gatekeeper-cli.sh plan-refinement P "
               "--adjudicate x --decision approve; done")
        assert pre_tool_hook._n9_parallel_dispatch(bad) is None, "kill switch 未生效"


class TestN9CoverageDegradationT11:
    """T11（n4 §2-T11 / §10-M3 / §5「N9 覆盖声明」）：**显式登记「N9 覆盖退化」**（结构守护断言）。

    事实（直读 `pre_tool_hook.py::_n9_parallel_dispatch` 与 `gatekeeper-cli.sh` T2 段）：
      · N9 机检（Gate R0.10）只吃 **agent 外层命令串**（判据 = `--adjudicate` 出现 + for/while
        + ≥2 条 `--adjudicate` 而无 `&`/`wait`）。
      · CLI 的组 fan-out（T2：`3×K` 臂）在 **`gatekeeper-cli.sh` 内部** shell 里 `( … ) & … wait`
        并行派发；agent 外层只写 **单条** `plan-refinement --adjudicate <id>` ⟹ **N9 判据面外**。
    ⟹ 守护从门禁**降级为测试**（**非**「N9 保持即受机检」）：本类把该退化钉为可回归事实（tripwire）——
      ① CLI 内确存在并行 fan-out（反例臂：无 fan-out 则「退化」无意义，防 PW-5 恒真）；
      ② N9 对外层**单条**命令确不命中（退化实证）；
      ③ 同一 fan-out 若写成**外层**串行链则 N9 **命中**（区分度：闸未坏，只是范围外）。
    任一事实漂移 ⟹ 本类变红 ⟹ 强制同步更新 §5「N9 覆盖声明」与本类（防静默假设）。
    落刀点（**具体文件，非 glob**）：`scripts/test_pre_tool_hook.py::TestN9CoverageDegradationT11`。
    """

    _CLI = Path(pre_tool_hook.SKILL_DIR) / "gatekeeper-cli.sh"

    def test_cli_internal_fanout_exists(self):
        """反例臂（防 PW-5 恒真退化）：CLI **确含** T2 组 fan-out（`( … ) &` 后台 + `wait` 收口）。"""
        src = self._CLI.read_text(encoding="utf-8")
        assert ") &" in src, "gatekeeper-cli.sh 未找到子 shell 后台 fan-out（`) &`）"
        assert any(ln.strip() == "wait" for ln in src.splitlines()), \
            "gatekeeper-cli.sh 未找到 fan-out 的 `wait` 收口"
        assert 'out" 2>"' in src, "gatekeeper-cli.sh 未找到逐臂 stdout/stderr 分离落盘（N7 口径）"
        assert "GK_PLAN_REFINE_GROUP" in src, "gatekeeper-cli.sh 未找到组 fan-out 开关"

    def test_n9_blind_to_cli_internal_fanout(self):
        """退化实证：agent 外层**单条** plan-refinement（CLI 内部再并行 fan-out 3×K）⟹ N9 None。"""
        outer = ("bash gatekeeper-cli.sh plan-refinement /tmp/p.md "
                 "--adjudicate abcd1234 --decision approve")
        assert pre_tool_hook._n9_parallel_dispatch(outer) is None, \
            "N9 竟命中外层单条命令 ⟹『CLI 内 fan-out 不在判据面』失效（须更新 §5 声明）"

    def test_n9_flags_equivalent_outer_fanout(self):
        """区分度（反例臂）：同一 3×K fan-out 若**外层**串行连写（≥2 条无 &/wait）⟹ N9 命中。"""
        arm = ("bash gatekeeper-cli.sh plan-refinement /tmp/p.md "
               "--adjudicate pr-%d --decision approve")
        serial = " ; ".join(arm % i for i in (1, 2, 3))
        assert pre_tool_hook._n9_parallel_dispatch(serial) is not None, \
            "N9 未拦外层串行多臂 ⟹ 判据面与 §5 声明不符（闸坏，非范围问题）"


class TestSessionMarkerShard:
    """2026-10-01（会话隔离 finding）：`.gatekeeper.session` 单槽被并发会话覆写 ⟹ 另写 sid 分片。

    病象实测：6 条 `plan-refinement --task` 入队 1 条落域 state / 5 条**静默**落默认 state
    （外来 sid 无 `.gatekeeper.plan.<sid>` ⟹ 启动块 `no_pointer_file` 静默回退）。
    """

    def test_writes_sid_shard_and_legacy_slot(self, tmp_path, monkeypatch):
        m = tmp_path / ".gatekeeper.session"
        monkeypatch.setattr(pre_tool_hook, "_SESSION_FILE", m)
        pre_tool_hook._write_session_marker("a" * 24, "RunCommand", "c:/x")
        assert m.exists(), "单槽（兼容面）未写"
        assert (tmp_path / (".gatekeeper.session." + "a" * 24)).exists(), \
            "未写 sid 分片 —— 并发会话身份互不覆写的前提缺失（red-first）"

    def test_no_sid_writes_nothing(self, tmp_path, monkeypatch):
        m = tmp_path / ".gatekeeper.session"
        monkeypatch.setattr(pre_tool_hook, "_SESSION_FILE", m)
        pre_tool_hook._write_session_marker("", "RunCommand", "c:/x")
        assert not m.exists(), "空 sid 不得写 marker"


class TestSessionIdentityWorktreeAnchor:
    """2026-10-02（finding ECC-AB2FA16E9133）：身份链**同源** —— env > worktree token > payload。

    平台无关兜底：hook 由 `_CALL_TARGET`（目标路径）所在 git worktree 派生 token，与 CLI 侧由
    `$PWD` 派生的**同一** token 对齐 ⟹ 消「hook 用宿主 sid / CLI 用 worktree token」两套账。
    解析单源 = `gk_session_identity`（禁第二实现）。无 worktree 锚 ⟹ 回落 payload（零回归）。
    """

    def test_identity_chain_same_source(self):
        src = (Path(__file__).parent / "pre_tool_hook.py").read_text(encoding="utf-8")
        assert "_gsi.derive(_CALL_TARGET)" in src, \
            "hook 未由目标路径派生 worktree token（两套账未消）"
        assert "_SESSION_ID = _env_sid or _wt_tok or _pay_sid" in src, \
            "身份链优先级不符（应 env > worktree token > payload sid）"
        i_target = src.find('_CALL_TARGET = _fp_ctx or ""')
        i_sess = src.find("_SESSION_ID = _env_sid or _wt_tok or _pay_sid")
        assert i_target != -1 and i_sess != -1 and i_target < i_sess, \
            "`_CALL_TARGET` 须先于身份计算（否则 token 档拿不到目标路径）"
        assert "gk_session_identity" in src, "解析单源引用缺失"

    def test_worktree_target_yields_token(self, monkeypatch):
        """行为面：工作树内目标路径 ⟹ derive 出该 worktree leaf（与 CLI 侧同源）。"""
        import gk_session_identity as gsi
        r = gsi.derive("<home>/.trae/worktrees/spz-gatekeeper-r-sequence/"
                       "agent/session/7c1e2933/scripts/pre_tool_hook.py")
        assert r["token"] == "7c1e2933" and r["source"] == "name"


class TestMergeLockPreflightR011:
    """Gate R0.11（2026-09-30）：`git merge` 前孤儿锁闸。

    实测病象：主树 `git merge` 撞 0 字节孤儿 `index.lock` ⟹ `Unable to write index`；
    `cmd_commit` 有 preflight 而 **merge 路径不跑它**。处置：孤儿归档放行 / 活锁 BLOCK。
    """

    @staticmethod
    def _repo(tmp_path, name="repo"):
        rp = tmp_path / name
        rp.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", str(rp)], capture_output=True, timeout=60)
        return rp

    @staticmethod
    def _wire(monkeypatch, tmp_path, rp):
        st = tmp_path / "s.json"
        st.write_text(json.dumps({"worktree": str(rp)}), encoding="utf-8")
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", st)
        monkeypatch.setattr(pre_tool_hook, "_log_hook", lambda *a, **k: None)

    def test_non_merge_ignored(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", tmp_path / "nope.state")
        assert pre_tool_hook._merge_lock_preflight("git -C /tmp status") is None

    def test_merge_clean_repo_allowed(self, tmp_path, monkeypatch):
        rp = self._repo(tmp_path)
        self._wire(monkeypatch, tmp_path, rp)
        assert pre_tool_hook._merge_lock_preflight(f"git -C {rp} merge --no-ff x") is None

    def test_merge_live_lock_blocked(self, tmp_path, monkeypatch):
        rp = self._repo(tmp_path)
        self._wire(monkeypatch, tmp_path, rp)
        (rp / ".git" / "index.lock").write_text("", encoding="utf-8")   # 新鲜 mtime
        v = pre_tool_hook._merge_lock_preflight(f"git -C {rp} merge --no-ff x")
        assert v is not None, "活锁未拦：merge 前预检失守"

    def test_merge_orphan_lock_archived_and_allowed(self, tmp_path, monkeypatch):
        rp = self._repo(tmp_path)
        self._wire(monkeypatch, tmp_path, rp)
        monkeypatch.setenv("GK_TRASH_DIR", str(tmp_path / "trash"))
        lk = rp / ".git" / "index.lock"
        lk.write_text("", encoding="utf-8")
        old = time.time() - 100000
        os.utime(lk, (old, old))
        v = pre_tool_hook._merge_lock_preflight(f"git -C {rp} merge --no-ff x")
        assert v is None, "孤儿锁应**归档放行**（非阻断）"
        assert not lk.exists(), "孤儿锁未归档（R0.11 未生效）"

    def test_r010_r011_wired_in_both_branches(self):
        """接线臂（**2026-09-30 实测缺陷**）：R0.10/R0.11 须**同时**挂普适分支与范围内分支。

        病象：只挂范围内分支 ⟹ 会话 cwd 在治理范围外（`c:\\Users\\HP`）时命令走 `sys.exit(0)` 早退
        ⟹ 两闸对 `git merge` 这类无治理目标的命令**恒不触达**（「门禁有、实际不生效」族）。
        """
        src = Path(pre_tool_hook.__file__).read_text(encoding="utf-8")
        for call in ("_n9_parallel_dispatch(command)", "_merge_lock_preflight(command)"):
            assert src.count(call) == 2, f"{call} 挂载数 != 2（普适 + 范围内）⟹ 存在不触达分支"


class TestStateSingleSource:
    """② state 单一事实源收敛（2026-09-04）：hook 读源 = CLI 同源（skill 默认 .gatekeeper.state），
    不再落仓库级 legacy 副本；标记命中即映射，范围外放行。"""

    def test_governed_marker_maps_to_single_source(self, tmp_path, monkeypatch):
        """gatekeeper 标记 cwd → 收敛后 state_file（模拟 scopes 指向 skill 默认单源）。"""
        sf = tmp_path / ".gatekeeper.state"
        sf.write_text(json.dumps({"r_phase": "R7.1", "stage": "STAGE_2"}), encoding="utf-8")
        # 2026-09-10 隔离修复：SKILL_DIR 落 tmp → 真实 .gatekeeper.plan 指针不可见
        # （指针优先级高于 scopes，环境存在 fresh 指针时本用例会误解析到隔离 state）
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", tmp_path)
        monkeypatch.setattr(pre_tool_hook, "GOVERNED_SCOPES",
                            {"spz_gatekeeper_project": str(sf)})
        monkeypatch.setattr(pre_tool_hook, "_win_to_wsl", lambda p: p)
        r = pre_tool_hook._resolve_state_by_cwd(
            r"<home>\Downloads\<workspace>\spz_gatekeeper_project\src\main.cpp")
        assert r == sf

    def test_skill_cwd_default_single_source(self, tmp_path, monkeypatch):
        """技能目录 cwd → skill 默认 state（CLI 同源）。"""
        sf = tmp_path / ".gatekeeper.state"
        sf.write_text(json.dumps({"stage": "STAGE_2"}), encoding="utf-8")
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", tmp_path)
        monkeypatch.setattr(pre_tool_hook, "GOVERNED_SCOPES", {})
        monkeypatch.setattr(pre_tool_hook, "_win_to_wsl", lambda p: p)
        r = pre_tool_hook._resolve_state_by_cwd(str(tmp_path))
        assert r == sf

    def test_worktree_cwd_maps_through_marker(self, tmp_path, monkeypatch):
        """r7.1 worktree cwd（marker 含 spz_gatekeeper_project）→ 同一单源（不复用 worktree 本地）。"""
        sf = tmp_path / ".gatekeeper.state"
        sf.write_text(json.dumps({"stage": "STAGE_2"}), encoding="utf-8")
        # 2026-09-10 隔离修复：同 test_governed_marker_maps_to_single_source（防真实 plan 指针干扰）
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", tmp_path)
        monkeypatch.setattr(pre_tool_hook, "GOVERNED_SCOPES",
                            {"spz_gatekeeper_project": str(sf)})
        monkeypatch.setattr(pre_tool_hook, "_win_to_wsl", lambda p: p)
        r = pre_tool_hook._resolve_state_by_cwd(
            r"<home>\.trae\worktrees\spz_gatekeeper_project\feature\spz-gatekeeper-2.0.4-r7.1\src")
        assert r == sf

    def test_out_of_scope_returns_none(self, tmp_path, monkeypatch):
        """范围外 cwd → None（放行，不再回退默认 state 误标其它项目）。"""
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", tmp_path)
        monkeypatch.setattr(pre_tool_hook, "GOVERNED_SCOPES", {})
        monkeypatch.setattr(pre_tool_hook, "_win_to_wsl", lambda p: p)
        assert pre_tool_hook._resolve_state_by_cwd(r"<home>\unrelated") is None

    def test_plan_pointer_wsl_form_state_resolves(self, tmp_path, monkeypatch):
        """plan 指针 state_file 为 /mnt 形态（WSL CLI 写入）→ Windows python 也能解析到真实文件
        （双向探测修复：此前只做 Win→/mnt 单向，/mnt 形态落空 → 回退默认 state 错标隔离计划）。"""
        sf = tmp_path / "isolated.state"
        sf.write_text(json.dumps({"stage": "STAGE_2"}), encoding="utf-8")
        import datetime as _dt
        plan = tmp_path / ".gatekeeper.plan"
        plan.write_text(json.dumps({"state_file": pre_tool_hook._win_to_wsl(str(sf)),
                                    "updated": _dt.datetime.now(_dt.timezone.utc).isoformat()}),
                        encoding="utf-8")
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", tmp_path)
        monkeypatch.setattr(pre_tool_hook, "GOVERNED_SCOPES", {"spz_gatekeeper_project": "x"})
        # 真实 _win_to_wsl/_wsl_to_win：验证跨形态解析而非打桩绕过
        r = pre_tool_hook._resolve_state_by_cwd(
            r"<home>\.trae\worktrees\spz_gatekeeper_project\feature\spz-gatekeeper-2.0.4-r7.1\src")
        assert r == sf and r.exists()

    def test_plan_pointer_stale_ignored(self, tmp_path, monkeypatch):
        """指针 updated 超 24h（对齐 CLI Phase 7b TTL，2026-09-05）→ hook 不跟随，回落 scopes 单源。"""
        import datetime as _dt
        stale_sf = tmp_path / "stale.isolated.state"
        stale_sf.write_text(json.dumps({"stage": "STAGE_1"}), encoding="utf-8")
        marker_sf = tmp_path / "marker.state"
        marker_sf.write_text(json.dumps({"stage": "STAGE_2"}), encoding="utf-8")
        plan = tmp_path / ".gatekeeper.plan"
        plan.write_text(json.dumps({"state_file": str(stale_sf),
                                    "updated": (_dt.datetime.now(_dt.timezone.utc)
                                                - _dt.timedelta(days=2)).isoformat()}),
                        encoding="utf-8")
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", tmp_path)
        monkeypatch.setattr(pre_tool_hook, "GOVERNED_SCOPES",
                            {"spz_gatekeeper_project": str(marker_sf)})
        monkeypatch.setattr(pre_tool_hook, "_win_to_wsl", lambda p: p)
        r = pre_tool_hook._resolve_state_by_cwd(
            r"<home>\Downloads\<workspace>\spz_gatekeeper_project\src")
        assert r == marker_sf  # stale 指针被忽略 → scopes 单源（隔离计划不复活）

    def test_resolve_existing_mnt_form_bidirectional(self):
        """`_resolve_existing` 双向：同一真实文件的「本宿主形态」与「对侧形态」都须命中（宿主无关）。

        XENV-FORM（2026-09-27，环境性 failed 清单）：原臂断言 `_win_to_wsl(...).startswith("/mnt/")`
        —— 仅 Windows python 宿主成立（tmp 为 `C:\\…`）；规范 runner（WSL）下 tmp 为 `/tmp/…`
        无盘符 ⟹ 该断言恒失败。改为对**两侧形态**都能解析回真实文件：语义更强且与宿主无关。
        """
        real = Path(pre_tool_hook.__file__).resolve()
        forms = {str(real), pre_tool_hook._win_to_wsl(str(real)),
                 pre_tool_hook._wsl_to_win(str(real))}
        for form in forms:
            r = pre_tool_hook._resolve_existing(form)
            assert r is not None and r.exists(), f"形态 {form!r} 未解析到真实文件"


class TestHSLSN:
    """H-SLSN 启发式技能加载安全网（2026-08-27，ECC-8570E847C7C1）：
    双条件激活 + 回环拦截 + 带状态 while 循环（attempts 超阈值降级防死循环）。"""

    @pytest.fixture(autouse=True)
    def _hslsn_tmp(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pre_tool_hook, "_HSLSN_FILE", tmp_path / ".gatekeeper.hslsn")
        yield
        for _f in (tmp_path / ".gatekeeper.hslsn", tmp_path / ".gatekeeper.hslsn.tmp", tmp_path / ".gatekeeper.hslsn.lock"):
            try:
                _f.unlink()
            except OSError:
                pass

    def test_activate_roundtrip(self):
        assert pre_tool_hook._hslsn_active() is False
        pre_tool_hook._hslsn_activate()
        assert pre_tool_hook._hslsn_active() is True
        d = pre_tool_hook._hslsn_load()
        assert d["active"] is True and d["attempts"] == 0

    # ── 2026-08-27 修复用例（质询缺口②：flock+checksum 原子事务，公理 A1/A2）──

    def test_transact_writes_checksum(self):
        """事务写入后状态文件必须带 _checksum，且 load 校验通过（公理 A2）。"""
        pre_tool_hook._hslsn_activate()
        raw = pre_tool_hook._HSLSN_FILE.read_text(encoding="utf-8")
        assert "_checksum" in raw
        d = pre_tool_hook._hslsn_load()
        assert d["active"] is True and d["attempts"] == 0

    def test_tamper_failsafe(self):
        """篡改 attempts → checksum 失配 → load 视为 inactive（fail-safe，公理 A2）。"""
        pre_tool_hook._hslsn_activate()
        d = json.loads(pre_tool_hook._HSLSN_FILE.read_text(encoding="utf-8"))
        d["attempts"] = 999  # 篡改：不重算 checksum
        pre_tool_hook._HSLSN_FILE.write_text(json.dumps(d), encoding="utf-8")
        assert pre_tool_hook._hslsn_load() == {}  # 篡改 → 失活
        assert pre_tool_hook._hslsn_active() is False

    def test_transact_serializes_read_modify_write(self):
        """并发读-改-写串行化（公理 A1）：10 次 record 后 attempts 精确 = 10（无丢失更新）。"""
        pre_tool_hook._hslsn_activate()
        for _ in range(10):
            pre_tool_hook._hslsn_record_and_verdict("bypass-msg")
        d = pre_tool_hook._hslsn_load()
        assert d["attempts"] == 10  # 每次 record 原子 +1，无覆盖写丢失

    def test_transact_rollback_on_mutator_error(self):
        """mutator 抛异常 → 事务回滚（不落盘），状态保持原值（公理 A1 原子性）。"""
        pre_tool_hook._hslsn_activate()
        before = pre_tool_hook._hslsn_load()

        def _boom(d):
            raise RuntimeError("boom")
        pre_tool_hook._hslsn_transact(_boom)
        after = pre_tool_hook._hslsn_load()
        assert after == before  # 回滚：状态不变

    # ── 2026-08-27 修复用例（质询缺口③：bypass 规范化，公理 A3）──

    def test_bypass_double_space(self):
        """多余空白不绕过：'python3  scripts/gk_x.py'（双空格）仍命中。"""
        r = pre_tool_hook._hslsn_bypass(
            "RunCommand", {"command": "python3  scripts/gk_audit_docs.py"}, "python3  scripts/gk_audit_docs.py", "", "/tmp")
        assert r is not None and "scripts/gk_" in r

    def test_bypass_python312(self):
        """解释器版本变体不绕过：'python3.12 scripts/gk_x.py' 仍命中。"""
        r = pre_tool_hook._hslsn_bypass(
            "RunCommand", {"command": "python3.12 scripts/gk_audit_docs.py"}, "python3.12 scripts/gk_audit_docs.py", "", "/tmp")
        assert r is not None and "scripts/gk_" in r

    def test_bypass_wsl_wrapped(self):
        """wsl bash -c 包装不绕过：'wsl bash -c \"python3 scripts/gk_x.py\"' 剥壳后仍命中。"""
        cmd = 'wsl bash -c "python3 scripts/gk_audit_docs.py"'
        r = pre_tool_hook._hslsn_bypass("RunCommand", {"command": cmd}, cmd, "", "/tmp")
        assert r is not None and "scripts/gk_" in r

    def test_bypass_semicolon_segment(self):
        """分号分段判定：'cd /tmp; python3 scripts/gk_x.py' 命中第二段。"""
        cmd = "cd /tmp; python3 scripts/gk_audit_docs.py"
        r = pre_tool_hook._hslsn_bypass("RunCommand", {"command": cmd}, cmd, "", "/tmp")
        assert r is not None and "scripts/gk_" in r

    def test_bypass_cli_in_segment_allowed(self):
        """合法 gatekeeper-cli.sh 出现在分段中 → 白名单优先放行（A3 不误伤）。"""
        cmd = "cd /tmp; bash gatekeeper-cli.sh audit --red"
        r = pre_tool_hook._hslsn_bypass("RunCommand", {"command": cmd}, cmd, "", "/tmp")
        assert r is None

    def test_bypass_bare_rg_double_space(self):
        """规范化后裸 rg（多余空白/路径引号）仍命中 search 引导。"""
        cmd = "rg  'pattern' src/"
        r = pre_tool_hook._hslsn_bypass("RunCommand", {"command": cmd}, cmd, "", "/tmp")
        assert r is not None and "search" in r

    def test_bypass_cli_legit(self):
        # gatekeeper-cli.sh 调用 = 技能内置 cmd 合法形态
        assert pre_tool_hook._hslsn_bypass(
            "RunCommand", {"command": "bash gatekeeper-cli.sh audit --red"}, "bash gatekeeper-cli.sh audit --red", "", "/tmp") is None

    def test_bypass_direct_gk_script(self):
        r = pre_tool_hook._hslsn_bypass(
            "RunCommand", {"command": "python3 scripts/gk_audit_docs.py"}, "python3 scripts/gk_audit_docs.py", "", "/tmp")
        assert r is not None and "scripts/gk_" in r

    def test_bypass_bare_rg(self):
        r = pre_tool_hook._hslsn_bypass(
            "RunCommand", {"command": "rg 'pattern' src/"}, "rg 'pattern' src/", "", "/tmp")
        assert r is not None and "search" in r

    def test_bypass_bare_find_points_to_fdfind(self):
        """`ECC-3F1B47B523F6`（2026-09-24，用户裁定「裸 find 拦截加回去」）：裸 `find` 的引导
        须指向高性能替代 `fdfind`。

        修前文案只说「裸 grep/rg」且只给 `search` 路由 —— 对 `find`（本地文件遍历，非跨仓搜索）
        是**错路由**；本臂钉住 `fdfind` 出现。
        """
        cmd = "find . -name '*.py'"
        r = pre_tool_hook._hslsn_bypass("RunCommand", {"command": cmd}, cmd, "", "/tmp")
        assert r is not None and "fdfind" in r

    def test_bypass_bare_find_exe_blocked(self):
        """`ECC-3F1B47B523F6`：`find.exe` 形态（宿主 exe 后缀）修前**漏网**（名单无 `find.exe`）
        ⟹ 裸 find 拦截不完整。"""
        cmd = "find.exe . -name '*.py'"
        assert pre_tool_hook._hslsn_bypass("RunCommand", {"command": cmd}, cmd, "", "/tmp") is not None

    def test_bypass_edit_skill_code_not_blocked(self):
        # 技能代码编辑不归 H-SLSN 拦截（Gate 8 已强制登记流程），避免与自维护冲突
        skill_f = str(pre_tool_hook.SKILL_DIR / "scripts" / "gk_audit_docs.py")
        assert pre_tool_hook._hslsn_bypass(
            "Edit", {"file_path": skill_f}, "", skill_f, str(pre_tool_hook.SKILL_DIR)) is None

    def test_bypass_readonly_observer_allowed(self):
        """`REV-16` §22.3（2026-10-05 · owner 裁定「门禁加只读白名单」）：Phase A 只读观测脚本
        `gk_bill_observe.py` 直跑须**放行** —— 纯读 state / 零写盘 / 不夺锁，且 §21.3 砍-list 明禁
        经 `_CMD_REG` 注册 ⟹ 直跑是其**唯一**通道。红先：白名单未加前本臂红（观测面被误拦）。"""
        cmd = "python3 scripts/gk_bill_observe.py --state /tmp/s.json"
        assert pre_tool_hook._hslsn_bypass("RunCommand", {"command": cmd}, cmd, "", "/tmp") is None

    def test_bypass_readonly_whitelist_is_exact(self):
        """负臂 · 守「白名单不放宽同类」：非白名单的 `scripts/gk_*.py` 仍一律拦；且白名单**逐字**
        命中 ⟹ 近名形态（`gk_bill_observe_x.py`）不得搭车放行。"""
        for bad in ("python3 scripts/gk_advance.py",
                    "python3 scripts/gk_bill_observe_x.py",
                    "python3.12 scripts/gk_bill_observe_x.py"):
            r = pre_tool_hook._hslsn_bypass("RunCommand", {"command": bad}, bad, "", "/tmp")
            assert r is not None and "scripts/gk_" in r, bad

    def test_record_verdict_degrade_after_threshold(self):
        pre_tool_hook._hslsn_activate()
        for i in range(pre_tool_hook._HSLSN_MAX_ATTEMPTS):
            v = pre_tool_hook._hslsn_record_and_verdict("bypass-msg")
            assert v is not None  # 阈值内硬拦截
        v = pre_tool_hook._hslsn_record_and_verdict("bypass-msg")
        assert v is None  # 超阈值降级 WARN（防死循环）
        assert pre_tool_hook._hslsn_load()["learned"]  # 启发式学习留痕

    def test_main_skill_activation_blocks_bypass(self, tmp_path, monkeypatch):
        # Skill 工具调用（含技能名）→ 激活会话；随后绕过调用被 BLOCK（exit 2）
        import io as _io
        pre_tool_hook._hslsn_activate()
        data = {"tool_name": "RunCommand", "tool_input": {"command": "python3 scripts/gk_audit_docs.py"}, "cwd": "/tmp"}
        old_stdin = sys.stdin
        sys.stdin = _io.StringIO(json.dumps(data))
        try:
            with pytest.raises(SystemExit) as e:
                pre_tool_hook.main()
            assert e.value.code == 2
        finally:
            sys.stdin = old_stdin

    # ── 2026-08-27 全名化改造用例（投毒点关闭：精确匹配 + 旧名/未知名拦截）──

    def test_skill_exact_name_activates(self):
        """Skill 精确名 spz-gatekeeper-r-sequence → 激活 H-SLSN 会话（非子串匹配）。"""
        assert pre_tool_hook._hslsn_active() is False
        pre_tool_hook._hslsn_activate()
        assert pre_tool_hook._hslsn_active() is True
        d = pre_tool_hook._hslsn_load()
        assert d["active"] is True

    def test_skill_legacy_name_blocked(self, tmp_path, monkeypatch):
        """旧名 plan-refine 作为 Skill 名 → 拦截（歧义名投毒点关闭）。"""
        import io as _io
        monkeypatch.setattr(pre_tool_hook, "_HSLSN_FILE", tmp_path / ".gatekeeper.hslsn")
        data = {"tool_name": "Skill", "tool_input": {"name": "plan-refine"}, "cwd": "/tmp"}
        old_stdin = sys.stdin
        sys.stdin = _io.StringIO(json.dumps(data))
        try:
            with pytest.raises(SystemExit) as e:
                pre_tool_hook.main()
            assert e.value.code == 2
        finally:
            sys.stdin = old_stdin

    def test_skill_unknown_name_blocked(self, tmp_path, monkeypatch):
        """未注册技能名 → 拦截（未知命令全部拦截原则）。"""
        import io as _io
        monkeypatch.setattr(pre_tool_hook, "_HSLSN_FILE", tmp_path / ".gatekeeper.hslsn")
        monkeypatch.setattr(pre_tool_hook, "_hslsn_installed_skills", lambda: {"plan-refinement", "spz-gatekeeper-r-sequence"})
        data = {"tool_name": "Skill", "tool_input": {"name": "nonexistent-skill"}, "cwd": "/tmp"}
        old_stdin = sys.stdin
        sys.stdin = _io.StringIO(json.dumps(data))
        try:
            with pytest.raises(SystemExit) as e:
                pre_tool_hook.main()
            assert e.value.code == 2
        finally:
            sys.stdin = old_stdin

    def test_skill_legit_name_passes(self, tmp_path, monkeypatch):
        """已注册技能全名 plan-refinement → 放行（非拦截）。"""
        import io as _io
        monkeypatch.setattr(pre_tool_hook, "_HSLSN_FILE", tmp_path / ".gatekeeper.hslsn")
        monkeypatch.setattr(pre_tool_hook, "_hslsn_installed_skills", lambda: {"plan-refinement", "spz-gatekeeper-r-sequence"})
        data = {"tool_name": "Skill", "tool_input": {"name": "plan-refinement"}, "cwd": "/tmp"}
        old_stdin = sys.stdin
        sys.stdin = _io.StringIO(json.dumps(data))
        try:
            try:
                code = pre_tool_hook.main()
                assert code in (None, 0)  # 放行：正常返回
            except SystemExit as e:
                assert e.code == 0  # 放行：exit 0（scope_out 普适 gate 通过路径）
        finally:
            sys.stdin = old_stdin


class TestManualMode:
    def test_no_stdin(self):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO("")
        try:
            pre_tool_hook.main()
        except SystemExit as e:
            assert e.code == 0
        finally:
            sys.stdin = old_stdin


class TestHSLSNWhitelist:
    """H-SLSN 技能白名单扫描（2026-08-28 修复：WSL 运行下 Path.home() 指向 WSL home，
    ~/.trae/skills 不存在 → 白名单空集 → 非主技能名（如 git-workflow）被误拦"未注册"）。
    修复：补扫 Windows 用户技能根 /mnt/c/Users/<user>/.trae(或-trae-cn)/skills。"""

    def test_installed_skills_real_includes_git_workflow(self):
        """真实环境：白名单必须收录 git-workflow / spz-gatekeeper-r-sequence（修复目标）。"""
        import pre_tool_hook
        s = pre_tool_hook._hslsn_installed_skills()
        assert "git-workflow" in s, s
        assert "spz-gatekeeper-r-sequence" in s

    def test_installed_skills_native_root(self, tmp_path, monkeypatch):
        """原生根扫描：~/.trae/skills/<name>/SKILL.md 目录被收录。"""
        import pathlib
        import pre_tool_hook
        monkeypatch.setattr(pre_tool_hook, "_hslsn_win_skill_roots", lambda: [])
        monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: tmp_path))
        sk = tmp_path / ".trae" / "skills" / "demo-skill"
        sk.mkdir(parents=True)
        (sk / "SKILL.md").write_text("# demo\n", encoding="utf-8")
        assert "demo-skill" in pre_tool_hook._hslsn_installed_skills()

    def test_installed_skills_wsl_win_roots(self, tmp_path, monkeypatch):
        """WSL 补扫分支：Windows 用户技能根经 _hslsn_win_skill_roots 补扫被收录。"""
        import pre_tool_hook
        win = tmp_path / "win" / "Users" / "HP" / ".trae" / "skills"
        sk = win / "wsl-demo"
        sk.mkdir(parents=True)
        (sk / "SKILL.md").write_text("# wsl\n", encoding="utf-8")
        monkeypatch.setattr(pre_tool_hook, "_hslsn_win_skill_roots",
                            lambda: [win])
        assert "wsl-demo" in pre_tool_hook._hslsn_installed_skills()


class TestGateChainBlocked:
    @pytest.fixture(autouse=True)
    def _no_wsl_conversion(self):
        """Windows python 下 _win_to_wsl 把 worktree 转 /mnt/c 致 Gate 2 exists() 误判。
        hook 设计在 WSL 下运行；测试进程内跑需 identity 保持路径原样（2026-08-15）。"""
        with patch("pre_tool_hook._win_to_wsl", side_effect=lambda p: str(p)):
            yield

    def test_no_state_file(self, tmp_path):
        with patch("pre_tool_hook.STATE_FILE", tmp_path / "nonexistent.json"):
            code = run_hook_inline({
                "tool_name": "SearchReplace",
                "tool_input": {"file_path": str(tmp_path / "test.py")},
                "cwd": str(tmp_path),
            })
        assert code == 2

    def test_stage_idle(self, tmp_path):
        wt = tmp_path / "worktree"
        wt.mkdir()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"stage": "IDLE", "worktree": str(wt), "_checksum": "0000"}))

        with patch("pre_tool_hook.STATE_FILE", state_file):
            code = run_hook_inline({
                "tool_name": "SearchReplace",
                "tool_input": {"file_path": str(wt / "test.py")},
                "cwd": str(tmp_path),
            })
        assert code == 2

    def test_worktree_missing(self, tmp_path):
        wt = tmp_path / "nonexistent_worktree"
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"stage": "ECO-EDIT", "worktree": str(wt)}))

        with patch("pre_tool_hook.STATE_FILE", state_file):
            code = run_hook_inline({
                "tool_name": "SearchReplace",
                "tool_input": {"file_path": str(wt / "test.py")},
                "cwd": str(tmp_path),
            })
        assert code == 2

    def test_path_outside_worktree(self, tmp_path):
        wt = tmp_path / "worktree"
        wt.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "test.py").write_text("x")

        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"stage": "ECO-EDIT", "worktree": str(wt)}))

        with patch("pre_tool_hook.STATE_FILE", state_file):
            code = run_hook_inline({
                "tool_name": "Write",
                "tool_input": {"file_path": str(outside / "test.py")},
                "cwd": str(tmp_path),
            })
        assert code == 2


class TestGateChainAllowed:
    @pytest.fixture(autouse=True)
    def _no_wsl_conversion(self):
        with patch("pre_tool_hook._win_to_wsl", side_effect=lambda p: str(p)):
            yield

    def test_path_in_worktree_passes(self, tmp_path):
        wt = tmp_path / "worktree"
        wt.mkdir()
        test_file = wt / "test.py"
        test_file.write_text("x")

        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"stage": "ECO-EDIT", "worktree": str(wt)}))

        with patch("pre_tool_hook.STATE_FILE", state_file), \
             patch("pre_tool_hook._run_cli", return_value={"ok": True}):
            code = run_hook_inline({
                "tool_name": "Write",
                "tool_input": {"file_path": str(test_file)},
                "cwd": str(wt),
            })
        assert code == 0

    def test_read_outside_worktree_blocked(self, tmp_path):
        """Gate 5 (e85d417 引入): Read scope — file must be within active worktree.
        /any/path 在 worktree 外 → BLOCK (exit 2)。
        原 test_non_edit_tool_passes 断言 exit==0 与 Gate 5 冲突（e85d417 未同步更新），
        2026-08-04 修正断言以匹配 Gate 5 设计。"""
        wt = tmp_path / "worktree"
        wt.mkdir()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"stage": "ECO-EDIT", "worktree": str(wt)}))

        with patch("pre_tool_hook.STATE_FILE", state_file):
            code = run_hook_inline({
                "tool_name": "Read",
                "tool_input": {"file_path": "/any/path"},
                "cwd": str(tmp_path),
            })
        assert code == 2

    def test_read_inside_worktree_passes(self, tmp_path):
        """Gate 5 反向: Read worktree 内文件 → ALLOW (exit 0)。"""
        wt = tmp_path / "worktree"
        wt.mkdir()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"stage": "ECO-EDIT", "worktree": str(wt)}))

        with patch("pre_tool_hook.STATE_FILE", state_file):
            code = run_hook_inline({
                "tool_name": "Read",
                "tool_input": {"file_path": str(wt / "inside.py")},
                "cwd": str(tmp_path),
            })
        assert code == 0

    def test_task_gatekeeper_blocked(self, tmp_path):
        """Gate 0: bare Task（无票据）→ exit 2（方案 B 起判据 = 票据，关键词仅告警）。"""
        wt = tmp_path / "worktree"
        wt.mkdir()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"stage": "ECO-EDIT", "worktree": str(wt)}))

        with patch("pre_tool_hook.STATE_FILE", state_file):
            code = run_hook_inline({
                "tool_name": "Task",
                "tool_input": {
                    "subagent_type": "general_purpose_task",
                    "query": "Strict alignment review of Batch 8 Phase 2 gatekeeper scripts"
                },
                "cwd": str(tmp_path),
            })
        assert code == 2

    def test_task_non_gatekeeper_without_ticket_blocked(self, tmp_path):
        """方案 B（2026-10-27）：**默认拒绝** —— 非 gatekeeper 的 Task 无票据同样 exit 2。

        旧行为（关键词黑名单）下此调用 exit 0；改为默认拒绝后，「非关键词」不再是放行依据。
        """
        wt = tmp_path / "worktree"
        wt.mkdir()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"stage": "ECO-EDIT", "worktree": str(wt)}))

        with patch("pre_tool_hook.STATE_FILE", state_file):
            code = run_hook_inline({
                "tool_name": "Task",
                "tool_input": {
                    "subagent_type": "search",
                    "query": "Find all React components"
                },
                "cwd": str(tmp_path),
            })
        assert code == 2

    def test_task_non_gatekeeper_with_ticket_passes(self, tmp_path, monkeypatch):
        """带**有效单次票据**的非 gatekeeper Task → exit 0（放行依据 = 票据，不是关键词）。"""
        import gk_dispatch_ticket as _dt
        monkeypatch.setenv("GATEKEEPER_HMAC_KEY", "a" * 64)
        monkeypatch.delenv("GK_JOURNAL_KEY", raising=False)
        wt = tmp_path / "worktree"
        wt.mkdir()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"stage": "ECO-EDIT", "worktree": str(wt)}))
        query = "Find all React components"
        out = _dt.issue(str(state_file), query)
        assert out["ok"] is True, out

        with patch("pre_tool_hook.STATE_FILE", state_file):
            code = run_hook_inline({
                "tool_name": "Task",
                "tool_input": {
                    "subagent_type": "search",
                    "query": query + "\nGK-TICKET:" + out["ticket"],
                },
                "cwd": str(tmp_path),
            })
        assert code == 0


class TestResolvePath:
    def test_empty(self):
        assert resolve_path("", "") == ""

    def test_absolute(self):
        # Windows 下 /tmp 解析为 C:\tmp（.resolve() 相对当前驱动器），WSL 下保持 /tmp。
        # endswith 断言两平台兼容（2026-08-15 环境修复）。
        result = resolve_path("/tmp/test.py", "")
        assert result.replace("\\", "/").endswith("/tmp/test.py")

    def test_relative_with_cwd(self):
        result = resolve_path("test.py", "/tmp/cwd")
        assert "/tmp/cwd/test.py" in result.replace("\\", "/")


class TestPluginBareCall:
    """Gate R0.4 — 插件裸调用强制统一入口（2026-08-27）。

    bashpy-migrate / zthl_bashpy_migrate 只允许经 gatekeeper-cli.sh migrate 调用
    （manifest cap 白名单 + gk_bashpy_loader 加载安全网硬门禁），裸调用 → BLOCK。
    """

    def test_direct_cli_hit(self):
        assert pre_tool_hook._plugin_bare_call("bashpy-migrate audit --bomb") is not None

    def test_direct_exe_hit(self):
        assert pre_tool_hook._plugin_bare_call(
            "bashpy-migrate.exe verify --baseline x --output y") is not None

    def test_windows_path_exe_hit(self):
        assert pre_tool_hook._plugin_bare_call(
            "<home>/AppData/Local/Programs/Python/Python311/Scripts/bashpy-migrate.exe audit") is not None

    def test_module_entry_hit(self):
        assert pre_tool_hook._plugin_bare_call(
            "python3 -m zthl_bashpy_migrate.cli audit --script x") is not None

    def test_python_c_import_hit(self):
        assert pre_tool_hook._plugin_bare_call(
            'python3 -c "import zthl_bashpy_migrate"') is not None

    def test_unified_entry_allowed(self):
        assert pre_tool_hook._plugin_bare_call(
            "wsl bash gatekeeper-cli.sh migrate audit --bomb") is None

    def test_unified_entry_full_path_allowed(self):
        assert pre_tool_hook._plugin_bare_call(
            "bash <home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh "
            "migrate verify --baseline b --output o") is None

    def test_plain_command_allowed(self):
        assert pre_tool_hook._plugin_bare_call("ls -la") is None

    def test_other_python_script_allowed(self):
        assert pre_tool_hook._plugin_bare_call("wsl python3 /tmp/old_reqbody.sh ds") is None

    def test_pip_install_not_hit(self):
        # pip 包名 zthl-bashpy-migrate 的 `-bashpy-migrate` 段不应误报（lookbehind 排除 - 前缀）
        assert pre_tool_hook._plugin_bare_call("pip install zthl-bashpy-migrate") is None

    def test_semicolon_bare_call_hit(self):
        # 分号后裸调用不因"命令含 migrate 字样"绕过（按命令段逐段判定）
        assert pre_tool_hook._plugin_bare_call(
            "gatekeeper-cli.sh migrate; bashpy-migrate audit") is not None

    def test_wsl_wrapped_bare_hit(self):
        # WSL 包装形态：bashpy-migrate 前是空白（段首 \s）→ 命中
        assert pre_tool_hook._plugin_bare_call("wsl bashpy-migrate audit --bomb") is not None

    def test_bash_c_nested_hit(self):
        # bash -c 内嵌执行（引号内代码是真绕过，不是文字引用）→ 命中
        assert pre_tool_hook._plugin_bare_call(
            'bash -c "bashpy-migrate audit --bomb"') is not None

    def test_python_m_nested_hit(self):
        # bash -c 内嵌 python3 -m（引号内也抓）→ 命中
        assert pre_tool_hook._plugin_bare_call(
            "bash -c 'python3 -m zthl_bashpy_migrate audit'") is not None

    def test_eval_wrapped_hit(self):
        # eval 内嵌执行（红队 2026-08-27：eval 引号内是执行代码，不是文字引用）→ 命中
        assert pre_tool_hook._plugin_bare_call(
            'eval "bashpy-migrate audit --bomb"') is not None

    def test_eval_module_hit(self):
        assert pre_tool_hook._plugin_bare_call(
            "wsl bash -c \"eval 'python3 -m zthl_bashpy_migrate audit'\"") is not None

    def test_backslash_windows_path_hit(self):
        # Windows 反斜杠路径形态 → 命中
        assert pre_tool_hook._plugin_bare_call(
            r"<home>\AppData\Local\Programs\Python\Python311\Scripts\bashpy-migrate.exe audit") is not None

    def test_upgrade_script_python3_hit(self):
        # 升级/状态脚本裸调用（统一入口后禁止）→ 命中
        assert pre_tool_hook._plugin_bare_call(
            "python3 scripts/gk_bashpy_upgrade.py upgrade") is not None

    def test_upgrade_script_python_hit(self):
        assert pre_tool_hook._plugin_bare_call(
            "python scripts/gk_bashpy_upgrade.py status") is not None

    def test_upgrade_script_full_path_hit(self):
        assert pre_tool_hook._plugin_bare_call(
            "python <home>/.trae/skills/spz-gatekeeper-r-sequence/scripts/gk_bashpy_upgrade.py check") is not None

    def test_migrate_lifecycle_unified_allowed(self):
        # 生命周期子命令统一入口豁免（status/check/upgrade/rollback）
        for sub in ("status", "check", "upgrade", "rollback"):
            assert pre_tool_hook._plugin_bare_call(
                f"bash gatekeeper-cli.sh migrate {sub}") is None, sub

    def test_quoted_text_not_hit(self):
        # 引号内文字引用（commit message / echo）不是调用方式 → 放行
        # （2026-08-27 修复：自身提交命令因 commit message 含插件名被 R0.4 误拦）
        assert pre_tool_hook._plugin_bare_call(
            'git commit -m "R0.4: bashpy-migrate/zthl_bashpy_migrate 裸调用拦截"') is None

    def test_echo_quoted_not_hit(self):
        assert pre_tool_hook._plugin_bare_call(
            'echo "running bashpy-migrate verify"') is None

    def test_module_name_quoted_not_hit(self):
        assert pre_tool_hook._plugin_bare_call(
            "wsl git commit -m '迁移 zthl_bashpy_migrate 引用'") is None

    # ── swe-rb 平级注册（2026-08-31）：zthl-swe-rb 引擎裸调用拦截，与 bashpy-migrate 同型 ──
    def test_swe_rb_direct_hit(self):
        assert pre_tool_hook._plugin_bare_call("swe-rb analyze --repo x") is not None

    def test_swe_rb_module_entry_hit(self):
        assert pre_tool_hook._plugin_bare_call(
            "python3 -m zthl_swe_rb.cli analyze --repo x") is not None

    def test_swe_rb_python_c_import_hit(self):
        assert pre_tool_hook._plugin_bare_call(
            'python3 -c "import zthl_swe_rb"') is not None

    def test_swe_rb_unified_entry_allowed(self):
        assert pre_tool_hook._plugin_bare_call(
            "wsl bash gatekeeper-cli.sh swe-rb status") is None

    def test_swe_rb_full_path_allowed(self):
        assert pre_tool_hook._plugin_bare_call(
            "bash <home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh "
            "swe-rb verify --repo x --contract-only") is None

    def test_swe_rb_quoted_text_not_hit(self):
        assert pre_tool_hook._plugin_bare_call(
            'echo "swe-rb 是 SWE 重构契约验证引擎"') is None

    def test_swe_rb_lifecycle_unified_allowed(self):
        for sub in ("status", "check"):
            assert pre_tool_hook._plugin_bare_call(
                f"bash gatekeeper-cli.sh swe-rb {sub}") is None, sub

    def test_swe_rb_node_guard_pid_allowed(self):
        # node_guard guard 的 --pid swe-rb 是节点标识参数（SRB G/D 验证），非插件裸调用
        # （2026-09-01 误伤：模式把参数值当裸调用拦截）
        assert pre_tool_hook._plugin_bare_call(
            "python3 gk_node_guard.py guard --node SRB-ANALYZE --pid swe-rb") is None

    def test_swe_rb_node_guard_exemption_no_bypass(self):
        # 豁免不削弱真实拦截：同段走私形态照抓（guard 豁免仅锚定 gk_node_guard.py 前缀）
        assert pre_tool_hook._plugin_bare_call(
            "swe-rb analyze --repo x && python3 gk_node_guard.py guard --pid swe-rb") is not None

    def test_swe_rb_node_guard_cmdsub_smuggle_blocked(self):
        # 红队向量 A（2026-09-01）：$(python3 -m zthl_swe_rb ...) 命令替换走私 → 拒绝豁免 → BLOCK
        assert pre_tool_hook._plugin_bare_call(
            "python3 gk_node_guard.py guard --node SRB-ANALYZE --pid swe-rb "
            "$(python3 -m zthl_swe_rb audit --repo /tmp/x --out contract.json)") is not None

    def test_swe_rb_node_guard_newline_smuggle_blocked(self):
        # 红队向量 B：换行非切分符，guard 段跨行走私 python3 -m zthl_swe_rb → BLOCK
        assert pre_tool_hook._plugin_bare_call(
            "gk_node_guard.py guard --pid swe-rb\npython3 -m zthl_swe_rb audit") is not None

    def test_swe_rb_node_guard_cross_plugin_smuggle_blocked(self):
        # 红队向量 C：guard 段内 $(bash -c 'bashpy-migrate audit') 跨插件走私 → BLOCK
        assert pre_tool_hook._plugin_bare_call(
            "gk_node_guard.py guard --pid swe-rb $(bash -c 'bashpy-migrate audit')") is not None

    def test_swe_rb_node_guard_ctx_trailing_allowed(self):
        # 合法形态：--pid swe-rb 后带尾部 --ctx（G/D 验证 ctx 注入）→ 豁免放行
        assert pre_tool_hook._plugin_bare_call(
            "python3 gk_node_guard.py guard --node SRB-ANALYZE --pid swe-rb "
            "--ctx '{\"entry_ok\": true}'") is None

    # ── paper-review 平级注册（2026-09-20，ECC-E4A5EB64FD05 / ECC-PLAN ④）──
    # 病灶：gk_paper_review.py **不在** _PLUGIN_BARE_PATTERNS ⟹ hook 不拦其裸调用；
    # 且插件内 fail-closed 只校验**自声明**的 GK_PAPER_REVIEW_VIA_CLI=1（可伪造）⟹ 直连即
    # 跳过唯一真正跑 gk_paper_review_loader 五源分流 + SHA256 pin 的地方（CLI cmd_paper_review）。
    def test_paper_review_direct_path_hit(self):
        assert pre_tool_hook._plugin_bare_call(
            "python3 <home>/.trae/skills/spz-gatekeeper-r-sequence/scripts/"
            "gk_paper_review.py --venue aamas --papers-dir /tmp/p") is not None

    def test_paper_review_self_declared_env_still_hit(self):
        # 报告实测的绕过形态：自声明 CLI 标记 + 直连脚本（插件内那道门形同纸面）
        assert pre_tool_hook._plugin_bare_call(
            "GK_PAPER_REVIEW_VIA_CLI=1 python3 scripts/gk_paper_review.py --venue fse") is not None

    def test_paper_review_unified_entry_allowed(self):
        assert pre_tool_hook._plugin_bare_call(
            "bash gatekeeper-cli.sh paper-review --venue aamas --papers-dir /tmp/p") is None

    def test_paper_review_own_test_file_not_hit(self):
        # 误伤防线：`test_gk_paper_review.py` 的 `test_` 前无路径分隔符 ⟹ 不算插件调用
        # （否则 `python3 scripts/test_gk_paper_review.py` 自测被自家 hook 拦死）
        assert pre_tool_hook._plugin_bare_call(
            "python3 scripts/test_gk_paper_review.py -q") is None


class TestEscalationDefense:
    """工具失效→提权绕过 三层防线（2026-09-02 用户需求）。

    场景链（模拟 agent 反应）: Edit 写 X 被 BLOCK → agent 放弃重试 → RunCommand
    `echo > X` 直写同一文件（绕过 Gate3/8/CLI pre-tool-check 的越权通道）。
    防线: ② 被禁意图持久化 state gate_data.hook_block_log（ring+TTL+_checksum 一致）
          + ③ Gate R0.5 权限边界拦截（同目标直写 → BLOCK）+ 快照监控信号（escalations）。
    """

    @pytest.fixture(autouse=True)
    def _no_wsl_conversion(self):
        """Windows python 下保持路径原样（同既有 GateChain 测试，Gate2 exists() 判定可用）。"""
        with patch("pre_tool_hook._win_to_wsl", side_effect=lambda p: str(p)):
            yield

    @staticmethod
    def _mk_state(tmp_path: Path, wt: Path) -> Path:
        import hashlib
        sp = tmp_path / ".gatekeeper.state"
        gd = {"narrow_tasks": []}
        data = {"r_phase": "R1", "stage": "ECO-EDIT", "worktree": str(wt), "gate_data": gd,
                "_checksum": hashlib.sha256(
                    json.dumps(gd, sort_keys=True, ensure_ascii=True).encode()).hexdigest()[:16]}
        sp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return sp

    def test_block_intent_recorded_checksum_consistent(self, tmp_path):
        """防线②：BLOCK 意图落 state gate_data.hook_block_log，且 _checksum 与
        gk_state._write_state 算法一致（gate_data 篡改检测不因意图日志误报）。"""
        wt = tmp_path / "worktree"
        wt.mkdir()
        sp = self._mk_state(tmp_path, wt)
        target = wt / "victim.md"
        with patch("pre_tool_hook.STATE_FILE", sp), \
             patch.object(pre_tool_hook, "_CALL_TOOL", "Edit"), \
             patch.object(pre_tool_hook, "_CALL_TARGET", str(target)), \
             patch.object(pre_tool_hook, "_CALL_KIND", "block"), \
             patch.object(pre_tool_hook, "_CALL_IN_SCOPE", True), \
             patch.object(pre_tool_hook, "_CALL_REASON", "Gate3 越界"):
            pre_tool_hook._record_block_intent()
        d = json.loads(sp.read_text(encoding="utf-8"))
        log = d["gate_data"]["hook_block_log"]
        assert len(log) == 1
        assert log[0]["tool"] == "Edit" and log[0]["kind"] == "block"
        assert log[0]["target"].replace("\\", "/").endswith("victim.md")
        gd = d["gate_data"]
        calc = hashlib.sha256(json.dumps(gd, sort_keys=True, ensure_ascii=True).encode()).hexdigest()[:16]
        assert d["_checksum"] == calc

    def test_scope_out_blocks_not_recorded(self, tmp_path):
        """治理范围外（scope_out）的普适 BLOCK 不入技能 state 的意图日志（防污染）。"""
        # 任意（scope_out 分支不触碰 STATE_FILE 解析）
        with patch("pre_tool_hook.STATE_FILE", tmp_path / "no_state.json"), \
             patch.object(pre_tool_hook, "_CALL_IN_SCOPE", False), \
             patch.object(pre_tool_hook, "_CALL_TOOL", "RunCommand"), \
             patch.object(pre_tool_hook, "_CALL_KIND", "block"):
            pre_tool_hook._record_block_intent()
        assert not (tmp_path / "no_state.json").exists()

    def test_edit_block_then_runcommand_write_blocked(self, tmp_path):
        """整链（模拟 agent 工具失效反应）：Edit 越界写 X BLOCK → agent 放弃重试 →
        RunCommand echo>X 同目标直写 → Gate R0.5 提权绕过拦截；被禁文件从未被写入。"""
        wt = tmp_path / "worktree"
        wt.mkdir()
        victim_dir = tmp_path / "outside"
        victim_dir.mkdir()
        victim = victim_dir / "victim.md"
        sp = self._mk_state(tmp_path, wt)
        with patch("pre_tool_hook.STATE_FILE", sp):
            # 1) Edit X（越界）→ Gate3 BLOCK（意图记录 kind=block）
            rc1 = run_hook_inline({
                "tool_name": "Edit",
                "tool_input": {"file_path": str(victim), "new_str": "x"},
                "cwd": str(wt),
            })
            assert rc1 == 2
            # 2) RunCommand 直写同一文件 → R0.5 BLOCK（kind=escalation）
            rc2 = run_hook_inline({
                "tool_name": "RunCommand",
                "tool_input": {"command": f"echo hacked > {victim}"},
                "cwd": str(wt),
            })
            assert rc2 == 2
        assert not victim.exists(), "越权写入必须被拦截（文件未产生）"
        d = json.loads(sp.read_text(encoding="utf-8"))
        log = d["gate_data"]["hook_block_log"]
        assert [r["kind"] for r in log] == ["block", "escalation"]
        snap = pre_tool_hook._block_log_snapshot(str(sp))
        assert snap["blocks"] == 2 and snap["escalations"] == 1

    def test_runcommand_write_without_prior_block_allowed(self, tmp_path):
        """无被禁意图 → RunCommand 重定向写（治理内）不被 R0.5 拦截（保留既有行为，防误伤）。"""
        wt = tmp_path / "worktree"
        wt.mkdir()
        sp = self._mk_state(tmp_path, wt)
        with patch("pre_tool_hook.STATE_FILE", sp):
            rc = run_hook_inline({
                "tool_name": "RunCommand",
                "tool_input": {"command": f"echo hi > {wt / 'legit.txt'}"},
                "cwd": str(wt),
            })
        assert rc == 0
        snap = pre_tool_hook._block_log_snapshot(str(sp))
        assert snap["blocks"] == 0 and snap["escalations"] == 0

    def test_retry_same_tool_not_false_positive(self, tmp_path):
        """同一 Edit 目标合法重试（修复后）不触发 escalation 语义——escalation 只由
        跨工具（RunCommand 直写）触发，Edit→Edit 重试仍是普通 block 记录（不叠加越权）。"""
        wt = tmp_path / "worktree"
        wt.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        victim = outside / "v.md"
        sp = self._mk_state(tmp_path, wt)
        with patch("pre_tool_hook.STATE_FILE", sp):
            for _ in range(2):
                rc = run_hook_inline({
                    "tool_name": "Write",
                    "tool_input": {"file_path": str(victim), "content": "x"},
                    "cwd": str(wt),
                })
                assert rc == 2
        d = json.loads(sp.read_text(encoding="utf-8"))
        log = d["gate_data"]["hook_block_log"]
        assert [r["kind"] for r in log] == ["block", "block"]  # 无 escalation

    def test_ttl_window_expiry(self, tmp_path):
        """TTL 窗口外（>1800s）的旧意图不再触发 R0.5（stale 意图过期）。"""
        wt = tmp_path / "worktree"
        wt.mkdir()
        victim_dir = tmp_path / "outside"
        victim_dir.mkdir()
        victim = victim_dir / "stale.md"
        sp = self._mk_state(tmp_path, wt)
        # 预置一条 10 分钟前的 block 意图（stale）
        import hashlib as _h
        d = json.loads(sp.read_text(encoding="utf-8"))
        d["gate_data"]["hook_block_log"] = [{
            "ts": time.time() - 2000, "tool": "Edit", "target": str(victim),
            "kind": "block", "reason": "stale"}]
        d["_checksum"] = _h.sha256(json.dumps(d["gate_data"], sort_keys=True, ensure_ascii=True)
                                   .encode()).hexdigest()[:16]
        sp.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
        with patch("pre_tool_hook.STATE_FILE", sp):
            rc = run_hook_inline({
                "tool_name": "RunCommand",
                "tool_input": {"command": f"echo x > {victim}"},
                "cwd": str(wt),
            })
        # stale 意图不触发 R0.5 → 走到 Gate2（worktree 存在）→ 无后续拦截 → ALLOW
        assert rc == 0
        snap = pre_tool_hook._block_log_snapshot(str(sp))
        assert snap["blocks"] == 0  # TTL 过滤后窗口内为空


class TestWslQuoteTrap:
    """(c) 行为矩阵补缺（2026-09-06 ㉖ 盘点：`_wsl_quoting_trap` 此前零直接单测）。

    WSL 引号陷阱（PS 宿主展开 + PS 5.1 native-arg mangling）——纯语法、无状态依赖、普适 gate。
    命中 → 修复指引 wslsh -c '<原文>'（内容不经过 wsl.exe 命令行）。
    """

    def test_double_quote_outer_hit(self):
        hit = pre_tool_hook._wsl_quoting_trap('wsl bash -c "echo $HOME"')
        assert hit is not None and "double-quote" in hit

    def test_wsl_exe_double_quote_hit(self):
        hit = pre_tool_hook._wsl_quoting_trap('wsl.exe bash -c "cd /tmp && ls"')
        assert hit is not None

    def test_single_quote_with_inner_quote_hit(self):
        # 单引号外层但内部含双引号（PS 5.1 剥内嵌引号；7.3+ 已修，判据保留）→ 命中
        hit = pre_tool_hook._wsl_quoting_trap("wsl bash -c 'echo \"$x\"'")
        assert hit is not None and "strips embedded quotes" in hit

    def test_single_quote_with_command_substitution_hit(self):
        hit = pre_tool_hook._wsl_quoting_trap("wsl bash -c 'echo $(pwd)'")
        assert hit is not None

    def test_wslsh_recommended_path_exempt(self):
        # wslsh 自落临时 .sh，内容不经 wsl.exe 命令行 → 豁免
        assert pre_tool_hook._wsl_quoting_trap('wslsh -c "echo $HOME"') is None

    def test_single_quote_clean_pass(self):
        assert pre_tool_hook._wsl_quoting_trap("wsl bash -c 'echo hi'") is None

    def test_no_wsl_pass(self):
        assert pre_tool_hook._wsl_quoting_trap("echo hi") is None

    def test_wsl_script_no_dash_c_pass(self):
        assert pre_tool_hook._wsl_quoting_trap("wsl bash /tmp/run.sh arg") is None


class TestPSManglingStory:
    """Gate R0.6【蓝色大肥鱼与powershell之间不得不说的故事】(2026-09-14)。

    PS 宿主对**任意** RunCommand 命令串的解析改写 —— 独立于 R0.1（后者只认 `wsl bash -c` 形态）。
    三例实证（2026-09-14 第五轮质询全程，均静默穿过当时全部 gate）：
      ① `bash -lc "...\\$P..."` ⟹ PS 先展开 $P（该变量只在 bash 里）⟹ --task 未被绑定；
      ② `git commit -m "$(cat <<'EOF' …)"` ⟹ PS ParserError（无 heredoc 重定向）；
      ③ `python -c "…[0-9.]+…"` ⟹ PS 类型字面量解析。
    严格度：P1-P3 = BLOCK，P4 = WARN。
    """

    def test_p1_bash_dq_payload_with_var_block(self):
        hit = pre_tool_hook._blue_fat_fish_ps_story('bash -lc "cd /x && echo $P"')
        assert hit is not None and hit[0] == "BLOCK" and "双引号载荷含 '$'" in hit[1]

    def test_p1_backslash_escaped_var_still_block(self):
        # 实证形态 '\\$P'：PS 把 '\' 当字面量后仍展开 $P ⟹ 同样受损
        hit = pre_tool_hook._blue_fat_fish_ps_story('bash -lc "cd /x && P=docs; echo \\$P"')
        assert hit is not None and hit[0] == "BLOCK"

    def test_p1_single_quoted_payload_with_var_block(self):
        # [ECC-EE9B544B88EA] 原断言「单引号安全」**被实测证伪**：宿主层对**单引号**载荷内的裸
        #   '$X' 照样展开（实测 `bash -lc 'X=abc; echo "[$X]"'` ⟹ 打出 `[]`，**静默置空**、
        #   无报错）—— 这正是跨宿主流程摩擦的主因（agent 写 $VAR，宿主先吃、命令静默错）。
        hit = pre_tool_hook._blue_fat_fish_ps_story("bash -lc 'echo $HOME'")
        assert hit is not None and hit[0] == "BLOCK" and "单引号载荷含未转义" in hit[1]

    def test_p1_single_quoted_escaped_var_pass(self):
        # '\$X' 可存活（实测 `bash -lc 'X=abc; echo "A:\$X"'` ⟹ 'A:abc'）⟹ 放行（正确的 next）。
        assert pre_tool_hook._blue_fat_fish_ps_story(
            "bash -lc 'X=abc; echo \"A:\\$X\"'") is None

    def test_p1_dq_payload_without_var_pass(self):
        assert pre_tool_hook._blue_fat_fish_ps_story(
            'bash -lc "cd /x && bash cli.sh plan-refinement p.md --task \'中文串\'"') is None

    def test_p2_heredoc_in_subexpression_block(self):
        hit = pre_tool_hook._blue_fat_fish_ps_story("git commit -m \"$(cat <<'EOF' hi EOF)\"")
        assert hit is not None and hit[0] == "BLOCK" and "<<" in hit[1]

    def test_p2_heredoc_inside_single_quoted_payload_pass(self):
        assert pre_tool_hook._blue_fat_fish_ps_story("bash -c 'cat <<EOF\nhi\nEOF'") is None

    def test_p3_backtick_outside_single_quotes_block(self):
        hit = pre_tool_hook._blue_fat_fish_ps_story('echo "a \x60b\x60 c"')
        assert hit is not None and hit[0] == "BLOCK" and "反引号" in hit[1]

    def test_p3_backtick_inside_single_quotes_pass(self):
        assert pre_tool_hook._blue_fat_fish_ps_story("echo 'a \x60b\x60 c'") is None

    def test_p4_type_literal_warn_only(self):
        hit = pre_tool_hook._blue_fat_fish_ps_story('python -c "re.sub(\'[0-9.]+\', \'\', s)"')
        assert hit is not None and hit[0] == "WARN"

    def test_p4_test_expression_outside_c_pass(self):
        assert pre_tool_hook._blue_fat_fish_ps_story("if [ -f x ]; then echo y; fi") is None

    def test_empty_pass(self):
        assert pre_tool_hook._blue_fat_fish_ps_story("") is None


class TestWslFamilyStory:
    """Gate R0.7【蓝色大肥鱼与wsl之间不得不说的故事】(2026-09-14)。

    wsl 家族入口（wsl / wsl.exe / wslsh / WSLENV）的引号与编码陷阱。
    **关键认知**：wslsh 的「落临时 .sh」只保护 **wsl.exe 命令行层**，不保护 **PowerShell 层**
    —— `wslsh -c "…$VAR…"` 中的 `$VAR` 在 wslsh 拿到参数**之前**就被 PS 展开。
    严格度：W1/W2 = BLOCK，W3/W4/W5 = WARN。
    """

    def test_w1_wslsh_dq_var_block(self):
        hit = pre_tool_hook._blue_fat_fish_wsl_story('wslsh -c "cd /mnt/c && echo $P"')
        assert hit is not None and hit[0] == "BLOCK" and "wslsh" in hit[1]

    def test_w1_wslsh_dq_backtick_block(self):
        hit = pre_tool_hook._blue_fat_fish_wsl_story('wslsh -c "echo \x60date\x60"')
        assert hit is not None and hit[0] == "BLOCK"

    def test_w1_wslsh_single_quoted_pass(self):
        assert pre_tool_hook._blue_fat_fish_wsl_story("wslsh -c 'cd /mnt/c && echo $HOME'") is None

    def test_w1_wslsh_plain_script_pass(self):
        assert pre_tool_hook._blue_fat_fish_wsl_story('wslsh C:\\path\\x.sh a b') is None

    def test_w2_wsl_exec_dq_inner_quote_block(self):
        hit = pre_tool_hook._blue_fat_fish_wsl_story('wsl -- bash -c "cd /x && echo \\"$x\\""')
        assert hit is not None and hit[0] == "BLOCK"

    def test_w2_wsl_dash_e_cmd_subst_block(self):
        hit = pre_tool_hook._blue_fat_fish_wsl_story('wsl -e bash -c "echo $(pwd)"')
        assert hit is not None and hit[0] == "BLOCK"

    def test_w2_wsl_dash_e_clean_pass(self):
        assert pre_tool_hook._blue_fat_fish_wsl_story('wsl -e bash -c "echo hi"') is None

    def test_w3_wslenv_missing_u_warn(self):
        hit = pre_tool_hook._blue_fat_fish_wsl_story(
            "WSLENV=DEEPSEEK_API_KEY:STATE_FILE/u wsl bash /mnt/c/x.sh")
        assert hit is not None and hit[0] == "WARN" and "缺 /u" in hit[1]

    def test_w3_wslenv_with_u_pass(self):
        assert pre_tool_hook._blue_fat_fish_wsl_story(
            "WSLENV=DEEPSEEK_API_KEY/u:MIMO_API_KEY/u wsl bash /mnt/c/x.sh") is None

    def test_w4_windows_path_warn(self):
        hit = pre_tool_hook._blue_fat_fish_wsl_story("wsl bash <home>\\x.sh")
        assert hit is not None and hit[0] == "WARN" and "mnt" in hit[1]

    def test_w4_mnt_path_pass(self):
        assert pre_tool_hook._blue_fat_fish_wsl_story("wsl bash <home>/x.sh") is None

    def test_empty_pass(self):
        assert pre_tool_hook._blue_fat_fish_wsl_story("") is None

    # ── 2026-09-24（ECC 待登记）：载体正则须认**组合短选项**（`-lc`），否则两侧同时出错 ──
    # 实测（本会话被 R0.7 拦 3 次）：W2 载体正则写 `-c\s+`，而 `bash -lc '<载荷>'` 里的
    # `-lc` **不含子串 `-c`**（字符序列是 `-`,`l`,`c`）⟹ 正则跳过外层、向后锁到**内层**
    # `python -c "…"` 的双引号载荷 ⟹ 判为 PS mangling 风险。两向后果：
    #   ① **误伤**：外层**单引号**载荷本就无风险（PS 不展开单引号内内容）却被 BLOCK；
    #   ② **漏网**：`wsl -e bash -lc "…$(…)"` 的**双引号**载荷是真风险（PS 会展开）却**从不拦**。
    def test_w2_login_shell_single_quoted_inner_python_c_pass(self):
        """`wsl -e bash -lc '<单引号载荷>'`（载荷内含 `python -c "…"`）⟹ **不得**拦。

        载荷须复刻**真实触发形态**：内层 `python -c "…"` 里带 ≥3 个双引号（如
        `json.dumps(..., ensure_ascii=False)` 一类），否则旧代码的 `count('"') > 2` 不成立、
        本臂会**假绿**（首版即踩：只写一对引号 ⟹ 修前也过）。
        """
        cmd = ('wsl.exe -e bash -lc \'cd /x && /opt/spz-py312/bin/python -c "import json;'
               'print(json.dumps({\\"a\\":1}, ensure_ascii=False))"\'')
        assert pre_tool_hook._blue_fat_fish_wsl_story(cmd) is None

    def test_w2_login_shell_double_quoted_payload_blocks(self):
        """对照/漏网臂：`-lc` 的**双引号**载荷含 `$(` ⟹ 必须 BLOCK（修前此处**漏网**）。"""
        hit = pre_tool_hook._blue_fat_fish_wsl_story('wsl -e bash -lc "echo $(pwd)"')
        assert hit is not None and hit[0] == "BLOCK", (
            "`-lc` 双引号载荷被 PS 展开却是真风险，必须拦：%r" % (hit,))

    # ── W5（2026-10-01，finding ECC-2EB738051C82）：stdin 管道的裸 CR 污染末 token ──
    # 机理：`wsl … bash` **无脚本参数** ⟹ 脚本经 stdin 管道送入 ⟹ PS 在管道末尾补裸 CR，
    #   粘在**最后一个 token** 上（实测 `git log --oneline -1` 参数变 `-1` + 裸 CR ⟹ git fatal）。
    def test_w5_bare_bash_stdin_warn(self):
        hit = pre_tool_hook._blue_fat_fish_wsl_story("git log -1 | wsl.exe -- bash")
        assert hit is not None and hit[0] == "WARN" and "CR" in hit[1], (
            "无脚本参数的 wsl bash（stdin 形态）须 WARN：%r" % (hit,))

    def test_w5_piped_bare_bash_warn(self):
        hit = pre_tool_hook._blue_fat_fish_wsl_story("echo hi | wsl bash")
        assert hit is not None and hit[0] == "WARN"

    def test_w5_script_file_pass(self):
        """对照：走**脚本文件**（命令行传参，不经 stdin 管道）⟹ 不得命中。"""
        assert pre_tool_hook._blue_fat_fish_wsl_story(
            "wsl.exe -e bash <home>/.gk_zh1.sh") is None

    def test_w5_inline_c_pass(self):
        """对照：`bash -lc '<载荷>'` 为命令行传参 ⟹ 不得命中（防误伤）。"""
        assert pre_tool_hook._blue_fat_fish_wsl_story('wsl bash -lc "echo hi"') is None


class TestPSAliasStory:
    """Gate R0.12【蓝色大肥鱼与 PowerShell 别名之间不得不说的故事】(2026-10-10)。

    实测摩擦：RunCommand 在 **PS** 上执行，`ls -d <path>` 被 PS 的**别名**解析成
    `Get-ChildItem -Depth <path>`（`-Depth` 只收整数）⟹ 报错 / 静默错值。同类：`cat -n`、
    `cp -r`、`mv -f`、`curl -o`、`wget -O`、`head -n`、`ps aux`… 全是 **POSIX 形态**，
    在 PS 上语义与 POSIX 完全不同（`curl`/`wget` = `Invoke-WebRequest` 的别名）。
    严格度：BLOCK（对齐 R0.6 P1-P3；可静默错值故不降级）。
    """

    def test_a1_ls_posix_flag_block(self):
        hit = pre_tool_hook._blue_fat_fish_ps_alias_story("ls -d <home>")
        assert hit is not None and hit[0] == "BLOCK" and "别名" in hit[1]

    def test_a1_ls_la_block(self):
        assert pre_tool_hook._blue_fat_fish_ps_alias_story("ls -la /tmp/gk-probe")[0] == "BLOCK"

    def test_a1_cp_r_block(self):
        hit = pre_tool_hook._blue_fat_fish_ps_alias_story("cp -r a b")
        assert hit is not None and hit[0] == "BLOCK"

    def test_a1_mv_f_block(self):
        assert pre_tool_hook._blue_fat_fish_ps_alias_story("mv -f a b")[0] == "BLOCK"

    def test_a1_cat_dash_n_block(self):
        assert pre_tool_hook._blue_fat_fish_ps_alias_story("cat -n README.md")[0] == "BLOCK"

    def test_a1_curl_dash_o_block(self):
        hit = pre_tool_hook._blue_fat_fish_ps_alias_story("curl -o out.html https://example.com")
        assert hit is not None and hit[0] == "BLOCK"

    def test_a1_wget_dash_O_block(self):
        assert pre_tool_hook._blue_fat_fish_ps_alias_story(
            "wget -O out.html https://example.com")[0] == "BLOCK"

    def test_a1_ps_aux_block(self):
        hit = pre_tool_hook._blue_fat_fish_ps_alias_story("ps aux")
        assert hit is not None and hit[0] == "BLOCK"

    def test_a1_after_separator_block(self):
        hit = pre_tool_hook._blue_fat_fish_ps_alias_story("echo hi; ls -d /tmp/gk-probe")
        assert hit is not None and hit[0] == "BLOCK"

    # ── 反例：不得误伤（合法形态）──
    def test_pshost_wsl_prefixed(self):
        assert pre_tool_hook._blue_fat_fish_ps_alias_story("wsl ls -la /mnt/c/x") is None

    def test_pshost_native_cmdlet(self):
        assert pre_tool_hook._blue_fat_fish_ps_alias_story("Get-ChildItem -Depth 2") is None

    def test_pshost_alias_without_posix_flag(self):
        assert pre_tool_hook._blue_fat_fish_ps_alias_story("ls /mnt/c/x") is None

    def test_pshost_curl_exe_explicit(self):
        assert pre_tool_hook._blue_fat_fish_ps_alias_story(
            "curl.exe -o out.html https://example.com") is None

    def test_pshost_git_flag_not_alias(self):
        assert pre_tool_hook._blue_fat_fish_ps_alias_story("git log --oneline -3") is None

    def test_pshost_wsl_git_C(self):
        assert pre_tool_hook._blue_fat_fish_ps_alias_story(
            "wsl git -C /mnt/c/x log --oneline -3") is None

    def test_pshost_empty_pass(self):
        assert pre_tool_hook._blue_fat_fish_ps_alias_story("") is None

    def test_pshost_mkdir_p_not_blocked(self):
        """R0.12 × R0.2 hint 冲突锁（finding `ECC-BC9FB99C4C93`）：`mkdir -p` **非** PS 危险形态。

        实测（2026-10-13，Windows PowerShell）：`mkdir -p <新嵌套路径>` **能**建出嵌套目录；
        `-p` 被 PS `New-Item` 接受（前缀 → `-Path`），不满足 R0.12 判据「PS cmdlet **不接受**
        的 POSIX 专属旗标」（对比真阳性 `ls -d` → `Get-ChildItem -Depth` 只收整数 ⟹ 静默错值）。
        原表 `mkdir: "p"` 系**假阳性**，且恰是 R0.2 自动替换 hint（`mkdir -p "<trash>" && mv -- …`）
        的形态 ⟹ hook 自家建议过不了自家闸（Q2 自洽臂 C 红先抓出）。
        """
        assert pre_tool_hook._blue_fat_fish_ps_alias_story('mkdir -p "/tmp/gk-trash"') is None
        # 对照（真阳性不许回退）：`ls -d` 一类**静默错值**形态仍须拦。
        assert pre_tool_hook._blue_fat_fish_ps_alias_story("ls -d /tmp/x")[0] == "BLOCK"


class TestPSPosixSyntaxStory:
    """Gate R0.13【蓝色大肥鱼与 PowerShell 解析器之间不得不说的故事】(2026-10-10)。

    实测摩擦：在 PS 上直接跑 **POSIX 控制语法** —— `for i in a b; do echo hi; done` ⟹
    PS ParserError（实测 `Missing statement body in do loop`）。修法：包
    `wsl -e bash -lc '…'` 或 Write 落 `.sh`。严格度：BLOCK（对齐 R0.6 P1-P3）。
    """

    def test_f1_for_do_done_block(self):
        hit = pre_tool_hook._blue_fat_fish_ps_posix_story("for i in a b; do echo hi; done")
        assert hit is not None and hit[0] == "BLOCK" and "POSIX" in hit[1]

    def test_f1_after_separator_block(self):
        assert pre_tool_hook._blue_fat_fish_ps_posix_story(
            "cd /x && for i in a b; do echo hi; done")[0] == "BLOCK"

    def test_f1_while_done_block(self):
        assert pre_tool_hook._blue_fat_fish_ps_posix_story(
            "while read x; do echo hi; done")[0] == "BLOCK"

    def test_f1_if_then_fi_block(self):
        assert pre_tool_hook._blue_fat_fish_ps_posix_story("if [ -f x ]; then echo y; fi")[0] == "BLOCK"

    def test_f1_case_esac_block(self):
        assert pre_tool_hook._blue_fat_fish_ps_posix_story("case $x in a) echo 1;; esac")[0] == "BLOCK"

    # ── 反例：不得误伤 ──
    def test_pshost_wrapped_bash_lc(self):
        assert pre_tool_hook._blue_fat_fish_ps_posix_story(
            "wsl -e bash -lc 'for i in a b; do echo $i; done'") is None

    def test_pshost_bare_bash_lc(self):
        assert pre_tool_hook._blue_fat_fish_ps_posix_story(
            "bash -lc 'for i in a b; do echo hi; done'") is None

    def test_pshost_bash_script_file(self):
        assert pre_tool_hook._blue_fat_fish_ps_posix_story("bash /mnt/c/x.sh") is None

    def test_pshost_plain_command(self):
        assert pre_tool_hook._blue_fat_fish_ps_posix_story("git status --porcelain") is None

    def test_pshost_ps_native_foreach(self):
        assert pre_tool_hook._blue_fat_fish_ps_posix_story("foreach ($i in 1..3) { }") is None

    def test_pshost_empty_pass(self):
        assert pre_tool_hook._blue_fat_fish_ps_posix_story("") is None


class TestReviewNodeBinding:
    """Gate 1b — 交叉审查车道节点绑定（2026-09-06，用户批评点闭环）。

    缺陷复盘: L2(--crossrev)/后R 双独立(monitor --subagent)/plan-refinement 质询等
    subagent/LLM 车道，CLI 侧仅 crossrev 显式通道有 CROSSREVIEW_NODE_BINDING；裸跑
    monitor --subagent 无节点绑定 → 任意阶段可跑，"全量 L1-L10 交叉审查" 可只跑确定性
    部分而跳过 L2/L3/L4/L5（车道绕过）。本测试钉死:
      ① subagent/LLM 车道须审查节点（standard STAGE_3|AUDIT-CROSSR / standing ECO-READ|ECO-AUDIT）；
      ② 非审查节点 + subagent 车道 → BLOCK（kind=review 留痕，hook_block_log 可审计）；
      ③ 确定性证据车道（doc-align/self-check/audit --crossr/monitor --local…）任意 active 阶段放行；
      ④ IDLE/DONE + review 形态 → BLOCK 且 kind=review；
      ⑤ GK_DEGRADE_REVIEW=1 显式降级豁免（对齐 CLI CROSSREVIEW_NODE_BINDING 语义）。
    """

    @pytest.fixture(autouse=True)
    def _no_wsl_conversion(self):
        with patch("pre_tool_hook._win_to_wsl", side_effect=lambda p: str(p)):
            yield

    # ── 纯函数：车道识别 ──
    def test_lookup_subagent_crossrev(self):
        r = pre_tool_hook._review_lane_lookup(
            'gatekeeper-cli.sh monitor --subagent --crossrev "L2 code-to-spec: src"')
        assert r and r["lane"] == "subagent"

    def test_lookup_subagent_double_independent(self):
        r = pre_tool_hook._review_lane_lookup(
            'gatekeeper-cli.sh monitor --subagent "audit --all 五域"')
        assert r and r["lane"] == "subagent"

    def test_lookup_subagent_plan_refinement(self):
        r = pre_tool_hook._review_lane_lookup("gatekeeper-cli.sh plan-refinement p.md --task x")
        assert r and r["lane"] == "subagent"

    def test_lookup_api_lane(self):
        r = pre_tool_hook._review_lane_lookup("gatekeeper-cli.sh monitor --api")
        assert r and r["lane"] == "api"

    def test_lookup_deterministic(self):
        for cmd in ("gatekeeper-cli.sh audit --crossr", "gatekeeper-cli.sh doc-align",
                    "gatekeeper-cli.sh self-check", "gatekeeper-cli.sh monitor --local",
                    "gatekeeper-cli.sh audit --red", "gatekeeper-cli.sh audit --hook",
                    "wslsh -c 'gatekeeper-cli.sh audit --crossr'"):
            r = pre_tool_hook._review_lane_lookup(cmd)
            assert r and r["lane"] == "deterministic", cmd

    def test_lookup_plain_not_hit(self):
        for cmd in ("git status", "echo hi", "wsl git -C /tmp status", "gatekeeper-cli.sh state"):
            assert pre_tool_hook._review_lane_lookup(cmd) is None, cmd

    # ── 纯函数：审查节点白名单 ──
    def test_node_ok(self):
        assert pre_tool_hook._review_node_ok("STAGE_3", "standard")
        assert pre_tool_hook._review_node_ok("AUDIT-CROSSR", "standard")
        assert not pre_tool_hook._review_node_ok("STAGE_2", "standard")
        assert not pre_tool_hook._review_node_ok("ECO-SCAN", "standing")
        assert pre_tool_hook._review_node_ok("ECO-AUDIT", "standing")
        assert pre_tool_hook._review_node_ok("ECO-READ", "standing")

    # ── 全链：非审查节点 + subagent/LLM 车道 → BLOCK(kind=review) ──
    def test_subagent_blocked_eco_scan_standing(self, tmp_path):
        wt = tmp_path / "worktree"
        wt.mkdir()
        sp = tmp_path / "state.json"
        sp.write_text(json.dumps({"stage": "ECO-SCAN", "worktree": str(wt),
                                  "gate_data": {"project_type": "standing"}}))
        with patch("pre_tool_hook.STATE_FILE", sp):
            code = run_hook_inline({
                "tool_name": "RunCommand",
                "tool_input": {"command": 'gatekeeper-cli.sh monitor --subagent --crossrev "L2"'},
                "cwd": str(wt)})
        assert code == 2
        d = json.loads(sp.read_text(encoding="utf-8"))
        kinds = [r["kind"] for r in d["gate_data"]["hook_block_log"]]
        assert kinds == ["review"]

    def test_subagent_blocked_stage2_standard(self, tmp_path):
        wt = tmp_path / "worktree"
        wt.mkdir()
        sp = tmp_path / "state.json"
        sp.write_text(json.dumps({"stage": "STAGE_2", "worktree": str(wt),
                                  "gate_data": {"project_type": "standard"}}))
        with patch("pre_tool_hook.STATE_FILE", sp):
            code = run_hook_inline({
                "tool_name": "RunCommand",
                "tool_input": {"command": 'gatekeeper-cli.sh monitor --subagent "audit --all"'},
                "cwd": str(wt)})
        assert code == 2

    # ── 全链：审查节点 + subagent 车道 → ALLOW ──
    def test_subagent_allowed_eco_audit_standing(self, tmp_path):
        wt = tmp_path / "worktree"
        wt.mkdir()
        sp = tmp_path / "state.json"
        sp.write_text(json.dumps({"stage": "ECO-AUDIT", "worktree": str(wt),
                                  "gate_data": {"project_type": "standing"}}))
        with patch("pre_tool_hook.STATE_FILE", sp):
            code = run_hook_inline({
                "tool_name": "RunCommand",
                "tool_input": {"command": 'gatekeeper-cli.sh monitor --subagent --crossrev "L2"'},
                "cwd": str(wt)})
        assert code == 0

    def test_subagent_allowed_stage3_standard(self, tmp_path):
        wt = tmp_path / "worktree"
        wt.mkdir()
        sp = tmp_path / "state.json"
        sp.write_text(json.dumps({"stage": "STAGE_3", "worktree": str(wt),
                                  "gate_data": {"project_type": "standard"}}))
        with patch("pre_tool_hook.STATE_FILE", sp):
            code = run_hook_inline({
                "tool_name": "RunCommand",
                "tool_input": {"command": 'gatekeeper-cli.sh monitor --subagent "audit --all"'},
                "cwd": str(wt)})
        assert code == 0

    # ── 确定性证据车道：任意 active 阶段放行 ──
    def test_deterministic_allowed_active_stage(self, tmp_path):
        wt = tmp_path / "worktree"
        wt.mkdir()
        sp = tmp_path / "state.json"
        sp.write_text(json.dumps({"stage": "ECO-SCAN", "worktree": str(wt),
                                  "gate_data": {"project_type": "standing"}}))
        with patch("pre_tool_hook.STATE_FILE", sp):
            for cmd in ("gatekeeper-cli.sh doc-align", "gatekeeper-cli.sh self-check",
                        "gatekeeper-cli.sh audit --crossr", "gatekeeper-cli.sh monitor --local"):
                code = run_hook_inline({
                    "tool_name": "RunCommand",
                    "tool_input": {"command": cmd},
                    "cwd": str(wt)})
                assert code == 0, cmd

    # ── IDLE/DONE + review 形态 → BLOCK 且 kind=review（Gate 1 留痕强化）──
    def test_idle_review_blocked_kind_review(self, tmp_path):
        wt = tmp_path / "worktree"
        wt.mkdir()
        sp = tmp_path / "state.json"
        sp.write_text(json.dumps({"stage": "IDLE", "worktree": str(wt)}))
        with patch("pre_tool_hook.STATE_FILE", sp):
            code = run_hook_inline({
                "tool_name": "RunCommand",
                "tool_input": {"command": "gatekeeper-cli.sh self-check"},
                "cwd": str(wt)})
        assert code == 2
        d = json.loads(sp.read_text(encoding="utf-8"))
        kinds = [r["kind"] for r in d["gate_data"]["hook_block_log"]]
        assert kinds == ["review"]

    # ── GK_DEGRADE_REVIEW=1 显式降级豁免（对齐 CLI 语义）──
    def test_degrade_env_allows_non_review_node(self, tmp_path, monkeypatch):
        wt = tmp_path / "worktree"
        wt.mkdir()
        sp = tmp_path / "state.json"
        sp.write_text(json.dumps({"stage": "ECO-SCAN", "worktree": str(wt),
                                  "gate_data": {"project_type": "standing"}}))
        monkeypatch.setenv("GK_DEGRADE_REVIEW", "1")
        with patch("pre_tool_hook.STATE_FILE", sp):
            code = run_hook_inline({
                "tool_name": "RunCommand",
                "tool_input": {"command": 'gatekeeper-cli.sh monitor --subagent --crossrev "L2"'},
                "cwd": str(wt)})
        assert code == 0


class TestAskHoldGate:
    """Gate 9【提问挂起闸】(F-REV-96, 2026-09-17) —— 无人时段 / 纯确认型 AskUserQuestion → BLOCK。

    事故复盘（§8.17 F-REV-92 备注）：agent 用 AskUserQuestion 请示「成本已裁定 / 小成本」分叉，
    用户已入睡 ⟹ **turn 级阻塞数小时**；CLI 侧任何看门狗都救不了（实测冒烟 85s/87s 均 exit=0）。
    本类钉死:
      ① H1 无人时段标志 —— 未过期 BLOCK / 过期自清 / 半写文件按 mtime+TTL 兜底；
      ② H2 纯确认型 —— 全元选项且无不可逆信号 → BLOCK；真分叉 / 不可逆确认 / 自由文本问询放行；
      ③ H3 小成本特征词 → WARN（不 BLOCK，对齐 R0.6-P4 / R0.3b 定案）；
      ④ GK_ALLOW_ASK=1 逃生。
    """

    @pytest.fixture(autouse=True)
    def _iso(self, tmp_path, monkeypatch):
        """标志位落 tmp（绝不触碰真 SKILL_DIR 的 .gatekeeper.no-ask）；GK_ALLOW_ASK 清场。"""
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", tmp_path)
        monkeypatch.delenv("GK_ALLOW_ASK", raising=False)
        return tmp_path

    def _flag(self, content, mtime=None):
        f = pre_tool_hook.SKILL_DIR / pre_tool_hook._ASK_NOASK_FLAG_NAME
        f.write_text(content, encoding="utf-8")
        if mtime is not None:
            os.utime(f, (mtime, mtime))
        return f

    @staticmethod
    def _q(question, labels):
        return {"questions": [{"question": question, "header": "H",
                               "options": [{"label": l, "description": ""} for l in labels]}]}

    # ── 纯函数：元选项识别 ──
    def test_meta_label_recognizes_and_rejects(self):
        assert pre_tool_hook._ask_meta_label("继续")
        assert pre_tool_hook._ask_meta_label("取消（停工）")   # 括号注解被剥离
        assert pre_tool_hook._ask_meta_label(" 直接执行 ")
        assert not pre_tool_hook._ask_meta_label("清理并登记")
        assert not pre_tool_hook._ask_meta_label("A + B 都做")
        assert not pre_tool_hook._ask_meta_label("")

    # ── H2 纯确认型 ──
    def test_h2_pure_confirmation_blocked(self):
        r = pre_tool_hook._ask_hold_gate(self._q("是否继续推进下一批？", ["继续", "取消"]))
        assert r and r[0] == "BLOCK" and "纯确认型" in r[1]

    def test_h2_concrete_fork_allowed(self):
        """带具体方案名的真分叉 → 放行（非纯确认）。"""
        assert pre_tool_hook._ask_hold_gate(
            self._q("F-REV-92 选哪个实现？", ["落 CLI 侧 deadline", "只落 agent 侧准则"])) is None

    def test_h3_lowcost_concrete_fork_not_blocked(self):
        """低风险主题 + 真分叉 → 只 WARN（不升级为 BLOCK，对齐 R0.6-P4 定案）。"""
        r = pre_tool_hook._ask_hold_gate(self._q("系统回收站怎么处理？", ["清理并登记", "只盘点"]))
        assert r and r[0] == "WARN"

    def test_h2_irreversible_confirmation_allowed(self):
        """全元选项但含不可逆信号词 ⟹ 可能是真风险的确认，放行（不误拦）。"""
        assert pre_tool_hook._ask_hold_gate(self._q("是否删除全部临时文件？", ["继续", "取消"])) is None

    def test_h2_free_text_question_not_pure_confirmation(self):
        """任一 question 无 options（自由文本问询）⟹ 不算纯确认型。"""
        q = {"questions": [{"question": "还有什么要补充？", "header": "H"},
                           {"question": "继续吗？", "header": "H2",
                            "options": [{"label": "继续"}, {"label": "取消"}]}]}
        assert pre_tool_hook._ask_hold_gate(q) is None

    def test_h2_malformed_input_none(self):
        assert pre_tool_hook._ask_hold_gate({}) is None
        assert pre_tool_hook._ask_hold_gate({"questions": []}) is None
        assert pre_tool_hook._ask_hold_gate({"questions": "not-a-list"}) is None

    # ── H3 小成本自决（只告警）──
    def test_h3_lowcost_warn(self):
        r = pre_tool_hook._ask_hold_gate(self._q("临时文件怎么整理？", ["方案甲", "方案乙"]))
        assert r and r[0] == "WARN" and "小成本" in r[1]

    def test_h3_concrete_non_lowcost_allowed(self):
        assert pre_tool_hook._ask_hold_gate(self._q("R7 用哪个方案？", ["方案甲", "方案乙"])) is None

    # ── H1 无人时段标志 ──
    def test_h1_flag_active_blocks(self):
        self._flag(f"{time.time() + 600}|night-batch")
        r = pre_tool_hook._ask_hold_gate(self._q("R7 用哪个方案？", ["方案甲", "方案乙"]))
        assert r and r[0] == "BLOCK" and "无人时段" in r[1] and "night-batch" in r[1]

    def test_h1_flag_expired_autoclean(self):
        f = self._flag(f"{time.time() - 1}|stale")
        assert pre_tool_hook._ask_hold_gate(self._q("R7 用哪个方案？", ["方案甲", "方案乙"])) is None
        assert not f.exists()   # 过期自清（不留死锁）

    def test_h1_unparseable_fresh_mtime_blocks(self):
        """半写/损坏标志（无 epoch）⟹ 按 mtime + 默认 TTL 兜底（fail-closed 但不永久锁死）。"""
        self._flag("garbage-no-epoch")
        r = pre_tool_hook._ask_hold_gate(self._q("R7 用哪个方案？", ["方案甲", "方案乙"]))
        assert r and r[0] == "BLOCK"

    def test_h1_unparseable_old_mtime_expired(self):
        f = self._flag("garbage-no-epoch", mtime=time.time() - 5 * 3600)
        assert pre_tool_hook._ask_hold_gate(self._q("R7 用哪个方案？", ["方案甲", "方案乙"])) is None
        assert not f.exists()

    def test_h1_zero_deadline_treated_unparseable(self):
        """deadline<=0 视为不可解析（防 "0|" 被当成 1970 早已过期 → 静默失效）。"""
        self._flag("0|bad")
        r = pre_tool_hook._ask_hold_gate(self._q("R7 用哪个方案？", ["方案甲", "方案乙"]))
        assert r and r[0] == "BLOCK"

    # ── 逃生 ──
    def test_escape_env_allows(self, monkeypatch):
        self._flag(f"{time.time() + 600}|night-batch")
        monkeypatch.setenv("GK_ALLOW_ASK", "1")
        assert pre_tool_hook._ask_hold_gate(self._q("继续吗？", ["继续", "取消"])) is None

    # ── 全链（main）──
    def test_main_flag_blocks_askuserquestion(self, tmp_path):
        self._flag(f"{time.time() + 600}|night-batch")
        wt = tmp_path / "worktree"
        wt.mkdir()
        sp = tmp_path / "state.json"
        sp.write_text(json.dumps({"stage": "STAGE_2", "worktree": str(wt)}), encoding="utf-8")
        with patch("pre_tool_hook.STATE_FILE", sp):
            code = run_hook_inline({"tool_name": "AskUserQuestion",
                                    "tool_input": self._q("继续吗？", ["继续", "取消"]),
                                    "cwd": str(wt)})
        assert code == 2

    def test_main_warn_lowcost_still_allowed(self, tmp_path):
        """WARN 档不阻断（严格面只覆盖静态可判形态）。"""
        wt = tmp_path / "worktree"
        wt.mkdir()
        sp = tmp_path / "state.json"
        sp.write_text(json.dumps({"stage": "STAGE_2", "worktree": str(wt)}), encoding="utf-8")
        with patch("pre_tool_hook.STATE_FILE", sp):
            code = run_hook_inline({"tool_name": "AskUserQuestion",
                                    "tool_input": self._q("临时文件怎么整理？", ["方案甲", "方案乙"]),
                                    "cwd": str(wt)})
        assert code == 0

    def test_main_pure_confirmation_blocked(self, tmp_path):
        """无标志（白天）时 H2 仍生效 —— 纯确认型提问任何时段都拦。"""
        wt = tmp_path / "worktree"
        wt.mkdir()
        sp = tmp_path / "state.json"
        sp.write_text(json.dumps({"stage": "STAGE_2", "worktree": str(wt)}), encoding="utf-8")
        with patch("pre_tool_hook.STATE_FILE", sp):
            code = run_hook_inline({"tool_name": "AskUserQuestion",
                                    "tool_input": self._q("是否继续？", ["继续", "取消"]),
                                    "cwd": str(wt)})
        assert code == 2


class TestTargetPathScope:
    """F5（ECC-05D9F1857601）— scope 由「按 cwd 判」改「按**目标路径**判」（用户裁定 ①）。

    现场：Trae 会话 cwd 常在治理范围外（如 `c:\\Users\\HP`）⟹ `_resolve_state_by_cwd` 返回 None
    ⟹ `scope_out=True` ⟹ `main()` 早退（`sys.exit(0)`）⟹ Gate 3（worktree 包含）/
    Gate 4（CLI `pre-tool-check` 含 `edit_budget` 扣减）/ Gate 8（技能自维护防裸跑）**整链不执行**
    —— `hook.log` 全量聚合实测：所有 `Edit`/`Write` 事件恒带 `[SCOPE-OUT:allow]`。

    本类锁三条判据：
      ① 目标在治理范围（技能目录 / 登记项目 marker / 就近 state）→ 进治理面（留痕 `[SCOPE-TARGET:`）
      ② 目标与治理范围无关 → **仍 scope_out 放行**（防误伤范围外项目）
      ③ `GK_SCOPE_TARGET=0` → 回退纯 cwd 判定（kill switch）
    ⚠ 不断言 `main()` 的退出码：进治理面后 Gate 4 会真跑 CLI（其判定依赖真实 worktree），
      故只断言**留痕**（scope 决策在 `_log_hook` 处即已可见，早于 Gate 2/4）。
    """

    @staticmethod
    def _env(tmp_path, monkeypatch):
        # skill 根与「就近 state 探测区」必须**分开**：若 SKILL_DIR == tmp_path，
        # `test_resolve_by_target_nearest_state` 会先命中技能目录分支（优先级本就高于就近查找）
        # ⟹ 测不到「就近」语义。
        skill = tmp_path / "skill"
        (skill / "scripts").mkdir(parents=True, exist_ok=True)
        sf = skill / ".gatekeeper.state"
        wt = tmp_path / "wt"
        wt.mkdir(exist_ok=True)
        sf.write_text(json.dumps({
            "stage": "ECO-EDIT", "r_phase": "ECO-SCAN", "worktree": str(wt),
            "gate_data": {"project_type": "standing",
                          "ecc_findings": [{"id": "ECC-X", "status": "open"}]},
        }), encoding="utf-8")
        log = tmp_path / "hook.log"
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", skill)
        monkeypatch.setattr(pre_tool_hook, "GOVERNED_SCOPES", {})
        monkeypatch.setattr(pre_tool_hook, "HOOK_LOG", log)
        monkeypatch.setattr(pre_tool_hook, "_win_to_wsl", lambda p: p)
        # main() 会 `global STATE_FILE` 改写该模块级全局（生产每条 hook 是独立进程，无害；
        # 同进程内多用例则互相污染）⟹ 显式锚定「模块默认」= tmp state，并让 monkeypatch 负责还原。
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", sf)
        monkeypatch.setattr(pre_tool_hook, "_DEFAULT_STATE_PATHS", {str(sf)})
        monkeypatch.delenv("GK_SCOPE_TARGET", raising=False)
        return sf, log

    # ── 解析优先级（纯函数）──
    def test_resolve_by_target_skill_dir(self, tmp_path, monkeypatch):
        sf, _ = self._env(tmp_path, monkeypatch)
        assert pre_tool_hook._resolve_state_by_target_path(
            str(tmp_path / "skill" / "scripts" / "gk_x.py")) == sf

    def test_resolve_by_target_governed_marker(self, tmp_path, monkeypatch):
        self._env(tmp_path, monkeypatch)
        proj = tmp_path / "myproj"
        proj.mkdir()
        osf = proj / ".gatekeeper.state"
        osf.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(pre_tool_hook, "GOVERNED_SCOPES", {"myproj": str(osf)})
        assert pre_tool_hook._resolve_state_by_target_path("/home/u/myproj/src/a.cpp") == osf

    def test_resolve_by_target_nearest_state(self, tmp_path, monkeypatch):
        self._env(tmp_path, monkeypatch)
        deep = tmp_path / "a" / "b"
        deep.mkdir(parents=True)
        near = tmp_path / "a" / ".gatekeeper.state"
        near.write_text("{}", encoding="utf-8")
        assert pre_tool_hook._resolve_state_by_target_path(str(deep / "f.py")) == near

    def test_resolve_by_target_none_when_unrelated(self, tmp_path, monkeypatch):
        self._env(tmp_path, monkeypatch)
        assert pre_tool_hook._resolve_state_by_target_path(
            str(tmp_path.parent / "zzz_unrelated" / "x.py")) is None

    # ── 方案 A（2026-09-23 用户裁定，ECC-B8974A514E81）：技能仓 worktree 归一主树 ──
    def test_resolve_skill_worktree_normalized_to_main_state(self, tmp_path, monkeypatch):
        """**正臂 + 负臂合一**：`<trae>/worktrees/<技能名>/…` 的目标归**主树** state。

        现场（实测）：hook 进程的 SKILL_DIR = 主树（wrapper 由主树启动），而编辑目标在
        `…/.trae/worktrees/<技能名>/…` ⟹ 原「技能仓」首判（只比 `SKILL_DIR` 自身）不命中
        ⟹ 落到下方「就近 state」分支 ⟹ 命中该 worktree **自己**的 `.gatekeeper.state`
        （stage=IDLE）⟹ 编辑被莫名拦下（`Cannot edit without active R-phase`），实为治理面
        分裂（在 worktree 里跑任何写 state 的 CLI 命令即可把门禁切到该份 ⟹ 可绕过主树治理）。
        本臂**故意**在 worktree 侧也放一份（stage=IDLE）—— 归一后不得被它抢走。
        """
        trae = tmp_path / "trae"
        skill = trae / "skills" / "spz-gatekeeper-r-sequence"
        (skill / "scripts").mkdir(parents=True)
        main_sf = skill / ".gatekeeper.state"
        main_sf.write_text(json.dumps({"stage": "ECO-EDIT"}), encoding="utf-8")
        wt = trae / "worktrees" / "spz-gatekeeper-r-sequence" / "feature" / "br-x"
        (wt / "scripts").mkdir(parents=True)
        (wt / ".gatekeeper.state").write_text(json.dumps({"stage": "IDLE"}), encoding="utf-8")
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", skill)
        monkeypatch.setattr(pre_tool_hook, "GOVERNED_SCOPES", {})
        monkeypatch.setattr(pre_tool_hook, "_win_to_wsl", lambda p: p)
        assert pre_tool_hook._resolve_state_by_target_path(
            str(wt / "scripts" / "gk_x.py")) == main_sf

    def test_resolve_other_repo_worktree_not_claimed(self, tmp_path, monkeypatch):
        """负臂：`worktrees/<别的仓名>/…` 不得被技能仓归一认领（防误伤他人仓库的 worktree）。"""
        trae = tmp_path / "trae"
        skill = trae / "skills" / "spz-gatekeeper-r-sequence"
        (skill / "scripts").mkdir(parents=True)
        (skill / ".gatekeeper.state").write_text("{}", encoding="utf-8")
        other = trae / "worktrees" / "some-other-repo" / "feature" / "br-y"
        other.mkdir(parents=True)
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", skill)
        monkeypatch.setattr(pre_tool_hook, "GOVERNED_SCOPES", {})
        monkeypatch.setattr(pre_tool_hook, "_win_to_wsl", lambda p: p)
        assert pre_tool_hook._resolve_state_by_target_path(str(other / "x.py")) is None

    # ── walk 边界（F5 落刀后实测补）──
    def test_walk_boundary_blocks_volume_root_crossing(self):
        """walk-up **不得跨出卷根**（`parent` 为 `/`/`\\` 即停）。

        现场（2026-09-18 实测，F5 落刀后立刻暴露）：WSL 根 `/` 存在**游离** `.gatekeeper.state`
        （`stage=STAGE_0 / r_phase=R1 / worktree=''`）⟹ 越界会把**任何**范围外路径认领进该 state
        ⟹ Gate 2 报 `Worktree '' does not exist` ⟹ 范围外编辑被误拦（实证：一次 `Write` 到
        `AppData\\Local\\Temp\\` 被 hook 拦，原因串即 `stage=STAGE_0 phase=R1 worktree=`）。
        ⚠ 只能做**判据级**用例：复现该形态需在**文件系统根**植回 `/.gatekeeper.state`（2026-09-18 已按用户
          裁定清理，不重造）；且该形态在 Windows 宿主下不可达（`Path("/mnt/c").parent` 落当前盘根、自指即停）
          ⟹ 集成级如实**不覆盖**。
        """
        P = pre_tool_hook.Path
        # ③ 卷根边界：`/mnt/c` 的父 = `/` ⟹ 必须停（不得进 `/` 找 state）
        assert pre_tool_hook._state_walk_boundary(P("/mnt/c"), P("/")) is True
        # ③ 对照：卷根**内**的祖先照常可继续（`/mnt/c/.gatekeeper.state` 仍受认领）
        assert pre_tool_hook._state_walk_boundary(P("/mnt/c/Users"), P("/mnt/c")) is False
        # ① 根锚自指（Windows 宿主的 `Path("C:/").parent` 即自身）
        assert pre_tool_hook._state_walk_boundary(P("C:/"), P("C:/")) is True

    # ── main() 全链（只断言留痕）──
    @staticmethod
    def _invoke(target, *, tool="Write", cwd=r"<home>"):
        return run_hook_inline({"hook_event_name": "PreToolUse", "tool_name": tool,
                                "tool_input": {"file_path": target}, "cwd": cwd})

    def test_main_target_in_governed_scope_enters(self, tmp_path, monkeypatch):
        _, log = self._env(tmp_path, monkeypatch)
        self._invoke(str(tmp_path / "skill" / "scripts" / "gk_x.py"))
        txt = log.read_text(encoding="utf-8")
        assert "[SCOPE-TARGET:" in txt and "[SCOPE-OUT" not in txt

    def test_main_target_outside_scope_still_allowed(self, tmp_path, monkeypatch):
        """反证：目标与治理范围无关 → 不得被拉进治理面（防误伤）。"""
        _, log = self._env(tmp_path, monkeypatch)
        self._invoke(str(tmp_path.parent / "zzz_unrelated" / "x.py"))
        assert "[SCOPE-OUT:allow]" in log.read_text(encoding="utf-8")

    def test_main_kill_switch_restores_cwd_only(self, tmp_path, monkeypatch):
        _, log = self._env(tmp_path, monkeypatch)
        monkeypatch.setenv("GK_SCOPE_TARGET", "0")
        self._invoke(str(tmp_path / "scripts" / "gk_x.py"))
        assert "[SCOPE-OUT:allow]" in log.read_text(encoding="utf-8")

    def test_main_non_edit_tool_skips_target_resolution(self, tmp_path, monkeypatch):
        """非编辑工具（如 Grep）：目标路径不参与 scope 判定 —— 行为不变。"""
        _, log = self._env(tmp_path, monkeypatch)
        self._invoke(str(tmp_path / "scripts"), tool="Grep")
        assert "[SCOPE-OUT:allow]" in log.read_text(encoding="utf-8")

    def test_main_mcp_write_target_in_governed_scope_enters(self, tmp_path, monkeypatch):
        """**红先臂**（2026-10-02）：F5 目标路径判定须覆盖 **MCP 写** 形态（堵写面旁路）。

        现场（实证）：MCP 写路径在 `tool_input["args"]["path"]`（`run_mcp`）或 `tool_input` 本体
        （`mcp__…`），**不在** `file_path`/`path`；而 F5 条件含 `tool_name in EDIT_TOOLS`（不含 MCP 名）
        ⟹ MCP 写**漏判** ⟹ 落回 cwd 判定 ⟹ 会话 cwd 在治理范围外（典型 `<home>`）时
        **整链早退 = 写面旁路**（同一目标改用原生 `Write` 则被 F5 认领）。判据：cwd 在治理范围外 +
        MCP 写目标在技能仓 ⟹ 必须与原生写**同**进治理面（留痕 `[SCOPE-TARGET:` 且无 `[SCOPE-OUT`），
        并在写面外被拦（exit 2）。
        """
        _, log = self._env(tmp_path, monkeypatch)
        target = str(tmp_path / "skill" / "scripts" / "gk_x.py")
        with patch("pre_tool_hook._run_cli", return_value={"ok": True}):
            code = run_hook_inline({
                "hook_event_name": "PreToolUse",
                "tool_name": "run_mcp",
                "tool_input": {"server_name": "filesystem", "tool_name": "write_file",
                               "args": {"path": target}},
                "cwd": r"<home>",
            })
        txt = log.read_text(encoding="utf-8")
        assert "[SCOPE-TARGET:" in txt and "[SCOPE-OUT" not in txt, \
            "MCP 写目标未参与 scope 判定 ⟹ 落 SCOPE-OUT（写面旁路）"
        assert code == 2, f"MCP 写目标进治理面后未在写面外被拦（exit={code}）"


def _fake_completed(stdout: str, rc: int = 1):
    """最小 `CompletedProcess` 替身（`_run_cli` 只读 `stdout` / `returncode`）。"""
    return type("_CP", (), {"stdout": stdout, "returncode": rc, "stderr": ""})()


class TestRunCliErrorBackfill:
    """f9（ECC-12836BA40C51，同族 ECC-4FAF495FFF27，2026-09-22，**红先**）。

    现场（2026-09-22 实测）：CLI 的阻断面是**纯文本**（`BLOCK: …` + `HINT: …`），而
    `_run_cli` 的旧 fallback `return {"ok": rc == 0, "raw": result.stdout}` **不带 `error` 键**
    ⟹ Gate 4 的 `cli_result.get("error", "unknown")` 恒得 `unknown`
    ⟹ 操作者看到的是 `GATEKEEPER-BLOCK: CLI pre-tool-check failed: unknown`，而真因
    （`edit_budget exhausted (used=4/max=4, remaining=0)`）**不可达**
    —— 本会话亲身踩中：一次 `SearchReplace` 被拦，文案只有 `unknown`，
    须另起探针直跑 CLI 才知道是预算耗尽。

    契约（本类三条）：
      ① 非 JSON stdout ⟹ 首条 `BLOCK`/`ERROR` 行回填 `error`（`raw` 原样保留）；
      ② JSON 行仍照旧解析（重构 `lines` 后不得回归）；
      ③ stdout 为空 ⟹ `error` 为 `""`（不得抛异常、不得退回 KeyError）。

    ⚠ 以 mock 替身锁契约，**不启 bash**：与本文件「直接函数调用」纪律一致（Windows 宿主可跑）。
    """

    def test_block_line_backfilled_into_error(self, monkeypatch):
        """判据①：真因可达（原为 `unknown`）。"""
        out = ("BLOCK: edit_budget exhausted (used=4/max=4, remaining=0) — no more edits in "
               "this phase/node.\nHINT: Run 'advance' to enter next node (resets budget).\n")
        monkeypatch.setattr(pre_tool_hook.subprocess, "run",
                            lambda *a, **k: _fake_completed(out, rc=1))
        r = pre_tool_hook._run_cli(["pre-tool-check", "Write", "/tmp/x.py"])
        assert r["ok"] is False
        assert "edit_budget exhausted" in r["error"], f"真因不可达（仍是 unknown？）：{r}"
        assert r["error"].startswith("BLOCK:"), "应回填**首条** BLOCK 行（而非 HINT）"
        assert r["raw"] == out, "raw 须原样保留（Gate 4 的 kind=budget 判据依赖它）"

    def test_block_not_on_first_line_still_found(self, monkeypatch):
        """判据①（边界）：BLOCK 行前有噪声行时仍须命中。"""
        monkeypatch.setattr(pre_tool_hook.subprocess, "run",
                            lambda *a, **k: _fake_completed("note: warming up\nBLOCK: nope\n", rc=1))
        r = pre_tool_hook._run_cli(["x"])
        assert r["error"] == "BLOCK: nope"

    def test_json_line_still_parsed(self, monkeypatch):
        """判据②：JSON 分支不回归（重构 `lines` 抽出后）。"""
        monkeypatch.setattr(pre_tool_hook.subprocess, "run",
                            lambda *a, **k: _fake_completed('{"ok":true,"v":1}\n', rc=0))
        assert pre_tool_hook._run_cli(["x"]) == {"ok": True, "v": 1}

    def test_empty_stdout_gives_empty_error(self, monkeypatch):
        """判据③：空 stdout ⟹ `error` 空串（由调用方退到 raw/'unknown'），不抛异常。"""
        monkeypatch.setattr(pre_tool_hook.subprocess, "run",
                            lambda *a, **k: _fake_completed("", rc=1))
        r = pre_tool_hook._run_cli(["x"])
        assert r["error"] == "" and r["raw"] == ""


def _fake_completed_err(stdout: str, stderr: str, rc: int = 1):
    """同 `_fake_completed`，但带**非空 stderr**（`_run_cli` 的 boot-失败面取证用）。"""
    return type("_CP", (), {"stdout": stdout, "returncode": rc, "stderr": stderr})()


class TestRunCliStderrSurface:
    """`ECC-E994635EF0EF`（2026-09-24，**红先**）：CLI **boot 失败**的真因须可达（原为 `unknown`）。

    现场：CLI 语法错 / 解释器缺失 ⟹ `pre-tool-check` 的 **stdout 为空**，真因只在 **stderr**
    （`bash: … syntax error near unexpected token`）⟹ 旧 `_run_cli` 的返回键 `{ok,raw,error}`
    三者皆空 ⟹ Gate 4 渲染 `CLI pre-tool-check failed: unknown`，操作者无法定位；
    而 Gate 4 对 Edit/Write 同样生效 ⟹ **全部编辑被封死**（自锁，本会话多次踩中）。
    本臂钉住 `stderr` 回填 —— **纯可观测性**面，不改任何放行/判据（Gate 仍 fail-closed）。

    ⚠ 以 mock 替身锁契约，**不启 bash**（与本文件「直接函数调用」纪律一致，Windows 宿主可跑）。
    """

    def test_boot_failure_surfaces_stderr(self, monkeypatch):
        """判据：boot 失败（stdout 空 + rc≠0）⟹ 返回值须带**非空** `stderr`。"""
        monkeypatch.setattr(pre_tool_hook.subprocess, "run",
                            lambda *a, **k: _fake_completed_err(
                                "", "bash: line 3: syntax error near unexpected token `fi'\n", rc=2))
        r = pre_tool_hook._run_cli(["pre-tool-check", "Edit", "/x", "0"])
        assert r["ok"] is False
        assert r.get("stderr", "").strip(), \
            f"boot 失败真因只在 stderr；回填缺失 ⟹ Gate 4 恒渲染 'unknown'：{r}"

    def test_json_path_key_set_unchanged(self, monkeypatch):
        """负臂：正常 JSON 分支返回**不得**被塞入 `stderr`（键集契约不变，勿回归）。"""
        monkeypatch.setattr(pre_tool_hook.subprocess, "run",
                            lambda *a, **k: _fake_completed('{"ok":true}\n', rc=0))
        assert pre_tool_hook._run_cli(["x"]) == {"ok": True}


class TestRunCliStateFilePassthrough:
    """`ECC-3104B66AA4EE`（2026-09-23，**红先**）：`_run_cli` 起 CLI 子进程必须**透传当前
    已解析的 `STATE_FILE`**。

    现场（读码实测）：`pre_tool_hook.main()` 按「目标路径 → cwd 就近」把 `STATE_FILE` 解析成
    **域化 / worktree 本地** state（模块内 `global STATE_FILE`），但 `_run_cli`（L1520-1528）
    `subprocess.run([...], capture_output=True, text=True, timeout=30)` **无 `env=`**
    ⟹ 子进程只继承父进程环境（无 `STATE_FILE`）⟹ CLI 自行回退「默认 state + plan 指针」
    ⟹ **Gate 1-3 用域化 state、Gate 4 的 `pre-tool-check` 用主 state** —— 于是
    `edit_budget` 仍按**主 state**计 ⟹ **并行会话共用同一预算计数器**（今天多会话被卡住的
    hook 侧根因）。同族 `ECC-8BE02C8CBB5F`（`apply-worktree` 不写 `state.worktree`）已登记。

    判据（`_WSLENV_SENSITIVE` L631 已含 `STATE_FILE` ⟹ 设计上本就要透传，只是漏了接线）：
      ① 子进程 `env["STATE_FILE"]` == 本进程 `pre_tool_hook.STATE_FILE`；
      ② 透传是**覆盖**而非**替换**（父环境其余变量与 `PATH` 不得丢）。
    """

    def test_subprocess_env_carries_resolved_state_file(self, monkeypatch):
        """判据①：域化 state 必须传到 Gate 4 的 CLI 子进程。"""
        seen = {}

        def _capture(*a, **k):
            seen.update(k)
            return _fake_completed('{"ok":true}\n', rc=0)

        monkeypatch.setattr(pre_tool_hook.subprocess, "run", _capture)
        monkeypatch.setattr(
            pre_tool_hook, "STATE_FILE",
            Path("<home>/.trae/worktrees/wt/.gatekeeper.state"))
        pre_tool_hook._run_cli(["pre-tool-check", "Write", "/tmp/x"])
        env = seen.get("env")
        assert env, ("未传 env ⟹ 子进程回退默认 state + plan 指针 ⟹ Gate 4 按主 state "
                     "记预算（并行会话共用计数器）")
        assert env.get("STATE_FILE") == "<home>/.trae/worktrees/wt/.gatekeeper.state", (
            f"未透传域化 state：env[STATE_FILE]={env.get('STATE_FILE')!r}")

    def test_passthrough_overlays_not_replaces_parent_env(self, monkeypatch):
        """判据②（负臂）：只覆盖 `STATE_FILE`，不得把父环境整体替换（否则 `PATH` 丢 ⟹ bash 起不来）。"""
        seen = {}

        def _capture(*a, **k):
            seen.update(k)
            return _fake_completed('{"ok":true}\n', rc=0)

        monkeypatch.setattr(pre_tool_hook.subprocess, "run", _capture)
        monkeypatch.setenv("GK_PROBE_KEEP", "yes")
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", Path("/tmp/s.state"))
        pre_tool_hook._run_cli(["x"])
        env = seen.get("env") or {}
        assert env.get("GK_PROBE_KEEP") == "yes", "父环境变量丢失（env 被替换而非叠加）"
        assert env.get("PATH"), "PATH 丢失 ⟹ 子进程 bash 无法启动"

    def test_passthrough_disables_pyc_write(self, monkeypatch):
        """判据③（加速）：透传 `PYTHONDONTWRITEBYTECODE=1` —— Gate 4 子进程禁写 `.pyc`。

        依据（实测）：一次 `pre-tool-check` = **1.13–1.50 s**（纯 python 启动 0.032 s），
        其成本含 CLI 内部多次 `python3 -c`，每个都会尝试在 `/mnt/c`(CIFS/9p) 写 `.pyc`。
        """
        seen = {}

        def _capture(*a, **k):
            seen.update(k)
            return _fake_completed('{"ok":true}\n', rc=0)

        # ⚠ 必须先清掉本进程的该变量：`{**os.environ}` 会把它**透传**进来 ⟹ 不移除则本臂在
        #   修前也「假绿」（红向 A/B 首跑实测即如此）。判据是「**_run_cli 显式设置**它」。
        monkeypatch.delenv("PYTHONDONTWRITEBYTECODE", raising=False)
        monkeypatch.setattr(pre_tool_hook.subprocess, "run", _capture)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", Path("/tmp/s.state"))
        pre_tool_hook._run_cli(["x"])
        assert (seen.get("env") or {}).get("PYTHONDONTWRITEBYTECODE") == "1", \
            "未**显式**禁 .pyc 写入 ⟹ Gate 4 每个 python 子进程多一次跨 fs 落盘往返"


class TestDangerousCommandAutoReplacement:
    """`rm -rf` 拦截 → **自动注入可执行的最安全替换**（2026-09-23 用户裁定）。

    用户原话：「给 rm-rf 拦截那块，加个最低权限影响最小的最安全的删除命令引导，**自动替换**
    高危命令；安全网虽然有引导但是不是自动注入，这就是硬摩擦也很耗时」。

    判定为「最低权限 / 影响最小 / 最安全」的形态 = **move-to-trash**：`mv` 到技能仓之外的
    `.gk-trash`（① rename 可逆，不是 unlink；② 同 fs 原子 rename，不需递归/删除权限；
    ③ 无「半删态」）。红先：修前 hint 只有泛化文案（"明确目标路径并备份"）⟹ 三臂全红。
    """

    def test_injects_concrete_runnable_replacement(self):
        """判据①：hint 必须含**具体**替换命令（带真实目标路径），且一字可执行。"""
        r = pre_tool_hook._dangerous_command("rm -rf /tmp/gk-probe-victim")
        assert r, "rm -rf 未被拦（拦截语义不得回退）"
        _reason, hint = r
        assert 'mv -- "/tmp/gk-probe-victim"' in hint, f"未注入具体替换命令：{hint}"
        assert ".gk-trash" in hint, "替换未落到**可逆**回收区"
        assert "$(" not in hint and "`" not in hint, (
            "注入串含命令替换 ⟹ 非一字可审阅/可执行（用户要的是零摩擦粘贴）")

    def test_injected_replacement_is_executable_and_reversible(self, tmp_path, monkeypatch):
        """判据②（行为 · 最强）：把注入的命令**真跑一遍** —— 目标须被搬走（可逆），而非删掉。

        这锁的是「注入的是等价命令」这一点：只断言字符串形态会漏掉拼错的路径/引号。
        """
        import subprocess
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", tmp_path / "skills" / "sk")
        victim = tmp_path / "victim"
        victim.mkdir()
        (victim / "f.txt").write_text("data", encoding="utf-8")
        _reason, hint = pre_tool_hook._dangerous_command("rm -rf %s" % victim)
        cmd = hint.split("最低权限/可逆）: ", 1)[1].split("；惰性")[0]
        p = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
        assert p.returncode == 0, f"注入命令跑不通：{p.stderr}"
        assert not victim.exists(), "注入命令未搬走目标"
        moved = list((tmp_path / ".gk-trash").glob("victim.*/f.txt"))
        assert moved, "目标未被搬进 .gk-trash ⟹ 不可逆（与「最安全」相悖）"
        assert moved[0].read_text(encoding="utf-8") == "data", "搬运后内容变化"

    def test_glob_target_does_not_inject(self):
        """判据③（负臂）：目标含 glob ⟹ **不**注入（带引号的 `mv` 不展开 glob，硬注入会搬错）。"""
        r = pre_tool_hook._dangerous_command("rm -rf /tmp/*.log")
        assert r, "rm -rf 未被拦"
        assert "mv -- " not in r[1], "对 glob 目标注入了具体命令 ⟹ 可能搬错对象"

    def test_prose_hit_does_not_inject_bogus_target(self):
        """判据④（负臂，finding `ECC-4DDED6B7E766`）：命中**散文**时**不得**注入替换串。

        现场（2026-09-24 实测 · 用户点名「自动替换好像有点蠢」）：一条 finding 的**标题**里
        出现该短语即被拦，门回注的 `mv` 目标是抽到的一个**中文散文词**（「的字面路径自动改
        写成」），却仍标称「一字可执行」⟹ 该「替换」比不替换**更糟**（使用者会被带去搬错东西）。
        判据 = 抽到的目标**必须长得像路径**；不像 ⟹ 退回泛化 hint（**不猜**）。
        """
        r = pre_tool_hook._dangerous_command(
            "echo rm -rf 的字面路径自动改写成 mv 进回收区（L741-L774）")
        assert r, "递归删除未被拦（拦截语义不得回退）"
        assert "mkdir -p" not in r[1], f"散文命中竟注入了替换串（会误导使用者）：{r[1]}"


# ═══════════ A 方案【惰性字面量豁免】(2026-09-24, ECC-8DFC84C5B9E5) ═══════════
# 用户点名：「写 finding / 文档时正文里出现危险字面量不该被自拦」，而自动替换在那种场合
# 给不出正确目标 —— 摩擦白吃。**双条件缺一不可**：① **段首**显式声明 `GK_INERT_CMD=1`；
# ② 结构**可证明**是数据（命中在引号内 + 无命令替换 + 段内不代码化）。
# **作用域**：只对「这一条命令」生效 —— 命令串与 `bash -c` 内联荷载吃豁免，
# **脚本文件内容不吃**（用户点名的 `run_e2e.sh` 自删事件）。
#
# **红先对照**：`git show HEAD:scripts/pre_tool_hook.py | grep -c GK_INERT_CMD` → **0**
# ⟹ 三条**正例**臂在 HEAD 上必红。负例与作用域臂是**决策锁定**（HEAD 上即绿）——
# 锁的是「不许开错门」，不是新行为。
class TestInertLiteralExemption:

    @staticmethod
    def _dec(cmd):
        """按 **R0.2 命令串**的真实调用形态探一遍（豁免开关不存在时退回默认行为）。

        ⚠ 为什么要这层：HEAD 上 `inert=` 形参**还不存在**，直接传会 TypeError —— 那会让
        **负例臂**「因报错而红/绿」，把真正的行为判据掩盖掉（首测即踩）。显式退回 ⟹
        负例臂在 HEAD 上跑的也是**真行为**（无豁免 = 照拦），红/绿都说明问题。
        """
        try:
            return pre_tool_hook._dangerous_command_decoded(cmd, inert=True)
        except TypeError:
            return pre_tool_hook._dangerous_command_decoded(cmd)

    def test_segment_declared_quoted_literal_is_exempt(self):
        """**正例①（红先）**：段首声明 + 字面量在引号内 ⟹ 放行。"""
        cmd = 'GK_INERT_CMD=1 bash gatekeeper-cli.sh finding register "标题含 rm -rf /tmp/x 字样"'
        assert self._dec(cmd) is None, "段首已声明且字面量在引号内，仍被拦 ⟹ 摩擦没减掉"

    def test_wrapped_shell_layer_inner_declaration_is_exempt(self):
        """**正例②（红先 · 真实调用形态）**：`wsl -e bash -lc '<载荷>'` 里层的声明也要认。

        外层段含 `-c` 旗标（`wsl -e bash -lc`）⟹ 只有「下钻载荷、按**它自己那一层**判」
        才成立。本机从 PowerShell 调 WSL 就是这个形态，不覆盖它则等于没修。
        """
        cmd = ("wsl -e bash -lc 'cd /tmp && GK_INERT_CMD=1 bash gatekeeper-cli.sh "
               "finding register \"标题含 rm -rf /tmp/x 字样\"'")
        assert self._dec(cmd) is None, "外层包裹形态没下钻 ⟹ 真实场景仍吃摩擦"

    def test_inline_bash_c_payload_is_exempt(self):
        """**正例③（红先 · R0.3 内联荷载路）**：内联荷载仍是「这一条命令」的一部分。"""
        cmd = "bash -c 'GK_INERT_CMD=1 echo \"rm -rf /tmp/x\"'"
        assert pre_tool_hook._scan_script_content(cmd) is None, \
            "内联荷载路未吃豁免 ⟹ 与命令串路不一致"

    def test_no_declaration_still_blocks(self):
        """负例①（决策锁定）：无声明 ⟹ 照拦（豁免不得退化成「引号内就放行」）。"""
        cmd = 'bash gatekeeper-cli.sh finding register "标题含 rm -rf /tmp/x 字样"'
        assert self._dec(cmd) is not None, "无声明也放行 ⟹ 豁免退化成了纯启发式"

    def test_declaration_must_be_at_segment_start(self):
        """负例②（决策锁定）：声明只出现在**正文**（非段首）⟹ 照拦。"""
        cmd = ('echo GK_INERT_CMD=1 && bash gatekeeper-cli.sh finding register '
               '"标题含 rm -rf /tmp/x 字样"')
        assert self._dec(cmd) is not None, \
            "正文里出现该词就豁免 ⟹ 谁都能无意中满足条件①"

    def test_command_substitution_inside_literal_is_not_exempt(self):
        """负例③（决策锁定）：引号内**含命令替换** ⟹ 真的会执行 ⟹ 照拦。"""
        cmd = ('GK_INERT_CMD=1 bash gatekeeper-cli.sh finding register '
               '"标题含 rm -rf /tmp/$(id) 字样"')
        assert self._dec(cmd) is not None, \
            "引号内含命令替换仍放行 ⟹ 真会执行的东西被豁免了"

    def test_inline_c_payload_without_declaration_still_blocks(self):
        """负例④（决策锁定）：`bash -c` 荷载里**没有**声明 ⟹ 照拦。"""
        cmd = "bash -c 'echo \"rm -rf /tmp/x\"'"
        assert pre_tool_hook._scan_script_content(cmd) is not None, \
            "内联荷载里没声明却放行 ⟹ 内联形态成了免死金牌"

    def test_script_file_content_never_takes_exemption(self, tmp_path):
        """**作用域硬臂**（用户点名的 `run_e2e.sh` 自删事件）：脚本**文件内容**不吃豁免。

        文件会在**别的时刻、被别的调用方**执行，「当时是不是数据」本层判不了 ⟹ 即便某行
        看起来是「段首声明 + 引号内数据」，R0.3 也必须照拦。这条锁的是**不许开错门**。
        """
        p = tmp_path / "inert_probe.sh"
        p.write_text('GK_INERT_CMD=1 echo "rm -rf /tmp/x"\n', encoding="utf-8")
        assert pre_tool_hook._scan_script_content("bash %s" % p) is not None, \
            "脚本文件内容吃到了豁免 ⟹ 自删事件那条防线被开了口子"

    def test_trust_root_scripts_are_exempt_from_self_scan(self, tmp_path):
        """**自指死锁锁死臂**（2026-10-22，用户裁定「消除自指死锁」）。

        病象：`gatekeeper-cli.sh` L2142 的 gitnexus memo 清理行
        （`find "$_GK_GX_MEMO_DIR" … -delete`）被 R0.3 判危 ⟹ CLI 整条不可执行 ⟹
        `advance` / `apply-worktree` 不可达 ⟹ 节点额度与写面都无法复位。而该 CLI
        本来就是 hook Gate 4 每次用 subprocess 直接执行的入口（`_run_cli`），
        扫它 = 自指、零安全增益。本臂锁两件事：① 两个信任根文件豁免；
        ② 豁免**不外溢**到普通脚本（危险命令藏脚本那条防线仍在）。
        """
        body = 'find "$_GK_GX_MEMO_DIR" -maxdepth 1 -type f -mmin +120 -delete 2>/dev/null || true\n'
        cli = tmp_path / "gatekeeper-cli.sh"
        cli.write_text(body, encoding="utf-8")
        assert pre_tool_hook._scan_script_content("bash %s" % cli) is None, \
            "信任根 CLI 仍被自扫 ⟹ advance/apply-worktree 永不可达（自指死锁复发）"
        other = tmp_path / "not_trust_root.sh"
        other.write_text(body, encoding="utf-8")
        assert pre_tool_hook._scan_script_content("bash %s" % other) is not None, \
            "豁免外溢到普通脚本 ⟹ 危险命令藏脚本的防线被打开"


# ═══════════ Gate 3b【standing 跨技能编辑白名单】(2026-09-23, ECC-A91DC4562198) ═══════════
# 用户裁定：「开白名单吧，这个插件是技能的内部组件，跨技能编辑只允许 standing 用，standard 不行」。
# 白名单源 = `gk_plugin_manifest` 中 **url 形如 `builtin:${SKILL_DIR}/../<name>/…`** 的**已登记**
# 插件（git-workflow 即此形态）⟹ 单一事实源，**无硬编码名单**；未登记的兄弟目录一律拒。
# 红先：落地时 `pre_tool_hook._standing_cross_skill_plugin` 尚不存在（AttributeError）。

def _patch_manifests(monkeypatch, manifests):
    import gk_plugin_manifest as gpm
    monkeypatch.setattr(gpm, "list_manifests", lambda: manifests, raising=False)


class TestStandingCrossSkillWhitelist:
    def test_standing_allows_registered_builtin_plugin(self, tmp_path, monkeypatch):
        skills = tmp_path / "skills"
        (skills / "git-workflow" / "scripts").mkdir(parents=True)
        target = str(skills / "git-workflow" / "scripts" / "git-workflow.sh")
        monkeypatch.setenv("GK_CROSS_SKILL_ROOT", str(skills))
        _patch_manifests(monkeypatch, [
            {"id": "git-workflow",
             "url": "builtin:${SKILL_DIR}/../git-workflow/scripts/git-workflow.sh"}])
        state = {"gate_data": {"project_type": "standing"}}
        assert pre_tool_hook._standing_cross_skill_plugin(target, state) == "git-workflow"

    def test_standard_is_never_allowed(self, tmp_path, monkeypatch):
        """用户明示：standard **不放行**（跨技能编辑是 standing 专用能力）。"""
        skills = tmp_path / "skills"
        (skills / "git-workflow").mkdir(parents=True)
        target = str(skills / "git-workflow" / "git-workflow.sh")
        monkeypatch.setenv("GK_CROSS_SKILL_ROOT", str(skills))
        _patch_manifests(monkeypatch, [
            {"id": "git-workflow",
             "url": "builtin:${SKILL_DIR}/../git-workflow/scripts/git-workflow.sh"}])
        state = {"gate_data": {"project_type": "standard"}}
        assert pre_tool_hook._standing_cross_skill_plugin(target, state) is None

    def test_unregistered_sibling_dir_rejected(self, tmp_path, monkeypatch):
        """负臂：未登记的兄弟目录（如 `../evil/`）不得放行 —— 白名单**不是**「任意兄弟目录」。"""
        skills = tmp_path / "skills"
        (skills / "evil").mkdir(parents=True)
        target = str(skills / "evil" / "x.sh")
        monkeypatch.setenv("GK_CROSS_SKILL_ROOT", str(skills))
        _patch_manifests(monkeypatch, [
            {"id": "git-workflow",
             "url": "builtin:${SKILL_DIR}/../git-workflow/scripts/git-workflow.sh"}])
        state = {"gate_data": {"project_type": "standing"}}
        assert pre_tool_hook._standing_cross_skill_plugin(target, state) is None

    def test_non_builtin_url_not_in_whitelist(self, tmp_path, monkeypatch):
        """负臂：`pip:`/`dev:` 等非 builtin 插件**不在**技能树内 ⟹ 不参与该白名单。"""
        skills = tmp_path / "skills"
        (skills / "pip-plugin").mkdir(parents=True)
        target = str(skills / "pip-plugin" / "x.py")
        monkeypatch.setenv("GK_CROSS_SKILL_ROOT", str(skills))
        _patch_manifests(monkeypatch, [{"id": "pip-plugin", "url": "pip:pip-plugin"}])
        state = {"gate_data": {"project_type": "standing"}}
        assert pre_tool_hook._standing_cross_skill_plugin(target, state) is None

    def test_manifest_failure_is_fail_closed(self, tmp_path, monkeypatch):
        """负臂：manifest 不可得 ⟹ **fail-closed**（判据不可得就不放行，绝不静默放行）。"""
        skills = tmp_path / "skills"
        (skills / "git-workflow").mkdir(parents=True)
        target = str(skills / "git-workflow" / "x.sh")
        monkeypatch.setenv("GK_CROSS_SKILL_ROOT", str(skills))

        def _boom():
            raise RuntimeError("registry down")

        import gk_plugin_manifest as gpm
        monkeypatch.setattr(gpm, "list_manifests", _boom, raising=False)
        state = {"gate_data": {"project_type": "standing"}}
        assert pre_tool_hook._standing_cross_skill_plugin(target, state) is None


# ═══════════ Gate 3b 落点归一【⑤ worktree 落点归一】(2026-09-25) ═══════════
# 病象：Gate 3b 的跨技能基址原为 `Path(__file__).parents[2]` —— **路径层数推算**，只在
#   「hook 恰位于 `<部署根>/<skill>/scripts/`」时成立。hook 若从 **feature worktree 副本**
#   （`.trae/worktrees/<repo>/feature/<branch>/scripts/`）加载，`parents[2]` = `…/worktrees/<repo>`
#   而非部署根 `.trae/skills` ⟹ 兄弟插件根算错 ⟹ standing 下**合法**的跨技能编辑被判越界
#   （fail-closed 拒，表现为「该怎么改 git-workflow 却改不动」）。
# 修法（与 `ECC-DEBCB4AC53C3` 同源）：`gk_route_center._main_worktree` = **git 权威视图**
#   （`git worktree list --porcelain` 首条）取本仓**主 worktree**，再取父目录当部署根。
#   非 git / 查询失败 ⟹ **不放行**（判据不可得就 fail-closed，绝不按层数猜）。

def _mk_linked_worktree(base: Path, repo: str, wt_rel: str):
    """造**真 git 仓** + 其 **linked worktree**（⑤ 臂专用）。

    `_main_worktree` 是 git 权威视图 ⟹ 纯 `mkdir` 的假目录树里查不出主树，臂必须造真仓才有判据。
    布局逐字对齐真实部署（`<部署根>/skills/<skill>` 主树 + `<部署根>/worktrees/<repo>/feature/<branch>`
    worktree）⟹ worktree 的 `parents[2]` ≠ 部署根（这正是被修的层数推算）。
    返回 `(主树, worktree, 部署根)`。
    """
    main = base / "skills" / repo
    (main / "scripts").mkdir(parents=True)
    (main / "scripts" / "pre_tool_hook.py").write_text("# copy\n", encoding="utf-8")
    (main / "gatekeeper-cli.sh").write_text("#!/bin/bash\n", encoding="utf-8")
    wt = base / wt_rel
    wt.parent.mkdir(parents=True, exist_ok=True)

    def _git(*a):
        return subprocess.run(
            ["git", "-C", str(main), "-c", "user.email=t@t", "-c", "user.name=t", *a],
            capture_output=True, text=True, timeout=60)

    for args in (("init", "-q"), ("add", "-A"), ("commit", "-q", "-m", "init")):
        r = _git(*args)
        assert r.returncode == 0, f"git {args[0]} 失败：{r.stdout}{r.stderr}"
    r = _git("worktree", "add", "--detach", str(wt))
    assert r.returncode == 0, f"git worktree add 失败：{r.stdout}{r.stderr}"
    return main, wt, base / "skills"


class TestCrossSkillRootWorktreeNormalization:
    def test_arm27_cross_skill_root_uses_git_main_worktree(self, tmp_path, monkeypatch):
        """判据⑲（红先）：**不设** `GK_CROSS_SKILL_ROOT`（= 生产形态，该 env 只是测试缝），
        且 hook 从 **feature worktree 副本**加载 ⟹ 已登记 builtin 插件根仍须解析到
        `<主树>/../<name>` ⟹ 放行。

        修前 `_here.parents[2]` = `…/worktrees/<repo>` ⟹ 插件根算成 `…/worktrees/<repo>/git-workflow`
        ⟹ 与真实插件路径不匹配 ⟹ 返回 None（红）。
        """
        main, wt, skills = _mk_linked_worktree(
            tmp_path, "spz-gatekeeper-r-sequence",
            "worktrees/spz-gatekeeper-r-sequence/feature/r7.5")
        monkeypatch.delenv("GK_CROSS_SKILL_ROOT", raising=False)
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", main, raising=False)
        monkeypatch.setattr(pre_tool_hook, "__file__",
                            str(wt / "scripts" / "pre_tool_hook.py"), raising=False)
        (skills / "git-workflow" / "scripts").mkdir(parents=True)
        target = str(skills / "git-workflow" / "scripts" / "git-workflow.sh")
        _patch_manifests(monkeypatch, [
            {"id": "git-workflow",
             "url": "builtin:${SKILL_DIR}/../git-workflow/scripts/git-workflow.sh"}])
        state = {"gate_data": {"project_type": "standing"}}
        assert pre_tool_hook._standing_cross_skill_plugin(target, state) == "git-workflow", (
            "跨技能基址仍由 `__file__.parents[*]` 推算 ⟹ 从 worktree 副本调用时兄弟插件根算错"
            "（standing 下合法的跨技能编辑被误拒）")

    def test_arm27b_non_git_deploy_is_fail_closed(self, tmp_path, monkeypatch):
        """判据⑲b（负臂 · fail-closed）：非 git 部署 / 主 worktree 不可得 + 未设
        `GK_CROSS_SKILL_ROOT` ⟹ 部署根**算不出即不放行**（绝不按 `__file__` 层数猜、也不静默放过）。"""
        fake_skill = tmp_path / "not-a-git-repo" / "spz-gatekeeper-r-sequence"
        (fake_skill / "scripts").mkdir(parents=True)
        skills = tmp_path / "skills"
        (skills / "git-workflow" / "scripts").mkdir(parents=True)
        target = str(skills / "git-workflow" / "scripts" / "git-workflow.sh")
        monkeypatch.delenv("GK_CROSS_SKILL_ROOT", raising=False)
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", fake_skill, raising=False)
        monkeypatch.setattr(pre_tool_hook, "__file__",
                            str(fake_skill / "scripts" / "pre_tool_hook.py"), raising=False)
        _patch_manifests(monkeypatch, [
            {"id": "git-workflow",
             "url": "builtin:${SKILL_DIR}/../git-workflow/scripts/git-workflow.sh"}])
        state = {"gate_data": {"project_type": "standing"}}
        assert pre_tool_hook._standing_cross_skill_plugin(target, state) is None


# ═══════════ ④ 写时 shellcheck 安全网（2026-09-24 用户裁定「病灶白名单注入」）═══════════
# 用户原话（本会话）：「$PY 这种问题总是出现，能不能在写脚本的时候就检查出来然后立刻自动
# 处理」「安全网的引导 fix 是被动而不是主动注入，这也是工程摩擦」。
# 用户裁定：**只**为本仓踩过的病灶注入可用 fix（不做全量 shellcheck 打扰）；
# 开销策略 = 结果缓存（mtime+size）+ 大小上限跳过 + `GK_SHELLCHECK=0` 全关。
# 红先：落地时 `_shellcheck_lint` / `_SHELLCHECK_MAX_BYTES` 尚不存在（AttributeError）
# ⟹ 本类全臂红。

class TestShellcheckSafenet:
    # **两轮红先踩坑留痕**（2026-09-24）：
    # ① 首版 `echo $GK_PROBE_UNDEFINED`（无引号）⟹ shellcheck 报的是 **SC2086**（未加引号
    #    展开）而非 SC2154 ⟹ 首轮 `1 failed / 4 passed` 当场抓出我的错误假设；
    # ② 改成加引号 `echo "$GK_X"` 想触达 SC2154 ⟹ 实测**什么都不报** ⟹ 关键局限：
    #    **shellcheck 不对「未定义变量」报 SC2154**（它认为变量可能来自环境）—— 本仓 `$PY`
    #    unbound 那类问题**它查不出来**。故主判据用**确实可查**的 SC2086。
    #    常量名保留历史（勿据名误解判据）。
    SH_SC2154 = "#!/bin/bash\nset -u\necho $GK_PROBE_UNDEFINED\n"

    @staticmethod
    def _isolate(tmp_path, monkeypatch):
        """缓存落点由 `SKILL_DIR` 派生 ⟹ 必须隔离，否则真实技能目录被测试写入。"""
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", tmp_path)
        monkeypatch.delenv("GK_SHELLCHECK", raising=False)

    def test_reports_whitelisted_code_with_runnable_fix(self, tmp_path, monkeypatch):
        self._isolate(tmp_path, monkeypatch)
        p = tmp_path / "a.sh"
        p.write_text(self.SH_SC2154, encoding="utf-8")
        out = pre_tool_hook._shellcheck_lint(str(p))
        assert "SC2086" in out, f"未报白名单码：{out!r}"
        assert "修" in out or "改" in out, f"未给出可用修法（用户要的是主动注入）：{out!r}"

    def test_clean_script_is_silent(self, tmp_path, monkeypatch):
        """负臂：无病灶 ⟹ 不得有任何输出（否则噪声化，真警告被脱敏）。"""
        self._isolate(tmp_path, monkeypatch)
        p = tmp_path / "ok.sh"
        p.write_text('#!/bin/bash\nset -euo pipefail\nx=1\necho "${x}"\n', encoding="utf-8")
        assert pre_tool_hook._shellcheck_lint(str(p)) == ""

    def test_kill_switch_disables(self, tmp_path, monkeypatch):
        """负臂：`GK_SHELLCHECK=0` ⟹ 全关（与 GK_ALLOW_ASK / GK_SCOPE_TARGET 同族逃生口）。"""
        self._isolate(tmp_path, monkeypatch)
        p = tmp_path / "a.sh"
        p.write_text(self.SH_SC2154, encoding="utf-8")
        monkeypatch.setenv("GK_SHELLCHECK", "0")
        assert pre_tool_hook._shellcheck_lint(str(p)) == ""

    def test_oversize_skipped(self, tmp_path, monkeypatch):
        """负臂：超上限文件跳过（600 KB 级脚本不做逐次全量扫，对齐用户裁定的「大小上限」）。"""
        self._isolate(tmp_path, monkeypatch)
        p = tmp_path / "big.sh"
        p.write_text("#!/bin/bash\n" + "# pad pad pad\n" * 20000, encoding="utf-8")
        assert p.stat().st_size > pre_tool_hook._SHELLCHECK_MAX_BYTES
        assert pre_tool_hook._shellcheck_lint(str(p)) == ""

    def test_cache_avoids_rescan(self, tmp_path, monkeypatch):
        """判据（开销）：同文件同 (mtime,size) 二次调用不得再起 shellcheck 子进程。"""
        self._isolate(tmp_path, monkeypatch)
        p = tmp_path / "a.sh"
        p.write_text(self.SH_SC2154, encoding="utf-8")
        real = pre_tool_hook.subprocess.run
        calls = []

        def _spy(*a, **k):
            calls.append(a)
            return real(*a, **k)

        monkeypatch.setattr(pre_tool_hook.subprocess, "run", _spy)
        first = pre_tool_hook._shellcheck_lint(str(p))
        n1 = len(calls)
        second = pre_tool_hook._shellcheck_lint(str(p))
        assert first == second and first, f"结果不稳定：{first!r} / {second!r}"
        assert len(calls) == n1, "二次调用未走缓存 ⟹ 每条编辑都付一次 shellcheck 全量开销"


# ── Gate R0.8 夹具：**拼接构造**（不写完整字面量）—— 门禁落地后本文件自身仍可编辑 ──
_SEC_SK = "sk-" + "A1b2C3d4E5f6G7h8I9j0" * 2
_SEC_TP = "tp-" + "cakjr1ghr99il84iejjlnj7" * 2
_SEC_PEM = "-----BEGIN " + "RSA PRIVATE KEY" + "-----"


class TestPlaintextSecretWrite:
    """Gate R0.8（2026-09-24 用户裁定「加个 hook 拦截明文写 api key」）。

    动因 = 本会话实测事故：`printenv <3 变量> | cut -d= -f1` 分隔符未生效，
    把两把真 key 明文打进了会话记录 —— 明文 key 的泄漏面（会话记录 / 文件 / git 历史）
    事后不可收回。

    设计：只认**高置信形**（前缀 + 足够长连续字母数字）⟹ `sk-****` / `sk-...` /
    `sk-<占位>` / `$DEEPSEEK_API_KEY` 这类脱敏或引用写法**天然不命中**（无需白名单）；
    逃生舱 = **段首**显式声明 `GK_SECRET_WRITE=1`（与 `GK_INERT_CMD=1` 同纪律）。
    ⚠ 已知取舍：`sk-` 后接 20 个完整字母数字的「占位串」会被拦 —— 用声明放行。
    """

    # ── 正例：真形命中 ──
    def test_sk_literal_detected(self):
        assert pre_tool_hook._plaintext_secret("echo " + _SEC_SK) is not None

    def test_mimo_tp_literal_detected(self):
        assert pre_tool_hook._plaintext_secret(_SEC_TP + " > /tmp/x") is not None

    def test_pem_private_key_header_detected(self):
        assert pre_tool_hook._plaintext_secret(_SEC_PEM) is not None

    # ── 负例：脱敏 / 引用写法不得误拦 ──
    def test_redacted_and_reference_forms_not_detected(self):
        for s in ("sk-****", "sk-...", "sk-<your-key>", "sk-",
                  "$DEEPSEEK_API_KEY", "${DEEPSEEK_API_KEY}",
                  "tp-", "sk-short", ".keys/context_ed25519.pem"):
            assert pre_tool_hook._plaintext_secret(s) is None, f"误拦：{s!r}"

    # ── 逃生舱：段首声明 ──
    def test_segment_declaration_allows_literal(self):
        assert pre_tool_hook._plaintext_secret("GK_SECRET_WRITE=1 echo " + _SEC_SK) is None

    def test_payload_declaration_allows_literal(self):
        # `wsl -e bash -lc '<载荷>'` 形态：声明位于**引号之后**的载荷段首。
        # 该形态是本仓主调用形态 ⟹ 逃生舱必须在此可用，否则形同虚设。
        assert pre_tool_hook._plaintext_secret(
            "wsl -e bash -lc 'GK_SECRET_WRITE=1 echo " + _SEC_SK + "'") is None

    def test_declaration_must_be_at_segment_start(self):
        # 声明落在**尾**（非段首）⟹ 不放行
        assert pre_tool_hook._plaintext_secret(
            "echo " + _SEC_SK + " GK_SECRET_WRITE=1") is not None

    # ── 接线：RunCommand 与 Edit/Write 载荷都走该闸 ──
    def test_runcommand_gate_blocks_plaintext_key(self):
        rc = run_hook_inline({"tool_name": "RunCommand", "cwd": str(Path.home()),
                              "tool_input": {"command": "echo " + _SEC_SK}})
        assert rc != 0, "RunCommand 里的明文 key 未被拦"

    def test_searchreplace_payload_gate_blocks_plaintext_key(self):
        rc = run_hook_inline({"tool_name": "SearchReplace", "cwd": str(Path.home()),
                              "tool_input": {"file_path": str(Path.home() / "x.env"),
                                             "old_str": "", "new_str": "K=" + _SEC_SK}})
        assert rc != 0, "SearchReplace 载荷里的明文 key 未被拦"

    def test_write_content_gate_blocks_plaintext_key(self):
        rc = run_hook_inline({"tool_name": "Write", "cwd": str(Path.home()),
                              "tool_input": {"file_path": str(Path.home() / "y.env"),
                                             "content": "M=" + _SEC_TP}})
        assert rc != 0, "Write 内容里的明文 key 未被拦"

    def test_edit_payload_declaration_allows(self):
        rc = run_hook_inline({"tool_name": "Write", "cwd": str(Path.home()),
                              "tool_input": {"file_path": str(Path.home() / "z.env"),
                                             "content": "GK_SECRET_WRITE=1\nK=" + _SEC_SK}})
        assert rc == 0, "段首声明后仍被拦（逃生舱失效）"


class TestSessionMarker:
    """§4.13.5「高并发②」使能切片（2026-09-25）：hook 的**会话身份出口**。

    病象：`session_id` 只在 PreToolUse 载荷里（仅 hook 进程可见），唯一出口 = `_run_cli` env
    ⟹ 只达 Gate 4；**agent 自己跑的 CLI 拿不到任何身份** ⟹ 落全局平面、与 hook 的会话平面
    **分叉 = 两套账**。出路：PreToolUse 先于工具执行 ⟹ 落 sid 标记，**同一次工具调用内**启动
    的 CLI 即可自解析到同一身份（见 `gatekeeper-cli.sh` 启动块的 `GK_SESSION_ID` 自解析块）。
    """

    SID = "0123456789abcdef01234567"

    def test_arm20_hook_writes_session_marker(self, tmp_path, monkeypatch):
        """判据：载荷带 `session_id` ⟹ 标记落地为 `sid<TAB>epoch<TAB>tool<TAB>cwd`。"""
        mf = tmp_path / ".gatekeeper.session"
        monkeypatch.setattr(pre_tool_hook, "_SESSION_FILE", mf, raising=False)
        rc = run_hook_inline({"tool_name": "RunCommand", "cwd": "C:/x",
                              "session_id": self.SID,
                              "tool_input": {"command": "echo hi"}})
        assert mf.is_file(), f"hook 未落会话标记（agent 侧无从自解析 sid）；rc={rc}"
        sid, ts, tool, cwd = mf.read_text(encoding="utf-8").rstrip("\n").split("\t")
        assert sid == self.SID, f"标记 sid 错：{sid!r}"
        assert ts.isdigit() and abs(time.time() - int(ts)) < 300, f"标记 epoch 不可用：{ts!r}"
        assert tool == "RunCommand", f"诊断列 tool 错：{tool!r}"
        assert cwd == "C:/x", f"诊断列 cwd 错：{cwd!r}"

    def test_arm20b_no_marker_without_sid_in_payload(self, tmp_path, monkeypatch):
        """负臂：载荷**无** `session_id`（老载荷 / 手工调用）⟹ 不写标记（不得造出假身份）。"""
        mf = tmp_path / ".gatekeeper.session"
        monkeypatch.setattr(pre_tool_hook, "_SESSION_FILE", mf, raising=False)
        run_hook_inline({"tool_name": "Grep", "cwd": "C:/x", "tool_input": {}})
        assert not mf.exists(), "无 sid 载荷却落了标记 ⟹ 假身份会污染 CLI 侧会话解析"


class TestMcpWriteGate:
    """MCP 写工具并入写类判定（`ECC-BC63B84B28AB`，A8「无旁路」）。

    背景：MCP 写工具经 `run_mcp` / `mcp__<server>__<tool>` **两形态**到达 hook（两形态在
    `.gatekeeper.hook.log` 均有真实 `event=PreToolUse` 派发记录），而写类判定只认
    `EDIT_TOOLS = {SearchReplace, Write, Edit, CreateFile, DeleteFile}` ⟹ **不归一即落空**
    （绕过 Gate 3 写面包含 / Gate 4 `edit_budget` / `R0.8` 密钥闸）。
    判据：归一成 `("Write", 目标路径)` 后**复用**既有 Gate，不新增第二套判定。
    """

    @pytest.fixture(autouse=True)
    def _no_wsl_conversion(self):
        with patch("pre_tool_hook._win_to_wsl", side_effect=lambda p: str(p)):
            yield

    @staticmethod
    def _mk(tmp_path):
        wt = tmp_path / "worktree"
        wt.mkdir()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"stage": "ECO-EDIT", "worktree": str(wt)}))
        return wt, state_file

    def test_arm1_run_mcp_write_outside_surface_blocked(self, tmp_path, monkeypatch):
        """arm-1（**红臂**）：`run_mcp` + 内层 `write_file` + 面外路径 ⟹ BLOCK(2)。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        with patch("pre_tool_hook._run_cli", return_value={"ok": True}):
            code = run_hook_inline({
                "tool_name": "run_mcp",
                "tool_input": {"server_name": "filesystem", "tool_name": "write_file",
                               "args": {"path": str(tmp_path / "outside.py")}},
                "cwd": str(wt),
            })
        assert code == 2, f"MCP 写工具写面外未被拦（exit={code}）⟹ A8 旁路仍开"

    def test_arm2_direct_mcp_write_outside_surface_blocked(self, tmp_path, monkeypatch):
        """arm-2（**红臂**）：直呼形态 `mcp__filesystem__write_file` + 面外路径 ⟹ BLOCK(2)。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        with patch("pre_tool_hook._run_cli", return_value={"ok": True}):
            code = run_hook_inline({
                "tool_name": "mcp__filesystem__write_file",
                "tool_input": {"path": str(tmp_path / "outside.py")},
                "cwd": str(wt),
            })
        assert code == 2, f"直呼形态 MCP 写工具写面外未被拦（exit={code}）"

    def test_arm2b_direct_mcp_write_real_shape_args_wrapped(self, tmp_path, monkeypatch):
        """arm-2b（**真机形态臂**，2026-10-02）：直呼形态真机 payload = `{"args": {...}}`。

        现场（DBG 实测）：`mcp__filesystem__write_file` 的 `tool_input` **只有** `args` 一个顶层键，
        参数（`path`/`content`）在 `args` 下 —— 原假设「参数即 `tool_input` 本体」取不到路径 ⟹
        写面/命令面**双双漏判**（`_mcp_inner_tool` 已按真机修正为「有 `args` 则解包」）。本臂锁真机形态。
        """
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        with patch("pre_tool_hook._run_cli", return_value={"ok": True}):
            code = run_hook_inline({
                "tool_name": "mcp__filesystem__write_file",
                "tool_input": {"args": {"path": str(tmp_path / "outside.py"), "content": "x"}},
                "cwd": str(wt),
            })
        assert code == 2, f"真机直呼形态（args 包裹）MCP 写工具写面外未被拦（exit={code}）"

    def test_arm3_mcp_readonly_not_blocked(self, tmp_path, monkeypatch):
        """arm-3（**负臂**）：MCP **只读**工具 ⟹ 不得拦（归一器不许误伤读面）。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        with patch("pre_tool_hook._run_cli", return_value={"ok": True}):
            code = run_hook_inline({
                "tool_name": "run_mcp",
                "tool_input": {"server_name": "filesystem", "tool_name": "read_text_file",
                               "args": {"path": str(tmp_path / "outside.txt")}},
                "cwd": str(wt),
            })
        assert code != 2, f"只读 MCP 工具被误拦（exit={code}）"

    def test_arm4_mcp_write_without_path_fail_closed(self, tmp_path, monkeypatch):
        """arm-4（**红臂** · fail-closed）：写类但**取不到路径** ⟹ 无法判写面包含 ⟹ 拒。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        with patch("pre_tool_hook._run_cli", return_value={"ok": True}):
            code = run_hook_inline({
                "tool_name": "run_mcp",
                "tool_input": {"server_name": "filesystem", "tool_name": "write_file",
                               "args": {}},
                "cwd": str(wt),
            })
        assert code == 2, f"写类无路径未 fail-closed（exit={code}）"

    def test_arm5_kill_switch_restores_original_behavior(self, tmp_path, monkeypatch):
        """arm-5（**回退面**）：`GK_MCP_WRITE_GATE=0` ⟹ 逐字恢复变更前行为（不拦）。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        monkeypatch.setenv("GK_MCP_WRITE_GATE", "0")
        with patch("pre_tool_hook._run_cli", return_value={"ok": True}):
            code = run_hook_inline({
                "tool_name": "run_mcp",
                "tool_input": {"server_name": "filesystem", "tool_name": "write_file",
                               "args": {"path": str(tmp_path / "outside.py")}},
                "cwd": str(wt),
            })
        assert code != 2, f"开关关闭后仍被拦（回退面失效，exit={code}）"


class TestMcpExecGate:
    """MCP 命令执行器并入 shell 安全面（`ECC-8F128D27B3E1`，A8 同族）。

    背景：Gate R0 家族（R0.1 引号陷阱 / R0.2 危险命令 / R0.3 脚本内容 / R0.4 插件裸调用 /
    R0.6 PS / R0.7 WSL / R0.8 明文密钥 / R0.9 windows-git 写）**全部**挂在
    `tool_name == "RunCommand"` 分支内；MCP 命令执行器（`mcp__windows-cli__execute_command` /
    `ssh_execute` / `run_mcp` 包裹）从不进该分支 ⟹ shell 面整体旁路。
    修法 = 与 `_write_identity` 同型：**只做身份归一**（`_cmd_identity` → `("RunCommand", cmd)`），
    判定仍由既有 R0 家族单源承载。

    两形态同 `_mcp_inner_tool`：`run_mcp`（内层名在 `tool_name`、参数在 `args`）与
    `mcp__<server>__<tool>`（`split("__",2)[2]`）。
    白名单 = **精确等值**（windows-cli 描述符实测：`execute_command` `{shell,command,workingDir}` /
    `ssh_execute` `{connectionId,command}`）；**禁用 token 交集** —— 否则只读工具
    `get_command_history` 会因 token `command` 被误收（arm-5 钉此边界）。
    """

    # 危险样例按仓内约定**拼接**生成（ECC-8DFC84C5B9E5：夹具里的危险字面量改用拼接写法，
    #   避免被自身防线误杀）—— 运行时等价于 `rm -rf /`（R0.2 类2 高危破坏）。
    _DANGER = " ".join(("rm", "-rf", "/"))

    @pytest.fixture(autouse=True)
    def _no_wsl_conversion(self):
        with patch("pre_tool_hook._win_to_wsl", side_effect=lambda p: str(p)):
            yield

    @staticmethod
    def _mk(tmp_path):
        wt = tmp_path / "worktree"
        wt.mkdir()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"stage": "ECO-EDIT", "worktree": str(wt)}))
        return wt, state_file

    def test_arm1_run_mcp_execute_command_blocked(self, tmp_path, monkeypatch, capsys):
        """arm-1（**红臂**）：`run_mcp` + 内层 `execute_command` + 危险命令 ⟹ BLOCK(2)。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        code = run_hook_inline({
            "tool_name": "run_mcp",
            "tool_input": {"server_name": "windows-cli", "tool_name": "execute_command",
                           "args": {"shell": "gitbash", "command": self._DANGER,
                                    "workingDir": str(wt)}},
            "cwd": str(wt),
        })
        err = capsys.readouterr().err
        assert code == 2, f"MCP 命令执行器（run_mcp 形态）绕过 R0（exit={code}）"
        assert "dangerous command" in err, f"非 R0.2 命中（拦错点）：{err[:300]}"

    def test_arm2_direct_mcp_execute_command_blocked(self, tmp_path, monkeypatch, capsys):
        """arm-2（**红臂**）：直呼形态 `mcp__windows-cli__execute_command` + 危险命令 ⟹ BLOCK(2)。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        code = run_hook_inline({
            "tool_name": "mcp__windows-cli__execute_command",
            "tool_input": {"shell": "gitbash", "command": self._DANGER, "workingDir": str(wt)},
            "cwd": str(wt),
        })
        err = capsys.readouterr().err
        assert code == 2, f"直呼形态 MCP 命令执行器绕过 R0（exit={code}）"
        assert "dangerous command" in err, f"非 R0.2 命中（拦错点）：{err[:300]}"

    def test_arm3_ssh_execute_blocked(self, tmp_path, monkeypatch, capsys):
        """arm-3（**红臂**）：`ssh_execute`（远程执行，风险更高）⟹ 同归一 ⟹ BLOCK(2)。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        code = run_hook_inline({
            "tool_name": "run_mcp",
            "tool_input": {"server_name": "windows-cli", "tool_name": "ssh_execute",
                           "args": {"connectionId": "pi", "command": self._DANGER}},
            "cwd": str(wt),
        })
        err = capsys.readouterr().err
        assert code == 2, f"ssh_execute 绕过 R0（exit={code}）"
        assert "dangerous command" in err, f"非 R0.2 命中（拦错点）：{err[:300]}"

    def test_arm4_exec_without_command_fail_closed(self, tmp_path, monkeypatch, capsys):
        """arm-4（**红臂** · fail-closed）：执行器但**取不到命令串** ⟹ 无法扫 ⟹ 拒。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        code = run_hook_inline({
            "tool_name": "run_mcp",
            "tool_input": {"server_name": "windows-cli", "tool_name": "execute_command",
                           "args": {}},
            "cwd": str(wt),
        })
        err = capsys.readouterr().err
        assert code == 2, f"执行器无命令串未 fail-closed（exit={code}）"
        assert "fail-closed" in err, f"非 fail-closed 命中：{err[:300]}"

    def test_arm5_readonly_get_command_history_not_blocked(self, tmp_path, monkeypatch):
        """arm-5（**负臂**）：只读工具 `get_command_history`（名含 token `command`）⟹ 不得误拦。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        code = run_hook_inline({
            "tool_name": "mcp__windows-cli__get_command_history",
            "tool_input": {"command": self._DANGER},   # 参数里放危险串：只读工具不该被扫
            "cwd": str(wt),
        })
        assert code != 2, f"只读 MCP 工具被误拦（token 交集写法会误伤）⟹ exit={code}"

    def test_arm6_kill_switch_restores_original_behavior(self, tmp_path, monkeypatch):
        """arm-6（**回退面**）：`GK_MCP_EXEC_GATE=0` ⟹ 逐字恢复变更前行为（不拦）。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        monkeypatch.setenv("GK_MCP_EXEC_GATE", "0")
        code = run_hook_inline({
            "tool_name": "run_mcp",
            "tool_input": {"server_name": "windows-cli", "tool_name": "execute_command",
                           "args": {"shell": "gitbash", "command": self._DANGER}},
            "cwd": str(wt),
        })
        assert code != 2, f"开关关闭后仍被拦（回退面失效，exit={code}）"


class TestMcpEgressGate:
    """Gate R0.14【单出网口闸】（`ECC-6007804DD7BD`，2026-10-10）：浏览器 MCP 出网归一。

    契约 = **单出网口**（`scripts/gk_evidence.py` L5）：一切出网走
    `subagent_runner._prior_art_fetch`（取回后经 `GK_WEB_EVIDENCE` 注入）。浏览器 MCP
    导航/取网动词此前**无面认领**（既不进写面也不进命令面）⟹ 第二出网通道 ⟹ 本闸普适 BLOCK。
    白名单 = **精确等值**（禁 token 交集）；`click`/`type`/`dom_tree`/`screenshot` 等
    **本地页面操作非出网** ⟹ 不收（负臂钉住）。
    """

    @pytest.fixture(autouse=True)
    def _no_wsl_conversion(self):
        with patch("pre_tool_hook._win_to_wsl", side_effect=lambda p: str(p)):
            yield

    @staticmethod
    def _mk(tmp_path):
        wt = tmp_path / "worktree"
        wt.mkdir()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"stage": "ECO-EDIT", "worktree": str(wt)}))
        return wt, state_file

    def test_arm1_run_mcp_navigate_blocked(self, tmp_path, monkeypatch, capsys):
        """arm-1（**红臂**）：`run_mcp` + 内层 `navigate` ⟹ BLOCK(2)（第二出网口）。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        code = run_hook_inline({
            "tool_name": "run_mcp",
            "tool_input": {"server_name": "Puppeteer", "tool_name": "navigate",
                           "args": {"url": "https://example.com"}},
            "cwd": str(wt),
        })
        err = capsys.readouterr().err
        assert code == 2, f"浏览器出网工具未被单出网口闸拦截（exit={code}）"
        assert pre_tool_hook.MCP_EGRESS_GATE_NAME in err, f"非 R0.14 命中：{err[:300]}"
        assert "_prior_art_fetch" in err, f"未给受治出网口指引：{err[:300]}"

    def test_arm2_direct_mcp_navigate_blocked(self, tmp_path, monkeypatch, capsys):
        """arm-2（**红臂**）：直呼形态 `mcp__Puppeteer__navigate` ⟹ 同样拦。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        code = run_hook_inline({
            "tool_name": "mcp__Puppeteer__navigate",
            "tool_input": {"args": {"url": "https://example.com"}},
            "cwd": str(wt),
        })
        err = capsys.readouterr().err
        assert code == 2, f"直呼形态浏览器出网未拦（exit={code}）"
        assert pre_tool_hook.MCP_EGRESS_GATE_NAME in err

    def test_arm3_fetch_blocked(self, tmp_path, monkeypatch, capsys):
        """arm-3（**红臂**）：`fetch`（通用取网）同样属出网 ⟹ 拦。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        code = run_hook_inline({
            "tool_name": "run_mcp",
            "tool_input": {"server_name": "octop-browser", "tool_name": "fetch",
                           "args": {"url": "https://example.com"}},
            "cwd": str(wt),
        })
        assert code == 2, f"fetch 未拦（exit={code}）"

    def test_arm4_local_ui_tools_not_blocked(self, tmp_path, monkeypatch):
        """arm-4（**负臂**）：`click`/`type`/`dom_tree`/`screenshot` = 本地页面操作（非出网）⟹ 不误拦。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        for inner in ("click", "type", "dom_tree", "screenshot"):
            code = run_hook_inline({
                "tool_name": "run_mcp",
                "tool_input": {"server_name": "Puppeteer", "tool_name": inner,
                               "args": {"selector": "#x"}},
                "cwd": str(wt),
            })
            assert code != 2, f"本地页面操作 {inner} 被误拦（exit={code}）"

    def test_arm5_kill_switch_restores_original(self, tmp_path, monkeypatch):
        """arm-5（**回退面**）：`GK_MCP_EGRESS_GATE=0` ⟹ 逐字恢复变更前行为（不拦）。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        monkeypatch.setenv("GK_MCP_EGRESS_GATE", "0")
        code = run_hook_inline({
            "tool_name": "run_mcp",
            "tool_input": {"server_name": "Puppeteer", "tool_name": "navigate",
                           "args": {"url": "https://example.com"}},
            "cwd": str(wt),
        })
        assert code != 2, f"开关关闭后仍被拦（exit={code}）"

    def test_octop_browser_prefixed_navigate_blocked(self, tmp_path, monkeypatch, capsys):
        """arm-6（**红臂**）：octop-browser 的 `browser_navigate`（带 `browser_` 前缀）⟹ 同样拦。

        `ECC-96B2214FA16B`：octop-browser（TencentCloud/octop-browser）的 MCP 工具名带
        `browser_` 前缀，与 `MCP_EGRESS_TOOLS` 的**裸动词精确集**不匹配（`_mcp_inner_tool`
        不做前缀剥离）⟹ 漏网 = 第二条未受治出网通道。本臂先证红。
        """
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        code = run_hook_inline({
            "tool_name": "run_mcp",
            "tool_input": {"server_name": "octop-browser", "tool_name": "browser_navigate",
                           "args": {"url": "https://example.com"}},
            "cwd": str(wt),
        })
        err = capsys.readouterr().err
        assert code == 2, f"octop-browser 前缀导航未拦（exit={code}）"
        assert pre_tool_hook.MCP_EGRESS_GATE_NAME in err, f"非 R0.14 命中：{err[:300]}"

    def test_octop_browser_eval_js_sealed(self, tmp_path, monkeypatch, capsys):
        """arm-7（**红臂**）：octop-browser 的 `browser_eval_js`（JS 内可 `fetch`）⟹ 封。

        `browser_eval_js` 与封禁集裸动词 `eval_js` 不匹配 ⟹ JS 内出网残余未封（同 finding）。
        """
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        code = run_hook_inline({
            "tool_name": "run_mcp",
            "tool_input": {"server_name": "octop-browser", "tool_name": "browser_eval_js",
                           "args": {"expression": "fetch('https://example.com')"}},
            "cwd": str(wt),
        })
        err = capsys.readouterr().err
        assert code == 2, f"octop-browser eval_js 未封（exit={code}）"
        assert pre_tool_hook.MCP_EGRESS_GATE_NAME in err, f"非 R0.14 命中：{err[:300]}"

    def test_octop_browser_local_tools_not_blocked(self, tmp_path, monkeypatch):
        """arm-8（**负臂**）：octop-browser 的本地页面操作（`browser_dom_tree`/`browser_click`/…）⟹ 不误拦。"""
        wt, state_file = self._mk(tmp_path)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
        for inner in ("browser_dom_tree", "browser_screenshot", "browser_click",
                      "browser_list_tabs", "browser_close_session"):
            code = run_hook_inline({
                "tool_name": "run_mcp",
                "tool_input": {"server_name": "octop-browser", "tool_name": inner,
                               "args": {"profile": "default"}},
                "cwd": str(wt),
            })
            assert code != 2, f"本地页面操作 {inner} 被误拦（exit={code}）"


# 宿主配置根（机器根；沿用仓内 `DEV_WORKTREE_ROOTS` 同款「机器根硬编码」先例）。
HOST_CFG_ROOT = "<home>/AppData/Roaming/Trae CN/User"


class TestHostConfigRoute:
    """宿主配置**独立面**（`R-HOSTCFG` 收尾）：与 cwd、`worktrees_extra` 都**无关**。

    病象（本会话实测）：① 原 cwd（`c:\\Users\\HP`）下 scope 判定 = `SCOPE-OUT` ⟹ 宿主配置护栏
    **整链不执行**（不拦、**不留痕**，hook.log 实测 `[SCOPE-OUT:allow]`、留痕账本零新增）；
    ② 若把宿主目录 bind 进 `worktrees_extra` 当写面，该键会被并发会话整体替换 ⟹ 绑定必丢。

    修法：在 **scope 判定之前**，把「宿主配置路径」接给**既有单源** `guard-edit`
    （= `_protected_region_check`）：WARN 档放行 + 强制留痕、BLOCK 档拦。⟹ **零 state 依赖**、
    **与 cwd 无关**、且不复制任何判定。
    """

    @staticmethod
    def _mk(tmp_path, monkeypatch):
        """夹具：**真复现 scope-out**（cwd 非治理范围）+ 活动 R 相位。

        `pre_tool_hook` 的 scope 判据里，`elif str(STATE_FILE) in _DEFAULT_STATE_PATHS:` 才会按 cwd
        解析 ⟹ 只 patch `STATE_FILE` 到临时路径会**落进 in-scope 链**（测不到病象）。故同时把
        `_DEFAULT_STATE_PATHS` 收窄为该临时路径 ⟹ `_resolve_state_by_cwd("c:\\Users\\HP")` 返回 None
        ⟹ `scope_out=True`（= 本会话实测的真实病灶）。
        """
        wt = tmp_path / "wt"
        wt.mkdir()
        st = tmp_path / "state.json"
        st.write_text(json.dumps({"stage": "ECO-EDIT", "worktree": str(wt)}))
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", st)
        monkeypatch.setattr(pre_tool_hook, "_DEFAULT_STATE_PATHS", (str(st),))
        return st

    @staticmethod
    def _audit(st):
        return Path(str(st) + ".protected-edits.jsonl")

    def test_arm1_host_mcp_json_allowed_and_audited_from_scope_out_cwd(self, tmp_path, monkeypatch):
        """arm-1（**红臂**）：cwd 非治理范围 + 宿主 `mcp.json` ⟹ 放行 **且必须留痕**。

        变更前实测：放行但**零留痕**（hook.log `[SCOPE-OUT:allow]`、审计账本零新增）⟹ 断言②即红。
        """
        st = self._mk(tmp_path, monkeypatch)
        code = run_hook_inline({
            "tool_name": "Write", "cwd": "c:\\Users\\HP",
            "tool_input": {"file_path": f"{HOST_CFG_ROOT}/mcp.json"},
        })
        aud = self._audit(st)
        assert code == 0, f"宿主 mcp.json 被拦（应放行）：exit={code}"
        assert aud.is_file() and '"region":"HOST-CONFIG"' in aud.read_text(encoding="utf-8"), \
            "宿主 mcp.json 写**未留痕**（护栏未执行 = 被 scope-out 静默绕过）"

    def test_arm2_host_hooks_json_blocked_from_scope_out_cwd(self, tmp_path, monkeypatch):
        """arm-2（**红臂**）：cwd 非治理范围 + 宿主 `hooks.json`（**门禁本体**）⟹ BLOCK。

        两断言（防"被别的闸拦也算过"的假绿）：① 默认开关 ⟹ 拦；② `GK_HOST_PROTECT=0` ⟹ 放行
        （证明拦阻确实只来 自本条规则，而非其他判据）。
        """
        st = self._mk(tmp_path, monkeypatch)
        payload = {
            "tool_name": "Write", "cwd": "c:\\Users\\HP",
            "tool_input": {"file_path": f"{HOST_CFG_ROOT}/hooks.json"},
        }
        assert run_hook_inline(dict(payload)) != 0, "宿主 hooks.json（门禁本体）未被拦"
        monkeypatch.setenv("GK_HOST_PROTECT", "0")
        assert run_hook_inline(dict(payload)) == 0, \
            "开关关闭后仍被拦 ⟹ 拦阻并非来自本条规则（假绿）"

    def test_arm3_lookalike_outside_host_root_not_governed(self, tmp_path, monkeypatch):
        """arm-3（**负臂**）：宿主根**之外**的同名文件不得被认领（防匹配写宽）。

        断言口径 = **账本里没有 HOST-CONFIG 记录**（而非退出码：范围外文件是否被别的闸拦不在本臂
        关注面内）。
        """
        st = self._mk(tmp_path, monkeypatch)
        run_hook_inline({
            "tool_name": "Write", "cwd": "c:\\Users\\HP",
            "tool_input": {"file_path": "/tmp/gk_lookalike/settings.json"},
        })
        aud = self._audit(st)
        assert not (aud.is_file() and '"region":"HOST-CONFIG"' in aud.read_text(encoding="utf-8")), \
            "范围外同名文件被认领为宿主配置（匹配过宽）"

    def test_arm5_windows_form_path_normalized(self, tmp_path, monkeypatch):
        """arm-5（**形态臂**）：hook 实测传 **Windows 形态** `C:\\...\\mcp.json` ⟹ 同样放行 + 留痕。

        动机：bash 侧 `basename "C:\\...\\mcp.json"` 对反斜杠串退化为整串 ⟹ 单源 `case` 永不命中
        （原式只对 WSL 形态有效）⟹ 真实场景保护失效。本臂钉住 `_host_config_check` 的反斜杠归一。
        """
        st = self._mk(tmp_path, monkeypatch)
        code = run_hook_inline({
            "tool_name": "Write", "cwd": "c:\\Users\\HP",
            "tool_input": {"file_path": r"<home>\AppData\Roaming\Trae CN\User\mcp.json"},
        })
        aud = self._audit(st)
        assert code == 0, f"Windows 形态宿主 mcp.json 被拦（应放行）：exit={code}"
        assert aud.is_file() and '"region":"HOST-CONFIG"' in aud.read_text(encoding="utf-8"), \
            "Windows 形态宿主 mcp.json 写**未留痕**（basename 未做反斜杠归一）"

    def test_arm4_predicate_names_match_bash_case(self):
        """arm-4（**一致性臂**）：python 谓词的 basename 集 == bash `case` 的名称集（防两处漂移）。"""
        import re
        from gk_host_paths import HOST_CONFIG_BASENAMES
        src = (pre_tool_hook.SKILL_DIR / "gatekeeper-cli.sh").read_text(encoding="utf-8")
        m = re.search(r'_host_config_check\(\)\s*\{.*?\n\s*esac', src, re.S)
        assert m, "未找到宿主配置保留集的单源 bash `case` 段（`_host_config_check` 落刀点漂移？）"
        names = set()
        for pat in re.findall(r"^\s*([a-z0-9.|*_-]+)\)", m.group(0), re.M):
            for alt in pat.split("|"):
                alt = alt.strip()
                if alt and alt != "*":
                    names.add(alt)
        py = set(HOST_CONFIG_BASENAMES)
        assert names == py, f"两处名称集漂移：bash={sorted(names)} python={sorted(py)}"


class TestMcpWriteCallContextSync:
    """MCP 写归一须同步调用上下文（`ECC-164BC163D0A5`，技能自维护）。

    缺口（回源）：`_cmd_identity`（命令面）归一后**显式回写** `_CALL_TOOL`/`_CALL_CMD`
    （L2978-2979「归一后同步（提权防线② / 审计口径）」）；而 `_write_identity`（写面）归一后
    **只改局部** `tool_name`/`file_path`，未回写 `_CALL_TOOL`/`_CALL_TARGET` ⟹ MCP 写被 BLOCK 时
    `_record_block_intent` 落盘的 `tool` = **原始名**（`run_mcp`/`mcp__…` ∉ `EDIT_TOOLS`）、
    `target` = **空串**（路径在 `tool_input["args"]`，scope 段的 `_CALL_TARGET` 取不到）⟹
    防线②「工具失效→提权绕过」对 MCP 写**整条失明**（原生 `Edit` 同链可拦 ⟹ 不对称 = 旁路）。
    判据：① block 日志身份 = 归一 `Write` + 归一目标路径；② MCP 写被拦 → 同目标 shell 直写
    被 Gate R0.5 拦（与原生 `Edit` 的整链同构）。
    """

    @pytest.fixture(autouse=True)
    def _no_wsl_conversion(self):
        with patch("pre_tool_hook._win_to_wsl", side_effect=lambda p: str(p)):
            yield

    @staticmethod
    def _mk_state(tmp_path: Path, wt: Path) -> Path:
        import hashlib
        sp = tmp_path / ".gatekeeper.state"
        gd = {"narrow_tasks": []}
        data = {"r_phase": "R1", "stage": "ECO-EDIT", "worktree": str(wt), "gate_data": gd,
                "_checksum": hashlib.sha256(
                    json.dumps(gd, sort_keys=True, ensure_ascii=True).encode()).hexdigest()[:16]}
        sp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return sp

    @staticmethod
    def _mcp_write_payload(victim: Path, wt: Path) -> dict:
        return {
            "tool_name": "run_mcp",
            "tool_input": {"server_name": "filesystem", "tool_name": "write_file",
                           "args": {"path": str(victim), "content": "x"}},
            "cwd": str(wt),
        }

    def test_mcpwriteblock_log_identity_synced(self, tmp_path):
        """臂 mcpwriteblock-a：MCP 写面外被拦后，block 日志须记归一身份（Write + 真目标）。"""
        wt = tmp_path / "worktree"
        wt.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        victim = outside / "victim.py"
        sp = self._mk_state(tmp_path, wt)
        with patch("pre_tool_hook.STATE_FILE", sp):
            rc = run_hook_inline(self._mcp_write_payload(victim, wt))
        assert rc == 2, f"MCP 写面外未被拦（exit={rc}）—— 前置行为被破坏"
        d = json.loads(sp.read_text(encoding="utf-8"))
        log = d["gate_data"]["hook_block_log"]
        assert log, "MCP 写被拦未落 block 意图（防线②前提缺失）"
        assert log[-1]["tool"] == "Write", (
            f"block 日志记原始名 {log[-1]['tool']!r} ⟹ 防线② 过滤 r['tool'] in EDIT_TOOLS 落空"
            "（MCP 写被拦后 shell 提权链不可见）")
        assert log[-1]["target"].replace("\\", "/").endswith("victim.py"), (
            f"block 日志 target 空/错（{log[-1]['target']!r}）⟹ 提权链目标比对落空")

    def test_mcpwriteblock_then_runcommand_escalation(self, tmp_path):
        """臂 mcpwriteblock-b（端到端）：MCP 写 X 被拦 → shell 重定向直写同 X → Gate R0.5 拦。"""
        wt = tmp_path / "worktree"
        wt.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        victim = outside / "victim.py"
        sp = self._mk_state(tmp_path, wt)
        with patch("pre_tool_hook.STATE_FILE", sp):
            rc1 = run_hook_inline(self._mcp_write_payload(victim, wt))
            assert rc1 == 2, f"MCP 写面外未被拦（exit={rc1}）"
            rc2 = run_hook_inline({
                "tool_name": "RunCommand",
                "tool_input": {"command": f"echo hacked > {victim}"},
                "cwd": str(wt),
            })
            assert rc2 == 2, "MCP 写被禁后 shell 直写同目标未被 R0.5 拦 ⟹ 提权绕过链存在"
        assert not victim.exists(), "越权写入必须被拦截（文件未产生）"
        d = json.loads(sp.read_text(encoding="utf-8"))
        assert [r["kind"] for r in d["gate_data"]["hook_block_log"]] == ["block", "escalation"]


class TestT6VerifyTelemetry:
    """T6 telemetry（§25；2026-10-08）：验证动作识别 + verify 事件落盘（**只采集不判罚**）。

    落刀前红：`pre_tool_hook._is_verify_command` / `._emit_verify_event` 不存在 ⟹ HEAD 必红。
    """

    def test_verify_command_detected(self):
        for c in ("python3 -m pytest -q scripts/test_x.py", "ctest --output-on-failure",
                  "bash run_verify.sh", "bash gatekeeper-cli.sh audit --all",
                  "go test ./...", "cargo test", "npm test"):
            assert pre_tool_hook._is_verify_command(c), "漏识验证命令：%r" % (c,)
        for c in ("ls -la", "git commit -m x", "echo hi", "python3 scripts/gk_advance.py"):
            assert not pre_tool_hook._is_verify_command(c), "误识非验证命令：%r" % (c,)

    def test_emit_verify_event_writes_log(self, tmp_path, monkeypatch):
        st = tmp_path / ".gatekeeper.state"
        st.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", st)
        pre_tool_hook._emit_verify_event("python3 -m pytest -q", node="STAGE_0")
        el = Path(str(st) + ".edit-log.jsonl")
        assert el.exists(), "verify 事件未落 edit-log（埋点未接线）"
        rec = json.loads([ln for ln in el.read_text(encoding="utf-8").splitlines() if ln.strip()][0])
        assert rec["kind"] == "verify" and rec["cmd"].startswith("python3 -m pytest"), rec
        assert rec.get("node") == "STAGE_0", "node 未透传：%r" % (rec.get("node"),)
        assert not Path(str(st) + ".budget-log.jsonl").exists(), "verify 事件污染了提额账本"

    def test_emit_verify_event_kill_switch(self, tmp_path, monkeypatch):
        st = tmp_path / ".gatekeeper.state"
        st.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", st)
        monkeypatch.setenv("GK_EDIT_LOG", "0")
        pre_tool_hook._emit_verify_event("pytest -q")
        assert not Path(str(st) + ".edit-log.jsonl").exists(), "kill switch 未生效（仍写 verify）"

    def test_emit_verify_event_missing_state_is_silent(self, tmp_path, monkeypatch):
        """fail-safe 臂：state 不存在 ⟹ 静默返回、**不抛**、不落盘（遥测不得阻断调用）。"""
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", tmp_path / "nope.state")
        pre_tool_hook._emit_verify_event("pytest -q")   # 不得抛异常


class TestStepTelemetry:
    """步数 telemetry（2026-10-23）：每条 `RunCommand` ⟹ 一条 `kind=step`，**只采集不判罚**。

    落刀前红：`pre_tool_hook._emit_step_event` / `gk_budget_ledger.append_step` 不存在。
    载体 = **独立** `<state>.step-log.jsonl` —— 步事件量级 ≫ 编辑事件，混入 edit-log 会稀释
    T4′ 的 `EDIT_SPAM_WINDOW`（按记录数切窗口）并加速 `EDIT_MAX_LINES` 轮转。
    采样点**两处**：范围内分支 + scope_out 分支（后者见 `TestT6VerifyTelemetryScopeOut`）。
    """

    @staticmethod
    def _mk_state(tmp_path, wt):
        import hashlib
        sp = tmp_path / ".gatekeeper.state"
        gd = {"narrow_tasks": []}
        data = {"r_phase": "R1", "stage": "ECO-EDIT", "worktree": str(wt), "gate_data": gd,
                "_checksum": hashlib.sha256(
                    json.dumps(gd, sort_keys=True, ensure_ascii=True).encode()).hexdigest()[:16]}
        sp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return sp

    @staticmethod
    def _rows(st):
        p = Path(str(st) + ".step-log.jsonl")
        if not p.exists():
            return []
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]

    def test_in_scope_runcommand_records_step(self, tmp_path, monkeypatch):
        """范围内分支：`RunCommand` ⟹ 一条 step（带 node），且**不进** edit-log。"""
        wt = tmp_path / "worktree"
        wt.mkdir()
        sp = self._mk_state(tmp_path, wt)
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", sp)
        monkeypatch.setenv("GK_EDIT_LOG", "1")
        monkeypatch.delenv("GK_STEP_LOG", raising=False)
        assert run_hook_inline({"hook_event_name": "PreToolUse", "tool_name": "RunCommand",
                                "tool_input": {"command": "echo hi"}, "cwd": str(wt)}) == 0
        rows = self._rows(sp)
        assert [r["kind"] for r in rows] == ["step"], "范围内 RunCommand 未采集步事件：%r" % (rows,)
        assert rows[0]["node"] == "ECO-EDIT", "node 未透传：%r" % (rows[0],)
        assert rows[0]["cmd"] == "echo hi", rows[0]
        assert not Path(str(sp) + ".edit-log.jsonl").exists(), "步事件污染了 edit-log"

    def test_emit_step_event_never_raises(self, tmp_path, monkeypatch):
        """fail-safe：state 缺失 ⟹ 静默（遥测不得阻断工具调用）。"""
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", tmp_path / "nope.state")
        pre_tool_hook._emit_step_event("echo hi", node="N")   # 不得抛异常

    def test_emit_step_event_kill_switches(self, tmp_path, monkeypatch):
        st = tmp_path / ".gatekeeper.state"
        st.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", st)
        for var in ("GK_EDIT_LOG", "GK_STEP_LOG"):
            monkeypatch.delenv("GK_EDIT_LOG", raising=False)
            monkeypatch.delenv("GK_STEP_LOG", raising=False)
            monkeypatch.setenv(var, "0")
            pre_tool_hook._emit_step_event("echo hi")
            assert self._rows(st) == [], "%s=0 未生效（仍写 step）" % (var,)
        monkeypatch.delenv("GK_STEP_LOG", raising=False)
        pre_tool_hook._emit_step_event("echo hi")
        assert [r["kind"] for r in self._rows(st)] == ["step"], "开关复位后应恢复采集"


class TestT6VerifyTelemetryScopeOut:
    """2026-10-23（红先）：**scope-out 的 RunCommand 也必须采集 verify**。

    病象（实测，本机）：会话 cwd 恒为 `c:\\Users\\HP`（治理范围外）⟹ `main()` 早退
    `sys.exit(0)` ⟹ 永不触达范围内分支尾部的 `_emit_verify_event` ⟹ 全仓
    `.gatekeeper.state.edit-log.jsonl` 的 `kind=verify` **恒 0**（grep 实测 0 条）⟹ T6 的
    `unverified` 只增不减（实测 `budget-probe/ECO-AUDIT` unverified=10）⟹ 节点每刀
    `cost=2`（`max=8` 实际只剩 4 刀）且**无销账路径**。
    判据：① scope-out + verify 命令 ⟹ 落 `kind=verify`（session/node 正确）；
         ② scope-out + 非 verify 命令 ⟹ 不落盘（不得把普通命令当验证）。
    """

    @staticmethod
    def _mk(tmp_path, monkeypatch):
        """复现真 scope_out：`STATE_FILE` 收窄进 `_DEFAULT_STATE_PATHS` + cwd 无主 state。"""
        wt = tmp_path / "wt"
        wt.mkdir()
        st = tmp_path / ".gatekeeper.state"
        st.write_text(json.dumps({"stage": "ECO-AUDIT", "worktree": str(wt),
                                  "gate_data": {}}), encoding="utf-8")
        monkeypatch.setattr(pre_tool_hook, "STATE_FILE", st)
        monkeypatch.setattr(pre_tool_hook, "_DEFAULT_STATE_PATHS", (str(st),))
        monkeypatch.setattr(pre_tool_hook, "_SESSION_ID", "s-t6")
        monkeypatch.setenv("GK_EDIT_LOG", "1")
        monkeypatch.setenv("GK_SESSION_ID", "s-t6")
        # 本组臂只测 **T6 verify/step 遥测**（命令只做形态识别、并不执行）⟹ 与 R0.16
        #   「pytest 必须用配好的解释器」正交；不加逃生舱会被 Gate R0.16 拦成 return 2，
        #   导致 5 臂假红（2026-10-27 实测）。
        monkeypatch.setenv("GK_ALLOW_ANY_PYTEST", "1")
        return st

    @staticmethod
    def _run(command, cwd="c:\\Users\\HP"):
        return run_hook_inline({"hook_event_name": "PreToolUse", "tool_name": "RunCommand",
                                "tool_input": {"command": command}, "cwd": cwd})

    @staticmethod
    def _rows(st):
        p = Path(str(st) + ".edit-log.jsonl")
        if not p.exists():
            return []
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]

    @staticmethod
    def _steps(st):
        """步事件在**独立**载体（`.step-log.jsonl`），不得混入 edit-log（否则稀释 T4′ 窗口）。"""
        p = Path(str(st) + ".step-log.jsonl")
        if not p.exists():
            return []
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]

    def test_scope_out_verify_is_recorded(self, tmp_path, monkeypatch):
        st = self._mk(tmp_path, monkeypatch)
        assert self._run("pytest -q scripts/test_gk_web_tools.py") == 0
        rows = self._rows(st)
        assert [r["kind"] for r in rows] == ["verify"], rows
        assert rows[0]["session"] == "s-t6" and rows[0]["node"] == "ECO-AUDIT", rows[0]
        # 步数 telemetry 同分支采集（验证动作本身也是一步）——**独立**载体，见 `_steps` 文档
        steps = self._steps(st)
        assert [r["kind"] for r in steps] == ["step"], steps
        assert steps[0]["session"] == "s-t6" and steps[0]["node"] == "ECO-AUDIT", steps[0]

    def test_scope_out_non_verify_not_recorded(self, tmp_path, monkeypatch):
        st = self._mk(tmp_path, monkeypatch)
        assert self._run("echo hi") == 0
        assert self._rows(st) == [], "非验证命令被当成 verify 落盘（判据过宽）"
        # 但步数 telemetry 必须落（否则 scope-out 分支等于没接步数采集）
        assert [r["kind"] for r in self._steps(st)] == ["step"], "scope-out 未采集步事件"

    def test_scope_out_verify_kill_switch(self, tmp_path, monkeypatch):
        st = self._mk(tmp_path, monkeypatch)
        monkeypatch.setenv("GK_EDIT_LOG", "0")
        assert self._run("pytest -q") == 0
        assert self._rows(st) == [], "kill switch 未生效（scope-out 仍写 verify）"
        assert self._steps(st) == [], "kill switch 未覆盖步数采集（GK_EDIT_LOG=0 须全关）"

    def test_scope_out_step_kill_switch(self, tmp_path, monkeypatch):
        """`GK_STEP_LOG=0` 只关步数、verify 仍落盘（两开关松耦合，便于单独停步数）。"""
        st = self._mk(tmp_path, monkeypatch)
        monkeypatch.setenv("GK_STEP_LOG", "0")
        assert self._run("pytest -q") == 0
        assert self._steps(st) == [], "GK_STEP_LOG=0 未生效（scope-out 仍写 step）"
        assert [r["kind"] for r in self._rows(st)] == ["verify"], "步数开关误伤了 verify 采集"

    def test_alias_routes_verify_to_worktree_token(self, tmp_path, monkeypatch):
        """同一对话的**两个身份**：载荷 sid（命令侧）↔ worktree token（Edit 计费侧）。

        实测病象：verify 落载荷桶、编辑记 token 桶 ⟹ `(session,node)` 分组永不交集 ⟹ T6
        永不销账。本臂锁「有别名 ⟹ verify 归位到 token」。
        """
        st = self._mk(tmp_path, monkeypatch)
        monkeypatch.setattr(pre_tool_hook, "_SESSION_FILE", tmp_path / ".gatekeeper.session")
        pre_tool_hook._write_session_alias("s-t6", "budget-probe")
        assert pre_tool_hook._read_session_alias("s-t6") == "budget-probe"
        assert self._run("pytest -q") == 0
        rows = self._rows(st)
        assert rows and rows[-1]["session"] == "budget-probe", rows

    def test_alias_absent_falls_back_to_payload_sid(self, tmp_path, monkeypatch):
        """反臂：无别名 ⟹ 不得凭空改身份（回落载荷 sid）。"""
        st = self._mk(tmp_path, monkeypatch)
        monkeypatch.setattr(pre_tool_hook, "_SESSION_FILE", tmp_path / ".gatekeeper.session")
        assert self._run("pytest -q") == 0
        rows = self._rows(st)
        assert rows and rows[-1]["session"] == "s-t6", rows


class TestWorktreeRouteGate:
    """Gate R0.17（2026-10-28，owner「把手动绕路的方式堵上，强制路由到 apply-worktree」）。

    病象实测：绕过 `apply-worktree` 手搓 `git worktree add -b feature/… <path>` 建树 ⟹ 该目录
    **不在** `state.worktree` / `worktrees_extra[]` ⟹ 首次 Edit 被 Gate 3 拦
    （"NOT in active write surface"）⟹ 再用 `cp` 把文件搬进去 —— 「奇怪绕路」。
    正路（单一入口）= `apply-worktree --plan <plan>` / `apply-worktree <finding> --family F`。
    """

    def test_git_worktree_add_blocked(self):
        assert pre_tool_hook._wt_route_gate(
            "git worktree add -b feature/x ../../.trae/worktrees/r/feature/x HEAD") is not None

    def test_git_dash_c_worktree_add_blocked(self):
        assert pre_tool_hook._wt_route_gate(
            'git -C "/mnt/c/repo" worktree add <home>/.trae/worktrees/r/feature/x HEAD'
        ) is not None

    def test_shell_wrapper_payload_blocked(self):
        assert pre_tool_hook._wt_route_gate(
            "bash -c 'git worktree add /x/y/z HEAD'") is not None

    def test_quoted_literal_not_blocked(self):
        """写文档时把命令示例放进引号 ⟹ 不得误伤。"""
        assert pre_tool_hook._wt_route_gate(
            "echo 'git worktree add <path> <branch>' >> docs/notes.md") is None

    def test_copy_into_worktree_root_blocked(self):
        assert pre_tool_hook._wt_route_gate(
            "cp -r docs/plans <home>/.trae/worktrees/r/feature/x/docs/") is not None

    def test_copy_out_of_worktree_root_allowed(self):
        """反臂：从 worktree 往外拷（非建树）不拦。"""
        assert pre_tool_hook._wt_route_gate(
            "cp -r <home>/.trae/worktrees/r/feature/x/docs .") is None

    def test_mkdir_in_worktree_root_blocked(self):
        assert pre_tool_hook._wt_route_gate(
            "mkdir -p <home>/.trae/worktrees/r/feature/x") is not None

    def test_apply_worktree_entry_allowed(self):
        assert pre_tool_hook._wt_route_gate(
            "bash gatekeeper-cli.sh apply-worktree --plan docs/plans/p.md") is None
        assert pre_tool_hook._wt_route_gate(
            "bash gatekeeper-cli.sh apply-worktree ECC-1234 --family F-coder") is None

    def test_kill_switch(self, monkeypatch):
        monkeypatch.setenv("GK_WT_ROUTE_GATE", "0")
        assert pre_tool_hook._wt_route_gate("git worktree add /x HEAD") is None

    def test_inline_escape(self):
        assert pre_tool_hook._wt_route_gate("GK_ALLOW_WT_ADD=1 git worktree add /x HEAD") is None

