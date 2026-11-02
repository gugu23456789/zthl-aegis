"""
test_gk_cron_night_batch.py — 夜间批次（dream 窗口）cron 作业内核测试（T-SLEEP-03 实装）

用户裁定（2026-09-17「其他都同意」）：「dream 机制只在北京时间凌晨生效，白天不执行。
这应该做成个 cron 插件？」本类钉死:
  ① 窗口语义: UTC 18–22 内 active / 窗口外 **零副作用**（不倒垃圾、**不** arm 标志）；
  ② F-REV-96 联动: 窗口内 arm 的 `.gatekeeper.no-ask` 必须能被 `pre_tool_hook._ask_noask_window`
     读成「活跃」——跨模块单点契约（否则提问挂起闸 H1 档收不到信号）；
  ③ 盘点全部**只读**（自有探针前缀白名单 / 回收站只加不减）；
  ④ ⑤ 探测**复用** self-check checks[]，不造第二份检查器（缺项下限 + 静默报错判据）；
  ⑤ wake gate 契约: stdout **末行** 是含 `wakeAgent` 的 JSON（`cron_jobs.parse_wake_gate` 语义）；
  ⑥ 红先模版漂移: **复用** doc-align 的 `red_arm_templates` 单点检查器（禁第二份实现）。
     用户裁定 2026-09-23「红先测试模版需要被 doc-align 检查是否存在漂移。顺便加个夜间任务」。
"""
import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_cron_night_batch as nb
import pre_tool_hook
import cron_jobs


@pytest.fixture(autouse=True)
def _iso(tmp_path, monkeypatch):
    """标志位落 tmp（绝不触碰真 SKILL_DIR/.gatekeeper.no-ask）；窗口强制清场。"""
    monkeypatch.setattr(nb, "NO_ASK_FLAG", str(tmp_path / ".gatekeeper.no-ask"))
    monkeypatch.delenv("GK_NIGHT_FORCE", raising=False)
    return tmp_path


def _in_window_now():
    """窗口内的**未来**时刻（明天 19:00 UTC）—— deadline 必在真实 now 之后，
    避免「用真实时钟」的测试在白天/深夜（UTC 22–18 之外）随机失败。"""
    import datetime as dt
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).replace(
        hour=19, minute=0, second=0, microsecond=0)


@pytest.fixture
def in_window(monkeypatch):
    """把 `_utcnow` 钉在窗口内（main()/run() 走真实 `_utcnow` 路径）。"""
    fixed = _in_window_now()
    monkeypatch.setattr(nb, "_utcnow", lambda: fixed)
    return fixed


def _fake_inventories(monkeypatch, recycle_files=3):
    """把四件重扫描替换成确定性桩（含真实回收站 walk 的场所）。"""
    monkeypatch.setattr(nb, "_inv_tmp", lambda: {
        "roots": ["/tmp"], "candidates": 2, "bytes": 2048, "stale_6h": 1,
        "top": ["/tmp/gk_a.sh"], "unreadable": 0})
    monkeypatch.setattr(nb, "_bomb_snapshot", lambda: {
        "ok": True, "counts": {"inline_python": 218, "stderr_swallow": 494,
                              "dangerous_command": 2, "fd_redirect": 82},
        "total": 796, "details": [], "error": ""})
    monkeypatch.setattr(nb, "_inv_recycle", lambda: {
        "roots": ["/mnt/c/$Recycle.Bin"], "files": recycle_files,
        "bytes": 1048576, "truncated": False})
    monkeypatch.setattr(nb, "_self_check", lambda: {
        "ok": True, "issues": 1, "items": 30, "fail": ["finding_journal_reconcile"],
        "skip": ["tests"], "silent": [], "missing": [], "compile_failures": [], "error": ""})
    monkeypatch.setattr(nb, "_red_arm_drift", lambda: {
        "ok": True, "status": "PASS", "detail": "红先模版登记表自洽", "error": ""})


# ── ① 窗口语义 + 窗口外零副作用 ──
class TestNightWindow:
    def test_window_boundaries(self):
        import datetime as dt
        mk = lambda h: dt.datetime(2026, 9, 17, h, 0, tzinfo=dt.timezone.utc)
        assert nb._night_window(mk(17))[0] is False
        assert nb._night_window(mk(18))[0] is True     # 含下界（北京 02:00）
        assert nb._night_window(mk(21))[0] is True
        assert nb._night_window(mk(22))[0] is False    # 不含上界（北京 06:00）
        assert nb._night_window(mk(9))[0] is False     # 白天不执行

    def test_deadline_is_same_day_2200_utc(self):
        import datetime as dt
        active, dl, _ = nb._night_window(dt.datetime(2026, 9, 17, 19, 30, tzinfo=dt.timezone.utc))
        assert active
        assert dt.datetime.fromtimestamp(dl, dt.timezone.utc).isoformat() == \
            "2026-09-17T22:00:00+00:00"

    def test_force_env(self, monkeypatch):
        import datetime as dt
        monkeypatch.setenv("GK_NIGHT_FORCE", "1")
        assert nb._night_window(dt.datetime(2026, 9, 17, 9, 0, tzinfo=dt.timezone.utc))[0] is True

    def test_outside_window_zero_side_effects(self, tmp_path, monkeypatch):
        """窗口外 → wakeAgent=False，且**不跑任何盘点**、**不 arm 标志**。"""
        import datetime as dt
        boom = lambda *a, **k: (_ for _ in ()).throw(AssertionError("窗口外不得跑盘点"))
        monkeypatch.setattr(nb, "_inv_tmp", boom)
        monkeypatch.setattr(nb, "_bomb_snapshot", boom)
        monkeypatch.setattr(nb, "_inv_recycle", boom)
        monkeypatch.setattr(nb, "_self_check", boom)
        code, gate, human = nb.run(now=dt.datetime(2026, 9, 17, 9, 0, tzinfo=dt.timezone.utc))
        assert code == 0 and gate["wakeAgent"] is False
        assert "窗口外" in human and "跳过" in human      # 不静默（留痕可辨「未触发」vs「触发即跳过」）
        assert not os.path.exists(nb.NO_ASK_FLAG)


# ── ② F-REV-96 联动（arm 的标志必须被 hook 读成活跃）──
class TestNoAskFlagIntegration:
    def test_arm_format_and_hook_reads_active(self, monkeypatch):
        """跨模块单点契约: cron arm 的标志 → hook 【提问挂起闸】H1 档读到「无人时段」。"""
        active, dl, note = nb._night_window(_in_window_now())
        assert active is True
        assert nb._arm_no_ask(dl) is True
        raw = Path(nb.NO_ASK_FLAG).read_text(encoding="utf-8")
        assert raw.split("|", 1)[0].strip() == str(int(dl))
        # hook 侧：SKILL_DIR 指向同一目录 → 必须读成活跃
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", Path(nb.NO_ASK_FLAG).parent)
        monkeypatch.setattr(pre_tool_hook, "_ASK_NOASK_FLAG_NAME", os.path.basename(nb.NO_ASK_FLAG))
        assert pre_tool_hook._ask_noask_window()[0] is True
        r = pre_tool_hook._ask_hold_gate({"questions": [{"question": "R7 用哪个方案？",
                                                          "options": [{"label": "甲"}, {"label": "乙"}]}]})
        assert r and r[0] == "BLOCK" and "无人时段" in r[1]

    def test_arm_failure_is_non_fatal(self, monkeypatch):
        monkeypatch.setattr(nb, "NO_ASK_FLAG", "/proc/nonexistent-dir/x")
        assert nb._arm_no_ask(time.time() + 60) is False


# ── ② bomb 快照（RED 引擎单点解析）──
class TestBombSnapshot:
    # 单点真实输出是 **indent=2 多行 JSON**（首版按单行解析 ⟹ counts 恒空，实测暴露）
    _REAL = json.dumps({
        "ok": True, "phase": "migrate", "findings": 4,
        "details": [
            {"id": "RED-MIGRATE-INLINE", "title": "218 inline python3 blocks in gatekeeper-cli.sh"},
            {"id": "RED-MIGRATE-SWALLOW", "title": "494 stderr swallows (2>/dev/null)"},
            {"id": "RED-MIGRATE-DANGER", "title": "2 dangerous commands (rm -rf 家族 / git push --force)"},
            {"id": "RED-MIGRATE-FD", "title": "82 fd redirects (2>&1/>&2)"},
        ]}, indent=2, ensure_ascii=False)

    def _stub(self, monkeypatch, stdout, rc=0, stderr=""):
        class P:
            returncode = rc
        P.stdout, P.stderr = stdout, stderr
        monkeypatch.setattr(nb.subprocess, "run", lambda *a, **k: P())

    def test_multiline_json_parsed(self, monkeypatch):
        self._stub(monkeypatch, self._REAL)
        r = nb._bomb_snapshot()
        assert r["ok"] is True
        assert r["counts"] == {"inline_python": 218, "stderr_swallow": 494,
                               "dangerous_command": 2, "fd_redirect": 82}
        assert r["total"] == 796 and len(r["details"]) == 4

    def test_garbage_output_reported_not_crash(self, monkeypatch):
        self._stub(monkeypatch, "boom", rc=1, stderr="traceback")
        r = nb._bomb_snapshot()
        assert r["ok"] is False and r["total"] == 0 and "未产出 JSON" in r["error"]

    def test_missing_rc_but_valid_json(self, monkeypatch):
        self._stub(monkeypatch, "prefix noise\n" + self._REAL)
        r = nb._bomb_snapshot()
        assert r["ok"] is True and r["total"] == 796     # 前置噪声行不影响解析


# ── ③ 盘点只读 + 白名单 ──
class TestInventories:
    def test_tmp_only_matches_probe_prefixes(self, tmp_path, monkeypatch):
        (tmp_path / "gk_probe.sh").write_text("x" * 100)
        (tmp_path / "bomb_now.json").write_text("y" * 50)
        (tmp_path / "user_important.docx").write_text("z" * 999)
        stale = tmp_path / "gk_old.sh"
        stale.write_text("w")
        os.utime(stale, (time.time() - 7 * 3600, time.time() - 7 * 3600))
        monkeypatch.setattr(nb, "_temp_roots", lambda: [str(tmp_path)])
        r = nb._inv_tmp()
        assert r["candidates"] == 3          # 用户文件不被计入
        assert r["bytes"] == 151
        assert r["stale_6h"] == 1
        assert all("user_important" not in p for p in r["top"])

    def test_recycle_readonly_count_and_truncation(self, tmp_path, monkeypatch):
        (tmp_path / "a.bin").write_bytes(b"12345")
        sub = tmp_path / "S-1-5-21"; sub.mkdir()
        (sub / "b.bin").write_bytes(b"123")
        monkeypatch.setattr(nb, "_RECYCLE_MAX_ENTRIES", 100)
        r = nb._inv_recycle([str(tmp_path)])
        assert r["files"] == 2 and r["bytes"] == 8 and r["truncated"] is False
        assert sorted(os.listdir(tmp_path)) == ["S-1-5-21", "a.bin"]   # 只读：无增删
        monkeypatch.setattr(nb, "_RECYCLE_MAX_ENTRIES", 1)
        r2 = nb._inv_recycle([str(tmp_path)])
        assert r2["files"] == 1 and r2["truncated"] is True


# ── ④⑤ self-check 复用 + 缺项 / 静默报错判据 ──
class TestSelfCheckProbe:
    def _stub(self, monkeypatch, checks, rc=0):
        class P:
            returncode = rc
            stdout = json.dumps({"ok": True, "issues": 1, "checks": checks})
            stderr = ""
        monkeypatch.setattr(nb.subprocess, "run", lambda *a, **k: P())

    def test_fail_and_silent_classified(self, monkeypatch):
        self._stub(monkeypatch, [
            {"check": "checksum_integrity", "status": "PASS", "detail": "ok"},
            {"check": "finding_journal_reconcile", "status": "FAIL", "detail": "10 项异常"},
            {"check": "ghost_checker", "status": "FAIL"},                     # 无 detail ⟹ 静默
            {"check": "tests", "status": "SKIP", "detail": "pytest 不可用"},
        ] + [{"check": f"c{i}", "status": "PASS", "detail": "ok"} for i in range(28)])
        r = nb._self_check()
        assert r["items"] == 32 and r["fail"] == ["finding_journal_reconcile", "ghost_checker"]
        assert r["silent"] == ["ghost_checker"]
        assert r["skip"] == ["tests"] and r["missing"] == []

    def test_item_floor_flags_missing(self, monkeypatch):
        self._stub(monkeypatch, [{"check": f"c{i}", "status": "PASS", "detail": "x"} for i in range(5)])
        r = nb._self_check()
        assert r["missing"] and "下限" in r["missing"][0]

    def test_no_json_output_is_reported_not_crash(self, monkeypatch):
        class P:
            returncode = 1
            stdout = "boom"
            stderr = "traceback"
        monkeypatch.setattr(nb.subprocess, "run", lambda *a, **k: P())
        r = nb._self_check()
        assert r["ok"] is False and "未产出 JSON" in r["error"] and r["items"] == 0

    def test_real_scripts_compile_clean(self):
        """真跑: scripts/*.py 全量 py_compile —— 0 失败（缺项/语法面确定判据，零副作用）。"""
        assert nb._compile_probe() == []


# ── ⑤ wake gate 契约（末行 JSON）──
class TestWakeGateContract:
    def test_last_line_is_wake_gate(self, monkeypatch, capsys, in_window):
        _fake_inventories(monkeypatch)
        nb.main([])
        out = [l for l in capsys.readouterr().out.strip().split("\n") if l.strip()]
        should_run, cleaned = cron_jobs.parse_wake_gate(out[-1])
        assert should_run is True
        gate = json.loads(out[-1])
        assert gate["wakeAgent"] is True and gate["no_ask_armed"] is True
        assert gate["self_check_items"] == 30 and gate["recycle_mb"] == 1.0
        # 人读报告在前（wake gate 之前的行都被 parse_wake_gate 视为 payload）
        assert "夜间批次报告" in "\n".join(out[:-1])

    def test_outside_window_gate_false(self, monkeypatch, capsys):
        import datetime as dt
        monkeypatch.setattr(nb, "_utcnow",
                            lambda: dt.datetime(2026, 9, 17, 9, 0, tzinfo=dt.timezone.utc))
        nb.main([])
        out = [l for l in capsys.readouterr().out.strip().split("\n") if l.strip()]
        should_run, cleaned = cron_jobs.parse_wake_gate("\n".join(out))
        assert should_run is False
        assert len(out) == 2                     # 一行「窗口外→跳过」留痕 + 末行 wake gate
        assert "窗口外" in cleaned

    def test_report_contains_all_five_sections(self, monkeypatch, capsys, in_window):
        _fake_inventories(monkeypatch)
        nb.main([])
        human = capsys.readouterr().out
        for sec in ("① 临时件盘点", "② bomb 统计快照", "③ 系统回收站只读盘点",
                    "④ self-check（规范入口）", "⑤ 检查器「缺项 / 静默报错」探测"):
            assert sec in human, sec

    def test_report_todo_lists_failures(self, monkeypatch, capsys, in_window):
        _fake_inventories(monkeypatch)
        monkeypatch.setattr(nb, "_self_check", lambda: {
            "ok": False, "issues": 2, "items": 10, "fail": ["checksum_integrity"],
            "skip": [], "silent": ["ghost_checker"], "missing": ["x"],
            "compile_failures": ["bad.py: SyntaxError"], "error": ""})
        nb.main([])
        human = capsys.readouterr().out
        assert "- self-check FAIL: checksum_integrity" in human
        assert "静默项归因" in human and "修语法/编译失败" in human and "为何只剩 10 项" in human


# ── ⑥ 红先模版漂移（用户裁定 2026-09-23「顺便加个夜间任务」）──
def _src_seg(name):
    """`name` 整函数体：切到下一个**列 0** 的块边界（与函数长度解耦）。

    红先模版 `func-boundary-slice` 的 **Python 同族**（原模版以列 0 的 `}` 为界，属 bash 形态；
    Python 无闭合大括号 ⟹ 边界取 `def `/`class `/`if __name__`）。
    """
    import re as _re
    src = Path(nb.__file__).read_text(encoding="utf-8")
    i = src.index("def %s(" % name)
    m = _re.search(r"(?m)^(?:def |class |if __name__)", src[i + 1:])
    return src[i:i + 1 + m.start()] if m else src[i:]


class TestRedArmDrift:
    """红先对照（本类落刀前对 HEAD 必红，实测记录）：

    · HEAD 无 `_red_arm_drift` ⟹ `_src_seg` / `nb._red_arm_drift` 全 `ValueError`/`AttributeError`；
    · 报告无「⑥ 红先模版漂移」段 ⟹ 段臂红。
    单源判据：检查器**必须**是 doc-align 的 `check_red_arm_templates`（禁第二份实现）。
    """

    def test_reuses_doc_align_single_checker(self):
        """源码形态臂：⑥ 委托 doc-align 单点检查器；**负臂**——不得内联模版 id 清单（第二份名单）。"""
        seg = _src_seg("_red_arm_drift")
        assert "gk_doc_align" in seg and "check_red_arm_templates" in seg
        for tid in ("source-absence", "func-boundary-slice", "api-absent",
                    "fail-loud-rc", "negative-arm"):
            assert tid not in seg, "第二份名单: %s" % tid

    def test_real_registry_is_consistent(self):
        """真跑（只读 / 0 API）：当前登记表自洽 ⟹ ok=True、status=PASS。"""
        r = nb._red_arm_drift()
        assert r["ok"] is True, r
        assert r["status"] == "PASS", r

    def test_missing_registry_is_reported_not_crash(self, monkeypatch):
        """例外态①：登记表缺失 ⟹ FAIL + 归因可见（不抛异常拖垮整轮夜间批次）。"""
        monkeypatch.setattr(nb, "SKILL_DIR", "/nonexistent-skill-dir-for-red-arm")
        r = nb._red_arm_drift()
        assert r["ok"] is False and r["status"] == "FAIL"
        assert "red-arm-templates" in r["detail"]

    def test_import_failure_is_fail_loud(self, monkeypatch):
        """例外态②：检查器导入失败 ⟹ error 归因（不静默、不抛）。"""
        monkeypatch.setitem(sys.modules, "gk_doc_align", None)
        r = nb._red_arm_drift()
        assert r["ok"] is False and r["status"] == "" and r["error"]

    def test_report_has_section_six(self, monkeypatch, capsys, in_window):
        _fake_inventories(monkeypatch)
        nb.main([])
        assert "⑥ 红先模版漂移" in capsys.readouterr().out

    def test_drift_surfaces_in_todo(self, monkeypatch, capsys, in_window):
        _fake_inventories(monkeypatch)
        monkeypatch.setattr(nb, "_red_arm_drift", lambda: {
            "ok": False, "status": "FAIL", "detail": "第二份名单漂移: gen=[] ≠ registry=[...]",
            "error": ""})
        nb.main([])
        human = capsys.readouterr().out
        assert "第二份名单漂移" in human           # 归因可见（不静默）
        assert "红先模版" in human

    def test_wake_gate_carries_drift_status(self, monkeypatch, capsys, in_window):
        _fake_inventories(monkeypatch)
        monkeypatch.setattr(nb, "_red_arm_drift", lambda: {
            "ok": False, "status": "FAIL", "detail": "x", "error": ""})
        nb.main([])
        out = [l for l in capsys.readouterr().out.strip().split("\n") if l.strip()]
        assert json.loads(out[-1])["red_arm_drift"] == "FAIL"
