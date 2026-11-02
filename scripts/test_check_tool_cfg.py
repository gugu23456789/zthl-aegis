"""
test_check_tool_cfg.py — check_tool_cfg.py 的 C 段（hook 覆盖盘点，F-REV-98）测试
================================================================================
背景（2026-09-17 实测）：Gate 0「裸 Task 拦截」逻辑正确、单测全绿，但
`.gatekeeper.hook.log` 中 `event=PreToolUse tool=Task` 匹配数为 **0** —— 全部 586 条
`tool=Task` 记录都是 `event=?` + pytest 临时 cwd（单测直接调 main() 伪造）。
⟹ 门禁**生产不可达**却无人发现，因为既有检查不查"Trae 到底派发了哪些工具"。

本文件锁定该盘点的两条关键语义：
  1. `event=?`（单测伪造）**不算** Trae 派发 —— 否则死门禁会看起来"有覆盖"（本 bug 的成因）。
  2. 已登记死门禁 → WARN（不 FAIL）；**新**发现死门禁 → FAIL（必须处置）。
测试全部 hermetic：四类输入（runner/cli/hook/log）均落在 tmp_path。
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import check_tool_cfg


def _write(p: Path, text: str) -> Path:
    p.write_text(text, encoding="utf-8")
    return p


RUNNER_SRC = """TOOL_REGISTRY = {"read": 1, "write": 2}
TOOL_REGION_MAP = {"read": 1, "write": 2}
"""

CLI_SRC = """local valid_tools="read,write"
"""

# hook 侧只放两类分支形态（== / in），用于验证提取器覆盖两种写点
HOOK_SRC = """SCOPE_PATH_MAP = {"Read": "x"}
SCOPE_TOOLS = frozenset(SCOPE_PATH_MAP)


def handle(tool_name):
    if tool_name == "Task":
        return 1
    if tool_name == "RunCommand":
        return 2
    if tool_name in ("Grep", "Glob"):
        return 3
    return 0
"""


def _log_line(tool: str, event: str = "PreToolUse") -> str:
    return (f"2026-09-17 00:00:00 INVOKE event={event} tool={tool} "
            f"cwd=c:\\Users\\HP state=/mnt/c/x/.gatekeeper.state\n")


class TestHookHandlerTools:
    """静态提取：hook 里被显式分支处理的工具名。"""

    def test_extracts_eq_and_in_forms(self, tmp_path):
        got = check_tool_cfg.hook_handler_tools(_write(tmp_path / "hook.py", HOOK_SRC))
        assert {"Task", "RunCommand", "Grep", "Glob"} <= got

    def test_missing_branch_yields_no_names(self, tmp_path):
        got = check_tool_cfg.hook_handler_tools(_write(tmp_path / "hook.py", "x = 1\n"))
        assert got == set()


class TestHookObservedTools:
    """观测集：只认 Trae 真实派发（event=PreToolUse），排除单测伪造（event=?）。"""

    def test_pytest_fabricated_records_are_excluded(self, tmp_path):
        """**本 bug 的成因回归锁**：event=? 的 tool=Task 不得算作覆盖。"""
        log = _write(tmp_path / "hook.log",
                     _log_line("Task", event="?") + _log_line("Read"))
        assert check_tool_cfg.hook_observed_tools(log) == {"Read"}

    def test_only_fabricated_records_returns_none(self, tmp_path):
        """整份日志全是 event=?（冷环境/纯单测）→ None = 无法对账，不得判成"已覆盖"。"""
        log = _write(tmp_path / "hook.log", _log_line("Task", event="?"))
        assert check_tool_cfg.hook_observed_tools(log) is None

    def test_missing_log_returns_none(self, tmp_path):
        assert check_tool_cfg.hook_observed_tools(tmp_path / "nope.log") is None

    def test_names_containing_spaces_are_kept_intact(self, tmp_path):
        """实测 MCP 工具名含空格（`mcp__Computer Use__list_apps`）——
        曾用 `\\S+` 捕获被截断成 `mcp__Computer`，误判覆盖面。"""
        log = _write(tmp_path / "hook.log",
                     _log_line("mcp__Computer Use__list_apps"))
        assert check_tool_cfg.hook_observed_tools(log) == {"mcp__Computer Use__list_apps"}


class TestKnownUnreachableRegistry:
    def test_task_is_registered(self):
        """Task 必须登记在案 —— 否则盘点会永久 FAIL（Trae 结构性不派发）。"""
        assert "Task" in check_tool_cfg._KNOWN_UNREACHABLE


class TestMainCoverageIntegration:
    """端到端：main() 的四类输入全部注入 tmp_path（hermetic）。"""

    @pytest.fixture()
    def _wired(self, tmp_path, monkeypatch):
        def _wire(log_text: str):
            monkeypatch.setattr(check_tool_cfg, "RUNNER",
                                _write(tmp_path / "runner.py", RUNNER_SRC))
            monkeypatch.setattr(check_tool_cfg, "CLI",
                                _write(tmp_path / "cli.sh", CLI_SRC))
            monkeypatch.setattr(check_tool_cfg, "HOOK",
                                _write(tmp_path / "hook.py", HOOK_SRC))
            log = _write(tmp_path / "hook.log", log_text)
            monkeypatch.setenv("GK_HOOK_LOG", str(log))
        return _wire

    def test_new_dead_gate_fails(self, _wired, capsys):
        """Task 被观测到、RunCommand 未观测 → RunCommand 是**新**死门禁 → FAIL。"""
        _wired(_log_line("Task") + _log_line("Read"))
        rc = check_tool_cfg.main()
        out = json.loads(capsys.readouterr().out)
        assert rc == 1 and out["ok"] is False
        assert "hook 覆盖: FAIL" in out["checks"][0]["detail"]
        assert "RunCommand" in out["checks"][0]["detail"]

    def test_known_dead_gate_warns_but_passes(self, _wired, capsys):
        """只有 Task 缺席 → 已登记 → WARN，不 FAIL（避免永久红）。"""
        _wired("".join(_log_line(t) for t in
                       ("RunCommand", "Grep", "Glob", "Read")))
        rc = check_tool_cfg.main()
        out = json.loads(capsys.readouterr().out)
        assert rc == 0 and out["ok"] is True
        assert "已知死门禁 ['Task']" in out["checks"][0]["detail"]

    def test_full_coverage_passes(self, _wired, capsys):
        """四个处理分支全被派发过 → PASS（无死门禁，不产生豁免噪声）。"""
        _wired("".join(_log_line(t) for t in
                       ("Task", "RunCommand", "Grep", "Glob", "Read")))
        rc = check_tool_cfg.main()
        out = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert "hook 覆盖: PASS" in out["checks"][0]["detail"]

    def test_log_unavailable_skips_instead_of_failing(self, _wired, capsys, tmp_path,
                                                     monkeypatch):
        """日志不可用 → SKIP（冷环境不得误红）。"""
        _wired("")
        monkeypatch.setenv("GK_HOOK_LOG", str(tmp_path / "absent.log"))
        rc = check_tool_cfg.main()
        out = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert "hook 覆盖: SKIP" in out["checks"][0]["detail"]
