"""test_gk_hook_manage.py — 钩子安装/卸载的加载安全网（2026-10-28 重写验收）

覆盖三失败模式（对齐 references/plugin-loading-test-framework.md §1.3）：
  漏加载 = 命令指向缺失 wrapper / 注册后不可达；
  误加载 = 覆盖用户条目 ⟹ 用例断言 foreign 条目逐字保留；
  错加载 = 目标 hooks.json 不可解析 ⟹ fail-closed 零写入。
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_hook_manage as ghm


def _skill(tmp_path):
    """造一个最小技能根：scripts/pre_tool_hook_wrapper.sh 存在。"""
    sd = tmp_path / "skill"
    (sd / "scripts").mkdir(parents=True)
    (sd / "scripts" / ghm.WRAPPER_NAME).write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    return str(sd)


def _write_hooks(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


FOREIGN = {"matcher": "RunCommand",
           "hooks": [{"type": "command", "command": "bash /opt/other/guard.sh", "timeout": 5}]}


def _base():
    return {"version": 1, "hooks": {"PreToolUse": [FOREIGN]}}


class TestStatus:
    def test_absent_when_missing(self, tmp_path):
        st = ghm.load_status(tmp_path / "hooks.json", _skill(tmp_path))
        assert st["source"] == "absent" and st["exists"] is False
        assert st["command_ok"] is True

    def test_foreign_only(self, tmp_path):
        hp = tmp_path / "hooks.json"
        _write_hooks(hp, _base())
        st = ghm.load_status(hp, _skill(tmp_path))
        assert st["source"] == "foreign" and st["foreign"] == 1 and st["ours"] == 0

    def test_unparseable_reported(self, tmp_path):
        hp = tmp_path / "hooks.json"
        hp.write_text("{not json", encoding="utf-8")
        st = ghm.load_status(hp, _skill(tmp_path))
        assert st["source"] == "unparseable" and st["detail"]


class TestInstall:
    def test_install_creates_and_verifies(self, tmp_path):
        hp = tmp_path / "hooks.json"
        sd = _skill(tmp_path)
        r = ghm.install(hp, sd, "safe")
        assert r["ok"] is True and r["changed"] is True
        st = ghm.load_status(hp, sd)
        assert st["source"] == "registered" and st["ours"] == 1
        data = json.loads(hp.read_text(encoding="utf-8"))
        assert data["hooks"]["PreToolUse"][0]["matcher"] == ghm.PROFILES["safe"]

    def test_install_idempotent(self, tmp_path):
        hp = tmp_path / "hooks.json"
        sd = _skill(tmp_path)
        assert ghm.install(hp, sd, "safe")["ok"]
        r2 = ghm.install(hp, sd, "safe")
        assert r2["ok"] is True and r2["changed"] is False
        assert ghm.load_status(hp, sd)["ours"] == 1

    def test_install_profile_change_updates_coverage(self, tmp_path):
        """重装换 profile ⟹ 覆盖面（matcher）原位更新，不允许叠第二条本仓条目。"""
        hp = tmp_path / "hooks.json"
        sd = _skill(tmp_path)
        assert ghm.install(hp, sd, "safe")["ok"]
        r = ghm.install(hp, sd, "full")
        assert r["ok"] is True and r["removed_stale"] == 1
        assert ghm.load_status(hp, sd)["ours"] == 1
        entries = json.loads(hp.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
        assert len(entries) == 1 and entries[0]["matcher"] == ghm.PROFILES["full"]

    def test_install_preserves_foreign_entries(self, tmp_path):
        hp = tmp_path / "hooks.json"
        _write_hooks(hp, _base())
        sd = _skill(tmp_path)
        assert ghm.install(hp, sd, "full")["ok"]
        entries = json.loads(hp.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
        assert FOREIGN in entries and len(entries) == 2
        assert ghm.load_status(hp, sd)["foreign"] == 1

    def test_install_refuses_unparseable(self, tmp_path):
        hp = tmp_path / "hooks.json"
        hp.write_text("{not json", encoding="utf-8")
        before = hp.read_bytes()
        r = ghm.install(hp, _skill(tmp_path), "safe")
        assert r["ok"] is False and r["error"] == "HOOKS_UNPARSEABLE"
        assert hp.read_bytes() == before, "fail-closed：不可解析必须零写入"

    def test_install_dry_run_writes_nothing(self, tmp_path):
        hp = tmp_path / "hooks.json"
        r = ghm.install(hp, _skill(tmp_path), "safe", dry_run=True)
        assert r["ok"] is True and r["dry_run"] is True
        assert not hp.exists()

    def test_install_requires_wrapper(self, tmp_path):
        """漏加载拦在写前：wrapper 缺失 ⟹ 拒绝注册（否则每次工具调用都被拦）。"""
        empty = tmp_path / "skill2"
        (empty / "scripts").mkdir(parents=True)
        r = ghm.install(tmp_path / "hooks.json", str(empty), "safe")
        assert r["ok"] is False and r["error"] == "WRAPPER_MISSING"

    def test_install_off_removes_ours_keeps_foreign(self, tmp_path):
        hp = tmp_path / "hooks.json"
        _write_hooks(hp, _base())
        sd = _skill(tmp_path)
        assert ghm.install(hp, sd, "full")["ok"]
        r = ghm.install(hp, sd, "off")
        assert r["ok"] is True and r["removed_stale"] == 1
        st = ghm.load_status(hp, sd)
        assert st["ours"] == 0 and st["foreign"] == 1

    def test_install_bad_profile(self, tmp_path):
        r = ghm.install(tmp_path / "hooks.json", _skill(tmp_path), "nope")
        assert r["ok"] is False and r["error"] == "BAD_PROFILE"

    def test_install_writes_backup_when_file_exists(self, tmp_path):
        hp = tmp_path / "hooks.json"
        _write_hooks(hp, _base())
        r = ghm.install(hp, _skill(tmp_path), "safe")
        assert r["ok"] and r["backup"] and Path(r["backup"]).exists()


class TestUninstall:
    def test_uninstall_removes_only_ours(self, tmp_path):
        hp = tmp_path / "hooks.json"
        _write_hooks(hp, _base())
        sd = _skill(tmp_path)
        ghm.install(hp, sd, "safe")
        r = ghm.uninstall(hp, sd)
        assert r["ok"] is True and r["removed"] == 1
        entries = json.loads(hp.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
        assert entries == [FOREIGN]

    def test_uninstall_absent_is_noop(self, tmp_path):
        r = ghm.uninstall(tmp_path / "hooks.json", _skill(tmp_path))
        assert r["ok"] is True and r["removed"] == 0 and r["changed"] is False

    def test_uninstall_refuses_unparseable(self, tmp_path):
        hp = tmp_path / "hooks.json"
        hp.write_text("[", encoding="utf-8")
        before = hp.read_bytes()
        r = ghm.uninstall(hp, _skill(tmp_path))
        assert r["ok"] is False and r["error"] == "HOOKS_UNPARSEABLE"
        assert hp.read_bytes() == before


class TestShapeAndLegacy:
    """2026-11-01：空文件不算损坏；hooks 形状错 fail-closed；旧版条目可摘；兄弟目录不误伤。"""

    def test_empty_file_treated_as_absent_and_installable(self, tmp_path):
        hp = tmp_path / "hooks.json"
        hp.write_text("", encoding="utf-8")
        sd = _skill(tmp_path)
        st = ghm.load_status(hp, sd)
        assert st["source"] == "absent" and st["exists"] is True
        r = ghm.install(hp, sd, "safe")
        assert r["ok"] is True and r["changed"] is True

    def test_bad_shape_fails_closed(self, tmp_path):
        hp = tmp_path / "hooks.json"
        hp.write_text(json.dumps({"hooks": [{"matcher": "*"}]}), encoding="utf-8")
        before = hp.read_bytes()
        sd = _skill(tmp_path)
        assert ghm.load_status(hp, sd)["source"] == "bad_shape"
        r = ghm.install(hp, sd, "safe")
        assert r["ok"] is False and r["error"] == "HOOKS_BAD_SHAPE"
        assert hp.read_bytes() == before, "fail-closed：形状不对必须零写入"
        u = ghm.uninstall(hp, sd)
        assert u["ok"] is False and u["error"] == "HOOKS_BAD_SHAPE"

    def test_legacy_pre_tool_hook_entry_is_removed(self, tmp_path):
        sd = _skill(tmp_path)
        hp = tmp_path / "hooks.json"
        legacy = {"matcher": "*",
                  "hooks": [{"type": "command", "command": "bash %s/scripts/pre_tool_hook.py" % sd}]}
        _write_hooks(hp, {"version": 1, "hooks": {"PreToolUse": [legacy, FOREIGN]}})
        r = ghm.uninstall(hp, sd)
        assert r["ok"] is True and r["removed"] == 1
        assert json.loads(hp.read_text(encoding="utf-8"))["hooks"]["PreToolUse"] == [FOREIGN]

    def test_sibling_skill_dir_not_matched(self, tmp_path):
        sd = _skill(tmp_path)
        hp = tmp_path / "hooks.json"
        sibling = {"matcher": "*",
                   "hooks": [{"type": "command",
                              "command": "bash %s-2/scripts/pre_tool_hook_wrapper.sh" % sd}]}
        _write_hooks(hp, {"version": 1, "hooks": {"PreToolUse": [sibling]}})
        st = ghm.load_status(hp, sd)
        assert st["ours"] == 0 and st["foreign"] == 1, "目录前缀相同不等于本仓条目"


class TestCli:
    def test_status_json_exit_zero(self, tmp_path):
        hp = tmp_path / "hooks.json"
        r = subprocess.run([sys.executable, str(Path(__file__).parent / "gk_hook_manage.py"),
                            "status", "--hooks", str(hp), "--skill-dir", _skill(tmp_path), "--json"],
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        assert json.loads(r.stdout)["source"] == "absent"

    def test_install_unparseable_exit_three(self, tmp_path):
        hp = tmp_path / "hooks.json"
        hp.write_text("{", encoding="utf-8")
        r = subprocess.run([sys.executable, str(Path(__file__).parent / "gk_hook_manage.py"),
                            "install", "--hooks", str(hp), "--skill-dir", _skill(tmp_path)],
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 3, r.stdout + r.stderr
        assert hp.read_text(encoding="utf-8") == "{"