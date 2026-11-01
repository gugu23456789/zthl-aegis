"""test_gk_cron_external_ref.py — cron 外部参考 job 测试（2026-09-01）

覆盖用户质询"cron 没动静 + 无外部参考"的修复：外部参考检查脚本（L4 上游版本
漂移 + 未推送提交 + 陈旧检测）的 JSON 契约与容错。确定性 0 API（网络查询走
subprocess monkeypatch）。不触碰真实 cron 注册表。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gk_cron_external_ref as cr


class TestMainContract:
    def test_ok_with_drift(self, monkeypatch, capsys):
        """正常：检出 gitnexus 版本漂移 + 未推送提交。"""
        monkeypatch.setattr(cr, "_run", _fake_run_multi({
            ("npm", "view", "gitnexus", "version"): ("1.6.10", "", 0),
            ("git", "rev-list", "--count", "@{u}..HEAD"): ("35", "", 0),
            ("git", "log", "-1", "--format=%ct"): ("1756000000", "", 0),
        }))
        # 伪造本地 package.json 版本
        monkeypatch.setattr(cr, "_read_gitnexus_local_version", lambda: "1.6.9")
        cr.main()
        d = json.loads(capsys.readouterr().out)
        assert d["ok"] is True
        assert d["source"] == "cron-external-ref"
        assert d["gitnexus_drift"] is True
        assert d["unpushed_commits"] == 35
        assert d["needs_attention"] is True
        assert any("版本漂移" in f for f in d["findings"])

    def test_no_drift_clean(self, monkeypatch, capsys):
        """无漂移 + 无未推送 → needs_attention False。"""
        monkeypatch.setattr(cr, "_run", _fake_run_multi({
            ("npm", "view", "gitnexus", "version"): ("1.6.9", "", 0),
            ("git", "rev-list", "--count", "@{u}..HEAD"): ("0", "", 0),
            ("git", "log", "-1", "--format=%ct"): (str(int(__import__("time").time())), "", 0),
        }))
        monkeypatch.setattr(cr, "_read_gitnexus_local_version", lambda: "1.6.9")
        cr.main()
        d = json.loads(capsys.readouterr().out)
        assert d["gitnexus_drift"] is False
        assert d["needs_attention"] is False
        assert d["findings"] == []

    def test_offline_npm_view(self, monkeypatch, capsys):
        """npm view 失败（离线）→ drift unknown，不崩溃。"""
        monkeypatch.setattr(cr, "_run", _fake_run_multi({
            ("npm", "view", "gitnexus", "version"): ("", "ETIMEDOUT", 1),
            ("git", "rev-list", "--count", "@{u}..HEAD"): ("0", "", 0),
            ("git", "log", "-1", "--format=%ct"): ("1756000000", "", 0),
        }))
        monkeypatch.setattr(cr, "_read_gitnexus_local_version", lambda: "1.6.9")
        cr.main()
        d = json.loads(capsys.readouterr().out)
        assert d["gitnexus_drift"] == "unknown"
        assert d["gitnexus_drift_note"] != ""

    def test_no_upstream_unpushed(self, monkeypatch, capsys):
        """无 upstream → unpushed -1 + note，不崩溃。"""
        monkeypatch.setattr(cr, "_run", _fake_run_multi({
            ("npm", "view", "gitnexus", "version"): ("1.6.9", "", 0),
            ("git", "rev-list", "--count", "@{u}..HEAD"): ("", "fatal: no upstream", 128),
            ("git", "log", "-1", "--format=%ct"): (str(int(__import__("time").time())), "", 0),
        }))
        monkeypatch.setattr(cr, "_read_gitnexus_local_version", lambda: "1.6.9")
        cr.main()
        d = json.loads(capsys.readouterr().out)
        assert d["unpushed_commits"] == -1
        assert "unpushed_note" in d
        assert d["needs_attention"] is False

    def test_stale_commit_flag(self, monkeypatch, capsys):
        """最后提交 >30 天 → 陈旧 flag。"""
        import time
        old = str(int(time.time()) - 40 * 86400)
        monkeypatch.setattr(cr, "_run", _fake_run_multi({
            ("npm", "view", "gitnexus", "version"): ("1.6.9", "", 0),
            ("git", "rev-list", "--count", "@{u}..HEAD"): ("0", "", 0),
            ("git", "log", "-1", "--format=%ct"): (old, "", 0),
        }))
        monkeypatch.setattr(cr, "_read_gitnexus_local_version", lambda: "1.6.9")
        cr.main()
        d = json.loads(capsys.readouterr().out)
        assert d["last_commit_days"] > 30
        assert any("天前" in f for f in d["findings"])

    def test_no_timeout_crash(self, monkeypatch, capsys):
        """_run 内部 subprocess 抛异常 → 返回 ("", err, 1)，main 不崩溃。"""
        import subprocess as _sp
        def boom(*a, **k):
            raise _sp.TimeoutExpired(a[0], 30)
        monkeypatch.setattr(_sp, "run", boom)
        monkeypatch.setattr(cr, "_read_gitnexus_local_version", lambda: "1.6.9")
        cr.main()
        d = json.loads(capsys.readouterr().out)
        assert d["ok"] is True


def _fake_run_multi(table):
    def f(cmd, timeout=30):
        key = tuple(cmd)
        if key in table:
            return table[key]
        return ("", f"unexpected: {cmd}", 1)
    return f
