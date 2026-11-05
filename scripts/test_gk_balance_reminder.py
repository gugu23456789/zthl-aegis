"""
test_gk_balance_reminder.py -- 余额投喂提醒单测（gk_views.topup_reminder，2026-11-05）
================================================================================
用户口径：「如果用户设置了 deepseek 余额告警，当命令检查到余额不足以跑一轮质询，
打印一行搞笑可爱、开源社区可接受的充钱提醒」。

覆盖：
① **未显式配置** `GK_BALANCE_MIN_CNY` ⟹ 不产提醒（不 nag）；非法阈值 ⟹ 不产；
② 低于阈值 ⟹ 一行文案（含充值链接与「不想投也完全没关系」）；`==` 阈值不报；
③ 文案纪律：**不出现「白嫖」**（自嘲主体是项目/大肥鱼，不是指责用户）；
④ 两个出口：`balance_format.py`（人读）与 `gk_balance_audit.py --json`（结构化）都不破契约
   —— 未配置时输出里没有该提醒；
⑤ 密钥防泄露回归：`cmd_balance` 的 Authorization 必须走 `--config -`（不进 argv）。
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from gk_views import TOPUP_URL, topup_reminder  # noqa: E402

_CLI = HERE.parent / "gatekeeper-cli.sh"

_BAL_RESP = json.dumps({
    "is_available": True,
    "balance_infos": [{"currency": "CNY", "total_balance": "1.83",
                       "granted_balance": "0.00", "topped_up_balance": "1.83"}],
})


@pytest.fixture
def no_alert(monkeypatch):
    monkeypatch.delenv("GK_BALANCE_MIN_CNY", raising=False)


def _run(script, args=(), stdin_text="", env_extra=None):
    env = {k: v for k, v in os.environ.items() if k != "GK_BALANCE_MIN_CNY"}
    env.update(env_extra or {})
    return subprocess.run([sys.executable, str(HERE / script), *args],
                          input=stdin_text, capture_output=True, text=True, env=env)


# ── ① 默认静默 / 非法阈值 ───────────────────────────────────────────────
def test_no_reminder_when_threshold_unset(no_alert):
    """未配置告警阈值 ⟹ 不打扰（提醒是「用户主动开了告警」才出现）。"""
    assert topup_reminder(0.0) is None


def test_no_reminder_when_threshold_invalid(monkeypatch):
    monkeypatch.setenv("GK_BALANCE_MIN_CNY", "abc")
    assert topup_reminder(0.0) is None


# ── ② 阈值判定 ─────────────────────────────────────────────────────────
def test_reminder_when_below_threshold(monkeypatch):
    monkeypatch.setenv("GK_BALANCE_MIN_CNY", "2")
    tip = topup_reminder(1.83)
    assert tip and "大肥鱼" in tip and TOPUP_URL in tip


def test_no_reminder_at_or_above_threshold(monkeypatch):
    monkeypatch.setenv("GK_BALANCE_MIN_CNY", "2")
    assert topup_reminder(2.0) is None
    assert topup_reminder(2.01) is None


def test_no_reminder_on_unparseable_total(monkeypatch):
    monkeypatch.setenv("GK_BALANCE_MIN_CNY", "2")
    assert topup_reminder(None) is None
    assert topup_reminder("") is None


# ── ③ 文案纪律（开源友好：不羞辱用户）───────────────────────────────
def test_copy_is_oss_friendly(monkeypatch):
    monkeypatch.setenv("GK_BALANCE_MIN_CNY", "2")
    tip = topup_reminder(0.5)
    assert "白嫖" not in tip                     # 自嘲 ≠ 指责使用者
    assert "不想投也完全没关系" in tip            # don't feel obligated
    assert tip.count("\n") == 0                   # 严格一行


# ── ④ 两个出口的契约 ───────────────────────────────────────────────────
def test_balance_format_silent_by_default(no_alert):
    out = _run("balance_format.py", stdin_text=_BAL_RESP)
    assert out.returncode == 0, out.stderr
    assert "大肥鱼" not in out.stdout


def test_balance_format_appends_tip_when_configured():
    out = _run("balance_format.py", stdin_text=_BAL_RESP,
               env_extra={"GK_BALANCE_MIN_CNY": "2"})
    assert out.returncode == 0, out.stderr
    assert out.stdout.rstrip().endswith("鱼不记仇。")
    assert "大肥鱼" in out.stdout


def test_audit_json_has_no_tip_field_by_default(no_alert):
    r = _run("gk_balance_audit.py", args=("--stdin", "--json"), stdin_text=_BAL_RESP)
    d = json.loads(r.stdout)
    assert d["snapshot"]["total"] == 1.83
    assert "topup_reminder" not in d


def test_audit_json_carries_tip_only_when_configured():
    r = _run("gk_balance_audit.py", args=("--stdin", "--json"), stdin_text=_BAL_RESP,
             env_extra={"GK_BALANCE_MIN_CNY": "2"})
    d = json.loads(r.stdout)
    assert "大肥鱼" in d["topup_reminder"]


# ── ⑤ 密钥不进 argv（防 ps / bash -x 泄露）─────────────────────────────
def _func_body(src: str, name: str) -> str:
    m = re.search(r"\n%s\(\) \{(.*?)\n\}\n" % re.escape(name), src, re.S)
    assert m, "%s 函数未找到" % name
    return m.group(1)


def test_balance_curl_keeps_key_out_of_argv():
    body = _func_body(_CLI.read_text(encoding="utf-8"), "_cmd_balance_body")
    assert "--config -" in body, "余额查询必须用 curl --config - 把 Authorization 放 stdin"
    assert not re.search(r'-H\s+"Authorization:\s*Bearer', body), \
        "Authorization 不得出现在 argv（会被 ps / bash -x 泄露）"


def test_balance_disables_xtrace_around_key():
    """红队 F-1：`bash -x` 会打印变量展开 ⟹ 包装层必须先 `set +x` 再进 body。"""
    src = _CLI.read_text(encoding="utf-8")
    wrapper = _func_body(src, "cmd_balance")
    assert "set +x" in wrapper and "_cmd_balance_body" in wrapper
    assert "set -x" in wrapper, "返回前须恢复 xtrace（用户可能在调试其它命令）"
