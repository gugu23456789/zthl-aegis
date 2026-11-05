#!/usr/bin/env python3
"""ECC 信封校验下沉（2026-11-04，C1）—— stdout 契约 + 接线面。

背景：`cmd_monitor` 原先各内联一份**逐字相同**的 pydantic 模型（validate 1.8 KB / hmac 3.0 KB）。
两块合成 `scripts/gk_monitor_envelope.py`，bash 侧按 stdout 字面判（`VALID` / `valid` /
`no_hmac` / `invalid`），异常时无输出 + 非零退出（hmac 侧由 `|| echo "skip"` 兜底）。

等价性已由一次性对比脚本对 7 类输入 × 2 模式（含畸形 JSON / 缺键 / 类型错 / HMAC 三态）
逐字比对为 14/14 相同后才切换；本文件守的是一条不变量 —— **契约不许在后续改动中漂移**。
"""
import hashlib
import hmac
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SD = Path(__file__).resolve().parent.parent
CLI = SD / "gatekeeper-cli.sh"
MOD = SD / "scripts" / "gk_monitor_envelope.py"
KEY = "0f" * 32


@pytest.fixture
def _needs_pydantic():
    pytest.importorskip("pydantic")


def _sign(payload, key=KEY):
    data = {k: v for k, v in payload.items() if k not in ("hmac", "jwt_token")}
    sk = bytes.fromhex(key) if len(key) == 64 else key.encode()
    return hmac.new(sk, json.dumps(data, separators=(",", ":"), default=str).encode(),
                    hashlib.sha256).hexdigest()


def _ecc(**over):
    base = {"mode": "subagent", "subagent_id": "sub-x", "nonce": "n0nce",
            "timestamp": "2026-11-05T00:00:00Z", "task": "t", "conclusion": "c",
            "evidence": [], "findings": {"worked": [], "failed": [], "not_tried": []},
            "next_steps": [], "confidence": "medium", "tools_used": [],
            "guardrail": "passed", "turns": 1, "total_items": 0, "total_tokens": 0,
            "budget_status": "ok", "kept": [], "challenges": [], "slashed": [],
            "assertions": [], "tool_call_count": 0}
    base.update(over)
    return base


def _run(mode, stdin, env_extra=None, drop=()):
    env = {k: v for k, v in os.environ.items() if k not in drop}
    env["SUBAGENT_ID"] = "sub-x"
    if "GATEKEEPER_HMAC_KEY" not in drop:
        env["GATEKEEPER_HMAC_KEY"] = KEY
    env.update(env_extra or {})
    r = subprocess.run([sys.executable, str(MOD), mode], input=stdin,
                       capture_output=True, text=True, env=env, timeout=60)
    return r.returncode, r.stdout


def test_validate_accepts_envelope(_needs_pydantic):
    assert _run("validate", json.dumps(_ecc())) == (0, "VALID\n")


def test_validate_rejects_bad_envelope_without_stdout(_needs_pydantic):
    """不合法 ⟹ **无 stdout**（bash 侧 `rg -q VALID` 必须判否）+ 非零退出。"""
    missing = _ecc()
    missing.pop("nonce")
    assert _run("validate", json.dumps(missing)) == (1, "")
    assert _run("validate", json.dumps(_ecc(turns="one"))) == (1, "")
    assert _run("validate", '{"mode": ') == (1, "")
    assert _run("validate", "") == (1, "")


def test_hmac_three_states(_needs_pydantic):
    good = _ecc()
    good["hmac"] = _sign(good)
    assert _run("hmac", json.dumps(good)) == (0, "valid\n")
    assert _run("hmac", json.dumps(_ecc())) == (0, "no_hmac\n")
    bad = _ecc(hmac="deadbeef")
    assert _run("hmac", json.dumps(bad)) == (0, "invalid\n")


def test_hmac_error_is_silent_nonzero(_needs_pydantic):
    """异常路径与内联实现一致：无 stdout + 非零（bash 侧 `|| echo skip` 兜底）。"""
    good = _ecc()
    good["hmac"] = _sign(good)
    assert _run("hmac", json.dumps(good), drop=("GATEKEEPER_HMAC_KEY",)) == (1, "")
    assert _run("hmac", "not-json") == (1, "")


def test_cli_wiring_is_file_call_not_inline():
    """结构面：CLI 不再内联 schema（单源约束），且两处调用都指向模块。"""
    cli = CLI.read_text(encoding="utf-8")
    assert "class O(BaseModel)" not in cli, "CLI 仍内联 pydantic 信封（双份 schema 漂移面）"
    assert cli.count("gk_monitor_envelope.py") == 2, (
        "validate / hmac 两处接线数不符（实得 %d）" % cli.count("gk_monitor_envelope.py"))
    assert 'gk_monitor_envelope.py" validate' in cli
    assert 'gk_monitor_envelope.py" hmac' in cli
