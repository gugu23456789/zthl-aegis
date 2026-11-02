#!/usr/bin/env python3
"""红先臂：DS 欠费（HTTP 402 / Insufficient Balance）须触发 failover 降级到 MiMo（`ECC-5E433392C5C7`）。

病象（2026-10-10）：降级链 `GK_FAILOVER_CHAIN=deepseek,mimo,local` 已存在，但两处 `_is_retryable`
都不认 402 ⟹ DS 余额耗尽时**不换腿**：
  · bash `gatekeeper-cli.sh::_is_retryable` 正则只含 5xx/网络类 ⟹ `_monitor_api` 在 402 上
    `break`（不换 provider）⟹ 直接 "all providers failed"；
  · python `gk_monitor_api._is_retryable` = `status>=500 or ==0` ⟹ 402 非可重试 ⟹ `stop_chain`。

判据面 = **已跟踪** `scripts/gk_monitor_api.py` + `gatekeeper-cli.sh`（禁第二事实源）。
red-first 沙箱按 `git archive HEAD` 取**未修**版 ⟹ 本文件对 HEAD 必红（arm_b1 / arm_bash）。
`test_guard_400_not_retryable` 为**非红**回归守卫（HEAD 即绿），不入选红先集。
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_monitor_api as m  # noqa: E402

_CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def test_arm_b1_python_402_is_retryable():
    """臂 b1（主判据·python 面）：`_is_retryable(402)` 须为 True（HEAD：False ⟹ stop_chain 不降级）。"""
    assert m._is_retryable(402) is True, \
        "402 Payment Required 须可重试（否则 DS 欠费时 python 面停链，降不到 MiMo）"


def test_arm_bash_cli_402_is_retryable():
    """臂 bash（CLI 面）：`_is_retryable` 匹配式须含余额语义词（HEAD：无 ⟹ monitor --api 不换腿）。"""
    src = _CLI.read_text(encoding="utf-8")
    mre = re.search(r"_is_retryable\(\)\s*\{(.*?)\n\}", src, re.S)
    assert mre, "未找到 bash _is_retryable 函数体"
    assert "insufficient.balance" in mre.group(1), \
        "bash _is_retryable 须纳入 Insufficient Balance（DS 欠费）⟹ monitor --api 才能降级到 MiMo"


def test_guard_400_not_retryable():
    """守卫臂（**非红**：HEAD 即绿，不入选红先集）：语义类 400 / 鉴权 401 仍不可重试（防过度放宽）。"""
    assert m._is_retryable(400) is False
    assert m._is_retryable(401) is False
