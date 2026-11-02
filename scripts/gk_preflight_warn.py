#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gk_preflight_warn.py — plan-refinement 入队前**软告警**（WARN，不阻断）判定核心。

背景（2026-09-14 用户定案「按建议把 balance 接入 preflight 作为 WARN 不阻断项」）：
  `cmd_plan_refinement` 的 preflight 段原先只查 计划文档 / META / 源文档 / 点检，
  **不查密钥与余额** ⟹ 密钥缺失或余额耗尽要等 subagent 派发后才失败（白付一次入队 + 审计留痕）。
  本脚本把该判定**前移为软告警**：只产出 `preflight.warnings[]`。

**为什么必须"不阻断"**（fail-soft）：余额查询依赖网络与密钥；若因"查不到余额"而阻断入队，
序列会被**外部依赖**锁死 —— 对齐本仓「评估器异常不阻断」「禁用不可用依赖锁死序列」纪律。

I/O 契约（对齐 N7 流契约）：stdout = `["warn1","warn2"]`（JSON 数组）；stderr = 诊断；**退出码恒 0**。

告警码
  `api_key_missing`      密钥为空 ⟹ 派发后 subagent 必失败（前移提示；0 成本，**始终判定**）
  `balance_unavailable`  余额查询失败（网络 / endpoint / 解析）⟹ 不阻断，仅提示
  `balance_low:<v>`      余额 `<` `GK_BALANCE_MIN_CNY` ⟹ 提示（默认阈值取 1 轮质询实测成本下界）

用法
  python3 scripts/gk_preflight_warn.py --key-present 1 --balance-enabled 1 --balance 12.34 --min-cny 2.0
"""
import argparse
import json
import sys

DEFAULT_MIN_CNY = 2.0  # 2026-09-14 实测：整轮质询 ≈ 2.96 元 ⟹ 取下界作粗阈值（env GK_BALANCE_MIN_CNY 可覆盖）


def build_warnings(key_present, balance_enabled, balance, min_cny):
    """纯函数（可确定性单测）：输入探针结果 → 告警码列表。

    `balance=None` 表示**探测已启用但未取到**（网络/解析失败）；探测**未启用**（开关关闭 /
    provider 无 endpoint）时调用方应传 `balance_enabled=False`，此时**不产生**余额类告警。
    """
    warnings = []
    if not key_present:
        warnings.append("api_key_missing")  # 密钥问题优先级最高（后面一切探测都无意义）
        return warnings
    if not balance_enabled:
        return warnings
    if balance is None:
        warnings.append("balance_unavailable")
        return warnings
    if balance < min_cny:
        warnings.append("balance_low:%g" % balance)
    return warnings


def _parse_balance(raw):
    """'' / None / 非数值 ⟹ None（未取到）；否则 float。"""
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description="plan-refinement preflight 软告警（WARN，不阻断）")
    ap.add_argument("--key-present", type=int, default=1, choices=(0, 1))
    ap.add_argument("--balance-enabled", type=int, default=0, choices=(0, 1))
    ap.add_argument("--balance", default="")
    ap.add_argument("--min-cny", type=float, default=DEFAULT_MIN_CNY)
    a = ap.parse_args(argv)

    warnings = build_warnings(
        key_present=bool(a.key_present),
        balance_enabled=bool(a.balance_enabled),
        balance=_parse_balance(a.balance),
        min_cny=a.min_cny,
    )
    print(json.dumps(warnings, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
