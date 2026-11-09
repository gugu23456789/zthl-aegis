#!/usr/bin/env python3
"""gk_accept_factor.py — accept 的**子进程因子 f 自动分档**（408 三档口径）。

口径（与 `gk_hub_scheduler.adaptive_workers(subprocess_factor=)` 同一含义）：
  f = 该批**每用例峰值外部子进程数**。按文件取证再聚合：

  单文件：density = 外部子进程调用点 / 用例数
    · density == 0                     → f=0（纯 python）
    · 0 < density ≤ 1                  → f=1（每例约 1 次 bash）
    · density > 1 或命中 wsl/openssl   → f=3（WSL+openssl 重活档）

  整批（本文件的目的）：
    · 全部文件 density==0              → 0（走旧口径 nproc×2）
    · 重活文件（f=3）占比 ≥ 50%        → 3
    · 其余                             → 1（混跑按 1；实测混跑 plateau 与 f=1 的 8 并发一致）

为什么**不**取「最重的那个文件」当整批 f：全量里重活只占少数文件，按 3 会把 5700+ 轻用例
  也压到 2 并发（实测全量 n=8 211s vs n=2 会翻倍），收益全丢。为什么又是 50% 而不是按用例加权：
  加权需要逐用例计数，成本高且对「一个文件里混重活」不敏感；50% 是文件面最小可用判据。

退出码：0 且 stdout 只含一个整数 0/1/3；扫描失败 ⤳ 打印 1（缺省混合口径，fail-safe）。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

#: 外部子进程调用点（与 408 报告同族；`bash.exe`/`wsl`/`openssl` 单列以命中重活档）
_CALL = re.compile(r"subprocess\.|Popen\(|bash\.exe|\bwsl\b|openssl")
_HEAVY = re.compile(r"bash\.exe|\bwsl\b|openssl")
_TEST = re.compile(r"(?m)^def test_")
_TEST_MARK = re.compile(r"(?m)^\s*def test_")


def classify_text(text: str) -> int:
    """单文件 → 0 / 1 / 3。"""
    tests = len(_TEST.findall(text)) or len(_TEST_MARK.findall(text))
    if tests == 0:
        return 0
    calls = len(_CALL.findall(text))
    if calls == 0:
        return 0
    if _HEAVY.search(text):
        return 3
    return 3 if (calls / float(tests)) > 1.0 else 1


def classify_files(paths) -> int:
    """整批 → 0 / 1 / 3（见模块 docstring 的聚合口径）。"""
    per = []
    for p in paths:
        try:
            per.append(classify_text(Path(p).read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    if not per:
        return 1
    if all(f == 0 for f in per):
        return 0
    heavy = sum(1 for f in per if f == 3)
    return 3 if heavy * 2 >= len(per) else 1


def _default_paths() -> list:
    here = Path(__file__).resolve().parent
    return sorted(str(p) for p in here.glob("test_*.py"))


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    paths = [a for a in args if not a.startswith("-")]
    if not paths:
        paths = _default_paths()
    try:
        print(classify_files(paths))
    except Exception:  # noqa: BLE001 — 边界：扫描失败 ⟹ 混合缺省（不阻断 accept）
        print(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
