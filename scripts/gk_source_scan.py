#!/usr/bin/env python3
"""gk_source_scan.py — 源码结构扫描（B9a，2026-10-27，锚 RED-MIGRATE-INLINE）

  · protected-regions <file>
      PROTECTED_REGION_START/END 区间表（`start:end:name`，按 END 出现顺序）。
      ← `_protected_region_check` 的内联解析（原 gatekeeper-cli.sh L3874）。
  · large-inline-blocks <file> [--min-lines 40]
      「跨行 python3 -c 块且行数 > N」计数（维护风险信号）。
      ← `cmd_self_check` dead_code_gate3 的内联扫描（原 L5252）。

纯只读：无 state / 无网络 / 无副作用。语义逐字对齐旧内联（含其边界怪癖）。
"""
import argparse
import re
import sys


def protected_regions(path: str) -> int:
    with open(path) as f:
        content = f.read()
    lines = content.split("\n")
    ranges = []
    for i, ln in enumerate(lines):
        m = re.match(r"^# PROTECTED_REGION_(START|END)::(\w+)", ln.strip())
        if m:
            ranges.append((m.group(1), m.group(2), i + 1))
    result = []
    stack = {}
    for action, name, lno in ranges:
        if action == "START":
            stack[name] = lno
        elif action == "END" and name in stack:
            result.append((stack[name], lno, name))
            del stack[name]
    for start, end, name in result:
        print(f"{start}:{end}:{name}")
    return 0


def large_inline_blocks(path: str, min_lines: int) -> int:
    with open(path) as f:
        lines = f.readlines()
    count = 0
    in_block = False
    q = ""
    start = 0
    for i, line in enumerate(lines):
        s = line.rstrip()
        if not in_block:
            m = re.search(r"python3\s+-c\s+['\"]", s)
            if m:
                q = m.group()[-1]
                after = s[m.end():]
                if after.count(q) < 2:
                    in_block = True
                    start = i
        else:
            # 旧式收尾判据（逐字保留其怪癖：q + '"' 而非重复 q）
            if q + '"' in s and ("2>/dev/null" in s or "2>&1" in s):
                if i - start + 1 > min_lines:
                    count += 1
                in_block = False
    print(count)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="gk_source_scan.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("protected-regions")
    r.add_argument("file")

    b = sub.add_parser("large-inline-blocks")
    b.add_argument("file")
    b.add_argument("--min-lines", type=int, default=40)

    ns = p.parse_args(argv)
    if ns.cmd == "protected-regions":
        return protected_regions(ns.file)
    if ns.cmd == "large-inline-blocks":
        return large_inline_blocks(ns.file, ns.min_lines)
    return 2


if __name__ == "__main__":
    sys.exit(main())
