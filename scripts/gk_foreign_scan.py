#!/usr/bin/env python3
"""gk_foreign_scan.py — file→stdout 的**薄 CLI wrapper**（P2c，2026-10-31）。

原实现是第 3 份独立副本（自有正则 + 自有词表），现只做 I/O 适配：
判定与词表全部来自单一事实源 `scripts/gk_foreign_content.py`。

用法: python3 gk_foreign_scan.py <file> [own_user]
输出: clean | foreign_user:<name> | leakage_marker:<name> | traversal:<seg> | UNRESOLVED_OWN_USER
      （退出码恒 0；调用方按字符串判断，非 clean 即阻断）

`own_user` 可省略；省略或为通用名（`root`/`user`/…）时由单源模块自行解析
（这正是 CLI 传 `"${USER:-HP}"` 在 WSL 下恒 `root` 的修复点）。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from gk_foreign_content import check_file  # noqa: E402


def main(argv: list[str]) -> int:
    if not argv:
        print("clean")
        return 0
    own = argv[1] if len(argv) > 1 else ""
    hit = check_file(argv[0], own=own or None)
    print(hit or "clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
