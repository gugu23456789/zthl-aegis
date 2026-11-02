#!/usr/bin/env python3
"""gk_path.py — 路径归一工具（B9f，2026-10-28，锚 RED-MIGRATE-INLINE）

替代两处内联 `python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))"`：
  · cmd_guard_edit 的 `_gov_rp`（治理仓主树动态臂）
  · cmd_guard_edit 的 `real_path`（受保护路径归一）

Usage:
  python3 gk_path.py realpath <path>     # 输出 os.path.realpath(path)（路径无需存在）

Exit: 0 = 正常；2 = usage error。
"""
import os
import sys


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] != "realpath":
        print("usage: gk_path.py realpath <path>", file=sys.stderr)
        return 2
    print(os.path.realpath(args[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
