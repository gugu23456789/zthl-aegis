#!/usr/bin/env python3
"""gk_num.py — 数值运算/阈值判定工具（batch8 批次 2 剩余，2026-08-26）。

替代 bash 内联浮点运算（bash 不支持浮点，原实现为 python3 -c 内联）：

  gk_num ratio <num> <denom>   # round(num/denom, 2)，denom=0/非法 → 0.0（L2295 语义）
  gk_num norm <value>          # round(s/100, 2) if s>1 else round(s, 2)（百分比归一化，L2287 语义）
  gk_num round <value>         # round(value, 2)
  gk_num gt <a> <b>            # exit 0 if a>b else 1（verdict 布尔判定，配合 || 降级）

输出: ratio/norm/round 打印数值；gt 走退出码（无输出）。
非数值输入按 0.0 处理（对齐原内联 float() 的隐式容错方向）。
"""
import sys


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else ""
    if cmd == "ratio":
        n = _num(argv[1]) if len(argv) > 1 else 0.0
        d = _num(argv[2]) if len(argv) > 2 else 0.0
        print(round(n / d, 2) if d else 0.0)
        return 0
    if cmd == "norm":
        s = _num(argv[1]) if len(argv) > 1 else 0.0
        print(round(s / 100, 2) if s > 1 else round(s, 2))
        return 0
    if cmd == "round":
        print(round(_num(argv[1]) if len(argv) > 1 else 0.0, 2))
        return 0
    if cmd == "gt":
        a = _num(argv[1]) if len(argv) > 1 else 0.0
        b = _num(argv[2]) if len(argv) > 2 else 0.0
        return 0 if a > b else 1
    print('{"error":"usage: gk_num ratio|norm|round|gt <args>"}')
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
