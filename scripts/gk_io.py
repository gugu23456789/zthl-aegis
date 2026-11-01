#!/usr/bin/env python3
"""gk_io.py — 通用文件 I/O 原语（B10a，2026-10-28，锚 RED-MIGRATE-INLINE）

  write-text <path>    stdin 原文写入（UTF-8，**不追加换行**）

取代内联 `python3 -c "import sys;open(path,'w',encoding='utf-8').write(sys.argv[1])"`：
正文走 stdin 而非 argv（避开 E2BIG 与引号折叠）。写失败 ⟹ rc=1，调用方
`|| { … }` 兜底仍生效。
"""
import sys


def cmd_write_text(args) -> int:
    path = args[0] if args else ""
    data = sys.stdin.read()
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
    except OSError:
        return 1
    return 0


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] != "write-text":
        print("usage: gk_io.py write-text <path>", file=sys.stderr)
        return 2
    return cmd_write_text(args[1:])


if __name__ == "__main__":
    sys.exit(main())
