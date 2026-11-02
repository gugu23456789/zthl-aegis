#!/usr/bin/env python3
"""薄别名 `opcap_evidence.py` → `gk_opcap_export.py`（2026-11-02）。

存在理由：`opcap_evidence.py` 是既有脚本使用的入口名，而本仓的实现名是
`scripts/gk_opcap_export.py`。本文件只做**入口名兼容**，判据/口径/输出全部由
`gk_opcap_export` 单源提供。

纪律：**零第二实现** —— 本文件不定义任何 `export()` / 解析逻辑；任何语义改动只改
`gk_opcap_export.py`。`test_opcap_evidence_alias.py` 钉住这一点（输出逐字相等）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_opcap_export  # noqa: E402


def main(argv=None) -> int:
    return gk_opcap_export.main(argv)


if __name__ == "__main__":
    sys.exit(main())
