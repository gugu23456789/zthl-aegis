#!/usr/bin/env python3
"""oss_export_surface.py — 公开导出面**判定**（单一事实源 = `references/oss-export-whitelist.json`）。

为什么单独成模块（2026-11-09）：
  `oss_scrub.py` 本身**不随公开包导出**（其反查词表即指纹），但 `gk_audit_docs` / `gk_doc_align`
  的「发布门（`--release`）」必须在**公开树内**回答「某文档/脚本缺席是预期还是漂移」。
  旧实现 `import oss_scrub` 在公开树必然失败 ⟹ 排除面判定静默退化为「全部必须存在」⟹
  公开树 doc 门恒红（夜间 bench-nightly `gk_bench_release` 即因此失败）。
  白名单 JSON **是**随包导出的（供第三方审计），故此处直接消费它，不依赖私有脚本是否在。

用法::

    from oss_export_surface import is_excluded
    is_excluded("references/security-measures.md", "/path/to/skill")   # → True
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

_CACHE = {}


def _load(skill_dir: str):
    """→ (names, prefixes, suffixes, globs)；任何读取失败 ⟹ 空排除面（fail-open，不误伤）。

    白名单查找顺序：① 目标树 `references/oss-export-whitelist.json`（公开树/私仓皆带）；
    ② 回落**本模块所在仓**的同名文件 —— 供 tmp 沙箱/被复制的最小夹具使用（与旧
    `oss_scrub.is_excluded` 的全局语义对齐，避免「夹具目录无白名单 ⟹ 全部判为未排除」）。
    """
    key = os.path.abspath(str(skill_dir or "."))
    hit = _CACHE.get(key)
    if hit is not None:
        return hit
    names, prefixes, suffixes, globs = set(), [], [], []
    cands = [Path(key) / "references" / "oss-export-whitelist.json",
             Path(__file__).resolve().parent.parent / "references" / "oss-export-whitelist.json"]
    for wl in cands:
        try:
            d = json.loads(wl.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 — 该候选不可用 ⟹ 试下一个
            continue
        names = {e.get("pattern") for e in d.get("exclude_names", []) if e.get("pattern")}
        prefixes = [e["pattern"] for e in d.get("exclude_prefixes", []) if e.get("pattern")]
        suffixes = [e["pattern"] for e in d.get("exclude_suffixes", []) if e.get("pattern")]
        globs = [re.compile(e["pattern"]) for e in d.get("exclude_globs", []) if e.get("pattern")]
        break
    out = (names, prefixes, suffixes, globs)
    _CACHE[key] = out
    return out


def is_excluded(rel: str, skill_dir: str = ".") -> bool:
    """`rel`（仓根相对路径）是否属公开导出**排除面**（导出树里缺席是预期）。"""
    s = str(rel or "").replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    s = s.lstrip("/")
    names, prefixes, suffixes, globs = _load(skill_dir)
    if s in names:
        return True
    if any(s.startswith(p) for p in prefixes):
        return True
    if any(s.endswith(x) for x in suffixes):
        return True
    return any(rx.search(s) for rx in globs)


__all__ = ["is_excluded"]
