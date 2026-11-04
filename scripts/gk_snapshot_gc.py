#!/usr/bin/env python3
"""gk_snapshot_gc.py — 本地公开快照回收（保留最近 N 份 + 年龄阈值）。

背景
====
发布链会在本地产出 `zthl-public-snapshot-<日期>-v<N>` 之类的整树快照（约 30 MB/份）。
它们只是发布中间态，GitHub Release 才是权威；长期堆积会占满磁盘。

策略（保守）
------------
- 只处理 `--root` 下名字以 `--prefix` 开头的**目录**；
- 永远保留**按 mtime 最新的 `--keep` 份**；
- 其余仅在 mtime 早于 `--min-age-days` 天才删除；
- **默认 dry-run**，只有显式 `--apply` 才真正删除。

用法：
  python3 scripts/gk_snapshot_gc.py                 # 预览
  python3 scripts/gk_snapshot_gc.py --apply         # 执行
  python3 scripts/gk_snapshot_gc.py --root D:\\snap --keep 3 --min-age-days 14 --apply
退出码：0 = 正常（含无可删）；2 = 参数/根目录错误。
"""
import argparse
import json
import shutil
import sys
import time
from pathlib import Path


def scan(root: Path, prefix: str) -> list:
    return sorted((p for p in root.iterdir()
                   if p.is_dir() and p.name.startswith(prefix)),
                  key=lambda p: p.stat().st_mtime, reverse=True)


def plan(root: Path, prefix: str, keep: int, min_age_days: float, now: float = None) -> list:
    now = time.time() if now is None else now
    items = scan(root, prefix)
    out = []
    for i, p in enumerate(items):
        age = (now - p.stat().st_mtime) / 86400.0
        if i < keep:
            out.append({"path": str(p), "action": "keep", "reason": "newest:%d" % keep,
                        "age_days": round(age, 2)})
        elif age < min_age_days:
            out.append({"path": str(p), "action": "keep",
                        "reason": "age<%.1fd" % min_age_days, "age_days": round(age, 2)})
        else:
            out.append({"path": str(p), "action": "delete", "reason": "stale",
                        "age_days": round(age, 2)})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_snapshot_gc.py")
    ap.add_argument("--root", default=str(Path.home()))
    ap.add_argument("--prefix", default="zthl-public-snapshot-")
    ap.add_argument("--keep", type=int, default=2)
    ap.add_argument("--min-age-days", type=float, default=7.0)
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args(argv)
    root = Path(a.root)
    if not root.is_dir():
        print(json.dumps({"ok": False, "error": "root 不存在：%s" % root}, ensure_ascii=False))
        return 2
    if a.keep < 1:
        print(json.dumps({"ok": False, "error": "--keep 必须 >= 1"}, ensure_ascii=False))
        return 2
    rows = plan(root, a.prefix, a.keep, a.min_age_days)
    removed = []
    if a.apply:
        for r in rows:
            if r["action"] == "delete":
                shutil.rmtree(r["path"])
                removed.append(r["path"])
    print(json.dumps({"ok": True, "apply": bool(a.apply), "root": str(root),
                      "items": rows, "removed": removed}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
