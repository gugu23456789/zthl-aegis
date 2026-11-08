#!/usr/bin/env python3
"""批 → state 自动解析（跨进程 plan 指针是会话级的，新会话会回落 base）。

背景：`discover --plan` 只写 `.gatekeeper.plan.<session>`；新进程没有 `GK_SESSION_ID`
⟹ CLI 的 `STATE_FILE` 回落 `.gatekeeper.state`（base），而派发的臂写在域 state。
本模块只做一件事：给定 `--batch`，若当前 state 不含该批，则扫 `.gatekeeper.plan.*`
指向的 state，唯一命中则输出该 state 路径；0 或多命中输出空（不武断）。

实现单源：批存在性判据 = `gate_data.satellite_index` 的 key 或
`gate_data.subagent_history[].batch_id`，与 `gk_satellite` 的索引形态一致。
"""
import argparse
import glob
import json
import os
import sys


def has_batch(path: str, batch: str) -> bool:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return False
    gd = data.get("gate_data") or {}
    si = gd.get("satellite_index") or {}
    if isinstance(si, dict) and batch in si:
        return True
    for h in (gd.get("subagent_history") or []):
        if isinstance(h, dict) and str(h.get("batch_id") or "") == batch:
            return True
    return False


def resolve(skill_dir: str, current: str, batch: str) -> str:
    if not batch or not current or has_batch(current, batch):
        return ""
    hits = set()
    for ptr_file in glob.glob(os.path.join(skill_dir, ".gatekeeper.plan.*")):
        try:
            with open(ptr_file, encoding="utf-8") as fh:
                ptr = json.load(fh)
        except Exception:
            continue
        st = ptr.get("state_file") or ""
        if not st or not os.path.isfile(st):
            continue
        if os.path.realpath(st) == os.path.realpath(current):
            continue
        if has_batch(st, batch):
            hits.add(st)
    return sorted(hits)[0] if len(hits) == 1 else ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skill-dir", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--batch", required=True)
    a = ap.parse_args(argv)
    out = resolve(a.skill_dir, a.state, a.batch)
    if out:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
