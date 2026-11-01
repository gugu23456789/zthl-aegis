#!/usr/bin/env python3
"""gk_amp_query.py — AMP 查询面（`zthl-harness-adapter` 计划 §2.7 ⑧「amp-query」）
========================================================================================

读面只消费 `~/.zthl/amp/*.log`（AMP 落盘记录），**不新建事实源**。

用法：
    python3 scripts/gk_amp_query.py --type access --since 1h --limit 20
    python3 scripts/gk_amp_query.py --type audit --field correlationId=ECC-xxx
    python3 scripts/gk_amp_query.py --type system --since 2026-10-26 --json

命名：`amp-query`（非 `monitor`）—— `monitor` 词已被 LLM 语义审查器占用（计划记）。

⚠ 本脚本是 **ZH3 `amp-query` CLI 的候选载体**：暂不注册进 `gatekeeper-cli.sh`
（计划 §0.3 H3-D3「查询面 = 权威面」+ 并发会话禁争写 CLI 的纪律），注册留待 ZH3。
"""
import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(_ROOT), str(_ROOT / "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from zthl.acp import amp  # noqa: E402


def _parse_field(s: str):
    if "=" not in s:
        raise argparse.ArgumentTypeError(f"--field 需要 k=v 形式：{s!r}")
    k, v = s.split("=", 1)
    return k.strip(), v


def main(argv=None):
    ap = argparse.ArgumentParser(description="AMP 查询（读 ~/.zthl/amp/*.log）")
    ap.add_argument("--type", default=None, help="六类之一；缺省 = 全部")
    ap.add_argument("--since", default=None, help="30m / 7d / ISO 8601；缺省 = 不限")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--field", action="append", default=[], type=_parse_field,
                    help="点号路径过滤，如 --field attributes.zthl.decision=block")
    ap.add_argument("--dir", default=None, help="覆盖 AMP 目录（默认 ~/.zthl/amp）")
    ap.add_argument("--json", action="store_true", help="输出 JSON 数组（缺省逐行摘要）")
    args = ap.parse_args(argv)

    try:
        recs = amp.query(args.type, since=args.since, limit=args.limit,
                         where=dict(args.field) if args.field else None,
                         root=Path(args.dir) if args.dir else None)
    except ValueError as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
        return 2

    if args.json:
        print(json.dumps(recs, ensure_ascii=False, indent=2))
        return 0
    for r in recs:
        body = r.get("body") or {}
        attrs = r.get("attributes") or {}
        print(f"{r.get('timestamp', '')}  {r.get('logType', ''):9s} "
              f"{r.get('severityText', ''):5s}  {json.dumps(body, ensure_ascii=False)[:160]}")
        if attrs:
            print(f"{'':26s}attrs={json.dumps(attrs, ensure_ascii=False)[:160]}")
    print(f"--- {len(recs)} record(s) @ {args.dir or amp.amp_dir()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
