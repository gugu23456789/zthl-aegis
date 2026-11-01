#!/usr/bin/env python3
"""build_w2a_web_evidence.py — 用受治 Fetch 构造 GK_WEB_EVIDENCE 证据集（2026-10-18）。

用途：W2A 金字塔 L1/L2/L3 的“证据共享拓扑”实验。主 agent 预取一组 URL，落成
`gk_evidence` 契约的 JSON 数组，再由
`gatekeeper-cli.sh plan-refinement --evidence-sharing Lx --web-evidence <file>` 注入到每个臂。

零新增出网口：逐 URL 调 `gk_web_tools.fetch()`（DeepSeek Fetch 受治车道，egress 留痕）。

用法:
  python3 scripts/build_w2a_web_evidence.py \
      --urls "https://a,https://b" --out /tmp/evidence.json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_evidence as ge  # noqa: E402
import gk_web_tools as wt  # noqa: E402


def build(urls):
    recs, failed = [], []
    for u in urls:
        raw = wt.fetch(u)
        try:
            obj = json.loads(raw.split("\n", 1)[1])
        except Exception as e:  # noqa: BLE001 — 工具边界
            failed.append({"url": u, "error": "envelope: %s" % e})
            continue
        if not obj.get("ok") or not isinstance(obj.get("evidence"), dict):
            failed.append({"url": u, "error": obj.get("error", "no evidence")})
            continue
        recs.append(obj["evidence"])
    return recs, failed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--urls", required=True, help="逗号分隔")
    ap.add_argument("--out", required=True, help="输出 JSON 数组路径")
    args = ap.parse_args()
    urls = [x.strip() for x in args.urls.split(",") if x.strip()]
    if not urls:
        print(json.dumps({"ok": False, "error": "no urls"}, ensure_ascii=False))
        return 2
    recs, failed = build(urls)
    if not recs:
        print(json.dumps({"ok": False, "error": "all fetches failed", "failed": failed},
                         ensure_ascii=False))
        return 2
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(ge.dumps(recs))
    print(json.dumps({"ok": True, "n": len(recs), "out": args.out, "failed": failed},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
