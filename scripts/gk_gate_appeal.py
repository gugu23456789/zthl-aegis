#!/usr/bin/env python3
"""Gate: Appeal gate check — **多源阻断登记单源**（X1，2026-10-31）。

历史问题（standard §12.6 X1/X2/X3、audit-bureau §28.4.X1）：`gate_data.appeal_required`
是**单值字符串**，且被三处各自实现地读（`gk_advance._check_appeal`、`gatekeeper-cli.sh` G-17、
`gk_escalate_resolve.resolve` G-17）。任何第二阻断源（额度银行/审计侧）写入都会：
  1. 与熵门**互相覆盖**（后写覆盖前写，前一个 gate 的 `appeal_records` 立即失联）；
  2. 让 `--force` 清场无法区分来源；
  3. 让 bash G-17 看不到新源（fail-open）。

本模块把「读 / 写 / 清」收成**单一实现**：

- 规范载体：`gate_data.appeal_blocks = {<source>: {"gate": ..., "since": ..., ...}}`
  多源并存；同一 source 再次阻断按 gate 覆盖（幂等）。
- 兼容载体：`gate_data.appeal_required`（旧 scalar）继续被**读**，来源记为 `entropy`；
  `entropy` 源写入时仍镜像该字段（连同 `appeal_entropy_at_block`），历史 state / 旧脚本零回归。
- 聚合：任一源 `blocked` / `denied` / `dangling` 即整体非 clear；`resolved` 的源不阻断。
  多条同severity 时按 (source, gate) 排序取首条，保证输出确定。

Usage:
  python3 gk_gate_appeal.py <state_file>
      -> clear | blocked:<gate> | resolved | denied:<gate> | dangling:<gate>
  python3 gk_gate_appeal.py --blocking <state_file>
      -> 逗号分隔的**阻断中** gate（空输出 = 无阻断），供 bash G-17 判空
"""
import json
import sys
from datetime import datetime, timezone

BLOCKS_KEY = "appeal_blocks"
LEGACY_KEY = "appeal_required"
LEGACY_RATE_KEY = "appeal_entropy_at_block"
PRIMARY_SOURCE = "entropy"   # 旧 scalar 的来源归属（唯一历史写入者 = 熵门）

# 严重度：denied 最高（须 escalate），resolved 不阻断。
_PRIORITY = {"denied": 3, "blocked": 2, "dangling": 1, "resolved": 0}


def _norm(source, rec):
    """单条 block 归一 → `(source, gate, record)`；坏形态返回 None。"""
    if isinstance(rec, str):
        return (str(source), rec, {"gate": rec})
    if isinstance(rec, dict):
        gate = rec.get("gate")
        if isinstance(gate, str) and gate:
            return (str(source), gate, rec)
    return None


def iter_blocks(gate_data: dict) -> list:
    """→ `[(source, gate, record)]`（按 source 排序，输出确定）。

    读优先级：`appeal_blocks`（dict 或 list 形态）> 旧 scalar `appeal_required`
    （记为 `entropy` 源，且仅在该源缺位时兜底 —— 规范载体更新，不被旧镜像覆盖）。
    """
    gd = gate_data or {}
    found = {}
    blocks = gd.get(BLOCKS_KEY)
    if isinstance(blocks, dict):
        for src, rec in blocks.items():
            item = _norm(src, rec)
            if item:
                found[item[0]] = item
    elif isinstance(blocks, list):
        for rec in blocks:
            src = rec.get("source", "unknown") if isinstance(rec, dict) else "unknown"
            item = _norm(src, rec)
            if item:
                found[item[0]] = item
    legacy = gd.get(LEGACY_KEY)
    if isinstance(legacy, dict):
        # 兼容「appeal_required 本身被写成 source→gate/record」的实验形态
        for src, val in legacy.items():
            item = _norm(src, val)
            if item:
                found.setdefault(item[0], item)
    elif isinstance(legacy, str) and legacy:
        found.setdefault(PRIMARY_SOURCE, (PRIMARY_SOURCE, legacy, {"gate": legacy}))
    return [found[k] for k in sorted(found)]


def block_status(d: dict, gate: str) -> str:
    """单个 gate 的申诉状态：`blocked` / `dangling` / `resolved` / `denied`。"""
    rec = (d.get("appeal_records") or {}).get(gate)
    if isinstance(rec, dict):
        verdict = rec.get("verdict", "")
        if verdict == "APPROVED":
            return "resolved"
        if verdict == "DENIED":
            return "denied"
        return "dangling"
    return "blocked"


def evaluate(d: dict) -> list:
    """全部 block 的状态明细（供报告/审计对账）。"""
    return [{"source": src, "gate": gate, "status": block_status(d, gate), "record": rec}
            for src, gate, rec in iter_blocks(d.get("gate_data", {}))]


def check_appeal_dict(d: dict) -> str:
    """聚合状态（对 `gk_advance._check_appeal` 的契约：`clear|blocked:X|resolved|denied:X|dangling:X`）。"""
    items = evaluate(d)
    if not items:
        return "clear"
    worst = max(items, key=lambda i: (_PRIORITY[i["status"]], i["source"], i["gate"]))
    if worst["status"] == "resolved":
        return "resolved"
    return f"{worst['status']}:{worst['gate']}"


def blocking_gates(d: dict) -> list:
    """阻断中的 gate 名（去重排序；`resolved` 不计）。G-17 判空用。"""
    return sorted({i["gate"] for i in evaluate(d) if i["status"] != "resolved"})


def add_block(gate_data: dict, source: str, gate: str, **extra) -> dict:
    """登记一个阻断源；`entropy` 源同步镜像旧 scalar（零回归）。返回落盘 record。"""
    gd = gate_data if gate_data is not None else {}
    blocks = gd.get(BLOCKS_KEY)
    if not isinstance(blocks, dict):
        blocks = {}
    rec = dict(extra)
    rec["gate"] = gate
    rec.setdefault("since", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    blocks[str(source)] = rec
    gd[BLOCKS_KEY] = blocks
    if str(source) == PRIMARY_SOURCE:
        gd[LEGACY_KEY] = gate
        if "entropy_rate" in rec:
            gd[LEGACY_RATE_KEY] = rec["entropy_rate"]
    return rec


def clear_blocks(gate_data: dict, gate: str = None, source: str = None) -> list:
    """清除 block：`gate`/`source` 均为 None = **全清**（人类 `--force` 终裁）。

    → 被清除的 `[(source, gate)]`。同时维护旧 scalar 镜像与 `appeal_entropy_at_block`。
    """
    gd = gate_data if gate_data is not None else {}
    targets = [(s, g) for s, g, _r in iter_blocks(gd)
               if (source is None or s == source) and (gate is None or g == gate)]
    if not targets:
        return []
    blocks = gd.get(BLOCKS_KEY)
    if isinstance(blocks, dict):
        for s, _g in targets:
            blocks.pop(s, None)
        if blocks:
            gd[BLOCKS_KEY] = blocks
        else:
            gd.pop(BLOCKS_KEY, None)
    elif isinstance(blocks, list):
        keep = []
        for rec in blocks:
            src = rec.get("source", "unknown") if isinstance(rec, dict) else "unknown"
            item = _norm(src, rec)
            if item is None or (item[0], item[1]) not in targets:
                keep.append(rec)
        if keep:
            gd[BLOCKS_KEY] = keep
        else:
            gd.pop(BLOCKS_KEY, None)
    legacy = gd.get(LEGACY_KEY)
    if isinstance(legacy, str):
        if (PRIMARY_SOURCE, legacy) in targets:
            gd.pop(LEGACY_KEY, None)
    elif isinstance(legacy, dict):
        for s, _g in targets:
            legacy.pop(s, None)
        if legacy:
            gd[LEGACY_KEY] = legacy
        else:
            gd.pop(LEGACY_KEY, None)
    if not gd.get(LEGACY_KEY):
        gd.pop(LEGACY_RATE_KEY, None)
    return targets


def check_appeal(state_file: str) -> str:
    """读 state 文件 → 聚合状态（旧 CLI 契约不变）。"""
    try:
        with open(state_file, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, json.JSONDecodeError):
        d = {}
    if not isinstance(d, dict):
        d = {}
    return check_appeal_dict(d)


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "--blocking":
        path = args[1] if len(args) > 1 else ""
        if not path:
            print("")
            return 2
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, json.JSONDecodeError):
            d = {}
        print(",".join(blocking_gates(d if isinstance(d, dict) else {})))
        return 0
    sf = args[0] if args else ""
    print(check_appeal(sf) if sf else "error")
    return 0


if __name__ == "__main__":
    sys.exit(main())
