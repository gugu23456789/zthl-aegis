#!/usr/bin/env python3
"""③ Phase A —— `edit_budget` 双通道**只读**观测（`REV-16` §22.3；正典 §21.3 修订 Y）。

**纯读**：只读 state（`gk_state._read_state`）+ 只读 CLI 源（取 `BILL_UNITS_DECL`）。**零写盘 /
零阻断 / 不夺锁 / 不入熵 / 不经 `_CMD_REG`**（§21.3「砍-list」明禁经 `_CMD_REG` 新子命令）⟹
本脚本**独立**于 CLI 分派表，只能被**显式**调用，不会被门禁路径误触。

观测面（三交付 + 一元数据）：
  · **分账 usage** —— 按通道分列已计费单位数。两通道**共享同一 `remaining`**
    （`BILL_UNITS_DECL counter=edit_budget.remaining`），由 `billed_files[]` 条目**形态**反推来源：
      `path1` = hook Gate4（保护区内）—— 记**触及文件的 realpath**（含 `/` 或 `\\`）；
      `path2` = 区外 `_bill_edit`（归化后）—— 记**身份哈希**（`sha256(实参向量)[:12]`，12-hex）。
  · **声明视图** —— `units_declared_equal`：取**声明锚** `path1 == path2` ⟹ `True`；不等 ⟹
    `False`；缺声明 ⟹ `None`。**`REV-24`（2026-10-23 owner 裁定「批次作计价单位」）后两通道
    维度主动分化（① `batches` / ② `files_dedup`）⟹ 本字段恒 `False` 是**预期**，不再是告警**。
    「实现是否等于声明」的漂移判据在 `scripts/test_gk_edit_budget_metering.py` 的 arm27/arm36
    由**源码反推**判定（本脚本不重复解析实现，免第二实现）。
  · **失配告警** —— `used + remaining != max`（账目不守恒）；另报
    `unaccounted = used - len(billed_files)`。⚠ `REV-24` 后 `used` 记**批次**、`billed_files` 记
    **文件** ⟹ 该差值**不再**是「漏记」判据（保留字段仅供历史对照；判据侧已无消费者）。
  · **λ（影子价格）= `UNKNOWN`** —— 内生影子价格不可识别（需外生扰动或行为边际数据，§21.3 修订 Y）。

用法：
  python3 scripts/gk_bill_observe.py [--state <path>] [--cli <path>] [--pretty]
  STATE_FILE=<path> python3 scripts/gk_bill_observe.py
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gk_state import _read_state, _resolve_default_state  # noqa: E402

_SKILL_ROOT = Path(__file__).resolve().parent.parent
_ID_HASH_RE = re.compile(r"^[0-9a-f]{12}$")
_DECL_RE = re.compile(r"(?m)^\s*#\s*BILL_UNITS_DECL\s+(.+)$")


def parse_units_decl(src: str) -> dict:
    """解析 CLI 头部那行 `BILL_UNITS_DECL k=v …`；缺行 ⟹ `{}`（= 无声明锚）。"""
    m = _DECL_RE.search(src or "")
    if not m:
        return {}
    out = {}
    for tok in m.group(1).split():
        if "=" in tok:
            k, _, v = tok.partition("=")
            out[k.strip()] = v.strip()
    return out


def units_declared_equal(decl: dict):
    """**声明视图**：`path1 == path2` ⟹ `True`；不等 ⟹ `False`；缺声明 ⟹ `None`。

    `REV-24` 后两通道维度主动分化（① `batches` / ② `files_dedup`）⟹ `False` 是**预期**；
    真正的漂移判据（实现 vs 声明）在 metering 的 arm27/arm36 由源码反推判定。
    """
    p1, p2 = (decl or {}).get("path1"), (decl or {}).get("path2")
    if not p1 or not p2:
        return None
    return p1 == p2


def classify_billed_file(entry: str) -> str:
    """`billed_files[]` 条目 → 通道：含路径分隔符 ⟹ `path1`；12-hex ⟹ `path2`；否则 `other`。"""
    s = str(entry or "")
    if "/" in s or "\\" in s:
        return "path1"
    if _ID_HASH_RE.match(s):
        return "path2"
    return "other"


def observe_box(box: dict) -> dict:
    """单个额度盒子（全局 `edit_budget` 或 `sessions.<sid>`）的只读快照。"""
    box = box or {}
    bf = box.get("billed_files") or []
    usage = {"path1": 0, "path2": 0, "other": 0}
    for e in bf:
        usage[classify_billed_file(e)] += 1
    mx, used, remaining = box.get("max"), box.get("used"), box.get("remaining")
    mismatch = None
    if isinstance(mx, int) and isinstance(used, int) and isinstance(remaining, int):
        mismatch = (used + remaining != mx)
    unaccounted = (used - len(bf)) if isinstance(used, int) else None
    return {"max": mx, "used": used, "remaining": remaining,
            "billed_files": len(bf), "usage": usage,
            "unaccounted": unaccounted, "mismatch": mismatch}


def observe(state_file: str, cli_src: str) -> dict:
    """只读观测报告（**不写任何文件**）。`cli_src` = CLI 源文本（`BILL_UNITS_DECL` 载体）。"""
    decl = parse_units_decl(cli_src)
    out = {
        "state_file": state_file,
        "lambda": "UNKNOWN",
        "lambda_note": "内生影子价格不可识别（需外生扰动或行为边际数据，§21.3 修订 Y）",
        "units": decl or None,
        "units_declared_equal": units_declared_equal(decl),
        "boxes": {},
    }
    data = _read_state(state_file)
    if "error" in data:
        out["error"] = data["error"]
        return out
    gd = data.get("gate_data") or {}
    eb = gd.get("edit_budget") or {}
    out["edit_count"] = gd.get("edit_count")
    out["boxes"]["global"] = observe_box(eb)
    for sid, box in sorted((eb.get("sessions") or {}).items()):
        out["boxes"]["session:%s" % sid] = observe_box(box)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_bill_observe.py")
    ap.add_argument("--state", default="")
    ap.add_argument("--cli", default="")
    ap.add_argument("--pretty", action="store_true")
    ns = ap.parse_args(argv)
    state_file = ns.state or os.environ.get("STATE_FILE", "") or _resolve_default_state()
    cli_path = ns.cli or str(_SKILL_ROOT / "gatekeeper-cli.sh")
    try:
        cli_src = Path(cli_path).read_text(encoding="utf-8")
    except OSError:
        cli_src = ""
    rep = observe(state_file, cli_src)
    print(json.dumps(rep, ensure_ascii=False, indent=2 if ns.pretty else None))
    return 1 if "error" in rep else 0


if __name__ == "__main__":
    sys.exit(main())
