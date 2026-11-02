#!/usr/bin/env python3
"""
Review-channel 组件 pin 表（D-lite, 2026-09-04 standing ECO-EDIT A-D SCR 收敛）
================================================================================
SCR D adjusted→D-lite 定案：不实例化五源 loader（runner 内建 subagent 无发行根，
dev/tampered/missing 态空洞——照搬 gk_bashpy_loader 是空转死重）；仿
gk_paper_review_loader 的 pin 纪律（source/version/output-contract + exit 2），
复用 manifest+cap 治理层思想但只保留轻量契约层。

职责（审查通道调用前确定性校验）：
  - cross-review L2（monitor --subagent --crossrev）/ plan-refinement（SCR 质询）
  - source    : 运行时组件实存（subagent_runner.py / 签名上下文文件）
  - version   : 组件内容 SHA256 pin（未登记 = dev WARN 非 CI 验证，同 paper-review 纪律）
  - contract  : 通道输出 JSON 必须字段集（防空白/机械性输出的最小结构化断言）

用法:
  python3 gk_review_pins.py verify --channel plan-refinement   # exit 2 = pin 失败
  python3 gk_review_pins.py verify --channel crossrev
  python3 gk_review_pins.py contract --channel crossrev        # 打印输出契约字段
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

SKILL = Path(__file__).resolve().parent.parent

# source/version/output-contract 三元 pin 表（单一事实源）。
# sha256: subagent_runner.py 内容 pin；None = dev（改动后未登记 → WARN 级，对齐
# _PAPER_REVIEW_PINS『未登记 = dev WARN，非 CI 验证』纪律；登记须全量回归后刷新）。
_REVIEW_PINS = {
    "subagent_runner": {
        "source": "scripts/subagent_runner.py",
        "sha256": None,  # 改动即失效——登记前为 dev（verify 输出 WARN 不 FAIL）
        "output_contract": ["conclusion", "confidence", "tools_used", "guardrail"],
    },
}

# 通道 → 组件 + 输出契约（plan-refinement / crossrev 均委托 subagent_runner；
# 额外硬性契约字段以通道声明为准——ECC JSON 必须带 conclusion/evidence/guardrail）
_CHANNELS = {
    "plan-refinement": {
        "components": ["subagent_runner"],
        "contract": ["conclusion", "evidence", "guardrail", "confidence"],
    },
    "crossrev": {
        "components": ["subagent_runner"],
        "contract": ["conclusion", "evidence", "confidence"],
    },
}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_channel(channel: str) -> dict:
    """校验通道组件 pin：全部 source 实存 + 输出契约字段定义存在；exit 2 语义由调用方执行。

    返回 {"ok": bool, "channel": str, "checks": [...], "warnings": [...]}；
    sha256 未登记 → WARN（dev），非 FAIL——FAIL 仅 source 缺失/契约未定义/未知通道。
    """
    cfg = _CHANNELS.get(channel)
    if cfg is None:
        return {"ok": False, "error": f"UNKNOWN_CHANNEL: '{channel}'",
                "known": sorted(_CHANNELS)}
    checks, warnings = [], []
    ok = True
    for comp in cfg["components"]:
        pin = _REVIEW_PINS.get(comp)
        if pin is None:
            checks.append({"component": comp, "status": "FAIL", "reason": "component_not_registered"})
            ok = False
            continue
        src = SKILL / pin["source"]
        if not src.exists():
            checks.append({"component": comp, "source": pin["source"], "status": "FAIL", "reason": "source_missing"})
            ok = False
            continue
        h = _sha256_file(src)
        if pin["sha256"] is None:
            warnings.append({"component": comp, "reason": "dev_unpinned — 全量回归后登记 sha256"})
        elif h != pin["sha256"]:
            checks.append({"component": comp, "status": "FAIL", "reason": "source_sha256_mismatch (tampered 或未刷新 pin)"})
            ok = False
            continue
        checks.append({"component": comp, "source": pin["source"], "status": "OK",
                       "output_contract": pin["output_contract"]})
    return {"ok": ok, "channel": channel, "checks": checks, "warnings": warnings,
            "contract": cfg["contract"]}


def contract_fields(channel: str) -> dict:
    cfg = _CHANNELS.get(channel)
    if cfg is None:
        return {"ok": False, "error": f"UNKNOWN_CHANNEL: '{channel}'", "known": sorted(_CHANNELS)}
    return {"ok": True, "channel": channel, "contract": cfg["contract"]}


def _main() -> int:
    p = argparse.ArgumentParser(description="Review-channel 组件 pin 表 (D-lite)")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify"); v.add_argument("--channel", required=True)
    c = sub.add_parser("contract"); c.add_argument("--channel", required=True)
    a = p.parse_args()
    if a.cmd == "verify":
        out = verify_channel(a.channel)
        print(json.dumps(out, ensure_ascii=False))
        return 0 if out.get("ok") else 2
    out = contract_fields(a.channel)
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok") else 2


if __name__ == "__main__":
    sys.exit(_main())
