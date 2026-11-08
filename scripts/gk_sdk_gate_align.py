#!/usr/bin/env python3
"""gk_sdk_gate_align.py — R14/R16 机械对齐门（0-API，纯文本 + manifest）。

R14：`x-tier` 必须与 `_CMD_REG` 的 `gate_level` / `side_effects` 白名单一致；
      in-process 动词绕过的是整条 `_dispatch` 校验链，所以不能只靠“不暴露 execute”。
R16：无 `_CMD_REG` 条目的动词（`repo_index.check`）必须声明
      `x-audit: sdk-readonly`，由本审计面覆盖；不得静默并入注册表
      （会撞 `test_gk_state_forms.py` 的“不新增条目/总数=52”不变量）。

用法：
  python scripts/gk_sdk_gate_align.py --json
  python scripts/gk_sdk_gate_align.py --manifest schema/gk-sdk-1.json --cli gatekeeper-cli.sh
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REG_RE = re.compile(r'^_CMD_REG\[([^\]]+)\]="([^"|]*)\|([^"|]*)\|([^"|]*)\|([^"]*)"', re.M)
ALLOWED_TIERS = {"read", "evaluate"}
ALLOWED_AUDITS = {"registry", "registry-readonly-subcommand", "sdk-readonly"}
READONLY_SUBCOMMAND = "registry-readonly-subcommand"


def load_registry(cli_path) -> dict:
    text = Path(cli_path).read_text(encoding="utf-8", errors="replace")
    reg = {}
    for m in REG_RE.finditer(text):
        name, fn, gate, stage, side = m.groups()
        reg[name] = {"fn": fn, "gate_level": gate, "stage": stage, "side_effects": side}
    return reg


def check(manifest: dict, cli_path) -> dict:
    verbs = manifest.get("verbs") or {}
    reg = load_registry(cli_path)
    errors = []
    if not verbs:
        errors.append("manifest.verbs 为空")
    for verb, spec in verbs.items():
        tier = spec.get("tier")
        audit = spec.get("x-audit")
        cli = spec.get("x-cli")
        if tier not in ALLOWED_TIERS:
            errors.append("%s: tier=%r 不在 read/evaluate（execute 禁止）" % (verb, tier))
        if audit not in ALLOWED_AUDITS:
            errors.append("%s: x-audit=%r 非法" % (verb, audit))
        if cli:
            entry = reg.get(cli)
            if not entry:
                errors.append("%s: x-cli=%r 不在 _CMD_REG" % (verb, cli))
                continue
            if entry["gate_level"] != "none":
                errors.append("%s: %s gate_level=%r ≠ none" % (verb, cli, entry["gate_level"]))
            if entry["side_effects"]:
                readonly_sub = (audit == READONLY_SUBCOMMAND
                                and entry["side_effects"] == "state_write"
                                and verb.endswith(".list"))
                if not readonly_sub:
                    errors.append("%s: %s side_effects=%r 未获只读子命令白名单"
                                  % (verb, cli, entry["side_effects"]))
        elif audit != "sdk-readonly":
            errors.append("%s: 无 x-cli 时 x-audit 必须为 sdk-readonly" % verb)
    return {"ok": not errors, "verbs": len(verbs), "registry": len(reg), "errors": errors}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default=str(ROOT / "schema" / "gk-sdk-1.json"))
    ap.add_argument("--cli", default=str(ROOT / "gatekeeper-cli.sh"))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    manifest = json.loads(Path(a.manifest).read_text(encoding="utf-8"))
    result = check(manifest, a.cli)
    if a.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("SDK-GATE OK (%d verbs)" % result["verbs"] if result["ok"]
              else "SDK-GATE FAIL: " + "; ".join(result["errors"]))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
