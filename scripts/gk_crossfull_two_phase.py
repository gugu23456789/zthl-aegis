#!/usr/bin/env python3
"""两阶段 crossfull —— 确定性车道先跑、红则早停；绿再跑 LLM 车道（**不降档**）。

病根（2026-10-26 实测）
=======================
`audit --crossfull` 的 runbook 顺序是 `E1 → L1 → L3 → L2(LLM) → L5 → L6…L10b`：
**LLM 车道跑在 L6/L7/L8/L9/L10/L10b 之前**。确定性面一旦红（当时是 L10b GBK + L2 节点绑定），
整轮 ~14 分钟里 LLM 段先白烧；重跑一次又 14 分钟。

本包装器只做**顺序优化**，不改 runbook（它在 `PROTECTED_REGION::gate` 内，行级禁改）：
  阶段 1 = 同一命令 + `GK_CROSSFULL_SUBAGENT=0`（只跑确定性车道，分钟级）
  阶段 2 = 原样全量（LLM 臂的 `reasoning=max / max_out / timeout` **一律不动**）
判据只读阶段 1 的 JSON：确定性步（`DETERMINISTIC_IDS`）出现 `FAIL` ⟹ 早停，退出 3。

用法（必须用配好的解释器 / WSL）
=================================
  python3 scripts/gk_crossfull_two_phase.py [--base <ref>] [--repo R]
      [--state S] [--isolate] [--force] [--cli <gatekeeper-cli.sh>]
  （解释器由 `scripts/py_resolve.sh` 发现；`GK_PYTHON` / `py_resolve.sh any` 输出均可直接调用）

  --force   确定性红也继续跑全量（诊断用）
退出码：0 = 全绿；2 = 解析/用法失败；3 = 确定性车道红（已早停）；其余 = 阶段 2 的原始退出码。
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

# runbook 确定性车道（与 gatekeeper-cli.sh 的 note 同源；L2/后R 属 LLM 车道）
DETERMINISTIC_IDS = ("E1", "L1", "L3", "L6", "L7", "L8", "L9", "L10", "L10b")


def parse_crossfull(stdout):
    """从输出里取**最后一条** crossfull JSON（前面的行是进度/中文摘要）。"""
    for line in reversed((stdout or "").splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        if isinstance(payload, dict) and payload.get("audit_mode") == "crossfull":
            return payload
    return None


def deterministic_failures(payload):
    """只认确定性步的 FAIL；WARN/SKIP/MANUAL/NOT-RUN 与 LLM 车道一律不算。"""
    steps = ((payload or {}).get("crossfull") or {}).get("steps") or []
    out = []
    for st in steps:
        if not isinstance(st, dict):
            continue
        if st.get("id") in DETERMINISTIC_IDS and st.get("status") == "FAIL":
            out.append((st.get("id"), st.get("detail", "")))
    return out


def _run(cli, argv, env):
    proc = subprocess.run(["bash", cli, "audit", "--crossfull", *argv],
                          capture_output=True, text=True, env=env)
    return proc.returncode, proc.stdout, proc.stderr


def main(argv=None):
    ap = argparse.ArgumentParser(description="两阶段 crossfull（确定性早停；LLM 车道不降档）")
    ap.add_argument("--base", default="HEAD~10")
    ap.add_argument("--repo", default="")
    ap.add_argument("--state", default="")
    ap.add_argument("--isolate", action="store_true")
    ap.add_argument("--force", action="store_true", help="确定性红也继续跑全量")
    ap.add_argument("--cli", default=str(Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"))
    args = ap.parse_args(argv)

    pass_args = ["--base", args.base]
    if args.repo:
        pass_args += ["--repo", args.repo]
    if args.state:
        pass_args += ["--state", args.state]
    if args.isolate:
        pass_args += ["--isolate"]

    env1 = dict(os.environ)
    env1["GK_CROSSFULL_SUBAGENT"] = "0"
    rc1, out1, err1 = _run(args.cli, pass_args, env1)
    sys.stdout.write(out1)
    if err1:
        sys.stderr.write(err1)

    payload = parse_crossfull(out1)
    if payload is None:
        print("FAIL 阶段 1 输出里没有 crossfull JSON（rc=%d）—— 不静默降级为「全绿」"
              % rc1, file=sys.stderr)
        return 2
    fails = deterministic_failures(payload)
    if fails:
        print("\n[two-phase] 确定性车道红：%s ⟹ 早停，未启动 LLM 车道（省一轮 ~14 min）"
              % ", ".join("%s" % fid for fid, _ in fails), file=sys.stderr)
        for fid, detail in fails:
            print("  - %s: %s" % (fid, str(detail)[:160]), file=sys.stderr)
        if not args.force:
            print("[two-phase] 需要诊断可加 --force（会跑全量，LLM 参数不变）", file=sys.stderr)
            return 3
        print("[two-phase] --force：继续跑阶段 2", file=sys.stderr)

    env2 = dict(os.environ)
    rc2, out2, err2 = _run(args.cli, pass_args, env2)
    sys.stdout.write(out2)
    if err2:
        sys.stderr.write(err2)
    print("[two-phase] 阶段 2 完成 rc=%d（确定性红=%d；LLM 参数未降档）"
          % (rc2, len(fails)), file=sys.stderr)
    return rc2


if __name__ == "__main__":
    sys.exit(main())
