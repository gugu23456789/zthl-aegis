#!/usr/bin/env python3
"""monitor 落库载荷的等价性夹具驱动（2026-11-04，B2 前置）。

用途
----
把 `gatekeeper-cli.sh::cmd_monitor` 里那段 311 行内联 payload 变成**可重复运行**的
fixture：固定 subagent 输出（含 HMAC）+ 固定 state + 固定 env ⟹ 任意候选实现都能在
同一输入上跑，比较 **stdout + 落库后的 state**（bashpy `verify` 只比 stdout，本驱动补
state 产物这一面）。

只做夹具与对比，**不触碰生产调用点**。

命令
----
  python scripts/gk_monitor_fixture.py --build <dir>      # 生成 state/out/env 三件套
  python scripts/gk_monitor_fixture.py --extract <out.py> # 从 CLI 抽出当前内联 payload
  python scripts/gk_monitor_fixture.py --selfcheck        # 抽出→跑两遍→断言一致（驱动自证）
"""
import argparse
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "gatekeeper-cli.sh"
SCRIPTS = ROOT / "scripts"
FIXED_KEY = "0f" * 32  # 64-hex，固定测试密钥（非生产）


def _sign(payload: dict) -> str:
    """与 runner 同构：去掉 hmac/jwt_token，按原始键序紧凑序列化后 HMAC-SHA256。"""
    data = {k: v for k, v in payload.items() if k not in ("hmac", "jwt_token")}
    sk = bytes.fromhex(FIXED_KEY)
    msg = json.dumps(data, separators=(",", ":"), default=str).encode()
    return hmac.new(sk, msg, hashlib.sha256).hexdigest()


def _out_payload() -> dict:
    base = {
        "mode": "subagent", "subagent_id": "fixture-sub", "nonce": "n0nce",
        "timestamp": "2026-11-04T00:00:00Z", "task": "fixture-task",
        "conclusion": "fixture", "evidence": [], "findings": {"worked": [], "failed": [], "not_tried": []},
        "next_steps": [], "confidence": "medium", "tools_used": [], "guardrail": "passed",
        "turns": 1, "total_items": 0, "total_tokens": 0, "budget_status": "ok",
        "gx_status": {"verdict": "n/a"}, "verification": {"status": "n/a"},
        "evidence_anchor": {"status": "n/a"}, "kept": ["k1"], "challenges": ["c1"],
        "slashed": [], "assertions": [], "tool_call_count": 0,
    }
    base["hmac"] = _sign(base)
    return base


def build(dir_path: str) -> dict:
    d = Path(dir_path)
    d.mkdir(parents=True, exist_ok=True)
    state = {"r_phase": "FIXTURE", "stage": "FIXTURE",
             "gate_data": {"edit_budget": {"max": 8, "used": 0, "remaining": 8},
                           "subagent_history": [], "narrow_tasks": []},
             "_checksum": ""}
    (d / "state.json").write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")
    out = _out_payload()
    (d / "out.json").write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
    env = {"GK_TASK": "fixture-task", "GK_HMAC_VALID": "valid",
           "GK_AGENT_IDENTITY": "verified", "GK_OUTPUT_FILE": str(d / "sub.out"),
           "GK_REPORT_FILE": str(d / "sub.report")}
    (d / "env.json").write_text(json.dumps(env, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"dir": str(d), "hmac": out["hmac"]}


def extract(out_py: str) -> int:
    """抽出 5332 起的 `python3 -c "` 载荷体（到 `" 2>>` 终止行），逐字落盘。"""
    lines = CLI.read_text(encoding="utf-8").splitlines()
    start = None
    for i, ln in enumerate(lines):
        if 'GK_HMAC_VALID="$hmac_valid" python3 -c "' in ln:
            start = i + 1
            break
    if start is None:
        print("ANCHOR_NOT_FOUND", file=sys.stderr)
        return 2
    end = None
    for j in range(start, min(start + 500, len(lines))):
        if lines[j].lstrip().startswith('" 2>>'):
            end = j
            break
    if end is None:
        print("TERMINATOR_NOT_FOUND", file=sys.stderr)
        return 2
    Path(out_py).write_text("\n".join(lines[start:end]) + "\n", encoding="utf-8")
    return end - start


def run(script: str, fixture_dir: str, workdir: str) -> dict:
    fx, wd = Path(fixture_dir), Path(workdir)
    wd.mkdir(parents=True, exist_ok=True)
    shutil.copy(fx / "state.json", wd / "state.json")
    env = dict(os.environ)
    env.update(json.loads((fx / "env.json").read_text(encoding="utf-8")))
    env.update({"GK_PY_SCRIPTS": str(SCRIPTS), "GK_PY_STATE": str(wd / "state.json"),
                "GK_BATCH_PLAN": "", "GK_BATCH_NARROW": "", "GK_BATCH_EPOCH": "",
                "GK_ARM_DELTA": ""})
    p = subprocess.run([sys.executable, script], cwd=str(wd),
                       stdin=open(fx / "out.json", "rb"),
                       capture_output=True, env=env, timeout=120)
    state_after = json.loads((wd / "state.json").read_text(encoding="utf-8"))
    return {"rc": p.returncode, "stdout": p.stdout.decode("utf-8", "replace"),
            "stderr": p.stderr.decode("utf-8", "replace"), "state": state_after}


# 允许归一化的字段：只列**显式**项，禁止静默忽略差异。
# 实测（2026-11-04，同一载荷跑两遍）唯一不定的三类，全部是**时钟派生**：
#   · gate_data.subagent_history[].ts
#   · gate_data.jti_store.<nonce>            （重放闸记的 epoch 秒）
#   · gate_data.satellite_index.*.*.first_ts/last_ts（卫星索引时间窗）
_NORMALIZE = ("subagent_history[].ts", "jti_store.*", "satellite_index.*.*.{first_ts,last_ts}")


def _norm(state: dict) -> dict:
    s = json.loads(json.dumps(state))
    gd = s.get("gate_data") if isinstance(s.get("gate_data"), dict) else {}
    for e in (gd.get("subagent_history") or []):
        if isinstance(e, dict):
            e.pop("ts", None)
    gd.pop("jti_store", None)
    for _node, idx in (gd.get("satellite_index") or {}).items():
        if isinstance(idx, dict):
            for _sid, rec in idx.items():
                if isinstance(rec, dict):
                    rec.pop("first_ts", None)
                    rec.pop("last_ts", None)
    return s


def compare(a: dict, b: dict) -> dict:
    diffs = []
    if a["rc"] != b["rc"]:
        diffs.append("rc %r != %r" % (a["rc"], b["rc"]))
    if a["stdout"] != b["stdout"]:
        diffs.append("stdout 不同（%d vs %d bytes）" % (len(a["stdout"]), len(b["stdout"])))
    if _norm(a["state"]) != _norm(b["state"]):
        diffs.append("state 不同（归一化后仍不等）")
    return {"equivalent": not diffs, "diffs": diffs}


def selfcheck() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="gk-mon-fixture-"))
    build(str(tmp / "fx"))
    n = extract(str(tmp / "baseline.py"))
    if n < 0:
        return 1
    r1 = run(str(tmp / "baseline.py"), str(tmp / "fx"), str(tmp / "r1"))
    r2 = run(str(tmp / "baseline.py"), str(tmp / "fx"), str(tmp / "r2"))
    cmp = compare(r1, r2)
    print(json.dumps({"payload_lines": n, "selfcheck": cmp,
                      "rc": r1["rc"], "stderr_tail": r1["stderr"][-200:]},
                     ensure_ascii=False, indent=2))
    return 0 if cmp["equivalent"] and r1["rc"] == 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser(prog="gk_monitor_fixture.py")
    ap.add_argument("--build")
    ap.add_argument("--extract")
    ap.add_argument("--selfcheck", action="store_true")
    ns = ap.parse_args()
    if ns.build:
        print(json.dumps(build(ns.build), ensure_ascii=False))
        return 0
    if ns.extract:
        n = extract(ns.extract)
        print("extracted_lines=%d" % n)
        return 0 if n > 0 else 1
    if ns.selfcheck:
        return selfcheck()
    print("usage: --build <dir> | --extract <out.py> | --selfcheck", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
