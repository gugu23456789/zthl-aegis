#!/usr/bin/env python3
"""
gk_chain.py — 可组合序列链（standing / audit / red，2026-10-30）
================================================================
用户裁定：standing 是**可组合、可拆分**调用的一键链；审计（audit）与红队（red）同样需要，
否则「审计署（audit --all 聚合口径）」与「审计序列（AUDIT-* 逐站口径）」各说各话。

设计边界（防双轨）：
  · 每步只驱动 `gatekeeper-cli.sh advance <node>` —— 证据注入（audit --state/memory/crossr/
    report、red_* 各阶段）在 `cmd_advance` 内单点完成，本文件**不复刻**任何采集逻辑。
  · 节点名单一真源 = `gk_node_guard.route_map()`；本文件的链只是「选站 + 排序」，
    `test_gk_chain.py` 交叉校验（链缺站/多站即红）。
  · 门禁不跳过：advance 的 ECO/AUDIT 顺序门、熵门、appeal、monitor 全部照旧生效；
    失败即停并回显该步 JSON（不吞、不重试、不降档）。

用法：
  python3 scripts/gk_chain.py list [standing|audit|red] [--json]
  python3 scripts/gk_chain.py run  <chain> [--only NODE[,NODE...]]... [--from NODE] [--to NODE]
                                  [--dry-run] [--state FILE] [--json]

  # 单站可独立调用（组合/拆分的原子面）：
  python3 scripts/gk_chain.py run audit --only AUDIT-CROSSR
  # 一段：
  python3 scripts/gk_chain.py run audit --from AUDIT-MEMORY --to AUDIT-REPORT
  # 只演练（advance --check，零 state 写）：
  python3 scripts/gk_chain.py run red --dry-run

退出码：0 = 全部通过；2 = 某步被门禁拦/失败；1 = 用法错误。
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gk_json_utils import extract_last_json  # noqa: E402


# ─── 链注册（节点名由 gk_node_guard.route_map 交叉校验，禁自成事实源）──────────
@dataclass(frozen=True)
class Step:
    node: str
    desc: str = ""


@dataclass(frozen=True)
class Chain:
    route: str
    name: str
    steps: tuple


CHAINS = {
    "standing": Chain(
        route="standing",
        name="MPR Standing 常驻序列（4 站，可逐站/可拆段）",
        steps=(
            Step("ECO-RESEARCH", "研究：结构扫描 + 深读 + 交叉审查"),
            Step("ECO-EDIT", "编辑：guard-edit / pre-tool-check / pytest"),
            Step("ECO-VERIFY", "验证：self-check / reflect / audit --crossfull"),
            Step("ECO-DOC", "文档：docgen / gitnexus analyze（环回收口）"),
        ),
    ),
    "audit": Chain(
        route="audit",
        name="审计执行序列（审计署下属；逐站证据由 advance 注入）",
        steps=(
            Step("AUDIT-STATE", "审计当前快照（advance 注入 audit --state）"),
            Step("AUDIT-MEMORY", "跨 session 记忆重放（audit --memory）"),
            Step("AUDIT-CROSSR", "跨 R 趋势分析（audit --crossr）"),
            Step("AUDIT-REPORT", "报告签发（audit --report；前置 = 前三站已完成）"),
        ),
    ),
    "red": Chain(
        route="red",
        name="红队序列（16 站；每站证据由 advance 分发）",
        steps=(
            Step("RED-SCOPE", "范围确认（self-check）"),
            Step("RED-SURFACE", "攻击面测绘（_red_attacks surface）"),
            Step("RED-CONSTRAINTS", "约束枚举（_red_attacks constraints）"),
            Step("RED-EXPLOIT", "渗透攻击（_red_attacks exploit）"),
            Step("RED-POSTEX", "后期利用评估（_red_attacks postex）"),
            Step("RED-REPORT", "攻击链报告（audit --report --type redteam）"),
            Step("RED-HINT", "advance hint 注入完整性"),
            Step("RED-HOOK", "pre_tool_hook 门禁旁路"),
            Step("RED-PY", "Python 自检绕过"),
            Step("RED-POISON", "投毒攻击面（poison）"),
            Step("RED-REGISTRY", "元数据路由（registry）"),
            Step("RED-GHOST", "高威胁幽灵面（ghost）"),
            Step("RED-COVERAGE", "审计覆盖缺口（coverage）"),
            Step("RED-DIFF", "差分对拍（diff）"),
            Step("RED-INTEGRITY", "产品完整性模式（integrity）"),
            Step("RED-AIG", "AI-Infra-Guard（仅 KVM 沙箱，aig）"),
        ),
    ),
}


class ChainError(Exception):
    """链执行错误（main 统一转 JSON）。"""


class UsageError(ChainError):
    """用法/参数错误（rc=1）。"""


class StepFailed(ChainError):
    """某步被门禁拦或输出不可解析（rc=2）。"""


# ─── 技能根解析（路径无关：GK_SKILL_DIR 覆盖 → 脚本位置 → cwd → $HOME）───
def resolve_skill_dir() -> Path:
    env = (os.environ.get("GK_SKILL_DIR") or "").strip()
    if env:
        p = Path(env).expanduser()
        if (p / "gatekeeper-cli.sh").is_file():
            return p
        raise UsageError(f"GK_SKILL_DIR 不可用（缺 gatekeeper-cli.sh）: {p}")
    here = Path(__file__).resolve().parent.parent
    if (here / "gatekeeper-cli.sh").is_file():
        return here
    for p in (Path.cwd() / ".trae" / "skills" / "spz-gatekeeper-r-sequence",
              Path.home() / ".trae" / "skills" / "spz-gatekeeper-r-sequence"):
        if (p / "gatekeeper-cli.sh").is_file():
            return p
    raise UsageError("SKILL_DIR_NOT_FOUND：设置 GK_SKILL_DIR 或从技能根运行")


# ─── 选择（组合面）──────────────────────────────────────────────────────────
def _chain(name: str) -> Chain:
    key = (name or "").strip().lower()
    if key not in CHAINS:
        raise UsageError(f"UNKNOWN_CHAIN: '{name}'（可选：{', '.join(sorted(CHAINS))}）")
    return CHAINS[key]


def _flatten(raw) -> list:
    out = []
    for item in raw or []:
        for part in str(item).split(","):
            part = part.strip()
            if part:
                out.append(part.upper())
    return out


def select_steps(name: str, only=None, start: str = "", end: str = "") -> list:
    """返回待跑步骤。--only 按用户给定顺序（显式组合）；--from/--to 按链序切片。"""
    chain = _chain(name)
    order = [s.node for s in chain.steps]
    wanted = _flatten(only)
    start = (start or "").strip().upper()
    end = (end or "").strip().upper()

    if wanted and (start or end):
        raise UsageError("--only 与 --from/--to 不可同时使用（组合方式择一）")

    if wanted:
        unknown = [n for n in wanted if n not in order]
        if unknown:
            raise UsageError(f"UNKNOWN_STEP: {','.join(unknown)}（本链：{', '.join(order)}）")
        seen, picked = set(), []
        for n in wanted:
            if n not in seen:
                seen.add(n)
                picked.append(next(s for s in chain.steps if s.node == n))
        return picked

    if start or end:
        s_idx = 0 if not start else _idx(order, start, name)
        e_idx = len(order) - 1 if not end else _idx(order, end, name)
        if s_idx > e_idx:
            raise UsageError(f"--from {start} 在链序上晚于 --to {end}")
        return list(chain.steps[s_idx:e_idx + 1])

    return list(chain.steps)


def _idx(order: list, node: str, name: str) -> int:
    if node not in order:
        raise UsageError(f"UNKNOWN_STEP: {node}（链 {name}：{', '.join(order)}）")
    return order.index(node)


# ─── 单步命令（与直接敲 CLI 同形：cwd=技能根，禁绝对用户路径）───────────────
def build_argv(step: Step, *, dry_run: bool = False, bash: str = "") -> list:
    """cwd = 技能根（由 run_chain 设定）⟹ 只用相对文件名，禁绝对用户路径。

    ⚠ `dry_run` **不影响 argv**：演练只打印计划、不执行（2026-11-02 修）。
    旧实现给每步加 `--check`，但 `--check` 不推进 state ⟹ 线性链第二步就撞
    「ECO sequential violation」（standing 在 ECO-VERIFY 必红，假失败）。
    单站前置校验请直接 `advance <node> --check`。
    """
    return [bash or os.environ.get("GK_BASH") or "bash",
            "gatekeeper-cli.sh", "advance", step.node]


def _result_ok(rc: int, parsed) -> bool:
    if not isinstance(parsed, dict):
        return False  # 非 JSON ⟹ fail-loud（禁把空输出当成功）
    if "ok" in parsed:
        return bool(parsed["ok"])
    if "allowed" in parsed:
        return bool(parsed["allowed"])
    return rc == 0


def _subprocess_runner(argv, env, cwd):
    cp = subprocess.run(argv, cwd=str(cwd), env=env, capture_output=True, text=True)
    return cp.returncode, cp.stdout, cp.stderr


def run_chain(name: str, steps: list, *, dry_run: bool = False, state: str = "",
              runner=None, skill_dir=None, echo=None) -> dict:
    """顺序驱动；任一步失败即停（不吞错、不重试、不跳过门禁）。"""
    cwd = Path(skill_dir) if skill_dir else resolve_skill_dir()
    env = os.environ.copy()
    if state:
        env["STATE_FILE"] = state
    runner = runner or _subprocess_runner
    total = len(steps)
    records, failed = [], None

    if dry_run:
        plan = [{"node": s.node, "argv": build_argv(s)} for s in steps]
        if echo:
            for i, rec in enumerate(plan, 1):
                echo(f"[{i}/{total}] {rec['node']} (dry-run)")
        return {"ok": True, "chain": name, "dry_run": True, "executed": 0,
                "total": total, "failed_step": None, "plan": plan, "steps": []}

    for i, step in enumerate(steps, 1):
        argv = build_argv(step, dry_run=dry_run)
        rc, out, err = runner(argv, env, cwd)
        parsed = extract_last_json(out or "")
        ok = _result_ok(rc, parsed)
        rec = {"node": step.node, "argv": argv, "ok": ok, "rc": rc,
               "result": parsed if parsed is not None else (out or "").strip()[-800:]}
        if parsed is None:
            rec["error"] = "NON_JSON_OUTPUT"
            if err:
                rec["stderr"] = err.strip()[-800:]
        records.append(rec)
        if echo:
            echo(f"[{i}/{total}] {step.node} {'ok' if ok else 'FAIL'}")
        if not ok:
            failed = step.node
            break

    return {"ok": failed is None, "chain": name, "dry_run": dry_run,
            "executed": len(records), "total": total, "failed_step": failed,
            "steps": records}


# ─── CLI ────────────────────────────────────────────────────────────────────
def _print_list(name: str = "", as_json: bool = False):
    names = [name] if name else list(CHAINS)
    if as_json:
        payload = {n: {"route": CHAINS[n].route, "name": CHAINS[n].name,
                       "steps": [{"node": s.node, "desc": s.desc} for s in CHAINS[n].steps]}
                   for n in names}
        print(json.dumps({"ok": True, "chains": payload}, ensure_ascii=False))
        return
    for n in names:
        c = CHAINS[n]
        print(f"{n} — {c.name}")
        for i, s in enumerate(c.steps, 1):
            print(f"  {i:>2}. {s.node:<15} {s.desc}")
        print()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="gk_chain.py", description="可组合序列链（standing/audit/red）")
    sub = p.add_subparsers(dest="cmd", required=True)

    lp = sub.add_parser("list", help="列出链与站")
    lp.add_argument("chain", nargs="?", default="")
    lp.add_argument("--json", action="store_true")

    rp = sub.add_parser("run", help="按链执行（失败即停）")
    rp.add_argument("chain")
    rp.add_argument("--only", action="append", default=[], metavar="NODE[,NODE...]")
    rp.add_argument("--from", dest="start", default="", metavar="NODE")
    rp.add_argument("--to", dest="end", default="", metavar="NODE")
    rp.add_argument("--dry-run", action="store_true",
                    help="只打印计划、不执行（零 state 写；不追加 --check，见 build_argv 注）")
    rp.add_argument("--state", default="", help="STATE_FILE（缺省用环境变量/CLI 默认）")
    rp.add_argument("--json", action="store_true")

    ns = p.parse_args(argv)
    try:
        if ns.cmd == "list":
            _print_list(ns.chain, ns.json)
            return 0
        steps = select_steps(ns.chain, only=ns.only, start=ns.start, end=ns.end)
        echo = (lambda _m: None) if ns.json else (lambda m: print(m, file=sys.stderr))
        res = run_chain(ns.chain, steps, dry_run=ns.dry_run, state=ns.state, echo=echo)
        print(json.dumps(res, ensure_ascii=False))
        return 0 if res["ok"] else 2
    except UsageError as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
        return 1
    except ChainError as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    sys.exit(main())
