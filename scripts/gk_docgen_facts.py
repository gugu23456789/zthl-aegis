#!/usr/bin/env python3
"""gk_docgen_facts.py — 文档事实块**生成器**（2026-11-01；SKILL.md / architecture-overview.md）。

问题（用户裁定）：两份文档手写数字，改一次代码就积累一批错误描述；而 doc-align 只查
「文里写了什么」、不查「这个数字从哪来」。故把**可机检的事实**收敛为一块自动生成内容：

    <!-- GK-FACTS:START（由 scripts/gk_docgen_facts.py 生成，勿手改） -->
    …markdown 表…
    <!-- GK-FACTS:END -->

消费方：`gk_doc_align.py::check_gk_facts`（漂移 = FAIL）。生成源全部是**活文件**：
CLI 行数 / `_CMD_REG` 计数 / `gk_chain` 站点 / `gk_self_check` 检查函数 / git 跟踪的
references md / ROLE_TOOLS / 红队向量与情报源登记表 / 解释器单源脚本。

用法：
  python scripts/gk_docgen_facts.py            # 打印事实块
  python scripts/gk_docgen_facts.py --write    # 回写两份文档（幂等）
  python scripts/gk_docgen_facts.py check      # 只比对（不一致 exit 2）
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

_SKILL_DIR = Path(__file__).resolve().parent.parent
_START = "<!-- GK-FACTS:START（由 scripts/gk_docgen_facts.py 生成，勿手改） -->"
_END = "<!-- GK-FACTS:END -->"
DOCS = ("SKILL.md", "references/architecture-overview.md")


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def collect(skill_dir: str = "") -> dict:
    """从**活文件**采集事实（只读；失败项 None，不猜）。"""
    sd = Path(skill_dir) if skill_dir else _SKILL_DIR
    cli = sd / "gatekeeper-cli.sh"
    hook = sd / "scripts" / "pre_tool_hook.py"
    chain = sd / "scripts" / "gk_chain.py"
    selfcheck = sd / "scripts" / "gk_self_check.py"
    facts = {"cli_lines": None, "commands": None, "red_stations": [],
             "selfcheck_checks": None, "refs_tracked": None,
             "roles": [], "gates": [], "interpreter": "scripts/py_resolve.sh",
             "red_vectors": None, "intel_sources": None}
    try:
        facts["cli_lines"] = len(_read(cli).splitlines())
        facts["commands"] = len(re.findall(r"(?m)^_CMD_REG\[", _read(cli)))
    except OSError:
        pass
    try:
        facts["gates"] = sorted(set(re.findall(r"Gate R0\.(\d+)", _read(hook))),
                                key=lambda x: int(x))
    except OSError:
        pass
    try:
        facts["red_stations"] = re.findall(r'Step\("(RED-[A-Z0-9-]+)"', _read(chain))
    except OSError:
        pass
    try:
        facts["selfcheck_checks"] = len(re.findall(r"(?m)^def check_", _read(selfcheck)))
    except OSError:
        pass
    try:
        r = subprocess.run(["git", "-C", str(sd), "ls-files", "references/"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            facts["refs_tracked"] = len([
                p for p in r.stdout.splitlines()
                if p.startswith("references/") and "/" not in p.split("/", 1)[1]
                and p.endswith(".md")])
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        sys.path.insert(0, str(sd / "scripts"))
        import subagent_runner as SR
        facts["roles"] = sorted(SR.ROLE_TOOLS)
    except Exception:  # noqa: BLE001
        pass
    try:
        facts["red_vectors"] = len(json.loads(
            _read(sd / "references" / "red-vectors.json"))["vectors"])
    except (OSError, ValueError, KeyError):
        pass
    try:
        facts["intel_sources"] = len(json.loads(
            _read(sd / "references" / "red-intel-sources.json"))["sources"])
    except (OSError, ValueError, KeyError):
        pass
    return facts


def render(facts: dict) -> str:
    gates = facts.get("gates") or []
    gate_txt = ("Gate R0.1–R0.%s（%d 个）" % (gates[-1], len(gates))) if gates else "—"
    rows = [
        ("CLI 行数", facts.get("cli_lines"), "`wc -l gatekeeper-cli.sh`"),
        ("CLI 命令数", facts.get("commands"), "`^_CMD_REG[` 计数"),
        ("红队站点", len(facts.get("red_stations") or []), "`gk_chain.py` 的 `Step(\"RED-*\")`"),
        ("自检检查函数", facts.get("selfcheck_checks"), "`gk_self_check.py` 的 `def check_*`"),
        ("references 入库 md", facts.get("refs_tracked"), "`git ls-files references/*.md`（顶层）"),
        ("子代理角色", len(facts.get("roles") or []), "`subagent_runner.ROLE_TOOLS`"),
        ("hook R0 门禁", gate_txt, "`pre_tool_hook.py` 的 `Gate R0.N`"),
        ("红队向量", facts.get("red_vectors"), "`references/red-vectors.json`"),
        ("情报源", facts.get("intel_sources"), "`references/red-intel-sources.json`"),
        ("解释器解析", "`%s`（发现式，无绝对路径）" % facts.get("interpreter"),
         "`scripts/py_resolve.sh`"),
    ]
    out = [_START, "| 事实 | 值 | 来源（可复算） |", "|:--|:--|:--|"]
    for k, v, src in rows:
        out.append("| %s | %s | %s |" % (k, "—" if v is None else v, src))
    out.append(_END)
    return "\n".join(out)


_README = "references/README.md"
_RSTART = "<!-- GK-REFS:START（由 scripts/gk_docgen_facts.py 生成，勿手改） -->"
_REND = "<!-- GK-REFS:END -->"
_CAT_ORDER = ["1. Architecture and routing", "2. Execution and CLI",
              "3. Safety and security", "4. Findings and history",
              "5. Templates", "9. Other"]
_CATEGORY = {
    "architecture-overview.md": "1. Architecture and routing",
    "meta-routing-protocol.md": "1. Architecture and routing",
    "state-storage.md": "1. Architecture and routing",
    "flows-a-b-c.md": "1. Architecture and routing",
    "extension-registry.md": "1. Architecture and routing",
    "superagent-comparison.md": "1. Architecture and routing",
    "stages.md": "2. Execution and CLI",
    "cli-protocol.md": "2. Execution and CLI",
    "prm-monitor-methodology.md": "2. Execution and CLI",
    "plan-writing-safety-net.md": "2. Execution and CLI",
    "convergence-evaluator.md": "2. Execution and CLI",
    "security-measures.md": "3. Safety and security",
    "security-incident-response.md": "3. Safety and security",
    "trae-cross-user-leakage-report.md": "3. Safety and security",
    "plugin-loading-test-framework.md": "3. Safety and security",
    "xspi-defense.md": "3. Safety and security",
    "standard-maintenance-module.md": "5. Templates",
    "ecc-write-spec.md": "4. Findings and history",
    "ecc-impact-20260609-gitnexus.md": "4. Findings and history",
    "ecc-impact-v7.md": "4. Findings and history",
    "game-path-audit.md": "4. Findings and history",
    "ci-pipeline-template.md": "5. Templates",
    "wasm-engineering-template.md": "5. Templates",
    "sequence-node-safety-net-template.md": "5. Templates",
}


def _git_ref_names(sd: Path) -> list:
    try:
        r = subprocess.run(["git", "-C", str(sd), "ls-files", "references/"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return []
        return sorted(n for n in (p.split("/", 1)[1] for p in r.stdout.splitlines()
                                  if p.startswith("references/"))
                      if n.endswith(".md") and "/" not in n)
    except (OSError, subprocess.SubprocessError):
        return []


def _first_title(p: Path) -> str:
    try:
        for line in _read(p).splitlines():
            s = line.strip()
            if not s:
                continue
            if s.startswith("#"):
                s = s.lstrip("#").strip()
            return s[:120].replace("|", "｜")
    except OSError:
        pass
    return ""


def collect_refs(sd: Path) -> list:
    """公开面参考文档（**排除面单源 = `oss_scrub.is_excluded`**，禁第二份名单）。"""
    try:
        sys.path.insert(0, str(sd / "scripts"))
        import oss_scrub as S
        names = [n for n in _git_ref_names(sd)
                 if n != "README.md" and not S.is_excluded("references/" + n)]
    except Exception:  # noqa: BLE001
        names = [n for n in _git_ref_names(sd) if n != "README.md"]
    return [{"name": n, "title": _first_title(sd / "references" / n),
             "cat": _CATEGORY.get(n, "9. Other")} for n in names]


def render_refs(sd: Path) -> str:
    rows = collect_refs(sd)
    out = [_RSTART,
           "> 公开面共 **%d** 份文档（本索引自动生成；出包范围 = `oss-export-whitelist.json`）。" % len(rows),
           ""]
    for cat in _CAT_ORDER:
        sub = sorted([r for r in rows if r["cat"] == cat], key=lambda x: x["name"])
        if not sub:
            continue
        out += ["### " + cat, "", "| Document | Purpose |", "|:--|:--|"]
        out += ["| [%s](%s) | %s |" % (r["name"], r["name"], r["title"]) for r in sub]
        out.append("")
    out.append(_REND)
    return "\n".join(out)


_STATE_DOC = "references/state-storage.md"
_CAP_START = "<!-- GK-CAP:START（由 scripts/gk_docgen_facts.py 生成，勿手改） -->"
_CAP_END = "<!-- GK-CAP:END -->"
_WALL_START = "<!-- GK-WALL:START（由 scripts/gk_docgen_facts.py 生成，勿手改） -->"
_WALL_END = "<!-- GK-WALL:END -->"
_WALL_TEXT = {
    "notice": ("过半", "`state_size_report` / `two_legs_report` 出 `WALL_NOTICE` 告警"),
    "warn": ("警告", "同上 `WALL_WARN`"),
    "trim": ("需要裁剪", "同上 `WALL_TRIM`；先裁再裁决"),
    "block": ("**触发拦截**", "`dump_state` **拒写**（`STATE_WALL_BLOCK`）"),
}


def collect_state(sd: Path) -> dict:
    """状态容量/水位常量（单源 = `gk_json_utils` + `gk_satellite` 的模块常量）。"""
    try:
        sys.path.insert(0, str(sd / "scripts"))
        import gk_json_utils as J
        import gk_satellite as S
    except Exception:  # noqa: BLE001
        return {}
    return {
        "wall": J.STATE_SIZE_WALL, "levels": list(J.WALL_LEVELS),
        "hist": J.HIST_MAX_BYTES, "pipe": J.TASK_PIPE_MAX_BYTES,
        "ecc": getattr(J, "ECC_MAX_BYTES", 0),
        "entries": getattr(J, "ECC_MAX_ENTRIES", 0),
        "open": getattr(J, "ECC_MAX_OPEN", 0),
        "rounds": S.SAT_ROUNDS_BUDGET, "arms": S.SAT_ARMS_PER_ROUND,
        "arm_b": S.SAT_ARM_BUDGET_BYTES, "head": S.SAT_ROUND_HEADROOM_PCT,
        "round_b": S.SAT_ROUND_BUDGET_BYTES, "shard_b": S.SAT_SHARD_BUDGET_BYTES,
        "max_arms": S.SAT_MAX_ARMS_PER_KIND,
    }


def _fmt(n) -> str:
    return "{:,}".format(int(n))


def render_state_cap(d: dict) -> str:
    if not d:
        raise ValueError("容量常量不可读（gk_json_utils / gk_satellite）")
    return "\n".join([
        _CAP_START,
        "**容量标定**（owner 2026-11-01 明确口径）：**一轮 = %d 个 subagent（档位 4，单臂 token 预算跑满）"
        % d["arms"],
        "产生的 history 总量 × %d%% 余量**；一片 = %d 轮。" % (d["head"], d["rounds"]),
        "",
        "| 项 | 值 | 口径 |",
        "|:--|:--|:--|",
        "| 单臂预算 | %d KB | 档位 4 跑满时 history 实测 10.9–12.7 KB 的上抬值 |" % (d["arm_b"] // 1024),
        "| 一轮预算 | **%s B（≈%.1f KB）** | %d 臂 × %d KB × %d%%（`SAT_ROUND_BUDGET_BYTES`） |"
        % (_fmt(d["round_b"]), d["round_b"] / 1024, d["arms"], d["arm_b"] // 1024, d["head"]),
        "| 片容量 | **%s B（≈%.2f MB）** | %d 轮（`SAT_SHARD_BUDGET_BYTES`） |"
        % (_fmt(d["shard_b"]), d["shard_b"] / 1048576, d["rounds"]),
        "| 臂数上限 | **%d 臂 / kind** | %d 轮 × %d 臂（`SAT_MAX_ARMS_PER_KIND`） |"
        % (d["max_arms"], d["rounds"], d["arms"]),
        "| 超限动作 | **只报不删** | 有片的叶子保留可回溯性；越线进自检 WARN |",
        _CAP_END,
    ])


def render_state_wall(d: dict) -> str:
    if not d:
        raise ValueError("水位常量不可读（gk_json_utils / gk_satellite）")
    out = [
        _WALL_START,
        "整墙 = `STATE_SIZE_WALL = %s B`（%.1f MB）。水位阈值单源 = `gk_json_utils.WALL_LEVELS`："
        % (_fmt(d["wall"]), d["wall"] / 1048576),
        "",
        "| 水位 | level | 含义 | 行为 |",
        "|:--|:--|:--|:--|",
    ]
    for pct, name in sorted(d["levels"]):          # 50 → 95
        meaning, action = _WALL_TEXT.get(name, ("", ""))
        out.append("| ≥ %g%% | `%s` | %s | %s |" % (pct, name, meaning, action))
    out += [
        "",
        "拦截的两条边界：**收缩写放行**（新体积 < 磁盘现有体积 ⟹ 裁剪正在生效，不自锁）；",
        "逃生舱 `GK_STATE_WALL_BLOCK=0`（显式放行，留 stderr 痕迹）。",
        "",
        "**三条腿**（各自独立的裁剪线，按墙的比例定价，各 5%、合计 15%，留 85% 给其余字段）：",
        "",
        "| 腿 | 落点 | 比例 | 值 | 越线动作 |",
        "|:--|:--|:--|:--|:--|",
        "| `subagent_history` | `gatekeeper-cli.sh` `_HIST_MAX_BYTES` | 5%% | %d KB | 最旧条目出窗 → 落 history 片 |"
        % (d["hist"] // 1024),
        "| `task_pipeline` | `gk_json_utils.TASK_PIPE_MAX_BYTES` | 5%% | %d KB | 已决条目出窗 → 落 pipeline 片 |"
        % (d["pipe"] // 1024),
        "| `ecc_findings` | `gk_json_utils.ECC_MAX_BYTES` | 5%% | %d KB | closed 可归档；open 超 `ECC_MAX_OPEN(%d)` 就地溢出 |"
        % (d["ecc"] // 1024, d["open"]),
        "",
        "另两个计数轴：`ECC_MAX_ENTRIES=%d`、`ECC_MAX_OPEN=%d`。运维覆盖口：`GK_STATE_TRIM_KB=<KB>`"
        % (d["entries"], d["open"]),
        "（只覆盖 history 腿，不改源码）。",
        _WALL_END,
    ]
    return "\n".join(out)


def _doc_blocks(sd: Path) -> list:
    facts = render(collect(str(sd)))
    st = collect_state(sd)
    return [
        (DOCS[0], _START, _END, facts, "GK-FACTS"),
        (DOCS[1], _START, _END, facts, "GK-FACTS"),
        (_README, _RSTART, _REND, render_refs(sd), "GK-REFS"),
        (_STATE_DOC, _CAP_START, _CAP_END, render_state_cap(st), "GK-CAP"),
        (_STATE_DOC, _WALL_START, _WALL_END, render_state_wall(st), "GK-WALL"),
    ]


def _replace_block(text: str, block: str, start: str = _START, end: str = _END,
                   label: str = "GK-FACTS") -> str:
    if start not in text or end not in text:
        raise ValueError("缺少 %s 标记" % label)
    pre, rest = text.split(start, 1)
    _, post = rest.split(end, 1)
    return pre + block + post


def write(skill_dir: str = "") -> dict:
    sd = Path(skill_dir) if skill_dir else _SKILL_DIR
    changed = []
    for rel, start, end, block, label in _doc_blocks(sd):
        p = sd / rel
        text = _read(p)
        new = _replace_block(text, block, start, end, label)
        if new != text:
            p.write_text(new, encoding="utf-8")
            if rel not in changed:
                changed.append(rel)
    return {"ok": True, "changed": changed}


def check(skill_dir: str = "") -> dict:
    """doc-align 消费面：事实块（2 份）+ README 索引 + state 容量/水位表必须与活文件一致。"""
    sd = Path(skill_dir) if skill_dir else _SKILL_DIR
    bad = []
    try:
        blocks = _doc_blocks(sd)
    except (OSError, ValueError, KeyError) as e:
        return {"check": "gk_facts", "status": "FAIL",
                "detail": "生成源不可用: %s: %s" % (type(e).__name__, e)}
    for rel, start, end, block, label in blocks:
        try:
            text = _read(sd / rel)
            if _replace_block(text, block, start, end, label) != text:
                bad.append("%s: %s 块与活文件不一致（跑 gk_docgen_facts.py --write）" % (rel, label))
        except (OSError, ValueError) as e:
            bad.append("%s: %s" % (rel, e))
    return {"check": "gk_facts", "status": "FAIL" if bad else "PASS",
            "detail": "; ".join(bad) if bad else "事实块 ×2 + README 索引 + state 容量/水位表一致"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("cmd", nargs="?", default="print")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--skill-dir", default="")
    a = ap.parse_args(argv)
    try:
        if a.write or a.cmd == "write":
            out = write(a.skill_dir)
        elif a.cmd == "check":
            out = check(a.skill_dir)
        else:
            print(render(collect(a.skill_dir)))
            return 0
    except (OSError, ValueError) as e:
        out = {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0 if out.get("ok") or out.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
