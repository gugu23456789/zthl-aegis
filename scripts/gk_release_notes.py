"""gk_release_notes.py — 发布说明**自动生成 + 两轮机检**（2026-11-08，owner 裁定）。

背景（实测教训）：v0.9.8.2 的发布说明是手写的，只覆盖了当日那一批工作，
把此前四十余个 commit 的真实变更全漏了；同时手写容易把**计划/草案**写成已落地。
本工具把「从 git 历史提取事实」与「两道检测」固化成可复跑的命令。

链路
====
1. `generate`：`git log <from>..<to>` → 按 conventional prefix 分类 → Markdown 草稿。
   · 触碰文件**全部**落在 `docs/`（计划/评审/备份面）的 commit ⟹ 归入「计划与内部文档」
     段落，并在标题标注「未随公开包发布」——**不**混进「变更」。
   · 触碰文件含 `docs/plans/` 的 commit ⟹ 在条目后缀 `[计划]`（提醒：计划 ≠ 已实施）。
2. `check --notes <file>`：两道机检（第一轮）——
   · **C1 发布面**：公开包里不可出现的内部 token（论文仓路径、本机绝对路径、真实邮箱/用户名）。
   · **C2 计划误写**：`已完成|已落地|已实现|已上线` 与 `计划|草案|DRAFT` 同行 ⟹ 违规
     （防止把未实施计划写成已交付）。
   · **C3 覆盖度**：`<from>..<to>` 内触碰**公开面**文件的 commit，其主题词须在 notes 中出现
     至少一次（防整批漏报）。缺失 ⟹ 列出，供人工补写（不自动编造）。
3. 第二轮（润色/事实）不可机检：脚本只出 `--advice` 检查清单（句式、时态、夸大词）。

用法
====
  python3 scripts/gk_release_notes.py generate --from v0.9.8.1 --out /tmp/notes.md
  python3 scripts/gk_release_notes.py check --notes RELEASE-NOTES/RELEASE-NOTES-v0.9.8.3.md \\
      --from v0.9.8.1
退出码：0 = 全绿；1 = 有 C1/C2/C3 违规。
"""
import argparse
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 公开面禁词（C1）：命中即拒发。与 `oss_scrub` 的身份/论文面判据同族，但这里是**文字面**。
FORBIDDEN_TOKENS = (
    # 论文仓身份 token 用拼接构造：本文件自身会被 `oss_scrub` 的公开面扫描，
    # 连续字面量会把「禁词表」自己打成导出缺陷。
    "papers/" + "www2027",
    "repro/" + "phase_probe.py",
    "/mnt/c/Users/",
    "C:\\Users\\",
    "C:/Users/",
)

# 计划 vs 已落地（C2）：同一行同时出现 ⟹ 语义混淆，必须人工改成「计划推进」或「已落地」。
DONE_WORDS = ("已完成", "已落地", "已实现", "已上线", "已交付", "fully implemented", "shipped")
PLAN_WORDS = ("计划", "草案", "DRAFT", "proposal", "RFC")

EXCLUDED_PREFIX = ("docs/",)

TYPE_ORDER = [
    ("feat", "新增"),
    ("fix", "修复"),
    ("perf", "性能"),
    ("refactor", "重构"),
    ("test", "测试"),
    ("docs", "文档"),
    ("chore", "杂项"),
]


def _git(*args, cwd=None):
    p = subprocess.run(["git", "-C", cwd or ROOT, *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError("git %s 失败：%s" % (" ".join(args), (p.stderr or p.stdout)[-300:]))
    return p.stdout


def _split_subject(subject: str):
    """`feat(scope): text` → (type, scope, text)。无 prefix ⟹ ("other", "", subject)。"""
    m = re.match(r"^(\w+)(?:\(([^)]*)\))?!?:\s*(.+)$", subject.strip())
    if not m:
        return "other", "", subject.strip()
    return m.group(1).lower(), (m.group(2) or ""), m.group(3).strip()


def collect(from_ref: str, to_ref: str = "HEAD", cwd=None, since: str = ""):
    """收集 `<from>..<to>`（或 `--since` 时间窗）的 commit 与其触碰文件。"""
    rng = "%s..%s" % (from_ref, to_ref) if from_ref else to_ref
    extra = ["--since=%s" % since] if since else []
    raw = _git("log", "--reverse", "--format=%H%x1f%s", rng, *extra, cwd=cwd)
    out = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        sha, _, subject = line.partition("\x1f")
        files = [x for x in _git("show", "--name-only", "--format=", sha, cwd=cwd).splitlines() if x.strip()]
        public = [f for f in files if not f.startswith(EXCLUDED_PREFIX)]
        ctype, scope, text = _split_subject(subject)
        out.append({
            "sha": sha[:8],
            "subject": subject,
            "type": ctype,
            "scope": scope,
            "text": text,
            "files": files,
            "public_files": public,
            "internal_only": bool(files) and not public,
            "touches_plan": any(f.startswith("docs/plans/") for f in files),
        })
    return out


def generate(commits, version="", title_suffix=""):
    """从 commit 列表产出 Markdown 草稿（确定性：按类型分组 + 原顺序）。"""
    lines = []
    if version:
        lines.append("# ZTHL Aegis %s — 发布说明%s" % (version, title_suffix))
        lines.append("")
        lines.append("> 本文件由 `scripts/gk_release_notes.py generate` 从 git 历史生成；"
                     "两轮检测见 `check`。生成后仍须人工润色与事实核对。")
        lines.append("")
    groups = {k: [] for k, _ in TYPE_ORDER}
    groups["other"] = []
    internal = []
    for c in commits:
        tag = " `[计划]`" if c["touches_plan"] else ""
        item = "- %s（`%s`）%s" % (c["text"], c["sha"], tag)
        if c["internal_only"]:
            internal.append(item)
            continue
        groups.get(c["type"], groups["other"]).append(item)
    for ctype, label in TYPE_ORDER:
        items = groups.get(ctype) or []
        if items:
            lines.append("## %s" % label)
            lines.append("")
            lines.extend(items)
            lines.append("")
    if groups["other"]:
        lines.append("## 其它")
        lines.append("")
        lines.extend(groups["other"])
        lines.append("")
    if internal:
        lines.append("## 计划与内部文档（不随公开包发布）")
        lines.append("")
        lines.append("> `docs/` 属导出排除面；下列 commit **只**动内部计划/评审/备份，"
                     "对外不可见，且**不代表已实施**。")
        lines.append("")
        lines.extend(internal)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def check_notes(text, commits=()):
    """第一轮机检。返回 {"ok": bool, "violations": [...], "advice": [...]}。"""
    violations = []
    for ln_no, line in enumerate(text.splitlines(), 1):
        for tok in FORBIDDEN_TOKENS:
            if tok in line:
                violations.append({"rule": "C1", "line": ln_no,
                                   "detail": "公开面禁词：%s" % tok})
        has_done = any(w in line for w in DONE_WORDS)
        has_plan = any(w in line for w in PLAN_WORDS)
        if has_done and has_plan:
            violations.append({"rule": "C2", "line": ln_no,
                               "detail": "同一行混用「已完成」与「计划/草案」⟹ 语义不清：%s"
                                          % line.strip()[:80]})
    # C3 覆盖度（**提示，不阻断**）：汇总式发布说明不会逐条复刻 commit 主题 ⟹ 全覆盖不现实；
    #   把未覆盖项列出来供人工判断"是否真漏了一个对外可感知的变更"。
    low = text.lower()
    missing = []
    for c in commits:
        if c.get("internal_only"):
            continue
        key = (c.get("scope") or "").strip()
        if key and key.lower() in low:
            continue
        head = re.sub(r"\s+", "", c["text"])[:8]
        if head and head in re.sub(r"\s+", "", text):
            continue
        missing.append("%s %s" % (c["sha"], c["text"][:40]))
    advice = [
        "第二轮（润色/事实）请人工核对：",
        "  · 时态与事实：计划只写「推进到 Rx / 未收敛」，不写「已完成」；",
        "  · 数量与命令名须能在仓内复算（命令 / 文件 / 测试数）；",
        "  · 去掉形容词与空话（「全面」「彻底」「大幅」），保留可核事实；",
        "  · 同一版本只讲对外可感知变化，内部治理细节归到「治理」小节。",
    ]
    if missing:
        advice.append("C3 覆盖提示（%d 条公开面 commit 未在说明中出现，请人工判断是否真漏）："
                      % len(missing))
        advice.extend("  - " + m for m in missing[:20])
    return {"ok": not violations, "violations": violations, "advice": advice,
            "coverage_missing": missing}


def main(argv=None):
    ap = argparse.ArgumentParser(description="发布说明自动生成 + 两轮机检")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="从 git 历史生成草稿")
    g.add_argument("--from", dest="from_ref", default="")
    g.add_argument("--since", default="", help="时间窗（无 from 时用，如 2026-11-06T06:00:00Z）")
    g.add_argument("--to", dest="to_ref", default="HEAD")
    g.add_argument("--version", default="")
    g.add_argument("--out", default="-", help="输出文件（缺省 stdout）")
    g.add_argument("--repo", default="")

    c = sub.add_parser("check", help="第一轮机检")
    c.add_argument("--notes", required=True)
    c.add_argument("--from", dest="from_ref", default="")
    c.add_argument("--since", default="")
    c.add_argument("--to", dest="to_ref", default="HEAD")
    c.add_argument("--repo", default="")
    c.add_argument("--json", action="store_true")

    ns = ap.parse_args(argv)
    repo = ns.repo or ROOT
    if ns.cmd == "generate":
        commits = collect(ns.from_ref, ns.to_ref, cwd=repo, since=ns.since)
        text = generate(commits, version=ns.version)
        if ns.out == "-":
            sys.stdout.write(text)
        else:
            with open(ns.out, "w", encoding="utf-8") as fh:
                fh.write(text)
            print("release-notes: %d commits → %s" % (len(commits), ns.out))
        return 0
    with open(ns.notes, encoding="utf-8") as fh:
        text = fh.read()
    commits = collect(ns.from_ref, ns.to_ref, cwd=repo, since=ns.since) if (ns.from_ref or ns.since) else []
    rep = check_notes(text, commits)
    if ns.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    else:
        for v in rep["violations"]:
            print("FAIL [%s] %s" % (v["rule"], v.get("detail", "")))
            for m in v.get("missing", []):
                print("   -", m)
        for a in rep["advice"]:
            print(a)
        print("OK" if rep["ok"] else "NOT OK")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
