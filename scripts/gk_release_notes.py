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
   · **三节自动填充**（2026-11-16 owner 裁定）：性能红利（基线口径 + 本版是否动机制脚本）、
     架构进化（机制登记表命中 + 新增文档/脚本面）、安全哲学（登记表不变式 + 代码锚点逐条验证）。
2. `check --notes <file>`：两道机检（第一轮）——
   · **C1 发布面**：公开包里不可出现的内部 token（论文仓路径、本机绝对路径、真实邮箱/用户名）。
   · **C2 计划误写**：`已完成|已落地|已实现|已上线` 与 `计划|草案|DRAFT` 同行 ⟹ 违规
     （防止把未实施计划写成已交付）。
   · **C3 覆盖度**：`<from>..<to>` 内触碰**公开面**文件的 commit，其主题词须在 notes 中出现
     至少一次（防整批漏报）。缺失 ⟹ 列出，供人工补写（不自动编造）。
   · **C4 数字回环**：声明的「N 个提交」必须等于 `上一版..本版` 实际数（仅私仓）。
   · **C5 安全锚点**：说明里的安全主张必须能在活代码里找到锚点（锚点失效即拦）。
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

# C4 数字回环：说明里唯一可机检的数量口径（「N 个提交」）
_COMMIT_COUNT_RE = re.compile(r"(\d+)\s*个提交")

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


# ── 自动填充三节（owner 2026-11-16）：性能红利 / 架构进化 / 安全哲学 ──────────────
# 纪律：三节只写**能从仓内文件复算**的事实；读不到就明说「不给数字」，禁编造。
_MECH_REG = os.path.join("references", "mechanism-registry.json")
_BENCH = os.path.join("references", "bench-baseline.json")


def _load_json(repo, rel):
    try:
        with open(os.path.join(repo, rel), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _changed(commits, prefix=""):
    out = set()
    for c in commits:
        for f in c.get("files") or []:
            if f.startswith(prefix):
                out.add(f)
    return out


def _perf_modules(repo):
    """性能面模块集（单源 = `gk_bench_compare._MECH_MODULES`；不可用时退到机制入口）。

    必须校验模块**来自本仓**：测试/同进程里已缓存另一份 `gk_bench_compare` 时，
    直接 `import` 会拿到外来单源 ⟹ 口径串仓（本臂 2026-11-17 实测踩中）。
    """
    try:
        import importlib
        sys.path.insert(0, os.path.join(repo, "scripts"))
        bc = importlib.import_module("gk_bench_compare")
        if not os.path.abspath(bc.__file__).startswith(os.path.abspath(repo) + os.sep):
            raise ImportError("foreign gk_bench_compare")
        return set(bc._MECH_MODULES)
    except Exception:  # noqa: BLE001 — 导出树/夹具无该模块 ⟹ 退到登记表入口
        reg = _load_json(repo, _MECH_REG)
        return {str(e) for m in reg.get("mechanisms") or []
                for e in (m.get("entrypoints") or [])}


def section_perf(commits, repo=ROOT):
    """性能红利：基线口径 + 本版是否动过**性能面机制模块**。没有改动就不吹「提升」。"""
    b = _load_json(repo, _BENCH)
    out = ["## 性能红利（自动生成）", ""]
    if not b:
        out += ["> 未读到 `references/bench-baseline.json` ⟹ 本节不给数字（须先采基线）。", ""]
        return out
    scen = {k: len((((b.get("benchmarks") or {}).get(k) or {}).get("scenarios") or []))
            for k in ("state", "gate", "satellite")}
    head = str(b.get("git_head") or "—")[:8]
    out += ["| 项 | 值 | 来源（可复算） |", "|:--|:--|:--|",
            "| 基线提交 | `%s` | `bench-baseline.json:git_head` |" % head,
            "| 场景数 | state %d / gate %d / satellite %d | 同上 `benchmarks.*.scenarios` |"
            % (scen["state"], scen["gate"], scen["satellite"]),
            "| 过期阈值 | %s（提交） | 同上 `stale_after_commits` |"
            % b.get("stale_after_commits", "—")]
    mods = _perf_modules(repo)
    hits = sorted(_changed(commits) & mods)
    out.append("")
    if not hits:
        out += ["本版未触碰**性能面机制模块**（`scripts/gk_json_utils.py` / `gk_state.py` / "
                "`gk_satellite.py` / `gk_state_patch.py` / `gk_state_wal.py` / "
                "`gk_write_claims.py` / `gatekeeper-cli.sh`）⟹ 性能红利 = **无变化**"
                "（既无提升也无退化）；基线可沿用，发布门只查「未退化」。", ""]
    else:
        out += ["本版触碰 **%d** 个性能面机制模块 ⟹ 发布前须按 "
                "`scripts/gk_bench_{state,gate,satellite}.py --full` 重采基线，"
                "并确认差异属有意变更而非退化。" % len(hits), ""]
        out += ["- `%s`" % f for f in hits]
        out.append("")
    return out


def _git_added_files(repo, from_ref, prefixes=("references/", "scripts/")):
    """`from_ref..HEAD` 新增文件（无 git / 无区间 ⟹ 空；不猜）。"""
    if not from_ref:
        return []
    try:
        p = subprocess.run(["git", "-C", str(repo), "diff", "--name-only",
                            "--diff-filter=A", "%s..HEAD" % from_ref, "--", *prefixes],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return []
    return [x.strip() for x in (p.stdout or "").splitlines() if x.strip()] if p.returncode == 0 else []


def section_arch(commits, repo=ROOT, from_ref=""):
    """架构进化：哪些机制被触碰（登记表口径）+ 新增的文档与脚本面。"""
    reg = _load_json(repo, _MECH_REG)
    changed = _changed(commits)
    out = ["## 架构进化（自动生成）", ""]
    mechs = reg.get("mechanisms") or []
    if not mechs:
        out += ["> 未读到机制登记表 ⟹ 本节只列文件面，不给机制结论。", ""]
    hits = []
    for m in mechs:
        eps = [str(x) for x in (m.get("entrypoints") or [])]
        touched = [f for f in eps if f in changed]
        if touched:
            hits.append((str(m.get("id")), str(m.get("doc")), touched))
    if mechs and not hits:
        out += ["登记机制的入口脚本**均未改动**（%d 个机制）⟹ 本版无机制面演进。" % len(mechs), ""]
    elif hits:
        out += ["| 机制 | 正本文档 | 触碰入口 |", "|:--|:--|:--|"]
        out += ["| `%s` | `%s` | %s |" % (i, d, " · ".join("`%s`" % os.path.basename(x) for x in t))
                for i, d, t in hits]
        out.append("")
    added = _git_added_files(repo, from_ref)
    docs = [f for f in added if f.startswith("references/")]
    codes = [f for f in added if f.startswith("scripts/") and not os.path.basename(f).startswith("test_")]
    if docs or codes:
        out += ["新增面（`%s..HEAD`：`references/` %d 份、`scripts/` %d 个）："
                % (from_ref, len(docs), len(codes)), ""]
        out += ["- `%s`" % f for f in (docs + codes)[:16]]
        out.append("")
    return out


def _anchor_ok(repo, rel, symbol):
    try:
        with open(os.path.join(repo, rel), encoding="utf-8", errors="replace") as fh:
            return bool(symbol) and symbol in fh.read()
    except OSError:
        return False


def section_security(repo=ROOT):
    """安全哲学：登记表里的不变式 + 逐条验证代码锚点（锚点失效必须显式暴露）。"""
    reg = _load_json(repo, _MECH_REG)
    invs = reg.get("security_invariants") or []
    out = ["## 安全哲学（自动生成）", ""]
    if not invs:
        out += ["> 未登记安全不变式 ⟹ 本节无内容（须在 `%s` 补 `security_invariants`）。"
                % _MECH_REG.replace(os.sep, "/"), ""]
        return out
    out += ["| 不变式 | 主张 | 代码锚点（逐条验证） |", "|:--|:--|:--|"]
    for it in invs:
        proof = it.get("proof") or {}
        rel, sym = str(proof.get("file") or ""), str(proof.get("symbol") or "")
        ok = _anchor_ok(repo, rel, sym)
        out.append("| `%s` | %s | %s `%s` |"
                   % (it.get("id"), it.get("claim"),
                      ("✅" if ok else "❌ 锚点缺失"), rel))
    out.append("")
    return out


def check_invariant_anchors(text, repo=ROOT):
    """C5：说明里出现某条安全主张时，它的代码锚点必须仍然存在（防「口号化」）。"""
    reg = _load_json(repo, _MECH_REG)
    bad = []
    for it in reg.get("security_invariants") or []:
        claim = str(it.get("claim") or "")
        if not claim or claim not in text:
            continue
        proof = it.get("proof") or {}
        if not _anchor_ok(repo, str(proof.get("file") or ""), str(proof.get("symbol") or "")):
            bad.append({"rule": "C5",
                        "line": text[:text.index(claim)].count("\n") + 1,
                        "detail": "安全主张缺代码锚点（%s: %s）：%s"
                                  % (proof.get("file"), proof.get("symbol"), claim[:40])})
    return bad


def generate(commits, version="", title_suffix="", repo="", from_ref="",
             sections=True):
    """从 commit 列表产出 Markdown 草稿（确定性：按类型分组 + 原顺序）。

    `sections=True` 时另出三节**自动填充**内容（owner 2026-11-16 裁定）：
    性能红利（取基线口径）/ 架构进化（取机制登记表 + 新增文件面）/ 安全哲学
    （取登记表的不变式，并逐个验证代码锚点）。
    """
    lines = []
    if version:
        lines.append("# ZTHL Aegis %s — 发布说明%s" % (version, title_suffix))
        lines.append("")
        lines.append("> 本文件由 `scripts/gk_release_notes.py generate` 从 git 历史生成；"
                     "两轮检测见 `check`。生成后仍须人工润色与事实核对。")
        lines.append("")
    if sections:
        repo = repo or ROOT
        lines += section_perf(commits, repo)
        lines += section_arch(commits, repo, from_ref)
        lines += section_security(repo)
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


def verify_commit_count(text, from_ref, to_ref, cwd=ROOT):
    """C4 数字回环校准：说明里声明的「N 个提交」必须等于 `git rev-list --count from..to`。

    病象（2026-11-16 实证）：v0.10.0 说明写「171 个提交」，实际 `v0.9.9..v0.10.0` = 246。
    C1/C2 只看措辞、C3 只看覆盖，**没有一条校验数字** ⟹ 手写口径漂移可以一路绿灯到发布。
    本函数把这句话变成可机检：声明值 ≠ 实测值即违规（阻断）。

    返回违规 dict 或 None（无声明 / git 不可用 / 数值相等）。
    """
    m = _COMMIT_COUNT_RE.search(text or "")
    if not m:
        return None
    claimed = int(m.group(1))
    try:
        p = subprocess.run(["git", "-C", str(cwd), "rev-list", "--count",
                            "%s..%s" % (from_ref, to_ref)],
                           capture_output=True, text=True, timeout=60)
        actual = int((p.stdout or "").strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if claimed == actual:
        return None
    return {"rule": "C4",
            "line": (text[:m.start()].count("\n") + 1),
            "detail": "提交数声明与实际不符：说明写 %d，实测 %s..%s = %d"
                      % (claimed, from_ref, to_ref, actual)}


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
    g.add_argument("--no-sections", action="store_true",
                   help="不自动填充 性能红利/架构进化/安全哲学 三节")

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
        text = generate(commits, version=ns.version, repo=repo,
                        from_ref=ns.from_ref, sections=not ns.no_sections)
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
    # C4 数字回环：`to` 优先取与说明同名的 tag（发布口径 = tag 所指提交），
    # 否则说明写完后主树再有提交就会把「N 个提交」算成 N+1 ⟹ 假红。
    to_ref = ns.to_ref
    mtag = re.search(r"RELEASE-NOTES-(v[\d.]+)\.md$", os.path.basename(ns.notes))
    if mtag and to_ref == "HEAD":
        if subprocess.run(["git", "-C", str(repo), "rev-parse", "--verify",
                           "refs/tags/" + mtag.group(1)],
                          capture_output=True).returncode == 0:
            to_ref = mtag.group(1)
    # C4 只在**私仓**生效：公开仓是过滤镜像（一次发布 = 一个 `release:` 提交），
    # `v0.9.9..v0.10.0` 只有几条，拿私有口径的「N 个提交」去比必然误判（2026-11-16 实测 CI 红）。
    # 判据与 `doc_align` 同源：`docs/` 是否随包 —— 公开树没有 `docs/`。
    if ns.from_ref and os.path.isdir(os.path.join(repo, "docs")):
        c4 = verify_commit_count(text, ns.from_ref, to_ref, cwd=repo)
        if c4:
            rep["violations"].append(c4)
            rep["ok"] = False
    # C5（2026-11-16）：安全哲学一节的主张必须有**活代码锚点**；锚点随代码改动失效即拦。
    for v in check_invariant_anchors(text, repo):
        rep["violations"].append(v)
        rep["ok"] = False
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
