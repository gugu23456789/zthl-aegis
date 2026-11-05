#!/usr/bin/env python3
"""gk_repo_index.py — 仓库索引生成器（`FILES.md` + `llms.txt`）。

为什么存在（2026-11-05）
========================
GitHub 移动端**没有** "Go to file"（桌面才有），目录树懒加载，深层文件要点很多次；
抓取工具（WebFetch 类）拿到的常是 JS 壳而不是文件正文。两条低成本对策：
  1. `FILES.md`：全量**公开面**文件地图（路径 + 一句说明 + 直达链接）⟹ 移动端点一次就到；
  2. `llms.txt`：按 llmstxt.org 约定的**精选索引**（标题 + 链接 + 摘要）⟹ 抓取端一次请求拿全。

纪律
====
- **确定性**：无时间戳、按 posix 路径排序；同输入必同输出（`--check` 才有意义）。
- **先 `git add` 新文件，再 `--write`**：文件集取自 `git ls-files`（只看已跟踪）；
  未跟踪的新文件不会进索引 ⟹ 本地绿、CI 红（2026-11-05 实测）。导出树无 git，走目录遍历。
- **只描述公开面**：私仓生成时经 `oss_scrub.is_excluded` 过滤；导出树没有该模块 ⟹ 全量文件
  本身就是公开面。两棵树各自自洽，导出时重生成（与 GK-FACTS 同款做法）。
- **描述来源**：`references/repo-index-annotations.json` 手工注 → md 首个 H1 →
  py 模块 docstring 首行 → 后缀标签。禁 LLM 摘要（不可复算）。

CLI
===
  python3 scripts/gk_repo_index.py --write    # 生成/刷新 FILES.md + llms.txt
  python3 scripts/gk_repo_index.py --check    # 漂移检查（0=一致，1=有漂移）
  python3 scripts/gk_repo_index.py --json     # 报告（不写盘）

stdlib only；不联网；不写私仓以外的东西。
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

ROOT = Path(HERE).parent
FILES_MD = "FILES.md"
LLMS_TXT = "llms.txt"
ANNOTATIONS = "references/repo-index-annotations.json"
_SKIP_DIRS = {".git", "__pycache__", "dist", ".venv", ".venv-accept", "node_modules", ".pytest_cache"}
_SKIP_EXT = {".pyc", ".pyo", ".zip"}
_HIDDEN_SKIP = {".gitignore", ".gitattributes"}
# 生成物自身不进「输入文件集」（否则首次写入后集合变化 ⟹ 自我漂移，`--check` 永不收敛）。
_SELF = {FILES_MD, LLMS_TXT}
_TITLE = "ZTHL Aegis (智御)"
_TAGLINE = "面向 AI 辅助软件工程的确定性治理层：门禁 + 阶段推进 + 审计/红队 + 证据留痕。"


def _is_excluded(rel: str) -> bool:
    """私仓：按导出白名单过滤；导出树无 `oss_scrub` ⟹ 全量即公开面。"""
    try:
        import oss_scrub as S  # noqa: WPS433 — 导出树里不存在，ImportError 即降级
        return bool(S.is_excluded(rel))
    except Exception:  # noqa: BLE001 — 边界：无该模块 = 公开树
        return False


def iter_files(root: Path = ROOT) -> list:
    """公开面文件列表（posix 相对路径，排序）。git 可用走索引，否则遍历目录。"""
    rels = []
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files"],
                             capture_output=True, text=True, timeout=30)
        if out.returncode == 0 and out.stdout.strip():
            rels = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
    except (OSError, subprocess.SubprocessError):
        rels = []
    if not rels:                                    # 导出树 / 无 git
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
            for name in filenames:
                p = Path(dirpath) / name
                rels.append(p.relative_to(root).as_posix())
    keep = []
    for rel in rels:
        if any(part in _SKIP_DIRS for part in rel.split("/")):
            continue
        if Path(rel).suffix.lower() in _SKIP_EXT:
            continue
        if rel in _HIDDEN_SKIP or rel in _SELF:
            continue
        if _is_excluded(rel):
            continue
        if not (root / rel).is_file():
            continue
        keep.append(rel)
    return sorted(set(keep))


def load_annotations(root: Path = ROOT) -> dict:
    p = root / ANNOTATIONS
    if not p.is_file():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    items = d.get("files") if isinstance(d, dict) else None
    return {k: str(v) for k, v in (items or {}).items() if str(v).strip()}


def _first_line(text: str) -> str:
    for ln in text.splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("<!--"):
            return ln
    return ""


def _redact(desc: str) -> str:
    """描述里若含**反查词表**中的词 ⟹ 丢弃（改用后缀标签）。

    2026-11-05 实测：`scripts/gk_moa_kappa.py` 的 docstring 含 MoA 污染记号（希腊字母 kappa
    的完整写法见私仓词表；该文件本身有文件×词豁免），但聚合进 FILES.md 后没有豁免
    ⟹ 导出被 OS-7 拒发。生成物不应成为豁免词的第二出口 ⟹ 命中即降级，不引入新豁免。
    """
    if not desc:
        return desc
    try:
        import oss_scrub as S
        terms = S.load_forbidden_terms(str(ROOT / "docs" / "oss" / "forbidden-terms.txt"))
        if terms and S.find_forbidden(desc, terms):
            return ""
    except Exception:  # noqa: BLE001 — 导出树无 oss_scrub / 无私仓词表 ⟹ 不红减
        pass
    return desc


def describe(root: Path, rel: str, annotations: dict = None) -> str:
    """一句说明（手工注 > md H1 > py docstring 首行 > 后缀）。**确定性**（无 LLM）。"""
    ann = annotations if annotations is not None else load_annotations(root)
    if rel in ann:
        return _redact(ann[rel]) or _fallback_desc(rel)
    p = root / rel
    suffix = p.suffix.lower()
    try:
        if suffix == ".md":
            text = p.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"^#\s+(.+?)\s*$", text, re.M)
            if m:
                got = _redact(m.group(1).strip())
                if got:
                    return got
        elif suffix == ".py":
            text = p.read_text(encoding="utf-8", errors="replace")
            m = re.match(r'^\s*(?:[rubf]{0,2})"""(.+?)(?:"""|\n)', text, re.S)
            if m:
                line = _first_line(m.group(1))
                got = _redact(line[:80])
                if got:
                    return got
    except OSError:
        pass
    return _fallback_desc(rel)


def _fallback_desc(rel: str) -> str:
    suffix = Path(rel).suffix.lower()
    return {
        ".py": "Python 模块", ".sh": "Shell 脚本", ".json": "JSON 数据",
        ".yml": "CI 配置", ".yaml": "YAML 配置", ".txt": "文本", ".toml": "配置",
        ".cfg": "配置", ".html": "HTML", ".css": "样式", ".js": "JavaScript",
    }.get(suffix, "文件" if "." in Path(rel).name else "无后缀文件")


def render_files_md(files: list, descs: dict) -> str:
    lines = [
        "# 文件地图（自动生成，勿手改）",
        "",
        "> 生成器：`scripts/gk_repo_index.py --write`；漂移由 "
        "`gk_release_preflight.py` 的 `repo_index` 项守。",
        "> 用途：**移动端**（GitHub App 没有 “Go to file”）与抓取工具一次拿到全量路径；"
        "点路径直达文件。",
        "",
        "**共 %d 个文件。**" % len(files),
        "",
        "## 索引生成物",
        "",
        "- [%s](%s) — 全量文件地图（本页）" % (FILES_MD, FILES_MD),
        "- [%s](%s) — 抓取友好索引（llmstxt.org 约定）" % (LLMS_TXT, LLMS_TXT),
        "",
    ]
    groups = {}
    for rel in files:
        head = rel.split("/", 1)[0] if "/" in rel else "根目录"
        groups.setdefault(head if "/" in rel else "根目录", []).append(rel)
    order = ["根目录"] + sorted(g for g in groups if g != "根目录")
    for g in order:
        lines.append("## %s" % (g if g == "根目录" else g + "/"))
        lines.append("")
        for rel in groups[g]:
            lines.append("- [%s](%s) — %s" % (rel, rel, descs.get(rel, "文件")))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_llms(files: list, descs: dict, annotated: set = frozenset()) -> str:
    """精选索引：根级 md + references/*.md + 有手工注的脚本/配置。"""
    picked = []
    for rel in files:
        if rel in annotated:
            picked.append(rel)
        elif rel.endswith(".md") and "/" not in rel:
            picked.append(rel)
        elif rel.startswith("references/") and rel.endswith(".md"):
            picked.append(rel)
    picked = sorted(set(picked))
    lines = ["# %s" % _TITLE, "", "> %s" % _TAGLINE, ""]
    docs = [r for r in picked if r.endswith(".md")]
    others = [r for r in picked if not r.endswith(".md")]
    if docs:
        lines += ["## 文档", ""]
        lines += ["- [%s](%s): %s" % (r, r, descs.get(r, "文档")) for r in docs]
        lines.append("")
    if others:
        lines += ["## 关键入口", ""]
        lines += ["- [%s](%s): %s" % (r, r, descs.get(r, "入口")) for r in others]
        lines.append("")
    lines += ["## 全量文件", "", "- [%s](%s): 全部公开面文件（路径 + 一句说明）"
              % (FILES_MD, FILES_MD), ""]
    return "\n".join(lines).rstrip() + "\n"


def build(root: Path = ROOT) -> dict:
    files = iter_files(root)
    ann = load_annotations(root)
    descs = {rel: describe(root, rel, ann) for rel in files}
    return {"files": files, "descs": descs,
            FILES_MD: render_files_md(files, descs),
            LLMS_TXT: render_llms(files, descs, set(ann))}


def write(root: Path = ROOT) -> list:
    data = build(root)
    changed = []
    for name in (FILES_MD, LLMS_TXT):
        p = root / name
        new = data[name]
        old = p.read_text(encoding="utf-8") if p.is_file() else None
        if old != new:
            p.write_text(new, encoding="utf-8")
            changed.append(name)
    return changed


def check(root: Path = ROOT) -> dict:
    data = build(root)
    issues = []
    for name in (FILES_MD, LLMS_TXT):
        p = root / name
        if not p.is_file():
            issues.append("%s 缺失" % name)
            continue
        if p.read_text(encoding="utf-8") != data[name]:
            issues.append("%s 漂移（跑 `--write` 刷新）" % name)
    return {"ok": not issues, "files": len(data["files"]), "issues": issues}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_repo_index.py")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.write:
        changed = write()
        print(json.dumps({"ok": True, "changed": changed, "files": len(iter_files())},
                         ensure_ascii=False) if a.json else
              ("REPO-INDEX OK — changed=%s" % (",".join(changed) or "none")))
        return 0
    r = check()
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print("REPO-INDEX %s — files=%d%s" % (
            "OK" if r["ok"] else "DRIFT", r["files"],
            "" if r["ok"] else "；" + "；".join(r["issues"])))
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
