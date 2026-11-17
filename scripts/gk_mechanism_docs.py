#!/usr/bin/env python3
"""gk_mechanism_docs.py — 机制正本闸（2026-11-16）。

病象
====
v0.10.0 之前的 260 个提交里，工作目录池 / 合并闸 / 发布管线 / 审计生命周期四个机制
**没有任何对外正本文档**；此后补写的四份文档如果只靠人维护，机制一改就会静默滞后——
这正是 `gk_docgen_facts.py` 当初要解决的问题（手写数字必漂移）。

判据（确定性、零网络）
======================
1. **登记即闭环**：`references/mechanism-registry.json` 登记的每个机制，其正本文档必须带
   `<!-- GK-MECH:START id=… -->` 事实块；块内容由本脚本从活代码重新派生：
   入口脚本 / 公开函数数 / CLI 入口 / 测试清单 / 校验命令。漂移即红。
2. **新增即登记**：`--from <tag>..HEAD` 新增的 `scripts/gk_*.py` 必须落在某个机制的
   入口清单里，否则补正本或在 `coverage.waivers` 写明理由（带 reason，禁静默放过）。
   仅私仓生效（判据与 C4 同源：`docs/` 是否随包），公开镜像的单提交历史不参与。

用法
====
  python scripts/gk_mechanism_docs.py --write          # 重写四份正本的事实块（幂等）
  python scripts/gk_mechanism_docs.py --check --json   # 漂移/缺登记即 rc=1
  python scripts/gk_mechanism_docs.py --check --id merge-gate --json
"""
import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_REGISTRY = "references/mechanism-registry.json"
_START = "<!-- GK-MECH:START id=%s（由 scripts/gk_mechanism_docs.py 生成，勿手改） -->"
_END = "<!-- GK-MECH:END id=%s -->"
_DEF_RX = re.compile(r"(?m)^def ([A-Za-z][A-Za-z0-9_]*)\s*\(")
_CLI_RX = r"(?m)^_CMD_REG\[%s\]="
_CASE_RX = r"(?m)^\s{2}%s\)"


def block_start(mech_id: str) -> str:
    return _START % mech_id


def block_end(mech_id: str) -> str:
    return _END % mech_id


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def load_registry(skill_dir=None) -> dict:
    """读登记表；结构错误直接抛 ValueError（fail-closed，不猜默认值）。"""
    sd = Path(skill_dir) if skill_dir else ROOT
    p = sd / _REGISTRY
    d = json.loads(_read(p))
    if not isinstance(d, dict) or not isinstance(d.get("mechanisms"), list):
        raise ValueError("%s 缺 mechanisms 列表" % _REGISTRY)
    return d


def _public_funcs(p: Path) -> list:
    names = _DEF_RX.findall(_read(p))
    return [n for n in names if not n.startswith("_")]


def _stem_label(rel: str) -> str:
    """`scripts/gk_demo_a.py` → `a`（去掉 `gk_` 前缀与扩展名，便于紧凑展示）。"""
    s = Path(rel).stem
    return s[3:] if s.startswith("gk_") else s


def _cli_registered(sd: Path, key: str) -> bool:
    try:
        text = _read(sd / "gatekeeper-cli.sh")
    except OSError:
        return False
    return bool(re.search(_CLI_RX % re.escape(key), text)
                or re.search(_CASE_RX % re.escape(key), text))


def render_block(mech: dict, skill_dir=None) -> str:
    """把一个机制的事实块从**活文件**派生出来（禁手写数字）。"""
    sd = Path(skill_dir) if skill_dir else ROOT
    mid = str(mech.get("id") or "")
    eps = [str(x) for x in (mech.get("entrypoints") or [])]
    counts = [(Path(e).name, len(_public_funcs(sd / e))) for e in eps]
    total = sum(n for _, n in counts)
    eps_txt = " · ".join("`%s`" % Path(e).name for e in eps) or "—"
    # 公开函数数：总数 + 每个入口的细分（细分名取去掉 `gk_` 的短名，便于一行读完）
    detail = " / ".join("%s %d" % (_stem_label(e), n) for e, (_, n) in zip(eps, counts))
    cli = [str(x) for x in (mech.get("cli") or [])]
    tests = [str(x) for x in (mech.get("tests") or [])]
    rows = [
        ("入口脚本", eps_txt, "`%s`" % _REGISTRY),
        ("公开函数", "%d（%s）" % (total, detail) if detail else str(total),
         "`^def <name>` 计数（入口脚本合计）"),
        ("CLI 入口", " · ".join("`%s`" % c for c in cli) or "—",
         "`gatekeeper-cli.sh`（`_CMD_REG` 或早期 case 分派）"),
        ("测试", " · ".join("`%s`" % t for t in tests) or "—", "`scripts/`"),
        ("校验", "`python scripts/gk_mechanism_docs.py --check --id %s`" % mid, "本闸自身"),
    ]
    out = [block_start(mid), "| 事实 | 值 | 来源（可复算） |", "|:--|:--|:--|"]
    out += ["| %s | %s | %s |" % r for r in rows]
    out.append(block_end(mid))
    return "\n".join(out)


def _replace_block(text: str, block: str, mid: str) -> str:
    s, e = block_start(mid), block_end(mid)
    if s not in text or e not in text:
        raise ValueError("缺少 GK-MECH 标记（id=%s）" % mid)
    pre, rest = text.split(s, 1)
    _, post = rest.split(e, 1)
    return pre + block + post


def _git_added(sd: Path, from_ref: str, pattern: str) -> list:
    """`from_ref..HEAD` 新增的脚本（仅私仓；无 git / 无 docs 时返回空）。"""
    if not from_ref or not (sd / "docs").is_dir():
        return []
    try:
        p = subprocess.run(["git", "-C", str(sd), "diff", "--name-only", "--diff-filter=A",
                            "%s..HEAD" % from_ref, "--", pattern],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return []
    if p.returncode != 0:
        return []
    return [x.strip() for x in (p.stdout or "").splitlines() if x.strip()]


def _waivers(reg: dict) -> tuple:
    """→ `(patterns, issues)`；缺 reason 的豁免必须报错（规则本身也受闸管）。"""
    entries = ((reg.get("coverage") or {}).get("waivers") or [])
    pats, issues = [], []
    for e in entries:
        if not isinstance(e, dict) or not str(e.get("pattern") or "").strip():
            issues.append("coverage.waivers 条目缺 pattern：%r" % (e,))
            continue
        if not str(e.get("reason") or "").strip():
            issues.append("coverage.waivers 条目 %s 缺 reason（禁静默放过）" % e.get("pattern"))
            continue
        pats.append(str(e["pattern"]))
    return pats, issues


def check(skill_dir=None, from_ref: str = "", added=None, only: str = "") -> dict:
    sd = Path(skill_dir) if skill_dir else ROOT
    issues, checks = [], []
    try:
        reg = load_registry(sd)
    except (OSError, ValueError) as e:
        return {"ok": False, "checks": [], "issues": ["登记表不可用：%s: %s" % (type(e).__name__, e)]}
    mechs = [m for m in reg["mechanisms"] if isinstance(m, dict)]
    if not only:
        ids = [str(m.get("id") or "") for m in mechs]
        if len(set(ids)) != len(ids):
            issues.append("机制 id 重复：%s" % ids)
        if not ids or any(not i for i in ids):
            issues.append("机制 id 不得为空")
    covered = {str(e) for m in mechs for e in (m.get("entrypoints") or [])}
    for m in mechs:
        mid = str(m.get("id") or "")
        if only and mid != only:
            continue
        doc = str(m.get("doc") or "")
        rel = [str(x) for x in (m.get("entrypoints") or [])]
        for f in rel:
            if not (sd / f).is_file():
                issues.append("[%s] 入口脚本缺失：%s" % (mid, f))
        for t in [str(x) for x in (m.get("tests") or [])]:
            if not (sd / t).is_file():
                issues.append("[%s] 测试文件缺失：%s" % (mid, t))
        for key in [str(x) for x in (m.get("cli") or [])]:
            if not _cli_registered(sd, key):
                issues.append("[%s] CLI 入口未在 gatekeeper-cli.sh 注册：%s" % (mid, key))
        if not doc or not (sd / doc).is_file():
            issues.append("[%s] 正本文档缺失：%s" % (mid, doc or "（未声明）"))
            continue
        text = _read(sd / doc)
        if block_start(mid) not in text or block_end(mid) not in text:
            issues.append("[%s] %s 缺 GK-MECH 标记（运行 --write 生成）" % (mid, doc))
            continue
        try:
            fresh = render_block(m, sd)
        except OSError as e:
            issues.append("[%s] 事实块无法派生：%s" % (mid, e))
            continue
        if _replace_block(text, fresh, mid) != text:
            issues.append("[%s] %s 的 GK-MECH 块与活代码不一致（跑 --write）" % (mid, doc))
        checks.append({"id": mid, "doc": doc, "entrypoints": len(rel)})
    if not only:
        pats, wissues = _waivers(reg)
        issues.extend(wissues)
        pattern = str((reg.get("coverage") or {}).get("glob") or "scripts/gk_*.py")
        if added is None:
            added = _git_added(sd, from_ref, pattern) if from_ref else []
        for f in added:
            if f in covered or any(fnmatch.fnmatchcase(f, p) for p in pats):
                continue
            issues.append("新增脚本未登记机制正本：%s（补 registry 入口，或写 waiver + reason）" % f)
    return {"ok": not issues, "checks": checks, "issues": issues}


def write(skill_dir=None) -> dict:
    sd = Path(skill_dir) if skill_dir else ROOT
    reg = load_registry(sd)
    changed = []
    for m in reg["mechanisms"]:
        mid = str(m.get("id") or "")
        doc = str(m.get("doc") or "")
        p = sd / doc
        if not doc or not p.is_file():
            raise ValueError("[%s] 正本文档缺失：%s" % (mid, doc or "（未声明）"))
        text = _read(p)
        new = _replace_block(text, render_block(m, sd), mid)
        if new != text:
            p.write_text(new, encoding="utf-8")
            if doc not in changed:
                changed.append(doc)
    return {"ok": True, "changed": changed}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_mechanism_docs.py")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--id", default="", help="只校验单个机制（事实块内展示的校验命令用）")
    ap.add_argument("--from", dest="from_ref", default="", help="覆盖度区间起点（私仓生效）")
    ap.add_argument("--skill-dir", default="")
    ap.add_argument("--json", action="store_true")
    ns = ap.parse_args(argv)
    try:
        if ns.write:
            out = write(ns.skill_dir)
        else:
            out = check(ns.skill_dir, from_ref=ns.from_ref, only=ns.id)
    except (OSError, ValueError) as e:
        out = {"ok": False, "issues": ["%s: %s" % (type(e).__name__, e)], "checks": []}
    if ns.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        for i in out.get("issues") or []:
            print("FAIL " + i)
        print("OK" if out.get("ok") else "NOT OK")
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
