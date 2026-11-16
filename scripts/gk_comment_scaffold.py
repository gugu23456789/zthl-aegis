#!/usr/bin/env python3
# gk_comment_scaffold.py — 注释骨架登记表的**唯一消费方**（2026-11-10）
# =============================================================================
# 定位：把「写注释」从**自由发挥**变成**选位置 → 填槽位 → 机检**。模版单一事实源 =
#   `references/comment-templates.json`（本模块**不内建第二份形态清单**，只读表）。
# 参照物 = 红先模版机制（`references/red-arm-templates.json` + `gk_red_arm_gen.py`）：
#   ① 登记表驱动：位置/形态/占位符全部可查，禁在别处另列名单；
#   ② 骨架先出：`scaffold` 返回带 `{占位符}` 的骨架，未填全时 `code` 为空（不伪装成品）；
#   ③ 事后回环：`check` 扫已落盘注释（锚点日期/裸 TODO/what 注释/未填槽位/块长/比例），
#      新形态必须「真实用进文件 + check 无 ERROR」才允许 `promote` 回灌并 version+1。
#
# 用法（确定性、0 API、只读登记表）：
#   python3 scripts/gk_comment_scaffold.py list
#   python3 scripts/gk_comment_scaffold.py show anchor-line
#   python3 scripts/gk_comment_scaffold.py render anchor-line date=2026-11-10 id=R7.7 \
#       what=... why=... delta=0 evidence=...
#   python3 scripts/gk_comment_scaffold.py classify "修事故判据" --position incident
#   python3 scripts/gk_comment_scaffold.py scaffold "修事故判据" --position incident
#   python3 scripts/gk_comment_scaffold.py check scripts/gk_finding.py [--changed-only] [--strict]
#   python3 scripts/gk_comment_scaffold.py promote draft.json --file scripts/x.py
#
# 契约（fail-loud，不静默）：未知 id / 缺占位符 / 多余键 / 渲染残留 / 登记表非法 → JSON
#   `{"ok":false,"error":...}` exit 2；`check` 有 ERROR → exit 1（WARN/INFO 不阻断，除非 --strict）。
import argparse
import json
import os
import re
import subprocess
import sys
import tokenize
from datetime import date
from io import StringIO
from pathlib import Path

_SKILL_DIR = Path(__file__).resolve().parent.parent
_REGISTRY = _SKILL_DIR / "references" / "comment-templates.json"
_PH_RE = re.compile(r"\{[A-Za-z0-9_]+\}")
_ANCHOR_RE = re.compile(r"^\s*(?:#+|//)\s*(20\d{2}-\d{2}-\d{2})\b")
_ID_RE = re.compile(
    r"\b(?:R-?\d+(?:\.\d+)?|ECO-[A-Z0-9]+|ECC-[A-Z0-9]+|W2A-[A-Z0-9]+|"
    r"STD-[A-Z]+|F\d+(?:\.\d+)?|[A-Z]{2,5}-\d{2,}[A-Za-z0-9]*)\b")
_TODO_RE = re.compile(r"^\s*(?:#+|//)\s*TODO\b(?!\s*\()")
_WHAT_RE = re.compile(r"^\s*(?:#+|//)\s*(设置|遍历|循环|定义|返回|获取|读取|打印|初始化)")
_VAGUE_RE = re.compile(r"(注意|务必|小心)")
_RESIDUAL_RE = re.compile(
    r"\{(%s)\}" % "|".join(("date", "id", "why", "boundary", "evidence", "delta",
                            "what", "symbol", "file", "purpose", "input", "output",
                            "failure", "task", "trigger", "risk")))
_INCIDENT_KW = ("事故", "根因", "判据", "防线", "复盘")


# ───────────────────────────── 登记表 ─────────────────────────────
def load_registry(path: str = "") -> dict:
    p = Path(path) if path else _REGISTRY
    if not p.is_file():
        raise ValueError("注释骨架登记表缺失: " + str(p))
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data.get("templates"), list) or not data["templates"]:
        raise ValueError("登记表结构非法（缺 templates）: " + str(p))
    return data


def template_ids(reg: dict = None) -> list:
    """全部模版 id（唯一来源 = 登记表；禁在别处再列一份名单）。"""
    reg = reg if reg is not None else load_registry()
    return [str(t.get("id") or "") for t in reg["templates"]]


def get_template(tid: str, reg: dict = None) -> dict:
    reg = reg if reg is not None else load_registry()
    for t in reg["templates"]:
        if str(t.get("id") or "") == tid:
            return t
    raise ValueError("未知模版 id: %r（已知: %s）" % (tid, ", ".join(template_ids(reg))))


def render(tid: str, values: dict, reg: dict = None) -> str:
    """占位符全量替换；缺键/多键/残留 → fail-loud（防把半成品当交付）。"""
    t = get_template(tid, reg)
    body = str(t.get("body") or "")
    need = set(_PH_RE.findall(body))
    declared = set(str(x) for x in (t.get("placeholders") or []))
    if need != declared:
        raise ValueError("模版 %s 自洽性破（body 占位符 %s ≠ 声明 %s）"
                         % (tid, sorted(need), sorted(declared)))
    need_bare = {p.strip("{}") for p in need}
    missing = sorted(need_bare - set(values))
    if missing:
        raise ValueError("缺占位符: %s（模版 %s）" % (", ".join(missing), tid))
    extra = sorted(set(values) - need_bare)
    if extra:
        raise ValueError("多余键: %s（模版 %s 不需要）" % (", ".join(extra), tid))
    out = body
    for k, v in values.items():
        out = out.replace("{%s}" % k, str(v))
    residual = _PH_RE.findall(out)
    if residual:
        raise ValueError("渲染后仍有未填占位符: %s" % sorted(set(residual)))
    return out


# ───────────────────────────── 分类 / 骨架 ─────────────────────────────
def _hits(template: dict, text: str) -> list:
    low = str(text or "").lower()
    out = []
    for kw in (template.get("keywords") or []):
        k = str(kw or "").strip()
        if k and k.lower() in low:
            out.append(k)
    return sorted(set(out))


def classify(change: str, position: str = "", min_score: int = 2,
             reg: dict = None) -> dict:
    """按登记表 keywords 判「复用既有形态」还是「需新增形态」。

    `position` 是强判据：给了就只在同位置模版里选（锚点行不会被判成行内 why）。
    """
    reg = reg if reg is not None else load_registry()
    if position and position not in reg.get("positions", []):
        raise ValueError("未知位置: %r（已知: %s）"
                         % (position, ", ".join(reg.get("positions") or [])))
    pool = [t for t in reg["templates"]
            if not position or str(t.get("position") or "") == position]
    if not pool:
        raise ValueError("位置 %r 无登记模版" % position)
    cands = []
    for t in pool:
        h = _hits(t, change)
        cands.append({"id": str(t.get("id") or ""), "score": len(h), "hits": h})
    cands.sort(key=lambda c: (-c["score"], c["id"]))
    best = cands[0] if cands else {"id": "", "score": 0, "hits": []}
    second = cands[1]["score"] if len(cands) > 1 else 0
    reuse = best["score"] >= int(min_score) and best["score"] > second
    return {
        "decision": "reuse" if reuse else "new",
        "id": best["id"] if reuse else "",
        "position": position,
        "score": best["score"],
        "second_score": second,
        "hits": best["hits"],
        "candidates": cands[:5],
        "reason": ("命中 %s（%d 分，领先 %d）" % (best["id"], best["score"], second)
                   if reuse else
                   "最高分 %d（%s）未达阈值或并列 ⟹ 需新增形态"
                   % (best["score"], best["id"] or "-")),
    }


def scaffold(change: str = "", position: str = "", values: dict = None,
             min_score: int = 2, reg: dict = None) -> dict:
    """复用 → 导出骨架（保留占位符）并可选填空；不复用 → 导出空草案。

    骨架不伪装成品：未给全值时 `missing` 非空、`code` 为空。
    """
    reg = reg if reg is not None else load_registry()
    c = classify(change, position, min_score, reg)
    if c["decision"] == "reuse":
        t = get_template(c["id"], reg)
        declared = [str(x) for x in (t.get("placeholders") or [])]
        vals = dict(values or {})
        bare = {p.strip("{}") for p in declared}
        missing = sorted(bare - set(vals))
        code = "" if missing else render(c["id"], vals, reg)
        return {"decision": "reuse", "id": c["id"], "position": c["position"],
                "placeholders": declared, "missing": missing,
                "skeleton": str(t.get("body") or ""), "code": code,
                "reason": c["reason"]}
    tokens = [w for w in re.split(r"[\s，。；：、/|（）()【】\[\]{}<>《》“”\"'`]+", str(change))
              if 2 <= len(w) <= 20]
    return {"decision": "new", "id": "", "position": position, "reason": c["reason"],
            "draft": {"id": "", "position": position, "desc": str(change),
                      "when": str(change), "keywords": sorted(set(tokens))[:12],
                      "placeholders": [], "body": ""}}


# ───────────────────────────── 注释解析 ─────────────────────────────
def _py_comments(text: str) -> list:
    """返回 [(行号, 行文本, 是否整行注释)]；独立字符串语句（docstring）计入整行注释。"""
    rows = []
    try:
        toks = list(tokenize.generate_tokens(StringIO(text).readline))
    except Exception:
        toks = []
    cm, dc = set(), set()
    prev = tokenize.NEWLINE
    for t in toks:
        if t.type == tokenize.COMMENT:
            cm.add(t.start[0])
        elif t.type == tokenize.STRING and prev in (
                tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
                tokenize.NL, tokenize.ENCODING):
            for r in range(t.start[0], t.end[0] + 1):
                dc.add(r)
        if t.type not in (tokenize.NL, tokenize.COMMENT):
            prev = t.type
    lines = text.splitlines()
    for r in sorted(cm | dc):
        if 1 <= r <= len(lines):
            raw = lines[r - 1]
            whole = (r in dc) or raw.lstrip().startswith("#")
            rows.append((r, raw, bool(whole)))
    return rows


def _strip_shell_comment(line: str):
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == q and (i == 0 or line[i - 1] != "\\"):
                q = None
        elif ch in ("'", '"'):
            q = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i], line[i:]
    return line, ""


def _sh_comments(text: str) -> list:
    """返回 [(行号, 行文本, 是否整行注释)]；跳过 shebang 与 heredoc 正文。"""
    rows = []
    hd_end = None
    for n, line in enumerate(text.splitlines(), 1):
        if hd_end is not None:
            if line.strip() == hd_end:
                hd_end = None
            continue
        s = line.strip()
        if not s:
            continue
        m = re.search(r"<<-?\s*[A-Za-z_][A-Za-z0-9_]*", line)
        if m and not s.startswith("#"):
            hd_end = m.group(0).split("<<")[-1].lstrip("- ").strip()
            body, com = _strip_shell_comment(line)
            if com:
                rows.append((n, line, False))
            continue
        if n == 1 and s.startswith("#!"):
            continue
        if s.startswith("#"):
            rows.append((n, line, True))
            continue
        body, com = _strip_shell_comment(line)
        if com:
            rows.append((n, line, False))
    return rows


def _comment_rows(text: str, ext: str) -> list:
    if ext == ".py":
        return _py_comments(text)
    return _sh_comments(text)


def _ratio_budget(path: str, ext: str) -> float:
    name = os.path.basename(path)
    if name.startswith("test_") or "/test_" in path.replace("\\", "/"):
        return 30.0
    if name == "gatekeeper-cli.sh":
        return 40.0
    return 40.0 if ext == ".py" else 45.0


def check_text(text: str, ext: str = "", path: str = "", strict: bool = False) -> dict:
    """扫描单个文件的注释，返回 stats + violations（纯函数，供单测直调）。"""
    ext = ext or os.path.splitext(path)[1].lower()
    rows = _comment_rows(text, ext)
    lines = text.splitlines()
    total = len(lines)
    blank = sum(1 for l in lines if not l.strip())
    comment_only = sum(1 for _, _, whole in rows if whole)
    comment_n = len(rows)
    code = max(total - blank - comment_n, 0)
    violations = []
    today = date.today()

    def add(level, rule, line, detail):
        violations.append({"line": line, "rule": rule, "level": level, "detail": detail})

    for ln, raw, whole in rows:
        s = raw.strip()
        m = _ANCHOR_RE.match(raw)
        if m:
            try:
                d = date.fromisoformat(m.group(1))
                if d > today:
                    add("ERROR", "anchor-date-future", ln, "锚点日期 %s 晚于今天" % m.group(1))
            except ValueError:
                add("ERROR", "anchor-date-invalid", ln, "锚点日期非法: %s" % m.group(1))
            if not _ID_RE.search(raw):
                add("WARN", "anchor-missing-id", ln, "锚点行缺工程编号（R#/ECC-*/ECO-*/F#）")
            if "净" in raw and "证据" not in raw and "evidence" not in raw.lower():
                add("WARN", "anchor-missing-evidence", ln, "锚点行写了净行数但缺证据锚")
        if _TODO_RE.match(raw):
            add("WARN", "todo-bare", ln, "TODO 缺 owner/触发条件（应写成 TODO(条件): ...）")
        if _WHAT_RE.match(raw):
            add("INFO", "comment-what", ln, "疑似 what 注释（复述代码在做什么），建议删除或改写为 why")
        if _VAGUE_RE.search(s) and not re.search(r"\d", s) and "/" not in s \
                and not re.search(r"判据|边界|fail-", s):
            add("INFO", "comment-vague", ln, "含「注意/务必/小心」但无判据/数字/路径")
        pm = _RESIDUAL_RE.search(raw)
        if pm:
            add("ERROR", "placeholder-residual", ln, "未填槽位 %s（骨架未填全就落盘）" % pm.group(0))

    # 连续整行注释块过长（排除事故复盘；docstring 契约块按规格允许 10–40 行，不在此列）
    def _is_hash(rec) -> bool:
        return rec[2] and rec[1].lstrip().startswith(("#", "//"))

    i = 0
    while i < len(rows):
        if not _is_hash(rows[i]):
            i += 1
            continue
        j = i
        while (j + 1 < len(rows) and _is_hash(rows[j + 1])
               and rows[j + 1][0] == rows[j][0] + 1):
            j += 1
        n = j - i + 1
        block = "\n".join(lines[rows[k][0] - 1] for k in range(i, j + 1))
        if n > 20 and not any(kw in block for kw in _INCIDENT_KW):
            add("WARN", "comment-block-too-long", rows[i][0],
                "%d 行连续注释块且无事故/判据关键词（上限 20）" % n)
        i = j + 1

    ratio = round(100.0 * comment_n / total, 1) if total else 0.0
    budget = _ratio_budget(path, ext)
    if total >= 30 and ratio > budget:
        add("WARN", "comment-ratio-over", 1,
            "注释率 %.1f%% 超预算 %.0f%%" % (ratio, budget))

    summary = {"ERROR": 0, "WARN": 0, "INFO": 0}
    for v in violations:
        summary[v["level"]] += 1
    ok = summary["ERROR"] == 0
    if strict:
        ok = ok and summary["WARN"] == 0
    return {
        "ok": ok,
        "file": path,
        "stats": {"total_lines": total, "blank": blank, "comment": comment_n,
                  "comment_only": comment_only, "code": code,
                  "ratio_pct": ratio, "ratio_budget_pct": budget},
        "summary": summary,
        "violations": violations,
    }


# ───────────────────────────── 写后回环 ─────────────────────────────
def _git_added_lines(path: Path) -> set:
    """`git diff -U0` 的新增行号集合；git 不可用 → 空集（调用方回退全文件）。"""
    try:
        top = subprocess.run(["git", "-C", str(path.parent), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=10)
        if top.returncode != 0:
            return set()
        root = Path(top.stdout.strip())
        rel = str(path.resolve().relative_to(root.resolve()))
        r = subprocess.run(["git", "-C", str(root), "diff", "-U0", "--", rel],
                           capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            return set()
    except (OSError, ValueError, subprocess.SubprocessError):
        return set()
    out = set()
    for line in r.stdout.splitlines():
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
        if m:
            start = int(m.group(1))
            count = int(m.group(2) or 1)
            out.update(range(start, start + count))
    return out


def check_file(path: str, changed_only: bool = False, strict: bool = False) -> dict:
    p = Path(path)
    if not p.is_file():
        raise ValueError("文件不存在: " + str(p))
    text = p.read_text(encoding="utf-8", errors="replace")
    res = check_text(text, p.suffix.lower(), str(p), strict)
    if changed_only:
        added = _git_added_lines(p)
        if added:
            res["violations"] = [v for v in res["violations"] if v["line"] in added]
        else:
            res["changed_only"] = "unavailable（git 无 diff 或不可用）⟹ 全文件扫描"
        summary = {"ERROR": 0, "WARN": 0, "INFO": 0}
        for v in res["violations"]:
            summary[v["level"]] += 1
        res["summary"] = summary
        res["ok"] = summary["ERROR"] == 0 and (not strict or summary["WARN"] == 0)
    return res


def _literal_segments(body: str) -> list:
    """模版体去掉占位符后的字面段（≥5 字符），用于证明「该形态真的被用过」。"""
    parts = _PH_RE.split(body)
    return [p.strip(" \n#/\"'") for p in parts
            if len(p.strip(" \n#/\"'")) >= 5]


def _used_in_text(body: str, text: str) -> str:
    segs = _literal_segments(body)
    if not segs:
        raise ValueError("模版体没有 ≥5 字符的字面段，无法证明已使用")
    best = max(segs, key=len)
    return best if best in text else ""


def promote(draft: dict, registry_path: str = "", evidence_file: str = "",
            checker=None) -> dict:
    """新形态回灌：必须先「真实用进文件」且 `check` 无 ERROR，才写回登记表并 version+1。"""
    p = Path(registry_path) if registry_path else _REGISTRY
    reg = load_registry(str(p))
    d = dict(draft or {})
    for k in ("id", "position", "desc", "when", "body"):
        if not str(d.get(k) or "").strip():
            raise ValueError("draft 缺字段: " + k)
    if str(d["position"]) not in (reg.get("positions") or []):
        raise ValueError("draft.position 未登记: " + str(d["position"]))
    tid = str(d["id"]).strip()
    if tid in template_ids(reg):
        raise ValueError("模版 id 已存在: " + tid)
    kw = d.get("keywords")
    if not isinstance(kw, list) or not [x for x in kw if str(x).strip()]:
        raise ValueError("draft 缺 keywords（分类器单源）")
    body = str(d["body"])
    need = set(_PH_RE.findall(body))
    declared = [str(x) for x in (d.get("placeholders") or sorted(need))]
    if need != set(declared):
        raise ValueError("占位符漂移: body=%s ≠ declared=%s"
                         % (sorted(need), sorted(set(declared))))
    if not need:
        raise ValueError("模版 body 至少要含 1 个占位符（否则无法填空）")
    ev = evidence_file or str(d.get("evidence_file") or "")
    if not ev:
        raise ValueError("promote 需要 --file <真实使用该形态的文件>")
    evp = Path(ev)
    if not evp.is_file():
        raise ValueError("证据文件不存在: " + str(evp))
    text = evp.read_text(encoding="utf-8", errors="replace")
    if not _used_in_text(body, text):
        raise ValueError("证据文件未出现该形态的最长字面段 ⟹ 尚未真实使用，不得回灌")
    ck = (checker or (lambda f: check_file(f)))(str(evp))
    if ck.get("summary", {}).get("ERROR", 1) != 0:
        raise ValueError("证据文件 check 存在 ERROR ⟹ 先修注释再回灌")
    entry = {"id": tid, "position": str(d["position"]),
             "lang": [str(x) for x in (d.get("lang") or ["py", "sh"])],
             "keywords": [str(x) for x in kw if str(x).strip()],
             "desc": str(d["desc"]), "when": str(d["when"]),
             "placeholders": declared, "body": body}
    reg["templates"].append(entry)
    reg["version"] = int(reg.get("version") or 1) + 1
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(reg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(str(tmp), str(p))
    return {"ok": True, "id": tid, "version": reg["version"],
            "templates": len(reg["templates"])}


# ───────────────────────────── CLI ─────────────────────────────
def _kv(tokens: list) -> dict:
    vals = {}
    for kv in tokens:
        if "=" not in kv:
            raise ValueError("参数须为 k=v，收到: %r" % kv)
        k, v = kv.split("=", 1)
        vals[k.strip()] = v
    return vals


def _split_flags(tokens: list) -> tuple:
    """把 [位置产物, --position X, k=v ...] 拆成 (position, kv_tokens)。"""
    pos, rest, i = "", [], 0
    while i < len(tokens):
        if tokens[i] == "--position" and i + 1 < len(tokens):
            pos = tokens[i + 1]
            i += 2
            continue
        rest.append(tokens[i])
        i += 1
    return pos, rest


def main(argv: list) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("cmd", nargs="?", default="list")
    ap.add_argument("args", nargs="*")
    ap.add_argument("--position", default="")
    ap.add_argument("--changed-only", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--file", default="")
    ap.add_argument("--registry", default="")
    try:
        a = ap.parse_args(argv)
        cmd = a.cmd
        if cmd == "list":
            reg = load_registry(a.registry)
            print(json.dumps({"ok": True, "ids": template_ids(reg),
                              "positions": reg.get("positions", []),
                              "version": reg.get("version")}, ensure_ascii=False))
            return 0
        if cmd == "show":
            if not a.args:
                raise ValueError("show 需要 <id>")
            print(json.dumps({"ok": True, "template": get_template(a.args[0], load_registry(a.registry))},
                             ensure_ascii=False, indent=1))
            return 0
        if cmd == "render":
            if not a.args:
                raise ValueError("render 需要 <id> k=v ...")
            vals = _kv(a.args[1:])
            print(json.dumps({"ok": True, "id": a.args[0],
                              "code": render(a.args[0], vals, load_registry(a.registry))},
                             ensure_ascii=False))
            return 0
        if cmd == "classify":
            ctx = " ".join(a.args)
            print(json.dumps({"ok": True, **classify(ctx, a.position, reg=load_registry(a.registry))},
                             ensure_ascii=False, indent=1))
            return 0
        if cmd == "scaffold":
            pos, rest = _split_flags(a.args)
            pos = a.position or pos
            if not pos and not rest:
                raise ValueError("scaffold 需要 <上下文描述> 或 --position <位置>")
            ctx = " ".join(x for x in rest if "=" not in x)
            vals = _kv([x for x in rest if "=" in x])
            print(json.dumps({"ok": True, **scaffold(ctx, pos, vals, reg=load_registry(a.registry))},
                             ensure_ascii=False, indent=1))
            return 0
        if cmd == "check":
            if not a.args:
                raise ValueError("check 需要 <file>")
            res = check_file(a.args[0], a.changed_only, a.strict)
            print(json.dumps(res, ensure_ascii=False, indent=1))
            return 0 if res["ok"] else 1
        if cmd == "promote":
            if not a.args:
                raise ValueError("promote 需要 <draft.json> --file <使用该形态的文件>")
            draft = json.loads(Path(a.args[0]).read_text(encoding="utf-8"))
            print(json.dumps(promote(draft, a.registry, a.file), ensure_ascii=False))
            return 0
        raise ValueError("未知子命令: %r（list/show/render/classify/scaffold/check/promote）" % cmd)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)},
                         ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
