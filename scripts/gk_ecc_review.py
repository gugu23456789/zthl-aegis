#!/usr/bin/env python3
"""gk_ecc_review.py — 转发 ECC 证据包**逐锚复核**（确定性，0 API）。

定位：把「转发包 → 人工逐锚读码复核」从**纯人工**变成「**机检起草 + 人工裁决**」。
实测代价（2026-09-25）：一份 8 锚的转发包，人工复核查出 **2 条因果反转 + 3 条行号漂移**，
全部靠读码发现 —— 本模块把那一步机械化。

设计约束（单一事实源）：
  · **锚提取复用** `gk_plan_lint.iter_anchor_refs`（禁第二套正则；`gk_plan_lint` 与
    `gk_doc_align.anchor_existence` 共用同一迭代器，见其 L23/L78-95 注释）。
  · 判定**只做确定性可判的事**：能绑到字面值就判 `hit/line_drift/literal_missing`；
    绑不到就老实报 `unverifiable`（宁报不可校验，不假装已校验）。

verdict（优先级即此处顺序）：
  `file_missing`    — 该 rel 在所有扫描根下都找不到
  `line_over_eof`   — 锚行号 > 目标文件行数
  `hit`             — 字面值落在锚点区间内
  `line_drift`      — 字面值在文件内有命中但不在区间 ⟹ 附 `suggested_line`（真值行号）
  `literal_missing` — 字面值全文件无命中 ⟹ 断言已过期
  `unverifiable`    — 锚所在行取不到可用字面值（含 CJK 或长度 < 4 者一律排除）

字面值抽取口径（确定性，无启发式外推）：取锚**所在行**内所有反引号片段，剔除
① 锚自身 ② 短于 4 字符 ③ 含 CJK 者；多候选取**最长**。

Usage:
  python3 scripts/gk_ecc_review.py <pkg.md> [--roots a,b] [--json]
退出码：0 = 无 file_missing/line_over_eof/line_drift/literal_missing（即全部 hit/unverifiable）；1 = 有需订正项；2 = 参数/环境错。
"""
import argparse
import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from gk_plan_lint import _lines_of, iter_anchor_refs  # noqa: E402  —— 锚提取/行数单一事实源

_SKILL_DIR = SCRIPT_DIR.parent

# 反引号片段；CJK 面（含 CJK 统一表意/兼容表意/中日韩标点/全角）+ 扩展面
_LIT_RE = re.compile(r"`([^`]+)`")
_CJK_RE = re.compile(r"[\u2e80-\u303f\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\ufe30-\ufe4f\uff00-\uffef]")

_VERDICT_ORDER = ("file_missing", "line_over_eof", "line_drift",
                  "literal_missing", "unverifiable", "hit", "ok")


def skill_dir() -> str:
    return str(_SKILL_DIR)


def _line_of(text: str, pos: int) -> int:
    """`pos` 所在的 1-based 行号。"""
    return text.count("\n", 0, pos) + 1


def _literals(line: str, anchor_text: str) -> list:
    """锚所在行的**可用字面值**候选（口径见模块头）。"""
    out = []
    for m in _LIT_RE.finditer(line or ""):
        t = m.group(1).strip()
        if not t or t == anchor_text or anchor_text in t:
            continue
        if len(t) < 4 or _CJK_RE.search(t):
            continue
        out.append(t)
    return out


def extract_anchors(text: str) -> list:
    """逐锚抽取（位置/文件/区间/字面值候选）；锚提取走 `iter_anchor_refs` 单一事实源。"""
    lines = text.splitlines()
    anchors = []
    for m in iter_anchor_refs(text):
        rel, lo = m.group(1), int(m.group(2))
        hi = int(m.group(3)) if m.group(3) else lo
        ln = _line_of(text, m.start())
        line = lines[ln - 1] if 0 <= ln - 1 < len(lines) else ""
        anchors.append({"ref": m.group(0), "rel": rel, "lo": lo, "hi": hi,
                        "doc_line": ln, "literals": _literals(line, m.group(0))})
    return anchors


def _resolve(rel: str, roots) -> Path | None:
    """该 rel 在根集合下的第一个存在者（先 `<root>/rel`，再 `<root>/scripts/<basename>`）。"""
    base = Path(rel).name
    for r in roots:
        for cand in (Path(r) / rel, Path(r) / "scripts" / base):
            if cand.is_file():
                return cand
    return None


_ANCHOR_MODES = ("content", "existence")


def classify_anchor(anchor: dict, target, mode: str = "content") -> dict:
    """单锚判决**单一源引擎**（A/B 同源双实现收口；判决阶梯同一条，EOF 面按 mode 分化）。

    `target` = **已解析**目标（`str` / `Path`）或 `None`；`None` ⟹ `file_missing`（两 mode 同）。
    解析**不在**此处（A = `gk_plan_lint._build_index` + `_resolve_path`；B = 本模块 `_resolve`）
    —— 两路解析根语义不同，**禁**统一解析器。

    `mode`（白名单，非法 ⟹ `ValueError`，**禁**静默落 content）：
      · `"content"`   = B（转发证据包）原语义**逐字保持**：EOF 操作数 = `lo`；EOF 计数 =
        `read_text(encoding="utf-8", errors="replace").splitlines()`；读失败 **fail-loud**（裸抛
        `OSError`）；逐字值 6 判决（hit / line_drift / literal_missing / unverifiable / …）。
      · `"existence"` = A（台账标题）原语义**逐字保持**：EOF 操作数 = `hi`；EOF 计数 = 逐行迭代
        （`gk_plan_lint._lines_of`）；读失败 **fail-soft**（`None` ⟹ 不越界 ⟹ `ok`）；
        **不**做字面值匹配。

    ⛔ 操作数 / 计数法 / 读失败语义**三者**不得在两 mode 间统一（统一即改写历史判据）。
    """
    if mode not in _ANCHOR_MODES:
        raise ValueError("classify_anchor mode 非法: %r（合法: %s）"
                         % (mode, " | ".join(_ANCHOR_MODES)))
    if target is None:
        return {"verdict": "file_missing"}
    if mode == "existence":
        n = _lines_of(target)
        if n is None:                       # 读失败 fail-soft（对齐 scan_title_anchors）
            return {"verdict": "ok"}
        if anchor["hi"] > n:
            return {"verdict": "line_over_eof", "eof": n}
        lits = anchor.get("literals") or []
        if not lits:
            # A v1 口径**逐字保持**：无字面值 ⟹ ok（**非** unverifiable ⟹ 闸不泛滥）。
            return {"verdict": "ok"}
        # A v2：有字面值 ⟹ 与 content 同一匹配阶梯（EOF/计数/读失败三轴仍按 existence）。
        lines = Path(target).read_text(encoding="utf-8", errors="replace").splitlines()
        return _match_literals(lines, anchor)
    lines = Path(target).read_text(encoding="utf-8", errors="replace").splitlines()
    if anchor["lo"] > len(lines):
        return {"verdict": "line_over_eof", "eof": len(lines)}
    return _match_literals(lines, anchor)


def _match_literals(lines: list, anchor: dict) -> dict:
    """字面值匹配阶梯（`content` 与 `existence`-v2 **共享**，禁第二套）。

    无字面值 ⟹ `unverifiable`（content 面口径）；existence-v2 面**不会**走到此 —— 其空字面值
    已在调用前短路为 `ok`，保持 A v1 判据。
    """
    lits = anchor.get("literals") or []
    if not lits:
        return {"verdict": "unverifiable"}
    for lit in sorted(lits, key=len, reverse=True):
        hits = [i for i, ln in enumerate(lines, 1) if lit in ln]
        if not hits:
            continue
        if any(anchor["lo"] <= h <= anchor["hi"] for h in hits):
            return {"verdict": "hit", "literal": lit}
        after = [h for h in hits if h >= anchor["lo"]]
        near = min(after) if after else min(hits, key=lambda i: abs(i - anchor["lo"]))
        return {"verdict": "line_drift", "literal": lit,
                "suggested_line": near, "hits": hits}
    return {"verdict": "literal_missing",
            "literal": sorted(lits, key=len, reverse=True)[0]}


def classify(anchor: dict, roots) -> dict:
    """单锚判定（确定性）—— `classify_anchor(..., "content")` 的**薄别名**（单一事实源）。"""
    return classify_anchor(anchor, _resolve(anchor["rel"], roots), "content")


def _note(a: dict) -> str:
    v = a["verdict"]
    if v == "line_drift":
        return f"真值 :{a['suggested_line']}（字面值 `{a.get('literal')}`）"
    if v == "line_over_eof":
        return f"越 EOF（目标文件 {a.get('eof')} 行）"
    if v == "literal_missing":
        return f"字面值 `{a.get('literal')}` 全文无命中 ⟹ **断言已过期**"
    if v == "file_missing":
        return "被引文件在扫描根内找不到"
    return "无可校验字面值 ⟹ 需人工判定"


def render_markdown(anchors, roots) -> str:
    """「⚠ 复核订正」段草稿（全部非 hit 锚逐条列出 + 真值行号）。"""
    out = ["## ⚠ 复核订正（机器起草 —— 供人工裁决，非结论）", "",
           "- 扫描根：" + "、".join(f"`{r}`" for r in roots), "",
           "| # | 锚（原样） | verdict | 真值 / 说明 |", "|:--|:--|:--|:--|"]
    n = 0
    for a in anchors:
        if a["verdict"] == "hit":
            continue
        n += 1
        out.append(f"| {n} | `{a['ref']}` | {a['verdict']} | {_note(a)} |")
    if not n:
        out += ["", "（全部锚 `hit` —— 无订正项）"]
    return "\n".join(out) + "\n"


def review(pkg_path: str, roots=None) -> dict:
    """复核一份转发包：逐锚判定 + 计数 + 订正段草稿。"""
    text = Path(pkg_path).read_text(encoding="utf-8", errors="replace")
    rts = [str(r) for r in (roots or []) if str(r).strip()] or [skill_dir()]
    anchors = []
    for a in extract_anchors(text):
        a.update(classify(a, rts))
        anchors.append(a)
    counts: dict = {}
    for a in anchors:
        counts[a["verdict"]] = counts.get(a["verdict"], 0) + 1
    return {"pkg": str(pkg_path), "roots": rts, "anchors": anchors,
            "counts": counts, "draft_md": render_markdown(anchors, rts)}


def main(argv: list) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pkg")
    ap.add_argument("--roots", default="")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    roots = [r.strip() for r in a.roots.split(",") if r.strip()] if a.roots else []
    if not Path(a.pkg).is_file():
        print(json.dumps({"ok": False, "error": f"pkg 不存在: {a.pkg}"}, ensure_ascii=False))
        return 2
    rep = review(a.pkg, roots=roots)
    blocking = {k: v for k, v in rep["counts"].items()
                if k in ("file_missing", "line_over_eof", "line_drift", "literal_missing")}
    print(json.dumps({"ok": True, "counts": rep["counts"], "anchor_total": len(rep["anchors"]),
                      "roots": rep["roots"]},
                     ensure_ascii=False, indent=2))
    print(rep["draft_md"])
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
