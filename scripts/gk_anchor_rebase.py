#!/usr/bin/env python3
"""锚重钉执行器 —— 补 P5 §7 落刀前置 #1「生成重钉清单**并执行**」缺失的那一半（2026-09-19）。

背景（实测，S1-a）：`gk_doc_align.py::anchor_rebase_plan` 只**规划**清单（`repin` / `manual`），
仓内**没有任何写回实现** ⟹ 该前置被写成确定性机械步，实际只能靠 agent 手改
（登记为 `ECC-4CFD7F53E00F`）。本脚本补执行面。

安全设计（每条都可机检，判据见 `test_gk_anchor_rebase.py`）：

  1. **默认什么都不做** —— 必须显式 `--docs a.md,b.md` 白名单。防「手滑跑全量」把密封 /
     熔断中的计划（conv-eval DRAFT-1 / ember §18 熔断 / crossreview 两次熔断）一并改掉。
  2. **只吃 `repin` / `repin_range` / `--map`** —— `manual`（含无绑定区间、倒置区间）一律不碰。
  3. **`repin_range` 保跨度** —— 有符号绑定的区间 `path:A-B sym`：起点 = 符号的最近命中行、
     长度 = 原跨度（2026-09-19 S1-a 二阶段）。无绑定/倒置区间仍留在 `manual`。
  4. **`--refs` 显式白名单**（调用方自担的核实纪律）—— `repin` 的「最近命中」对**高频字面量**
     会给错值，实测 2026-09-19 conv-eval：
       · `gatekeeper-cli.sh:6648 _CMD_REG` 工具给 6701 / 读码真值 **6734**；
       · `:6309 cmd_plan_refinement` 工具给 6377 / 真值 **6395**；
       · `:4201 existing` 与 `:4210 existing` **双双塌陷**到 5459，而 5459 是无关函数里的
         `existing = f.read()`；`:4233 json` 被钉到 4235 的 `retrospect_json`（**子串**命中）；
       · `:6589 L2` 的符号绑定根本不成立（`L2` 是文档自己的段落标签）。
     ⟹ 只允许 apply「已逐条读码核实」的子集。⚠ 默认（不给 `--refs`）**不收窄**，故这条纪律须由
     调用方显式承担 —— 本脚本**不**替你判对错，它只保证「按你给的清单精确改写」。
  5. **`--map old=new,...` 显式对** —— 给 `repin` **够不到**的真值用（实测 `gatekeeper-cli.sh:199`
     在 doc-align 侧连 `content_drift` 都不是 ⟹ 永远不进 `repin`）。真值仍须调用方读码定，
     本参数只负责机械落盘。替换**有界**：`old` 之后不得紧跟数字/连字符 ⟹ 防 `:199` 命中 `:1991`。
  6. **逐条校验替换真的发生** —— `path:OLD` 在目标行内找不到 ⟹ 记 `not_found` 且**不写**该行
     （宁可少改，不改错）；已成功的照写，故**可重跑**（改过的下一轮不再是 `repin`）。
  7. **只改行内的锚文本，不动行号结构** ⟹ 不产生级联漂移；换行风格（LF/CRLF）按原样保留。
  8. **不写 `--apply` 就是只读预览**（默认 dry-run）。

用法：
  python3 scripts/gk_anchor_rebase.py <skill_dir> --docs a.md,b.md [--refs a:1,b:2-9]
                                                             [--map a:1=b:2,c:3=d:4] [--apply] [--json]
退出码：0 = 无 not_found；1 = 有 not_found（有东西没改成，需人看）；2 = 参数/环境错。
"""
import json
import os
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))


def _doc_path(skill_dir: str, doc: str, plans_roots=None) -> Path:
    """该 doc 的落点：`<skill_dir>/docs/plans/<doc>` 与各 `plans_roots/<doc>` 中**第一个存在**者。

    2026-09-26（`ECC-1FA6B6E7D15C` B 侧）：原实现硬绑 `Path(skill_dir)/"docs"/"plans"/doc`
    （`:55` / `:131`）⟹ **仓外计划**（如 `.codex/docs/plans/`）根本进不来。现在计划根可配；
    `plans_roots` 为空 ⟹ 候选集与旧实现**逐字一致**（唯一候选 = 技能仓内那份）。
    """
    cands = [Path(skill_dir) / "docs" / "plans" / doc]
    cands += [Path(r) / doc for r in (plans_roots or []) if str(r).strip()]
    for c in cands:
        if c.is_file():
            return c
    return cands[0]


def _map_edits(skill_dir: str, allow: set, mapping: dict, plans_roots=None) -> list:
    """`--map` 模式：在**白名单文档**内按显式对逐行找 `old`（有界）⟹ 出 edits。

    有界 = `old` 之后不得紧跟数字/连字符：`:199` 不得命中 `:1991`（静默串改）。
    每行每个对最多出一条（`apply_edits` 逐条顺序替换）。
    """
    edits = []
    for doc in sorted(allow):
        path = _doc_path(skill_dir, doc, plans_roots)
        if not path.is_file():
            continue
        with path.open(encoding="utf-8", newline="") as fh:
            lines = fh.read().splitlines()
        for ln, line in enumerate(lines, 1):
            for old, new in mapping.items():
                if re.search(re.escape(old) + r"(?![\d\-])", line):
                    edits.append({"doc": doc, "doc_line": ln, "old": old, "new": new,
                                  "source": "map"})
    return edits


def plan_edits(skill_dir: str, docs, refs=None, mapping=None, plans_roots=None) -> dict:
    """取 `rebase_plan`（或 `mapping`），按白名单（文档 + 可选 `refs`）算出 old→new 锚文本。

    白名单为空 ⟹ 返回空 edits（**不是**全量）。`refs` 为空/None ⟹ **不按 ref 收窄**
    （退化为「白名单文档内全量」）；要收窄必须显式给 `refs`。`mapping` 非空 ⟹ 走 `--map`
    模式（不经 `rebase_plan`，`refs` 不参与）。
    """
    allow = {d.strip() for d in docs if d and d.strip()}
    allow_refs = {r.strip() for r in (refs or []) if r and r.strip()}
    skipped = []

    if mapping:
        return {"edits": _map_edits(skill_dir, allow, mapping, plans_roots),
                "skipped": skipped, "manual_untouched": 0}

    from gk_doc_align import check_anchor_existence

    plan = (check_anchor_existence(skill_dir).get("rebase_plan") or {})
    edits = []

    def _gate(it):
        """文档 + ref 双层白名单；不收则记 `skipped` 并返回 None。"""
        doc = it.get("doc")
        if doc not in allow:
            skipped.append({"doc": doc, "ref": it.get("ref"), "why": "doc_not_in_whitelist"})
            return None
        ref = str(it.get("ref") or "")
        if allow_refs and ref not in allow_refs:
            skipped.append({"doc": doc, "ref": ref, "why": "ref_not_in_whitelist"})
            return None
        return ref

    for it in plan.get("repin", []):
        ref = _gate(it)
        if ref is None:
            continue
        edits.append({"doc": it.get("doc"), "doc_line": it.get("doc_line"),
                      "old": ref, "new": _new_ref(ref, int(it["suggested_line"])),
                      "evidence": it.get("evidence"),
                      "symbol": it.get("symbol"), "hits_total": it.get("hits_total")})
    for it in plan.get("repin_range", []):
        ref = _gate(it)
        if ref is None:
            continue
        edits.append({"doc": it.get("doc"), "doc_line": it.get("doc_line"), "old": ref,
                      "new": _new_ref(ref, int(it["suggested_start"]),
                                      int(it["suggested_end"])),
                      "evidence": it.get("evidence"),
                      "symbol": it.get("symbol"), "hits_total": it.get("hits_total"),
                      "span": it.get("span")})
    return {"edits": edits, "skipped": skipped,
            "manual_untouched": len(plan.get("manual", []))}


def _new_ref(ref: str, start: int, end=None) -> str:
    """把 `ref` 里的行号换成 `start`(/`end`)，**保留原锚形态**（`:` 或 `#L`；`-` 或 `-L`）。

    A2（2026-09-28，ECC-F68E6BEE4F68）：`#L` 锚若写回成 `path:NEW`，文档就混入第二套锚口径
    —— `apply_edits` 是按文本逐字替换，形态不一致虽仍能命中 `old`，但产出物会 `#L` 与 `:`
    混杂。形态无关的替换**只能**在行号层做：前缀原样 + 分隔符原样重建。
    """
    m = re.search(r"(#L|:)(\d+)(?:(-L|-)(\d+))?$", ref)
    if not m:
        return ref
    if end is None:
        return ref[:m.start()] + "%s%d" % (m.group(1), start)
    return ref[:m.start()] + "%s%d%s%d" % (m.group(1), start, m.group(3) or "-", end)


def apply_edits(skill_dir: str, edits, apply: bool = False, plans_roots=None) -> list:
    """按文档分组改写；返回逐条结果（`applied` / `not_found` / `preview`）。"""
    by_doc: dict = {}
    for e in edits:
        by_doc.setdefault(e["doc"], []).append(e)

    results = []
    for doc, items in sorted(by_doc.items()):
        path = _doc_path(skill_dir, doc, plans_roots)
        # newline="" ⟹ 不做通用换行转换，才能判出并保留原 CRLF（Path.read_text 在 3.12
        # 不收 newline 形参；且默认会把 \r\n 折成 \n ⟹ 会把整份 CRLF 文档改写成 LF 大 diff）
        with path.open(encoding="utf-8", newline="") as fh:
            raw = fh.read()
        crlf = "\r\n" in raw
        lines = raw.splitlines()
        touched = False
        for e in items:
            i = int(e["doc_line"]) - 1
            if not (0 <= i < len(lines)) or e["old"] not in lines[i]:
                results.append({**e, "status": "not_found"})
                continue
            lines[i] = lines[i].replace(e["old"], e["new"], 1)
            touched = True
            results.append({**e, "status": "applied" if apply else "preview"})
        if apply and touched:
            sep = "\r\n" if crlf else "\n"
            with path.open("w", encoding="utf-8", newline="") as fh:
                fh.write(sep.join(lines) + sep)
    return results


def _main(argv: list) -> int:
    args = list(argv[1:])
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if args else 2
    skill_dir = args[0]
    docs, apply, refs, mapping = [], False, [], {}
    # 2026-09-26（ECC-1FA6B6E7D15C）：仓外计划根 —— env 缺省源 + 显式 `--plans-root` 追加。
    # ⚠ CLI 侧 `cmd_anchor_rebase` 在 `PROTECTED_REGION::gate` 内（禁改）⟹ 新参数靠**原样转发**
    #   既有参数表 + env 携带，无需改 CLI。
    plans_roots = [x for x in os.environ.get("GK_ANCHOR_REBASE_ROOTS", "").split(os.pathsep)
                   if x.strip()]
    i = 1
    while i < len(args):
        if args[i] == "--docs" and i + 1 < len(args):
            docs = args[i + 1].split(","); i += 2
        elif args[i] == "--plans-root" and i + 1 < len(args):
            plans_roots += [x for x in args[i + 1].split(",") if x.strip()]; i += 2
        elif args[i] == "--refs" and i + 1 < len(args):
            refs = args[i + 1].split(","); i += 2
        elif args[i] == "--map" and i + 1 < len(args):
            for kv in args[i + 1].split(","):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    mapping[k.strip()] = v.strip()
            i += 2
        elif args[i] == "--apply":
            apply = True; i += 1
        elif args[i] == "--json":
            i += 1
        else:
            print(json.dumps({"ok": False, "error": "unknown arg: %s" % args[i]}))
            return 2
    if not any(os.path.isdir(d) for d in
               [os.path.join(skill_dir, "docs", "plans")] + plans_roots):
        print(json.dumps({"ok": False, "error": "no plans root under %s" % skill_dir
                          + "（技能仓 docs/plans + --plans-root / env GK_ANCHOR_REBASE_ROOTS）"}))
        return 2

    p = plan_edits(skill_dir, docs, refs=refs, mapping=mapping, plans_roots=plans_roots)
    res = apply_edits(skill_dir, p["edits"], apply=apply, plans_roots=plans_roots)
    not_found = [r for r in res if r["status"] == "not_found"]
    print(json.dumps({
        "ok": not not_found, "apply": apply, "docs_whitelist": sorted(
            {d.strip() for d in docs if d and d.strip()}),
        "refs_whitelist": sorted({r.strip() for r in refs if r and r.strip()}),
        "plans_roots": plans_roots,
        "map_pairs": len(mapping),
        "edits": len(p["edits"]), "skipped_not_whitelisted": len(p["skipped"]),
        "manual_untouched": p["manual_untouched"], "results": res,
    }, ensure_ascii=False, indent=2))
    return 1 if not_found else 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
