#!/usr/bin/env python3
"""内联 Python 载荷清点（standard 压缩计划 §5-T1）。

只读扫描 `gatekeeper-cli.sh`，把每处 `python3 -c` / `python3 <<` 归为四类：

| 类别 | 判据（可机检） | 为什么要单列 |
|:--|:--|:--|
| `comment` | 该行 lstrip 后以 `#` 开头 | 说明文字，不是可执行载体；计入会虚高 |
| `import_probe` | 单引号体内**仅有** `import X` / `from X import Y` | 能力探测，无业务逻辑，改造收益为零 |
| `wrapper` | `-c` 后紧跟 `$`（`"$var"` / `"$(...)"`） | 代码在变量里，本处只是壳，改这里没用 |
| `payload` | 其余：单行 `-c '...'` / 多行 `-c "` / heredoc | **真实载荷**，才是下沉目标 |

口径（可复现，勿凭印象）：
- 计数单位 = **出现次数**（同一行两个 `-c` 记 2），不是行数；
- 归属函数 = 该行之前最近一个 `^name()` / `^function name` 定义（无则 `<top-level>`）；
- 载荷身份 = `sha1(载荷全文)[:12]`，**不含行号** ⟹ 代码搬家不算新增。

`--assert-baseline` 只报 **NEW**，不比对总数：该文件只增不减是常态，盯总数会被噪声淹没。
NEW 的判定 = 基线里不存在 `(func, cat, code_sha)` 三元组。

⚠ 与计划原文的偏差（2026-10-31 实测，已在计划 §5-T1 订正）：计划称「字面 103 / 载荷 94」，
但该读数**无法从任何版本复现** —— 10-28 版本实测 `-c` 102 + heredoc 7 = 109 行级出现、
非注释 104；要到 94 还需再排除 10 条「小工具」，排除标准未留在任何文件里。
故判据改为「脚本自产基线 + 只报 NEW」，绝对值由本脚本首次运行确定，不写死历史数字。
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

_C_RE = re.compile(r"python3\s+-c")
# heredoc 两种入口：`python3 <<'TAG'` 与 `python3 - "$a" "$b" <<'TAG'`（stdin 模式带 argv）。
# 2026-10-31 补：原正则只覆盖前者，实测漏 4 处（`python3 - "$_inv_root" ... <<'PYEOF'`）。
# 用 `(?:-\s[^<]*?)?` 吸收 `-` 及其参数；`-c` 不会误入（要求 `-\s`，`-c` 不匹配）。
_H_RE = re.compile(r"python3\s+(?:-\s[^<]*?)?<<\s*'?([A-Za-z_][A-Za-z0-9_]*)'?")
_FUNC_RE = re.compile(r"^(?:function\s+)?([A-Za-z_][A-Za-z0-9_.:/-]*)\s*\(\)")
# `-c` 后紧跟 `$`：代码在变量/命令替换里（"$var" / "$(...)" / '$x'）
_WRAP_RE = re.compile(r"""python3\s+-c\s+["']?\$""")
# 单引号内联体，同行闭合
_SQ_RE = re.compile(r"""python3\s+-c\s+'([^']*)'""")
_IMPORT_ONLY_RE = re.compile(
    r"^(?:import\s+[\w.]+(?:\s*,\s*[\w.]+)*|from\s+[\w.]+\s+import\s+[\w.,\s*]+)$")


def _sha(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:12]


def _norm(s: str) -> str:
    """归一化：折叠空白 + 去首尾，避免纯缩进变动造成假 NEW。"""
    return re.sub(r"\s+", " ", s).strip()


def _collect_dq_body(lines: list, i: int, after: int) -> tuple:
    """从 `-c` 之后开始，收集**开引号之后**到未转义闭引号的载荷（跨行）。

    ⚠ 2026-10-31 修 bug：原实现把 `-c` 后紧跟的**开引号**当成了闭引号，body 恒空
    ⟹ 所有多行载荷 sha 相同（`da39a3ee5e6b` = 空串 sha1）⟹ `--assert-baseline` 的
    NEW 判定对**任何**新增多行载荷都失效（全被当成"已存在"）。先跳过空白定位开引号。
    """
    cur = lines[i][after:]
    k = 0
    while k < len(cur) and cur[k] in " \t":
        k += 1
    start = k + 1 if (k < len(cur) and cur[k] == '"') else k

    buf = []
    cur = lines[i][after + start:]
    while True:
        j = 0
        while j < len(cur):
            ch = cur[j]
            if ch == "\\":
                buf.append(cur[j:j + 2])
                j += 2
                continue
            if ch == '"':
                buf.append(cur[:j])
                return "".join(buf), i
            j += 1
        buf.append(cur)
        buf.append("\n")
        i += 1
        if i >= len(lines):
            return "".join(buf), len(lines) - 1
        cur = lines[i]


def _collect_heredoc(lines: list, i: int, tag: str) -> tuple:
    """从 heredoc 起始行的下一行收集到 `^tag$`。"""
    buf = []
    i += 1
    while i < len(lines):
        if lines[i].strip() == tag:
            return "\n".join(buf), i
        buf.append(lines[i])
        i += 1
    return "\n".join(buf), len(lines) - 1


def scan(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    lines = text.split("\n")
    items = []
    func = "<top-level>"
    i = 0
    while i < len(lines):
        ln = lines[i]
        mf = _FUNC_RE.match(ln)
        if mf:
            func = mf.group(1)

        mh = _H_RE.search(ln)
        if mh and not ln.lstrip().startswith("#"):
            body, end = _collect_heredoc(lines, i, mh.group(1))
            items.append({"line": i + 1, "func": func, "cat": "payload",
                          "kind": "heredoc", "sha": _sha(_norm(body)),
                          "size": len(body)})
            i = end + 1
            continue

        # 同一行可能有多个 `-c`（如嵌套命令替换）⟹ 逐个计
        for mc in _C_RE.finditer(ln):
            if ln.lstrip().startswith("#"):
                items.append({"line": i + 1, "func": func, "cat": "comment",
                              "kind": "comment", "sha": _sha(_norm(ln)),
                              "size": len(ln)})
                break  # 注释行只记一次
            if _WRAP_RE.search(ln):
                items.append({"line": i + 1, "func": func, "cat": "wrapper",
                              "kind": "wrapper", "sha": _sha(_norm(ln)),
                              "size": len(ln)})
                break
            msq = _SQ_RE.search(ln)
            if msq:
                body = msq.group(1)
                cat = ("import_probe"
                       if _IMPORT_ONLY_RE.match(body.strip()) else "payload")
                items.append({"line": i + 1, "func": func, "cat": cat,
                              "kind": "single", "sha": _sha(_norm(body)),
                              "size": len(body)})
                break
            # 多行 `-c "`：从该 `-c` 之后收集
            body, end = _collect_dq_body(lines, i, mc.end())
            items.append({"line": i + 1, "func": func, "cat": "payload",
                          "kind": "multi", "sha": _sha(_norm(body)),
                          "size": len(body)})
            i = end
            break
        i += 1

    by_cat = {}
    for it in items:
        by_cat[it["cat"]] = by_cat.get(it["cat"], 0) + 1
    by_func = {}
    for it in items:
        d = by_func.setdefault(it["func"], {})
        d[it["cat"]] = d.get(it["cat"], 0) + 1
    return {"file": str(path), "total": len(items), "by_cat": by_cat,
            "by_func": by_func, "items": items}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="内联 Python 载荷清点（T1）")
    ap.add_argument("--cli", default=None, help="gatekeeper-cli.sh 路径（默认按本脚本位置推导）")
    ap.add_argument("--json", action="store_true", help="输出完整 JSON（含 items）")
    ap.add_argument("--summary", action="store_true", help="只输出计数摘要")
    ap.add_argument("--assert-baseline", default=None,
                    help="基线 JSON 路径；只报 NEW（基线中不存在的 func+cat+sha）")
    ap.add_argument("--max-payload", type=int, default=None,
                    help="payload 计数硬上限（棘轮：只许调低）；超出 ⟹ exit 1")
    ap.add_argument("--freeze", default=None,
                    help="把当前扫描冻结为基线文件（含 frozen_at/note，供 --assert-baseline 使用）")
    ap.add_argument("--note", default="", help="与 --freeze 同用：写入基线的说明")
    args = ap.parse_args(argv)

    cli = args.cli or str(Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh")
    if not Path(cli).exists():
        print(json.dumps({"error": f"未找到 {cli}"}, ensure_ascii=False), file=sys.stderr)
        return 2

    r = scan(cli)

    if args.freeze:
        import datetime
        fp = Path(args.freeze)
        fp.parent.mkdir(parents=True, exist_ok=True)
        snap = {"schema": "gk-bomb-inventory/1",
                "frozen_at": datetime.datetime.now(datetime.timezone.utc)
                             .strftime("%Y-%m-%dT%H:%M:%SZ"),
                "note": args.note}
        snap.update(r)
        fp.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"ok": True, "frozen": str(fp), "total": r["total"],
                          "payload": r["by_cat"].get("payload", 0)}, ensure_ascii=False))
        return 0

    payload = r["by_cat"].get("payload", 0)
    if args.max_payload is not None and payload > args.max_payload:
        print(json.dumps({"ok": False, "check": "max-payload", "payload": payload,
                          "limit": args.max_payload,
                          "overflow": payload - args.max_payload,
                          "hint": "新增内联载荷不得入库；拆掉旧块后可调低该上限"},
                         ensure_ascii=False))
        return 1

    if args.assert_baseline:
        bp = Path(args.assert_baseline)
        if not bp.exists():
            print(json.dumps({"error": f"基线不存在: {bp}"}, ensure_ascii=False))
            return 2
        base = json.loads(bp.read_text(encoding="utf-8"))
        known = {(it.get("func"), it.get("cat"), it.get("sha"))
                 for it in base.get("items", [])}
        new = [it for it in r["items"]
               if (it["func"], it["cat"], it["sha"]) not in known]
        out = {"baseline_total": base.get("total"), "current_total": r["total"],
               "new_count": len(new), "new": new[:50],
               "verdict": "NEW_FOUND" if new else "NO_NEW"}
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 1 if new else 0

    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return 0

    print(f"file: {r['file']}")
    print(f"total: {r['total']}")
    for k in ("comment", "import_probe", "wrapper", "payload"):
        print(f"  {k:<13} {r['by_cat'].get(k, 0)}")
    if not args.summary:
        print("\nby function (payload only):")
        rows = sorted(((f, d.get("payload", 0)) for f, d in r["by_func"].items()),
                      key=lambda x: -x[1])
        for f, n in rows:
            if n:
                print(f"  {n:>3}  {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
