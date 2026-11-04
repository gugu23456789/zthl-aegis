#!/usr/bin/env python3
"""gk_edit_verify.py — 写后落盘校验（2026-11-04）。

为什么要有（用户原话：「我有时候看不到你的更新去哪了，所以给我加个检测确保你真的
修改成功了」）：编辑动作**报告成功**与文件**真的变成预期内容**是两件事 ——
编码差异、路径落错（WSL `/mnt/c` vs `C:\\`）、写到了同名副本、锚点被上一次编辑吃掉了，
都会让「我以为改了」与「磁盘上是啥」分叉。本工具把这件事变成**可复现的一次判定**：
重读文件 → 逐条断言 → 打印命中行号 + sha256 作为证据。

判据（全部显式，缺省不猜）：
  --contains TEXT     必须出现（可多次；重复出现时报告次数与全部行号）
  --absent TEXT       必须不出现（可多次）
  --line N --line-has 第 N 行（1-based）必须包含某串（定位型断言）
  --sha256 HEX        整文件 sha256 必须等于给定值（**最强**断言：逐字节命中）
  --expect-changed    该文件必须在 git 工作区有改动 / 是未跟踪新文件（「更新去哪了」的直接回答）

用法：
  python3 scripts/gk_edit_verify.py --file scripts/x.py --contains "def foo" --expect-changed
  python3 scripts/gk_edit_verify.py --file scripts/x.py --line 42 --line-has "return 1" --json
退出码：0 全部 PASS；1 存在 FAIL（WARN 不计失败，除非 --strict）。
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_state(path: Path, root: Path) -> dict:
    """`git status --porcelain -- <path>` → {status: changed|clean|unknown, detail}。"""
    try:
        rel = str(path.resolve().relative_to(Path(root).resolve()))
    except ValueError:
        return {"status": "unknown", "detail": "文件不在仓库根内，无法对账"}
    try:
        r = subprocess.run(["git", "-C", str(root), "status", "--porcelain", "--", rel],
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as e:
        return {"status": "unknown", "detail": "git 不可用: %s" % type(e).__name__}
    if r.returncode != 0:
        return {"status": "unknown", "detail": "不是 git 仓库或 git 报错"}
    rows = [ln for ln in (r.stdout or "").splitlines() if ln.strip()]
    return {"status": "changed" if rows else "clean",
            "detail": "; ".join(rows) if rows else "工作区无改动（= 没有落盘，或内容与 HEAD 相同）"}


def _shown_lines(text: str, needle: str) -> list:
    return [i for i, ln in enumerate(text.splitlines(), 1) if needle in ln]


def verify(path: Path, contains=(), absent=(), line: int = 0, line_has: str = "",
           sha256: str = "", expect_changed: bool = False, root: Path = None) -> dict:
    """逐条断言；返回 {ok, file, sha256, size, checks[], git{}}。"""
    path = Path(path)
    checks = []

    def add(name, status, detail):
        checks.append({"check": name, "status": status, "detail": detail})

    if not path.is_file():
        add("exists", "FAIL", "文件不存在（写到了别处？路径形态差异？）")
        return {"ok": False, "file": str(path), "sha256": None, "size": None,
                "checks": checks, "git": {}}
    add("exists", "PASS", "存在")

    data = path.read_bytes()
    size = len(data)
    add("non_empty", "PASS" if size else "FAIL", "%d bytes" % size)
    text = data.decode("utf-8", errors="replace")
    digest = _sha256(path)

    for needle in contains:
        hits = _shown_lines(text, needle)
        if hits:
            add("contains", "PASS", "%r 命中 %d 处，行号 %s"
                % (needle, len(hits), hits[:10]))
        else:
            add("contains", "FAIL", "%r 未出现（锚点被吃掉 / 写错文件？）" % needle)

    for needle in absent:
        hits = _shown_lines(text, needle)
        if hits:
            add("absent", "FAIL", "%r 仍存在，行号 %s" % (needle, hits[:10]))
        else:
            add("absent", "PASS", "%r 已不存在" % needle)

    if line and line_has:
        lines = text.splitlines()
        if line > len(lines):
            add("line", "FAIL", "文件只有 %d 行，断言第 %d 行越界" % (len(lines), line))
        else:
            actual = lines[line - 1]
            ok = line_has in actual
            add("line", "PASS" if ok else "FAIL",
                "L%d = %r（期望包含 %r）" % (line, actual[:160], line_has))

    if sha256:
        ok = digest.lower() == sha256.lower()
        detail = "逐字节命中" if ok else "实测 %s ≠ 期望 %s" % (digest[:16], sha256[:16])
        add("sha256", "PASS" if ok else "FAIL", detail)

    git = {}
    if expect_changed:
        git = _git_state(path, Path(root or ROOT))
        if git["status"] == "changed":
            add("expect_changed", "PASS", git["detail"])
        elif git["status"] == "clean":
            add("expect_changed", "FAIL", git["detail"])
        else:
            add("expect_changed", "WARN", git["detail"])

    return {"ok": not any(c["status"] == "FAIL" for c in checks),
            "file": str(path), "sha256": digest, "size": size, "checks": checks, "git": git}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_edit_verify.py")
    ap.add_argument("--file", required=True)
    ap.add_argument("--contains", action="append", default=[])
    ap.add_argument("--absent", action="append", default=[])
    ap.add_argument("--line", type=int, default=0)
    ap.add_argument("--line-has", default="")
    ap.add_argument("--sha256", default="")
    ap.add_argument("--expect-changed", action="store_true")
    ap.add_argument("--root", default="")
    ap.add_argument("--strict", action="store_true", help="WARN 也计失败")
    ap.add_argument("--json", action="store_true")
    ns = ap.parse_args(argv)

    r = verify(Path(ns.file), contains=ns.contains, absent=ns.absent, line=ns.line,
               line_has=ns.line_has, sha256=ns.sha256,
               expect_changed=ns.expect_changed, root=ns.root or None)
    if ns.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print("edit-verify: %s %s sha256=%s"
              % ("PASS" if r["ok"] else "FAIL", r["file"],
                 (r["sha256"] or "-")[:16]))
        for c in r["checks"]:
            print("  [%s] %-15s %s" % (c["status"], c["check"], c["detail"]))
    bad = not r["ok"] or (ns.strict and any(c["status"] == "WARN" for c in r["checks"]))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
