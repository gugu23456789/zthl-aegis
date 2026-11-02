#!/usr/bin/env python3
"""gk_gate_evidence.py — gate 源码变更证据摘要（F-REV-11 C2，2026-09-10）

出处：security-hardening-assessment F-REV-11 C2。审计/红队/L2/后R 的职责核心是
gatekeeper-cli.sh（advance 绕过 / --force / guard-edit 全在 gate bash），但 LLM 车道此前
既读不到 gate（角色面：L2/后R 落 default → read_repo 无 gate），也无变更面证据（证据面）
→ 红队曾因读不到 bash 误判"F-REV-9 未接线"。

本脚本产 **gate 源码变更摘要**（确定性 0-API），经 GK_GATE_EVIDENCE env 注入
subagent_runner（对齐 GK_L3_EVIDENCE 预取先例：单计算点、失败降级不阻断）。

用法:
  python3 gk_gate_evidence.py --repo-dir <dir> --base <ref> [--paths gatekeeper-cli.sh] [--max-chars 1200]

输出契约:
  {"available": true, "repo_dir", "base", "paths", "files": [{"path","added","deleted"}],
   "hunks": n, "digest": "..."}
  {"available": false, "error": "..."}   # 失败 exit 0 —— 预取不可用不阻断
"""
import argparse
import json
import subprocess
import sys

DEFAULT_PATHS = ["gatekeeper-cli.sh"]
DEFAULT_MAX_CHARS = 1200


def parse_numstat(text: str) -> list:
    """`git diff --numstat` 输出 → [{"path","added","deleted"}]（二进制 → added/deleted 为 None）。"""
    out = []
    for line in (text or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        a, d, p = parts[0].strip(), parts[1].strip(), parts[2].strip()
        if not p:
            continue
        out.append({
            "path": p,
            "added": None if a == "-" else int(a) if a.isdigit() else 0,
            "deleted": None if d == "-" else int(d) if d.isdigit() else 0,
        })
    return out


def hunk_headers(text: str, limit: int = 12) -> list:
    """从 `git diff -U0` 输出提取 hunk 头（`@@ ... @@`），最多 limit 条。"""
    out = []
    for line in (text or "").splitlines():
        if line.startswith("@@"):
            out.append(line.strip()[:100])
            if len(out) >= limit:
                break
    return out


def _git(repo_dir: str, args: list, timeout: int = 60) -> tuple:
    """git -C repo_dir <args> → (rc, stdout)。异常 → (1, "")。"""
    try:
        r = subprocess.run(["git", "-C", repo_dir] + args,
                           capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "")
    except Exception:
        return 1, ""


def build(repo_dir: str, base: str, paths=None, max_chars: int = DEFAULT_MAX_CHARS) -> dict:
    """收集 gate 变更证据 + 有界摘要；git 不可用/失败 → available:false（不抛）。"""
    paths = list(paths or DEFAULT_PATHS)
    rng = f"{base}..HEAD"
    rc_a, numstat = _git(repo_dir, ["diff", "--numstat", rng, "--", *paths])
    if rc_a != 0:
        return {"available": False, "error": f"git diff --numstat failed (rc={rc_a})"}
    rc_b, diff0 = _git(repo_dir, ["diff", "-U0", rng, "--", *paths])
    files = parse_numstat(numstat)
    hunks = hunk_headers(diff0) if rc_b == 0 else []
    head = [f"gate 源码变更证据（{rng}，{' '.join(paths)}）",
            f"变更文件 {len(files)} 个 · 变更块 {len(hunks)} 个"]
    body = []
    for f in files:
        a = "-" if f["added"] is None else f["added"]
        d = "-" if f["deleted"] is None else f["deleted"]
        body.append(f"  {f['path']} +{a}/-{d}")
    body.extend("  " + h for h in hunks)
    if not files:
        body.append("  (无变更——gate 源码本区间未改动)")
    digest = "\n".join(head + body)
    return {"available": True, "repo_dir": repo_dir, "base": base, "paths": paths,
            "files": files, "hunks": len(hunks), "digest": digest[:max_chars]}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    p = argparse.ArgumentParser(description="gate 源码变更证据摘要（F-REV-11 C2）")
    p.add_argument("--repo-dir", required=True)
    p.add_argument("--base", default="HEAD~1")
    p.add_argument("--paths", default=",".join(DEFAULT_PATHS),
                   help="逗号分隔的相对路径（默认 gatekeeper-cli.sh）")
    p.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    a = p.parse_args(argv)
    paths = [s.strip() for s in a.paths.split(",") if s.strip()]
    print(json.dumps(build(a.repo_dir, a.base, paths, a.max_chars), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
