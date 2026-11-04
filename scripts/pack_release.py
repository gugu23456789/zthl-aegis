#!/usr/bin/env python3
"""发布包打包器（2026-11-02，对齐 `references/ci-pipeline-template.md` §3.6/§5/§6）。

输入一棵**已导出的树**（或任意待发布目录），产出：

  <out>/<name>-<version>.zip        确定性 zip（固定 mtime、路径排序、排除运行期产物）
  <out>/SHA256SUMS                 逐文件 sha256（不含自身；随包内根目录一份）
  <out>/release-manifest.json      文件数 / 逐文件 sha256 / zip sha256 / 身份与禁词反查结果
  <out>/PROVENANCE.json            来源绑定（repo / commit / tag）+ 主体 sha256（发布资产必需）

纪律（沿 CI 模版）：
  · **拒发**：身份字面量 / 密钥形态 / 禁词命中 ⟹ exit 2，**不产出 zip**（fail-closed）。
  · **确定性**：同输入两次打包 zip sha256 必须相同（mtime 固定为 1980-01-01，成员排序）。
  · **零网络**、仅标准库。
  · 身份/密钥正则优先复用 `oss_scrub`（单一事实源）；公开树无该模块时退化为保守内置形态。

用法：
  python3 scripts/pack_release.py --tree <dir> --out dist --version v0.9.2
  python3 scripts/pack_release.py --tree <dir> --out dist --version v0.9.2 \
      --forbidden docs/oss/forbidden-terms.txt --json
"""
import argparse
import hashlib
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone

EXCLUDE_DIRS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".zthl", ".keys",
                "dist", "node_modules", ".venv", "venv", ".venv-accept", ".idea", ".vscode"}
# 运行期落盘（2026-11-02）：CI release 作业先跑 smoke ⟹ 仓库根出现 `.gatekeeper.*`
#   （state / plan / session / write-claims 等）；`pack-report.json` 由 shell 重定向预建。
#   二者都是**运行期产物**，进包即污染发布物（且 claims 属运行元数据）。
EXCLUDE_PREFIXES = (".gatekeeper.",)
EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".log", ".tmp", ".bak", ".sig", ".seal")
EXCLUDE_NAMES = {"SHA256SUMS", "release-manifest.json", "pack-report.json"}
# 未脱敏的私仓原件标记（2026-11-02）：`oss_scrub export` 会剥离 `GK-PUBLIC:CUT-*` 块；
#   打包树里仍有标记 ⟹ 这是**私仓树/漏跑 export**，不是发布树 ⟹ fail-closed 拒发。
_PUBLIC_MARKER = re.compile(r"<!--\s*" + re.escape("GK-PUBLIC:CUT-START") + r"\b")

# 公开树没有 oss_scrub 时的保守兜底（只挡「本机绝对路径」这一类最硬的身份形态）
_FALLBACK_IDENTITY = (
    re.compile(r"C:[\\/]+Users[\\/]+[A-Za-z0-9_.-]+"),
    re.compile(r"/mnt/c/Users/[A-Za-z0-9_.-]+"),
)
_FALLBACK_SECRET = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
)


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _excluded(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    if any(p in EXCLUDE_DIRS for p in parts[:-1]):
        return True
    name = parts[-1]
    if name in EXCLUDE_NAMES:
        return True
    if name.startswith(EXCLUDE_PREFIXES):
        return True
    if name.endswith(EXCLUDE_SUFFIXES):
        return True
    return False


def walk(tree: str) -> list:
    """→ 排序后的相对路径列表（排除运行期产物与器身文件）。"""
    out = []
    for root, dirs, files in os.walk(tree):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDE_DIRS)
        for f in sorted(files):
            rel = os.path.relpath(os.path.join(root, f), tree).replace("\\", "/")
            if not _excluded(rel):
                out.append(rel)
    return sorted(out)


def _scan_text(text: str) -> list:
    """→ 命中标签列表。优先 oss_scrub 单一事实源，缺失则保守兜底。"""
    hits = []
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import oss_scrub as S
        hits.extend(h[0] for h in S.scan_text(text, S.SECRET_PATTERNS))
        hits.extend(h[0] for h in S.scan_text(text, S.IDENTITY_PATTERNS))
        return hits
    except Exception:
        for rx in _FALLBACK_SECRET:
            if rx.search(text):
                hits.append("secret")
        for rx in _FALLBACK_IDENTITY:
            if rx.search(text):
                hits.append("identity")
        return hits


def _load_terms(path: str) -> list:
    if not path:
        return []
    terms = []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            s = ln.strip()
            if s and not s.startswith("#"):
                terms.append(s)
    return terms


def pack(tree: str, out: str, version: str, forbidden: str = "",
         source_repo: str = "", source_commit: str = "", source_tag: str = "") -> dict:
    tree = os.path.abspath(tree)
    out = os.path.abspath(out)
    if not os.path.isdir(tree):
        raise SystemExit("tree 不是目录: %s" % tree)
    if os.path.isdir(os.path.join(tree, ".keys")):
        # fail-closed：私仓原树含密钥面 ⟹ 不是已清洗的发布树（先跑 oss_scrub export）
        raise SystemExit("tree 含 .keys（未清洗的私仓树）⟹ 拒发")
    if not os.path.isfile(os.path.join(tree, "LICENSE")):
        raise SystemExit("tree 缺 LICENSE（发布包必须带许可）")
    terms = _load_terms(forbidden)
    files = walk(tree)
    if not files:
        raise SystemExit("tree 为空: %s" % tree)

    identity_hits, forbidden_hits, marker_hits, file_rows = [], [], [], []
    for rel in files:
        with open(os.path.join(tree, rel), "rb") as f:
            raw = f.read()
        file_rows.append({"path": rel, "sha256": _sha256_bytes(raw), "size": len(raw)})
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        hits = _scan_text(text)
        if hits:
            identity_hits.append({"path": rel, "hits": sorted(set(hits))})
        if _PUBLIC_MARKER.search(text):
            marker_hits.append({"path": rel})
        for t in terms:
            if t in text:
                forbidden_hits.append({"path": rel, "term": t})

    if identity_hits or forbidden_hits or marker_hits:
        return {"ok": False, "refused": True, "identity_hits": identity_hits,
                "forbidden_hits": forbidden_hits, "public_marker_hits": marker_hits,
                "files": file_rows}

    os.makedirs(out, exist_ok=True)
    base = "zthl-aegis-%s" % version
    zip_path = os.path.join(out, base + ".zip")
    sums_lines = ["%s  %s" % (r["sha256"], r["path"]) for r in file_rows]
    sum_text = "\n".join(sums_lines) + "\n"
    sum_sha = _sha256_bytes(sum_text.encode("utf-8"))

    # 确定性 zip：固定 mtime + 排序 + 固定权限位
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for r in file_rows:
            zi = zipfile.ZipInfo(r["path"], date_time=(1980, 1, 1, 0, 0, 0))
            zi.external_attr = (0o644 & 0xFFFF) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(os.path.join(tree, r["path"]), "rb") as f:
                z.writestr(zi, f.read())
        zi = zipfile.ZipInfo("SHA256SUMS", date_time=(1980, 1, 1, 0, 0, 0))
        zi.external_attr = (0o644 & 0xFFFF) << 16
        zi.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(zi, sum_text)

    with open(os.path.join(out, "SHA256SUMS"), "w", encoding="utf-8", newline="\n") as f:
        f.write(sum_text)
    zip_sha = _sha256_bytes(open(zip_path, "rb").read())
    manifest = {
        "schema": "zthl-release-manifest/1",
        "version": version,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tree": tree,
        "file_count": len(file_rows),
        "zip": os.path.basename(zip_path),
        "zip_sha256": zip_sha,
        "sha256sums_sha256": sum_sha,
        "files": file_rows,
        "identity_hits": [],
        "forbidden_hits": [],
    }
    with open(os.path.join(out, "release-manifest.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")
    # 2026-11-04（CI 契约修复）：release.yml 的 publish 步要求 `dist/PROVENANCE.json`
    #   （并传 `--source-repo/--source-commit/--source-tag`），原实现既不产出该文件也不认这些
    #   参数 ⟹ 发版作业在 pack 步直接 argparse 退出 2（v0.9.6.8–v0.9.6.10 连续三版）。
    provenance = {
        "schema": "zthl-provenance/1",
        "version": version,
        "source": {"repo": source_repo or None, "commit": source_commit or None,
                   "tag": source_tag or None},
        "subject": [
            {"name": os.path.basename(zip_path), "sha256": zip_sha},
            {"name": "SHA256SUMS", "sha256": sum_sha},
        ],
        "file_count": len(file_rows),
        "created_at": manifest["created_at"],
        "builder": {"tool": "scripts/pack_release.py", "deterministic": True},
    }
    with open(os.path.join(out, "PROVENANCE.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump(provenance, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return {"ok": True, "zip": zip_path, "zip_sha256": zip_sha,
            "file_count": len(file_rows), "manifest": manifest,
            "provenance": os.path.join(out, "PROVENANCE.json")}


def build_parser() -> argparse.ArgumentParser:
    """CLI 契约**单源**：`main()` 与发布预检（`gk_release_preflight.py`）共用。

    2026-11-04 事故：release.yml 传 `--source-*` 而本脚本不认 ⟹ 发版 CI 连续三版在
    pack 步 argparse 退出 2。预检必须能从同一 parser 读出「支持哪些 flag」。
    """
    ap = argparse.ArgumentParser(prog="pack_release.py")
    ap.add_argument("--tree", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--forbidden", default="")
    ap.add_argument("--source-repo", default="")
    ap.add_argument("--source-commit", default="")
    ap.add_argument("--source-tag", default="")
    ap.add_argument("--json", action="store_true")
    return ap


def main(argv=None) -> int:
    ns = build_parser().parse_args(argv)
    r = pack(ns.tree, ns.out, ns.version, ns.forbidden,
             source_repo=ns.source_repo, source_commit=ns.source_commit,
             source_tag=ns.source_tag)
    if ns.json:
        print(json.dumps({k: v for k, v in r.items() if k != "files"}, ensure_ascii=False, indent=2))
    if not r.get("ok"):
        if not ns.json:
            print("REFUSED: identity=%d forbidden=%d public_markers=%d"
                  % (len(r.get("identity_hits") or []), len(r.get("forbidden_hits") or []),
                     len(r.get("public_marker_hits") or [])))
            for h in (r.get("identity_hits") or [])[:10]:
                print("  identity", h["path"], h["hits"])
            for h in (r.get("forbidden_hits") or [])[:10]:
                print("  forbidden", h["path"], h["term"])
            for h in (r.get("public_marker_hits") or [])[:10]:
                print("  public_marker", h["path"], "⟹ 先跑 oss_scrub export（未脱敏树不得发布）")
        return 2
    if not ns.json:
        print("OK %s (%d files) sha256=%s" % (r["zip"], r["file_count"], r["zip_sha256"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
