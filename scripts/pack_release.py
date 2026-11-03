#!/usr/bin/env python3
"""发布包打包器（2026-11-02，对齐 `references/ci-pipeline-template.md` §3.6/§5/§6）。

输入一棵**已导出的树**（或任意待发布目录），产出：

  <out>/<name>-<version>.zip        确定性 zip（固定 mtime、路径排序、排除运行期产物）
  <out>/SHA256SUMS                 逐成员 sha256（不含自身；随包内根目录一份）
  <out>/PROVENANCE.json            来源声明（source repo/commit/tag + 导出策略 + 工具哈希）
  <out>/release-manifest.json      文件数 / 逐文件 sha256 / zip sha256 / 身份与禁词反查结果

纪律（沿 CI 模版）：
  · **拒发**：身份字面量 / 密钥形态 / 禁词命中 ⟹ exit 2，**不产出 zip**（fail-closed）。
  · **确定性**：同输入两次打包 zip sha256 必须相同（mtime 固定为 1980-01-01，成员排序；
    PROVENANCE.json **不含墙钟时间** ⟹ 不破坏确定性）。
  · **零网络**、仅标准库。
  · 身份/密钥正则优先复用 `oss_scrub`（单一事实源）；公开树无该模块时退化为保守内置形态。
  · **来源可对账**（2026-11-03）：`--source-repo/--source-commit/--source-tag`（缺省读
    `GITHUB_REPOSITORY/GITHUB_SHA/GITHUB_REF_NAME`）写进包内 PROVENANCE.json 与 manifest；
    导出排除面的权威文件 = `references/oss-export-whitelist.json`（记录其 sha256，不复制清单）。

用法：
  python3 scripts/pack_release.py --tree <dir> --out dist --version v0.9.2 \
      --source-repo owner/repo --source-commit <sha> --source-tag v0.9.2
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
EXCLUDE_NAMES = {"SHA256SUMS", "release-manifest.json", "pack-report.json",
                 "PROVENANCE.json"}
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
         source: dict = None, excluded: list = None, tool_sha: str = "") -> dict:
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

    # 来源声明（确定性：**不含墙钟时间**，否则同输入两次 zip sha 会不同）。
    policy_rel = "references/oss-export-whitelist.json"
    policy_abs = os.path.join(tree, *policy_rel.split("/"))
    policy_sha = (_sha256_bytes(open(policy_abs, "rb").read())
                  if os.path.isfile(policy_abs) else "")
    provenance = {
        "schema": "zthl-provenance/1",
        "version": version,
        "source": {k: v for k, v in (source or {}).items() if v},
        "export": {
            "policy": policy_rel if policy_sha else "",
            "policy_sha256": policy_sha,
            "tool_sha256": tool_sha or "",
            "excluded": sorted(excluded or []),
        },
        "license": "LICENSE",
        "payload_files": len(file_rows),
        "note": "clean export（非开发仓）；canonical 仓库与 commit 见 source 字段",
    }
    # 第三方存档标识（可选）：Concept DOI 稳定 ⟹ 可随包分发；Version DOI 不进包（上传后才存在）。
    archive_rel = "references/archive.json"
    archive_abs = os.path.join(tree, *archive_rel.split("/"))
    if os.path.isfile(archive_abs):
        try:
            with open(archive_abs, encoding="utf-8") as f:
                meta = json.load(f)
        except (OSError, ValueError):
            meta = {}
        arch = {k: str(meta.get(k) or "").strip()
                for k in ("concept_doi", "zenodo_record", "swhid")}
        arch = {k: v for k, v in arch.items() if v}
        if arch:
            provenance["archive"] = arch
    prov_bytes = (json.dumps(provenance, ensure_ascii=False, indent=2,
                             sort_keys=True) + "\n").encode("utf-8")
    prov_sha = _sha256_bytes(prov_bytes)

    sums_lines = ["%s  %s" % (r["sha256"], r["path"]) for r in file_rows]
    sums_lines.append("%s  %s" % (prov_sha, "PROVENANCE.json"))
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
        zi = zipfile.ZipInfo("PROVENANCE.json", date_time=(1980, 1, 1, 0, 0, 0))
        zi.external_attr = (0o644 & 0xFFFF) << 16
        zi.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(zi, prov_bytes)
        zi = zipfile.ZipInfo("SHA256SUMS", date_time=(1980, 1, 1, 0, 0, 0))
        zi.external_attr = (0o644 & 0xFFFF) << 16
        zi.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(zi, sum_text)

    with open(os.path.join(out, "SHA256SUMS"), "w", encoding="utf-8", newline="\n") as f:
        f.write(sum_text)
    with open(os.path.join(out, "PROVENANCE.json"), "wb") as f:
        f.write(prov_bytes)
    zip_sha = _sha256_bytes(open(zip_path, "rb").read())
    manifest = {
        "schema": "zthl-release-manifest/1",
        "version": version,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tree": os.path.basename(tree.rstrip("/\\")) or ".",
        "file_count": len(file_rows),
        "zip": os.path.basename(zip_path),
        "zip_sha256": zip_sha,
        "sha256sums_sha256": sum_sha,
        "provenance_sha256": prov_sha,
        "source": provenance["source"],
        "export": provenance["export"],
        "archive": provenance.get("archive", {}),
        "files": file_rows,
        "identity_hits": [],
        "forbidden_hits": [],
    }
    with open(os.path.join(out, "release-manifest.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return {"ok": True, "zip": zip_path, "zip_sha256": zip_sha,
            "file_count": len(file_rows), "manifest": manifest}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pack_release.py")
    ap.add_argument("--tree", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--forbidden", default="")
    ap.add_argument("--source-repo", default=os.environ.get("GITHUB_REPOSITORY", ""),
                    help="canonical 仓（缺省 GITHUB_REPOSITORY）")
    ap.add_argument("--source-commit", default=os.environ.get("GITHUB_SHA", ""),
                    help="本次发布对应 commit（缺省 GITHUB_SHA）")
    ap.add_argument("--source-tag", default=os.environ.get("GITHUB_REF_NAME", ""),
                    help="发布 tag（缺省 GITHUB_REF_NAME）")
    ap.add_argument("--exclude", action="append", default=[], metavar="PATH",
                    help="写入 PROVENANCE.json 的排除面声明（可重复；仅记录，不改变打包）")
    ap.add_argument("--export-tool-sha256", default="",
                    help="导出自证工具的 sha256（缺省取 <tree>/scripts/oss_scrub.py）")
    ap.add_argument("--json", action="store_true")
    ns = ap.parse_args(argv)
    tool_sha = ns.export_tool_sha256
    if not tool_sha:
        cand = os.path.join(ns.tree, "scripts", "oss_scrub.py")
        if os.path.isfile(cand):
            tool_sha = hashlib.sha256(open(cand, "rb").read()).hexdigest()
    source = {"repo": ns.source_repo, "commit": ns.source_commit, "tag": ns.source_tag}
    r = pack(ns.tree, ns.out, ns.version, ns.forbidden, source=source,
             excluded=ns.exclude, tool_sha=tool_sha)
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
