"""gk_public_bridge.py — 私仓 → 公开仓的**单向**发布桥（2026-11-08，owner 裁定）。

权威方向（唯一）：**私仓 = 唯一权威**；公开仓 = `oss_scrub export` 的**过滤产物**。
本桥只做私仓 → 公开仓单写，**绝不**把公开仓内容回灌私仓。

链路（一条命令）：
  ① 发布预检（`scripts/gk_release_preflight.py`，非 0 ⟹ 拒发）
  ② `scripts/oss_scrub.py export` 导出**过滤快照**（白名单/去标识/禁词复扫全在该脚本内）
  ③ 镜像到公开工作副本（整树同步：多余文件删除，`.git` 永不动）
  ④ 公开仓 commit（无变更 ⟹ 拒发，不产空提交）
  ⑤ **双 annotated tag**：公开仓 `<version>` + 私仓 `<version>`（同名同发布口径）
  ⑥ push（默认带推送；**永不 force**）—— 公开 `HEAD:main` + tag；私仓 tag
  ⑦ 记账 `docs/oss/release-line.json`（版本 ↔ 私仓 commit ↔ 公开 commit ↔ 导出文件数）
     `docs/` 在导出排除面内 ⟹ 账本仅存私仓，不随包外泄。

安全闸（任一条不满足即拒，零写）：
  · `--apply` 才落刀；缺省 dry-run（与 `apply-worktree --reclaim` 同纪律）
  · 版本已存在于任一仓 ⟹ 拒（禁重发/禁覆盖）
  · 公开工作副本有未提交变更 ⟹ 拒（防把他人改动裹进发布）
  · 公开目录 == 私仓 / 不是 git 仓 / 不是 `main` 分支 ⟹ 拒
  · 私仓不是 clean master ⟹ 拒（发布源必须确定）
  · 远端必须命中 `GK_PUBLIC_REMOTE_ALLOW`（默认 `github.com/`）；**禁 force push**（无该路径）
  · 预检 / 导出一律 fail-loud；导出文件数 0 ⟹ 拒

用法：
  python scripts/gk_public_bridge.py release --version v0.9.8.2            # dry-run
  python scripts/gk_public_bridge.py release --version v0.9.8.2 --apply    # 落刀（含 push）
  python scripts/gk_public_bridge.py release --version v0.9.8.2 --apply --no-push
  python scripts/gk_public_bridge.py audit                                 # 双仓 tag 对账
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_PUBLIC_DIR = os.environ.get("GK_PUBLIC_DIR", r"<home>\zthl-aegis-public")
LINE_FILE = os.path.join(ROOT, "docs", "oss", "release-line.json")
VERSION_RE = re.compile(r"^v\d+(\.\d+){1,4}$")
REMOTE_ALLOW = [p for p in os.environ.get("GK_PUBLIC_REMOTE_ALLOW", "github.com/").split(",") if p]


def _norm(p):
    """Windows 形态 → POSIX 形态（同一默认值可在 WSL / Windows 两侧直接可用）。"""
    if p and os.name != "nt" and re.match(r"[A-Za-z]:[\\/]", p):
        return "/mnt/%s/%s" % (p[0].lower(), p[2:].replace("\\", "/").lstrip("/"))
    return p


def _run(cmd, cwd=None, env=None, timeout=900):
    """跑子进程；返回 (rc, stdout, stderr)。env=None ⟹ 继承但剔除 STATE_FILE（防域 state 干扰）。"""
    e = dict(os.environ)
    e.pop("STATE_FILE", None)
    if env:
        e.update(env)
    try:
        p = subprocess.run(cmd, cwd=cwd, env=e, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.SubprocessError) as ex:  # noqa: BLE001 — 边界：统一 fail-loud
        return 127, "", str(ex)


def _git(repo, *args):
    return _run(["git", "-C", repo, *args])


def _git_out(repo, *args):
    rc, out, _ = _git(repo, *args)
    return out.strip() if rc == 0 else ""


def _fail(code, msg, detail=""):
    return {"ok": False, "error": code, "message": msg, "detail": detail}


# ── 纯步骤（可单测） ────────────────────────────────────────────────────────────
def _tree_files(root):
    """目录内全部文件相对路径（跳过顶层 `.git`）。"""
    out = []
    for dirpath, dirs, files in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".":
            dirs[:] = [d for d in dirs if d != ".git"]
        for f in files:
            rel = os.path.normpath(os.path.join(rel_dir, f)) if rel_dir != "." else f
            out.append(rel.replace(os.sep, "/"))
    return sorted(out)


def sync_tree(export_dir, public_dir, apply=False):
    """整树镜像：export_dir ⟹ public_dir（多余文件删除；`.git` 永不触碰）。

    返回 {added, updated, deleted, unchanged, removed_dirs}；dry-run 零写。
    """
    src = {p for p in _tree_files(export_dir)}
    dst = {p for p in _tree_files(public_dir)}
    rep = {"added": [], "updated": [], "deleted": [], "unchanged": 0, "removed_dirs": []}
    for rel in sorted(src):
        s = os.path.join(export_dir, rel.replace("/", os.sep))
        d = os.path.join(public_dir, rel.replace("/", os.sep))
        if not os.path.exists(d):
            rep["added"].append(rel)
        elif os.path.getsize(s) != os.path.getsize(d) or _sha(s) != _sha(d):
            rep["updated"].append(rel)
        else:
            rep["unchanged"] += 1
            continue
        if apply:
            os.makedirs(os.path.dirname(d), exist_ok=True)
            shutil.copy2(s, d)
    for rel in sorted(dst - src):
        rep["deleted"].append(rel)
        if apply:
            p = os.path.join(public_dir, rel.replace("/", os.sep))
            try:
                os.remove(p)
            except OSError:
                pass
    if apply:
        # 清空目录（自底向上；`.git` 与工作树根保留）
        for dirpath, dirs, files in os.walk(public_dir, topdown=False):
            if dirpath == public_dir:
                continue
            rel = os.path.relpath(dirpath, public_dir)
            if rel.split(os.sep)[0] == ".git":
                continue
            if not dirs and not files:
                try:
                    os.rmdir(dirpath)
                    rep["removed_dirs"].append(rel.replace(os.sep, "/"))
                except OSError:
                    pass
    return rep


def _sha(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_notes_title(path):
    """发布说明首行（非空、去 `#`）—— 用作 commit/tag 的短标题。"""
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            s = ln.strip()
            if s:
                return s.lstrip("# ").strip()
    return ""


def load_line(path=LINE_FILE):
    if not os.path.exists(path):
        return {"schema": "gk-release-line/1", "what": "私仓→公开仓发布映射（私仓唯一权威）",
                "releases": []}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save_line(data, path=LINE_FILE):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")


def tag_names(repo):
    rc, out, _ = _git(repo, "tag", "-l")
    return sorted(x for x in out.split() if x) if rc == 0 else []


def audit(private_repo=ROOT, public_dir=DEFAULT_PUBLIC_DIR):
    """双仓 tag 对账（只读）：同名 / 仅私仓 / 仅公开，附发布日期。"""
    private_repo, public_dir = _norm(private_repo), _norm(public_dir)
    pri = tag_names(private_repo)
    pub = tag_names(public_dir) if os.path.isdir(public_dir) else []
    both = sorted(set(pri) & set(pub))
    return {
        "ok": True,
        "private_repo": private_repo,
        "public_dir": public_dir,
        "private_count": len(pri),
        "public_count": len(pub),
        "common": both,
        "only_private": sorted(set(pri) - set(pub)),
        "only_public": sorted(set(pub) - set(pri)),
        "verdict": "IN_SYNC" if set(pri) == set(pub) else "DRIFT",
    }


# ── 主流程 ─────────────────────────────────────────────────────────────────────
def release(version, public_dir=DEFAULT_PUBLIC_DIR, notes="", apply=False, push=True,
            private_repo=ROOT, preflight=_run, exporter=None, verbose=False):
    """单向发布。`apply=False` = dry-run（零写、零 push）；返回上报 dict。"""
    public_dir = _norm(public_dir)
    private_repo = _norm(private_repo)
    if not VERSION_RE.match(version or ""):
        return _fail("BAD_VERSION", "版本须形如 v0.9.8.2（regex %s）" % VERSION_RE.pattern, version)
    if not os.path.isdir(private_repo):
        return _fail("PRIVATE_MISSING", "私仓不存在", private_repo)
    if not os.path.isdir(public_dir):
        return _fail("PUBLIC_MISSING", "公开工作副本不存在", public_dir)
    if os.path.abspath(public_dir) == os.path.abspath(private_repo):
        return _fail("SAME_DIR", "公开目录不得等于私仓", public_dir)
    if _git_out(public_dir, "rev-parse", "--git-dir") == "":
        return _fail("PUBLIC_NOT_GIT", "公开目录不是 git 仓库", public_dir)
    br = _git_out(public_dir, "rev-parse", "--abbrev-ref", "HEAD")
    if br != "main":
        return _fail("PUBLIC_BRANCH", "公开仓须在 main 分支（当前 %s）" % br, public_dir)
    priv_br = _git_out(private_repo, "rev-parse", "--abbrev-ref", "HEAD")
    if priv_br != "master":
        return _fail("PRIVATE_BRANCH", "私仓发布源须在 master（当前 %s）" % priv_br, private_repo)
    if _git(private_repo, "status", "--porcelain")[1].strip():
        return _fail("PRIVATE_DIRTY", "私仓工作区不干净 ⟹ 发布源不确定",
                     _git(private_repo, "status", "--porcelain")[1][:400])
    if _git(public_dir, "status", "--porcelain")[1].strip():
        return _fail("PUBLIC_DIRTY", "公开工作副本有未提交变更 ⟹ 拒（防裹入他人改动）",
                     _git(public_dir, "status", "--porcelain")[1][:400])
    remote = _git_out(public_dir, "remote", "get-url", "origin")
    if not remote or not any(p in remote for p in REMOTE_ALLOW):
        return _fail("REMOTE_NOT_ALLOWED", "公开远端不在白名单 %s" % REMOTE_ALLOW, remote)
    for repo, name in ((private_repo, "私仓"), (public_dir, "公开仓")):
        if _git_out(repo, "rev-parse", "--verify", "refs/tags/" + version):
            return _fail("TAG_EXISTS", "%s已存在 tag %s ⟹ 禁重发/禁覆盖" % (name, version), version)
    if not notes:
        notes = os.path.join(private_repo, "RELEASE-NOTES", "RELEASE-NOTES-%s.md" % version)
    if not os.path.isfile(notes):
        return _fail("NOTES_MISSING", "缺发布说明（发布即事实，须先写说明）", notes)
    title = read_notes_title(notes)
    if not title:
        return _fail("NOTES_EMPTY", "发布说明为空", notes)
    line = load_line(os.path.join(private_repo, "docs", "oss", "release-line.json"))
    if any(r.get("version") == version for r in line.get("releases", [])):
        return _fail("LINE_DUP", "release-line 已登记该版本", version)

    tmp = tempfile.mkdtemp(prefix="gk-pub-export-")
    rep = {"ok": True, "dry_run": not apply, "version": version,
           "private_repo": private_repo, "public_dir": public_dir, "remote": remote,
           "notes": notes, "title": title, "export_dir": tmp}
    try:
        # ① 预检（导出前）
        rc, out, err = preflight([sys.executable, os.path.join(private_repo, "scripts",
                                                               "gk_release_preflight.py")],
                                 cwd=private_repo)
        rep["preflight_rc"] = rc
        rep["preflight_tail"] = (out or err).strip().splitlines()[-3:]
        if rc != 0:
            return _fail("PREFLIGHT_FAILED", "发布预检未通过 ⟹ 拒发", rep["preflight_tail"])
        # ② 过滤导出（单一事实源 = oss_scrub）
        if exporter is None:
            exporter = _run
        rc, out, err = exporter([sys.executable, os.path.join(private_repo, "scripts", "oss_scrub.py"),
                                 "export", "--out", tmp], cwd=private_repo)
        rep["export_rc"] = rc
        rep["export_tail"] = (out or err).strip().splitlines()[-3:]
        if rc != 0:
            return _fail("EXPORT_FAILED", "导出未通过 ⟹ 拒发", rep["export_tail"])
        files = _tree_files(tmp)
        rep["exported_files"] = len(files)
        if not files:
            return _fail("EXPORT_EMPTY", "导出文件数为 0 ⟹ 拒发", tmp)
        # ③ 镜像
        diff = sync_tree(tmp, public_dir, apply=apply)
        rep["sync"] = {k: (v if isinstance(v, int) else len(v)) for k, v in diff.items()}
        if verbose:
            rep["sync_detail"] = diff
        else:
            rep["sync_sample"] = {k: (v[:5] if isinstance(v, list) else v) for k, v in diff.items()}
        if apply and not diff["added"] and not diff["updated"] and not diff["deleted"]:
            return _fail("NO_CHANGES", "导出树与公开仓内容一致 ⟹ 拒发（不产空提交）", rep["sync"])
        if not apply:
            rep["action"] = "WOULD-COMMIT-AND-TAG"
            return rep
        # ④ commit
        _git(public_dir, "add", "-A")
        if _git(public_dir, "diff", "--cached", "--quiet")[0] == 0:
            return _fail("NO_CHANGES", "暂存后无差异 ⟹ 拒发", public_dir)
        priv_head = _git_out(private_repo, "rev-parse", "HEAD")
        msg = "release: %s（%s）\n\n源: 私仓 %s（gk_public_bridge 过滤导出）" % (
            version, title, priv_head[:8])
        rc, _, err = _git(public_dir, "-c", "user.name=" + os.environ.get(
            "GK_PUBLIC_AUTHOR_NAME", "zthl-release"),
            "-c", "user.email=" + os.environ.get("GK_PUBLIC_AUTHOR_EMAIL", "release@local"),
            "commit", "-m", msg)
        if rc != 0:
            return _fail("PUBLIC_COMMIT_FAILED", "公开仓提交失败", err[-400:])
        pub_head = _git_out(public_dir, "rev-parse", "HEAD")
        rep["private_commit"] = priv_head
        rep["public_commit"] = pub_head
        # ⑤ 双 annotated tag（同名）
        rc, _, err = _git(public_dir, "tag", "-a", version, "-m", "%s（源 %s）" % (title, priv_head[:8]))
        if rc != 0:
            return _fail("PUBLIC_TAG_FAILED", "公开仓打 tag 失败", err[-300:])
        rc, _, err = _git(private_repo, "tag", "-a", version, "-m",
                          "%s（公开 %s）" % (title, pub_head[:8]))
        if rc != 0:
            return _fail("PRIVATE_TAG_FAILED", "私仓打 tag 失败（公开仓已提交/tag，需人工核对）",
                         err[-300:])
        rep["tags_created"] = True
        # ⑥ push（永不 force）
        if push:
            rc, out, err = _git(public_dir, "push", "origin", "HEAD:main")
            rep["public_push_rc"] = rc
            if rc != 0:
                return _fail("PUBLIC_PUSH_FAILED", "公开仓 push 失败", (err or out)[-400:])
            rc, out, err = _git(public_dir, "push", "origin", version)
            rep["public_tag_push_rc"] = rc
            if rc != 0:
                return _fail("PUBLIC_TAG_PUSH_FAILED", "公开 tag push 失败", (err or out)[-400:])
            rc, out, err = _git(private_repo, "push", "origin", version)
            rep["private_tag_push_rc"] = rc
            if rc != 0:
                rep["warn"] = "私仓 tag push 失败（发布本体已成立）：" + (err or out)[-200:]
        # ⑦ 记账（docs/ 不导出 ⟹ 仅私仓）
        line.setdefault("releases", []).append({
            "version": version,
            "private_commit": priv_head,
            "public_commit": pub_head,
            "exported_files": len(files),
            "released_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "remote": remote,
        })
        lp = os.path.join(private_repo, "docs", "oss", "release-line.json")
        save_line(line, lp)
        rc, _, err = _git(private_repo, "add", os.path.relpath(lp, private_repo).replace(os.sep, "/"))
        if rc == 0:
            _git(private_repo, "-c", "user.name=gatekeeper", "-c", "user.email=gatekeeper@local",
                 "commit", "-m", "docs(oss): release-line 登记 %s" % version)
        rep["line_file"] = lp
        return rep
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description="私仓 → 公开仓单向发布桥（默认 dry-run）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("release", help="导出 + 镜像 + commit + 双 tag + push + 记账")
    r.add_argument("--version", required=True)
    r.add_argument("--public-dir", default=DEFAULT_PUBLIC_DIR)
    r.add_argument("--notes", default="")
    r.add_argument("--apply", action="store_true", help="落刀（缺省 dry-run）")
    r.add_argument("--no-push", action="store_true", help="只做本地 commit/tag，不 push")
    r.add_argument("--verbose", action="store_true", help="回包带完整 diff 清单（默认只取样例）")
    a = sub.add_parser("audit", help="双仓 tag 对账（只读）")
    a.add_argument("--public-dir", default=DEFAULT_PUBLIC_DIR)
    ns = ap.parse_args(argv)
    if ns.cmd == "audit":
        print(json.dumps(audit(public_dir=ns.public_dir), ensure_ascii=False, indent=2))
        return 0
    rep = release(ns.version, public_dir=ns.public_dir, notes=ns.notes,
                  apply=ns.apply, push=not ns.no_push, verbose=ns.verbose)
    print(json.dumps(rep, ensure_ascii=False, indent=2))
    return 0 if rep.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
