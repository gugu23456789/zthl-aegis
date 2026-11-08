"""test_gk_public_bridge.py — 单向发布桥红先臂集（2026-11-08，owner 裁定「私仓唯一权威」）。

锁四件事：
  ① **方向**：只私仓 → 公开仓；公开仓内容永不回灌（静态：无 fetch/pull/checkout 公开面）。
  ② **镜像语义**：整树同步（新增/更新/删除），`.git` 永不触碰。
  ③ **安全闸**：版本已存在 / 公开脏 / 公开非 main / 私仓脏 ⟹ 拒（零写）；**无 force push 路径**。
  ④ **双 tag + 账本**：同名 annotated tag 落两仓；`docs/oss/release-line.json` 记录映射。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_public_bridge as pb


def _git(repo, *a):
    return subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)


def _init(repo, branch):
    repo.mkdir(parents=True, exist_ok=True)
    _git(str(repo), "init", "-q", "-b", branch)
    (repo / "seed.txt").write_text("seed", encoding="utf-8")
    _git(str(repo), "add", "seed.txt")
    _git(str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "seed")
    return str(repo)


@pytest.fixture()
def two_repos(tmp_path):
    pri = _init(tmp_path / "private", "master")
    pub = _init(tmp_path / "public", "main")
    _git(pub, "remote", "add", "origin", "https://github.com/gugu23456789/zthl-aegis.git")
    return pri, pub


def _stub_preflight(cmd, cwd=None):
    return 0, "PASS preflight", ""


def _make_exporter(files):
    """伪造导出器：把给定 {rel: content} 写到命令里的 --out 目录。"""
    def _exp(cmd, cwd=None):
        out = cmd[cmd.index("--out") + 1]
        for rel, content in files.items():
            p = os.path.join(out, rel.replace("/", os.sep))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(content)
        return 0, "export: %d files copied" % len(files), ""
    return _exp


def _write_notes(pri, version, title="ZTHL Aegis 发布"):
    d = os.path.join(pri, "RELEASE-NOTES")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "RELEASE-NOTES-%s.md" % version)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write("# %s\n\n正文。\n" % title)
    _git(pri, "add", os.path.relpath(p, pri))
    _git(pri, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "notes " + version)
    return p


def test_sync_tree_dry_run_zero_write(tmp_path):
    exp = tmp_path / "exp"
    pub = tmp_path / "pub"
    exp.mkdir()
    pub.mkdir()
    (exp / "a.txt").write_text("new", encoding="utf-8")
    (pub / "a.txt").write_text("old", encoding="utf-8")
    (pub / "extra.txt").write_text("x", encoding="utf-8")
    r = pb.sync_tree(str(exp), str(pub), apply=False)
    assert r["updated"] == ["a.txt"] and r["deleted"] == ["extra.txt"], r
    assert (pub / "a.txt").read_text(encoding="utf-8") == "old", "dry-run 竟写了文件"
    assert (pub / "extra.txt").exists(), "dry-run 竟删了文件"


def test_sync_tree_apply_mirrors_and_keeps_git(tmp_path):
    exp = tmp_path / "exp"
    pub = tmp_path / "pub"
    exp.mkdir()
    pub.mkdir()
    (exp / "a.txt").write_text("new", encoding="utf-8")
    (exp / "sub").mkdir()
    (exp / "sub" / "b.txt").write_text("b", encoding="utf-8")
    (pub / "a.txt").write_text("old", encoding="utf-8")
    (pub / "extra").mkdir()
    (pub / "extra" / "c.txt").write_text("c", encoding="utf-8")
    (pub / ".git").mkdir()
    (pub / ".git" / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")
    r = pb.sync_tree(str(exp), str(pub), apply=True)
    assert r["added"] == ["sub/b.txt"] and r["updated"] == ["a.txt"], r
    assert r["deleted"] == ["extra/c.txt"], r
    assert (pub / "a.txt").read_text(encoding="utf-8") == "new"
    assert not (pub / "extra" / "c.txt").exists()
    assert (pub / ".git" / "HEAD").exists(), ".git 被误删！"


def test_release_dry_run_zero_write(two_repos):
    pri, pub = two_repos
    _write_notes(pri, "v0.9.8.2")
    head = _git(pub, "rev-parse", "HEAD").stdout.strip()
    rep = pb.release("v0.9.8.2", public_dir=pub, private_repo=pri, apply=False,
                     preflight=_stub_preflight, exporter=_make_exporter({"a.txt": "x"}))
    assert rep["ok"] and rep["dry_run"], rep
    assert _git(pub, "rev-parse", "HEAD").stdout.strip() == head, "dry-run 竟提交了公开仓"
    assert not _git(pub, "tag", "-l", "v0.9.8.2").stdout.strip(), "dry-run 竟打了 tag"


def test_release_apply_commits_tags_and_ledger(two_repos):
    pri, pub = two_repos
    _write_notes(pri, "v0.9.8.2", "v0.9.8.2：发布桥落地")
    Path(pub, "stale.txt").write_text("stale", encoding="utf-8")
    _git(pub, "add", "stale.txt")
    _git(pub, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "stale")
    rep = pb.release("v0.9.8.2", public_dir=pub, private_repo=pri, apply=True, push=False,
                     preflight=_stub_preflight,
                     exporter=_make_exporter({"a.txt": "x", "scripts/b.py": "print(1)"}))
    assert rep["ok"], rep
    # 公开仓：内容 = 导出树（多余文件删除）、commit、annotated tag
    assert Path(pub, "a.txt").read_text(encoding="utf-8") == "x"
    assert not Path(pub, "stale.txt").exists(), "公开仓多余文件未删除"
    assert _git(pub, "cat-file", "-t", "v0.9.8.2").stdout.strip() == "tag", "公开 tag 非 annotated"
    # 私仓：同名 tag 指向发布源 commit
    assert _git(pri, "cat-file", "-t", "v0.9.8.2").stdout.strip() == "tag", "私仓缺同名 tag"
    assert _git(pri, "rev-parse", "v0.9.8.2^{}").stdout.strip() == rep["private_commit"]
    # 账本：仅私仓，且已提交
    lp = os.path.join(pri, "docs", "oss", "release-line.json")
    assert os.path.exists(lp), "release-line 未写"
    data = json.load(open(lp, encoding="utf-8"))
    assert data["releases"][-1]["version"] == "v0.9.8.2"
    assert data["releases"][-1]["public_commit"] == rep["public_commit"]
    assert "release-line" in _git(pri, "log", "-1", "--format=%s").stdout


def test_release_refuses_existing_tag(two_repos):
    pri, pub = two_repos
    _write_notes(pri, "v0.9.8.2")
    _git(pub, "tag", "-a", "v0.9.8.2", "-m", "dup")
    rep = pb.release("v0.9.8.2", public_dir=pub, private_repo=pri, apply=True, push=False,
                     preflight=_stub_preflight, exporter=_make_exporter({"a.txt": "x"}))
    assert not rep["ok"] and rep["error"] == "TAG_EXISTS", rep


def test_release_refuses_dirty_public(two_repos):
    pri, pub = two_repos
    _write_notes(pri, "v0.9.8.2")
    Path(pub, "dirty.txt").write_text("d", encoding="utf-8")
    rep = pb.release("v0.9.8.2", public_dir=pub, private_repo=pri, apply=True, push=False,
                     preflight=_stub_preflight, exporter=_make_exporter({"a.txt": "x"}))
    assert not rep["ok"] and rep["error"] == "PUBLIC_DIRTY", rep


def test_release_refuses_dirty_private(two_repos):
    pri, pub = two_repos
    _write_notes(pri, "v0.9.8.2")
    Path(pri, "dirty.txt").write_text("d", encoding="utf-8")
    rep = pb.release("v0.9.8.2", public_dir=pub, private_repo=pri, apply=True, push=False,
                     preflight=_stub_preflight, exporter=_make_exporter({"a.txt": "x"}))
    assert not rep["ok"] and rep["error"] == "PRIVATE_DIRTY", rep


def test_release_refuses_preflight_failure(two_repos):
    pri, pub = two_repos
    _write_notes(pri, "v0.9.8.2")
    rep = pb.release("v0.9.8.2", public_dir=pub, private_repo=pri, apply=True, push=False,
                     preflight=lambda c, cwd=None: (1, "FAIL docgen", ""),
                     exporter=_make_exporter({"a.txt": "x"}))
    assert not rep["ok"] and rep["error"] == "PREFLIGHT_FAILED", rep


def test_audit_reports_drift(two_repos):
    pri, pub = two_repos
    _git(pri, "tag", "v1")
    _git(pub, "tag", "v2")
    _git(pri, "tag", "v0.9.8.2")
    _git(pub, "tag", "v0.9.8.2")
    r = pb.audit(private_repo=pri, public_dir=pub)
    assert r["verdict"] == "DRIFT"
    assert r["common"] == ["v0.9.8.2"]
    assert r["only_private"] == ["v1"] and r["only_public"] == ["v2"]


def test_no_force_push_path_and_one_way_source():
    """方向/安全静态臂：源码无 `--force`，且不从公开仓 fetch/pull/checkout。"""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "gk_public_bridge.py"),
               encoding="utf-8").read()
    assert "--force" not in src and " -f " not in src, "出现 force push 路径"
    for bad in ('"fetch"', '"pull"', '"checkout"'):
        assert bad not in src, "出现反向取数动作（破坏单向权威）：" + bad
