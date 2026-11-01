"""gk_session_identity 判别臂（finding ECC-AB2FA16E9133）。

覆盖 Q1a 解析矩阵：name 优先（agent/session、agent/<family>、其它 2 段）+ 路径哈希兜底 +
主树/空路径零回归 + 跨形态（WSL/Windows/superpowers root/反斜杠）+ token 文件名安全。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_session_identity as gsi  # noqa: E402

ROOT_WSL = "<home>/.trae/worktrees/"
ROOT_WIN = "<home>/.trae/worktrees/"
ROOT_SUP = "/root/.config/superpowers/worktrees/"


def test_agent_session_leaf_name():
    r = gsi.derive(ROOT_WSL + "spz-gatekeeper-r-sequence/agent/session/7c1e2933/scripts/x.py")
    assert r["token"] == "7c1e2933"
    assert r["source"] == "name"
    assert r["worktree"].endswith("agent/session/7c1e2933")


def test_agent_family_leaf_name():
    r = gsi.derive(ROOT_WSL + "spz-gatekeeper-r-sequence/agent/F-MAIN-REPO-GUARD/d012f4b5")
    assert r["token"] == "d012f4b5"
    assert r["source"] == "name"


def test_other_two_seg_name():
    r = gsi.derive(ROOT_WSL + "other-repo/foo/bar/file.md")
    assert r["token"] == "bar"
    assert r["source"] == "name"


def test_deep_weird_hash_fallback():
    r = gsi.derive(ROOT_WSL + "repo-only/onlyseg")
    assert r["source"] == "hash"
    assert r["token"].startswith("w")
    assert gsi.is_valid_token(r["token"])


def test_hash_is_stable():
    a = gsi.derive(ROOT_WSL + "repo-only/onlyseg")
    b = gsi.derive(ROOT_WSL + "repo-only/onlyseg")
    assert a["token"] == b["token"]


def test_main_tree_no_token():
    r = gsi.derive("<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh")
    assert r["token"] == ""
    assert r["reason"] == "not_in_dev_worktree_tree"


def test_empty_no_token():
    assert gsi.derive("")["token"] == ""


def test_windows_form():
    r = gsi.derive(ROOT_WIN + "spz-gatekeeper-r-sequence/agent/session/abcd1234/scripts/x.py")
    assert r["token"] == "abcd1234"


def test_superpowers_root():
    r = gsi.derive(ROOT_SUP + "repo/agent/session/deadbeef")
    assert r["token"] == "deadbeef"


def test_backslash_normalized():
    r = gsi.derive("<home>\\.trae\\worktrees\\spz-gatekeeper-r-sequence\\agent\\session\\cafe0001\\x")
    assert r["token"] == "cafe0001"


def test_token_validity():
    assert gsi.is_valid_token("7c1e2933")
    assert gsi.is_valid_token("wDEADBEEF")
    assert gsi.is_valid_token("sess-ident")
    assert not gsi.is_valid_token("")
    assert not gsi.is_valid_token("../evil")
    assert not gsi.is_valid_token("a/b")
