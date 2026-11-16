"""R0.24 合并闸（git reference-transaction）：**任何**主 ref 前进无票据必须被拒（2026-11-13）。

口径（R0.24-b 扩面）：主 ref（master/main）的任何 old≠new 更新都要票据，不再区分「合并式 /
单条直接提交」；主 ref 删除一律拒；`old == ZERO` 的引导放行。起因 = 实测单条直接提交
（`7a835309`）绕过了首版只拦「合并式」的判据。
"""
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_merge_hook as H  # noqa: E402
import gk_merge_hook_install as HI  # noqa: E402


def _git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    assert r.returncode == 0, (args, r.stdout, r.stderr)
    return r


def _repo(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-b", "master")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    return repo


def _commit(repo, name, text):
    (Path(repo) / name).write_text(text, encoding="utf-8")
    _git(repo, "add", name)
    _git(repo, "commit", "-m", "c " + name)
    return (_git(repo, "rev-parse", "HEAD").stdout or "").strip()


def _hook(repo, old, new, ref="refs/heads/master"):
    p = subprocess.run([sys.executable, str(Path(H.__file__)), "prepared"],
                       input="%s %s %s\n" % (old, new, ref), cwd=str(repo),
                       capture_output=True, text=True)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def test_direct_single_commit_blocked(tmp_path):
    """主树单条直接提交（old..new 恰 1 条）**无票据** ⟹ 拒绝（R0.24-b 扩面）。"""
    repo = _repo(tmp_path)
    c0 = _commit(repo, "a.txt", "a\n")
    c1 = _commit(repo, "b.txt", "b\n")
    rc, err = _hook(repo, c0, c1)
    assert rc == 1 and "BLOCK[merge-hook]" in err and "NO_TICKET" in err, err


def test_direct_single_commit_with_ticket_allowed(tmp_path):
    """单条直接提交**带合法票据**（闸已授权）⟹ 放行，票据一次性消费。"""
    repo = _repo(tmp_path)
    c0 = _commit(repo, "a.txt", "a\n")
    c1 = _commit(repo, "b.txt", "b\n")
    cd = H.common_dir(str(repo))
    H.write_ticket(cd, "refs/heads/master", c0, c0)
    rc, err = _hook(repo, c0, c1)
    assert rc == 0, err
    assert not os.path.exists(H.ticket_path(cd)), "票据必须一次性消费"


def test_main_ref_deletion_blocked(tmp_path):
    """主 ref 删除（new = ZERO）⟹ 直接拒（无删除票据通道）。"""
    repo = _repo(tmp_path)
    c0 = _commit(repo, "a.txt", "a\n")
    rc, err = _hook(repo, c0, H.ZERO)
    assert rc == 1 and "主分支引用删除被拒" in err, err


def test_bootstrap_zero_old_allowed(tmp_path):
    """引导（old = ZERO：init / 首提交）⟹ 放行 —— 此时无既存主树可写。"""
    repo = _repo(tmp_path)
    c0 = _commit(repo, "a.txt", "a\n")
    rc, err = _hook(repo, H.ZERO, c0)
    assert rc == 0, err


def test_installed_hook_blocks_direct_commit_end_to_end(tmp_path):
    """端到端：装上真钩子后，主树 `git commit` 被 git 自身拒绝；分支提交不受影响。

    这是「所有向主树写入都过闸」的实际形态 —— 不依赖手工调用 hook 入口。
    """
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    out = HI.install(str(repo))
    assert out.get("ok") and out.get("installed"), out
    p = subprocess.run(["git", "-C", str(repo), "commit", "--allow-empty", "-m", "direct"],
                       capture_output=True, text=True)
    assert p.returncode != 0, "直写主树竟成功（闸未生效）"
    assert "BLOCK[merge-hook]" in (p.stdout + p.stderr), p.stdout + p.stderr
    # 非主 ref（特性分支）仍可正常提交
    _git(repo, "checkout", "-b", "feat-x")
    p2 = subprocess.run(["git", "-C", str(repo), "commit", "--allow-empty", "-m", "on-branch"],
                        capture_output=True, text=True)
    assert p2.returncode == 0, p2.stdout + p2.stderr
    head = (_git(repo, "rev-parse", "--abbrev-ref", "HEAD").stdout or "").strip()
    assert head == "feat-x", head


def test_merge_commit_without_ticket_blocked(tmp_path):
    """真 merge 提交（≥2 父）无票据 ⟹ 拒绝。"""
    repo = _repo(tmp_path)
    base = _commit(repo, "a.txt", "a\n")
    _git(repo, "checkout", "-b", "feat")
    _commit(repo, "f.txt", "f\n")
    _git(repo, "checkout", "master")
    _commit(repo, "m.txt", "m\n")
    _git(repo, "merge", "--no-ff", "-m", "merge feat", "feat")
    merge_sha = (_git(repo, "rev-parse", "HEAD").stdout or "").strip()
    rc, err = _hook(repo, base, merge_sha)
    assert rc == 1 and "BLOCK[merge-hook]" in err, err


def test_merge_commit_with_ticket_allowed_and_consumed(tmp_path):
    """带票据（HMAC + old 匹配）⟹ 放行，且票据一次性消费。"""
    repo = _repo(tmp_path)
    base = _commit(repo, "a.txt", "a\n")
    _git(repo, "checkout", "-b", "feat")
    feat_sha = _commit(repo, "f.txt", "f\n")
    _git(repo, "checkout", "master")
    _commit(repo, "m.txt", "m\n")
    _git(repo, "merge", "--no-ff", "-m", "merge feat", "feat")
    merge_sha = (_git(repo, "rev-parse", "HEAD").stdout or "").strip()
    cd = H.common_dir(str(repo))
    H.write_ticket(cd, "refs/heads/master", base, feat_sha)
    rc, err = _hook(repo, base, merge_sha)
    assert rc == 0, err
    assert not os.path.exists(H.ticket_path(cd)), "票据必须一次性消费"


def test_multi_commit_fast_forward_blocked(tmp_path):
    """多提交快进（= 把一条分支整体搬上来）无票据 ⟹ 拒绝。"""
    repo = _repo(tmp_path)
    base = _commit(repo, "a.txt", "a\n")
    _git(repo, "checkout", "-b", "f2")
    _commit(repo, "x.txt", "1\n")
    _commit(repo, "y.txt", "2\n")
    _git(repo, "checkout", "master")
    _git(repo, "merge", "--ff-only", "f2")
    tip = (_git(repo, "rev-parse", "HEAD").stdout or "").strip()
    rc, err = _hook(repo, base, tip)
    assert rc == 1 and "BLOCK[merge-hook]" in err, err


def test_single_commit_fast_forward_blocked(tmp_path):
    """单提交快进（= 分支只多 1 个提交）无票据 ⟹ 拒绝（R0.24-b 扩面，原「已知残余」收口）。"""
    repo = _repo(tmp_path)
    base = _commit(repo, "a.txt", "a\n")
    _git(repo, "checkout", "-b", "f3")
    _commit(repo, "z.txt", "z\n")
    _git(repo, "checkout", "master")
    _git(repo, "merge", "--ff-only", "f3")
    tip = (_git(repo, "rev-parse", "HEAD").stdout or "").strip()
    rc, err = _hook(repo, base, tip)
    assert rc == 1 and "BLOCK[merge-hook]" in err, err


def test_stale_ticket_blocked(tmp_path):
    """票据 old 与本次 ref 旧值不符 ⟹ 拒绝（防旧票重放）。"""
    repo = _repo(tmp_path)
    c0 = _commit(repo, "a.txt", "a\n")
    _git(repo, "checkout", "-b", "feat")
    feat_sha = _commit(repo, "f.txt", "f\n")
    _git(repo, "checkout", "master")
    _commit(repo, "m.txt", "m\n")
    _git(repo, "merge", "--no-ff", "-m", "m", "feat")
    merge_sha = (_git(repo, "rev-parse", "HEAD").stdout or "").strip()
    cd = H.common_dir(str(repo))
    H.write_ticket(cd, "refs/heads/master", H.ZERO, feat_sha)
    rc, err = _hook(repo, c0, merge_sha)
    assert rc == 1 and "TICKET_STALE_OLD" in err, err


def test_bad_signature_blocked(tmp_path):
    """票据签名被改 ⟹ 拒绝（fails-closed）。"""
    repo = _repo(tmp_path)
    c0 = _commit(repo, "a.txt", "a\n")
    _git(repo, "checkout", "-b", "feat")
    _commit(repo, "f.txt", "f\n")
    _git(repo, "checkout", "master")
    _commit(repo, "m.txt", "m\n")
    _git(repo, "merge", "--no-ff", "-m", "m", "feat")
    merge_sha = (_git(repo, "rev-parse", "HEAD").stdout or "").strip()
    cd = H.common_dir(str(repo))
    with open(H.ticket_path(cd), "w", encoding="utf-8") as f:
        f.write('{"v":1,"ref":"refs/heads/master","old":"%s","source":"x","ts":1,"sig":"dead"}'
                % c0)
    rc, err = _hook(repo, c0, merge_sha)
    assert rc == 1 and "TICKET_BAD_SIGNATURE" in err, err


def test_non_main_ref_ignored(tmp_path):
    """非 master/main 的分支指针更新不在本闸判据内。"""
    repo = _repo(tmp_path)
    c0 = _commit(repo, "a.txt", "a\n")
    _git(repo, "checkout", "-b", "feat")
    _commit(repo, "f.txt", "f\n")
    _git(repo, "checkout", "-b", "g")
    _commit(repo, "g.txt", "g\n")
    _git(repo, "checkout", "feat")
    _git(repo, "merge", "--no-ff", "-m", "m", "g")
    merge_sha = (_git(repo, "rev-parse", "HEAD").stdout or "").strip()
    rc, err = _hook(repo, c0, merge_sha, ref="refs/heads/feat")
    assert rc == 0, err
