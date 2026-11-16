"""R0.24 唯一合并入口（gk_merge_cli）：闸①→merge→闸②→提交/回滚 闭环（2026-11-13）。

为什么必须端到端测：闸①/闸② 各自单测绿 ≠ 编排正确（回滚、票据、脏 index 都在编排层）。
"""
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_merge_cli as C          # noqa: E402
import gk_merge_hook_install as I  # noqa: E402


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def _ok(repo, *args):
    r = _git(repo, *args)
    assert r.returncode == 0, (args, r.stdout, r.stderr)
    return r


def _repo(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _ok(repo, "init", "-b", "master")
    _ok(repo, "config", "user.email", "t@example.com")
    _ok(repo, "config", "user.name", "t")
    return repo


def _commit(repo, name, text):
    (Path(repo) / name).write_text(text, encoding="utf-8")
    _ok(repo, "add", name)
    _ok(repo, "commit", "-m", "c " + name)
    return (_ok(repo, "rev-parse", "HEAD").stdout or "").strip()


def test_clean_merge_lands(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    _ok(repo, "checkout", "-b", "feat")
    _commit(repo, "f.txt", "f\n")
    _ok(repo, "checkout", "master")
    _commit(repo, "m.txt", "m\n")
    rc, out = C.run("feat", "master", str(repo))
    assert rc == 0 and out["decision"] == "MERGED", out
    assert (repo / "f.txt").exists()
    parents = _ok(repo, "rev-list", "--parents", "-n", "1", "HEAD").stdout.split()
    assert len(parents) == 3, "必须是 --no-ff 合并提交（双父）"


def test_progress_heartbeat_emitted(tmp_path):
    """编排必须逐步吐心跳（调用方空闲超时看"有没有输出"，不是"跑了多久"）。"""
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    _ok(repo, "checkout", "-b", "feat")
    _commit(repo, "f.txt", "f\n")
    _ok(repo, "checkout", "master")
    _commit(repo, "m.txt", "m\n")
    steps = []
    rc, out = C.run("feat", "master", str(repo), progress=steps.append)
    assert rc == 0, out
    joined = "\n".join(steps)
    for token in ("start", "单队列锁", "暂存面干净", "闸①", "闸②", "提交", "done"):
        assert token in joined, "缺少心跳节点 %s\n%s" % (token, joined)


def test_dirty_index_blocked(tmp_path):
    """暂存面非空 ⟹ 不得开合并（否则 merge 提交会把它一起带走 —— 792 条删除事故形态）。"""
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    _ok(repo, "checkout", "-b", "feat")
    _commit(repo, "f.txt", "f\n")
    _ok(repo, "checkout", "master")
    (repo / "a.txt").write_text("dirty\n", encoding="utf-8")
    _ok(repo, "add", "a.txt")
    rc, out = C.run("feat", "master", str(repo))
    assert rc == 3 and out["code"] == "DIRTY_INDEX", out


def test_conflict_rolls_back(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "base\n")
    _ok(repo, "checkout", "-b", "feat")
    _commit(repo, "a.txt", "feat\n")
    _ok(repo, "checkout", "master")
    _commit(repo, "a.txt", "master\n")
    before = (_ok(repo, "rev-parse", "HEAD").stdout or "").strip()
    rc, out = C.run("feat", "master", str(repo))
    # 冲突在**闸①**（三方模拟）就被拦，不必等 git merge；两者都算合法拒绝
    assert rc == 3 and (out.get("code") in ("MERGE_FAILED", "MERGE_CONFLICT")
                        or (out.get("reasons") or [{}])[0].get("code") == "MERGE_CONFLICT"), out
    assert _git(repo, "rev-parse", "--verify", "-q", "MERGE_HEAD").returncode != 0, \
        "失败后必须回滚 merge 态（MERGE_HEAD 不得残留）"
    assert (_ok(repo, "rev-parse", "HEAD").stdout or "").strip() == before


def test_facts_rebuild_is_staged_into_merge_commit(tmp_path, monkeypatch):
    """事实块重算结果必须进**合并提交**，不得残留工作区。

    实测（2026-11-13）：重算只写工作区、未 `git add` ⟹ `git commit` 只提交 index ⟹
    合并后 `git status` 恒脏，下一次合并被 "local changes would be overwritten" 挡死。
    """
    repo = _repo(tmp_path)
    (repo / "scripts").mkdir()
    _commit(repo, "scripts/pre_tool_hook.py", "# base\n")
    _commit(repo, "SKILL.md", "old facts\n")
    _ok(repo, "checkout", "-b", "feat")
    _commit(repo, "scripts/pre_tool_hook.py", "# feat\n")
    _ok(repo, "checkout", "master")
    _commit(repo, "m.txt", "m\n")
    fake = tmp_path / "fake_facts.py"
    fake.write_text(
        "import sys\n"
        "p = sys.argv[sys.argv.index('--skill-dir') + 1]\n"
        "open(p + '/SKILL.md', 'w').write('new facts\\n')\n",
        encoding="utf-8")
    monkeypatch.setattr(C, "_FACTS", fake)
    rc, out = C.run("feat", "master", str(repo))
    assert rc == 0, out
    blob = _ok(repo, "show", "HEAD:SKILL.md").stdout
    assert "new facts" in blob, "事实块重算未进合并提交（生成物残留 = 假绿）"
    assert _git(repo, "status", "--porcelain", "SKILL.md").stdout.strip() == "", \
        "合并后 SKILL.md 仍脏 ⟹ 下次合并不可能过"


def test_installed_hook_blocks_raw_merge(tmp_path):
    """装钩子后，手搓 `git merge`（无票据）必须在 ref 更新处被拒。

    2026-11-13 R0.24-b：安装点挪到**主树提交之后** —— 判据已扩为「主 ref 任何前进都要票据」，
    装早了连测试夹具自己的 `git commit` 都会被拒（夹具不该依赖被闸放行）。
    """
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    _ok(repo, "checkout", "-b", "feat2")
    _commit(repo, "x.txt", "x\n")
    _ok(repo, "checkout", "master")
    _commit(repo, "m.txt", "m\n")
    before = (_ok(repo, "rev-parse", "HEAD").stdout or "").strip()
    inst = I.install(str(repo))
    assert inst["ok"], inst
    r = _git(repo, "merge", "--no-ff", "-m", "raw merge", "feat2")
    assert r.returncode != 0, (r.stdout, r.stderr)
    assert "BLOCK[merge-hook]" in (r.stderr or ""), r.stderr
    assert (_ok(repo, "rev-parse", "HEAD").stdout or "").strip() == before
