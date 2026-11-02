"""Test gk_git_workflow_check.py — git-workflow 全量检测（2026-09-01 L1 扩展实装）"""
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_git_workflow_check as gw


# ── 单元：各检查项 ─────────────────────────────────────────────

def test_repo_healthy_ok(monkeypatch):
    monkeypatch.setattr(gw, "_git",
                        lambda repo, *a, **k: (0, "abc123", "") if a[0] == "rev-parse" else (0, "5", ""))
    res = gw.check_repo_healthy("/fake/repo")
    assert res["status"] == "ok"
    assert res["commits"] == "5"


def test_repo_healthy_bad_head(monkeypatch):
    monkeypatch.setattr(gw, "_git", lambda repo, *a, **k: (1, "", "fatal"))
    res = gw.check_repo_healthy("/fake/repo")
    assert res["status"] == "warn"


def test_protected_branch_warn(monkeypatch):
    monkeypatch.setattr(gw, "_git", lambda repo, *a, **k: (0, "main\n", ""))
    res = gw.check_protected_branch("/fake/repo")
    assert res["status"] == "warn"
    assert res["branch"] == "main"


def test_protected_branch_feature_ok(monkeypatch):
    monkeypatch.setattr(gw, "_git", lambda repo, *a, **k: (0, "feature/x\n", ""))
    res = gw.check_protected_branch("/fake/repo")
    assert res["status"] == "ok"


def test_detached_head_warn(monkeypatch):
    monkeypatch.setattr(gw, "_git", lambda repo, *a, **k: (0, "HEAD\n", ""))
    res = gw.check_detached_head("/fake/repo")
    assert res["status"] == "warn"
    assert res["detached"] is True


def test_merge_state_detected(tmp_path):
    import gk_git_workflow_check as _gw
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "MERGE_HEAD").write_text("abc")
    orig = _gw._git_dir
    _gw._git_dir = lambda repo: str(git_dir)
    try:
        res = _gw.check_merge_state(str(tmp_path))
        assert res["status"] == "warn"
        assert res["active_ops"] == ["MERGE_HEAD"]
    finally:
        _gw._git_dir = orig


def test_dirty_worktree_detected(monkeypatch):
    monkeypatch.setattr(gw, "_git", lambda repo, *a, **k: (0, " M f.txt\n", ""))
    res = gw.check_dirty_worktree("/fake/repo")
    assert res["status"] == "warn"
    assert res["changed_files"] == 1


def test_unpushed_commits_warn(monkeypatch):
    monkeypatch.setattr(gw, "_git", lambda repo, *a, **k: (0, "3\n", ""))
    res = gw.check_unpushed_commits("/fake/repo")
    assert res["status"] == "warn"
    assert res["unpushed"] == 3


def test_unpushed_commits_ok(monkeypatch):
    monkeypatch.setattr(gw, "_git", lambda repo, *a, **k: (0, "0\n", ""))
    res = gw.check_unpushed_commits("/fake/repo")
    assert res["status"] == "ok"


def test_stale_commit_warn(monkeypatch):
    old = int(time.time()) - 40 * 86400  # 40 天前
    monkeypatch.setattr(gw, "_git", lambda repo, *a, **k: (0, str(old) + "\n", ""))
    res = gw.check_stale_commit("/fake/repo")
    assert res["status"] == "warn"
    assert res["age_days"] > 30


def test_stale_commit_fresh_ok(monkeypatch):
    now = int(time.time())
    monkeypatch.setattr(gw, "_git", lambda repo, *a, **k: (0, str(now) + "\n", ""))
    res = gw.check_stale_commit("/fake/repo")
    assert res["status"] == "ok"


def test_worktree_orphan_detected(monkeypatch):
    # 两个 worktree，一个 branch ref 已不存在 → 孤儿
    out = ("worktree /main\nbranch refs/heads/main\n\n"
           "worktree /wt\nbranch refs/heads/ghost\n\n")
    def fake_git(repo, *a, **k):
        if a[0] == "worktree":
            return 0, out, ""
        if "ghost" in a[-1]:
            return 1, "", ""  # ghost ref 不存在
        return 0, "", ""     # main ref 存在
    monkeypatch.setattr(gw, "_git", fake_git)
    res = gw.check_worktree_status("/fake/repo")
    assert res["status"] == "warn"
    # f5（ECC-C69048822CD5）：孤儿须报**短名**（`ghost`）而非全 ref（`refs/heads/ghost`）——
    # 原式把全 ref 再拼一次前缀 ⟹ `refs/heads/refs/heads/*` 恒 rc=1 ⟹ 每个分支 worktree 皆假孤儿。
    assert res["orphan_worktrees"] == ["ghost"]


def test_worktree_branch_full_ref_is_not_false_orphan(monkeypatch):
    """f5 假阳判据：`branch refs/heads/main` 且该 ref **存在** ⟹ 不得报孤儿。

    原实现 `l[7:]` 得 `refs/heads/main`，拼成 `refs/heads/refs/heads/main` 查 ref ⟹ 恒 1 ⟹
    真存分支被误报（本仓实测虚报 4→真 1：master / standing/xenv-form-fix / dryrun/moa-chain
    三条假阳 + feature/skill-r-t6 一条真孤儿）。
    """
    out = ("worktree /main\nbranch refs/heads/master\n\n"
           "worktree /wt\nbranch refs/heads/standing/xenv-form-fix\n\n")
    seen = []

    def fake_git(repo, *a, **k):
        if a[0] == "worktree":
            return 0, out, ""
        seen.append(a[-1])
        return 0, "", ""  # 两个 ref 都"存在"
    monkeypatch.setattr(gw, "_git", fake_git)
    res = gw.check_worktree_status("/fake/repo")
    assert res["status"] == "ok", res
    assert res["orphan_worktrees"] == []
    assert seen == ["refs/heads/master", "refs/heads/standing/xenv-form-fix"], (
        f"查 ref 的全名被拼错（多一层 refs/heads/）：{seen}")


def test_worktree_no_orphan_ok(monkeypatch):
    out = ("worktree /main\nbranch refs/heads/main\n\n")
    def fake_git(repo, *a, **k):
        if a[0] == "worktree":
            return 0, out, ""
        return 0, "", ""  # show-ref → 存在
    monkeypatch.setattr(gw, "_git", fake_git)
    res = gw.check_worktree_status("/fake/repo")
    assert res["status"] == "ok"
    assert res["worktree_count"] == 1


def test_worktree_main_path_not_truncated(monkeypatch):
    """f5 同批（实测）：`worktree ` 前缀 9 字符，原式 `l[6:]` 把 `main_worktree` 切成
    `"ee /mnt/c/main"` —— 报告给出的主 worktree 路径是错的。"""
    out = "worktree /mnt/c/main\nbranch refs/heads/master\n\n"
    monkeypatch.setattr(
        gw, "_git",
        lambda repo, *a, **k: (0, out, "") if a[0] == "worktree" else (0, "", ""))
    res = gw.check_worktree_status("/fake/repo")
    assert res["main_worktree"] == "/mnt/c/main", res["main_worktree"]


def test_hooks_missing_info(tmp_path):
    # 模拟真实 git-dir（hooks 目录缺失 → info 非阻断）
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    import gk_git_workflow_check as _gw
    orig = _gw._git_dir
    _gw._git_dir = lambda repo: str(git_dir)
    try:
        res = _gw.check_hooks_ok(str(tmp_path))
        assert res["status"] == "info"  # 缺 hooks 目录 = info 非阻断
    finally:
        _gw._git_dir = orig


def test_hooks_present_ok(tmp_path):
    import gk_git_workflow_check as _gw
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "hooks").mkdir()
    (git_dir / "hooks" / "pre-push").write_text("#!/bin/sh")
    orig = _gw._git_dir
    _gw._git_dir = lambda repo: str(git_dir)
    try:
        res = _gw.check_hooks_ok(str(tmp_path))
        assert res["status"] == "ok"
        assert res["key_hooks"] == ["pre-push"]
    finally:
        _gw._git_dir = orig


def test_loader_pin_skip_when_unreachable(monkeypatch):
    monkeypatch.setattr(gw, "_GIT_WORKFLOW_SKILL",
                        "/nonexistent/git-workflow")
    res = gw.check_loader_pin()
    assert res["status"] == "skip"


# ── 换行符污染检测（2026-09-01 新增，L1 git 层扩展）────────────────

def test_line_ending_mixed_warn(tmp_path, monkeypatch):
    """同文件混合 CRLF+LF → warn 污染。"""
    monkeypatch.setattr(gw, "_git", lambda repo, *a, **k: (0, "unset\n", "") if a[0] == "config" else (0, "a.py\0b.py\0", ""))
    (tmp_path / "a.py").write_bytes(b"line1\r\nline2\n")
    (tmp_path / "b.py").write_bytes(b"x\n")
    res = gw.check_line_ending_pollution(str(tmp_path))
    assert res["status"] == "warn"
    assert "a.py" in res["mixed_files"]


def test_line_ending_no_policy_warn(tmp_path, monkeypatch):
    """无 .gitattributes 且 autocrlf 未开 → warn（无显式换行策略）。"""
    monkeypatch.setattr(gw, "_git", lambda repo, *a, **k: (0, "unset\n", "") if a[0] == "config" else (0, "a.py\0", ""))
    (tmp_path / "a.py").write_bytes(b"line\n")
    res = gw.check_line_ending_pollution(str(tmp_path))
    assert res["status"] == "warn"
    assert res["has_gitattributes"] is False
    assert res["autocrlf"] == "unset"


def test_line_ending_clean_ok(tmp_path, monkeypatch):
    """纯 LF + .gitattributes + autocrlf 配置 → ok。"""
    def fake_git(repo, *a, **k):
        if a[0] == "config":
            return (0, "true\n", "")
        return (0, "a.py\0", "")
    monkeypatch.setattr(gw, "_git", fake_git)
    (tmp_path / "a.py").write_bytes(b"line1\nline2\n")
    (tmp_path / ".gitattributes").write_text("* text=auto\n*.py text eol=lf\n", encoding="utf-8")
    res = gw.check_line_ending_pollution(str(tmp_path))
    assert res["status"] == "ok"
    assert res["mixed_files"] == []


def test_line_ending_ls_failed_skip(monkeypatch):
    """ls-files 失败 → skip 不阻断。"""
    monkeypatch.setattr(gw, "_git", lambda repo, *a, **k: (128, "", "fatal"))
    res = gw.check_line_ending_pollution("/fake")
    assert res["status"] == "skip"


# ── 集成：真实 git 仓库全流程 ─────────────────────────────────

@pytest.fixture()
def real_repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True)
    (tmp_path / "f.txt").write_text("hi")
    subprocess.run(["git", "-C", str(tmp_path), "add", "f.txt"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "init"], check=True)
    return tmp_path


def test_real_repo_all_checks_json(real_repo):
    """真实仓库上全部 10 项检查可运行且输出 JSON 契约完整。"""
    # 直接构造 main 的输出路径：调用每个检查函数（main 打印 JSON，无法直接捕获 → 模拟）
    checks = {
        "repo_healthy": gw.check_repo_healthy(str(real_repo)),
        "protected_branch": gw.check_protected_branch(str(real_repo)),
        "detached_head": gw.check_detached_head(str(real_repo)),
        "merge_state": gw.check_merge_state(str(real_repo)),
        "dirty_worktree": gw.check_dirty_worktree(str(real_repo)),
        "unpushed_commits": gw.check_unpushed_commits(str(real_repo)),
        "stale_commit": gw.check_stale_commit(str(real_repo)),
        "worktree_status": gw.check_worktree_status(str(real_repo)),
        "hooks_ok": gw.check_hooks_ok(str(real_repo)),
        "loader_pin": gw.check_loader_pin(),
        "merge_integrity": gw.check_merge_integrity(str(real_repo)),
    }
    for k, v in checks.items():
        assert v["status"] in ("ok", "warn", "info", "skip"), f"{k}: {v}"
    # 干净仓库：dirty 应 ok、merge_state 应 ok
    assert checks["dirty_worktree"]["status"] == "ok"
    assert checks["merge_state"]["status"] == "ok"


def test_dirty_after_modify(real_repo):
    """修改文件后 dirty_worktree 必须转 warn。"""
    (real_repo / "f.txt").write_text("changed")
    res = gw.check_dirty_worktree(str(real_repo))
    assert res["status"] == "warn"


def test_crossr_gwscan_merge():
    """gk_audit_crossr 的 GWSCAN env 合并契约（L1 实装接线验证）。"""
    import gk_audit_crossr as cr
    import json as _json
    fake_gw = _json.dumps({"ok": False, "issues": ["dirty_worktree"]})
    # 直接测合并逻辑：临时 env 下跑 analyze_crossr（空 state → 契约恒有字段）
    import os
    old = os.environ.get("GWSCAN")
    os.environ["GWSCAN"] = fake_gw
    try:
        r = cr.analyze_crossr("")
        assert r["git_workflow"]["ok"] is False
        assert "dirty_worktree" in r["git_workflow"]["issues"]
    finally:
        if old is None:
            os.environ.pop("GWSCAN", None)
        else:
            os.environ["GWSCAN"] = old


def test_main_json_contract(real_repo, capsys):
    """main() 输出必须是可解析 JSON，且契约字段齐全。"""
    import json as _json
    old_argv = sys.argv
    sys.argv = ["gk_git_workflow_check.py", str(real_repo)]
    try:
        gw.main()
    finally:
        sys.argv = old_argv
    out = capsys.readouterr().out
    d = _json.loads(out)
    assert "ok" in d and "repo" in d and "checks" in d and "issues" in d
    assert "recommendation" in d
    # 2026-09-04 L1 降噪契约字段
    assert "self_repo" in d and "self_debt_registered" in d


# ── 2026-09-04 L1 自仓库既有债务降噪 ─────────────────────────────

def test_is_skill_self_repo_true(tmp_path, monkeypatch):
    monkeypatch.setattr(gw, "_SELF_ROOT", tmp_path)
    assert gw._is_skill_self_repo(str(tmp_path)) is True
    assert gw._is_skill_self_repo(str(tmp_path / ".." / tmp_path.name)) is True


def test_is_skill_self_repo_other_false(tmp_path, monkeypatch):
    monkeypatch.setattr(gw, "_SELF_ROOT", tmp_path)
    assert gw._is_skill_self_repo(str(tmp_path / "other")) is False


def test_relax_self_debt_info(tmp_path, monkeypatch):
    monkeypatch.setattr(gw, "_SELF_ROOT", tmp_path)
    checks = {"dirty_worktree": {"status": "warn", "changed_files": 3},
              "unpushed_commits": {"status": "warn", "unpushed": 16},
              "merge_state": {"status": "warn", "active_ops": ["MERGE_HEAD"]}}
    relaxed = gw._relax_self_debt(str(tmp_path), checks)
    assert relaxed == ["dirty_worktree", "unpushed_commits"]
    assert checks["dirty_worktree"]["status"] == "info"
    assert checks["unpushed_commits"]["status"] == "info"
    assert checks["dirty_worktree"]["self_debt"] is True
    assert "既有状态" in checks["dirty_worktree"]["reason"]
    assert checks["merge_state"]["status"] == "warn"  # 其他异常项不放松


def test_relax_other_repo_unchanged(tmp_path, monkeypatch):
    monkeypatch.setattr(gw, "_SELF_ROOT", tmp_path)
    checks = {"dirty_worktree": {"status": "warn", "changed_files": 1},
              "unpushed_commits": {"status": "warn", "unpushed": 5}}
    relaxed = gw._relax_self_debt(str(tmp_path / "other"), checks)
    assert relaxed == []
    assert checks["dirty_worktree"]["status"] == "warn"
    assert checks["unpushed_commits"]["status"] == "warn"


def test_relax_self_debt_f5_extension(tmp_path, monkeypatch):
    """f5（ECC-C69048822CD5）扩表：protected_branch / worktree_status / hooks_ok 自仓降 info。

    ⚠ 登记**不等于**修好：明细/计数必须保留（可见的非阻断项），未登记项不受影响。
    """
    monkeypatch.setattr(gw, "_SELF_ROOT", tmp_path)
    checks = {"protected_branch": {"status": "warn", "branch": "master"},
              "worktree_status": {"status": "warn", "worktree_count": 10,
                                  "orphan_worktrees": ["feature/skill-r-t6"]},
              "hooks_ok": {"status": "warn", "key_hooks": []},
              "detached_head": {"status": "warn", "detached": True}}
    relaxed = gw._relax_self_debt(str(tmp_path), checks)
    assert set(relaxed) == {"protected_branch", "worktree_status", "hooks_ok"}
    for k in relaxed:
        assert checks[k]["status"] == "info" and checks[k]["self_debt"] is True
        assert "既有状态" in checks[k]["reason"]
    # 明细保留（登记非抹除）
    assert checks["worktree_status"]["orphan_worktrees"] == ["feature/skill-r-t6"]
    assert checks["worktree_status"]["worktree_count"] == 10
    assert checks["hooks_ok"]["key_hooks"] == []
    # 未登记项不受影响
    assert checks["detached_head"]["status"] == "warn"


def test_self_debt_registry_pinned():
    """扩表须**显式**（防静默加/删放松项把真异常洗白）——注册表以本臂钉住。"""
    assert gw._SELF_DEBT_KEYS == ("dirty_worktree", "unpushed_commits",
                                  "protected_branch", "worktree_status", "hooks_ok")


# ── 2026-10-01（§15.8 二期）：合并结果硬校验 `merge_integrity` ──────────────
# 治「空合并」静默丢批次（§15.6 实害：两次空合并丢 12 文件）；判据与
# `gk_git_lease.verify_merge_result` **同源**（不另起第二实现），此处只做**历史例行全扫**。

def _mk_merge_repo(tmp_path):
    """基线仓 + `feature` 分支（加 `feat.txt`）；返回 `(repo, ours, theirs, g)`。"""
    def g(*a):
        r = subprocess.run(["git", "-C", str(tmp_path)] + list(a),
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, f"git {' '.join(a)} 失败：{r.stderr}"
        return r.stdout.strip()
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    g("config", "user.email", "t@t")
    g("config", "user.name", "t")
    (tmp_path / "base.txt").write_text("b\n", encoding="utf-8", newline="\n")
    g("add", "base.txt")
    g("commit", "-q", "-m", "base")
    ours = g("rev-parse", "HEAD")
    g("checkout", "-q", "-b", "feature")
    (tmp_path / "feat.txt").write_text("f\n", encoding="utf-8", newline="\n")
    g("add", "feat.txt")
    g("commit", "-q", "-m", "feat")
    theirs = g("rev-parse", "HEAD")
    g("checkout", "-q", "-")
    return tmp_path, ours, theirs, g


def _fake_empty_merge(g, ours, theirs):
    """造「双亲齐、tree 却是 ours」的合并提交并让 `HEAD` 可达（**§15.6 病象**复现）。"""
    tree = g("rev-parse", "HEAD^{tree}")
    fake = g("commit-tree", tree, "-p", ours, "-p", theirs, "-m", "fake empty merge")
    br = g("rev-parse", "--abbrev-ref", "HEAD")
    g("update-ref", f"refs/heads/{br}", fake)     # 移分支指针 ⟹ 进入 `rev-list --merges HEAD`
    return fake


def test_merge_integrity_ok_on_clean_history(tmp_path):
    """正例：只有真合并 ⟹ `ok`、无 suspects。"""
    rp, _ours, _theirs, g = _mk_merge_repo(tmp_path)
    g("merge", "-q", "--no-ff", "-m", "m", "feature")
    res = gw.check_merge_integrity(str(rp))
    assert res["status"] == "ok", res
    assert res["suspects"] == [] and res["scanned"] >= 1, res


def test_merge_integrity_detects_empty_merge(tmp_path):
    """**红先**（§15.6 病象复现）：结果 tree == ours 而分支有变更 ⟹ `warn` 并列入 `suspects`。"""
    rp, ours, theirs, g = _mk_merge_repo(tmp_path)
    fake = _fake_empty_merge(g, ours, theirs)
    res = gw.check_merge_integrity(str(rp))
    assert res["status"] == "warn", res
    assert [s["commit"] for s in res["suspects"]] == [fake], res
    assert res["suspects"][0]["verdict"] == "empty_merge", res


def test_merge_integrity_waiver_is_self_repo_and_sha_pinned(tmp_path, monkeypatch):
    """豁免**只**对技能自仓 + **须命中登记 sha**；非自仓/未命中一律照报（防「洗白」）。"""
    rp, ours, theirs, g = _mk_merge_repo(tmp_path)
    fake = _fake_empty_merge(g, ours, theirs)
    # ① 非自仓：不得豁免
    assert gw.check_merge_integrity(str(rp))["status"] == "warn", "非自仓不得豁免"
    # ② 自仓但 sha 未登记：仍须报
    monkeypatch.setattr(gw, "_SELF_ROOT", rp)
    monkeypatch.setattr(gw, "_MERGE_INTEGRITY_KNOWN_SELF", ("deadbee",))
    assert gw.check_merge_integrity(str(rp))["status"] == "warn", "未命中登记 sha 不得豁免"
    # ③ 自仓 + 命中登记 sha：转 ok，但**细节保留**（可见的非阻断）
    monkeypatch.setattr(gw, "_MERGE_INTEGRITY_KNOWN_SELF", (fake[:7],))
    res = gw.check_merge_integrity(str(rp))
    assert res["status"] == "ok", res
    assert [w["commit"] for w in res["waived_known_self"]] == [fake], res
