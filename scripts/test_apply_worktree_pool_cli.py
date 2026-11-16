#!/usr/bin/env python3
"""热池 CLI 摩擦修复（`--pool-acquire` 显式入口 + reclaim dry-run 语义）红先臂（2026-11-16）。

## 病象（实测，2026-11-15）

池生命周期此前只有三个 CLI 面：`--pool-ensure` / `--pool-status` / `--pool-sweep`。
**抢槽没有显式入口** —— 只能靠发起一次派发（`--session` / `--finding` / `--code-fix`）
间接触发 `gk_worktree_pool.acquire`；想手动占一个槽做实验、或脚本化「先占后做」的
两段式流程，无通路。

同时 `--reclaim --apply --dry-run` **静默落刀**：CLI 的 reclaim 分支只把 `--apply`
拼进 `_rc_args`，`--dry-run` 完全不参与判定（core 侧本就「默认 dry-run」）⟹ 用户以为
在预览，实际已执行归还/归档。回包里 `"dry_run": false` 是事后唯一线索。

## 臂（红先 = 落刀前必红）

  arm1 静态：`cmd_apply_worktree` 含 `--pool-acquire` 分支且委托 `gk_worktree_pool.py acquire`
             （语义单源，禁第二实现）。
  arm2 静态：usage 串列出 `--pool-acquire --sid`；且**无**新 `_CMD_REG` 条目。
  arm3 行为：ensure 1 槽 → `--pool-acquire` 抢槽成功（ok / slot / worktree 存在 / 分支）。
  arm4 行为：同 sid 同分支再抢 ⟹ 幂等复用同一槽（不吃第二槽）。
  arm5 行为：缺 `--sid` ⟹ rc=2 且错误显式（不静默派发）。
  arm6 行为：`--reclaim --apply --dry-run` ⟹ rc=2 `CONFLICTING_FLAGS`，零落刀。
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SD = Path(__file__).resolve().parent.parent
SCRIPTS = SD / "scripts"
CLI = SD / "gatekeeper-cli.sh"
sys.path.insert(0, str(SCRIPTS))


def _wsl(p) -> str:
    """Windows 盘符路径 → WSL 形态（`bash` 此处是 WSL bash）。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _fn_seg(name: str) -> str:
    txt = CLI.read_text(encoding="utf-8")
    rest = txt[txt.index(name + "()"):]
    m = re.search(r"(?m)^\}\s*$", rest)
    return rest[: m.end()] if m else rest


def _git(repo, *a):
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True)


def _repo(tmp_path):
    repo = tmp_path / "main"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "master")
    (repo / "a.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    return repo


def _state(tmp_path):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"stage": "STAGE_0", "r_phase": "R1", "worktree": "",
                              "gate_data": {}}), encoding="utf-8", newline="\n")
    return st


def _cli(args, state, root, repo):
    """真跑 CLI：临时池根 + 临时 state + 显式主仓。"""
    env = ("STATE_FILE='%s' GATEKEEPER_WORKTREE_ROOT='%s' GK_POOL_ALLOW_ANY_ROOT=1 "
           % (_wsl(state), _wsl(root)))
    cmd = ("cd '%s' && %s bash gatekeeper-cli.sh apply-worktree %s"
           % (_wsl(SD), env, " ".join(args)))
    return subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, timeout=180)


def _last_json(p):
    out = [ln for ln in (p.stdout or "").splitlines() if ln.strip().startswith("{")]
    assert out, "CLI 未输出 JSON：rc=%s stdout=%s stderr=%s" % (
        p.returncode, (p.stdout or "")[-400:], (p.stderr or "")[-400:])
    return json.loads(out[-1])


# ── arm1/arm2：静态接线 ───────────────────────────────────────────────────────
def test_arm1_pool_acquire_mode_wired_static():
    seg = _fn_seg("cmd_apply_worktree")
    assert "--pool-acquire" in seg, "cmd_apply_worktree 缺 `--pool-acquire` 模式"
    assert re.search(r"gk_worktree_pool\.py.*acquire --sid", seg), \
        "acquire 模式未委托语义单源 `gk_worktree_pool.py acquire --sid`"


def test_arm2_usage_lists_mode_and_no_new_cmd_reg():
    txt = CLI.read_text(encoding="utf-8")
    assert "--pool-acquire --sid <sid>" in txt, "usage 串未列 `--pool-acquire --sid <sid>`"
    assert not re.search(r"^_CMD_REG\[pool-acquire\]", txt, re.M), \
        "不得新注册 `_CMD_REG[pool-acquire]`（走既有命令的模式）"


# ── arm3/arm4：显式抢槽 ──────────────────────────────────────────────────────
def test_arm3_pool_acquire_leases_slot(tmp_path):
    repo, root = _repo(tmp_path), tmp_path / "wts"
    root.mkdir()
    st = _state(tmp_path)
    e = _cli(["--pool-ensure", "--pool-size", "1", "--main-repo", _wsl(repo)], st, root, repo)
    assert e.returncode == 0, (e.returncode, e.stdout[-400:], e.stderr[-400:])

    a = _cli(["--pool-acquire", "--sid", "probe-sid",
              "--pool-branch", "agent/session/probe", "--main-repo", _wsl(repo)], st, root, repo)
    assert a.returncode == 0, (a.returncode, a.stdout[-400:], a.stderr[-400:])
    d = _last_json(a)
    assert d.get("ok") and d.get("slot") == 0, d
    wt = Path(d["worktree"])
    assert wt.is_dir(), d
    assert _git(wt, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == "agent/session/probe", d


def test_arm4_pool_acquire_is_idempotent_per_sid(tmp_path):
    repo, root = _repo(tmp_path), tmp_path / "wts"
    root.mkdir()
    st = _state(tmp_path)
    _cli(["--pool-ensure", "--pool-size", "1", "--main-repo", _wsl(repo)], st, root, repo)
    args = ["--pool-acquire", "--sid", "probe-sid",
            "--pool-branch", "agent/session/probe", "--main-repo", _wsl(repo)]
    d1 = _last_json(_cli(args, st, root, repo))
    d2 = _last_json(_cli(args, st, root, repo))
    assert d1.get("ok") and d2.get("ok"), (d1, d2)
    assert d2.get("slot") == d1.get("slot") and d2.get("worktree") == d1.get("worktree"), d2
    assert d2.get("idempotent") or d2.get("reused"), "同 sid 同分支未走幂等复用"


# ── arm5：缺参 fail-loud ────────────────────────────────────────────────────
def test_arm5_pool_acquire_requires_sid(tmp_path):
    repo, root = _repo(tmp_path), tmp_path / "wts"
    root.mkdir()
    st = _state(tmp_path)
    p = _cli(["--pool-acquire", "--pool-branch", "agent/session/probe",
              "--main-repo", _wsl(repo)], st, root, repo)
    assert p.returncode == 2, (p.returncode, p.stdout[-300:])
    d = _last_json(p)
    assert d.get("ok") is False and "--sid" in str(d.get("error")), d


# ── arm6：dry-run 与 apply 互斥（不静默取一个）──────────────────────────────
def test_arm6_reclaim_apply_with_dry_run_is_rejected(tmp_path):
    repo, root = _repo(tmp_path), tmp_path / "wts"
    root.mkdir()
    st = _state(tmp_path)
    p = _cli(["--reclaim", "--apply", "--dry-run", "--main-repo", _wsl(repo)], st, root, repo)
    assert p.returncode == 2, (p.returncode, p.stdout[-400:], p.stderr[-400:])
    d = _last_json(p)
    assert d.get("error") == "CONFLICTING_FLAGS", d
    assert d.get("usage"), "互斥拒绝必须给 usage（禁让用户自己猜）"


# ── arm8：池满时 status 必须显式标记 ────────────────────────────────────────
def test_arm8_pool_status_marks_full_and_degraded(tmp_path):
    repo, root = _repo(tmp_path), tmp_path / "wts"
    root.mkdir()
    st = _state(tmp_path)
    _cli(["--pool-ensure", "--pool-size", "1", "--main-repo", _wsl(repo)], st, root, repo)
    _last_json(_cli(["--pool-acquire", "--sid", "probe-sid",
                     "--pool-branch", "agent/session/probe",
                     "--main-repo", _wsl(repo)], st, root, repo))
    s = _last_json(_cli(["--pool-status", "--main-repo", _wsl(repo)], st, root, repo))
    assert s.get("full") is True and s.get("free") == 0, s
    assert s.get("degraded") == "cold-build", s
    assert s.get("next"), "满时 status 必须给可执行降级路径"


# ── arm7：显式 dry-run 必须真的零落刀 ───────────────────────────────────────
def test_arm7_reclaim_dry_run_is_zero_write(tmp_path):
    """`--reclaim --dry-run` ⟹ 回包 `dry_run: true` 且 `removed`/`archived` 为空。

    注：`gk_worktree_reclaim.py` 的扫描面恒为**主仓**（`--repo "$SKILL_DIR"`），临时池不在其中；
    故本臂只锁「CLI 不把 dry-run 变成落刀」这一条 —— 用 `--path` 白名单把真实槽全部 skip，
    零副作用。池槽的预告语义（`WOULD-POOL-RELEASE`）由 `test_gk_worktree_reclaim.py` 覆盖。
    """
    repo, root = _repo(tmp_path), tmp_path / "wts"
    root.mkdir()
    st = _state(tmp_path)
    _cli(["--pool-ensure", "--pool-size", "1", "--main-repo", _wsl(repo)], st, root, repo)
    a = _last_json(_cli(["--pool-acquire", "--sid", "probe-sid",
                         "--pool-branch", "agent/session/probe",
                         "--main-repo", _wsl(repo)], st, root, repo))

    d = _last_json(_cli(["--reclaim", "--dry-run", "--path", a["worktree"],
                         "--main-repo", _wsl(repo)], st, root, repo))
    assert d.get("dry_run") is True, d
    assert d.get("removed") == [] and d.get("archived") == [], d

    # 槽必须仍在租（零落刀）
    s = _last_json(_cli(["--pool-status", "--main-repo", _wsl(repo)], st, root, repo))
    slot = [x for x in s.get("slots", []) if x.get("slot") == a.get("slot")]
    assert slot and slot[0].get("state") == "leased", s

