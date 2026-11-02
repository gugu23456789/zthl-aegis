#!/usr/bin/env python3
"""观景台（`state --watch`）红先臂（2026-11-01）。

要求：
  1. 只读：跑完工作区文件 mtime/字节不变（无写盘）；
  2. 结构：必需段齐全（worktrees/recent/scratch/states/cross_os/buddy）；
  3. 归属面：`states[].owner` 三态（ok/missing/mismatch）+ 路径形态分类（win/wsl/posix）；
  4. 只读性声明：`read_only=true`（供上游审计直接采信）。
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import gk_watch as W  # noqa: E402


def _run(tmp_path, *extra):
    r = subprocess.run([sys.executable, str(Path(W.__file__)), "--skill-dir", str(tmp_path), *extra],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_schema_and_read_only(tmp_path):
    sf = tmp_path / ".gatekeeper.state"
    sf.write_text(json.dumps({"worktree": str(tmp_path)}), encoding="utf-8")
    (tmp_path / ".mk_domain_state.py").write_text("# scratch\n", encoding="utf-8")
    log = tmp_path / ".gatekeeper.state.watch-log.jsonl"
    out = _run(tmp_path, "--hours", "1")
    assert out["ok"] is True and out["read_only"] is True
    for k in ("worktrees", "recent", "scratch", "states", "cross_os", "buddy"):
        assert k in out, k
    # 观景台唯一的写面 = 访客日志（append-only）；除此之外零改盘
    assert log.is_file(), "必须落访客记录"
    rec = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
    for k in ("ts", "event", "side", "user", "host", "pid", "snapshot_sha256", "counts", "scope"):
        assert k in rec, k
    assert rec["event"] == "observe" and rec["scope"] == "own"
    assert rec["snapshot_sha256"] == hashlib.sha256(
        json.dumps({k: v for k, v in out.items() if k != "visit_log"},
                   ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def test_cross_side_is_gated_by_default(tmp_path):
    """跨边界观测默认关闭：buddy 段只给 gated 说明，不列另一侧目录。"""
    (tmp_path / ".gatekeeper.state").write_text(json.dumps({"worktree": str(tmp_path)}), encoding="utf-8")
    out = _run(tmp_path, "--hours", "1")
    assert out["buddy"]["roots"] == [] and out["buddy"].get("gated"), out["buddy"]


def test_scratch_and_state_owner(tmp_path):
    (tmp_path / ".gatekeeper.state").write_text(json.dumps({"worktree": str(tmp_path)}), encoding="utf-8")
    (tmp_path / ".gatekeeper.state.skill.x").write_text(json.dumps({"worktree": "/elsewhere"}), encoding="utf-8")
    (tmp_path / ".gatekeeper.state.skill.y").write_text(json.dumps({}), encoding="utf-8")
    (tmp_path / ".fix_sidecar.py").write_text("x=1\n", encoding="utf-8")
    out = _run(tmp_path, "--hours", "1")
    owners = {(s["path"]): s["owner"] for s in out["states"]}
    assert owners[".gatekeeper.state"] == "ok"
    assert owners[".gatekeeper.state.skill.x"] == "mismatch"
    assert owners[".gatekeeper.state.skill.y"] == "missing"
    assert any(s["path"] == ".fix_sidecar.py" for s in out["scratch"]), out["scratch"]


def test_cross_os_form_classification():
    assert W._form("<home>/x") == "win"
    assert W._form("<home>/x") == "wsl"
    assert W._form("/home/x") == "posix"
    assert W._form("") == "none"
    # 形态归一：同一棵树两种写法必须相等（跨平台比较的唯一正确口径）
    assert W._canon("<home>\\x\\") == W._canon("<home>/x")


def test_artifacts_are_not_states(tmp_path):
    (tmp_path / ".gatekeeper.state").write_text(json.dumps({"worktree": str(tmp_path)}), encoding="utf-8")
    (tmp_path / ".gatekeeper.state.finding-journal.jsonl").write_text("{}", encoding="utf-8")
    (tmp_path / ".gatekeeper.scopes.json").write_text("{}", encoding="utf-8")
    out = _run(tmp_path, "--hours", "1")
    names = [s["path"] for s in out["states"]]
    assert names == [".gatekeeper.state"], names


def test_probes_present(tmp_path):
    (tmp_path / ".gatekeeper.state").write_text(json.dumps({"worktree": str(tmp_path)}), encoding="utf-8")
    out = _run(tmp_path, "--hours", "1")
    for k in ("path_forms", "worktree_git_view", "line_endings", "identity_literals",
              "runtime_artifacts", "remote_whitelist", "case_sensitivity", "interpreter"):
        assert k in out["probes"], k
    assert "side" in out and "issues" in out


def test_local_form_roundtrip():
    """双向核心：任一侧形态都能转成本侧可解析形态，且 canon 后同一棵树。"""
    assert W._canon(W._local("<home>/x")) == W._canon("<home>/x")
    assert W._canon(W._local("<home>/x")) == "c:/users/hp/x"


def test_os_refs_summary(tmp_path):
    """OS-5/6/7 汇总面：清洁时也给 0 计数（供 zthl-adapter §ZH4 直接采信）。"""
    (tmp_path / ".gatekeeper.state").write_text(json.dumps({"worktree": "/elsewhere"}), encoding="utf-8")
    out = _run(tmp_path, "--hours", "1")
    refs = out["os_refs"]
    assert {"OS-5", "OS-6", "OS-7"} <= set(refs)
    assert refs["OS-6"]["state_owner_bad"] == 1, refs["OS-6"]
    assert refs["OS-7"]["remote_unmatched"] == 0


def test_save_then_compare(tmp_path):
    (tmp_path / ".gatekeeper.state").write_text(json.dumps({"worktree": str(tmp_path)}), encoding="utf-8")
    snap = tmp_path / ".zthl" / "watch" / "snap.json"
    out = _run(tmp_path, "--hours", "1", "--save", str(snap))
    assert out["read_only"] is False and out.get("saved") == str(snap)
    other = json.loads(snap.read_text(encoding="utf-8"))
    other["side"] = "nt" if out["side"] != "nt" else "wsl"
    other["probes"]["line_endings"] = {"crlf_only": 99, "mixed": 0, "sample": [], "scanned": 1}
    op = tmp_path / "other.json"
    op.write_text(json.dumps(other), encoding="utf-8")
    cmp_out = _run(tmp_path, "--hours", "1", "--compare", str(op))
    ids = [d["id"] for d in cmp_out["compare"]["divergences"]]
    assert "side_differs" in ids and "probe_line_endings" in ids, ids


def test_save_outside_allowed_is_refused(tmp_path):
    """写入边界：仓库根/任意目录一律拒（只允许 .zthl/watch 或 ~/.trae/watch）。"""
    (tmp_path / ".gatekeeper.state").write_text(json.dumps({"worktree": str(tmp_path)}), encoding="utf-8")
    r = subprocess.run([sys.executable, str(Path(W.__file__)), "--skill-dir", str(tmp_path),
                        "--hours", "1", "--save", str(tmp_path / "snap.json")],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 2, r.stdout + r.stderr
    assert json.loads(r.stdout)["error"] == "SAVE_PATH_NOT_ALLOWED"
    assert not (tmp_path / "snap.json").exists()


def test_identity_masked_by_default():
    assert W._mask_identity("<home>/x/y") == "/mnt/c/Users/<user>/x/y"
    assert W._mask_identity(r"<home>\x") == r"C:\Users\<user>\x"


def test_keys_dir_not_scanned(tmp_path):
    """读取边界：`.keys/` 不参与 recent 列举（连文件名都不进快照）。"""
    (tmp_path / ".gatekeeper.state").write_text(json.dumps({"worktree": str(tmp_path)}), encoding="utf-8")
    k = tmp_path / ".keys"
    k.mkdir()
    (k / "secret_ed25519.pem").write_text("x", encoding="utf-8")
    out = _run(tmp_path, "--hours", "1")
    assert all(".keys/" not in r["path"] for r in out["recent"]), out["recent"]


def test_default_skill_dir_is_not_cwd(tmp_path, monkeypatch):
    """缺省 `--skill-dir` = 技能目录（`GK_SKILL_DIR` > 本文件父父目录），**不是 cwd**。

    裸跑（不经 CLI）时 cwd 是任意项目根 ⟹ 访客记录会被写到那儿，与 hook 侧分叉。
    """
    monkeypatch.delenv("GK_SKILL_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    d = Path(W._default_skill_dir()).resolve()
    assert d == Path(W.__file__).resolve().parent.parent, d
    assert d != tmp_path.resolve()
    monkeypatch.setenv("GK_SKILL_DIR", str(tmp_path / "skill"))
    assert W._default_skill_dir() == str(tmp_path / "skill")
