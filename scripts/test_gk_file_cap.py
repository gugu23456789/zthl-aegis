"""红先臂：单文件硬上限（REV-23，2026-10-23；owner 裁定 A + N=10）。

病象（本仓实测）：计费按「唯一改动文件」去重 ⟹ 反复改**同一**文件只把 `cost` 抬到 2（T4′），
**没有上限**；而「改崩」最典型的形态恰恰是同文件反复落刀 —— 加价拦不住（额度还够就一直改）。

修法（本臂钉住）：
  · 判据单源 = `gk_budget_ledger.file_cap_flag`（只读）：同 `(session,node)` 内、**最近一次
    verify 之后**、同 `path` 的编辑数 ≥ N ⟹ Gate 4 **BLOCK**（不是加价）；
  · 销账通道 = `kind=verify`（与 T6 同一信号源）：先证明没改崩再继续；
  · kill switch：`GK_EDIT_FILE_CAP=0` 关；`=<n>` 覆盖 N。

落刀前红：`file_cap_flag` / CLI `file-cap` 不存在 ⟹ 本套件红（AttributeError / CLI 无子命令）。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = Path(os.environ.get("GK_CLI_UNDER_TEST") or (SKILL_DIR / "gatekeeper-cli.sh"))

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import gk_budget_ledger as B  # noqa: E402


def _mkstate(tmp_path):
    st = str(tmp_path / ".gkstate")
    Path(st).write_text(json.dumps({"gate_data": {"edit_budget": {"max": 24, "used": 0,
                                                                  "remaining": 24}}}),
                        encoding="utf-8")
    return st


# ───────── 判据（只读、纯函数面）─────────
def test_cap_flags_at_n_threshold(tmp_path):
    st = _mkstate(tmp_path)
    for i in range(B.FILE_EDIT_CAP - 1):
        B.append_edit(st, session="s", node="N", path="/x/a.py")
    assert B.file_cap_flag(st, "/x/a.py", session="s", node="N")["flagged"] is False, \
        "未达上限就拦（过早）"
    B.append_edit(st, session="s", node="N", path="/x/a.py")
    got = B.file_cap_flag(st, "/x/a.py", session="s", node="N")
    assert got["flagged"] is True and got["count"] == B.FILE_EDIT_CAP, got


def test_cap_ignores_other_paths_and_nodes(tmp_path):
    """只数**同 path + 同节点 + 同会话**：别的文件/节点的落刀不得把人拦死。"""
    st = _mkstate(tmp_path)
    for i in range(B.FILE_EDIT_CAP):
        B.append_edit(st, session="s", node="N", path="/x/other.py")
        B.append_edit(st, session="s", node="OTHER", path="/x/a.py")
    assert B.file_cap_flag(st, "/x/a.py", session="s", node="N")["flagged"] is False


def test_cap_cleared_by_verify(tmp_path):
    """销账腿：verify 之后计数归零（先证明没改崩再继续）。"""
    st = _mkstate(tmp_path)
    for i in range(B.FILE_EDIT_CAP):
        B.append_edit(st, session="s", node="N", path="/x/a.py")
    assert B.file_cap_flag(st, "/x/a.py", session="s", node="N")["flagged"] is True
    B.append_verify(st, session="s", node="N", cmd="pytest -q")
    got = B.file_cap_flag(st, "/x/a.py", session="s", node="N")
    assert got["flagged"] is False and got["count"] == 0, got
    B.append_edit(st, session="s", node="N", path="/x/a.py")
    assert B.file_cap_flag(st, "/x/a.py", session="s", node="N")["count"] == 1, \
        "verify 后计数未从 0 起算"


def test_cap_k_zero_disables(tmp_path):
    st = _mkstate(tmp_path)
    for i in range(B.FILE_EDIT_CAP * 2):
        B.append_edit(st, session="s", node="N", path="/x/a.py")
    assert B.file_cap_flag(st, "/x/a.py", k=0, session="s", node="N")["flagged"] is False


def test_cap_rejects_do_not_count(tmp_path):
    """`reject` 不计（与 T4′/T6 同口径）：否则「撞墙一次 ⟹ 计数 +1 ⟹ 更撞墙」自我强化。"""
    st = _mkstate(tmp_path)
    for i in range(B.FILE_EDIT_CAP * 2):
        B.append_edit(st, session="s", node="N", path="/x/a.py", result="reject")
    got = B.file_cap_flag(st, "/x/a.py", session="s", node="N")
    assert got["flagged"] is False and got["count"] == 0, got


# ───────── Gate 4 集成（真 CLI `pre-tool-check edit`）─────────
def _wsl(p) -> str:
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _mk_sandbox(tmp_path: Path) -> Path:
    """沙箱技能根：`scripts` 软链 + CLI 实拷 + 最小 state（standing）+ 目标文件。"""
    sb = (tmp_path / "sb").resolve()
    sb.mkdir()
    w = _wsl(sb)
    r = subprocess.run(
        ["bash", "-lc", 'ln -s "%s" "%s/scripts" && cp "%s" "%s/gatekeeper-cli.sh"'
         % (_wsl(SCRIPT_DIR), w, _wsl(CLI_SRC), w)],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, "沙箱搭建失败：%s%s" % (r.stdout, r.stderr)
    (sb / ".gatekeeper.state").write_text(json.dumps({
        "stage": "STAGE_0", "r_phase": "R1", "worktree": w,
        "gate_data": {"project_type": "standing",
                      "edit_budget": {"max": 100, "used": 0, "remaining": 100}},
    }, ensure_ascii=False), encoding="utf-8", newline="\n")
    (sb / "note.md").write_text("x", encoding="utf-8", newline="\n")
    return sb


def _run_edit(sb: Path, extra_env: dict = None):
    w = _wsl(sb)
    env = {**os.environ, "STATE_FILE": _wsl(sb / ".gatekeeper.state"),
           "GK_SESSION_ID": "", "GK_EDIT_LOG": "1"}
    env.pop("GK_EDIT_FILE_CAP", None)
    env.update(extra_env or {})
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh pre-tool-check edit "%s/note.md"'
         % (w, w)],
        env=env, capture_output=True, text=True, timeout=180)


def _seed_edits(sb: Path, n: int, path: str):
    st = str(sb / ".gatekeeper.state")
    for i in range(n):
        B.append_edit(st, session="", node="STAGE_0", path=path)


def test_gate4_blocks_when_cap_reached(tmp_path):
    """正臂：同文件自上次验证以来第 N 次落刀 ⟹ `pre-tool-check edit` 必须 BLOCK。"""
    sb = _mk_sandbox(tmp_path)
    target = str((sb / "note.md").resolve())
    _seed_edits(sb, B.FILE_EDIT_CAP, target)
    p = _run_edit(sb)
    assert p.returncode != 0, "已达单文件上限却放行：%s" % (p.stdout[:300],)
    assert "single-file edit cap" in p.stdout, p.stdout[:400]


def test_gate4_allows_below_cap(tmp_path):
    """负臂：N-1 次落刀仍放行（防「一上电就全拦」）。"""
    sb = _mk_sandbox(tmp_path)
    _seed_edits(sb, B.FILE_EDIT_CAP - 1, str((sb / "note.md").resolve()))
    p = _run_edit(sb)
    assert p.returncode == 0, "未达上限却被拦：%s" % (p.stdout[:300],)


def test_gate4_allows_after_verify(tmp_path):
    """销账臂：撞上限后跑一次 verify ⟹ 下一刀放行（否则等于不可恢复的死锁）。"""
    sb = _mk_sandbox(tmp_path)
    target = str((sb / "note.md").resolve())
    _seed_edits(sb, B.FILE_EDIT_CAP, target)
    assert _run_edit(sb).returncode != 0
    B.append_verify(str(sb / ".gatekeeper.state"), session="", node="STAGE_0", cmd="pytest -q")
    assert _run_edit(sb).returncode == 0, "verify 之后仍被单文件上限拦死（销账通道失效）"


def test_gate4_cap_kill_switch(tmp_path):
    """kill switch：`GK_EDIT_FILE_CAP=0` ⟹ 逐字回到修前（不再有该判据）。"""
    sb = _mk_sandbox(tmp_path)
    _seed_edits(sb, B.FILE_EDIT_CAP * 2, str((sb / "note.md").resolve()))
    p = _run_edit(sb, {"GK_EDIT_FILE_CAP": "0"})
    assert p.returncode == 0, "GK_EDIT_FILE_CAP=0 未生效：%s" % (p.stdout[:300],)


def test_gate4_cap_env_override(tmp_path):
    """可调：`GK_EDIT_FILE_CAP=<n>` 覆盖 N（撞墙点随之移动）。"""
    sb = _mk_sandbox(tmp_path)
    _seed_edits(sb, 2, str((sb / "note.md").resolve()))
    assert _run_edit(sb, {"GK_EDIT_FILE_CAP": "2"}).returncode != 0, "N=2 未生效"
    assert _run_edit(sb, {"GK_EDIT_FILE_CAP": "3"}).returncode == 0, "N=3 时 2 次落刀不该被拦"


def test_cli_file_cap_wired(tmp_path):
    """CLI 面：`file-cap` 子命令可调用并回 JSON（供人工核账/脚本复用）。"""
    st = _mkstate(tmp_path)
    B.append_edit(st, session="s", node="N", path="/x/a.py")
    r = subprocess.run([sys.executable, str(SCRIPT_DIR / "gk_budget_ledger.py"), "file-cap",
                        "--state", st, "--path", "/x/a.py", "--session", "s", "--node", "N",
                        "--k", "1"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["flagged"] is True and out["count"] == 1 and out["k"] == 1, out
