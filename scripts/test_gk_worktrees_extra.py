#!/usr/bin/env python3
"""S3 红先臂：`worktrees_extra[]` 唯一写通路（`ECC-D21AFB35DC1E`，2026-09-27）。

缺陷（`ECC-D21AFB35DC1E`，open）：`state-patch --set-top` 只挡 `gate_data` 与 `_` 前缀
⟹ `worktrees_extra` 这类**新顶层键可自助写入** = 活动写面允许集能被自助放宽（硬约束退化）。

修法：① `gk_state_patch._TOP_DENY` 收编 `worktrees_extra`（`set-top` fail-loud 拒绝）；
② 新增 `gk_state_patch worktrees-extra <state> bind|unbind <path>` 作为**唯一写通路**
（持 `state_lock` + `_write_state` 重算 checksum + **幂等** + `--dry-run` 零写盘）；
③ CLI `apply-worktree --bind/--unbind --path <dir>` 接线（区外，零保护区改动）。

臂：arm19a 静态（函数 / 黑名单 / CLI 接线）；arm19b 行为（写路径契约）；arm19c 负臂（直写被拒）。

**S4 追加**（`ECC-D15C62FFF34A`，「RC6 回收未闭合」的允许集面）：`reclaim` 删目录 ⟹ **同批清
悬空 `extras`**（`worktrees_extra[]` 中目录已不存在的条目 = 永不命中的放行项）：
  arm20a 静态：`gk_worktree_reclaim.py` 暴露 `dangling_extras` / 接线 `unbound_extras`，且 CLI 把
              本域 state 传给回收链（`--state`）；
  arm20b 行为：dry-run 只报（零写盘）→ `--apply` 解绑悬空项**且保留仍存在的项**；
  arm20c 负臂：非悬空项（目录仍在）**不得**被解绑。

HEAD 上 `gk_state_patch.py` 无 `worktrees-extra` 子命令、`_TOP_DENY` 未收编该键、CLI 无接线、
`gk_worktree_reclaim.py` 无 `dangling_extras` ⟹ 六臂全红（非 error）。
"""
import json
import subprocess
import sys
from pathlib import Path

SD = Path(__file__).resolve().parent.parent
SCRIPTS = SD / "scripts"
CLI = SD / "gatekeeper-cli.sh"
SP = SCRIPTS / "gk_state_patch.py"
RC = SCRIPTS / "gk_worktree_reclaim.py"
PY = sys.executable


def _state(tmp: Path, extra=None) -> Path:
    d = {"stage": "ECO-EDIT", "r_phase": "R1", "worktree": ""}
    if extra is not None:
        d["worktrees_extra"] = extra
    p = tmp / ".gatekeeper.state"
    p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8", newline="\n")
    return p


def _run(*args):
    return subprocess.run([PY, str(SP), *args], capture_output=True, text=True, timeout=60)


def _json(p) -> dict:
    """`gk_state_patch.py` 输出为 `indent=2` 多行 JSON ⟹ 解析**整段** stdout（非末行）。"""
    try:
        return json.loads((p.stdout or "").strip())
    except Exception:
        try:
            return json.loads((p.stdout or "").strip().splitlines()[-1])
        except Exception:
            return {}


def test_arm19a_unique_write_path_static():
    """arm19a（静态，红先）：唯一写通路存在 + `_TOP_DENY` 收编 + CLI 接线。"""
    src = SP.read_text(encoding="utf-8")
    assert "def cmd_worktrees_extra(" in src, "缺 `cmd_worktrees_extra`（唯一写通路）"
    # 黑名单须收编该键（防 set-top 自助放宽）；取 `_TOP_DENY` 定义块切片
    deny = src[src.index("_TOP_DENY"):src.index("def cmd_set_top(")]
    assert "worktrees_extra" in deny, "`_TOP_DENY` 未收编 worktrees_extra ⟹ set-top 仍可自助写入"
    cli = CLI.read_text(encoding="utf-8")
    assert "worktrees-extra" in cli, "CLI 未接线 gk_state_patch `worktrees-extra`"
    assert "--bind" in cli and "--unbind" in cli and "--path" in cli, \
        "CLI 未接线 `apply-worktree --bind/--unbind --path`"


def test_arm19b_bind_unbind_idempotent_dryrun(tmp_path):
    """arm19b（行为，红先）：bind 归一化写入 / 幂等零写盘 / dry-run 零写盘 / unbind 移除。"""
    st = _state(tmp_path)
    d = tmp_path / "wtA"
    d.mkdir()
    j1 = _json(_run("worktrees-extra", str(st), "bind", str(d)))
    assert j1.get("ok") and j1.get("changed") and j1.get("worktrees_extra"), j1
    assert any(x.endswith("/wtA") for x in json.loads(st.read_text(encoding="utf-8"))["worktrees_extra"]), \
        "bind 未落到 state.worktrees_extra"
    raw1 = st.read_bytes()
    # 幂等：重复 bind ⟹ changed:false 且零写盘
    j2 = _json(_run("worktrees-extra", str(st), "bind", str(d)))
    assert j2.get("ok") and j2.get("changed") is False, j2
    assert st.read_bytes() == raw1, "幂等 bind 却改写了 state（应零写盘）"
    # dry-run ⟹ 零写盘
    j3 = _json(_run("worktrees-extra", str(st), "unbind", str(d), "--dry-run"))
    assert j3.get("ok") and j3.get("changed") and j3.get("dry_run"), j3
    assert st.read_bytes() == raw1, "dry-run 改写了 state（应零写盘）"
    # unbind
    j4 = _json(_run("worktrees-extra", str(st), "unbind", str(d)))
    assert j4.get("ok") and j4.get("changed"), j4
    assert json.loads(st.read_text(encoding="utf-8")).get("worktrees_extra") == [], "unbind 未移除"


def test_arm19c_set_top_denies_worktrees_extra(tmp_path):
    """arm19c（负臂，红先）：`set-top worktrees_extra` 必须 fail-loud —— 防自助放宽。"""
    st = _state(tmp_path)
    j = _json(_run("set-top", str(st), "worktrees_extra", "[]"))
    assert j.get("ok") is not True, f"set-top worktrees_extra 未被拒（自助放宽面仍在）：{j}"


# ────────────────────── S4：回收链同批清悬空 extras（`ECC-D15C62FFF34A`）──────────────────────

def _reclaim(*args):
    return subprocess.run([PY, str(RC), *args], capture_output=True, text=True, timeout=60)


def test_arm20a_reclaim_dangling_wired_static():
    """arm20a（静态，红先）：`dangling_extras` 暴露 + 接线 + CLI 传 state。"""
    src = RC.read_text(encoding="utf-8")
    assert "def dangling_extras(" in src, "缺 `dangling_extras`（悬空允许集枚举）"
    assert "unbound_extras" in src, "回收链未接线解绑结果字段"
    cli = CLI.read_text(encoding="utf-8")
    assert '--state "${state_override:-$STATE_FILE}" "${_rc_args[@]}"' in cli, \
        "CLI 未把本域 state 传给回收链（悬空 extras 无从判定）"


def test_arm20b_reclaim_unbinds_dangling_keeps_existing(tmp_path):
    """arm20b（行为，红先）：dry-run 只报零写盘 → `--apply` 解绑悬空且保留存在项。"""
    repo = tmp_path / "repo"
    repo.mkdir()
    root = tmp_path / "wtroot"
    root.mkdir()
    st = _state(tmp_path)
    gone = tmp_path / "gone_wt"                          # 不创建 ⟹ 悬空
    keep = tmp_path / "keep_wt"
    keep.mkdir()
    for p in (str(gone), str(keep)):
        assert _json(_run("worktrees-extra", str(st), "bind", p)).get("ok"), p
    # dry-run：只报，零写盘
    rep = _json(_reclaim("--repo", str(repo), "--root", str(root), "--state", str(st)))
    assert any(x.endswith("gone_wt") for x in rep.get("dangling_extras") or []), \
        f"dry-run 未报出悬空项：{rep.get('dangling_extras')}"
    assert len(json.loads(st.read_text(encoding="utf-8"))["worktrees_extra"]) == 2, \
        "dry-run 改写了 state（应零写盘）"
    # apply：解绑悬空 + 保留存在项
    r2 = _reclaim("--repo", str(repo), "--root", str(root), "--state", str(st), "--apply")
    assert r2.returncode == 0, r2.stderr[-300:]
    extra = json.loads(st.read_text(encoding="utf-8")).get("worktrees_extra", [])
    assert len(extra) == 1 and extra[0].endswith("keep_wt"), \
        f"悬空未清 / 存在项被误清：{extra}"


def test_arm20c_reclaim_keeps_existing_extras(tmp_path):
    """arm20c（负臂，红先）：目录仍存在的允许集项**不得**被解绑（防过度清理）。"""
    repo = tmp_path / "repo"
    repo.mkdir()
    root = tmp_path / "wtroot"
    root.mkdir()
    st = _state(tmp_path)
    alive = tmp_path / "alive_wt"
    alive.mkdir()
    assert _json(_run("worktrees-extra", str(st), "bind", str(alive))).get("ok")
    r = _reclaim("--repo", str(repo), "--root", str(root), "--state", str(st), "--apply")
    assert r.returncode == 0, r.stderr[-300:]
    extra = json.loads(st.read_text(encoding="utf-8")).get("worktrees_extra", [])
    assert len(extra) == 1 and extra[0].endswith("alive_wt"), f"存在项被误清：{extra}"
