#!/usr/bin/env python3
"""真因 D 红先臂（2026-11-02）：python 侧路径形态必须以**解释器**为锚。

病象（worktree `scripts/gk_dbg.log` 实测，6 臂全中）：
  · MSYS bash + 原生 Windows python ⟹ `open('/c/Users/...')` → FileNotFoundError
    ⟹ 外层报 `DUMP_REPORT_INVALID`（真因被伪装成「报告缺字段」，且该告警不阻断）；
  · 同一形态进 `sys.path.insert(0,'/c/.../scripts')` → ModuleNotFoundError
    ⟹ 整个 history 落库块未执行 ⟹ `HISTORY_WRITE_FAILED`（真丢数据）。

判据（每条都曾在旧实现上为红）：
  1. 形态转换单源 `_gk_py_path`：win 解释器下 `/c/…` 与 `/mnt/c/…` 均转 `C:/…`，
     已是 Windows 形态则原样；posix 解释器下原样（它自己认得两种 POSIX 形态）。
  2. history 载荷的 state / scripts 路径**经 env 传入**（禁内联 `'$STATE_FILE'` /
     `'$SKILL_DIR/scripts'`）。
  3. 落盘校验同样经 env（禁 `open('$sub_out_file'`）。
"""
import os
import re
import subprocess
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"
TXT = CLI.read_text(encoding="utf-8")


def _func(name):
    m = re.search(r"^%s\(\) \{.*?^\}" % re.escape(name), TXT, re.S | re.M)
    assert m, "缺函数 %s（python 侧形态单源未落）" % name
    return m.group(0)


def _run(expr, form):
    script = "\n".join([_func("_gx_to_win_path"), _func("_gk_py_form"),
                        _func("_gk_py_path"), expr])
    env = {**os.environ, "GK_PY_FORM": form}
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def test_py_path_win_form():
    assert _run('_gk_py_path "/c/Users/HP/x"', "win") == "<home>/x"
    assert _run('_gk_py_path "<home>/x"', "win") == "<home>/x"
    assert _run('_gk_py_path "<home>/x"', "win") == "<home>/x"
    assert _run('_gk_py_path "<home>\\\\x"', "win") == "<home>\\x"


def test_py_path_posix_form_unchanged():
    assert _run('_gk_py_path "/c/Users/HP/x"', "posix") == "/c/Users/HP/x"
    assert _run('_gk_py_path "<home>/x"', "posix") == "<home>/x"
    assert _run('_gk_py_path "/home/u/x"', "posix") == "/home/u/x"


def _history_segment():
    start = TXT.index('echo "$subagent_out" | GK_TASK=')
    end = TXT.index("[hist] ERROR HISTORY_WRITE_FAILED", start)
    return TXT[start:end]


def test_history_payload_uses_env_paths():
    seg = _history_segment()
    assert "GK_PY_SCRIPTS" in seg and "GK_PY_STATE" in seg, seg[:400]
    assert "sys.path.insert(0,os.environ['GK_PY_SCRIPTS'])" in seg
    assert "state_lock(os.environ['GK_PY_STATE'])" in seg
    assert "open(os.environ['GK_PY_STATE']" in seg
    # 内联形态会让原生 Windows python 直接 FileNotFoundError / ModuleNotFoundError
    assert "'$SKILL_DIR/scripts'" not in seg
    assert "'$STATE_FILE'" not in seg


def test_dump_report_validation_uses_env_path():
    i = TXT.index("printf '[hist] ERROR DUMP_REPORT_INVALID")
    seg = TXT[max(0, i - 1200):i]
    assert "GK_PY_OUT_FILE" in seg, seg
    assert "open('$sub_out_file'" not in seg


# ─── 第二轮（2026-11-02）：其余「状态读写」内联拼接清零 ──────────────────────────
# 判据：内联路径只有一种后果 —— 原生 Windows python 收到 `/c/…` 形态即报错。
#   注释行里的反例（如 `json.dump(open('$STATE_FILE','w'))` 的历史说明）不算实现，
#   故统一在**去注释**后的源码上判。
def _no_comments(src):
    return "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))


def _outside_protected(src):
    """剔除 `PROTECTED_REGION::*` 区间（区内行级禁改，另行授权，不能算本轮的清理面）。"""
    out, inside = [], False
    for ln in src.splitlines():
        s = ln.strip()
        if s.startswith("# PROTECTED_REGION_START::"):
            inside = True
        if not inside:
            out.append(ln)
        if s.startswith("# PROTECTED_REGION_END::"):
            inside = False
    return "\n".join(out)


def test_state_write_core_uses_env_paths():
    body = _no_comments(_func("_state_write"))
    assert "GK_PY_SCRIPTS" in body and "GK_PY_STATE" in body, body[:300]
    assert "sys.path.insert(0,os.environ['GK_PY_SCRIPTS'])" in body
    assert "state_lock(os.environ['GK_PY_STATE'])" in body
    assert "open(os.environ['GK_PY_STATE']" in body
    assert "dump_state(os.environ['GK_PY_STATE']" in body
    assert "'$SKILL_DIR/scripts'" not in body
    assert "'$STATE_FILE'" not in body


def test_checksum_write_core_uses_env_paths():
    body = _no_comments(_func("_state_checksum_write"))
    assert "GK_PY_SCRIPTS" in body and "GK_PY_STATE" in body, body[:300]
    assert "sys.path.insert(0,os.environ['GK_PY_SCRIPTS'])" in body
    assert "state_lock(os.environ['GK_PY_STATE'])" in body
    assert "'$SKILL_DIR/scripts'" not in body
    assert "'$STATE_FILE'" not in body


def test_discover_carry_payloads_use_env_paths():
    assert "open('$_idle_cf'" not in TXT
    assert "open('$_carry_f'" not in TXT
    assert TXT.count("GK_PY_CARRY") >= 4, "carry 快照路径未走 env（见 cmd_discover 两处）"


def test_gx_repo_dir_reads_state_via_env():
    body = _func("_gx_repo_dir_for_current")
    assert "GK_PY_STATE" in body
    assert "open('$STATE_FILE'" not in body


def test_bill_payload_uses_env_state():
    a = TXT.index('GK_BILL_PATH="$real_path" _state_write "')
    b = TXT.index('" >/dev/null 2>&1 || true', a)
    pay = TXT[a:b]
    assert "'$STATE_FILE'" not in pay, "计费 payload 仍内联 state 路径"
    assert "GK_PY_STATE" in pay


def test_monitor_and_cron_inline_paths_cleared():
    """monitor 读 state / hook 快照 / check-changes / cron 起停 / 回收落点。

    判据面 = **区外**（受保护区行级禁改，需另行授权，见 `PROTECTED_REGION` 标记）。
    """
    code = _no_comments(_outside_protected(TXT))
    assert "open('$" not in code, "区外仍有 python 内联 open('$…')（原生 Windows python 必失败）"
    assert "open(\"$" not in code, "区外仍有 python 内联 open(\"$…\")"
    assert "'${SKILL_DIR}/scripts'" not in code, "区外仍有 sys.path 内联 SKILL_DIR"
    assert "'$SKILL_DIR/scripts'" not in code, "区外仍有 sys.path 内联 SKILL_DIR"
    for lit in ("open('$bs_tmp'", "open('$rc_file'", "open('$GK_DBG_LOG'"):
        assert lit not in TXT, "%s 仍内联（形态会随 bash 而非解释器）" % lit
