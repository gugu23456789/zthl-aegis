#!/usr/bin/env python3
"""sanctioned release 出口（`apply-worktree --release-claim <sid>`）红先臂（2026-10-06）。

动机：`gk_write_claims.release` 是设计内的**终态出口**（`state ∈ {live,renewed}` 之外唯一收口），
但**无 CLI 面** —— 直跑 `scripts/gk_*.py` 被**加载安全网**拦（绕开 CLI 门禁 / 审计留痕）⟹ 悬空 /
测试残留 / 会话提前终结的 claim 只能干等 TTL（默认 3600s）自然失活，窗口内回收面对账持续误报
（zombie / 误 held）。本刀把它挂到**既有** `apply-worktree`（与 `--reclaim` 同属 claims 面），
**不新注册命令**（`_CMD_REG` 在 `PROTECTED_REGION::gate` 内）。

臂（红先 = 落刀前必红）：
  arm1 静态：`cmd_apply_worktree` 含 `--release-claim` 分支且委托 `gk_write_claims.py release`。
  arm2 静态：usage 串列出该模式；且**无**新 `_CMD_REG` 条目（守注册表不变量）。
  arm3 行为：live claim 经 CLI release ⟹ 台账追加 `released` 行 + `live()` 不再含该 sid。
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
import gk_write_claims as C  # noqa: E402


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


def test_arm1_release_claim_mode_wired_static():
    seg = _fn_seg("cmd_apply_worktree")
    assert "--release-claim" in seg, "cmd_apply_worktree 缺 `--release-claim` 模式"
    assert "gk_write_claims.py" in seg and "release" in seg, \
        "release 模式未委托语义单源 `gk_write_claims.py release`"


def test_arm2_usage_lists_mode_and_no_new_cmd_reg():
    txt = CLI.read_text(encoding="utf-8")
    assert "--release-claim <sid>" in txt, "usage 串未列 `--release-claim <sid>`"
    assert not re.search(r"^_CMD_REG\[release-claim\]", txt, re.M), \
        "不得新注册 `_CMD_REG[release-claim]`（注册表在保护区，走既有命令的模式）"


def test_arm3_cli_release_appends_terminal_row(tmp_path):
    led = os.environ["GK_WRITE_CLAIMS_PATH"]
    sid = "probe-release-sid"
    wt = tmp_path / "wt"
    wt.mkdir()
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"stage": "STAGE_0", "r_phase": "R1", "worktree": "",
                              "gate_data": {}}), encoding="utf-8", newline="\n")
    r = C.append(repo=led, sid=sid, worktree=str(wt), paths=[str(wt)], ttl_s=3600)
    assert r.get("ok"), r
    assert any(c.get("sid") == sid for c in C.live(led)), "前提失败：claim 未 live"
    r2 = subprocess.run(
        ["bash", "-lc",
         'cd "%s" && STATE_FILE="%s" GK_WRITE_CLAIMS_PATH="%s" '
         'bash gatekeeper-cli.sh apply-worktree --release-claim %s'
         % (_wsl(SD), _wsl(st), _wsl(led), sid)],
        capture_output=True, text=True, timeout=120)
    out = [ln for ln in (r2.stdout or "").splitlines() if ln.startswith("{")]
    assert r2.returncode == 0 and out, (r2.returncode, r2.stdout[-400:], r2.stderr[-400:])
    d = json.loads(out[-1])
    assert d.get("ok") and (d.get("record") or {}).get("state") == "released", d
    assert not any(c.get("sid") == sid for c in C.live(led)), "release 后该 sid 仍 live"
    rows = [json.loads(x) for x in Path(led).read_text(encoding="utf-8").splitlines() if x.strip()]
    assert rows[-1].get("sid") == sid and rows[-1].get("state") == "released", rows[-1]
