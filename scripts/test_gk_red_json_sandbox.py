#!/usr/bin/env python3
"""test_gk_red_json_sandbox.py — 红队面：JSON 注入打击 + 沙箱防 OOM（2026-11-09）。

用户令：「红队需要打击这一堆 json 和尝试在沙箱里让系统 oom」。本文件是**确定性红队臂**：
  · 红队 16 站必须可规划启动（`gk_chain run red --dry-run`）；
  · `gk_json.build` 对敌意值（Windows 反斜杠/引号/换行/超长）必须产出**可解析 JSON**；
  · `gk_sandbox` 必须**真实生效**（enforced=True），内存超限**被拦住**且宿主存活；
  · 超时闸必须整树/进程被杀并返回 timed_out。

不做的事：不真的把宿主内存打爆（内存上限设在 128–256MB，只验证**边界控制**生效）。
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import gk_json as gj  # noqa: E402
import gk_sandbox as sb  # noqa: E402


# ── 1. 红队 16 站可启动（只规划，不落 state）──────────────────────────────
def test_red_chain_16_stations_dry_run_starts():
    p = subprocess.run([sys.executable, "scripts/gk_chain.py", "run", "red", "--dry-run"],
                       cwd=str(ROOT), capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr[-400:]
    d = json.loads(p.stdout.strip().splitlines()[-1])
    assert d["ok"] is True and d["total"] == 16
    names = [s["node"] for s in d["plan"]]
    assert names[0] == "RED-SCOPE" and names[-1] == "RED-AIG"
    assert all(n.startswith("RED-") for n in names)


# ── 2. JSON 注入打击：敌意值必须可解析（转义单一事实源）────────────────────
@pytest.mark.parametrize("value", [
    r"<home>\.gatekeeper.state",          # \U 非法转义的经典炸弹
    'he said "hi" and \\ and \t',              # 引号 + 反斜杠
    "line1\nline2\r\nline3",                   # 换行
    "</script>&<script>alert(1)</script>",     # HTML 注入形态
    "x" * 20000,                               # 超长（拒绝放大）
    "中文/emoji🙂/\u0000-like?skip",            # 非 ASCII
])
def test_json_build_survives_hostile_values(value):
    out = gj.cmd_build([("k", value)])
    s = json.dumps(out["value"], ensure_ascii=False)
    assert json.loads(s)["k"] == value, "敌意值经 build 后必须可 JSON 往返"


def test_json_build_raw_fragment_rejects_garbage():
    with pytest.raises(ValueError):
        gj.cmd_build([("k:", "{not-json}")])


# ── 3. 沙箱完整性：enforced + 内存边界 + 超时 ───────────────────────────────
def test_sandbox_is_enforceable_and_runs():
    out = sb.run([sys.executable, "-c", "print('ok')"], mem_mb=512, timeout_s=20)
    assert out["ok"] is True and out["enforced"] is True, out
    assert out["rc"] == 0


def test_sandbox_blocks_memory_exhaustion():
    """在 128MB 上限里申请 300MB：必须失败（MemoryError/被杀），宿主必须存活。"""
    code = "b=[]\nfor i in range(3):\n b.append(bytearray(100*1024*1024))\nprint('never')"
    out = sb.run([sys.executable, "-c", code], mem_mb=128, timeout_s=30)
    assert out["ok"] is True and out["enforced"] is True, out
    assert out["rc"] != 0, "超限分配不得成功退出（沙箱边界失效）"
    # 宿主存活 = 还能再起一个受限进程
    again = sb.run([sys.executable, "-c", "print('alive')"], mem_mb=512, timeout_s=20)
    assert again["ok"] is True and again["rc"] == 0


def test_sandbox_timeout_kills_child():
    out = sb.run([sys.executable, "-c", "import time; time.sleep(30)"],
                 mem_mb=512, timeout_s=1)
    assert out["ok"] is True and out["timed_out"] is True, out
    assert out["rc"] not in (0, None)


def test_sandbox_cannot_be_disabled_silently():
    """`fail_closed` 语义：无法建限时不得静默放行（本机可建限 ⟹ 只断言常态）。"""
    out = sb.run([sys.executable, "-c", "print(1)"], mem_mb=512, timeout_s=10,
                 fail_closed=True)
    assert out["enforced"] is True
