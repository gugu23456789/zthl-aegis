#!/usr/bin/env python3
"""红先臂：解释器解析**单源** `scripts/py_resolve.sh`（2026-11-01）。

背景：解释器是**机器属性**——本机 WSL 有隔离 venv、Windows 侧另有同级 venv，公开包在别人
机器上两者都没有。原实现把**某台机器的隔离 venv 绝对路径**写进 CLI / 沙箱 / W2A 脚本 ⟹ 开源即炸
（或静默退化成无 pytest 的 python3 ⟹ 自检 quick 档假绿成 SKIP）。

判据：
  1. `GK_PYTHON` 最高优先（CI / 本机 / 跨 OS 都走它）；
  2. `--need pytest` 只挑**真能 import pytest** 的候选，且候选之间**同级并列**（env、pin、
     仓内 .venv、`GK_PY_GLOBS` 通配、PATH 依次尝试，谁在位用谁）；
  3. 需求不满足时**回落** any 解释器（让 check_tests 显式 SKIP 并给原因，不解析失败炸掉）；
  4. 公开面**零绝对硬编码**：CLI / suagent_sandbox.sh / run_w2a_web_pyramid.sh 不得再出现
     `<绝对路径>/<venv>/bin/python` 之类个人 venv 路径。
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "scripts" / "py_resolve.sh"


def _shim(tmp_path, name, has_pytest, has_subagent=False):
    """伪解释器：`-c 'import sys'` 恒 0；pytest / 子代理依赖由入参决定。"""
    p = tmp_path / name
    p.write_text(
        '#!/bin/sh\n'
        'if [ "$2" = "import pytest" ]; then exit %d; fi\n'
        'if [ "$2" = "import openai, agents, pydantic" ]; then exit %d; fi\n'
        'exit 0\n' % (0 if has_pytest else 1, 0 if has_subagent else 1),
        encoding="utf-8")
    p.chmod(0o755)
    return str(p)


def _isolated_copy(tmp_path):
    """把解析器复制到 tmp（root=tmp）⟹ 不读仓库里的 `.venv` / `_accept_py.local`。"""
    dst = tmp_path / "scripts"
    dst.mkdir()
    shutil.copy2(SRC, dst / "py_resolve.sh")
    return dst / "py_resolve.sh"


def _run(tmp_path, need, env_extra):
    script = _isolated_copy(tmp_path)
    empty = tmp_path / "emptybin"
    empty.mkdir(exist_ok=True)
    env = {"PATH": str(empty), "HOME": str(tmp_path), "GK_PY_GLOBS": ""}
    env.update(env_extra)
    if os.name == "nt":
        # 环境变量不走 MSYS 的参数路径转换：一律给 POSIX 形态（C:/...），
        # 否则 `[ -x "$cand" ]` / 执行在 PATH 受限时行为不一致。
        env = {k: (v.replace("\\", "/") if isinstance(v, str) else v)
               for k, v in env.items()}
    bash = shutil.which("bash") or "/bin/bash"   # 绝对路径：PATH 已清空（避免捡到系统 python3）
    # 必须给 bash 传 POSIX 形态：Windows 反斜杠路径会让 `BASH_SOURCE` 归一到 `.` ⟹
    # `_root` 算错，仓内 venv / 通配候选全丢（2026-11-02 Windows CI 实测）。
    r = subprocess.run([bash, script.as_posix(), need], capture_output=True, text=True,
                       env=env, timeout=30)
    return r.returncode, r.stdout.strip()


def test_env_override_wins(tmp_path):
    shim = _shim(tmp_path, "py-ok", has_pytest=True)
    rc, out = _run(tmp_path, "any", {"GK_PYTHON": shim})
    assert rc == 0 and os.path.normcase(out) == os.path.normcase(shim), (rc, out)


def test_pytest_requirement_picks_peer_candidate(tmp_path):
    """env 给的候选没 pytest ⟹ 继续看 glob 里的同级候选（不是只认第一个）。"""
    bad = _shim(tmp_path, "py-bad", has_pytest=False)
    good = _shim(tmp_path, "py-good", has_pytest=True)
    rc, out = _run(tmp_path, "pytest", {"GK_PYTHON": bad,
                                        "GK_PY_GLOBS": str(tmp_path / "py-good")})
    assert rc == 0 and os.path.normcase(out) == os.path.normcase(good), (rc, out)


def test_pytest_requirement_falls_back_to_any(tmp_path):
    """一个带 pytest 的都没有 ⟹ 回落 any（调用方据此显式 SKIP，而非解析失败）。"""
    bad = _shim(tmp_path, "py-bad", has_pytest=False)
    rc, out = _run(tmp_path, "pytest", {"GK_PYTHON": bad})
    assert rc == 0 and os.path.normcase(out) == os.path.normcase(bad), (rc, out)


def test_no_candidate_exits_nonzero(tmp_path):
    rc, out = _run(tmp_path, "any", {})
    assert rc == 1 and out == "", (rc, out)


# ── 子代理需求门（2026-11-01 owner 裁定 B 方案：解释器与 gitnexus 同侧）────────

def test_subagent_requirement_skips_python_without_deps(tmp_path):
    """`any` 能跑但缺 openai/agents/pydantic ⟹ 继续找同级候选，不捡第一个。"""
    plain = _shim(tmp_path, "py-plain", has_pytest=False)
    full = _shim(tmp_path, "py-full", has_pytest=True, has_subagent=True)
    rc, out = _run(tmp_path, "subagent", {"GK_PYTHON": plain,
                                          "GK_PY_GLOBS": str(full)})
    assert rc == 0 and os.path.normcase(out) == os.path.normcase(full), (rc, out)


def test_subagent_requirement_does_not_fall_back(tmp_path):
    """依赖不全 ⟹ exit 1（调用方 fail-closed），**不**回落 any（否则空壳照旧产生）。"""
    plain = _shim(tmp_path, "py-plain", has_pytest=False)
    rc, out = _run(tmp_path, "subagent", {"GK_PYTHON": plain})
    assert rc == 1 and out == "", (rc, out)


def _windows_path(p):
    """MSYS 形态（`/tmp/...`）→ Windows 形态，供断言比较；非 Windows 原样返回。"""
    if os.name != "nt":
        return p
    bash = shutil.which("bash")
    if not bash:
        return p
    r = subprocess.run([bash, "-c", 'cygpath -w "$1"', "_", p],
                       capture_output=True, text=True)
    return r.stdout.strip() or p


def test_discovers_venv_variant_windows_layout(tmp_path):
    """仓内 `.venv-win/Scripts/python.exe`（Windows 布局）也必须被发现。"""
    winbin = tmp_path / ".venv-win" / "Scripts"
    if os.name == "nt":
        # Windows 不能执行「改名成 .exe 的 shell 脚本」（CI 实测 exit 1），也不宜只复制
        # python.exe（副本目录缺 DLL）。直接建一个真 venv：Scripts/python.exe + pyvenv.cfg
        # 就是生产形态，且不依赖 PATH。
        subprocess.run([sys.executable, "-m", "venv", "--without-pip",
                        str(tmp_path / ".venv-win")],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shim = winbin / "python.exe"
        rc, out = _run(tmp_path, "any", {})
    else:
        winbin.mkdir(parents=True)
        shim = Path(_shim(winbin, "python.exe", has_pytest=False))
        rc, out = _run(tmp_path, "any", {})
    assert rc == 0 and os.path.normcase(_windows_path(out)) == os.path.normcase(str(shim)), (rc, out)


# ── ④ 公开面零绝对硬编码 ─────────────────────────────────────────────────────

@pytest.mark.parametrize("rel", ["gatekeeper-cli.sh",
                                 "scripts/suagent_sandbox.sh",
                                 "scripts/run_w2a_web_pyramid.sh"])
def test_no_personal_venv_path_in_shipped_scripts(rel):
    text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
    assert not re.search(r"/opt/[A-Za-z0-9_.-]+/bin/python", text), \
        "%s 仍写死个人 venv 绝对路径（公开包会炸）" % rel


def test_cli_delegates_to_single_resolver():
    text = (ROOT / "gatekeeper-cli.sh").read_text(encoding="utf-8", errors="replace")
    assert "scripts/py_resolve.sh" in text, "CLI 未委托单源解析器"
    assert "_subagent_py_real" in text


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
