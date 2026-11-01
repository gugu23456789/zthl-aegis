#!/usr/bin/env python3
"""`scripts/_push_auth_url.sh` 的单测（3 臂）—— 带凭据 push URL 的构造必须是**平台正确**的。

背景（2026-09-28 实测）：`cmd_push confirm` 原实现恒构造 **token-only** 形态
（`https://<token>@host/...`，见 `gatekeeper-cli.sh:6730-6732`）。该形态对 GitHub 系可用
（token 当用户名、空密码），但**对 atomgit/Gitee 系失败**：

    $ git ls-remote https://<TOKEN>@atomgit.com/<user>/<repo>.git
    fatal: could not read Password for 'https://<TOKEN>@atomgit.com': terminal prompts disabled

正解是 **`user:token`** 形态（实测 `https://<user>:<TOKEN>@atomgit.com/...` → rc=0 并回 refs）。
本文件钉住三种形态：① https + 有 user → `user:token`；② https + 无 user → 兼容 token-only；
③ 非 https（ssh/scp）→ **原样透传**（不得注入凭据）。

被测面 = 可直接执行的纯函数助手 `scripts/_push_auth_url.sh`（无副作用；`cmd_push` 同源调用）。
"""
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent / "_push_auth_url.sh"


def _run(*args: str):
    return subprocess.run(["bash", str(SCRIPT), *args],
                          capture_output=True, text=True, timeout=30)


@pytest.fixture(autouse=True)
def _need_bash():
    if shutil.which("bash") is None:
        pytest.skip("本机无 bash（Windows 语义下无法执行该助手）")


def test_atomgit_user_token_form():
    """① atomgit/Gitee 系：给 user ⟹ 构 `https://<user>:<token>@host/...`（本臂在修前 = 红）。"""
    r = _run("https://atomgit.com/<user>/spz-gatekeeper-r-sequence.git", "TOK", "<user>")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == (
        "https://<user>:TOK@atomgit.com/<user>/spz-gatekeeper-r-sequence.git"), r.stdout


def test_github_token_only_when_no_user():
    """② GitHub 系：不给 user ⟹ 保持 token-only 形态（向后兼容）。"""
    r = _run("https://github.com/spz-ecosystem/x.git", "TOK")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "https://TOK@github.com/spz-ecosystem/x.git", r.stdout


def test_non_https_passthrough():
    """③ 非 https（ssh/scp）⟹ 原样透传，**不得**注入凭据。"""
    r = _run("git@github.com:spz-ecosystem/x.git", "TOK", "<user>")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "git@github.com:spz-ecosystem/x.git", r.stdout
