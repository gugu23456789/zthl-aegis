#!/usr/bin/env python3
"""ECC-774A4BD638FB 红先臂：链接 worktree 的 gitnexus 目录归一。

病根：链接 worktree 的 `.git` 是**文件**（内容 `gitdir: /mnt/c/...`）；gitnexus（Windows node
+ Windows git）读该 gitdir 失败 ⟹ 报 `Not a git repository` ⟹ `status` 恒 unavailable ⟹
plan-refinement 的 `BASELINE_STALE` 结构性拦停（质询在 worktree 内被硬拦）。

修法：`_gx_worktree_main_root <dir>` —— 若 `<dir>/.git` 是文件，归一到主仓根
（`dirname(git -C <dir> rev-parse --git-common-dir)`），否则原样返回（零回归）。

本臂断言：
  ① worktree 目录 → 归一为主仓根（realpath 相等）
  ② 普通仓库目录 → 原样返回（不误伤）
  ③ 非仓库目录 → 原样返回
"""
import os
import re
import subprocess
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _extract_fn(name: str) -> str:
    src = CLI.read_text(encoding="utf-8")
    m = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}", src, re.S | re.M)
    assert m, f"函数 {name} 未在 gatekeeper-cli.sh 中定义（红先：实现前必失败）"
    return m.group(0)


def _call(fn_src: str, arg: str) -> str:
    script = fn_src + f'\n_gx_worktree_main_root "{arg}"\n'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, f"bash 退出码 {r.returncode}: {r.stderr}"
    return r.stdout.strip()


def _git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), *args], check=True,
                   capture_output=True, text=True)


def _mk_repo(tmp: Path) -> Path:
    main = tmp / "main"
    main.mkdir()
    subprocess.run(["git", "init", "-q", str(main)], check=True,
                   capture_output=True, text=True)
    (main / "a.txt").write_text("x", encoding="utf-8")
    _git(main, "add", "-A")
    subprocess.run(["git", "-C", str(main), "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-qm", "init"], check=True, capture_output=True, text=True)
    return main


def test_worktree_normalizes_to_main_root(tmp_path):
    fn = _extract_fn("_gx_worktree_main_root")
    main = _mk_repo(tmp_path)
    wt = tmp_path / "wt"
    subprocess.run(["git", "-C", str(main), "worktree", "add", "-q", str(wt)], check=True,
                   capture_output=True, text=True)
    assert (wt / ".git").is_file(), "前置：worktree 的 .git 应为文件"
    out = _call(fn, str(wt))
    assert os.path.realpath(out) == os.path.realpath(str(main)), \
        f"worktree 未归一主仓根：{out!r} != {main!r}"


def test_plain_repo_passthrough(tmp_path):
    fn = _extract_fn("_gx_worktree_main_root")
    main = _mk_repo(tmp_path)
    assert (main / ".git").is_dir(), "前置：普通仓库的 .git 应为目录"
    out = _call(fn, str(main))
    assert os.path.realpath(out) == os.path.realpath(str(main)), \
        f"普通仓库被误改：{out!r}"


def test_non_repo_passthrough(tmp_path):
    fn = _extract_fn("_gx_worktree_main_root")
    plain = tmp_path / "plain"
    plain.mkdir()
    out = _call(fn, str(plain))
    assert os.path.realpath(out) == os.path.realpath(str(plain)), \
        f"非仓库目录被误改：{out!r}"


if __name__ == "__main__":
    import tempfile
    failures = 0
    for fn_obj in (test_worktree_normalizes_to_main_root,
                   test_plain_repo_passthrough,
                   test_non_repo_passthrough):
        with tempfile.TemporaryDirectory() as td:
            try:
                fn_obj(Path(td))
                print(f"PASS {fn_obj.__name__}")
            except Exception as e:  # noqa: BLE001
                failures += 1
                print(f"FAIL {fn_obj.__name__}: {e}")
    raise SystemExit(1 if failures else 0)
