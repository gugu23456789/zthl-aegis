"""主仓只读保护：运行时派生正则 + 两处 guard 的 fail-closed 臂。

2026-10-31（开源前置）改写：主仓路径不再硬编码（单源 = `gk_main_repo.py` / `.sh`）。
本文件判据随之改为：
  · 派生正则由**运行时解析值**生成（`/` 与 `\\` 两形态等价）；
  · 两处 guard 均引用派生变量，且都有 `-z "$RG"` fail-closed 臂；
  · 主仓内路径 BLOCK、worktree 路径 ALLOW。

执行面纪律（实测教训）：探针脚本一律落盘再 `bash <file>`，不经 `bash -c <argv>`
（反斜杠过 Windows→WSL argv 会被吞）。
"""
import atexit
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parent.parent
CLI_PATH = SKILL_DIR / "gatekeeper-cli.sh"
SH = SKILL_DIR / "scripts" / "gk_main_repo.sh"

_TMP = Path(tempfile.mkdtemp(prefix="gk_mainrepo_guard_"))
atexit.register(lambda: shutil.rmtree(_TMP, ignore_errors=True))


def _run(script: str, tag: str = "probe") -> str:
    p = _TMP / f"{tag}.sh"
    p.write_text("set -u\n" + script, encoding="utf-8", newline="\n")
    r = subprocess.run(["bash", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, f"{r.stderr}\n--- script ---\n{script}"
    return r.stdout.strip()


def _cli() -> str:
    return CLI_PATH.read_text(encoding="utf-8")


def _guard_lines(src: str) -> list:
    """两处**调用点**（2026-11-04 起判定收敛为单源 `_main_repo_hit`）。"""
    return [ln.strip() for ln in src.splitlines()
            if ln.strip().startswith("if _main_repo_hit ")]


def _helper_body(src: str) -> str:
    """抽取 `_main_repo_hit() { ... }` 全文（fail-closed 臂住在函数体内）。"""
    lines = src.splitlines()
    start = next((i for i, l in enumerate(lines)
                  if l.startswith("_main_repo_hit() {")), None)
    assert start is not None, "_main_repo_hit 未定义"
    for i in range(start + 1, len(lines)):
        if lines[i] == "}":
            return "\n".join(lines[start:i + 1])
    raise AssertionError("_main_repo_hit 花括号不配对（抽取失败）")


def _guard_body(cond: str) -> str:
    i = cond.find(" # ")
    if i >= 0:
        cond = cond[:i].rstrip()
    body = cond[3:] if cond.startswith("if ") else cond
    return body[:-len("; then")] if body.endswith("; then") else body


def _resolved(main_repo: str) -> str:
    return (f'export GK_MAIN_REPO="{main_repo}"\n'
            f'. "{SH}"\n'
            '_main_repo_resolve\n')


class TestDerivedRegex:
    def test_derivation_follows_resolved_path(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        out = _run(_resolved(str(repo))
                   + 'printf "%s\\n%s" "$_MAIN_REPO_WSL_RE" "$_MAIN_REPO_WIN_RE"', "derive")
        wsl_re, win_re = out.splitlines()
        assert "pytest-of-root" in wsl_re, wsl_re
        assert "[\\\\/]" in wsl_re and "[\\\\/]" in win_re, \
            f"分隔符未做 [\\\\/] 归一: {wsl_re} | {win_re}"

    def test_no_hardcoded_literal_in_cli(self):
        assert "<workspace>" not in _cli(), "CLI 仍含个人主仓字面量"

    def test_equivalence_on_path_samples(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        rg = _run('RG=$(command -v rg 2>/dev/null || true); printf %s "$RG"\n', "rgpath")
        if not rg:
            pytest.skip("本机（bash 侧）无 rg，样本等价无法判")
        out = _run(
            _resolved(str(repo))
            + 'RG=$(command -v rg 2>/dev/null || true)\n'
            + f'for s in "{repo}" "$(printf %s "{repo}" | sed "s#/#\\\\\\\\#g")"; do\n'
            + '  if printf "%s" "$s" | "$RG" -qi -- "$_MAIN_REPO_WSL_RE"; then echo HIT; else echo MISS; fi\n'
            + "done\n", "samples")
        assert out.split() == ["HIT", "HIT"], out


class TestGuardSites:
    def test_exactly_two_guard_sites(self):
        assert len(_guard_lines(_cli())) == 2

    def test_both_have_rg_missing_arm(self):
        conds = _guard_lines(_cli())
        assert len(conds) == 2, "站点数须为 2，否则本断言会空跑通过"
        body = _helper_body(_cli())
        assert '[ -z "$RG" ]' in body, (
            "单源判定缺 fail-closed 臂（rg 缺位即静默失效）: %r" % body[:200])

    def test_both_fail_closed_when_rg_missing(self, tmp_path):
        repo = tmp_path / "repo"
        (repo / "src").mkdir(parents=True)
        conds = _guard_lines(_cli())
        assert len(conds) == 2
        helper = _helper_body(_cli())
        for i, cond in enumerate(conds):
            script = (_resolved(str(repo)) + helper + "\n"
                      + 'path="%s/src/main.cpp"\n' % repo
                      + "real_path=\"$path\"\nRG=''\n"
                      + f"if {_guard_body(cond)}; then echo BLOCK; else echo ALLOW; fi\n")
            assert _run(script, f"norgg{i}") == "BLOCK", cond

    def test_positive_and_negative_arms(self, tmp_path):
        repo = tmp_path / "repo"
        (repo / "src").mkdir(parents=True)
        wt = str(SKILL_DIR / ".trae" / "worktrees" / "feature" / "x" / "scripts" / "y.py")
        conds = _guard_lines(_cli())
        assert len(conds) == 2
        rg = _run('RG=$(command -v rg 2>/dev/null || true); printf %s "$RG"\n', "rgpath2")
        if not rg:
            pytest.skip("本机（bash 侧）无 rg，正负两臂无法判")
        helper = _helper_body(_cli())
        for i, cond in enumerate(conds):
            for path, expect, tag in ((str(repo / "src" / "main.cpp"), "BLOCK", "pos"),
                                      (wt, "ALLOW", "neg")):
                script = (_resolved(str(repo)) + helper + "\n"
                          + f'path="{path}"\nreal_path="$path"\n'
                          + f'RG="{rg}"\n'
                          + f"if {_guard_body(cond)}; then echo BLOCK; else echo ALLOW; fi\n")
                assert _run(script, f"{tag}{i}") == expect, cond
