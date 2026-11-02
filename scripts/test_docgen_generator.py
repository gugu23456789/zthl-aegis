"""docgen 生成器（cmd_docgen 内联 python）三项实证缺陷的守卫测试。

2026-09-20 实测（端到端，非读码推测）——三项各自独立可复现：

① `alias = name.replace('cmd_','')` 取自**函数名**而非 `_CMD_REG` 注册键
   ⟹ 含连字符的命令名被印成下划线形态（`cmd_paper_review` 到 `paper_review`，
   而 CLI 实际派发键是 `paper-review`）⟹ 生成文档里 21/48 命令的调用公式不可达。
② 表头解析取 def 前**最后一条** `#` 行作 Purpose ⟹ `# Usage:` 注记行被当 Purpose
   （6 条），真实用途（banner 描述行）被覆盖。
③ 表头循环条件 `while j >= 0 and lines[j].strip() in ('', '') or lines[j].startswith('#')`
   因 `and`/`or` 优先级等价于 `(j>=0 and blank) or startswith('#')`
   ⟹ `j` 走到 -1 后**负索引回绕**到文件尾，把尾部注释当表头
   ⟹ 尾部注释里的 `Refs:` 会被当成该命令的引用。

本文件按**内容锚**从 gatekeeper-cli.sh 抽取生成器源码执行（不复制、不改写），
保证测的是**盘上真代码**；夹具为合成 mini-CLI，故不触碰真实 references/cli-protocol.md。
"""
import os
import subprocess
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
CLI_PATH = SKILL_DIR / "gatekeeper-cli.sh"

_BLOCK_OPEN = "cat > \"$gen_script\" << 'PYEOF'\n"
_BLOCK_CLOSE = "\nPYEOF\n"


def _extract_generator() -> str:
    """按内容锚切出 cmd_docgen 的内联 python（不依赖行号，防漂移）。"""
    src = CLI_PATH.read_text(encoding="utf-8")
    start = src.index(_BLOCK_OPEN) + len(_BLOCK_OPEN)
    end = src.index(_BLOCK_CLOSE, start)
    return src[start:end]


def _run_generator(tmp_path: Path, cli_body: str) -> str:
    """把合成 mini-CLI 当作 gatekeeper-cli.sh 喂给盘上生成器，回 stdout。"""
    gen = tmp_path / "gen.py"
    gen.write_text(_extract_generator(), encoding="utf-8")
    (tmp_path / "gatekeeper-cli.sh").write_text(cli_body, encoding="utf-8")
    env = dict(os.environ, SKILL_DIR=str(tmp_path))
    env.pop("DOCGEN_CHECK", None)
    r = subprocess.run([sys.executable, str(gen)], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    return r.stdout


# 夹具 1：注册键含连字符（`paper-review`），函数名是下划线形态（`cmd_paper_review`）。
# 注记序 = banner / Refs / Usage —— 正是被 ② 覆盖成 Purpose 的形态。
_ALIAS_FIXTURE = """#!/bin/bash
# ---------- paper-review (论文模拟同行评审) ----------
# Refs: references/paper-review.md
# Usage: paper-review --venue aamas|fse
cmd_paper_review() {
  local venue="${1:-}"
  echo "$venue"
}
_CMD_REG[paper-review]="cmd_paper_review|partial|any|state_write"
"""


class TestAliasFromCmdReg:
    """① Usage 行必须用 `_CMD_REG` 的注册键，而非函数名去掉 cmd_ 前缀。"""

    def test_usage_uses_registered_alias(self, tmp_path):
        out = _run_generator(tmp_path, _ALIAS_FIXTURE)
        assert "gatekeeper-cli.sh paper-review " in out, out
        assert "gatekeeper-cli.sh paper_review " not in out, \
            "Usage 行用了函数名派生形态（该命令经文档路径不可达）"

    def test_func_name_still_shown_as_command_column(self, tmp_path):
        """控制：Command 列本就该是函数名，修复不得改变它。"""
        out = _run_generator(tmp_path, _ALIAS_FIXTURE)
        assert "`cmd_paper_review`" in out


class TestPurposeNotPollutedByUsageNote:
    """② `# Usage:` 注记行不得被当 Purpose；真实用途（banner 描述）必须胜出。"""

    def test_usage_note_never_becomes_purpose(self, tmp_path):
        out = _run_generator(tmp_path, _ALIAS_FIXTURE)
        assert "**Purpose**: Usage:" not in out, "Usage 注记行仍被当 Purpose"

    def test_purpose_is_banner_description(self, tmp_path):
        out = _run_generator(tmp_path, _ALIAS_FIXTURE)
        assert "**Purpose**: paper-review (论文模拟同行评审)" in out, out


# 夹具 2：cmd_alpha 之上全是注释（含 shebang）⟹ 触发 j 到 -1；
# 文件**末尾**是注释块 ⟹ 负索引回绕会把尾部注释吃成 cmd_alpha 的表头。
_WRAP_FIXTURE = """#!/bin/bash
# alpha (首行 banner)
# Refs: forward-ref.md
cmd_alpha() {
  local x="${1:-}"
  echo "$x"
}
echo filler-01
echo filler-02
# ---- 尾部注释块（不是 cmd_alpha 的表头）----
# Refs: TAIL_REF_SHOULD_NOT_APPEAR
"""


class TestHeaderWalkNoWraparound:
    """③ 表头采集必须在 j<0 处停下，不得回绕到文件尾。"""

    def test_tail_comment_not_treated_as_header(self, tmp_path):
        out = _run_generator(tmp_path, _WRAP_FIXTURE)
        assert "TAIL_REF_SHOULD_NOT_APPEAR" not in out, \
            "尾部注释被当成 cmd_alpha 的表头（负索引回绕）"

    def test_forward_refs_still_collected(self, tmp_path):
        """控制：正上方的 Refs 仍须被采集。"""
        out = _run_generator(tmp_path, _WRAP_FIXTURE)
        assert "forward-ref.md" in out
