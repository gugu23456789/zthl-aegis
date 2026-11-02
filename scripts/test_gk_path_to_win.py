# -*- coding: utf-8 -*-
"""红先臂：路径形态转换单一事实源 `_gx_to_win_path`（纯 bash，零外部依赖）。

病灶（2026-11-01 实锤，MSYS 跨平台 bug 家族）：CLI 里 13 处 `wslpath -w` 把路径转
Windows 形态。`wslpath` 只在 WSL 存在 —— Git Bash(MSYS) 下 `command -v wslpath` 恒空
⟹ `wslpath -w ... 2>/dev/null || echo ""` 产出空串 ⟹ fail-loud 拦停：
  · L2073 `_user_home_win`     → 空串 ⟹ identity cache 路径拼接失败
  · L2081 `_js_win`            → 空串 ⟹ `WARN[gx-env]: 解析 gitnexus 入口失败` ⟹ 图能力不可用
  · L2187 `_win_gx_js`         → 空串 ⟹ `unavailable: gitnexus 入口解析失败` ⟹ BASELINE_STALE 拦停质询
其余 9 处 fallback 为 `|| echo "$path"`（原样透传）—— Git Bash 下路径本就是 Windows 形态，
透传正确，但同一语义散在 13 处手写、形态判断不一致（`/mnt/*)` case 守卫 vs 无守卫）。

正解 = 纯 bash 单一事实源（不引 wslpath/cygpath 外部依赖，也不新增 inline_python bomb）：
  · Windows 形态 `C:\\x` / `C:/x` → 原样（已在目标形态）
  · WSL 形态     `/mnt/c/x`      → `C:/x`
  · MSYS  形态   `/c/x`          → `C:/x`
  · 其它（纯 POSIX `/home/x`）   → 原样（无法转换，交调用方 fail-loud）

臂1（行为级·红→绿）：三形态转换正确性（bash 子进程 eval 真实函数体）。
臂2（行为级·防放水）：纯 POSIX 路径原样返回，不臆造盘符。
臂3（源码级）：函数体禁调 wslpath/cygpath（外部依赖 = 跨平台分叉根源）。
臂4（源码级·防回归）：gatekeeper-cli.sh 禁残留裸 `wslpath -w`。
"""
import re
import subprocess
import sys
from pathlib import Path

_CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"
_BASH = "bash"


def _func_body() -> str:
    src = _CLI.read_text(encoding="utf-8", errors="replace")
    i = src.find("_gx_to_win_path()")
    assert i >= 0, "路径转换单一事实源 _gx_to_win_path 缺失"
    # 函数体到下一个顶格 `}` 为止
    j = src.find("\n}\n", i)
    assert j > i, "函数体未闭合"
    return src[i:j + 3]


def _run(args: list) -> str:
    """在 bash 子进程里 eval 真实函数体后调用（行为级，非复制实现）。

    ⚠ 传参方式（2026-11-01 三个实测坑，均已避掉）：
      ① 函数体是**多行字符串**，作**单个 argv 元素**传 `bash -c` 会被 MSYS 的 argv 换行
        转换破坏（实测：注释里的反引号内容被当命令执行 `/mnt/c: Is a directory`）；
      ② 写临时文件再传路径也不行 —— tempfile 给的是 **Windows 反斜杠路径**
        `<home>`，MSYS bash 不认（rc=127 No such file）；
      ③ `bash -s` + text-mode stdin 仍炸 —— **Python 在 Windows 下 text-mode 管道会把
        `\n` 翻译成 `\r\n`** ⟹ bash 见 `$'{\\r'` 语法错。故用 **bytes 模式**传 input
        （不开 text mode，彻底绕开 newline 翻译），输出再 decode。
    """
    body = _func_body()
    quoted = " ".join("'" + a.replace("'", "'\\''") + "'" for a in args)
    script = (body + "\n_gx_to_win_path " + quoted + "\n").encode("utf-8")
    r = subprocess.run([_BASH, "-s"], input=script, capture_output=True)
    assert r.returncode == 0, (
        f"rc={r.returncode} stderr={r.stderr.decode('utf-8', 'replace')[:200]}"
    )
    return r.stdout.decode("utf-8")


def test_wsl_form_converts_to_windows():
    """臂1a：WSL 形态 /mnt/c/... → C:/..."""
    assert _run(["<home>/.trae/skills/x"]) == "<home>/.trae/skills/x"


def test_msys_form_converts_to_windows():
    """臂1b：MSYS 形态 /c/... → C:/...（与 WSL 形态同结果 ⟹ 归一后同一棵树）。"""
    assert _run(["/c/Users/HP/.trae/skills/x"]) == "<home>/.trae/skills/x"


def test_windows_form_passthrough():
    """臂1c：已是 Windows 形态 → 原样（正反斜杠都不改写，避免破坏下游拼接）。"""
    assert _run(["<home>/x"]) == "<home>/x"
    assert _run(["<home>\\x"]) == "<home>\\x"


def test_posix_path_untouched():
    """臂2（防放水）：纯 POSIX 路径不臆造盘符，原样返回。"""
    assert _run(["/home/linuxmmlsh/.venv/bin/python"]) == "/home/linuxmmlsh/.venv/bin/python"


def test_empty_input_safe():
    """臂2b：空输入安全（set -u 下不炸）。"""
    assert _run([""]) == ""


def test_no_external_path_tool():
    """臂3：函数体禁调 wslpath/cygpath —— 外部依赖正是跨平台分叉根源。"""
    body = _func_body()
    assert "wslpath" not in body, "函数体仍调 wslpath ⟹ MSYS 下恒空，回归原病灶"
    assert "cygpath" not in body, "函数体调 cygpath ⟹ 引入 MSYS 专属依赖，WSL 下不可用"


def test_no_bare_wslpath_left():
    """臂4（防回归）：全文件禁残留裸 `wslpath -w`（含注释外的实际调用）。"""
    src = _CLI.read_text(encoding="utf-8", errors="replace")
    bare = []
    for n, line in enumerate(src.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue                      # 注释允许（历史说明）
        if re.search(r"(?<![_A-Za-z])wslpath\s+-w", line):
            bare.append(n)
    assert not bare, (
        f"gatekeeper-cli.sh 仍有裸 wslpath -w 调用（行 {bare}）⟹ Git Bash 下恒空 ⟹ "
        "BASELINE_STALE/图能力不可用复燃。须改用 _gx_to_win_path。"
    )
