# -*- coding: utf-8 -*-
"""红先臂：BARE_PLAN_REFINEMENT 守卫的 sys.path 须走 env（跨平台）。

病灶（2026-11-01 实锤，Windows Git Bash + Windows python 正规链现场）：
  cmd_monitor 的裸角色守卫（L4436-4441）内联 python 用 bash 插值
  `sys.path.insert(0, '$SKILL_DIR/scripts')` —— Git Bash 的 `$SKILL_DIR` 是
  **MSYS 形态** `/c/Users/...`；MSYS 只对 **env 传递**做路径转换（`/c/` → `C:/`），
  对 argv/字符串插值**不转换** ⟹ Windows 原生 python 拿到 `/c/...` 认不出
  ⟹ `ModuleNotFoundError: gk_task_gate` ⟹ `_san_ok=false` ⟹ fail-closed
  `BARE_PLAN_REFINEMENT`（正规链 fan-out 必挂）。WSL 下 `/mnt/c` 合法 ⟹ 从未暴露。
  对照：同文件 5504/9370/9570 等守卫已用 `os.environ['SKILL_DIR']`（env 形态，恒绿）。

判据：BARE 守卫内联块必须经 `os.environ['SKILL_DIR']` 取路径（禁 bash 插值进 python 字符串）。
"""
from pathlib import Path

_CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def test_bare_guard_syspath_uses_env():
    """臂1（红→绿）：BARE 守卫内联 python 的 sys.path 须走 os.environ（跨平台安全）。"""
    src = _CLI.read_text(encoding="utf-8", errors="replace")
    i = src.find("from gk_task_gate import task_in_pipeline")
    assert i >= 0, "BARE 守卫锚点缺失"
    seg = src[max(0, i - 400):i]
    assert "os.environ" in seg and "SKILL_DIR" in seg, (
        "BARE 守卫 sys.path 用 bash 插值 SKILL_DIR（裸美元形态进 python 字符串）⟹ "
        "MSYS 路径 /c/... 不被 Windows python 识别 ⟹ ModuleNotFoundError ⟹ fail-closed "
        "BARE_PLAN_REFINEMENT（跨平台必挂）。须改 env 形态 "
        "os.path.join(os.environ['SKILL_DIR'], 'scripts')。"
    )
    # 判据收紧（2026-11-01 二轮）：只查 **python3 -c 之后**的 python 代码段 ——
    #   env 前缀 `SKILL_DIR="$SKILL_DIR"`（在 python3 -c 之前）是修复本身的正确形态
    #   （bash 展开 + MSYS 对 env 值做 /c/→C:/ 转换），粗查整个 seg 会误伤它。
    #   python 段内的合法引用是 os.environ['SKILL_DIR']（无裸美元），故裸美元插值必为病灶。
    py_seg = seg.split("python3 -c", 1)[-1]
    assert "'$SKILL_DIR" not in py_seg and '"$SKILL_DIR' not in py_seg, (
        "BARE 守卫内联 python 代码段仍含 bash 插值 SKILL_DIR ⟹ MSYS 形态泄漏进 python。"
    )
