"""test_safetynet_self_guiding.py — 加载安全网·阻断响应自引导（红先，5 臂）。

背景（owner 2026-10-06「实装这个机械处方，这些应该都是加载安全网的一部分，
高性能自动注入自动引导」）：四处机制其实已在（`cmd_help` / `--check-only` / 常量单源
/ `task_too_long` 回显上限），缺的是**阻断即自引导** —— 调用面撞错时响应不注入
`usage` + `limits` + `next`，逼人「记得先 help / 记得 grep 常量」。

实测事故（同轮）：`--plan`（真名 `--plan-file`）无合法集回显；`pipeline_over_wall`
只报墙、不给可执行 `next`（正解 `gk_route_center.py build-state --plan-file`）。

判据（红先，对 HEAD 呈现「a/b 红、c 绿」）：
  arm_a 未知 flag 须回显合法集（`allowed`）⟹ HEAD 无该字段 ⟹ 红
  arm_b 阻断响应须含非空 `next`（可执行出口）⟹ HEAD 无该字段 ⟹ 红
  arm_c `limits` 须回显**运行时真值**（HEAD 绿 —— 守卫臂，防未来写死）

第二切片（本条 family 条目③ 收口，2026-10-06；对当前族基线呈现「d/e 红」）：
  arm_d CLI 四处「unknown arg」响应须含 `next` ⟹ 基线无该字段 ⟹ 红
  arm_e `_dispatch` 未知命令响应须含 `next` ⟹ 基线无该字段 ⟹ 红
        （该 echo 在 `PROTECTED_REGION::gate` 内；owner 2026-10-06 授权行级 WARN+留痕放行）

安全网 R1：只读/构造内存对象；不写真实 state；不 patch 标准库；不读网络。
"""
import inspect
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

SKILL = SCRIPTS.parent


# ─── arm_a：未知 flag 须回显合法集（HEAD 无 allowed ⟹ 红）──────────────────────
def test_arm_a_unknown_flag_echoes_allowed():
    import gk_finding as gf
    src = inspect.getsource(gf.main)
    assert ("\"allowed\"" in src) or ("'allowed'" in src), \
        "未知 flag 分支须回显该子命令合法 flag 集（allowed）"


# ─── arm_b：阻断响应须含非空 next（HEAD 无 next ⟹ 红）────────────────────────
def test_arm_b_block_response_has_next(tmp_path):
    import gk_task_gate as g
    plan = tmp_path / "p.md"
    plan.write_text("# 样本计划\n\n正文。\n", encoding="utf-8")
    r = g.check(task="A" * (g._NT_MAX_TASK_LEN + 50), target_path=str(plan))
    assert r.get("ok") is False, r
    assert "task_too_long" in json.dumps(r, ensure_ascii=False), r
    assert r.get("next"), "阻断响应须给可执行的 next（自动引导）"


# ─── arm_c：limits 须回显运行时真值（HEAD 绿 —— 守卫臂）───────────────────────
def test_arm_c_limits_echo_runtime_value(tmp_path):
    import gk_task_gate as g
    plan = tmp_path / "p2.md"
    plan.write_text("# 样本计划二\n\n正文。\n", encoding="utf-8")
    r = g.check(task="A" * (g._NT_MAX_TASK_LEN + 50), target_path=str(plan))
    assert str(g._NT_MAX_TASK_LEN) in json.dumps(r, ensure_ascii=False), \
        "上限须回显运行时真值（禁写死/禁复制）"


# ─── arm_d：CLI 各「unknown arg」响应须含 next（基线无 ⟹ 红）──────────────────
def test_arm_d_cli_unknown_arg_responses_have_next():
    src = (SKILL / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    lines = [ln for ln in src.splitlines() if "unknown arg: $1" in ln]
    assert len(lines) >= 4, f"应至少 4 处 unknown arg 面（doc-align/paper-review/moa-aggregate/apply-worktree），实测 {len(lines)}"
    # 注：shell 源码里 JSON 键写作转义形态 `\"next\"` ⟹ 判据取 `"next`（含前导引号、不含尾反斜杠）
    missing = [ln.strip()[:70] for ln in lines if '"next' not in ln]
    assert not missing, f"unknown arg 响应缺 next：{missing}"


# ─── arm_e：_dispatch 未知命令响应须含 next（基线无 ⟹ 红；owner 授权保护区）──
def test_arm_e_dispatch_unknown_command_has_next():
    src = (SKILL / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    lines = [ln for ln in src.splitlines() if "Unknown command: $cmd" in ln]
    assert lines, "未找到 _dispatch 未知命令响应（Unknown command: $cmd）"
    missing = [ln.strip()[:70] for ln in lines if '"next' not in ln]
    assert not missing, f"_dispatch 未知命令响应缺 next：{missing}"
