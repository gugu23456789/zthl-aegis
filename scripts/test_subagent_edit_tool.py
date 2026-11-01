"""F7 基座：runner edit 工具接线（red-first）。

判据（4 臂）：
  ① `edit` 必须在 `TOOL_REGISTRY`（否则 `validate_tool_names` fail-loud 拒绝下发）；
  ② `edit` **不得**出现在只读档位 tier 1-4（最小权限：档位阶梯仍是纯读面）；
  ③ fix 档位清单 `_FIX_TIER_TOOLS` 必须含 `edit`（唯一位移面）；
  ④ CLI `valid_tools` 必须含 `edit`（否则 `monitor --subagent --tools edit` 在派发前 return 1）。

另：`TOOL_REGISTRY == TOOL_REGION_MAP` 键集一致由 `test_subagent_gitnexus_contract` /
`check_tool_cfg` 守护 —— 故 `edit` 必须同时补 `TOOL_REGION_MAP`。
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import subagent_runner as sr

SK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_edit_registered_in_tool_registry():
    assert "edit" in sr.TOOL_REGISTRY


def test_edit_not_in_readonly_tier_tools():
    """只读档位不得含 edit（最小权限）。"""
    for t in (1, 2, 3, 4):
        assert "edit" not in sr.SUBA_TIERS[t]["tools"].split(",")


def test_fix_tier_tools_contains_edit():
    assert "edit" in sr._FIX_TIER_TOOLS.split(",")


def test_cli_valid_tools_contains_edit():
    txt = open(os.path.join(SK, "gatekeeper-cli.sh"), encoding="utf-8").read()
    m = re.search(r'^    local valid_tools="([^"]+)"', txt, re.M)
    assert m and "edit" in m.group(1).split(",")


def _cmd_seg(fn_name):
    """取 `gatekeeper-cli.sh` 中 `<fn_name>() {…}` 的**完整函数体**（界 = 下一个顶层函数定义）。

    原实现用固定 `span=12000` 字符窗口。`cmd_apply_worktree` 在 ECC-591BA1B918B4/ECC-6C0742C3BC90
    接线时补入 `_fix_tools` / `--role coder`（L7194/L7205）后**尾部超出窗口** ⟹ 同文件另两臂
    （`test_code_fix_next_cmd_carries_role_coder` / `test_code_fix_next_cmd_tools_equal_fix_tier_tools`）
    断言看不到尾段，**假红**。改以「下一个顶层定义」为界，与函数规模解耦。
    """
    txt = open(os.path.join(SK, "gatekeeper-cli.sh"), encoding="utf-8").read()
    i = txt.index(fn_name + "()")
    body_from = i + len(fn_name) + 2
    m = re.search(r"(?m)^[A-Za-z_][A-Za-z0-9_]*\(\)\s*\{", txt[body_from:])
    return txt[i:body_from + m.start()] if m else txt[i:]


def test_code_fix_next_cmd_tools_equal_fix_tier_tools():
    """ECC-591BA1B918B4（2026-09-23）— `apply-worktree --code-fix` 回显的 next 串下发的工具面
    必须 = fix 档位全集（`_FIX_TIER_TOOLS`），**不得**写死 `--tools edit`。

    现场：原串只给 `edit` ⟹ agent 无 read/search 无法定位 `_log_block()` 内容（做 old_str 匹配）、
    无 state 看配额 ⟹ 实测 subagent `turns=1`、自述「本次审查无读/搜工具（仅 edit）」空手而归
    （T10 Step 3 派发失败）。CLI 是 bash、无法 import python 常量 ⟹ 以机检比对两处**同串**防漂移。
    """
    seg = _cmd_seg("cmd_apply_worktree")
    m = re.search(r'local _fix_tools="([^"]+)"', seg)
    assert m, "cmd_apply_worktree 须定义 _fix_tools（禁写死 --tools edit）"
    assert m.group(1) == sr._FIX_TIER_TOOLS, (
        "CLI _fix_tools 与 runner _FIX_TIER_TOOLS 漂移:\n  CLI=%s\n  runner=%s"
        % (m.group(1), sr._FIX_TIER_TOOLS))
    assert "--tools $_fix_tools" in seg, "next 串须用 $_fix_tools 下发"


def test_edit_tier_dispatch_prefers_wsl_python():
    """2026-10-14（owner 裁定）— subagent **默认解释器** = 隔离 venv（原写死 WSL `/opt/spz-py312`）。

    沿革：原（ECC-6C0742C3BC90，2026-09-23）只对 `--tools` 含 `edit` 优先 WSL（`edit_gk` 走
    `os.path.realpath()` 解析 worktree 路径，Windows 语义把 `/mnt/c/...` 解析成不存在路径 ⟹
    `guard-edit` 恒拒）。后默认档整体切到隔离 venv（免受全局 `site-packages` 升级波及）。
    **2026-11-01 修正**：隔离 venv 是**机器属性**，不能写进公开源码（他机无此路径必炸，
    且 Windows 侧同级 venv 无法并列）⟹ 改由 `scripts/py_resolve.sh` 发现式解析：
    env → 本机 pin → 仓内 .venv → 通配 → PATH。本臂改为守「委托单源 + 无绝对硬编码」。
    """
    seg = _cmd_seg("cmd_monitor")
    assert "py_resolve.sh" in seg, "默认档须委托 scripts/py_resolve.sh（解释器单源）"
    assert "/opt/spz-py312" not in seg, "解释器不得写死个人 venv 绝对路径（公开包会炸）"


def test_coder_role_can_read_fix_landing_regions():
    """region 面（ECC-591BA1B918B4 配套，2026-09-23）— fix 档位角色 `coder` 必须能**实读**落点代码。

    **行为臂**（直接调 `check_scope_access`，非结构断言）：实测 `--code-fix` 不带角色 ⟹ 落
    `default`（`ROLE_ALLOWED_REGIONS["default"] == ["evidence"]`）⟹ agent 的 read 全被
    `scope denied: gate/transition not in effective_regions={'evidence'}` 拒（6 条
    access_violations），拿不到待改函数逐字原文、无法构造 `old_str` ⟹ 零落刀。
    约束本质：「能落刀的 agent 必须能读它要改的代码」（落点必在 gate/transition 段）。
    """
    assert sr.ROLE_ALLOWED_REGIONS["coder"] == ["evidence", "transition", "gate"]
    assert sr.ROLE_TOOLS["coder"] == sr._FIX_TIER_TOOLS.split(","), \
        "coder 的工具面单一事实源 = _FIX_TIER_TOOLS（逗号分隔串，须 split）"
    # 三层交集 = TOOL_REGION_MAP[tool] ∩ ROLE_ALLOWED_REGIONS[role]（见 check_scope_access）：
    #   · **gate 段原文**（`gatekeeper-cli.sh`，F3a 落点）→ `read` 可及（read ∩ coder ⊇ gate）
    ok1, r1 = sr.check_scope_access("read", "gatekeeper-cli.sh", "coder")
    assert ok1, r1
    #   · **transition 段**（幂等/状态机测试）→ `read`/`read_repo` 的 TOOL_REGION_MAP **不含
    #     transition**（二者 = [evidence, constants, gate]）⟹ 须走 `gitnexus`/`search`
    #     （含 transition）。此为既有设计选择（非缺陷），本臂只钉「coder 对该段可达」。
    ok2, r2 = sr.check_scope_access(
        "gitnexus", "scripts/test_gk_state_write_single_entry.py", "coder")
    assert ok2, r2
    # 负臂（最小权限不退化）：default 仍读不到 gate 段
    ok3, _ = sr.check_scope_access("read", "gatekeeper-cli.sh", "default")
    assert not ok3


def test_code_fix_next_cmd_carries_role_coder():
    """派发串须带 `--role coder` —— 否则落 default ⟹ 读不到 gate/transition 段落点代码。"""
    assert "--role coder" in _cmd_seg("cmd_apply_worktree")
