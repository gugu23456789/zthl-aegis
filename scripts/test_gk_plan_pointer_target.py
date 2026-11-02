"""F-3 收口：plan 指针「命令→计划」对账（red-first，`ECC-D44630007AE9`）。

落刀面（`gatekeeper-cli.sh` 顶层 plan 指针块）：
  · **顶部派生** `GK_CMD_TARGET_PLAN`（env 显式优先 / `plan-refinement`·`plan-lint` 从位置参派生，
    口径 = `basename <plan>.md`，与 `discover` 写指针同源）；
  · 指针块**默认对账**：显式目标 ≠ 指针 `plan` ⟹ **不跟随**（防跨计划劫持；相符/无声明 ⟹ 零回归跟随）；
  · `GK_PLAN_POINTER_STRICT=1` 保留（无声明时进一步收紧）。

红先对照：HEAD 版全仓无 `GK_CMD_TARGET_PLAN` ⟹ 臂 c1/c2/c3 在 HEAD 上必红。
`c4`（STRICT 保留）在 HEAD 已绿 ⟹ **不属红先臂**，作回归护栏，排除在 `-k` 之外。
"""
import os

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gatekeeper-cli.sh")
_SRC_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "gk_state_route.py")


def _src():
    return open(_SRC, encoding="utf-8").read()


def _src_py():
    return open(_SRC_PY, encoding="utf-8").read()


def test_c1_cmd_target_plan_declared():
    """臂 c1：`GK_CMD_TARGET_PLAN` 透传渠道须在场（派生侧 + 对账侧，≥3 处）。"""
    s = _src()
    assert s.count("GK_CMD_TARGET_PLAN") >= 3, \
        "`GK_CMD_TARGET_PLAN` 未实现/未接线（「命令→计划」透传渠道缺失）"


def test_c2_mismatch_blocks_follow():
    """臂 c2（③ 单源后重定位）：显式目标 ≠ 指针计划 ⟹ 不跟随（**默认对账**，无需 STRICT）。

    ③（`ECC-1EC0E0732F0D`）把判定体移入 `gk_state_route.select_plan_pointer`
    （`reason=cmd_target_mismatch`），bash 启动块零判定、仅按返回 `reason` 回放 WARN
    ⟹ 本臂锚点由「bash 内联 `!=`」改为「单源实现 ∧ bash 消费该 reason」（行为不变量不变）。
    """
    assert "cmd_target_mismatch" in _src_py(), \
        "缺「显式目标 ≠ 指针计划」对账 ⟹ 跨计划劫持未被默认拦截（单源判定侧）"
    assert "cmd_target_mismatch)" in _src(), \
        "bash 启动块未消费单源判定的 cmd_target_mismatch ⟹ 解绑/告警通道断"


def test_c3_derives_from_known_commands():
    """臂 c3：`plan-refinement` / `plan-lint` 的位置参须被派生为 `GK_CMD_TARGET_PLAN`。"""
    s = _src()
    assert "plan-refinement|plan-lint)" in s, \
        "未对已知携带计划位置参的命令派生目标计划"
    assert 'basename "${2}" .md' in s, \
        "派生口径须与 discover 写指针同源（`basename <plan>.md`）"


def test_c4_strict_still_available():
    """回归护栏（HEAD 已绿，非红先臂 · ③ 单源后重定位）：`GK_PLAN_POINTER_STRICT` 收窄开关须保留。

    ③（`ECC-1EC0E0732F0D`）后开关由**判定侧**读（`gk_route_center.resolve_state` 的
    `strict=` 入参 ← env），bash 仅消费返回 `reason=strict` ⟹ 锚点改钉「判定侧读 env ∧ bash 消费」。
    """
    facade = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                               "scripts", "gk_route_center.py"), encoding="utf-8").read()
    assert "GK_PLAN_POINTER_STRICT" in facade, "STRICT 收窄开关被误删（单源判定侧未读 env）"
    assert "strict)" in _src(), "bash 启动块未消费单源 strict 判定（解绑通道断）"


def test_c5_pointer_write_is_atomic():
    """臂 c5（红先 · 并发写）：指针写入须**原子**（tmp + rename）。

    现值 `echo "{...}" > "$_PLAN_POINTER_OWN"` 是**非原子重定向** ⟹ 并发 `discover`
    （多会话 / sid-less 同写一路径）可致读者见**半行** ⟹ `json.load` 失败（静默回落默认 state）
    或读到损坏绑定。先例 = `.gatekeeper.session`（`pre_tool_hook._write_session_marker` 显式
    `tmp + os.replace`，注释点明「原子 ⟹ 读者不会见到半行」）。
    """
    s = _src()
    assert "${_PLAN_POINTER_OWN}.tmp" in s, \
        "指针写入仍为非原子重定向（无 tmp+rename）⟹ 并发写者可致半行/损坏指针"
