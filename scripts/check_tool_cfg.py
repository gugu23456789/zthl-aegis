#!/usr/bin/env python3
"""check_tool_cfg.py — 工具调用配置一致性自检（2026-08-09）

守护"单一数据源 + 自动派生"机制，防止 subagent 层与 hook 层工具配置失同步：

  A. subagent 层（同层，必须一致）
     - scripts/subagent_runner.py TOOL_REGISTRY == TOOL_REGION_MAP
     - TOOL_REGISTRY == gatekeeper-cli.sh valid_tools
  B. hook 层内部（自动派生关系）
     - pre_tool_hook.py SCOPE_TOOLS 必须由 SCOPE_PATH_MAP 经 frozenset() 派生，
       不允许回退为手写 set 字面量（否则新增只读工具时两处失同步）

挂载点：gatekeeper-cli.sh cmd_self_check（self-check 已存在于 ECO-RESEARCH/ECO-VERIFY/
AUDIT-*/RED-SCOPE 等常驻序列 hint，无新增流程节点/命令，不增加 batch8 拆分负担）。

输出：{"ok":bool,"issues":int,"checks":[{"check":"tool_config","status":"PASS|FAIL","detail":...}]}
"""
import ast
import json
import re
import sys
from pathlib import Path

SKILL = Path(__file__).resolve().parent.parent
RUNNER = SKILL / "scripts" / "subagent_runner.py"
CLI = SKILL / "gatekeeper-cli.sh"
HOOK = SKILL / "scripts" / "pre_tool_hook.py"


def _dict_keys(node):
    """ast.Dict → set of literal keys（TOOL_REGISTRY/TOOL_REGION_MAP/SCOPE_PATH_MAP）"""
    if not isinstance(node, ast.Dict):
        return None
    try:
        return {ast.literal_eval(k) for k in node.keys}
    except Exception:
        return None


def extract(path: Path, name: str) -> set | None:
    """提取模块顶层 Assign/AnnAssign 的目标名 → 集合。找不到返回 None。"""
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name) and t.id == name:
                    v = _dict_keys(node.value)
                    if v is not None:
                        return v
    return None


def check_frozenset_derivation(path: Path) -> tuple[bool, set | None, set | None]:
    """检查 SCOPE_TOOLS 是否由 SCOPE_PATH_MAP 派生。
    返回 (is_derived, declared_set, derived_set)；找不到 → (None, None, None)。"""
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name) and t.id == "SCOPE_TOOLS":
                    v = node.value
                    # 期望形态: SCOPE_TOOLS = frozenset(SCOPE_PATH_MAP)
                    if (
                        isinstance(v, ast.Call)
                        and isinstance(v.func, ast.Name)
                        and v.func.id == "frozenset"
                        and len(v.args) == 1
                        and isinstance(v.args[0], ast.Name)
                        and v.args[0].id == "SCOPE_PATH_MAP"
                    ):
                        return True, None, None
                    # 兼容回退: 手写 set 字面量（应被本检查告警）
                    if isinstance(v, ast.Set):
                        return False, {ast.literal_eval(e) for e in v.elts}, None
    return None, None, None


def main() -> int:
    issues = 0
    detail = []

    # ── A. subagent 层 ──
    reg = extract(RUNNER, "TOOL_REGISTRY")
    region = extract(RUNNER, "TOOL_REGION_MAP")
    if reg is None or region is None:
        issues += 1
        detail.append("subagent_runner: TOOL_REGISTRY/TOOL_REGION_MAP 未找到")
    elif reg != region:
        issues += 1
        detail.append(f"subagent_runner: TOOL_REGISTRY != TOOL_REGION_MAP 差集={sorted(reg ^ region)}")
    else:
        detail.append(f"subagent_runner: TOOL_REGISTRY==TOOL_REGION_MAP ({len(reg)} 项)")

    m = re.search(r'local valid_tools="([^"]+)"', CLI.read_text(encoding="utf-8"))
    valid = set(m.group(1).split(",")) if m else None
    if valid is None:
        issues += 1
        detail.append("gatekeeper-cli.sh: valid_tools 未找到")
    elif reg is not None and reg != valid:
        issues += 1
        detail.append(f"gatekeeper-cli.sh: valid_tools != TOOL_REGISTRY 差集={sorted(reg ^ valid)}")
    else:
        detail.append(f"gatekeeper-cli.sh: valid_tools==TOOL_REGISTRY ({len(valid)} 项)")

    # ── B. hook 层自动派生 ──
    pmap = extract(HOOK, "SCOPE_PATH_MAP")
    derived, declared, _ = check_frozenset_derivation(HOOK)
    if pmap is None or derived is None:
        issues += 1
        detail.append("pre_tool_hook: SCOPE_PATH_MAP/SCOPE_TOOLS 未找到")
    elif not derived:
        issues += 1
        detail.append(
            f"pre_tool_hook: SCOPE_TOOLS 是手写 set {sorted(declared or [])}，"
            f"应改为 frozenset(SCOPE_PATH_MAP) 自动派生（差集={sorted((declared or set()) ^ frozenset(pmap))}）"
        )
    else:
        detail.append(f"pre_tool_hook: SCOPE_TOOLS 由 SCOPE_PATH_MAP 自动派生 ({len(pmap)} 项)")

    # ── C. hook 覆盖盘点（F-REV-98，2026-09-17；用户裁定 ①）──
    # 动机：Gate 0（裸 Task 拦截）逻辑正确、单测全绿，但 2026-09-17 实测
    # `.gatekeeper.hook.log` 中 `event=PreToolUse tool=Task` 匹配数 = 0 ⟹ 门禁**生产不可达**，
    # 而既有 A/B 两项都不查"Trae 到底派发了哪些工具"。本项把「门禁自以为覆盖了什么」变成可对账事实。
    handlers = hook_handler_tools(HOOK)
    observed = hook_observed_tools(_hook_log_path())
    if not handlers:
        issues += 1
        detail.append("pre_tool_hook: 未提取到任何 tool_name 分支（提取器失效？）")
    elif observed is None:
        detail.append(f"hook 覆盖: SKIP — hook 日志不可用/无真实记录，无法对账"
                      f"（{len(handlers)} 个处理分支，待有真实调用后复检）")
    else:
        dead = handlers - observed
        known, unknown = dead & set(_KNOWN_UNREACHABLE), dead - set(_KNOWN_UNREACHABLE)
        if unknown:
            issues += 1
            detail.append(f"hook 覆盖: FAIL — 门禁有处理逻辑但 Trae 从不派发 {sorted(unknown)}"
                          f"（真实观测 {len(observed)} 个工具；新发现须登记 _KNOWN_UNREACHABLE 或删死代码）")
        elif known:
            detail.append(f"hook 覆盖: WARN — 已知死门禁 {sorted(known)}"
                          f"（登记在案；覆盖 {len(observed)}/{len(handlers)}）")
        else:
            detail.append(f"hook 覆盖: PASS — {len(handlers)} 个处理分支全部被真实派发过")

    status = "PASS" if issues == 0 else "FAIL"
    print(json.dumps({
        "ok": issues == 0,
        "issues": issues,
        "checks": [{"check": "tool_config", "status": status, "detail": "; ".join(detail) or "ok"}],
    }, ensure_ascii=False))
    return 0 if issues == 0 else 1


# ── C. hook 覆盖盘点辅助（F-REV-98）──────────────────────────────────────────
# 已知「处理逻辑存在但 Trae 从不派发」的工具 = **死门禁**。必须登记原因，否则本检查 FAIL。
# 2026-09-17 实测（`.gatekeeper.hook.log` 全量扫描，10MB / 5.4 万行）：
#   · `event=PreToolUse tool=Task` 匹配数 = **0**；全部 586 条 `tool=Task` 记录都是
#     `event=?` + pytest 临时 cwd（单测直接调 main() 伪造，非 Trae 派发）。
#   · 其余工具（Read/Grep/Glob/Edit/Write/Delete/RunCommand/WebSearch/
#     CheckCommandStatus/AskUserQuestion/Skill）均有真实 `event=PreToolUse` 记录。
_KNOWN_UNREACHABLE = {
    "Task": "Trae 不为 Task 派发 PreToolUse（实测零记录）⟹ Gate 0 生产不可达；"
            "改由 SKILL.md 硬约束『门禁域禁裸 Task』+ CLI 通道 monitor --subagent 兜底",
}
_HOOK_HANDLER_EQ_RE = re.compile(r'tool_name\s*==\s*["\']([^"\']+)["\']')
_HOOK_HANDLER_IN_RE = re.compile(r"tool_name\s+in\s*[\(\[\{]([^\)\]\}]*)[\)\]\}]")
_HOOK_LOG_INVOKE_RE = re.compile(r"INVOKE event=(PreToolUse) tool=(.*?) cwd=")


def _hook_log_path() -> Path:
    """hook 调用日志路径（GK_HOOK_LOG 可覆盖，供测试注入）。"""
    return Path(__import__("os").environ.get("GK_HOOK_LOG") or (SKILL / ".gatekeeper.hook.log"))


def hook_handler_tools(path: Path) -> set:
    """静态提取 pre_tool_hook.py 中被显式分支处理的工具名。

    只认 `tool_name == "X"` / `tool_name in ("X", ...)` 两种形态（与 hook 真实写点同形）。
    注释里的同形文本也会被计入 = 可接受的**过近似**：多算一个名字只让盘点更保守，不会漏报死门禁。
    """
    src = path.read_text(encoding="utf-8")
    names = set(_HOOK_HANDLER_EQ_RE.findall(src))
    for blob in _HOOK_HANDLER_IN_RE.findall(src):
        names |= set(re.findall(r'["\']([^"\']+)["\']', blob))
    return names


def hook_observed_tools(log: Path) -> set | None:
    """Trae 真实派发过的工具集（**只认 `event=PreToolUse`**）。

    `event=?` 是单测直接调 `main()` 留下的记录（hook_event_name 缺失），不是 Trae 派发，
    必须排除 —— 否则测试伪造的 `tool=Task` 会让死门禁看起来"有覆盖"，正是本次漏检的成因。
    日志不存在/无真实记录 → None（无法对账，报 SKIP 而非 FAIL，避免冷环境误红）。
    """
    if not log.exists():
        return None
    observed: set = set()
    with log.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            m = _HOOK_LOG_INVOKE_RE.search(line)
            if m:
                observed.add(m.group(2))
    return observed or None


if __name__ == "__main__":
    sys.exit(main())
