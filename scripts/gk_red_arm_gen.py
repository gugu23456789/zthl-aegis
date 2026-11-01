#!/usr/bin/env python3
"""gk_red_arm_gen.py — 红先测试模版**自动填空**发生器（2026-09-23，用户裁定「扩展红先测试模版」）。

定位：把「写红先臂」从**手写**变成**填空**。模版**单一事实源** = `references/red-arm-templates.json`
（本模块**不内建第二份模版名清单**，只读表；漂移由 `gk_doc_align.py` 的 `red_arm_templates`
检查项守护）。调用方（主 agent / 窄任务模板）给出 `id` + 占位符值，本器返回可粘贴的测试片段。

为什么需要（本会话实测的三类浪费）：
  · **形态重复**：5 类臂（源码缺席 / 函数边界切片 / API 缺席 / 功能 rc / 负臂）每族各手写一遍，
    措辞与骨架漂移，且「固定字符窗口」假红在 `_code_fix_seg()`/`_state_patch_seg()` 上重复踩了两次；
  · **对照缺失**：臂写出后常忘「HEAD 计数 ⟹ 必红」对照行，导致**真空通过/假红**无法判；
  · **负臂缺席**：只写正臂 = 没测边界（用户纪律：不允许偷工减料）。

用法（确定性、0 API）：
  python3 scripts/gk_red_arm_gen.py list
  python3 scripts/gk_red_arm_gen.py show <id>
  python3 scripts/gk_red_arm_gen.py render <id> k=v [k=v ...]

契约（fail-loud，不静默）：
  · 未知 id / 缺占位符 / 多余键 → `{"ok":false,"error":...}` exit 2；
  · 渲染结果**必须**已无 `{...}` 残留（残留 → 拒绝输出，防把未填模板当成品交付）。
"""
import json
import os
import re
import sys
from pathlib import Path

_SKILL_DIR = Path(__file__).resolve().parent.parent
_REGISTRY = _SKILL_DIR / "references" / "red-arm-templates.json"
_PH_RE = re.compile(r"\{[A-Za-z0-9_]+\}")


def load_registry(path: str = "") -> dict:
    """读模版登记表（单一事实源）。失败 → 抛 ValueError（调用方 fail-loud）。"""
    p = Path(path) if path else _REGISTRY
    if not p.is_file():
        raise ValueError("模版登记表缺失: " + str(p))
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data.get("templates"), list) or not data["templates"]:
        raise ValueError("模版登记表结构非法（缺 templates）: " + str(p))
    return data


def template_ids(reg: dict = None) -> list:
    """全部模版 id（**唯一来源 = 登记表**；禁在别处再列一份名单）。"""
    reg = reg if reg is not None else load_registry()
    return [str(t.get("id") or "") for t in reg["templates"]]


def get_template(tid: str, reg: dict = None) -> dict:
    reg = reg if reg is not None else load_registry()
    for t in reg["templates"]:
        if str(t.get("id") or "") == tid:
            return t
    raise ValueError("未知模版 id: %r（已知: %s）" % (tid, ", ".join(template_ids(reg))))


def finding_test_file(finding: str, reg: dict = None) -> str:
    """该 finding 的**红先臂测试文件**（登记表 `finding_arms[].test_file`；未登记 ⟹ `""`）。

    单一事实源 = `references/red-arm-templates.json::finding_arms`（**禁第二份 finding→测试文件映射**）。
    这是 2026-09-30 设计 A 的取数口：`gk_agent_family.resolve` 据此把「该 finding 的红先臂文件」
    并入 coder 的有效 `allowed_paths`（**消除「族定义每加一个 finding 就要手抄测试文件」的流程摩擦**）。

    **未登记不是错误**：返回 `""`（调用方据此跳过并入，不阻断派发）；只有**登记表本身不可读**
    才抛（fail-loud）。
    """
    reg = reg if reg is not None else load_registry()
    for a in (reg.get("finding_arms") or []):
        if str((a or {}).get("finding") or "") == str(finding or ""):
            return str((a or {}).get("test_file") or "")
    return ""


def render(tid: str, values: dict, reg: dict = None) -> str:
    """渲染模版体：占位符**全量替换**；残留/多余键 → fail-loud（防半成品交付）。"""
    t = get_template(tid, reg)
    body = str(t.get("body") or "")
    need = set(_PH_RE.findall(body))
    declared = set(str(x) for x in (t.get("placeholders") or []))
    if need != declared:
        raise ValueError("模版 %s 自洽性破（body 占位符 %s ≠ 声明 %s）"
                         % (tid, sorted(need), sorted(declared)))
    # 调用方按**裸名**传值（`target=A`），登记表内是带花括号形态（`{target}`）⟹ 归一后比对。
    need_bare = {p.strip("{}") for p in need}
    missing = sorted(need_bare - set(values))
    if missing:
        raise ValueError("缺占位符: %s（模版 %s）" % (", ".join(missing), tid))
    extra = sorted(set(values) - need_bare)
    if extra:
        raise ValueError("多余键: %s（模版 %s 不需要）" % (", ".join(extra), tid))
    out = body
    for k, v in values.items():
        out = out.replace("{%s}" % k, str(v))
    residual = _PH_RE.findall(out)
    if residual:
        raise ValueError("渲染后仍有未填占位符: %s" % sorted(set(residual)))
    return out


def main(argv: list) -> int:
    cmd = argv[0] if argv else "list"
    try:
        if cmd == "list":
            reg = load_registry()
            print(json.dumps({"ok": True, "ids": template_ids(reg),
                              "version": reg.get("version")}, ensure_ascii=False))
            return 0
        if cmd == "show" and len(argv) >= 2:
            t = get_template(argv[1])
            print(json.dumps({"ok": True, "template": t}, ensure_ascii=False, indent=1))
            return 0
        if cmd == "render" and len(argv) >= 2:
            vals = {}
            for kv in argv[2:]:
                if "=" not in kv:
                    raise ValueError("render 参数须为 k=v，收到: %r" % kv)
                k, v = kv.split("=", 1)
                vals[k.strip()] = v
            print(json.dumps({"ok": True, "id": argv[1],
                              "code": render(argv[1], vals)}, ensure_ascii=False))
            return 0
        if cmd == "test-file" and len(argv) >= 2:
            # 只读取数口（设计 A）：未登记 ⟹ `test_file=""`（**非**错误，调用方据此跳过）。
            print(json.dumps({"ok": True, "finding": argv[1],
                              "test_file": finding_test_file(argv[1])}, ensure_ascii=False))
            return 0
        print(json.dumps({"ok": False,
                          "error": "usage: list | show <id> | render <id> k=v ... | test-file <finding>"}))
        return 2
    except Exception as e:  # noqa: BLE001 — CLI 边界，fail-loud 不裸抛
        print(json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)},
                         ensure_ascii=False))
        return 2


if __name__ == "__main__":
    # 便于 `python3 gk_red_arm_gen.py <cmd>` 与 import 双形态
    if os.environ.get("GK_RED_ARM_NO_MAIN") == "1":
        raise SystemExit(0)
    raise SystemExit(main(sys.argv[1:]))
