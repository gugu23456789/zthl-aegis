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
  python3 scripts/gk_red_arm_gen.py classify "<改动描述>"          # 复用 or 新增
  python3 scripts/gk_red_arm_gen.py scaffold "<改动描述>" [k=v ...] # 出骨架（复用）/出草案（新增）
  python3 scripts/gk_red_arm_gen.py promote <draft.json>            # 红→绿都过 ⟹ 回灌登记表

「大幅刷新」后的 20 形态全部登记在 `references/red-arm-templates.json`；分类器**只读该表的
keywords**（无第二份形态清单）。新增形态的回环 = `promote`：先跑 `<rev>` 红（--expect=red）、
再跑 HEAD 绿（--expect=green），两者 rc=0 才写回登记表并 version+1。

契约（fail-loud，不静默）：
  · 未知 id / 缺占位符 / 多余键 → `{"ok":false,"error":...}` exit 2；
  · 渲染结果**必须**已无 `{...}` 残留（残留 → 拒绝输出，防把未填模板当成品交付）。
"""
import json
import os
import re
import subprocess
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


def _hits(template: dict, text: str) -> list:
    low = str(text or "").lower()
    out = []
    for kw in (template.get("keywords") or []):
        k = str(kw or "").strip()
        if k and k.lower() in low:
            out.append(k)
    return sorted(set(out))


def classify(change: str, min_score: int = 2, reg: dict = None) -> dict:
    """按登记表 `keywords` 判定「复用既有形态」还是「需要新增形态」。

    单一事实源仍是登记表（无第二份形态清单）。判据：最高分 ≥ min_score **且严格领先
    第二名**；并列/不足 ⟹ new（不确定时不硬套旧形态，避免把新缺陷塞进旧模版）。
    """
    reg = reg if reg is not None else load_registry()
    cands = []
    for t in reg["templates"]:
        h = _hits(t, change)
        cands.append({"id": str(t.get("id") or ""), "score": len(h), "hits": h})
    cands.sort(key=lambda c: (-c["score"], c["id"]))
    best = cands[0] if cands else {"id": "", "score": 0, "hits": []}
    second = cands[1]["score"] if len(cands) > 1 else 0
    reuse = best["score"] >= int(min_score) and best["score"] > second
    return {
        "decision": "reuse" if reuse else "new",
        "id": best["id"] if reuse else "",
        "score": best["score"],
        "second_score": second,
        "hits": best["hits"],
        "candidates": cands[:5],
        "reason": ("命中 %s（%d 分，领先 %d）" % (best["id"], best["score"], second)
                   if reuse else
                   "最高分 %d（%s）未达阈值或并列 ⟹ 需新增形态"
                   % (best["score"], best["id"] or "-")),
    }


def scaffold(change: str, values: dict = None, id_hint: str = "new-shape",
             min_score: int = 2, reg: dict = None) -> dict:
    """可复用 → 导出模版骨架（保留占位符）并可选填空；不可复用 → 导出空草案。

    骨架**不伪装成成品**：未给全值时 `missing` 非空、`code` 为空；新增形态 `body` 为空，
    必须由本轮真实臂写入后走 `promote` 回灌。
    """
    reg = reg if reg is not None else load_registry()
    c = classify(change, min_score, reg)
    if c["decision"] == "reuse":
        t = get_template(c["id"], reg)
        declared = [str(x) for x in (t.get("placeholders") or [])]
        vals = dict(values or {})
        bare = {p.strip("{}") for p in declared}
        missing = sorted(bare - set(vals))
        code = "" if missing else render(c["id"], vals, reg)
        return {"decision": "reuse", "id": c["id"], "placeholders": declared,
                "missing": missing, "skeleton": str(t.get("body") or ""),
                "code": code, "reason": c["reason"]}
    tokens = [w for w in re.split(r"[\s，。；：、/|（）()【】\[\]{}<>《》\"'`]+", str(change))
              if 2 <= len(w) <= 20]
    return {"decision": "new", "id": "", "reason": c["reason"],
            "draft": {"id": id_hint, "desc": str(change), "when": str(change),
                      "keywords": sorted(set(tokens))[:12], "placeholders": [],
                      "body": "", "test_file": "", "shape_k": "", "rev": ""}}


def _run_redfirst(rev: str, test_file: str, k: str, expect: str) -> int:
    """真跑 `_redfirst_cli.sh`（与生产同解释器/同沙箱）；rc 语义由该脚本保证。"""
    cmd = ["bash", str(_SKILL_DIR / "scripts" / "_redfirst_cli.sh"),
           str(rev), str(test_file), str(k), "--expect=" + str(expect)]
    return subprocess.call(cmd, cwd=str(_SKILL_DIR))


def _append_template_text(text: str, entry: dict) -> str:
    """把 entry 追加到 `templates` 数组尾（保留原文件格式，不整体重排）。"""
    idx = text.find('"_templates_extended_')
    if idx < 0:
        idx = text.find('"finding_arms"')
    if idx < 0:
        raise ValueError("登记表结构非法：找不到 templates 结束锚")
    close = text.rindex("\n  ],", 0, idx)
    block = json.dumps(entry, ensure_ascii=False, indent=2)
    block = "\n".join("    " + line for line in block.splitlines())
    return text[:close] + ",\n" + block + text[close:]


def promote(draft: dict, registry_path: str = "", runner=None) -> dict:
    """红先验收回环：红 → 绿都达成，才把本轮「新形态」写回登记表。

    `runner(rev, test_file, shape_k, expect) -> rc` 可注入（测试用）；CLI 缺省真跑
    `_redfirst_cli.sh`。任一环未达成 ⟹ ValueError（不回灌、不留半成品）。
    """
    p = Path(registry_path) if registry_path else _REGISTRY
    reg = load_registry(str(p))
    d = dict(draft or {})
    for k in ("id", "desc", "when", "body", "test_file", "shape_k", "rev"):
        if not str(d.get(k) or "").strip():
            raise ValueError("draft 缺字段: " + k)
    kw = d.get("keywords")
    if not isinstance(kw, list) or not [x for x in kw if str(x).strip()]:
        raise ValueError("draft 缺 keywords（分类器单源）")
    tid = str(d["id"]).strip()
    if tid in template_ids(reg):
        raise ValueError("模版 id 已存在: " + tid)
    body = str(d["body"])
    need = set(_PH_RE.findall(body))
    declared = [str(x) for x in (d.get("placeholders") or sorted(need))]
    if need != set(declared):
        raise ValueError("占位符漂移: body=%s ≠ declared=%s"
                         % (sorted(need), sorted(set(declared))))
    if not need:
        raise ValueError("模版 body 至少要含 1 个占位符（否则无法填空）")
    run = runner or _run_redfirst
    rc_red = run(str(d["rev"]), str(d["test_file"]), str(d["shape_k"]), "red")
    if rc_red != 0:
        raise ValueError("红先未达成（rev=%s rc=%s）— 不得回灌" % (d["rev"], rc_red))
    rc_green = run("HEAD", str(d["test_file"]), str(d["shape_k"]), "green")
    if rc_green != 0:
        raise ValueError("绿未达成（HEAD rc=%s）— 不得回灌" % rc_green)
    entry = {"id": tid, "keywords": [str(x) for x in kw if str(x).strip()],
             "desc": str(d["desc"]), "when": str(d["when"]),
             "placeholders": declared, "body": body}
    text = p.read_text(encoding="utf-8")
    new_text = _append_template_text(text, entry)
    new_text = re.sub(r'("version":\s*)(\d+)',
                      lambda m: m.group(1) + str(int(m.group(2)) + 1),
                      new_text, count=1)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(new_text, encoding="utf-8")
    os.replace(str(tmp), str(p))
    ver = int(re.search(r'"version":\s*(\d+)', new_text).group(1))
    return {"ok": True, "id": tid, "version": ver,
            "templates": len(reg["templates"]) + 1}


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
        if cmd == "classify" and len(argv) >= 2:
            print(json.dumps({"ok": True, **classify(argv[1])}, ensure_ascii=False))
            return 0
        if cmd == "scaffold" and len(argv) >= 2:
            vals, id_hint, min_score = {}, "new-shape", 2
            for kv in argv[2:]:
                if kv.startswith("--id-hint="):
                    id_hint = kv.split("=", 1)[1]
                elif kv.startswith("--min-score="):
                    min_score = int(kv.split("=", 1)[1])
                elif "=" in kv:
                    k, v = kv.split("=", 1)
                    vals[k.strip()] = v
                else:
                    raise ValueError("scaffold 参数须为 k=v 或 --id-hint=/--min-score=: %r" % kv)
            print(json.dumps({"ok": True, **scaffold(argv[1], vals, id_hint, min_score)},
                             ensure_ascii=False))
            return 0
        if cmd == "promote" and len(argv) >= 2:
            registry = ""
            for a in argv[2:]:
                if a.startswith("--registry="):
                    registry = a.split("=", 1)[1]
                else:
                    raise ValueError("promote 仅接受 --registry=<f>，收到: %r" % a)
            draft = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
            print(json.dumps(promote(draft, registry), ensure_ascii=False))
            return 0
        print(json.dumps({"ok": False,
                          "error": ("usage: list | show <id> | render <id> k=v ... | "
                                    "test-file <finding> | classify <change> | "
                                    "scaffold <change> [k=v ...] | promote <draft.json>")}))
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
