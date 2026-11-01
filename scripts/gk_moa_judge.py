#!/usr/bin/env python3
"""规则式判分器（W2A §6.3(1) ② / F3；`ECC-0FC756057411`）。

把臂的输出映射到它检出的缺陷 id，并对 `gk_defect_gen` 的金标集算 `det_F1`。口径优先级
（F3）：**字符串/正则 > 嵌入 > LLM**。本模块实现**字符串档**，**按构造相位不变** —— 位置无关的
子串匹配**不可能**重新引入实验所抽象的 `L mod S` 混杂（F3）。嵌入 / LLM 档为**桩**：LLM 判分器
**自身**相位敏感、缓存敏感，须**相位钉定**并记录其 cache-hit（§6.3(6)）；**拒绝**比静默双重混杂安全。

臂输出契约：臂**每行一条 finding**（bullet / 编号 / 引号皆可）；每个非空行是候选主张，逐字
（大小写/空白无关）与金标 clause 匹配：命中 ⟹ 检出；未命中 ⟹ 假阳；金标 clause 从未命中 ⟹ 漏检。

**纯库**（禁直接执行；技能内置 cmd 路由）。
"""
import re

# §6.3(1) 写 `correct = det_F1 >= tau`；spec 未钉 tau 值 ⟹ 调用方按 run 钉定并随结果记录。
DEFAULT_TAU = 0.8
VALID_MODES = ("rule", "embed", "llm")


def _norm(s):
    return re.sub(r"\s+", " ", str(s).lower()).strip()


def candidates(arm_output):
    """One non-empty, de-bulleted line per candidate claim (a documented contract)."""
    out = []
    for line in str(arm_output).splitlines():
        s = line.strip().lstrip("-*+\u2022 \t")
        s = re.sub(r"^\d+[.)]\s*", "", s)
        s = s.strip().strip("\"'`").strip()
        if s:
            out.append(s)
    return out


def detect(arm_output, gold):
    """Return `(detected_ids, n_false_positives)`.  Deterministic; ignores line order."""
    clauses = {g["id"]: _norm(g["clause"]) for g in gold}
    detected, fp = set(), 0
    for cand in candidates(arm_output):
        c = _norm(cand)
        hit = next((gid for gid, cl in clauses.items() if cl and cl in c), None)
        if hit is None:
            fp += 1
        else:
            detected.add(hit)
    return detected, fp


def det_f1(gold, detected, false_pos=0):
    """F1 over the defect-id sets; precision = tp / (tp + fp)."""
    tp = len(detected)
    n_gold = len({g["id"] for g in gold})
    p = tp / (tp + false_pos) if (tp + false_pos) else 0.0
    r = tp / n_gold if n_gold else 0.0
    return 0.0 if (p + r) == 0 else 2 * p * r / (p + r)


def score(gold, arm_output, tau=DEFAULT_TAU, mode="rule"):
    """Score one arm output against the gold set -> `{det_F1, detected, false_positives, ...}`."""
    if mode != "rule":
        raise ValueError("judge mode %r not implemented -- priority rule > embed > llm; "
                         "an embed/LLM judge must be phase-pinned (see §6.3(6) F3)" % mode)
    det, fp = detect(arm_output, gold)
    f1 = det_f1(gold, det, fp)
    return {"det_F1": round(f1, 4), "detected": sorted(det), "false_positives": fp,
            "correct": bool(f1 >= tau), "tau": tau}
