#!/usr/bin/env python3
"""S5：ecc-findings → 单一批级人工裁定评分（确定性，2026-10-06）。

用途（owner 需求）：由 S2/S4 产出的 `ecc_findings[]`（分类 / 载体 / 严重度）**自动生成**
一份**批级** `verdicts.json`(F1-F7) + `score` + `decision`（+ 非 PASS 的 `concessions`），
可直接喂 CLI `adjudicate`。**无 arm 维度** —— 全批一份判定（对齐 S3「批级单判」）。

映射（确定性）：P=计划文本 ⟹ F1；L/M=机制 ⟹ F4；unknown ⟹ F3；关键词分派 F2/F5/F6/F7。
级差：0 命中=PASS；1=WARN；≥2=BLOCKED。score = 100 − 12·WARN − 30·BLOCKED（截 0-100）。
"""
import argparse
import json
import re
import sys
from pathlib import Path

_FCODES = ["F1", "F2", "F3", "F4", "F5", "F6", "F7"]
_KEYWORD_F = (("F2", r"复发|重复|依赖"), ("F5", r"假设|模糊|不明确|含糊"),
              ("F6", r"回退|恢复|快照|退路|回滚"), ("F7", r"锁定|框架|绑定"))
_LEVEL_ORDER = {"PASS": 0, "WARN": 1, "BLOCKED": 2}


def _facet(f: dict, prefix: str) -> str:
    for x in (f.get("facets") or []):
        s = str(x)
        if s.startswith(prefix + ":"):
            return s.split(":", 1)[1]
    return ""


def _classify(f: dict) -> str:
    """取分类：先看显式 `classification` 字段，再看 facets。"""
    c = str(f.get("classification", "") or "")
    if c:
        return c
    c = _facet(f, "classification")
    return c or "unknown"


def _bump(levels: dict, code: str, hit: int):
    lv = "PASS" if hit <= 0 else ("WARN" if hit == 1 else "BLOCKED")
    if _LEVEL_ORDER[lv] > _LEVEL_ORDER.get(levels.get(code, "PASS"), 0):
        levels[code] = lv


_DIRECTIONS = ("allow", "reject", "abstain")


def score(findings: list[dict], *, direction: str = "reject") -> dict:
    """findings → 单一批级裁定（verdicts/concessions/score/decision）。确定性。

    - **相关性隔离**（默认输入即污染）：`relevance:out`（未锚定）的条目移入 `unverified`，
      **不计缺陷、也不丢弃**（可审计）。
    - **结论方向三态** `direction`：
      - `reject`（缺省）：列表项 = 缺陷，按现规则罚分；
      - `allow`：列表项 = 已接受的观察项，**不罚分**（仅机制类 F4 保留，因机制缺陷不能靠"人接受"消解）；
      - `abstain`：不做判定（`verdicts={}`、`score=None`），仅落台账。
    """
    if direction not in _DIRECTIONS:
        direction = "reject"
    fs_all = list(findings or [])
    quarantined = [f for f in fs_all if _facet(f, "relevance") == "out"]
    fs = [f for f in fs_all if _facet(f, "relevance") != "out"]
    levels = {c: "PASS" for c in _FCODES}
    n_plan = n_infra = n_unknown = 0
    kw = {code: 0 for code, _ in _KEYWORD_F}
    for f in fs:
        cls = _classify(f)
        carrier = _facet(f, "carrier")
        if cls == "plan-error" or carrier == "P":
            n_plan += 1
        elif cls == "infra-defect":
            n_infra += 1
        else:
            n_unknown += 1
        blob = "%s %s" % (f.get("title", ""), f.get("source_note", ""))
        for code, pat in _KEYWORD_F:
            if re.search(pat, blob):
                kw[code] += 1
    _bump(levels, "F1", n_plan)        # 范围蔓延 ← 计划文本类
    _bump(levels, "F3", n_unknown)     # 假验证 ← 未分类（无从核验）
    _bump(levels, "F4", n_infra)       # 绕过现有设施 ← 机制类
    for code, cnt in kw.items():
        _bump(levels, code, cnt)

    if direction == "allow":           # 仅机制类保留罚分（人手接受不能消解机制缺陷）
        for c in _FCODES:
            if c != "F4":
                levels[c] = "PASS"
    abstained = (direction == "abstain")
    if abstained:
        levels = {}
        sc = None
        concessions = {}
        decision = ("MoA 批级：**弃权**（人工未做判定）—— 隔离 %d 条未锚定；"
                    "仅落台账，勿喂 adjudicate" % len(quarantined))
    else:
        warns = sum(1 for v in levels.values() if v == "WARN")
        blocks = sum(1 for v in levels.values() if v == "BLOCKED")
        sc = max(0, min(100, 100 - 12 * warns - 30 * blocks))
        concessions = {c: "自动初判 %s：本批命中 %s 类缺陷，需人工确认修补/让步方案"
                       % (levels[c], c) for c in _FCODES if levels[c] != "PASS"}
        _tail = ("人工放行" if direction == "allow"
                 else ("驳回或大改" if blocks else ("带让步放行" if warns else "放行")))
        decision = ("MoA 批级自动初判（方向=%s）：计分 %d 条 finding（计划类 %d / 机制类 %d / "
                    "未分类 %d），隔离 %d 条未锚定 —— %d BLOCKED / %d WARN；建议 %s"
                    % (direction, len(fs), n_plan, n_infra, n_unknown, len(quarantined),
                       blocks, warns, _tail))
    out = {"verdicts": levels, "concessions": concessions, "score": sc, "decision": decision,
           "direction": direction, "abstained": abstained,
           "counts": {"plan_error": n_plan, "infra_defect": n_infra, "unknown": n_unknown},
           "unverified": [str(f.get("title", "")) for f in quarantined]}
    # ① 空 findings 护栏（2026-10-06）：0 条计分 ⟹ 全 PASS/100 属**静默放行** ⟹ 显式告警。
    if not fs:
        out["warning"] = ("空 findings ⟹ 全 PASS/100（非人工结论；"
                          "散文可能未按 `-` / `1.` 列表项解析，或被相关性闸全部隔离）")
    return out


def main() -> int:
    p = argparse.ArgumentParser(description="ecc-findings → 单一批级裁定评分")
    p.add_argument("--file", default="", help="findings JSON（列表）；缺省读 stdin")
    p.add_argument("--out-dir", default=".", help="verdicts.json / concessions.json 落盘目录")
    p.add_argument("--direction", default="reject", choices=list(_DIRECTIONS),
                   help="结论方向：allow 放行 / reject 驳回（缺省）/ abstain 弃权")
    a = p.parse_args()
    raw = Path(a.file).read_text(encoding="utf-8") if a.file else sys.stdin.read()
    findings = json.loads(raw)
    if isinstance(findings, dict):            # 容许 state 形态
        findings = findings.get("gate_data", {}).get("ecc_findings", [])
    res = score(findings, direction=a.direction)
    d = Path(a.out_dir)
    d.mkdir(parents=True, exist_ok=True)
    (d / "verdicts.json").write_text(json.dumps(res["verdicts"], ensure_ascii=False),
                                     encoding="utf-8")
    (d / "concessions.json").write_text(json.dumps(res["concessions"], ensure_ascii=False),
                                        encoding="utf-8")
    if res.get("warning"):
        sys.stderr.write("⚠ " + res["warning"] + "\n")
    _extra = {"direction": res["direction"], "unverified": res["unverified"]}
    if res.get("abstained"):
        _extra["abstained"] = True
    if res.get("warning"):
        _extra["warning"] = res["warning"]
    print(json.dumps({"ok": True, "score": res["score"], "decision": res["decision"],
                      "verdicts": res["verdicts"], "out_dir": str(d), **_extra},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
