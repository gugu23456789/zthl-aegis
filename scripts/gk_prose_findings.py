#!/usr/bin/env python3
"""S4：散文 → ecc-findings（确定性规则解析，2026-10-06）。

用途（owner 需求）：把一段**结论散文**转成结构化 `ecc_findings[]`，供 S5 生成人工裁定评分。
**确定性、零 LLM、零依赖**：只按行结构（列表项）+ 载体标记 `(P)/(L)/(M)` 解析。

- 条目形态（**单源 = gk_moa_aggregate.parse_items**）：列表项 `- xxx` / `* xxx` / `1. xxx` /
  `1、` / `一、`（中文序号）/ `（1）` / `①`（标题行与普通段落不入 finding）；
  **无任何标记的纯散文**按空行分段成条（段内换行合并）。
- 载体标记：`(P)`/`[P]`（大小写不敏感）⟹ `carrier`；P=计划文本 ⟹ plan-error，
  L/M=机制 ⟹ infra-defect；无标记 ⟹ unknown。
- 输出字段：`title`/`source`(`prose`)/`root_key`(`prose:<hash16>`；**键含 `plan|batch` 作用域**
  ，皆空则退回仅 `title` —— 防同句跨计划被吞，`ECC-08E30B02B2F1`)/`anchors`/`facets`/`source_note`/`severity`。
"""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

try:  # 单源：载体→类映射 + 相关性裁判 + 散文条目解析 复用聚合器（禁第二实现）
    from gk_moa_aggregate import _CARRIER_CLASS, _refs_of, relevance_judge, parse_items
except Exception:  # pragma: no cover
    _CARRIER_CLASS = {"P": "plan-error", "L": "infra-defect", "M": "infra-defect"}
    _refs_of = None
    relevance_judge = None

    def parse_items(prose):  # noqa: D401 —— 兜底：仅 ASCII 列表项
        out = []
        for l in str(prose or "").splitlines():
            m = re.match(r"^\s*(?:[-*]|\d+[.)])\s+(.*)$", l)
            if m and m.group(1).strip():
                out.append(m.group(1).strip())
        return out

_MARK_RE = re.compile(r"[\(\[]\s*([PLM])\s*[\)\]]", re.IGNORECASE)
_HIGH_RE = re.compile(r"崩溃|失败|截断|伪造|不可行|越权|漏洞|阻塞")


def _severity(text: str) -> str:
    return "high" if _HIGH_RE.search(text or "") else "medium"


def convert(prose: str, *, plan: str = "", batch: str = "",
            refs=None, min_score: float = 0.0) -> list[dict]:
    """散文 → findings 列表。确定性：同输入同输出。

    `refs` 非空时启用**相关性闸**（锚定硬下限 + BM25；默认输入即污染）：每条须与批内
    证据有 token 重叠且 BM25 ≥ `min_score`，否则落 `relevance:out`（下游 score 隔离为
    unverified，不计缺陷）。同时落 `bm25:`/`anchor:` facet 供阈值标定。
    """
    anchors = ([("batch:" + batch)] if batch else []) + ([("plan:" + plan)] if plan else [])
    out = []
    for body in parse_items(prose):
        mk = _MARK_RE.search(body)
        carrier = mk.group(1).upper() if mk else ""
        title = _MARK_RE.sub("", body).strip()
        if not title:
            continue
        cls = _CARRIER_CLASS.get(carrier, "unknown")
        # 幂等键**须含作用域**（`ECC-08E30B02B2F1`，2026-10-16）：原式仅以 `title` 为键 ⟹ 同句
        #   出现在**两个计划 / 两批**时被吞成一条（实测）。`plan|batch` 皆空（`from-prose` 直调）
        #   ⟹ 退回仅 title，与旧行为**逐字一致**（零回归）。
        _scope = "|".join(x for x in (plan, batch) if x)
        _key_src = (_scope + "|" + title) if _scope else title
        rk = "prose:" + hashlib.sha256(_key_src.encode("utf-8")).hexdigest()[:16]
        facets = (["carrier:" + carrier] if carrier else []) + ["classification:" + cls]
        if refs is not None and relevance_judge is not None:
            j = relevance_judge(title, refs, min_score=min_score)
            facets += ["relevance:" + ("in" if j["in"] else "out"),
                       "bm25:%s" % j["bm25"], "anchor:%d" % j["anchor"]]
            if j.get("weak"):
                facets.append("relevance:weak")
        # `source = "prose"`（`ECC-E844E67E64A5`，2026-10-16）：原硬编码 `review` 与 **MoA 聚合
        #   finding 同源** ⟹ 来源分面不可分；散文=人写结论 ⟹ 独立登记来源。
        #   `family` **删除**：convert 产出后 `chain()` / `main()` 均**不传给** register = **死字段**。
        out.append({
            "title": title,
            "source": "prose",
            "root_key": rk,
            "anchors": list(anchors),
            "facets": facets,
            "source_note": body,
            "severity": _severity(title),
        })
    return out


def main() -> int:
    p = argparse.ArgumentParser(description="散文 → ecc-findings（确定性解析）")
    p.add_argument("--file", default="", help="散文文件；缺省读 stdin")
    p.add_argument("--plan", default="")
    p.add_argument("--batch", default="")
    p.add_argument("--out", default="", help="findings JSON 落盘路径；缺省打印 stdout")
    p.add_argument("--state", default="", help="给了则经 gk_finding.register 落库（可选）")
    p.add_argument("--context", default="",
                   help="聚合 JSON / state 路径；给了则启用相关性闸（锚定 + BM25）")
    p.add_argument("--min-score", type=float, default=None,
                   help="BM25 相关度下限（缺省取 env GK_MOA_REL_MIN，再缺省 0）")
    a = p.parse_args()
    text = Path(a.file).read_text(encoding="utf-8") if a.file else sys.stdin.read()
    refs = None
    if a.context and _refs_of is not None:
        try:
            refs = _refs_of(json.loads(Path(a.context).read_text(encoding="utf-8")))
        except Exception as e:      # 上下文不可用 ⟹ 不启用闸（退化为旧行为），但 fail-loud 告警
            sys.stderr.write("⚠ --context 读取失败，未启用相关性闸：%s\n" % e)
    _ms = a.min_score
    if _ms is None:
        _ms = float(os.environ.get("GK_MOA_REL_MIN", "0") or 0)
    fs = convert(text, plan=a.plan, batch=a.batch, refs=refs, min_score=_ms)
    if a.state:
        import gk_finding
        for f in fs:
            gk_finding.register(a.state, f["title"], f["source"], root_key=f["root_key"],
                                anchors=f["anchors"], facets=f["facets"],
                                source_note=f["source_note"],
                                provenance="untrusted")   # T5-a：散文来源不可信（摄取外部结论）
    blob = json.dumps(fs, ensure_ascii=False, indent=1)
    # ① 空 findings 护栏（2026-10-06）：非列表散文被逐行丢弃 ⟹ count=0 ⟹ 下游恒全 PASS，
    #   属**静默放行**陷阱 ⟹ 显式告警（stderr + JSON warning 字段），禁无声通过。
    if not fs:
        sys.stderr.write("⚠ 散文未解析出任何 finding（须 `-` / `*` / `1.` 开头的列表项；"
                         "标题行与普通段落会被忽略）⟹ 后续 `finding score` 将全 PASS/100。\n")
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(blob, encoding="utf-8")
        res = {"ok": True, "count": len(fs), "out": a.out}
        if refs is not None:
            res["relevant"] = sum(1 for f in fs if "relevance:in" in f["facets"])
            res["unverified"] = sum(1 for f in fs if "relevance:out" in f["facets"])
        if not fs:
            res["warning"] = ("0 findings ⟹ 下游 score 全 PASS/100；"
                              "散文须为 `-` / `*` / `1.` 开头的列表项")
        print(json.dumps(res, ensure_ascii=False))
    else:
        print(blob)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
