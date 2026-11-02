#!/usr/bin/env python3
"""gk_ecc_sink.py — 「直调 subagent_runner」通道的 `EccOutput` 落盘中枢。

定位（`references/ecc-write-spec.md` §4）
=======================================================================
`monitor --subagent` 路径的 ECC 落盘是**已实装**的（CLI 落库段）：
`docs/analysis/subagent/<sid>.json`（全量）+ `.md`（人读）+ `subagent_history` 条目
+ 卫星 `history` 片 + `satellite_index` 叶子。**红队四角色走的正是该路径**
（`monitor --subagent RED-SCOPE|RED-EXPLOIT|RED-POSTEX|RED-REPORT`）⟹ 红队输出本就有落点。

缺口 = **审计内嵌 LLM 车道**：`audit --crossr` 的 LLM 注解与 `audit --report` 的报告生成
**直调** `subagent_runner.py`，只取 `conclusion` 拼进结果，**原始 EccOutput 整份丢弃**
（无文件、无片、无索引 ⟹ 事后不可复盘、MoA 聚合器也看不见这些臂）。

本模块补这条通道，**与质询同构**（文件 + 卫星片 + 索引）：
  ① 全量 ECC → `docs/analysis/<domain>/<batch_id>/<arm>.json`（原子写，禁半截文件）
  ② 有界投影 → 卫星 `history` 片（`gk_satellite.append` **唯一写者**，禁第二直写者）
  ③ 索引 → `gate_data.satellite_index.<domain>-<batch_id>.<arm>`（经中枢 per-arm 叶子）

纪律
=======================================================================
- 片名 / 索引段语法**单源**取 `gk_satellite`（`KIND_SUFFIX` / `SEG_RE`），本模块不自持第二份。
- 原始 ECC 非法 ⟹ **fail-loud**（返回 ok:false）但**不丢证据**：原文落 `<arm>.invalid.txt`。
- 「文件成功、片/索引失败」⟹ ok:false 且 `error` 具名（不静默降级：片缺 = 对接断裂面）。
- domain 白名单校验（禁拼错静默建新目录）。
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 落盘域白名单。`subagent` = monitor 通道（既有落点，仅供本模块显式归档时复用）；
# `refine` = 计划质询；`audit` / `red` = 审计/红队。
DOMAINS = ("audit", "red", "refine", "subagent")

# 卫星 `history` 片投影里的 conclusion 上限（**入片的是摘要**；全量在 ① 的文件里）。
# 128KB 片窗口下 4000 字符/条足以承载结论，又不至于两三条就把片撑到不可读。
CONCLUSION_MAX = 4000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seg_ok(name: str) -> bool:
    """batch/arm 段语法 —— **单源** `gk_satellite.SEG_RE`（禁本模块另写正则）。"""
    import gk_satellite as SAT
    return bool(SAT.SEG_RE.match(name or ""))


def artifact_dir(root: str, domain: str, batch_id: str) -> str:
    return os.path.join(root, "docs", "analysis", domain, batch_id)


def artifact_path(root: str, domain: str, batch_id: str, arm: str) -> str:
    return os.path.join(artifact_dir(root, domain, batch_id), arm + ".json")


def _atomic_write(path: str, text: str) -> None:
    """同目录临时文件 + `os.replace`（禁半截产物；跨进程读侧永不见半行）。"""
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp.%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def _findings_projection(ecc: dict) -> dict:
    """`findings` 归一（与 CLI 落库段同口径）：三键全空时用 kept / challenges 回填。

    对齐说明：CLI 落库段有同语义内联实现（bash 内嵌 python，不可 import）。此处是
    **读侧投影**的第二入口，取值口径必须逐字一致，否则同一臂在两条通道里 findings 不同。
    """
    f = ecc.get("findings")
    f = f if isinstance(f, dict) else {}
    if not any(f.get(k) for k in ("worked", "failed", "not_tried")):
        return {"worked": list(ecc.get("kept") or [])[:5],
                "failed": list(ecc.get("challenges") or [])[:5],
                "not_tried": []}
    return {"worked": list(f.get("worked") or []),
            "failed": list(f.get("failed") or []),
            "not_tried": list(f.get("not_tried") or [])}


def _mc_field(x, key):
    return (x or {}).get(key, "") if isinstance(x, dict) else ""


def _agent_identity_status(ecc: dict) -> dict:
    """身份验签投影（单源 `gk_agent_identity.verify_ecc`；禁第二实现）。

    缺省公钥目录 = `<skill>/.keys/agents`（`GATEKEEPER_AGENT_PUBKEY_DIR` 可覆盖）。
    `agent_identity` 缺失 ⟹ unsigned（不阻断）；验不过 ⟹ invalid（读侧按 untrusted）。
    """
    try:
        from gk_agent_identity import verify_ecc
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        d = os.environ.get("GATEKEEPER_AGENT_PUBKEY_DIR", "") or os.path.join(root, ".keys", "agents")
        r = verify_ecc(ecc, d)
        return {"status": r.get("status", "invalid"), "pubkey_id": r.get("pubkey_id", ""),
                "reason": r.get("reason", "")}
    except Exception:  # noqa: BLE001 — 边界：可选能力，缺库/坏输入不阻断落盘
        return {"status": "unsigned", "pubkey_id": "", "reason": "verify_unavailable"}


def monitor_last(state_file: str) -> dict:
    """最近一条 `monitor_history` 的**可复盘摘要**（2026-10-31，owner 裁定 A）。

    `monitor --api` 的分数只进 `monitor_history`（advisory），而复盘面（history entry /
    机检面）此前完全看不见它 ⟹ 「付了调用成本、留不下可比对的行」。这里把它投影成
    `{score, verdict, mode, ts}` 塞进 `machine_check`（**只读、零写盘**）。
    """
    try:
        with open(state_file, encoding="utf-8") as f:
            d = json.load(f)
        hist = ((d or {}).get("gate_data") or {}).get("monitor_history") or []
        rec = hist[-1] if hist else {}
        if not isinstance(rec, dict):
            return {}
        return {"score": rec.get("score"), "verdict": rec.get("verdict"),
                "mode": rec.get("mode"), "ts": rec.get("ts")}
    except Exception:  # noqa: BLE001 — 边界：state 不可读 ⟹ 空摘要（不改主契约）
        return {}


def bounded_entry(ecc: dict, *, domain: str, batch_id: str, arm: str,
                  output_file: str = "", monitor: dict = None) -> dict:
    """全量 ECC → **卫星片投影**（有界、可聚合；全量留在 `output_file`）。"""
    from gk_subagent_report import normalize_evidence
    conclusion = str(ecc.get("conclusion") or "")
    return {
        "task": str(ecc.get("task") or ""),
        "subagent_id": str(ecc.get("subagent_id") or ""),
        "conclusion": conclusion[:CONCLUSION_MAX],
        "conclusion_len": len(conclusion),
        "kept": list(ecc.get("kept") or [])[:5],
        "slashed": list(ecc.get("slashed") or [])[:5],
        "challenges": list(ecc.get("challenges") or [])[:5],
        "evidence": normalize_evidence(ecc.get("evidence") or []),
        "findings": _findings_projection(ecc),
        "next_steps": list(ecc.get("next_steps") or []),
        "confidence": str(ecc.get("confidence") or ""),
        "tools_used": list(ecc.get("tools_used") or []),
        "assertions": list(ecc.get("assertions") or []),
        "tool_call_count": int(ecc.get("tool_call_count") or 0),
        "seven_dim_score": ecc.get("seven_dim_score") or {},
        "overall_score": ecc.get("overall_score"),
        "verdicts": ecc.get("verdicts") or {},
        "budget_status": str(ecc.get("budget_status") or "ok"),
        "total_tokens": int(ecc.get("total_tokens") or 0),
        "token_budget": ecc.get("token_budget"),
        "total_items": int(ecc.get("total_items") or 0),
        "item_budget": ecc.get("item_budget"),
        "machine_check": {
            "verification": _mc_field(ecc.get("verification"), "status"),
            "evidence_anchor": _mc_field(ecc.get("evidence_anchor"), "status"),
            "gx_status": _mc_field(ecc.get("gx_status"), "verdict"),
            "token_usage_rounds": _mc_field(ecc.get("token_usage"), "rounds"),
            "guardrail": str(ecc.get("guardrail") or ""),
            "turns": int(ecc.get("turns") or 0),
            "mode": str(ecc.get("mode") or ""),
            "timestamp": str(ecc.get("timestamp") or ""),
            # 2026-10-31（A）：monitor 分与本臂**同屏**可见（复盘用；空 = 无 monitor 记录）
            "monitor_last": monitor or {},
            # 2026-10-31：身份验签三态（verified|unsigned|invalid；invalid 读侧按 untrusted）
            "agent_identity": _agent_identity_status(ecc),
        },
        # 落盘通道身份（**本模块独有**：读侧据此区分「直调 subagent_runner」的臂）
        "domain": domain,
        "batch_id": domain + "-" + batch_id,
        "arm": arm,
        "output_file": output_file,
        "sink_ts": _now(),
    }


def persist(state_file: str, raw: str, *, domain: str, batch_id: str, arm: str,
            root: str = "", render_md: bool = False) -> dict:
    """全量 ECC 落 ①文件 ②卫星片 ③索引；返回结构化结果（fail-loud，不静默）。

    `root` 缺省 = 本 skill 根目录（`scripts/` 的父目录）——与 CLI 的 `SKILL_DIR` 同源，
    使 worktree / 安装副本的产物落在**自己的**树下（禁写回主仓）。
    """
    domain = (domain or "").strip()
    batch_id = (batch_id or "").strip()
    arm = (arm or "").strip()
    root = root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if domain not in DOMAINS:
        return {"ok": False, "error": "未知 domain: %r（合法：%s）" % (domain, list(DOMAINS))}
    for val, nm in ((batch_id, "batch_id"), (arm, "arm")):
        if not val:
            return {"ok": False, "error": "%s 不可为空" % nm}
        if not _seg_ok(val):
            return {"ok": False, "error": "非法 %s=%r（须匹配 ^[A-Za-z0-9][A-Za-z0-9-]*$）"
                                          % (nm, val)}
    path = artifact_path(root, domain, batch_id, arm)
    try:
        ecc = json.loads(raw)
    except Exception as e:  # noqa: BLE001 — 边界：LLM 原始输出
        bad = os.path.splitext(path)[0] + ".invalid.txt"
        try:
            _atomic_write(bad, str(raw))
        except Exception:  # noqa: BLE001 — 边界：连原文都写不下时仍要报错
            bad = ""
        return {"ok": False, "error": "ECC 非法 JSON（%s: %s）" % (type(e).__name__, e),
                "invalid_file": bad, "output_len": len(raw or "")}
    if not isinstance(ecc, dict):
        bad = os.path.splitext(path)[0] + ".invalid.txt"
        try:
            _atomic_write(bad, str(raw))
        except Exception:  # noqa: BLE001
            bad = ""
        return {"ok": False, "error": "ECC 非对象形态（%s）" % type(ecc).__name__,
                "invalid_file": bad}
    try:
        _atomic_write(path, json.dumps(ecc, ensure_ascii=False, indent=2) + "\n")
    except Exception as e:  # noqa: BLE001 — 边界：文件是主契约，失败即 fail-loud
        return {"ok": False, "error": "ECC 文件写失败：%s: %s" % (type(e).__name__, e),
                "file": path}
    md_file = ""
    _err = ""
    if render_md:
        try:
            import gk_subagent_report as REP
            md_file = os.path.splitext(path)[0] + ".md"
            _atomic_write(md_file, REP.render(ecc))
        except Exception as e:  # noqa: BLE001 — 边界：人读面失败不改主契约
            md_file = ""
            _err = "%s: %s" % (type(e).__name__, e)
    entry = bounded_entry(ecc, domain=domain, batch_id=batch_id, arm=arm,
                          output_file=path, monitor=monitor_last(state_file))
    try:
        import gk_satellite as SAT
        res = SAT.append(state_file, "history", [entry],
                         batch_id=entry["batch_id"], arm=arm)
    except Exception as e:  # noqa: BLE001 — 边界
        res = {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
    out = {"ok": bool(res.get("ok")), "file": path, "md_file": md_file,
           "shard": res.get("shard", ""), "index_path": res.get("index_path", ""),
           "subagent_id": entry["subagent_id"], "domain": domain,
           "batch_id": batch_id, "arm": arm}
    if not res.get("ok"):
        out["error"] = "卫星片/索引落盘失败（文件已落）：%s" % res.get("error", "")
    if _err:
        out["md_error"] = _err
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="ECC 落盘中枢（文件 + 卫星片 + 索引）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("persist", help="把一份全量 ECC JSON 落盘")
    p.add_argument("--state", required=True, help="目标 state 文件（卫星片归属）")
    p.add_argument("--domain", required=True, help="落盘域：%s" % ",".join(DOMAINS))
    p.add_argument("--batch", required=True, help="批 id（同一派发单元）")
    p.add_argument("--arm", required=True, help="臂名（同批内互异）")
    p.add_argument("--root", default="", help="skill 根目录（缺省按本文件位置推导）")
    p.add_argument("--md", action="store_true", help="额外产出人读 .md 报告")
    p.add_argument("--raw-file", default="-", help="ECC JSON 文件（缺省 - = stdin）")
    a = ap.parse_args(argv)
    if a.cmd == "persist":
        if a.raw_file == "-":
            raw = sys.stdin.read()
        else:
            try:
                raw = open(a.raw_file, encoding="utf-8").read()
            except Exception as e:  # noqa: BLE001 — CLI 边界
                print(json.dumps({"ok": False, "error": "读 raw 失败：%s: %s"
                                  % (type(e).__name__, e)}))
                return 2
        r = persist(a.state, raw, domain=a.domain, batch_id=a.batch, arm=a.arm,
                    root=a.root, render_md=a.md)
        print(json.dumps(r, ensure_ascii=False))
        return 0 if r.get("ok") else 3
    return 2


if __name__ == "__main__":
    sys.exit(main())
