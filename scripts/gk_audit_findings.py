#!/usr/bin/env python3
"""gk_audit_findings.py — 审计证据 → finding 台账适配器（E18 / 计划 B4，2026-10-29）
================================================================================
缺口（B1/B2/B4 断点）：`audit --state` / `audit --docs` 把 `match=false` 落到
`gate_data.audit_state_result` / `gate_data.audit_docs_result` 后**闭环终止** ——
没有生产者把审计失败转成 finding ⟹ 审计结果进不了 ECC 台账、也进不了交付门。

本模块是**唯一**适配点（单源）：
  - 读 `audit_state_result.state_checks[]` / `audit_docs_result.docs_checks[]` 中
    `match is False` 的项；
  - 逐项 `gk_finding.register(source="audit", release_state="provisional",
    severity=..., owner=...)`；`root_key` 由「域 + 检查项」确定性生成 ⟹ 重跑幂等合并
    （同根因不各建一条镜像）；
  - 不复制证据正文进 finding（`source_note` 只留摘要），证据本体仍留在被审 state（S1）。

严重度判据（机械，可对表）：
  - state 检查项字段名含封印/校验类词（seal/checksum/signature/hmac/ed25519）⟹ `critical`
  - 其余 state 检查项：带 `issues` ⟹ `high`，否则 `medium`
  - docs 检查：C2（extension-registry 命令表覆盖）⟹ `high`，其余 `medium`

用法:
  python3 gk_audit_findings.py <state_file> [--dry-run] [--owner <token>]
输出: stdout JSON {"ok":true,"schema":...,"candidates":N,"registered":N,"merged":N,...}
"""
import hashlib
import json
import os
import re
import sys

SCHEMA = "gk-audit-findings/v1"
DEFAULT_OWNER = "skill.2026-10-04-audit-bureau-plan"
USAGE = ("usage: gk_audit_findings.py <state_file> [--dry-run] [--owner <token>]")

_ROOT_KEY_MAX = 64
_SEAL_HINTS = ("seal", "checksum", "signature", "hmac", "ed25519")


def _slug(x) -> str:
    """root_key 片段：空白→`_`，去掉其余非标识符字符（禁空白是 register 的硬约束）。"""
    s = re.sub(r"\s+", "_", str(x or "").strip())
    s = re.sub(r"[^\w.\-:/]", "", s)
    return s or "unknown"


def _root_key(*parts) -> str:
    """确定性根因指纹：`audit.<域>.<检查项>`；超长时截断 + 内容哈希（仍确定性）。"""
    key = ".".join(_slug(p) for p in parts)
    if len(key) <= _ROOT_KEY_MAX:
        return key
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]
    return key[: _ROOT_KEY_MAX - 9] + "-" + h


def _note(check: dict) -> str:
    """证据摘要（不搬正文）：只保留 replay/issue/error 的短视图。"""
    parts = []
    for k in ("replay", "error"):
        v = check.get(k)
        if v:
            parts.append("%s=%s" % (k, str(v)[:160]))
    iss = check.get("issues") or []
    if isinstance(iss, list) and iss:
        parts.append("issues=" + " | ".join(str(x)[:80] for x in iss[:3]))
    return "; ".join(parts)[:500]


def _state_severity(field: str, check: dict) -> str:
    low = str(field or "").lower()
    if any(h in low for h in _SEAL_HINTS):
        return "critical"
    if check.get("issues"):
        return "high"
    return "medium"


def _docs_severity(check: dict) -> str:
    blob = ("%s %s" % (check.get("doc") or "", check.get("check") or "")).lower()
    if "extension-registry" in blob or "c2" in blob:
        return "high"
    return "medium"


def collect(gd: dict, owner: str = DEFAULT_OWNER) -> list:
    """把两份审计证据里的失败项转成 finding 候选（**只读**，不写盘）。"""
    out = []
    if not isinstance(gd, dict):
        return out
    st = gd.get("audit_state_result")
    if isinstance(st, dict):
        for c in st.get("state_checks") or []:
            if not isinstance(c, dict) or c.get("match") is not False:
                continue
            field = str(c.get("field") or "unknown")
            out.append({
                "title": "audit(state): %s 不可复现" % field,
                "root_key": _root_key("audit", "state", field),
                "family": "AUDIT-STATE",
                "severity": _state_severity(field, c),
                "owner": owner,
                "facets": ["audit:state", "audit-field:%s" % _slug(field)],
                "source_note": _note(c),
            })
    docs = gd.get("audit_docs_result")
    if isinstance(docs, dict):
        for c in docs.get("docs_checks") or []:
            if not isinstance(c, dict) or c.get("match") is not False:
                continue
            doc = str(c.get("doc") or "unknown")
            chk = str(c.get("check") or "unknown")
            out.append({
                "title": "audit(docs): %s / %s 不通过" % (doc, chk),
                "root_key": _root_key("audit", "docs", doc, chk),
                "family": "AUDIT-DOCS",
                "severity": _docs_severity(c),
                "owner": owner,
                "facets": ["audit:docs", "audit-doc:%s" % _slug(doc)],
                "source_note": _note(c),
            })
    return out


def apply_findings(state_file: str, gd: dict, owner: str = DEFAULT_OWNER,
                   dry_run: bool = False) -> dict:
    """登记候选（幂等：`root_key` 命中即合并）。`dry_run` ⟹ 零写盘。"""
    items = collect(gd, owner=owner)
    out = {"ok": True, "schema": SCHEMA, "candidates": len(items),
           "registered": 0, "merged": 0, "dry_run": bool(dry_run), "findings": []}
    if dry_run:
        out["findings"] = [{"title": it["title"], "severity": it["severity"],
                            "root_key": it["root_key"]} for it in items]
        return out
    import gk_finding as F
    # 读侧 union（遗漏⑤）：溢出片里的 id 也算「已存在」⟹ 否则同一 finding 会被反复计成 new。
    before = {f.get("id") for f in F.load_findings_union(state_file)}
    for it in items:
        rec = F.register(state_file, it["title"], "audit",
                         family=it["family"], root_key=it["root_key"],
                         facets=it["facets"], closure_oracle="mechanical",
                         source_note=it["source_note"], release_state="provisional",
                         severity=it["severity"], owner=it["owner"])
        is_new = rec.get("id") not in before
        out["registered" if is_new else "merged"] += 1
        out["findings"].append({"id": rec.get("id"), "title": it["title"],
                                "severity": it["severity"], "new": is_new})
    return out


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(USAGE, file=sys.stderr)
        return 2
    state_file = args[0]
    dry = "--dry-run" in args
    owner = DEFAULT_OWNER
    if "--owner" in args:
        i = args.index("--owner")
        owner = args[i + 1] if len(args) > i + 1 else ""
    if not os.path.exists(state_file):
        print(json.dumps({"ok": False, "error": "state not found: %s" % state_file},
                         ensure_ascii=False))
        return 1
    with open(state_file, encoding="utf-8") as f:
        d = json.load(f)
    gd = d.get("gate_data") if isinstance(d.get("gate_data"), dict) else {}
    try:
        out = apply_findings(state_file, gd, owner=owner, dry_run=dry)
    except Exception as e:  # noqa: BLE001 — CLI 边界：统一转 JSON 错误
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
        return 1
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
