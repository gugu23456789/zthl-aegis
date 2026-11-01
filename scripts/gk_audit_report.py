#!/usr/bin/env python3
"""gk_audit_report.py — 审计报告 JSON 侧车（E18 / 计划 B3，2026-10-29）
====================================================================
缺口（B3）：`audit --report` 只产出 `references/ecc-audit-<date>.md`（且路径写死安装目录）
⟹ 报告**不可机读**、也不随 state 走，交付/复核侧没有入口。

本模块 = 侧车的唯一写者：`<state>.audit-report.json`（与审计登记 sidecar 同构，
落在被审 state 旁边，随 state 迁移/归档）：
  - `audit_id` / `audit_type` / `content_hash` / `report_path` / `state_file` / `written_at`
  - `findings[]`：id/title/severity/status/source 摘要（**不复制证据正文**，S1 零搬迁）
  - `summary`：按 severity 计数（空值归 `unrated`）

用法:
  python3 gk_audit_report.py write <state_file> [--audit-id <id>] [--type <t>]
                                 [--content-hash <h>] [--report-path <p>]
  python3 gk_audit_report.py read  <state_file>
输出: stdout JSON {"ok":true,"schema":...,"path":...,"findings":N}
"""
import datetime
import json
import os
import sys

SCHEMA = "gk-audit-report/v1"
SUFFIX = ".audit-report.json"


def sidecar_path(state_file: str) -> str:
    return state_file + SUFFIX


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _findings_summary(state_file: str) -> list:
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from gk_finding import load_findings_union
        # 读侧 union（遗漏⑤）：溢出片条目也须进审计报告的 findings 面（否则报告少条）。
        raw = load_findings_union(state_file)
    except Exception:  # noqa: BLE001 — 边界：台账不可读 ⟹ 侧车仍可写（findings 空）
        raw = []
    out = []
    for f in raw:
        if not isinstance(f, dict):
            continue
        out.append({"id": f.get("id", ""), "title": f.get("title", ""),
                    "severity": f.get("severity", ""), "status": f.get("status", ""),
                    "source": f.get("source", "")})
    return out


def _sign_doc(doc: dict, key_dir: str = "") -> dict:
    """给侧车加 `signature` 块（2026-11-01）：签名面 = 去掉 signature 后的规范化 JSON。

    复用 `gk_budget_ledger._sign`（封印实现单源）；无 audit 私钥/公钥 ⟹ `unsigned`
    （不阻断，供迁移期；`invalid` 才在门禁侧判失败）。
    """
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import hashlib
        from gk_budget_ledger import _canonical, _key_dir, _sign, _now_str
        body = {k: v for k, v in doc.items() if k != "signature"}
        digest = hashlib.sha256(_canonical(body)).hexdigest()
        mode, sig, fp = _sign(digest, _key_dir(key_dir))
        if mode != "ed25519" or not sig:
            return {"status": "unsigned", "alg": mode, "digest": digest,
                    "signed_at": _now_str(), "reason": "no_audit_key"}
        return {"status": "verified", "alg": "ed25519", "key_id": fp,
                "sig": sig, "digest": digest, "signed_at": _now_str()}
    except Exception as e:  # noqa: BLE001 — 边界：签名失败不阻断侧车写
        return {"status": "unsigned", "reason": "sign_error:%s" % type(e).__name__}


def verify_sidecar(state_file: str, key_dir: str = "") -> dict:
    """验侧车签名（门禁唯一消费点）。返回 `{status: verified|invalid|unsigned|unverified_no_key}`。"""
    path = sidecar_path(state_file)
    if not os.path.exists(path):
        return {"status": "absent"}
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return {"status": "invalid", "reason": "unreadable"}
    sig = doc.get("signature") if isinstance(doc, dict) else None
    if not isinstance(sig, dict) or not sig.get("sig"):
        return {"status": "unsigned"}
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import hashlib
        from gk_budget_ledger import _canonical, _key_dir
        from gk_ember_replay import verify_ed25519
        body = {k: v for k, v in doc.items() if k != "signature"}
        digest = hashlib.sha256(_canonical(body)).hexdigest()
        if digest != sig.get("digest"):
            return {"status": "invalid", "reason": "digest_mismatch"}
        pub = os.path.join(_key_dir(key_dir), "audit_ed25519.pub")
        v = verify_ed25519(pub, str(sig.get("sig")), digest.encode("utf-8"))
        st = v.get("status", "invalid")
        if st == "verified":
            return {"status": "verified", "key_id": sig.get("key_id", "")}
        if st == "unverified_no_key":
            return {"status": "unverified_no_key"}
        return {"status": "invalid", "reason": st}
    except Exception as e:  # noqa: BLE001
        return {"status": "invalid", "reason": "verify_error:%s" % type(e).__name__}


def build(state_file: str, audit_id: str = "", audit_type: str = "",
          content_hash: str = "", report_path: str = "", key_dir: str = "") -> dict:
    items = _findings_summary(state_file)
    by_sev = {}
    for f in items:
        k = (f.get("severity") or "unrated").strip().lower() or "unrated"
        by_sev[k] = by_sev.get(k, 0) + 1
    doc = {
        "schema": SCHEMA,
        "audit_id": audit_id,
        "audit_type": audit_type,
        "content_hash": content_hash,
        "report_path": report_path,
        "state_file": state_file,
        "written_at": _now(),
        "findings": items,
        "summary": {"total": len(items), "by_severity": by_sev},
    }
    doc["signature"] = _sign_doc(doc, key_dir)
    return doc


def write(state_file: str, audit_id: str = "", audit_type: str = "",
          content_hash: str = "", report_path: str = "", key_dir: str = "") -> dict:
    doc = build(state_file, audit_id, audit_type, content_hash, report_path, key_dir)
    path = sidecar_path(state_file)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)
    return {"ok": True, "schema": SCHEMA, "path": path,
            "findings": len(doc["findings"]), "summary": doc["summary"]}


def read(state_file: str) -> dict:
    path = sidecar_path(state_file)
    if not os.path.exists(path):
        return {"ok": False, "error": "sidecar not found: %s" % path}
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    return {"ok": True, "path": path, "report": doc}


USAGE = ("usage: gk_audit_report.py write <state_file> [--audit-id <id>] [--type <t>]"
         " [--content-hash <h>] [--report-path <p>]\n"
         "       gk_audit_report.py read <state_file>")


def _opt(args, name, default=""):
    if name in args:
        i = args.index(name)
        if len(args) > i + 1:
            return args[i + 1]
    return default


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2 or args[0] not in ("write", "read"):
        print(USAGE, file=sys.stderr)
        return 2
    verb, state_file = args[0], args[1]
    if not os.path.exists(state_file):
        print(json.dumps({"ok": False, "error": "state not found: %s" % state_file},
                         ensure_ascii=False))
        return 1
    if verb == "read":
        print(json.dumps(read(state_file), ensure_ascii=False))
        return 0
    out = write(state_file, _opt(args, "--audit-id"), _opt(args, "--type"),
                _opt(args, "--content-hash"), _opt(args, "--report-path"))
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
