#!/usr/bin/env python3
# gk_template_audit.py — 模板登记表**统一审计**（2026-11-11）
# =============================================================================
# 定位：把「模板登记表」这一族资产的漂移检查收敛为**一份实现**。红先（fill）、注释（fill）
#   以及后续的 checklist/data/spec 表，统一在 `references/template-registries.json` 登记；
#   本模块只读清单，**不内建第二份表名清单**。
#
# 每张表必须能回答四个问题（缺一即 DRIFT）：
#   ① 表本身自洽：JSON 可解析、条目非空、id 唯一、必填字段齐、占位符与 body 一致；
#   ② 消费方真的读它：consumer 源码里出现该表文件名（防「表在但没人用」的幻影门）；
#   ③ 文档面真的写它：doc 里出现表文件名或登记 id（防「代码有、文档失联」）；
#   ④ 事后回环有着落：post_gate 指向的验证器实存（红先=redfirst，注释=check）。
#
# 用法：
#   python3 scripts/gk_template_audit.py check [--skill-dir <d>]
#   python3 scripts/gk_template_audit.py list  [--skill-dir <d>]
# Exit: 0 = PASS；1 = FAIL（任一表 DRIFT）；2 = 清单不可读/参数错。
import argparse
import json
import re
import sys
from pathlib import Path

_SKILL_DIR = Path(__file__).resolve().parent.parent
_MANIFEST = "references/template-registries.json"
KINDS = ("fill", "checklist", "data", "spec")
_PH_RE = re.compile(r"\{[A-Za-z0-9_]+\}")


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def _nonempty(v) -> bool:
    if isinstance(v, str):
        return bool(v.strip())
    if isinstance(v, (list, tuple, dict)):
        return bool(v)
    return v is not None


def _audit_one(sd: Path, ent: dict, seen_paths: set) -> dict:
    """单张表的四问审计；返回 {id, kind, path, status, issues}。"""
    issues = []
    rid = str(ent.get("id") or "").strip()
    kind = str(ent.get("kind") or "").strip()
    rel = str(ent.get("path") or "").strip()
    if not rid:
        issues.append("MISSING_ID")
    if kind not in KINDS:
        issues.append("BAD_KIND:%s" % (kind or "-"))
    for key in ("path", "consumer", "doc", "post_gate"):
        if not str(ent.get(key) or "").strip():
            issues.append("MISSING_FIELD:%s" % key)
    for key in ("path", "consumer", "doc", "post_gate"):
        val = str(ent.get(key) or "").strip()
        if val and not (sd / val).is_file():
            issues.append("MISSING_FILE:%s=%s" % (key, val))
    if rel:
        if rel in seen_paths:
            issues.append("DUP_PATH:%s" % rel)
        seen_paths.add(rel)

    reg = None
    reg_p = sd / rel if rel else None
    if reg_p and reg_p.is_file():
        try:
            reg = json.loads(_read(reg_p))
        except (OSError, ValueError) as e:
            issues.append("BAD_JSON:%s:%s" % (type(e).__name__, e))
    for key in (ent.get("required_top") or []):
        if not reg or key not in reg:
            issues.append("MISSING_TOP:%s" % key)
    if kind == "checklist" and reg is not None:
        if not (reg.get("target_glob") or reg.get("target_globs")):
            issues.append("MISSING_TARGET")
    items_key = str(ent.get("items_key") or "templates")
    items = (reg or {}).get(items_key) or []
    if reg is not None and not isinstance(items, list):
        issues.append("BAD_ITEMS:%s" % items_key)
        items = []
    if reg is not None and not items:
        issues.append("EMPTY_ITEMS:%s" % items_key)

    ids = []
    for it in items:
        if not isinstance(it, dict):
            issues.append("BAD_ITEM:not-object")
            continue
        iid = str(it.get("id") or "").strip()
        ids.append(iid)
        for key in (ent.get("required_fields") or []):
            if not _nonempty(it.get(key)):
                issues.append("ITEM_MISSING:%s@%s" % (key, iid or "-"))
        if ent.get("placeholders_from_body"):
            body_ph = set(_PH_RE.findall(str(it.get("body") or "")))
            decl = set(str(x) for x in (it.get("placeholders") or []))
            if body_ph != decl:
                issues.append("PLACEHOLDER_DRIFT@%s" % (iid or "-"))
        if kind == "checklist":
            level = str(it.get("level") or "").upper()
            if level not in ("ERROR", "WARN", "INFO"):
                issues.append("BAD_LEVEL:%s@%s" % (level or "-", iid or "-"))
            mode = str(it.get("mode") or "present").lower()
            if mode not in ("present", "absent"):
                issues.append("BAD_MODE:%s@%s" % (mode, iid or "-"))
            try:
                re.compile(str(it.get("pattern") or ""))
            except re.error as e:
                issues.append("BAD_REGEX@%s:%s" % (iid or "-", e))
    if any(not i for i in ids):
        issues.append("EMPTY_ITEM_ID")
    if len(ids) != len(set(ids)):
        issues.append("DUP_ID:%s" % ",".join(sorted({i for i in ids if ids.count(i) > 1})))

    # ③ 消费方真的读表（checklist 的消费方 = 本审计器自身，经清单泛化读取，免按文件名硬编码）
    consumer = str(ent.get("consumer") or "").strip()
    if consumer and Path(consumer).name != "gk_template_audit.py" \
            and (sd / consumer).is_file() and rel:
        if Path(rel).name not in _read(sd / consumer):
            issues.append("CONSUMER_NOT_WIRED:%s" % consumer)
    # ④ 文档面真的写表（只认表文件名：doc 标题/正文出现登记 id 不算「写了表」）
    doc = str(ent.get("doc") or "").strip()
    if doc and (sd / doc).is_file():
        text = _read(sd / doc)
        if rel and Path(rel).name not in text:
            issues.append("DOC_NOT_MENTION:%s" % doc)

    return {"id": rid or "-", "kind": kind or "-", "path": rel or "-",
            "status": "FAIL" if issues else "PASS", "issues": issues}


def audit(skill_dir: str = "") -> dict:
    sd = Path(skill_dir) if skill_dir else _SKILL_DIR
    out = {"check": "template_registries", "registries": []}
    mp = sd / _MANIFEST
    if not mp.is_file():
        out.update({"status": "FAIL", "detail": "缺 " + _MANIFEST})
        return out
    try:
        man = json.loads(_read(mp))
    except (OSError, ValueError) as e:
        out.update({"status": "FAIL", "detail": "清单解析失败: %s: %s" % (type(e).__name__, e)})
        return out
    rows = man.get("registries") or []
    if not isinstance(rows, list) or not rows:
        out.update({"status": "FAIL", "detail": "清单无 registries"})
        return out
    seen_paths, seen_ids = set(), set()
    for ent in rows:
        if not isinstance(ent, dict):
            out["registries"].append({"id": "-", "kind": "-", "path": "-",
                                      "status": "FAIL", "issues": ["BAD_ENTRY:not-object"]})
            continue
        rid = str(ent.get("id") or "").strip()
        if rid in seen_ids:
            r = _audit_one(sd, ent, seen_paths)
            r["issues"].append("DUP_REGISTRY_ID:%s" % rid)
            r["status"] = "FAIL"
            out["registries"].append(r)
            continue
        seen_ids.add(rid)
        out["registries"].append(_audit_one(sd, ent, seen_paths))
    bad = [r for r in out["registries"] if r["status"] != "PASS"]
    out["status"] = "FAIL" if bad else "PASS"
    if bad:
        out["detail"] = "；".join("%s: %s" % (r["id"], ",".join(r["issues"])) for r in bad)
    else:
        out["detail"] = "%d 张登记表自洽（%s）" % (
            len(out["registries"]), ", ".join(r["id"] for r in out["registries"]))
    return out


def _target_globs(reg: dict) -> list:
    g = reg.get("target_globs")
    if isinstance(g, list) and g:
        return [str(x) for x in g if str(x).strip()]
    one = str(reg.get("target_glob") or "").strip()
    return [one] if one else []


def apply_checklist(skill_dir: str, rid: str, root: str) -> dict:
    """把 checklist 套到目标仓：present 项须命中、absent 项须不命中；ERROR 项失败 ⟹ FAIL。"""
    sd = Path(skill_dir) if skill_dir else _SKILL_DIR
    man = json.loads(_read((sd / _MANIFEST)))
    ent = next((r for r in (man.get("registries") or [])
                if str(r.get("id") or "") == str(rid)), None)
    if ent is None:
        raise ValueError("未知登记表 id: %s" % rid)
    if ent.get("kind") != "checklist":
        raise ValueError("登记表 %s 不是 checklist（kind=%s）" % (rid, ent.get("kind")))
    reg = json.loads(_read(sd / str(ent.get("path") or "")))
    rootp = Path(root)
    if not rootp.is_dir():
        raise ValueError("目标根不存在: %s" % root)
    files = set()
    for g in _target_globs(reg):
        files.update(p for p in rootp.glob(g) if p.is_file())
    files = sorted(files)
    results = []
    for it in (reg.get("items") or []):
        pat = re.compile(str(it.get("pattern") or ""))
        mode = str(it.get("mode") or "present").lower()
        hits = []
        for f in files:
            try:
                if pat.search(_read(f)):
                    hits.append(str(f.relative_to(rootp)).replace("\\", "/"))
            except OSError:
                continue
        ok = bool(hits) if mode == "present" else not hits
        results.append({"id": str(it.get("id") or "-"),
                        "level": str(it.get("level") or "WARN").upper(),
                        "mode": mode, "status": "PASS" if ok else "FAIL",
                        "files": hits[:5]})
    errs = [r for r in results if r["status"] == "FAIL" and r["level"] == "ERROR"]
    warns = [r for r in results if r["status"] == "FAIL" and r["level"] != "ERROR"]
    return {"check": "checklist", "id": rid, "root": str(rootp),
            "files": len(files), "status": "FAIL" if errs else "PASS",
            "summary": {"ERROR": len(errs), "WARN": len(warns), "total": len(results)},
            "items": results}


def main(argv: list) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("cmd", nargs="?", default="check")
    ap.add_argument("--skill-dir", default="")
    ap.add_argument("--id", default="")
    ap.add_argument("--root", default="")
    try:
        a = ap.parse_args(argv)
        sd = Path(a.skill_dir) if a.skill_dir else _SKILL_DIR
        if a.cmd == "list":
            man = json.loads(_read(sd / _MANIFEST))
            print(json.dumps({"ok": True, "kinds": man.get("kinds"),
                              "registries": [{"id": r.get("id"), "kind": r.get("kind"),
                                              "path": r.get("path")}
                                             for r in (man.get("registries") or [])]},
                             ensure_ascii=False, indent=1))
            return 0
        if a.cmd == "apply":
            if not a.id or not a.root:
                raise ValueError("apply 需要 --id <登记表 id> --root <目标仓根>")
            res = apply_checklist(str(sd), a.id, a.root)
            print(json.dumps(res, ensure_ascii=False, indent=1))
            return 0 if res["status"] == "PASS" else 1
        if a.cmd not in ("check", "audit"):
            raise ValueError("未知子命令: %r（check/list/apply）" % a.cmd)
        res = audit(str(sd))
        print(json.dumps(res, ensure_ascii=False, indent=1))
        return 0 if res["status"] == "PASS" else 1
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)},
                         ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
