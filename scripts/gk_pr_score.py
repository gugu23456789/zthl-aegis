#!/usr/bin/env python3
"""
gk_pr_score.py — PR-SCORE 双盲评分锚定（C9, 2026-09-06）
=======================================================================
plan-refinement 双盲评分（SKILL.md 8.2 角色 2：F1-F7 + 7 维独立打分）锚定：
主 agent 双盲打分从"会话内产物"固化为可审计锚——两副本 + A3 seal（同 C10 ember 模型）：

  副本 A：被质询计划文档内嵌 `<!-- PR-SCORE -->` 区块（META 同款 HTML 注释模式，含
          7 维分 + F1-F7 + divergence + snapshot 引用 + sealed_at）
  副本 B：独立快照 `.prscore-<plan>.json`（plan 同目录，不入 .gitignore → 入库可 diff）
  密封：A3 audit key（Ed25519）签规范化 payload（seal 自排除，复用 gk_ember_replay 单源）

防"双盲评分产物事后可改无锚"（2026-08-28-security-hardening-assessment §15.6 ⑨/⑩ C9）：
  - 区块与快照两副本互相指认；verify 比对关键字段（dimensions/f1_f7/divergence）+ seal 验签
  - 快照入 git → 历史本身就是审计链（事后改写必留 git 痕迹 + seal 校验失败）

用法: python3 gk_pr_score.py <seal|verify|list> --plan <plan_doc>
                                     [--score <score.json>] [--audit-key-dir <dir>]
  seal   = 读 score.json + plan → 写快照 + 注入 plan PR-SCORE 区块（--no-update-plan 跳过注入）
  verify = 快照 seal 验签 + plan 区块存在性与关键字段一致性 → 锚定状态
  list   = 列出 plan 同目录 .prscore-*.json（只读面）
输出: stdout JSON。错误 {"ok":false,"error":...} exit 1（解析纪律对齐 gk_finding/gk_ember_replay）。
"""
import base64
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gk_ember_replay import canonical_bytes, verify_seal  # 单源：A3 seal 字节契约 + 读侧验签

PRSCORE_PREFIX = ".prscore-"
SCHEMA = "pr-score/1"
_BLOCK_RE = re.compile(r"<!-- PR-SCORE\s*\n(.*?)\n-->", re.S)
_META_END_RE = re.compile(r"-->\s*", re.S)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _plan_name(plan_path: str) -> str:
    return os.path.splitext(os.path.basename(plan_path))[0]


def snapshot_path(plan_path: str) -> str:
    """快照与 plan 同目录：`.prscore-<plan>.json`（不入 .gitignore → 入库可 diff 审计）。"""
    return os.path.join(os.path.dirname(os.path.abspath(plan_path)),
                        PRSCORE_PREFIX + _plan_name(plan_path) + ".json")


def load_score(score_path: str) -> dict:
    """读主 agent 双盲打分 score.json；缺关键字段显式报错（fail-loud，不静默放行）。"""
    if not os.path.isfile(score_path):
        return {"error": "score_file_missing", "detail": score_path}
    try:
        with open(score_path, encoding="utf-8") as f:
            s = json.load(f)
    except Exception as e:
        return {"error": "score_unreadable", "detail": str(e)}
    if not isinstance(s.get("dimensions"), dict) or not s.get("dimensions"):
        return {"error": "score_missing_dimensions", "detail": "dimensions (7 维打分) 缺失"}
    if not isinstance(s.get("f1_f7"), dict) or not s.get("f1_f7"):
        return {"error": "score_missing_f1_f7", "detail": "f1_f7 (F1-F7 判定) 缺失"}
    return s


def _safe_block_str(v) -> str:
    """HTML 注释内禁止 `--` 序列：所有入区块字符串字段统一消毒。"""
    return str(v).replace("--", "-")


def _build_block(payload: dict, snap: str) -> str:
    """PR-SCORE 区块文本：单行紧凑 JSON（纯 ASCII 消毒，规避 HTML 注释 `--` 约束）。"""
    inner = {
        "schema": SCHEMA,
        "plan": _safe_block_str(payload.get("plan", "")),
        "snapshot": _safe_block_str(os.path.basename(snap)),
        "sealed_at": _safe_block_str(payload.get("sealed_at", "")),
        "dimensions": payload.get("dimensions", {}),
        "f1_f7": payload.get("f1_f7", {}),
        "divergence": payload.get("divergence"),
    }
    line = json.dumps(inner, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return "<!-- PR-SCORE\n" + line + "\n-->"


def _inject_block(plan_path: str, block: str) -> dict:
    """把 PR-SCORE 区块注入 plan 文档：插到首个 `<!-- META` 块之后（META 缺失 → 拒绝）。"""
    try:
        with open(plan_path, encoding="utf-8") as f:
            text = f.read()
    except Exception as e:
        return {"ok": False, "error": "plan_unreadable", "detail": str(e)}
    m = re.search(r"<!--\s*META.*?-->", text, re.S)
    if not m:
        return {"ok": False, "error": "no_meta_block",
                "detail": "plan 无 <!-- META --> 块（质询对象须先补 META，参照 r-phase-meta-template.md）"}
    if _BLOCK_RE.search(text):
        return {"ok": False, "error": "pr_score_block_exists",
                "detail": "plan 已含 PR-SCORE 区块——先人工审阅再决定轮换/覆盖（禁止静默重写锚）"}
    pos = m.end()
    sep = "\n" if not text[pos:pos + 1] == "\n" else ""
    new_text = text[:pos] + sep + "\n" + block + "\n" + text[pos:]
    try:
        with open(plan_path, "w", encoding="utf-8", newline="") as f:
            f.write(new_text)
    except Exception as e:
        return {"ok": False, "error": "plan_write_failed", "detail": str(e)}
    return {"ok": True, "inserted_after": "META"}


def _replace_block(plan_path: str, block: str) -> dict:
    """轮换路径（2026-09-07 ECC-3E10D111D382）：把既有 PR-SCORE 区块原位替换为新区块。

    仅显式 --rotate（人工审批）调用；旧区块内容由 git 历史保留（plan 入库可 diff），
    不做自制归档系统——重锚的审计链 = plan git diff + 旧快照归档（_archive_snapshot）。
    """
    try:
        with open(plan_path, encoding="utf-8") as f:
            text = f.read()
    except Exception as e:
        return {"ok": False, "error": "plan_unreadable", "detail": str(e)}
    if not _BLOCK_RE.search(text):
        return {"ok": False, "error": "no_block_to_replace",
                "detail": "无既有 PR-SCORE 区块——首次锚定请用 seal（不带 --rotate）"}
    new_text = _BLOCK_RE.sub(lambda _m: block, text, count=1)
    try:
        with open(plan_path, "w", encoding="utf-8", newline="") as f:
            f.write(new_text)
    except Exception as e:
        return {"ok": False, "error": "plan_write_failed", "detail": str(e)}
    return {"ok": True, "mode": "rotated"}


def _archive_snapshot(snap: str, sealed_at: str) -> str:
    """轮换前把旧快照归档为 `.prscore-<plan>.<sealed_at>.json`（保留历史锚，verify 仍读当前）。

    归档名跨平台安全：Windows 文件名禁 `:`，时间戳内冒号一律替换为 `-`。
    """
    if not os.path.isfile(snap):
        return ""
    _ts = re.sub(r"[^0-9A-Za-z._-]", "-", sealed_at or "prev")
    archived = snap[:-5] + "." + _ts + ".json"
    try:
        os.rename(snap, archived)
        return os.path.basename(archived)
    except OSError:
        return ""


def _parse_block(plan_path: str) -> dict:
    """读 plan 内 PR-SCORE 区块 → 解析 JSON；无区块 → {"present": False}。"""
    try:
        with open(plan_path, encoding="utf-8") as f:
            text = f.read()
    except Exception:
        return {"present": False, "error": "plan_unreadable"}
    m = _BLOCK_RE.search(text)
    if not m:
        return {"present": False}
    try:
        data = json.loads(m.group(1))
    except Exception as e:
        return {"present": True, "parse_error": str(e)}
    data["present"] = True
    return data


def _sign(payload: dict, snap: str, audit_key_dir: str) -> tuple:
    """A3 seal：audit key 签 canonical payload → (payload_with_seal, seal_meta/None)。"""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key as _lpk
    priv_p = os.path.join(audit_key_dir, "audit_ed25519.pem")
    pub_p = os.path.join(audit_key_dir, "audit_ed25519.pub")
    if not (os.path.isfile(priv_p) and os.path.isfile(pub_p)):
        return None, {"error": "no_audit_key",
                      "detail": "audit key 缺失 → 先跑 audit --init-keys / --key rotate（fail-loud，不产未签锚）"}
    import hashlib
    canon = canonical_bytes(payload)
    priv = _lpk(open(priv_p, "rb").read(), password=None)
    sig = base64.b64encode(priv.sign(canon)).decode()
    seal = {
        "alg": "ed25519", "key": "audit_ed25519",
        "key_fp": hashlib.sha256(open(pub_p, "rb").read()).hexdigest()[:32],
        "sig": sig, "signed_at": payload.get("sealed_at", _now()),
    }
    payload["seal"] = seal
    return payload, None


def cmd_seal(plan_path: str, score_path: str, audit_key_dir: str = "",
             update_plan: bool = True, rotate: bool = False) -> dict:
    """seal：score.json + plan → 快照（seal 签名）+ plan 区块注入。

    2026-09-07 ECC-3E10D111D382：重锚轮换 —— plan 已含 PR-SCORE 区块时：
      - 不带 --rotate → 保持 pr_score_block_exists 硬拒（防静默覆盖首锚）；
      - 带 --rotate（显式人工审批）→ 旧快照归档 + 新区块原位替换，旧锚由
        git 历史 + 归档快照双保留（verify 读当前快照/区块，语义不变）。
    半态清理：update_plan 注入/替换失败 → 回滚删除已写快照（不留 snapshot_written 半态）。
    """
    plan_path = os.path.abspath(plan_path)
    if not os.path.isfile(plan_path):
        return {"ok": False, "error": "plan_not_found", "detail": plan_path}
    s = load_score(score_path)
    if "error" in s:
        return {"ok": False, **s}
    d = audit_key_dir or os.environ.get("_AUDIT_KEY_DIR", "") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", ".keys")
    payload = {
        "schema": SCHEMA,
        "plan": _plan_name(plan_path),
        "dimensions": s.get("dimensions"),
        "f1_f7": s.get("f1_f7"),
        "divergence": s.get("divergence"),
        "checkpoint_task": s.get("checkpoint_task", ""),
        "scored_at": s.get("scored_at", ""),
        "sealed_at": _now(),
    }
    # 既有区块探测（写快照前判定，避免半态：先写快照才发现区块存在 → 残留）
    block_present = _parse_block(plan_path).get("present", False)
    if block_present and not rotate:
        return {"ok": False, "error": "pr_score_block_exists",
                "detail": "plan 已含 PR-SCORE 区块——重锚需显式人工审批：pr-score seal --plan <p> --score <s> --rotate（旧锚归档 + 原位替换，禁止静默重写）"}
    signed, err = _sign(dict(payload), None, d)
    if err:
        return {"ok": False, "error": err["error"], "detail": err["detail"]}
    snap = snapshot_path(plan_path)
    archived = ""
    if rotate:
        archived = _archive_snapshot(snap, payload["sealed_at"])  # 旧快照归档（若存在）
    with open(snap, "w", encoding="utf-8") as f:
        json.dump(signed, f, ensure_ascii=False, indent=1)
    result = {"ok": True, "schema": SCHEMA, "plan": payload["plan"],
              "snapshot": os.path.basename(snap), "sealed_at": payload["sealed_at"]}
    if archived:
        result["archived_snapshot"] = archived
    if update_plan:
        block = _build_block(signed, snap)
        inj = (_replace_block(plan_path, block) if block_present
               else _inject_block(plan_path, block))
        if not inj["ok"]:
            # 半态回滚：注入失败 → 删已写快照（防 snapshot_written 残留），归档已移回不可恢复
            #（归档保留旧锚，不删——回滚仅针对本次新写快照）
            if os.path.isfile(snap):
                try:
                    os.remove(snap)
                except OSError:
                    pass
            return {"ok": False, "error": inj["error"], "detail": inj["detail"],
                    "snapshot_rolled_back": True}
        result["plan_block"] = "rotated" if block_present else "injected"
    else:
        result["plan_block"] = "skipped"
    return result


def cmd_verify(plan_path: str, audit_key_dir: str = "") -> dict:
    """verify：快照 seal 验签 + plan 区块存在性与关键字段一致性。"""
    plan_path = os.path.abspath(plan_path)
    if not os.path.isfile(plan_path):
        return {"ok": False, "error": "plan_not_found", "detail": plan_path}
    snap = snapshot_path(plan_path)
    if not os.path.isfile(snap):
        return {"ok": True, "anchored": False, "error": "no_snapshot",
                "detail": "无 .prscore-<plan>.json → 该 plan 未经 C9 锚定"}
    try:
        with open(snap, encoding="utf-8") as f:
            snap_data = json.load(f)
    except Exception as e:
        return {"ok": True, "anchored": False, "error": "snapshot_unreadable", "detail": str(e)}
    d = audit_key_dir or os.environ.get("_AUDIT_KEY_DIR", "") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", ".keys")
    seal = verify_seal(snap_data, d)
    block = _parse_block(plan_path)
    mismatches = []
    if not block.get("present"):
        mismatches.append("plan PR-SCORE 区块缺失（快照存在但区块被移除/分离）")
    else:
        for field in ("schema", "plan", "dimensions", "f1_f7", "divergence"):
            bv = block.get(field)
            sv = snap_data.get(field)
            if bv != sv:
                mismatches.append("field_mismatch:" + str(field))
    anchored = seal["status"] == "verified" and not mismatches
    return {"ok": True, "anchored": anchored,
            "seal": seal["status"], "snapshot": os.path.basename(snap),
            "mismatches": mismatches,
            "gate": {"ok": anchored,
                     "verdict": "anchored" if anchored else "unverified" +
                     (":" + seal["status"] if seal["status"] != "verified" else "") +
                     (":block_mismatch" if mismatches else "")}}


def cmd_list(plan_path: str) -> dict:
    """list：plan 同目录 .prscore-*.json（只读面）。"""
    d = os.path.dirname(os.path.abspath(plan_path))
    files = sorted(glob.glob(os.path.join(d, PRSCORE_PREFIX + "*.json")),
                   key=os.path.getmtime, reverse=True)
    return {"ok": True, "snapshots": [os.path.basename(p) for p in files], "dir": d}


def main(argv=None):
    """CLI entry: 参数注入（argv=None → sys.argv[1:]，对齐 #23 python_argv_inject 约定）。"""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(json.dumps({"ok": False, "error": "usage: pr-score <seal|verify|list> "
                         "--plan <plan_doc> [--score <score.json>] [--audit-key-dir <dir>] "
                         "[--no-update-plan]"}))
        return 1
    sub = args[0]
    plan_path = score_path = audit_key_dir = ""
    update_plan = True
    rotate = False
    i = 1
    while i < len(args):
        if args[i] == "--plan" and i + 1 < len(args):
            plan_path = args[i + 1]; i += 2
        elif args[i] == "--score" and i + 1 < len(args):
            score_path = args[i + 1]; i += 2
        elif args[i] == "--audit-key-dir" and i + 1 < len(args):
            audit_key_dir = args[i + 1]; i += 2
        elif args[i] == "--no-update-plan":
            update_plan = False; i += 1
        elif args[i] == "--rotate":
            # 2026-09-07 ECC-3E10D111D382: 重锚轮换（显式人工审批）——plan 已含区块时
            # 归档旧快照 + 原位替换新区块；不带此标志保持 pr_score_block_exists 硬拒。
            rotate = True; i += 1
        else:
            i += 1
    if not plan_path:
        print(json.dumps({"ok": False, "error": "--plan <plan_doc> required"}))
        return 1
    if sub == "seal":
        if not score_path:
            print(json.dumps({"ok": False, "error": "seal 需要 --score <score.json>"}))
            return 1
        r = cmd_seal(plan_path, score_path, audit_key_dir, update_plan, rotate)
    elif sub == "verify":
        r = cmd_verify(plan_path, audit_key_dir)
    elif sub == "list":
        r = cmd_list(plan_path)
    else:
        r = {"ok": False, "error": "unknown subcommand: " + sub}
    print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
