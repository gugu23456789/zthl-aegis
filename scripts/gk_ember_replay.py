#!/usr/bin/env python3
"""
gk_ember_replay.py — ember-replay-audit（C10, 2026-09-05）
=======================================================================
读 `.gatekeeper.ember.<phase>.json`（R 相位切换余烬，gatekeeper-cli.sh L708-737）
对归档快照跑 archived finding_journal_reconcile（同构 gk_finding.reconcile_pair 单源）
+ Ed25519 seal 验签（A3 最小 seal，C10 同批前置）→ 输出"当时应判"回判痕迹。

语义（plan 2026-08-28-security-hardening-assessment §15.6 ⑬，SCR 收敛 sub-1788622220-32-23687）:
  - 回判基准 = 存档 slice（ember 内嵌 finding_journal 冻结行），非全量 live journal
  - 相位作用域：只对 fid ∈ archived ecc_findings 的事件对账（跨相位合法 closure 不误报残留；
    ember 每份内嵌的是导出时刻的整份 journal，gate_data_full 相位末冻结 → 须过滤 out-of-scope）
  - pre-C8 epoch（无 finding_journal 字段的快照）→ 豁免 INFO（不产 critical 回判，防全量假阳性）
  - seal：缺签 → integrity-unverified 降级标注（best-effort 诊断）；验签失败 → invalid（阻断级）
  - 体积门禁：EMBER_MAX_BYTES（默认 64MB）/ EMBER_EVENTS_MAX（默认 200k 行）超限显式 SKIP

用法: python3 gk_ember_replay.py <list|get|verify|reconcile> --state-file <path>
                                     [--phase <phase>] [--audit-key-dir <dir>] [--out <trace.json>]
  list      = 倒序列出余烬快照（get_state_history 同构只读面）
  get       = 单份快照元数据摘要（不含 gate_data_full 全量，防巨量 stdout）
  verify    = 仅 seal 验签
  reconcile = archived reconcile + seal 验签 → 回判痕迹（replay --ember 归口）
输出: stdout JSON。错误/用法错误 {"ok":false,"error":...} exit 1（解析纪律对齐 gk_finding）。

同源取数接口（A6-T3, 2026-09-15 —— **库函数，非子命令**，CLI 子命令集不变）:
  - `snapshot_pair(path)` = **同源 (state, journal) 对**单一取数接口：跨代际 `μ` 反推
    （收敛评估器 / 本模块 reconcile / 09-13-ember 计划的"余烬预筛"）**共用**此一处，
    **禁各写一份读取器**（F-REV-41 同族）。判据 = 同一快照 ⟹ 任何消费者取到的
    `(gate_data_full.ecc_findings, 内嵌 journal)` **逐字相同**。
"""
import base64
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
except Exception:  # pragma: no cover - 缺 cryptography 时 seal 验签降级 unverified（不阻断读取）
    InvalidSignature = None
    ed25519 = None
    load_pem_public_key = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gk_finding import reconcile_pair  # 单源：live reconcile 与 archived replay 共用四形态异常规则

EMBER_GLOB = ".gatekeeper.ember.*.json"
_EMBER_RE = re.compile(r"\.gatekeeper\.ember\.(.+)\.json$")
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_EVENTS_MAX = 200_000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _max_bytes() -> int:
    return int(os.environ.get("EMBER_MAX_BYTES", str(DEFAULT_MAX_BYTES)) or DEFAULT_MAX_BYTES)


def _max_events() -> int:
    return int(os.environ.get("EMBER_EVENTS_MAX", str(DEFAULT_EVENTS_MAX)) or DEFAULT_EVENTS_MAX)


def _phase_from_name(path: str) -> str:
    m = _EMBER_RE.search(os.path.basename(path))
    return m.group(1) if m else os.path.basename(path)


def ember_files(state_dir: str) -> list:
    """倒序列出余烬快照（get_state_history 同构：reverse chronological）。"""
    paths = glob.glob(os.path.join(state_dir, EMBER_GLOB))
    paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return paths


def resolve_ember(state_dir: str, phase: str = "") -> dict:
    """按相位精确匹配或取最新；返回 {"ok":true,"path":...} / {"ok":false,"error":...}。"""
    paths = ember_files(state_dir)
    if not paths:
        return {"ok": False, "error": "no_ember", "detail": "no .gatekeeper.ember.*.json under state dir"}
    if phase:
        want = ".gatekeeper.ember." + re.sub(r"[^A-Za-z0-9_-]", "_", phase) + ".json"
        hit = os.path.join(state_dir, want)
        if os.path.isfile(hit):
            return {"ok": True, "path": hit}
        for p in paths:  # 容错：phase 名未消毒时按 basename 匹配
            if os.path.basename(p) == want or _phase_from_name(p) == phase:
                return {"ok": True, "path": p}
        return {"ok": False, "error": "phase_not_found",
                "detail": "no ember snapshot for phase=" + str(phase), "available": [_phase_from_name(p) for p in paths]}
    return {"ok": True, "path": paths[0]}


def load_ember(path: str) -> dict:
    """加载余烬并做体积门禁（超限 → {"error":"too_large",...} 显式 SKIP，不静默截断）。"""
    size = os.path.getsize(path)
    cap = _max_bytes()
    if size > cap:
        return {"error": "too_large", "path": path, "size_bytes": size, "cap_bytes": cap}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        return {"error": "unreadable", "path": path, "detail": str(e)}


def snapshot_pair(path: str) -> dict:
    """A6-T3（2026-09-15）：**同源 (state, journal) 对**的单一取数接口（库函数）。

    跨代际 `μ` 反推需要"同一导出时刻的 (findings 账, journal)"——ember 余烬快照天然满足
    （每份内嵌**导出时刻的整份** `finding_journal` + `gate_data_full`）。

    **契约（判据）**：同一快照路径 ⟹ **任何消费者**调用本函数取到的
    `(gate_data_full.ecc_findings, 内嵌 journal)` **逐字相同** ⟹ **禁**各写一份读取器
    （F-REV-41 同族：字段链断裂 / 第二实现漂移）。故本函数**复用**同模块既有唯一读取器
    `load_ember` 与唯一 journal 解析器 `_parse_journal_lines`，**不新增第二份加载逻辑**。

    返回：{"ok":True, "path","phase","ecc_findings","journal"(原始行 list[str]),
           "journal_events","corrupt_lines"}；失败 → {"ok":False,"error","detail"?}。
    """
    try:
        ember = load_ember(path)
    except Exception as e:  # noqa: BLE001 — 缺失/不可读须**显式**返回，禁抛穿（消费者要判决）
        return {"ok": False, "path": path, "error": "unreadable",
                "detail": f"{type(e).__name__}: {e}"[:200]}
    if not isinstance(ember, dict) or "error" in ember:
        err = ember.get("error", "unreadable") if isinstance(ember, dict) else "unreadable"
        det = ember.get("detail", "") if isinstance(ember, dict) else ""
        return {"ok": False, "path": path, "error": str(err), "detail": str(det)[:200]}
    if "finding_journal" not in ember:
        # pre-C8 epoch：无 finding_journal 字段 ⟹ **显式降级**（同 reconcile 的豁免口径），
        # 禁静默当空 journal —— 空 journal 会产出假"零事件"结论。
        return {"ok": False, "path": path, "error": "no_finding_journal",
                "detail": "pre-C8 快照无 finding_journal 字段 ⟹ 无同源 journal，"
                          "跨代际 μ 反推不可用"}
    lines = list(ember.get("finding_journal", []) or [])
    events, corrupt = _parse_journal_lines(lines)
    findings = list((ember.get("gate_data_full", {}) or {}).get("ecc_findings", []) or [])
    return {"ok": True, "path": path, "phase": _phase_from_name(path),
            "ecc_findings": findings, "journal": lines,
            "journal_events": events, "corrupt_lines": corrupt}


def canonical_bytes(payload: dict) -> bytes:
    """A3 seal 字节契约：规范化 JSON（sort_keys + 紧凑分隔符 + UTF-8），seal 字段自排除。"""
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def pubkey_path(audit_key_dir: str = "") -> str:
    d = audit_key_dir or os.environ.get("_AUDIT_KEY_DIR", "")
    if not d:
        d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".keys")
    return os.path.join(d, "audit_ed25519.pub")


def verify_ed25519(pub_key_file: str, sig_b64: str, message: bytes) -> dict:
    """**唯一** Ed25519 验签原语（封印实现单源，2026-10-07；审计署计划 §9/§11 C-5）。

    消费方 = 本模块 `verify_seal`（余烬 dict）+ `gk_budget_ledger.verify_seal` /
    `gk_credit_ledger.verify_seal`（旁挂账本文件）。**禁第三实现**。
    返回 {status: verified|invalid|unverified_no_key|error, detail?}。
    """
    if load_pem_public_key is None or InvalidSignature is None:
        return {"status": "unverified_no_key", "detail": "cryptography 不可用，验签降级"}
    if not os.path.isfile(pub_key_file):
        return {"status": "unverified_no_key", "detail": "audit pubkey 不存在: " + pub_key_file}
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return {"status": "invalid", "detail": "sig 非合法 base64"}
    if len(sig) != 64:
        return {"status": "invalid", "detail": "sig len=" + str(len(sig)) + " != 64"}
    try:
        pub = load_pem_public_key(open(pub_key_file, "rb").read())
        pub.verify(sig, message)
    except InvalidSignature:
        return {"status": "invalid", "detail": "Ed25519 验签失败（协调篡改/密钥轮换）"}
    except Exception as e:
        return {"status": "error", "detail": "verify exception: " + str(e)}
    return {"status": "verified"}


def verify_seal(ember: dict, audit_key_dir: str = "") -> dict:
    """A3 读侧验签：返回 {status: verified|invalid|unverified_no_seal|unverified_no_key|error,...}。

    Ed25519 验签**委托**唯一原语 `verify_ed25519`（单源收敛，2026-10-07）。
    """
    seal = ember.get("seal")
    if not seal:
        return {"status": "unverified_no_seal", "detail": "seal 缺失（pre-A3/未签），回判=best-effort 诊断"}
    if seal.get("alg") != "ed25519":
        return {"status": "invalid", "detail": "seal alg=" + str(seal.get("alg")) + " != ed25519"}
    payload = {k: v for k, v in ember.items() if k != "seal"}
    r = verify_ed25519(pubkey_path(audit_key_dir), seal.get("sig", ""), canonical_bytes(payload))
    if r.get("status") == "verified":
        return {"status": "verified", "key": seal.get("key"), "key_fp": seal.get("key_fp")}
    return r


def _parse_journal_lines(lines) -> tuple:
    """ember finding_journal（list[str]）→ (events, corrupt)；损坏行=清洗/截断候选。"""
    events, corrupt = [], 0
    for line in lines or []:
        line = str(line).strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except ValueError:
            corrupt += 1
    return events, corrupt


def _hook_block_slice_anomalies(ember: dict) -> tuple:
    """hook_block_log 切片回判（2026-09-06 ㉕a，承接 ㉕① 实证修正——管道已通、补回放消费端）。

    Best-effort 完整性/一致性（无权威"该拦"基准，不做对抗级判定，同 C3 ⑤ 自证极限哲学）：
    - prev_entry.hook_block_log（意图记忆 last-24 归档切片）应为 gate_data_full.hook_block_log
      同快照窗口的**尾部子序列**；漂移 = 记忆改写/烧失候选。
    - 条目非 dict / 缺 reason → malformed（意图记忆烧失候选）。
    - 两字段均缺 = pre-hook-block epoch（2026-09-02 前）→ 豁免（空，不误报）。
    返回 (anomalies, {full, prev})。
    """
    gd = ember.get("gate_data_full", {}) or {}
    full = gd.get("hook_block_log") or []
    prev = (ember.get("prev_entry", {}) or {}).get("hook_block_log") or []
    if not isinstance(full, list) or not isinstance(prev, list):
        return [{"fid": "*", "status": "",
                 "reason": "hook_block_log 非列表形态（损坏快照）"}], {"full": "?", "prev": "?"}
    # ECC-727423471579（2026-10-07 质询跨臂共识）：**同源前提门**。`prev_entry` 取被审 state 本
    #   身（导出侧新记 `prev_entry_source`），而 `gate_data_full` 在域态 gate_data 为空时**回落**
    #   权威 default state（`gate_data_source`，ECC-F8DC9418D005）。二者**异源**时尾部子序列比较
    #   **无判据力**（真断链 ≡ 跨源伪链，不可区分）⟹ 禁据其报「切片漂移/归档接线缺失」假异常；
    #   显式降级 `baseline_cross_state`（留痕，**非静默豁免**）。
    _gd_src = str(ember.get("gate_data_source") or "")
    _pe_src = str(ember.get("prev_entry_source") or "")
    if _gd_src and _pe_src and _gd_src != _pe_src:
        return [], {"full": len(full), "prev": len(prev), "baseline_cross_state": True,
                    "gate_data_source": _gd_src, "prev_entry_source": _pe_src}
    out = []
    for i, e in enumerate(prev):
        if not isinstance(e, dict) or not e.get("reason"):
            out.append({"fid": "*", "status": "",
                        "reason": f"prev_entry.hook_block_log[{i}] 条目损坏/缺 reason（意图记忆烧失候选）"})
    if prev:
        tail = full[-len(prev):] if full else []
        if tail != prev:
            out.append({"fid": "*", "status": "",
                        "reason": "hook_block_log 切片漂移：prev_entry 归档段≠gate_data_full 同窗口尾部（"
                                  + str(len(prev)) + " 条）——记忆改写/烧失候选"})
    elif full:
        out.append({"fid": "*", "status": "",
                    "reason": "gate_data_full 含 hook_block_log 但 prev_entry 无归档切片（归档接线缺失）"})
    return out, {"full": len(full), "prev": len(prev)}


def reconcile_ember(ember_path: str, audit_key_dir: str = "") -> dict:
    """archived 回判（C10 核心）：相位作用域 slice 对账 + seal 验签 + epoch 豁免。"""
    base = {"check": "ember_replay_audit", "ember_path": ember_path,
            "phase": _phase_from_name(ember_path), "run_at": _now()}
    ember = load_ember(ember_path)
    if "error" in ember:
        base.update({"ok": True, "gate": {"ok": False, "verdict": "skip"},
                     "skip": ember["error"], "detail": ember.get("detail", "")})
        return base
    base["r_phase"] = ember.get("r_phase")
    base["archived_at"] = ember.get("archived_at")
    base["seal"] = verify_seal(ember, audit_key_dir)

    # pre-C8 epoch：无 finding_journal 字段 → 豁免/INFO（不产 critical 回判，防全量假阳性）
    if "finding_journal" not in ember:
        base.update({"ok": True, "epoch": "pre-c8", "gate": {"ok": True, "verdict": "epoch-exempt"},
                     "detail": "pre-C8 快照无 finding_journal 字段，回判豁免（INFO），仅 seal 可验"})
        return base
    base["epoch"] = "c8+"

    events, corrupt = _parse_journal_lines(ember.get("finding_journal"))
    findings = (ember.get("gate_data_full", {}) or {}).get("ecc_findings", []) or []
    hbl_anoms, hbl_stat = _hook_block_slice_anomalies(ember)
    if not findings:
        _hb_ok = not hbl_anoms
        base.update({"ok": True,
                     "gate": {"ok": _hb_ok, "verdict": "anomalies" if hbl_anoms else "no-findings"},
                     "reconcile": {"ok": _hb_ok, "events": len(events), "findings": 0,
                                   "out_of_scope": len(events), "anomalies": hbl_anoms,
                                   "hook_block": hbl_stat},
                     "detail": "本相位无归档 ECC finding（相位作用域内无对账对象）"
                               + ("；hook_block 切片一致性异常" if hbl_anoms else "")})
        return base

    # 事件数门禁（有界 O(n)）
    if len(events) > _max_events():
        base.update({"ok": True, "gate": {"ok": False, "verdict": "skip"},
                     "skip": "events_cap", "detail": "journal events=" + str(len(events))
                     + " > EMBER_EVENTS_MAX=" + str(_max_events())})
        return base

    # 相位作用域：只对 fid ∈ archived findings 的事件对账（跨相位合法 closure 不误报残留）
    ids = {str(f.get("id")) for f in findings if f.get("id")}
    scoped = [e for e in events if str(e.get("fid", "")) in ids]
    out_of_scope = len(events) - len(scoped)

    anomalies = []
    if corrupt:
        anomalies.append({"fid": "*", "status": "",
                          "reason": "journal " + str(corrupt) + " 行损坏/非法 JSON（清洗或截断候选）"})
    rec = reconcile_pair(findings, scoped)
    # 精确化"journal 缺失"语义：作用域内无事件但存在 out-of-scope 事件 → 相位锚缺失（跨相位清洗候选）
    if rec["anomalies"] and not scoped and events:
        rec["anomalies"] = [a for a in rec["anomalies"] if a.get("fid") == "*"]
        if out_of_scope:
            rec["anomalies"].append({"fid": "*", "status": "",
                                     "reason": "作用域内无 journal 事件（仅 " + str(out_of_scope)
                                     + " 条 out-of-scope 事件）——本相位裁决无对账锚"})
    anomalies = hbl_anoms + rec["anomalies"] + anomalies

    integrity_ok = base["seal"]["status"] not in ("invalid", "error")
    gate_ok = (not anomalies) and integrity_ok
    verdict = "consistent" if not anomalies else "anomalies"
    if not integrity_ok:
        verdict = "integrity-" + base["seal"]["status"]
    base.update({
        "ok": True,
        "reconcile": {"ok": not anomalies, "events": len(scoped), "findings": len(findings),
                      "out_of_scope": out_of_scope, "journal_total": len(events),
                      "anomalies": anomalies, "hook_block": hbl_stat},
        "gate": {"ok": gate_ok, "verdict": verdict},
    })
    return base


def _summary(ember: dict, path: str) -> dict:
    gd = ember.get("gate_data_full", {}) or {}
    findings = gd.get("ecc_findings", []) or []
    return {
        "phase": _phase_from_name(path),
        "path": path,
        "archived_at": ember.get("archived_at"),
        "r_phase": ember.get("r_phase"),
        "size_bytes": os.path.getsize(path),
        "has_seal": "seal" in ember,
        "findings": len(findings),
        "journal_lines": len(ember.get("finding_journal", []) or []),
    }


def main(argv: list = None) -> int:
    """CLI 入口。argv 注入（对齐 gk_json/gk_num/gk_req_body 清理后的约定）：

    - argv=None → sys.argv[1:]（脚本直跑）；测试直接传列表，无需 monkeypatch sys.argv
    - 解析纪律对齐 gk_finding（2026-09-05）：未知 --flag → 显式 usage 错误 exit 1，不静默
    """
    args = list(sys.argv[1:] if argv is None else argv)
    # §18.2 判据 c3（2026-10-04）：declared-but-unresolved（指针 stale/dangling）⟹ 禁静默读 base。
    from gk_state_route import read_point_pointer_error
    _rp_err = read_point_pointer_error()
    if _rp_err:
        print(json.dumps(_rp_err, ensure_ascii=False))
        return 1
    if not args or args[0] not in ("list", "get", "verify", "reconcile"):
        print(json.dumps({"ok": False, "error": "usage: gk_ember_replay.py <list|get|verify|reconcile>"
                          " --state-file <path> [--phase <p>] [--audit-key-dir <dir>] [--out <f>]"},
                         ensure_ascii=False))
        return 1
    cmd, rest = args[0], args[1:]
    state_file, phase, audit_key_dir, out = "", "", "", ""
    i = 0
    while i < len(rest):
        if rest[i] == "--state-file" and i + 1 < len(rest):
            state_file, i = rest[i + 1], i + 2
        elif rest[i] == "--phase" and i + 1 < len(rest):
            phase, i = rest[i + 1], i + 2
        elif rest[i] == "--audit-key-dir" and i + 1 < len(rest):
            audit_key_dir, i = rest[i + 1], i + 2
        elif rest[i] == "--out" and i + 1 < len(rest):
            out, i = rest[i + 1], i + 2
        else:
            print(json.dumps({"ok": False, "error": "unknown arg: " + str(rest[i])}, ensure_ascii=False))
            return 1
    if not state_file:
        state_file = os.environ.get("STATE_FILE", "")
    if not state_file or not os.path.isfile(state_file):
        print(json.dumps({"ok": False, "error": "state_file required (missing or not a file)"}, ensure_ascii=False))
        return 1
    state_dir = os.path.dirname(state_file)
    resolved = resolve_ember(state_dir, phase)
    if not resolved["ok"]:
        print(json.dumps(resolved, ensure_ascii=False))
        return 0  # 可操作空结果（无余烬/相位不存在 → ok:false 但非脚本错误），对齐 finding reconcile SKIP 语义
    path = resolved["path"]

    if cmd == "list":
        result = {"ok": True, "command": "list", "snapshots": [_summary(load_ember(p), p) for p in ember_files(state_dir)]}
    elif cmd == "get":
        ember = load_ember(path)
        if "error" in ember:
            result = {"ok": True, "command": "get", "skip": ember["error"]}
        else:
            result = {"ok": True, "command": "get", "snapshot": _summary(ember, path),
                      "seal": verify_seal(ember, audit_key_dir)}
    elif cmd == "verify":
        ember = load_ember(path)
        result = {"ok": True, "command": "verify", "phase": _phase_from_name(path),
                  "seal": verify_seal(ember, audit_key_dir) if "error" not in ember
                  else {"status": "skip", "detail": ember["error"]}}
    else:  # reconcile
        result = reconcile_ember(path, audit_key_dir)
        result["command"] = "reconcile"
        if out:
            try:
                os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
                with open(out, "w", encoding="utf-8") as f:
                    json.dump(result, f, ensure_ascii=False, indent=1)
                result["trace_out"] = out  # 痕迹独立对象（防 report→prev_entry→余烬→replay 自指回环）
            except OSError as e:
                result["trace_error"] = str(e)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
