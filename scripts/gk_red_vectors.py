#!/usr/bin/env python3
"""gk_red_vectors.py — 红队向量登记表**单源读取器**（2026-11-01，向量数据化）。

定位：`references/red-vectors.json` = 向量**唯一事实源**（谁、归哪站、看什么面、何时复核过）；
`scripts/_red_attacks.py` = **执行器**（只产出 findings，不再持有第二份清单语义）。
本模块只做四件事：**读 / 校验 / 覆盖率 / stale** —— 禁在别处再列第二份向量名单。

为什么（2026-11-01 实测）：原实现 2343 行 / 22 个函数 / ~190 处 `RED-*` 字面量全静态，
无锚点、无复核期、无站点覆盖判据 ⟹ 行号引用漂了 5400 行（`_CMD_REG` L4592 vs 9998）也无人察觉。

用法（确定性、0 网络）：
  python gk_red_vectors.py list [--station RED-HOOK] [--severity high]
  python gk_red_vectors.py check [--skill-dir DIR] [--today YYYY-MM-DD]
  python gk_red_vectors.py coverage
  python gk_red_vectors.py stale [--today YYYY-MM-DD] [--grace-days 0]

契约（fail-loud）：
  · `check` 发现任何不一致 → `{"ok": false, "errors": [...]}` + **exit 2**；
  · 登记表缺失/结构非法 → `ValueError`（调用方自行决定 SKIP 还是 FAIL）；
  · 代码 ↔ 登记表 **双向集合等价**：多一条、少一条都算错（防「加了向量没登记」与
    「登记了永远不会触发的死向量」）。
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

_SKILL_DIR = Path(__file__).resolve().parent.parent
_REGISTRY = _SKILL_DIR / "references" / "red-vectors.json"
_CODE = _SKILL_DIR / "scripts" / "_red_attacks.py"
_CHAIN = _SKILL_DIR / "scripts" / "gk_chain.py"
SCHEMA = "gk-red-vectors/1"

_ID_RE = re.compile(r'"id":\s*(f?)"((?:[^"\\]|\\.)+)"')
_TUPLE_RE = re.compile(
    r'\(\s*"(RED-[A-Z0-9]+(?:-[A-Z0-9]+)+)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*,'
    r'.{0,400}?"(critical|high|medium|low|info)"', re.S)
_STEP_RE = re.compile(r'Step\("(RED-[A-Z0-9-]+)"')


def load(path: str = "") -> dict:
    """读登记表并做结构校验；结构非法 → ValueError（调用方 fail-loud）。"""
    p = Path(path) if path else _REGISTRY
    if not p.is_file():
        raise ValueError("向量登记表缺失: " + str(p))
    data = json.loads(p.read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA:
        raise ValueError("登记表 schema 非 %s: %r" % (SCHEMA, data.get("schema")))
    for key in ("stations", "vectors", "dynamic_patterns"):
        if not isinstance(data.get(key), list):
            raise ValueError("登记表缺少列表字段: " + key)
    ids = [v.get("id") for v in data["vectors"]]
    if len(ids) != len(set(ids)):
        raise ValueError("登记表存在重复向量 id")
    return data


def vector_ids(reg: dict) -> list:
    return [v["id"] for v in reg["vectors"]]


def by_station(reg: dict) -> dict:
    out = {}
    for v in reg["vectors"]:
        out.setdefault(v["station"], []).append(v["id"])
    return out


def scan_code(text: str, station_ids=()) -> dict:
    """从 `_red_attacks.py` 正文抽取向量：静态 id 集合 + 动态模板集合。

    `station_ids` 里的站名不算向量（它们是阶段名，出现在 docstring / phases 列表里）。
    """
    static, dynamic = set(), set()
    for m in _ID_RE.finditer(text):
        vid = m.group(2)
        if "{" in vid:
            dynamic.add(vid)
        elif vid not in station_ids:
            static.add(vid)
    for m in _TUPLE_RE.finditer(text):
        static.add(m.group(1))
    return {"static": sorted(static), "dynamic": sorted(dynamic)}


def station_ids(reg: dict) -> set:
    return {s["id"] for s in reg["stations"]}


def chain_stations(path: str = "") -> list:
    """`gk_chain.py` 的红队站序列（站点权威源）；解析失败返回 []。"""
    p = Path(path) if path else _CHAIN
    try:
        return _STEP_RE.findall(p.read_text(encoding="utf-8"))
    except OSError:
        return []


def coverage(reg: dict) -> dict:
    """站点覆盖：每站有多少向量 / 是否 dynamic-only / 是否有豁免理由。"""
    per = by_station(reg)
    out = {}
    for s in reg["stations"]:
        out[s["id"]] = {"kind": s.get("kind", "station"),
                        "fn": s.get("fn", ""),
                        "vectors": len(per.get(s["id"], [])),
                        "dynamic_only": bool(s.get("dynamic_only")),
                        "exempt": bool(s.get("no_vectors_reason"))}
    return out


def stale(reg: dict, today: str, grace_days: int = 0) -> list:
    """复核过期：`verified_at + ttl_days + grace_days < today` ⟹ stale。

    日期一律 `YYYY-MM-DD`；`verified_at` 缺失/非法 ⟹ 视为 stale（未复核不能算新鲜）。
    """
    import datetime
    try:
        t0 = datetime.date.fromisoformat(today)
    except ValueError:
        raise ValueError("today 需为 YYYY-MM-DD: %r" % today)
    out = []
    for v in reg["vectors"]:
        try:
            base = datetime.date.fromisoformat(str(v.get("verified_at") or ""))
            ttl = int(v.get("ttl_days"))
        except (ValueError, TypeError):
            out.append({"id": v["id"], "reason": "verified_at/ttl_days 不可解析"})
            continue
        if base + datetime.timedelta(days=ttl + grace_days) < t0:
            out.append({"id": v["id"], "verified_at": base.isoformat(),
                        "ttl_days": ttl, "reason": "复核过期"})
    return out


def file_last_change_dates(skill_dir: str = "") -> dict:
    """`{相对路径: 最后一次提交日期(YYYY-MM-DD)}`（git；失败 ⟹ {}）。

    用途 = **锚点失效**：锚点文件在 `verified_at` 之后被改过 ⟹ 该向量须人工复核
    （与 finding 的「diff 触及 auto-reopen」同一口径）。只读 git，不写盘。
    """
    sd = str(skill_dir or _SKILL_DIR)
    try:
        r = subprocess.run(["git", "-C", sd, "log", "--date=short",
                            "--pretty=format:%cs", "--name-only"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return {}
    if r.returncode != 0:
        return {}
    out, cur = {}, ""
    for ln in (r.stdout or "").splitlines():
        s = ln.strip()
        if not s:
            continue
        if re.match(r"^\d{4}-\d{2}-\d{2}$", s):
            cur = s
        elif cur and s not in out:
            out[s] = cur          # git log 新→旧：首次出现即最近一次改动
    return out


def reopen(reg: dict, skill_dir: str = "", dates: dict = None) -> dict:
    """锚点复核：`anchor` 文件最后改动日期 > `verified_at` ⟹ 该向量「待复核」。

    **不自动改登记表**（复核是人的动作）；只产出清单，供 `stamp --ids` 回填 verified_at。
    """
    dates = dates if dates is not None else file_last_change_dates(skill_dir)
    rows = []
    for v in reg["vectors"]:
        rel = str(v.get("anchor") or "").split("::")[0]
        last = dates.get(rel)
        if last and last > str(v.get("verified_at") or ""):
            rows.append({"id": v["id"], "anchor": v.get("anchor"),
                         "verified_at": v.get("verified_at"), "last_change": last})
    return {"ok": True, "count": len(rows), "reopened": rows,
            "scanned_files": len(dates)}


def propose_promotion(finding: dict, today: str = "") -> dict:
    """把 finding 晋升为向量的**提案**（不写表）——带**防飞轮自证**闸。

    「红队产出 ECC → ECC 变成向量 → 向量再产 ECC」会自我强化；本函数要求**独立证据**：
      ① `status == confirmed`；② 有 `repro_cmd`（可复现）；③ 有 `pre_fix_commit`
    （修复前必红）；④ `source` 属红队自产时，必须有 `independent_verification`
    （外部引用 / 第三方复现 / 独立会话复验），否则拒绝升格。
    """
    import datetime
    errs = []
    if str(finding.get("status") or "") != "confirmed":
        errs.append("finding 未 confirmed")
    ev = finding.get("evidence") or {}
    for k in ("repro_cmd", "pre_fix_commit"):
        if not str(ev.get(k) or "").strip():
            errs.append("缺少独立证据字段: evidence." + k)
    src = str(finding.get("source") or finding.get("by") or "")
    if src.lower().startswith("red") and not str(ev.get("independent_verification") or "").strip():
        errs.append("红队自产 finding 缺 independent_verification（防飞轮自证）")
    if str(finding.get("severity") or "") not in ("critical", "high", "medium", "low", "info"):
        errs.append("severity 非法: %r" % finding.get("severity"))
    if errs:
        return {"ok": False, "errors": errs}
    fid = str(finding.get("id") or "")
    return {"ok": True, "candidate": {
        "id": "RED-PROMOTED-" + fid if fid else "",
        "station": finding.get("station") or "",
        "fn": finding.get("fn") or "",
        "severity": finding.get("severity"),
        "title": str(finding.get("title") or "")[:160],
        "surface": str(finding.get("surface") or ""),
        "anchor": finding.get("anchor") or "",
        "introduced": str(ev.get("pre_fix_commit")),
        "verified_at": today or datetime.date.today().isoformat(),
        "ttl_days": 180,
        "source": "finding:" + fid,
        "external_ref": str(ev.get("independent_verification") or ""),
    }}


def stamp(reg: dict, ids, today: str, path: str = "") -> dict:
    """人工复核回填：把指定 id 的 `verified_at` 改成 `today` 并**写回**登记表。

    只接受显式 id 清单（禁 `--all` 无脑刷新：那会把「没看的」也标成「看过」）。
    """
    import datetime
    try:
        datetime.date.fromisoformat(today)
    except ValueError:
        return {"ok": False, "error": "today 需为 YYYY-MM-DD: %r" % today}
    want = set(ids or [])
    if not want:
        return {"ok": False, "error": "须显式给 --ids（禁全量刷新）"}
    hit, miss = [], []
    for v in reg["vectors"]:
        if v["id"] in want:
            v["verified_at"] = today
            hit.append(v["id"])
    miss = sorted(want - set(hit))
    if not hit:
        return {"ok": False, "error": "未命中任何向量", "missed": miss}
    p = Path(path) if path else _REGISTRY
    p.write_text(json.dumps(reg, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return {"ok": True, "stamped": hit, "missed": miss, "path": str(p)}


# 站点 → 观察面（station 级 surface；逐向量细化留给后续人工，不臆造）
STATION_SURFACE = {
    "RED-SCOPE": ".gatekeeper.state 敏感字段 / 未签名决议 / 审计日志缺失",
    "RED-SURFACE": "gatekeeper-cli.sh::_CMD_REG（命令面 / gate_level / side_effects）",
    "RED-CONSTRAINTS": "PROTECTED_REGION / gate_level / 永久拒绝门",
    "RED-EXPLOIT": "state 篡改 / 注入倾向字段 / 无 checksum",
    "RED-POSTEX": "Ed25519 验签 / 熵值合法性",
    "RED-REPORT": "报告汇总（无独立向量）",
    "RED-HINT": "advance hint 注入完整性（各站 checklist / gates / tool_policy）",
    "RED-HOOK": "scripts/pre_tool_hook.py 门禁链（Gate 0-9 + R0.x）",
    "RED-PY": "scripts/*.py 自检与解释器面",
    "RED-POISON": "references/*.json / 子代理上下文投毒面",
    "RED-REGISTRY": "元数据路由 / 注册表归属",
    "RED-GHOST": "高威胁幽灵面（未登记读取 / 越权输出）",
    "RED-COVERAGE": "审计覆盖缺口（文档/测试/检查器）",
    "RED-DIFF": "契约模型 ↔ 实现的差分对拍",
    "RED-INTEGRITY": "产品代码 fail-open / fail-closed 模式",
    "RED-AIG": "AI-Infra-Guard（仅 KVM 沙箱）",
    "RED-BOOTSTRAP": "引导链完整性",
    "RED-ROUTE": "路由中心 / worktree 白名单",
    "RED-RECUR": "递归自改（loader/pid 守卫）",
    "RED-CTX": "subagent-context.json 签名发布竞态",
    "RED-MIGRATE": "bash→Python 迁移残留",
    "RED-POISON-MATRIX": "投毒矩阵（跨文件组合面）",
}


def first_seen_dates(skill_dir: str = "", ids=None,
                     src_rel: str = "scripts/_red_attacks.py") -> dict:
    """每个向量 id **首次出现**的提交日期（`git log -S<id> --reverse`）。

    用于回填 `introduced`（「这条向量什么时候进来的」）。git 不可用 ⟹ {}，不猜。
    """
    sd = str(skill_dir or _SKILL_DIR)
    out = {}
    for vid in (ids or []):
        try:
            r = subprocess.run(["git", "-C", sd, "log", "-S", str(vid), "--format=%cs",
                                "--reverse", "--", src_rel],
                               capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            continue
        lines = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
        if lines and re.match(r"^\d{4}-\d{2}-\d{2}$", lines[0]):
            out[str(vid)] = lines[0]
    return out


def backfill(reg: dict, skill_dir: str = "", path: str = "", apply: bool = False,
             dates: dict = None) -> dict:
    """回填 `surface`（站点级）与 `introduced`（git 首次出现）；默认 dry-run。"""
    if dates is None:
        need = [v["id"] for v in reg["vectors"] if not v.get("introduced")]
        dates = first_seen_dates(skill_dir, need)
    filled = {"surface": 0, "introduced": 0}
    for v in reg["vectors"]:
        if not str(v.get("surface") or "").strip():
            s = STATION_SURFACE.get(str(v.get("station") or ""), "")
            if s:
                v["surface"] = s
                v["surface_kind"] = "station"
                filled["surface"] += 1
        if not v.get("introduced"):
            d = dates.get(v["id"])
            if d:
                v["introduced"] = d
                filled["introduced"] += 1
    if apply and (filled["surface"] or filled["introduced"]):
        p = Path(path) if path else _REGISTRY
        p.write_text(json.dumps(reg, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return {"ok": True, "applied": bool(apply), "filled": filled,
            "unresolved_introduced": sorted(v["id"] for v in reg["vectors"]
                                            if not v.get("introduced"))[:20]}


def load_external(path: str = "") -> dict:
    p = Path(path) if path else (_SKILL_DIR / "references" / "red-external-map.json")
    if not p.is_file():
        raise ValueError("外部映射表缺失: " + str(p))
    data = json.loads(p.read_text(encoding="utf-8"))
    if data.get("schema") != "gk-red-external-map/1":
        raise ValueError("外部映射表 schema 非法")
    return data


def external_map(reg: dict, ext: dict = None) -> dict:
    """外部框架 → 站点映射校验 + 覆盖统计（引用不存在的站点 ⟹ FAIL）。"""
    ext = ext or load_external()
    sids = station_ids(reg)
    errors, coverage = [], {}
    for fw, body in (ext.get("frameworks") or {}).items():
        entries = body.get("entries") or []
        covered, gaps = set(), 0
        for e in entries:
            for st in e.get("stations") or []:
                if st not in sids:
                    errors.append("%s/%s: 未登记站点 %s" % (fw, e.get("id"), st))
                else:
                    covered.add(st)
            if e.get("gap"):
                gaps += 1
        coverage[fw] = {"entries": len(entries), "stations_covered": len(covered),
                        "stations": sorted(covered), "entries_with_gap": gaps}
    return {"ok": not errors, "errors": errors, "coverage": coverage}


def _anchor_ok(anchor: str, skill_dir: Path) -> str:
    """anchor `<相对路径>::<符号>` → "" 表示 OK，否则返回错误原因。"""
    if not anchor or "::" not in anchor:
        return "anchor 需为 `<相对路径>::<符号>`: %r" % anchor
    rel, sym = anchor.split("::", 1)
    p = skill_dir / rel
    if not p.is_file():
        return "anchor 文件不存在: " + rel
    try:
        body = p.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return "anchor 不可读: %s (%s)" % (rel, type(e).__name__)
    if sym and ("def %s(" % sym) not in body and ("%s() {" % sym) not in body:
        return "anchor 符号不存在: %s::%s" % (rel, sym)
    return ""


def check(skill_dir: str = "", code_text: str = None) -> dict:
    """机检主体：代码↔登记表集合等价 + 动态模板一致 + 站点覆盖 + 站点权威一致 + anchor。"""
    sd = Path(skill_dir) if skill_dir else _SKILL_DIR
    try:
        reg = load(str(sd / "references" / "red-vectors.json"))
    except (OSError, ValueError, json.JSONDecodeError) as e:
        return {"ok": False, "errors": ["登记表不可用: %s" % e]}
    if code_text is None:
        try:
            code_text = (sd / "scripts" / "_red_attacks.py").read_text(encoding="utf-8")
        except OSError as e:
            return {"ok": False, "errors": ["执行器不可读: %s" % e]}

    errors = []
    sids = station_ids(reg)
    code = scan_code(code_text, sids)
    reg_ids = set(vector_ids(reg))
    code_ids = set(code["static"])
    for vid in sorted(code_ids - reg_ids):
        errors.append("向量未登记（代码有、表无）: " + vid)
    for vid in sorted(reg_ids - code_ids):
        errors.append("死向量（表有、代码无）: " + vid)
    reg_dyn = {d["pattern"] for d in reg["dynamic_patterns"]}
    for pat in sorted(set(code["dynamic"]) - reg_dyn):
        errors.append("动态模板未登记: " + pat)
    for pat in sorted(reg_dyn - set(code["dynamic"])):
        errors.append("动态模板已失效: " + pat)

    for s in reg["stations"]:
        n = len(by_station(reg).get(s["id"], []))
        if n == 0 and not s.get("dynamic_only") and not s.get("no_vectors_reason"):
            errors.append("站点无向量且无豁免理由: " + s["id"])
    for v in reg["vectors"]:
        if v.get("station") not in sids:
            errors.append("向量的站点未登记: %s → %r" % (v["id"], v.get("station")))
        why = _anchor_ok(str(v.get("anchor") or ""), sd)
        if why:
            errors.append("%s: %s" % (v["id"], why))

    ch = chain_stations(str(sd / "scripts" / "gk_chain.py"))
    if ch:
        declared = {s["id"] for s in reg["stations"] if s.get("kind", "station") == "station"}
        for sid in ch:
            if sid not in declared:
                errors.append("序列站点未登记: " + sid)
        for sid in sorted(declared - set(ch)):
            errors.append("登记表站点不在序列: " + sid)

    return {"ok": not errors, "errors": errors,
            "counts": {"vectors": len(reg_ids), "code_vectors": len(code_ids),
                       "dynamic": len(reg_dyn), "stations": len(reg["stations"]),
                       "chain_stations": len(ch)}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("cmd", nargs="?", default="check")
    ap.add_argument("--skill-dir", default="")
    ap.add_argument("--today", default="")
    ap.add_argument("--grace-days", type=int, default=0)
    ap.add_argument("--station", default="")
    ap.add_argument("--severity", default="")
    ap.add_argument("--registry", default="")
    ap.add_argument("--ids", default="")
    ap.add_argument("--finding-json", default="")
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args(argv)
    import datetime
    today = a.today or datetime.date.today().isoformat()
    try:
        if a.cmd == "check":
            out = check(a.skill_dir)
        elif a.cmd == "stale":
            out = {"ok": True, "today": today,
                   "stale": stale(load(a.registry), today, a.grace_days)}
            out["count"] = len(out["stale"])
        elif a.cmd == "coverage":
            reg = load(a.registry)
            out = {"ok": True, "coverage": coverage(reg)}
        elif a.cmd == "list":
            reg = load(a.registry)
            rows = [v for v in reg["vectors"]
                    if (not a.station or v["station"] == a.station)
                    and (not a.severity or v["severity"] == a.severity)]
            out = {"ok": True, "count": len(rows), "vectors": rows}
        elif a.cmd == "reopen":
            out = reopen(load(a.registry), a.skill_dir)
        elif a.cmd == "promote":
            if not a.finding_json:
                out = {"ok": False, "error": "promote 需要 --finding-json '<json>'"}
            else:
                out = propose_promotion(json.loads(a.finding_json), today)
        elif a.cmd == "stamp":
            ids = [x.strip() for x in a.ids.split(",") if x.strip()]
            out = stamp(load(a.registry), ids, today, a.registry)
        elif a.cmd == "backfill":
            out = backfill(load(a.registry), a.skill_dir, a.registry, apply=a.apply)
        elif a.cmd == "map":
            out = external_map(load(a.registry))
        else:
            out = {"ok": False,
                   "error": "未知子命令: %s（list|check|coverage|stale|reopen|promote|stamp|backfill|map）" % a.cmd}
    except (ValueError, OSError, json.JSONDecodeError) as e:
        out = {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0 if out.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
