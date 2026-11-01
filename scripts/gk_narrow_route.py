#!/usr/bin/env python3
"""
gk_narrow_route.py — 窄任务清单 → subagent 档位路由（2026-08-28）
=================================================================
从 gate_data.narrow_tasks[] 中匹配当前 subagent 任务，返回条目声明的 tier（1-4）。
未命中 / 未声明 tier → 返回空（调用方落角色默认档位）。

契约（模板 sequence-node-safety-net-template.md §4.1）:
  gate_data.narrow_tasks[] 条目: {"id", "goal", "task", "name", "tier", ...}
  匹配规则: 当前 task 与条目 task/name 前缀或包含匹配（startswith 优先，再退化包含）。

用法:
  python3 scripts/gk_narrow_route.py --state <state.json> --task "<subagent task>"
  输出: tier 数字（命中）或空字符串（未命中）
  python3 scripts/gk_narrow_route.py --state <state.json> --register <file.json>
  输出: {"registered":true,"ids":[...]}（成功）/ {"registered":false,"issues":[...]}（exit 4）
"""
import argparse
import json
import sys
from pathlib import Path

# L4（2026-09-25）：整文件上限判据改**canonical 字节**（形态无关）—— 计量口径单源（`gk_json_utils`）。
sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_json_utils as gju  # noqa: E402 —— 计量 + **整文件墙**口径单源（运行时读，禁第二份字面量）


# 投毒清洗模式（下发前防御 — 2026-08-28）：窄任务清单是档位路由的事实源，
# 被投毒 → 任务/档位被操纵。命中任一强信号 → 该条目视为 POISON（路由拒绝 + CLI 阻断）。
# 注：这只是第一道确定性防线（强信号显式注入），深层投毒（条件植入/压缩凸显/虚假先例等）
# 需聚合器/后续研究级清洗，见 red-findings §4.9 分类表。
_POISON_MARKERS = [
    "忽略", "忽略以上", "ignore previous", "ignore all",
    "system:", "assistant:", "你现在是", "You are now",
    "小红书", "xiaohongshu", "xhs-copilot",
]

# ── 窄任务清单格式规范与复杂度管控（2026-08-28，域 2 专项）─────────────────
# 清单是下发路由/档位分配的事实源，须有界：条目数上限、字段长度上限、总大小上限。
# 超限 → 视为清单污染（拒绝下发），防"巨型清单淹没 subagent 上下文/占满注意力"。
_NT_MAX_ENTRIES = 20          # 单清单最大条目数
_NT_MAX_TASK_LEN = 650        # task 字段最大长度（2026-10-04：500→650，用户裁定）
_NT_MAX_NAME_LEN = 100        # name 字段最大长度
_NT_MAX_ID_LEN = 64           # id 字段最大长度
_NT_MAX_ENTRY_BYTES = 8192    # 单条目序列化最大字节数
_NT_MAX_TOTAL_BYTES = 65536   # 全清单序列化最大字节数（64KB）
_VALID_TIERS = {1, 2, 3, 4}   # 档位合法域（对齐 SUBA_TIERS）


def validate_entries(entries) -> list[dict]:
    """清单级 + 条目级 schema/复杂度校验（**单一事实源**）：返回违规明细
    [{"id","rule","detail"}]（无 → []）。

    规则：清单为数组、条目数/总体积有界、条目为 dict、id 必填、task/name 至少其一、
    tier∈1-4、字段长度有界。供 `validate_narrow_tasks`（state 形态）与 `register`
    （生产者路径）**共用**，杜绝常量的第二份拷贝。"""
    if not isinstance(entries, list):
        return [{"id": "?", "rule": "not_list", "detail": "narrow_tasks 非数组"}]
    if len(entries) > _NT_MAX_ENTRIES:
        return [{"id": "?", "rule": "too_many_entries",
                 "detail": f"{len(entries)} > {_NT_MAX_ENTRIES}"}]
    issues = []
    total = 0
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            issues.append({"id": f"#{i}", "rule": "entry_not_dict", "detail": str(type(e))})
            continue
        blob = json.dumps(e, ensure_ascii=False)
        total += len(blob.encode("utf-8"))
        if len(blob.encode("utf-8")) > _NT_MAX_ENTRY_BYTES:
            issues.append({"id": str(e.get("id", f"#{i}")), "rule": "entry_oversized",
                           "detail": f"{len(blob)} bytes > {_NT_MAX_ENTRY_BYTES}"})
        if not str(e.get("id", "")).strip():
            issues.append({"id": f"#{i}", "rule": "missing_id", "detail": "id 必填"})
        if len(str(e.get("id", ""))) > _NT_MAX_ID_LEN:
            issues.append({"id": str(e.get("id", ""))[:20], "rule": "id_too_long",
                           "detail": f"id > {_NT_MAX_ID_LEN}"})
        t = str(e.get("task", ""))
        n = str(e.get("name", ""))
        if not t and not n:
            issues.append({"id": str(e.get("id", f"#{i}")), "rule": "no_task_or_name",
                           "detail": "task/name 至少其一"})
        if len(t) > _NT_MAX_TASK_LEN:
            issues.append({"id": str(e.get("id", f"#{i}")), "rule": "task_too_long",
                           "detail": f"task {len(t)} > {_NT_MAX_TASK_LEN}"})
        if len(n) > _NT_MAX_NAME_LEN:
            issues.append({"id": str(e.get("id", f"#{i}")), "rule": "name_too_long",
                           "detail": f"name {len(n)} > {_NT_MAX_NAME_LEN}"})
        tier = e.get("tier")
        if tier is not None and (not str(tier).isdigit() or int(tier) not in _VALID_TIERS):
            issues.append({"id": str(e.get("id", f"#{i}")), "rule": "tier_out_of_range",
                           "detail": f"tier={tier} 合法域 {sorted(_VALID_TIERS)}"})
    if total > _NT_MAX_TOTAL_BYTES:
        issues.append({"id": "?", "rule": "list_oversized",
                       "detail": f"{total} bytes > {_NT_MAX_TOTAL_BYTES}"})
    return issues


# ── 三组窄任务的下发约束（2026-10-19）──────────────────────────────────────
# 探索跑暴露：窄任务清单只校验 schema/投毒，**不校验组语义** ⟹ K=1 时 G1 没有
# “相同对”、G2 没有“互补臂”、G3 没有污染，三组标签退化为下标；组序错位还会让
# `_group_expand_records` 的 index//K 把 G# 写错。
# 约束（grouped 模式，条目带 `group` 字段时启用；legacy 清单不检查 ⟹ 零回归）：
#   C1 每组条目数相同且 K≥2；
#   C2 组序必须 G1×K → G2×K → G3×K；
#   C3 G1：K 条 task 逐字相同、covers 相同、pair_id 相同（相同对）；
#   C4 G2：covers 两两不相交，并集 == coverage_target（正交互补）；
#   C5 G3：polluted=true + poison_claim 非空且出现在 task 文本中（污染组真的被污染）；
#   C6 每条 task 必须含输出契约 `verdict` + `SOURCES`（否则聚合侧 rho 不可测）。
_GROUPS = ("G1", "G2", "G3")
_GROUP_MIN_K = 2


def _norm_task(text) -> str:
    return " ".join(str(text or "").split())


def _covers_of(entry: dict) -> list:
    c = entry.get("covers")
    if not isinstance(c, list):
        return []
    out = []
    for x in c:
        try:
            out.append(int(x))
        except (TypeError, ValueError):
            return []
    return out


def _registry_keywords(registry, ids) -> set:
    """从 `assertion_registry` 取一组断言的判别关键词（小写）。"""
    if not isinstance(registry, dict):
        return set()
    out = set()
    for i in ids:
        v = registry.get(str(i), registry.get(i))
        vals = v if isinstance(v, list) else [v]
        for x in vals:
            s = str(x or "").strip().lower()
            if s:
                out.add(s)
    return out


def validate_group_constraints(entries, coverage_target=None,
                               assertion_registry=None, min_k=None) -> dict:
    """机检三组窄任务的下发约束（纯函数，0 写盘）。

    `min_k`：每组最小条数（缺省 `_GROUP_MIN_K`=2）。**读侧**（`gk_task_gate.submit`）按本次
    实际 K 传入 —— 显式 `--arms-per-group 1` 时传 1，仅放宽「条数下限」，`covers` / 正交 /
    污染标记等语义**一条不减**（2026-10-28：K=1 曾让整组语义静默退化）。

    G1/G2 **必须正交**：`covers(G1) ∩ covers(G2) = ∅` 且二者并集 == `coverage_target`
    （两者是目标断言集的一个**划分**）。G3 是污染探针，允许与 G1/G2 重叠。
    若提供 `assertion_registry`（断言 id → 判别关键词），再做**文本正交**机检：
    G1 的 task 不得出现 G2 断言的判别词，反之亦然。

    返回 `{mode, ok, k, counts, coverage_target, groups, orthogonality, violations}`。
    `mode=legacy`（无任何条目带 `group`）⟹ `unchecked=True`，不阻断旧清单。
    """
    ents = [e for e in (entries or []) if isinstance(e, dict)]
    grouped = [e for e in ents if str(e.get("group", "") or "").strip()]
    if not grouped:
        return {"mode": "legacy", "ok": True, "unchecked": True, "violations": []}

    violations = []

    def _add(rule, gid, detail):
        violations.append({"rule": rule, "id": str(gid or "?"), "detail": detail})

    if len(grouped) != len(ents):
        _add("mixed_group_mode", "?", "部分条目有 group、部分没有")

    seq = [str(e.get("group", "") or "").strip().upper() for e in ents]
    counts = {g: seq.count(g) for g in _GROUPS}
    unknown = sorted(set(seq) - set(_GROUPS))
    if unknown:
        _add("unknown_group", "?", "未知组别: %s" % ",".join(unknown))
    sizes = [counts[g] for g in _GROUPS]
    k = sizes[0] if sizes and len(set(sizes)) == 1 else None
    _min_k = _GROUP_MIN_K if min_k is None else int(min_k)
    if k is None or k < _min_k:
        _add("group_size_below_min", "?",
             "每组条目数须相同且 ≥%d；实测 %s" % (_min_k, counts))
    elif seq[:3 * k] != [g for g in _GROUPS for _ in range(k)]:
        _add("group_order", "?", "组序须为 G1×%d → G2×%d → G3×%d" % (k, k, k))

    ids = [str(e.get("id", "")) for e in ents]
    if len(ids) != len(set(ids)):
        _add("duplicate_id", "?", "id 必须唯一")

    for e in ents:
        g = str(e.get("group", "") or "").strip().upper()
        if not _covers_of(e):
            _add("missing_covers", e.get("id"), "covers 须为非空整数数组")
        t = _norm_task(e.get("task")).lower()
        if "verdict" not in t or "sources" not in t:
            _add("missing_output_contract", e.get("id"),
                 "task 须含 verdict=... 与 SOURCES: ...（供聚合侧测 rho）")
        if g == "G1" and not str(e.get("pair_id", "") or "").strip():
            _add("g1_missing_pair_id", e.get("id"), "G1 须声明 pair_id")

    by = {g: [e for e in ents if str(e.get("group", "") or "").strip().upper() == g]
          for g in _GROUPS}

    if len(by["G1"]) >= 2:
        if len({_norm_task(e.get("task")) for e in by["G1"]}) != 1:
            _add("g1_not_identical", "G1", "相同对要求 K 条 task 逐字相同")
        if len({tuple(_covers_of(e)) for e in by["G1"]}) != 1:
            _add("g1_covers_differ", "G1", "相同对要求 covers 相同")
        if len({str(e.get("pair_id", "")) for e in by["G1"]}) != 1:
            _add("g1_pair_id_differ", "G1", "相同对要求 pair_id 相同")

    # ── G1 × G2 正交（2026-10-19）：两者是 coverage_target 的一个划分 ──
    g1_union = set().union(*[set(_covers_of(e)) for e in by["G1"]]) if by["G1"] else set()
    g2_cov = [set(_covers_of(e)) for e in by["G2"]]
    g2_union = set().union(*g2_cov) if g2_cov else set()
    orthogonality = {
        "g1_union": sorted(g1_union),
        "g2_union": sorted(g2_union),
        "covers_disjoint": None,
        "joint_covers_target": None,
        "text": "unchecked",
    }
    if by["G1"] and by["G2"]:
        inter = g1_union & g2_union
        orthogonality["covers_disjoint"] = not inter
        if inter:
            _add("g1_g2_overlap", "G1,G2",
                 "G1/G2 必须完全正交；重叠断言 %s" % sorted(inter))
        if coverage_target is None:
            _add("coverage_target_missing", "?", "grouped 模式须给 coverage_target")
        else:
            try:
                target = {int(x) for x in coverage_target}
            except (TypeError, ValueError):
                target = set()
                _add("coverage_target_invalid", "?", str(coverage_target))
            joint = g1_union | g2_union
            orthogonality["joint_covers_target"] = (joint == target)
            if joint != target:
                _add("g1_g2_coverage_gap", "G1,G2",
                     "G1∪G2 %s != coverage_target %s" % (sorted(joint), sorted(target)))

    if len(by["G2"]) >= 2:
        for i in range(len(g2_cov)):
            for j in range(i + 1, len(g2_cov)):
                if g2_cov[i] & g2_cov[j]:
                    _add("g2_overlap", "%s,%s" % (by["G2"][i].get("id"),
                                                  by["G2"][j].get("id")),
                         "正交互补要求 covers 两两不相交：%s" %
                         sorted(g2_cov[i] & g2_cov[j]))

    # ── 文本正交（可选）：assertion_registry 提供判别词 ──
    if assertion_registry:
        orthogonality["text"] = "checked"
        g2_kw = _registry_keywords(assertion_registry, g2_union)
        g1_kw = _registry_keywords(assertion_registry, g1_union)
        for e in by["G1"]:
            hit = sorted(k for k in g2_kw if k in _norm_task(e.get("task")).lower())
            if hit:
                _add("g1_mentions_g2_assertion", e.get("id"),
                     "G1 任务出现 G2 断言判别词：%s" % hit)
        for e in by["G2"]:
            hit = sorted(k for k in g1_kw if k in _norm_task(e.get("task")).lower())
            if hit:
                _add("g2_mentions_g1_assertion", e.get("id"),
                     "G2 任务出现 G1 断言判别词：%s" % hit)

    for e in by["G3"]:
        if e.get("polluted") is not True:
            _add("g3_not_polluted", e.get("id"), "污染组须显式 polluted=true")
        claim = _norm_task(e.get("poison_claim"))
        if not claim:
            _add("g3_missing_claim", e.get("id"), "污染组须给 poison_claim")
        elif claim not in _norm_task(e.get("task")):
            _add("g3_claim_not_in_task", e.get("id"),
                 "poison_claim 必须真的写进 task 文本")

    return {
        "mode": "grouped",
        "ok": not violations,
        "k": k,
        "counts": counts,
        "coverage_target": list(coverage_target) if coverage_target is not None else None,
        "groups": {g: {"size": len(by[g]),
                       "covers": [_covers_of(e) for e in by[g]]} for g in _GROUPS},
        "orthogonality": orthogonality,
        "violations": violations,
    }


def validate_narrow_tasks(state_file: str) -> list[dict]:
    """schema/复杂度校验：返回违规明细 [{"id","rule","detail"}]（无 → []）。
    规则：条目为 dict、id/task 必填、tier∈1-4、字段长度与清单总量有界。"""
    if not state_file or not Path(state_file).is_file():
        return [{"id": "?", "rule": "state_missing", "detail": state_file}]
    try:
        raw = Path(state_file).read_bytes()
    except OSError:
        return [{"id": "?", "rule": "state_unreadable", "detail": state_file}]
    try:
        d = json.loads(raw.decode("utf-8"))
    except Exception:
        return [{"id": "?", "rule": "state_invalid_json", "detail": "non-JSON state"}]
    # L4（2026-09-25）：整文件上限判据改 **canonical 字节**（形态无关）；原为 `len(raw)` 磁盘原始字节。
    #   病根：磁盘字节随**末位写者形态**漂移 —— legacy 写者一次 `ensure_ascii=True` 就把每个 CJK
    #   逃逸成 `\uXXXX`（3B→6B）凭空 "长大"，而内容一字未变 ⟹ 硬墙**提前命中**（实测同一 state 三种
    #   写法 249,562 / 262,906 / 328,109 B：「形态本身就是体积」）。canon = 内容的真实大小 ⟹
    #   判据与形态解耦，不再因"谁最后写"而误拒。注：解析前置（原为廉价磁盘预检）—— state ~256KB，
    #   解析成本可忽略；非法 JSON 现报 `state_invalid_json`（比"超大"更准确）。
    # 2026-10-16 owner 裁定「给 state 加个0」：整文件墙**单源** —— 本判据**运行时读**
    #   `gk_json_utils.STATE_SIZE_WALL`（×10 = 2,621,440）；原内联 `_NT_MAX_TOTAL_BYTES * 4`
    #   是**第二份字面量**（改一处必漂移 ⟹ 裁定无法单点生效）。
    canon = gju.canon_bytes(d)
    if canon > gju.STATE_SIZE_WALL:
        # F-REV-51（2026-09-14）：本项**与 narrow_tasks 清单体积/格式无关** —— 是**整文件**
        # 累积触发（常见根因 gate_data.task_pipeline / subagent_history 累积）。detail 显式
        # 点明，防被 CLI hint 误读为"清单格式问题"而白改清单。
        return [{"id": "?", "rule": "state_oversized",
                 "detail": f"state canon {canon} bytes（磁盘 {len(raw)}）> 整文件上限 {gju.STATE_SIZE_WALL}"
                           "（非 narrow_tasks 清单体积；常见根因 task_pipeline/subagent_history 累积）"}]
    nt = d.get("gate_data", {}).get("narrow_tasks", []) or []
    # 单一事实源：清单级 + 条目级判据全在 `validate_entries`（此处不再复制常量逻辑）。
    return validate_entries(nt)


def poison_hits(entries) -> list[dict]:
    """扫描给定条目列表的强注入信号（**单一事实源**）。返回 [{"id","marker","tier"}]（无 → []）。"""
    hits = []
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        blob = json.dumps(e, ensure_ascii=False)
        for marker in _POISON_MARKERS:
            if marker.lower() in blob.lower():
                hits.append({"id": str(e.get("id", "?")), "marker": marker,
                             "tier": e.get("tier")})
                break
    return hits


def poison_check(state_file: str) -> list[dict]:
    """扫描 narrow_tasks[] 中携带强注入信号的条目。返回 [{"id","marker","tier"}]（无 → []）。"""
    if not state_file or not Path(state_file).is_file():
        return []
    try:
        d = json.loads(Path(state_file).read_text(encoding="utf-8"))
    except Exception:
        return []
    nt = d.get("gate_data", {}).get("narrow_tasks", []) or []
    return poison_hits(nt)


def route(state_file: str, task: str) -> str:
    """匹配 narrow_tasks[] 中声明合法 tier（1-4）且命中 task 的条目。返回 tier 字符串或 ''。"""
    if not state_file or not Path(state_file).is_file() or not task:
        return ""
    try:
        d = json.loads(Path(state_file).read_text(encoding="utf-8"))
    except Exception:
        return ""
    nt = d.get("gate_data", {}).get("narrow_tasks", []) or []
    for e in nt:
        if not isinstance(e, dict):
            continue
        tier = e.get("tier")
        if tier is None or not str(tier).isdigit() or int(tier) not in _VALID_TIERS:
            continue  # 2026-08-28: 档位越界（如 99）不参与路由（防操纵）
        t = str(e.get("task", ""))
        n = str(e.get("name", ""))
        if (t and (task.startswith(t) or t in task)) or \
           (n and (task.startswith(n) or n in task)):
            return str(tier)
    return ""


def _load_register_entries(register_file: str):
    """读 register JSON：接受**裸数组** `[{...}]` 或**包裹对象**
    `{"narrow_tasks":[...], "coverage_target":[1,2,...]}`。
    返回 (entries, meta, issues)；issues 非空 = 读取/形态错误（entries 为 None）。"""
    if not register_file or not Path(register_file).is_file():
        return None, {}, [{"id": "?", "rule": "register_file_missing",
                           "detail": register_file}]
    try:
        obj = json.loads(Path(register_file).read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001 — CLI 边界，显式失败
        return None, {}, [{"id": "?", "rule": "register_invalid_json",
                           "detail": f"{type(e).__name__}: {e}"}]
    meta = {}
    if isinstance(obj, dict):
        meta["coverage_target"] = obj.get("coverage_target")
        meta["assertion_registry"] = obj.get("assertion_registry")
        obj = obj.get("narrow_tasks", [])
    if not isinstance(obj, list):
        return None, meta, [{"id": "?", "rule": "not_list",
                             "detail": "register JSON 须为数组或 {\"narrow_tasks\":[...]}"}]
    return obj, meta, []


def _balanced_split(ids, k):
    """把有序 id 列表按 K 臂**均衡连续切分**（确定性；差 ≤1，余数给后臂）。

    余数给后臂而非前臂：与 W2A 清单既有人工分区 `[3] / [4,5]` 同构，
    显式 covers 改为缺省派生时不会产生无意义的重排 diff。
    """
    n, out, start = len(ids), [], 0
    rem = n % k
    for i in range(k):
        size = n // k + (1 if i >= k - rem else 0)
        out.append(ids[start:start + size])
        start += size
    return out


def derive_g2_covers(entries, coverage_target=None):
    """G2 covers 缺省时，由 `coverage_target \\ covers(G1)` **构造性派生**。

    正交从此不是“两处手标后校验”，而是：
      · G1 是唯一自变量；
      · G2 := target − G1（补集），再按臂序均衡切分 ⟹ 重叠在构造上不可能。
    显式给了 G2 covers ⟹ 不做派生（保留人工分区能力，仍走原机检）。
    无法派生（target/G1 缺失、补集不足 K）⟹ fail-closed issues，零写盘。
    返回 (entries, info)；成功时 entries 为**注入了 covers 的副本**。
    """
    ents = entries if isinstance(entries, list) else []
    g2_idx = [i for i, e in enumerate(ents)
              if isinstance(e, dict)
              and str(e.get("group", "") or "").strip().upper() == "G2"]
    if not g2_idx:
        return entries, {"ok": True, "mode": "no_g2"}
    if any(_covers_of(ents[i]) for i in g2_idx):
        return entries, {"ok": True, "mode": "explicit"}
    try:
        target = sorted({int(x) for x in (coverage_target or [])})
    except (TypeError, ValueError):
        return entries, {"ok": False, "mode": "derived", "issues": [
            {"id": "?", "rule": "coverage_target_invalid",
             "detail": str(coverage_target)}]}
    if not target:
        return entries, {"ok": False, "mode": "derived", "issues": [
            {"id": "?", "rule": "coverage_target_missing",
             "detail": "G2 covers 缺省时必须给 coverage_target 才能派生"}]}
    g1_union = set()
    for e in ents:
        if isinstance(e, dict) and str(e.get("group", "") or "").strip().upper() == "G1":
            g1_union |= set(_covers_of(e))
    if not g1_union:
        return entries, {"ok": False, "mode": "derived", "issues": [
            {"id": "G1", "rule": "g1_covers_missing",
             "detail": "G2 covers 缺省时 G1 必须先声明 covers（G1 是自变量）"}]}
    comp = [x for x in target if x not in g1_union]
    if len(comp) < len(g2_idx):
        return entries, {"ok": False, "mode": "derived", "issues": [
            {"id": "G2", "rule": "g2_complement_too_small",
             "detail": "补集 %s 不足以分给 %d 个 G2 臂" % (comp, len(g2_idx))}]}
    chunks = _balanced_split(comp, len(g2_idx))
    out = [dict(e) if isinstance(e, dict) else e for e in ents]
    for i, chunk in zip(g2_idx, chunks):
        out[i]["covers"] = chunk
    return out, {"ok": True, "mode": "derived",
                 "g2_union": comp, "chunks": chunks}


def register(state_file: str, register_file: str) -> tuple[dict, int]:
    """生产者：从 register JSON 载入窄任务条目，校验后**替换** `gate_data.narrow_tasks`。

    校验/投毒判据复用 `validate_entries` / `poison_hits`（单一事实源）；写盘**经由既有**
    `gk_state_patch.cmd_update_gate_data`（checksum 单一事实 + state_lock）。
    返回 (输出 JSON dict, exit code)：违规 → ({registered:false, issues:[...]}, 4)。
    """
    entries, meta, issues = _load_register_entries(register_file)
    derivation = {"ok": True, "mode": "legacy"}
    if not issues:
        # 构造性正交：G2 covers 缺省 ⟹ 由 target \\ G1 派生（显式则只校验）。
        entries, derivation = derive_g2_covers(
            entries, meta.get("coverage_target"))
        if not derivation.get("ok"):
            issues = derivation["issues"]
    if not issues:
        issues = validate_entries(entries)
    if not issues:
        # 复用 `_POISON_MARKERS`：投毒条目并入 issues（rule="poison"）。
        issues = [{"id": h["id"], "rule": "poison", "detail": h["marker"]}
                  for h in poison_hits(entries)]
    if issues:
        return {"registered": False, "issues": issues}, 4
    # 组语义约束（grouped 模式）：违规 ⟹ fail-closed，零写盘。
    constraints = validate_group_constraints(
        entries, meta.get("coverage_target"), meta.get("assertion_registry"))
    if constraints.get("mode") == "grouped" and not constraints.get("ok"):
        return {"registered": False,
                "issues": [{"id": v["id"], "rule": v["rule"], "detail": v["detail"]}
                           for v in constraints["violations"]],
                "constraints": constraints}, 4
    if not state_file or not Path(state_file).is_file():
        return {"registered": False,
                "issues": [{"id": "?", "rule": "state_missing", "detail": state_file}]}, 4
    # 写通路单源：既有 `gk_state_patch.py`（update-gate-data → gate_data 顶层 update = 替换列表）。
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import gk_state_patch  # noqa: PLC0415 — 惰性 import（保持模块导入面不变）
    payload = {"narrow_tasks": entries}
    if constraints.get("mode") == "grouped":
        # 供聚合/复核端重放同一 coverage_target / assertion_registry（单源，禁第二份推导）。
        payload["narrow_coverage_target"] = constraints.get("coverage_target")
        payload["narrow_assertion_registry"] = meta.get("assertion_registry")
    out = gk_state_patch.cmd_update_gate_data(
        state_file, json.dumps(payload, ensure_ascii=False),
        allow_narrow_tasks=True)   # 唯一写通路内部放行面（通用写面一律拒，见 _NARROW_TASKS_KEY）
    if not out.get("ok"):
        return {"registered": False,
                "issues": [{"id": "?", "rule": "state_write_failed",
                            "detail": out.get("error", "state 写入失败")}]}, 4
    return {"registered": True, "ids": [str(e.get("id", "")) for e in entries],
            "constraints": constraints, "derivation": derivation}, 0


def check_groups(state_file: str) -> dict:
    """对 state 内已登记的窄任务重放组语义约束（只读，供聚合/审计复核）。"""
    if not state_file or not Path(state_file).is_file():
        return {"mode": "legacy", "ok": False, "unchecked": True,
                "violations": [{"rule": "state_missing", "id": "?", "detail": state_file}]}
    try:
        d = json.loads(Path(state_file).read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return {"mode": "legacy", "ok": False, "unchecked": True,
                "violations": [{"rule": "state_invalid_json", "id": "?",
                                "detail": str(e)}]}
    gd = d.get("gate_data", {}) or {}
    return validate_group_constraints(gd.get("narrow_tasks") or [],
                                      gd.get("narrow_coverage_target"),
                                      gd.get("narrow_assertion_registry"))


def main() -> int:
    p = argparse.ArgumentParser(description="窄任务清单 → subagent 档位路由")
    p.add_argument("--state", required=True, help="state JSON 文件路径")
    p.add_argument("--task", help="当前 subagent 任务描述（--check-poison 时可选）")
    p.add_argument("--check-poison", action="store_true",
                   help="只做投毒检查：命中强注入信号 → 输出 JSON 明细并 exit 3")
    p.add_argument("--check-schema", action="store_true",
                   help="schema/复杂度校验：违规 → 输出明细并 exit 4")
    p.add_argument("--check-groups", action="store_true",
                   help="三组窄任务语义约束：违规 → 输出明细并 exit 4")
    p.add_argument("--register", metavar="FILE",
                   help="生产者：从 JSON（数组或 {\"narrow_tasks\":[...]}）替换写入 "
                        "gate_data.narrow_tasks；违规 → 输出 {registered:false,issues} 并 exit 4")
    args = p.parse_args()
    if args.register is not None:
        out, rc = register(args.state, args.register)
        print(json.dumps(out, ensure_ascii=False))
        return rc
    if args.check_groups:
        rep = check_groups(args.state)
        print(json.dumps(rep, ensure_ascii=False))
        return 0 if rep.get("ok") else 4
    if args.check_schema:
        issues = validate_narrow_tasks(args.state)
        if issues:
            print(json.dumps({"schema_valid": False, "issues": issues}, ensure_ascii=False))
            return 4
        print(json.dumps({"schema_valid": True}, ensure_ascii=False))
        return 0
    if args.check_poison:
        hits = poison_check(args.state)
        if hits:
            print(json.dumps({"poison": True, "hits": hits}, ensure_ascii=False))
            return 3
        print(json.dumps({"poison": False}, ensure_ascii=False))
        return 0
    print(route(args.state, args.task or ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
