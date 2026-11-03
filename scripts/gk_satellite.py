#!/usr/bin/env python3
"""gk_satellite.py — state 卫星存储中枢（卫星片**唯一写入者** + `satellite_index` **首生产者**）。

定位（卫星计划 §8 落刀点表）
=======================================================================
`docs/plans/2026-10-04-state-satellite-storage-plan.md` §3①「元数据中枢」与判据 c5（同
`batch_id` 两臂并发 ⟹ 片数==臂数、各片 `wc -l` 互不覆盖）此前**无落地面** —— `satellite_index`
只有拦截面（c4，`gk_state_patch.cmd_update_gate_data`）+ 宿主写许可（`_PAYLOAD_KEYS`），
**零生产者**（finding `ECC-1256AF7829DC`，P1）。本模块补**唯一生产者**。

分片模型 = **(b) 单片 + per-arm 索引叶子**（2026-10-06 质询定稿）
=======================================================================
- **单片**（每 kind 一文件，复用既有同族名，见 `KIND_SUFFIX`）：`<state>.<kind>-archive.jsonl`，
  append-only、`batch_id`/`arm` 作**字段**（对齐 §18.2 载体）。
- **per-arm 索引叶子**：**热**叶在 `gate_data.satellite_index.<batch_id>.<arm>`（每 kind 只留最近
  `INLINE_LEAVES_MAX_PER_KIND` 叶）；**冷**叶落 `<state>.satellite-index.jsonl`（append-only 侧车）。
  读面 `index_entries` = 热 ∪ 冷（侧车同键优先）⟹ 主 state 体积有上界，臂数增长不再线性撑大 state。
  **理由（实证）**：`cmd_set_nested` 禁「目标已是容器」的整键替换（G4 防丢更新）⟹ 若把
  `satellite_index.<batch_id>` 写成含 `arms{}` 的容器，**第一臂**写入后即变容器 ⟹ **第二臂
  （或宿主）写入被 fail-loud 拒** ⟹ 与中枢单写者契约**结构性不相容**、c5 不可达。per-arm
  互异叶子 ⟹ 各臂各写各的，零覆盖；且与 c4 拦截面（顶层键仍为 `<batch_id>`）、宿主写面
  （`_PAYLOAD_KEYS` 只拦载荷键）、ember `gate_data_full` 快照均兼容。

纪律
=======================================================================
- 片名**单源** = 本模块 `KIND_SUFFIX`；既有溢出写者（`gk_task_gate._retain_pipeline` /
  CLI history 落库段）**收敛为调用本中枢**（禁第二实现，见卫星计划 §8）。
- 索引写**只经** `gk_state_patch.cmd_set_nested`（定点叶子、锁内读-改-写、checksum 单源）；
  **禁**顶层 `update-gate-data` 整替（c4 拦截面）。
- **唯一例外**（2026-11-01）：`gc_index` 删叶子（`set-nested` 无删除语义）—— 整键重写
  `satellite_index`、持锁、只动该键、同批重算 checksum；仅删「已墓碑 / 片不存在」两类。
"""
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 片名单源（复用既有同族名 `<state>.<kind>-archive.jsonl`，零改名/零迁移）：
#   pipeline → 与 `gk_task_gate._TASK_PIPE_ARCHIVE_SUFFIX` 一致（收敛前由红先臂守漂移）
#   history  → 与 `gatekeeper-cli.sh` history 落库段一致
#   finding  → 与 `gk_finding._ARCHIVE_SUFFIX` 一致
KIND_SUFFIX = {
    "pipeline": ".task-pipeline-archive.jsonl",
    "history": ".history-archive.jsonl",
    "finding": ".finding-archive.jsonl",
}

INDEX_ROOT = "gate_data.satellite_index"
# 索引段语法（禁 '.'/前导 '_'，见 append）。**公开单源**：`SEG_RE` 供其它落盘通道
# （如 `gk_ecc_sink` 的 batch/arm）复用，禁各写一份正则（漂移 = 登记路径 ≠ 读回路径）。
SEG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*$")
_SEG_RE = SEG_RE   # 兼容本模块既有引用

# S3（M2，2026-11-03）：内联热索引写开关。**缺省 False** = 写侧只落片 + 侧车；
# 读面 `index_entries` 并集内联 ∪ 侧车，旧内联叶照常可读，由 GC 按 TTL 清理。
# 置 True 即回滚到「逐叶 set-nested」（计划 §6 的回滚路径）。
INLINE_INDEX_WRITES = False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def shard_path(state_file: str, kind: str) -> str:
    """片文件路径（单源）。未知 kind ⟹ KeyError（fail-loud，禁拼错静默建新片区）。"""
    return str(state_file) + KIND_SUFFIX[kind]


def index_path(batch_id: str, arm: str) -> str:
    """per-arm 索引叶子路径（`gate_data.satellite_index.<batch_id>.<arm>`）。"""
    return "%s.%s.%s" % (INDEX_ROOT, batch_id, arm)


# ── 冷索引侧车（2026-11-02）────────────────────────────────────────────────
# 主 state 只保留**最近一轮**的内联热索引（6 臂/kind）；更旧的叶子落到
# `<state>.satellite-index.jsonl`（append-only），读面 `index_entries` 取并集。
# 目的：`satellite_index` 不再随臂数单调增长 ⟹ 主 state 体积有上界，
# 同时保留 per-arm 叶子语义与 `set-nested` 定点写（热路径零 schema 变更）。
INDEX_SIDECAR_SUFFIX = ".satellite-index.jsonl"
INLINE_LEAVES_MAX_PER_KIND = 6


def sidecar_path(state_file: str) -> str:
    """冷索引侧车路径（state 同目录；`.jsonl` ⟹ `iter_live_states` 天然看不见）。"""
    return str(state_file) + INDEX_SIDECAR_SUFFIX


def _append_sidecar(state_file: str, entries: list) -> int:
    """追加侧车行（调用方须持 `state_lock`；fsync 后返回条数）。"""
    if not entries:
        return 0
    p = sidecar_path(state_file)
    d = os.path.dirname(os.path.abspath(p))
    if d:
        os.makedirs(d, exist_ok=True)
    n = 0
    with open(p, "a", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
            n += 1
        f.flush()
        os.fsync(f.fileno())
    return n


def _sidecar_write(state_file: str, entries: list) -> int:
    """持锁写侧车（`state_lock` 可重入）；失败抛给调用方决定 fail-loud / best-effort。"""
    from gk_json_utils import state_lock as _state_lock
    with _state_lock(state_file):
        return _append_sidecar(state_file, entries)


def _read_sidecar(state_file: str) -> dict:
    """读回侧车 `{(batch_id, arm): leaf}`；坏行/半行跳过（append-only 容忍）。"""
    p = sidecar_path(state_file)
    out = {}
    if not os.path.isfile(p):
        return out
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:  # noqa: BLE001 — 半行/坏行
                    continue
                if not isinstance(e, dict):
                    continue
                key = (str(e.get("batch_id") or ""), str(e.get("arm") or ""))
                op = e.get("op")
                if op == "del":
                    out.pop(key, None)
                elif op == "put" and isinstance(e.get("leaf"), dict):
                    out[key] = e["leaf"]
    except OSError:
        return {}
    return out


def _inline_index(state_file: str) -> dict:
    """主 state 内联热索引（`gate_data.satellite_index`）；缺失/坏读 ⟹ `{}`。"""
    try:
        import gk_state as GS
        data = GS._read_state(state_file)
    except Exception:  # noqa: BLE001 — 边界
        try:
            with open(state_file, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
    si = ((data or {}).get("gate_data") or {}).get("satellite_index") or {}
    return si if isinstance(si, dict) else {}


def _leaf_ts(leaf: dict) -> str:
    return str((leaf or {}).get("last_ts") or (leaf or {}).get("first_ts") or "")


def _spill_candidates(si: dict) -> list:
    """内联索引中超出 `INLINE_LEAVES_MAX_PER_KIND` 的**最旧**叶子（按 kind **全局**计数）。

    ⚠ 计数必须跨 batch：否则每个 batch 各留 6 叶 ⟹ 总内联量随 batch 数线性增长，
    外置形同虚设（实测 audit-bureau：23 batch × ≤6 pipeline 叶 ⟹ 旧实现 0 候选）。
    """
    out = []
    by_kind = {}
    for batch, arms in (si or {}).items():
        if not isinstance(arms, dict):
            continue
        for arm, leaf in arms.items():
            if isinstance(leaf, dict):
                by_kind.setdefault(str(leaf.get("kind") or ""), []).append(
                    (batch, arm, leaf))
    for _kind, items in by_kind.items():
        if len(items) <= INLINE_LEAVES_MAX_PER_KIND:
            continue
        items.sort(key=lambda x: _leaf_ts(x[2]))
        out.extend(items[:len(items) - INLINE_LEAVES_MAX_PER_KIND])
    return out


def _rewrite_inline_index(state_file: str, remove) -> bool:
    """从主 state 内联索引删除 `remove={(batch,arm)}`（整键重写、持锁、重算 checksum）。

    这是**唯一**允许整键重写 `satellite_index` 的删除面（`set-nested` 无删除语义）；
    只动该键，不碰其它 gate_data。
    """
    remove = set(remove or ())
    if not remove:
        return True
    import gk_json_utils as JU
    with JU.state_lock(state_file):
        try:
            with open(state_file, encoding="utf-8") as f:
                d = json.load(f)
        except Exception:  # noqa: BLE001 — 边界
            return False
        gd = d.setdefault("gate_data", {})
        si = gd.get("satellite_index")
        if not isinstance(si, dict):
            return True
        for batch, arm in remove:
            arms = si.get(batch)
            if isinstance(arms, dict):
                arms.pop(arm, None)
            if isinstance(arms, dict) and not arms:
                si.pop(batch, None)
        gd["satellite_index"] = si
        d["_checksum"] = hashlib.sha256(
            json.dumps(gd, sort_keys=True).encode()).hexdigest()[:16]
        return bool(JU.dump_state(state_file, d))


def _spill_inline(state_file: str, gd: dict = None) -> int:
    """把内联热索引中超额的**最旧**叶子移到侧车（冷索引），再从内联删除。

    `gd` 非 None ⟹ 只处理调用方持有的 `gd`（in-tx，零 state 写）；
    否则读主 state 并在删除时整键重写。**先写侧车成功、后删内联**（崩溃安全）。
    """
    si = (gd or {}).get("satellite_index") if gd is not None else _inline_index(state_file)
    if not isinstance(si, dict):
        return 0
    victims = _spill_candidates(si)
    if not victims:
        return 0
    side = _read_sidecar(state_file)
    entries = []
    for batch, arm, leaf in victims:
        if side.get((batch, arm)) != leaf:
            entries.append({"op": "put", "batch_id": batch, "arm": arm,
                            "leaf": leaf, "ts": _now()})
    if entries:
        try:
            _sidecar_write(state_file, entries)
        except Exception:  # noqa: BLE001 — 侧车失败 ⟹ 保留内联（不丢），best-effort
            return 0
    if gd is not None:
        for batch, arm, _leaf in victims:
            arms = si.get(batch)
            if isinstance(arms, dict):
                arms.pop(arm, None)
            if isinstance(arms, dict) and not arms:
                si.pop(batch, None)
        return len(victims)
    return len(victims) if _rewrite_inline_index(
        state_file, {(b, a) for b, a, _ in victims}) else 0


def append(state_file: str, kind: str, records: list, *, batch_id: str,
           arm: str = "default", ttl_s: int = 0, gd: dict = None, ts: str = "") -> dict:
    """把 `records` 落**卫星片**（append-only）并登记 **per-arm 索引叶子**。

    **两种模式**（P1 后续收敛靠此分派）：
      · **standalone**（`gd is None`）：索引经 `gk_state_patch.cmd_set_nested` 定点写 state。
      · **in-tx**（`gd` 非 None）：索引**就地把** `gd["satellite_index"][batch][arm]` 写入调用方
        持有的 `gd`，**零 state 写** —— 供**已在 state 事务内**的调用方（`gk_task_gate._retain_pipeline`
        在 `save_state` **之前**被调；若此处另写 state，随后 `save_state` 会**覆盖**索引 = lost update）。

    返回 {"ok", "shard", "appended", "leaf", "claim"(, "index_path" standalone)}。片写失败 ⟹ ok:false
    （fail-loud，不静默）；standalone 索引登记失败 ⟹ ok:false 且附 `leaf_error`（片已落，索引缺 =
    对接断裂面，显式报）。**片写自持 `state_lock`（可重入）** ⟹ 调用方已持锁则只加深度（免自锁）；
    跨进程追加互斥（防 JSONL 半行）。

    **判活锚接线**（`ECC-078AAECF33FB`，两种模式**都**落锚）：片一落盘即 `claim_anchor`（片基址入
    write-claims 台账）⟹ `reclaim` 对活片 `held`。best-effort：锚失败**不改** `ok`，只在 `claim` 里报。
    """
    kind = (kind or "").strip()
    if kind not in KIND_SUFFIX:
        return {"ok": False, "error": "未知片 kind: %r（合法：%s）"
                % (kind, sorted(KIND_SUFFIX))}
    batch_id = (batch_id or "").strip() or "nobatch"
    arm = (arm or "").strip() or "default"
    # [P2 修 · ECC-2462CED343D5] 索引段语法校验（fail-loud）：`index_path` 以 `.` 拼
    #   `satellite_index.<batch>.<arm>`，`cmd_set_nested` 按点切分 ⟹ 段内含 `.` 会把叶子
    #   切深/错位（**登记路径 ≠ 读回路径**，静默）；前导 `_` 被 `_path_denied` 拦。
    #   段须匹配 `^[A-Za-z0-9][A-Za-z0-9-]*$`（现有 id / batch / subagent_id 均满足）。
    for _seg, _nm in ((batch_id, "batch_id"), (arm, "arm")):
        if not _SEG_RE.match(_seg):
            return {"ok": False, "error": "非法索引段 %s=%r（须匹配 %s）"
                    % (_nm, _seg, _SEG_RE.pattern)}
    stamp = ts or _now()
    shard = shard_path(state_file, kind)
    nbytes = 0
    # [P2 修 · ECC-C207BAD27AB6] 片写**自锁**（`state_lock` **可重入**：调用方已持锁 ⟹ 只加深度，
    #   不重复 flock）—— 原实现纯外借调用方，且行完整性依赖 flush 边界（>8KB 记录跨进程
    #   O_APPEND 可把 JSONL 撕成半行）。锁键 = state（片同属该 state），与 submit/commit/
    #   adjudicate/CLI 段共用**同一**互斥原语；非 POSIX 退化为无锁（对齐既有行为）。
    try:
        from gk_json_utils import state_lock as _state_lock
        with _state_lock(state_file):
            with open(shard, "a", encoding="utf-8") as f:
                for r in records:
                    line = json.dumps(r, ensure_ascii=False) + "\n"
                    f.write(line)
                    nbytes += len(line.encode("utf-8"))
    except Exception as e:  # noqa: BLE001 — 边界：片写失败 fail-loud（不静默丢）
        return {"ok": False, "error": "卫星片写失败：%s: %s" % (type(e).__name__, e),
                "shard": shard}
    # [ECC-2A298C57FF7E · T2/R6] 叶子 `ttl_s` **单源透传**：三处生产调用点不传 `ttl_s`
    #   ⟹ 原实现恒落 0 ⟹ `reclaim` 过期判据在生产上**恒假**（卫星计划 §4.2「判据真、生产假活」）。
    #   缺省回落到**租约单源** `claim_ttl_s()`（与判活锚同源），使片真能被判过期。
    try:
        from gk_git_lease import claim_ttl_s as _claim_ttl_s
        _lease_ttl = int(_claim_ttl_s() or 0)
    except Exception:  # noqa: BLE001 — 边界：拿不到即 0（退化，不阻断片写）
        _lease_ttl = 0
    leaf = {"kind": kind, "file": os.path.basename(shard), "arm": arm,
            "records": len(records), "bytes": nbytes,
            "first_ts": stamp, "last_ts": stamp, "ttl_s": int(ttl_s or _lease_ttl or 0)}
    # 冷索引侧车：**先落侧车**（append-only + fsync）再登记内联热索引。
    # 侧车是索引的第二持久面（主 state 内联只留最近一轮）；写失败 ⟹ fail-loud（片已落）。
    try:
        _sidecar_write(state_file, [{"op": "put", "batch_id": batch_id, "arm": arm,
                                     "leaf": leaf, "ts": stamp}])
    except Exception as e:  # noqa: BLE001 — 边界
        return {"ok": False, "error": "卫星索引侧车写失败（片已落）：%s: %s"
                % (type(e).__name__, e), "shard": shard, "leaf": leaf}
    # [ECC-078AAECF33FB] 生产者接线：片一落盘即把**片基址登记为判活锚**（卫星计划 §3③a/§7）。
    #   遗漏（cross-review）：`claim_anchor` 已实装却**无生产调用点** ⟹ 只有测试手调才落锚；真实
    #   路径产的片**无锚** ⟹ `reclaim` 一旦从 dry-run 转 live 即可误删在用片。best-effort：锚失败
    #   **不改** `append` 的 ok（片 / 索引是主契约），只在返回附 `claim` 供观测。
    #   TTL 取**租约单源** `claim_ttl_s()` —— `claim_anchor` 默认 `ttl_s=0` 是**非活锚**（`live()`
    #   判 `now <= ts+ttl`），生产者若沿用默认则锚形同虚设。
    try:
        claim = claim_anchor(state_file, sid=_anchor_sid(state_file), ttl_s=_lease_ttl)
    except Exception as e:  # noqa: BLE001 — 边界：锚是 best-effort，绝不阻断片写
        claim = {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
    # in-tx：索引并入调用方的 `gd`（**零 state 写** —— 防 caller 随后 save_state 覆盖）
    if gd is not None:
        gd.setdefault("satellite_index", {}).setdefault(batch_id, {})[arm] = leaf
        _spilled = _spill_inline(state_file, gd=gd)
        return {"ok": True, "shard": shard, "appended": len(records), "leaf": leaf,
                "claim": claim, "spilled": _spilled}
    # S3（M2，2026-11-03）：**写侧停更内联热索引**。读面 `index_entries` 已是
    #   内联 ∪ 侧车 的并集，侧车（append-only + fsync）是完整持久索引 ⟹ 内联只留历史叶，
    #   由 `gc_index` / `reclaim` 按 TTL 清理。常量仅作回滚开关（计划 §6）。
    if not INLINE_INDEX_WRITES:
        return {"ok": True, "shard": shard, "appended": len(records), "leaf": leaf,
                "claim": claim, "spilled": 0, "inline_skipped": True,
                "inline_skip_reason": "S3: 写侧只落片 + 侧车（内联热索引停写）"}
    # 索引登记（**只经**定点 set-nested；禁顶层整替 ⟹ 与 c4 拦截面同调）
    try:
        import gk_state_patch as SP
        reg = SP.cmd_set_nested(state_file, index_path(batch_id, arm),
                                json.dumps(leaf, ensure_ascii=False))
    except Exception as e:  # noqa: BLE001 — 边界
        reg = {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
    if not reg.get("ok"):
        # `cmd_set_nested` → `_write_state` 把异常放在 `detail`（`error` 恒 `write_failed`）
        _err = "%s %s" % (reg.get("error", ""), reg.get("detail", ""))
        # 95% 水位拦截时，**侧车已是事实源**：热索引只是缓存，跳过它不算写失败
        # （否则 `archive_closed` / `ember burn` 这类「收缩修复」会被自己的收尾写阻断）。
        if "STATE_WALL_BLOCK" in _err:
            return {"ok": True, "shard": shard, "appended": len(records),
                    "index_path": index_path(batch_id, arm), "leaf": leaf,
                    "claim": claim, "spilled": 0, "inline_skipped": True,
                    "leaf_error": _err}
        return {"ok": False, "error": "索引登记失败（片已落）", "shard": shard,
                "appended": len(records), "leaf_error": _err}
    _spilled = _spill_inline(state_file)
    return {"ok": True, "shard": shard, "appended": len(records),
            "index_path": index_path(batch_id, arm), "leaf": leaf, "claim": claim,
            "spilled": _spilled}


def index_entries(state_file: str, batch_id: str = "") -> dict:
    """读回卫星索引（hub/余烬读面）：**内联热索引 ∪ 冷索引侧车**，侧车同键优先。

    `batch_id` 空 ⟹ 整份并集；非空 ⟹ 该 batch 的 arms map。
    读面**单源**（`gk_moa_aggregate` 等一律经此，禁直读 `gate_data.satellite_index`）。
    """
    merged = {}
    for batch, arms in _inline_index(state_file).items():
        if isinstance(arms, dict):
            merged[batch] = dict(arms)
    for (batch, arm), leaf in _read_sidecar(state_file).items():
        merged.setdefault(batch, {})[arm] = leaf
    if batch_id:
        return merged.get(batch_id, {})
    return merged


def _iso_age_s(ts: str, now: float):
    """ISO-8601 ts → 距 `now` 的**年龄秒**（解析失败 ⟹ None，不静默当 0）。"""
    if not ts:
        return None
    try:
        s = str(ts).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return now - dt.timestamp()
    except Exception:  # noqa: BLE001 — 边界：非法 ts 不判过期（保守）
        return None


def shards(state_file: str) -> list:
    """**独立枚举面**（卫星片；卫星计划 §18.2 遗漏③）：本 state 的全部卫星片三 kind。

    `.jsonl` 旁挂被 `state_form` 判 **artifact** ⟹ `iter_live_states` **天然看不见片** ⟹
    回收 / 对账**禁**复用 `iter_live_states`（否则永久漏扫），须用本枚举面。
    返回 `[{"kind","shard","exists","bytes"}]`（三 kind 恒列；缺片 `exists=False`）。
    """
    out = []
    for kind, suf in KIND_SUFFIX.items():
        p = str(state_file) + suf
        exists = os.path.isfile(p)
        out.append({"kind": kind, "shard": p, "exists": exists,
                    "bytes": (os.path.getsize(p) if exists else 0)})
    return out


def _basenames(paths) -> list:
    return sorted({os.path.basename(str(p).replace("\\", "/")) for p in (paths or []) if str(p).strip()})


def _anchor_sid(state_file: str) -> str:
    """生产者判活锚的 `sid` —— **每 state 互异**（`ECC-078AAECF33FB`）。

    `gk_write_claims.live()` 对每个 `sid` **只取最后一条** ⟹ 若生产者用**恒定** sid（如 `"satellite"`），
    第二个 state 落锚即**顶掉**第一个 state 的锚 ⟹ 先者片静默失锚（回收面可误删）。故以 state 基名
    派生（同仓内 state 基名唯一），前缀 `satellite:` 标明来源。
    """
    base = os.path.basename(str(state_file).rstrip("/\\")) or "state"
    return "satellite:" + base


def claim_anchor(state_file: str, sid: str = "satellite", ttl_s: int = 0,
                 repo: str = None) -> dict:
    """把**卫星片基址**登记进 write-claims 台账（**判活锚**，卫星计划 §3③a/§7）。best-effort。

    无片存在 ⟹ no-op（不落空 claim）；同一 `sid` 已登记**同样片集** ⟹ no-op（幂等，防台账膨胀）。
    """
    exist = [s["shard"] for s in shards(state_file) if s["exists"]]
    if not exist:
        return {"ok": True, "noop": True, "reason": "no shard", "paths": []}
    try:
        import gk_write_claims as WC
    except Exception as e:  # noqa: BLE001 — 边界
        return {"ok": False, "error": "claim 台账不可用：%s" % e}
    want = _basenames(exist)
    for c in WC.live(repo):
        if c.get("sid") == sid and _basenames(c.get("paths")) == want:
            # [ECC-2A298C57FF7E · T4] 已锚 ⟹ **续期**（刷新 ts）而非 no-op —— 原 no-op 使锚
            #   自首次落锚起不再刷新 ⟹ 约 1h 后静默失活（技能根锚零续期通路的缺口）。
            ren = WC.renew(repo=repo, sid=sid, source="satellite-anchor", paths=exist)
            return {"ok": bool(ren.get("ok")), "renewed": not ren.get("noop", False),
                    "reason": "already anchored → renewed", "sid": sid}
    return WC.append(repo=repo, sid=sid,
                     worktree=os.path.dirname(os.path.abspath(state_file)),
                     family="satellite", source="satellite-anchor", paths=exist, ttl_s=ttl_s)


def _live_claim_sids_for_shards(state_file: str, repo: str = None):
    """片路径 → 覆盖它的 live claim `sid`（**判活锚读面**）。

    **fail-closed（T3，`ECC-2A298C57FF7E`）**：台账不可读 ⟹ 返回 `None`（**非** `{}`）——
    原 `{}` 语义 = 「无 live claim」= **fail-open**，会把在用片判成可回收（与注释自称「保守」
    方向相反）。调用方（`reclaim`）见 `None` 须**拒刀**。
    **全路径匹配（R2）**：原按 `basename` 匹配 ⟹ 同基名双副本（不同 state 目录同名片）互相
    误判 held（跨 state 遮蔽）。改按**规范化全路径**匹配。
    """
    try:
        import gk_write_claims as WC
        lives = WC.live(repo)
        _canon = getattr(WC, "_canon", None)
    except Exception:  # noqa: BLE001 — 边界：台账不可判 ⟹ fail-closed
        return None
    base = os.path.dirname(os.path.abspath(state_file))

    def _key(p):
        return (_canon(str(p), base) if _canon else str(p).replace("\\", "/"))

    shard_by_key = {_key(s["shard"]): s["shard"] for s in shards(state_file)}
    out = {}
    for c in lives:
        for p in (c.get("paths") or []):
            k = _key(p)
            if k in shard_by_key:
                out[shard_by_key[k]] = c.get("sid")
    return out


def _disabled() -> bool:
    """**kill switch 读点**（卫星计划 §7；finding `ECC-F3AB40FD6CD7`）。

    §7 明列 `GK_SATELLITE=0` 为回退开关，但原**零代码载体** = **幻影回退** ⟹ 先装读点。
    **只旁路回收半场**（`reclaim`）—— 它是卫星唯一的**破坏性**面（打墓碑/回收）；`append` 是
    **加性无损失**面，旁路反而会让调用方（`_retain_pipeline`/溢出）的裁剪丢数据 ⟹ **故意不**旁路
    append（对 §7「全有全无」的一处显式收窄，已入 finding `ECC-F3AB40FD6CD7` 备裁）。
    """
    return str(os.environ.get("GK_SATELLITE", "1")).strip() == "0"


def backfill_ttl(state_file: str, *, ttl_s: int = 0, dry_run: bool = False) -> dict:
    """**T5 存量片回填**：给 `satellite_index` 中 `ttl_s<=0` 的叶子补缺省 TTL（finding `ECC-F3AB40FD6CD7`）。

    动机：T2 之前的生产叶子 `ttl_s` 恒 0 ⟹ `reclaim` 对**存量**片永不判过期（判据真、生产假活）。
    保守取**单源** `claim_ttl_s()`（与 `append`/`reclaim` 同源）；打 `backfilled_ts` 标记 ⟹ **幂等**。
    `dry_run=True` ⟹ 只报不写；**不**改 `ttl_s>0` 的叶子（不动既有语义）。
    """
    try:
        from gk_git_lease import claim_ttl_s as _claim_ttl_s
        _ttl = int(ttl_s or 0) or int(_claim_ttl_s() or 0)
    except Exception:  # noqa: BLE001 — 边界：拿不到即用参数/0
        _ttl = int(ttl_s or 0)
    if _ttl <= 0:
        return {"ok": False, "error": "ttl_s 不可判（claim_ttl_s 不可用）", "backfilled": 0}
    targets = []
    for batch, arms in (index_entries(state_file) or {}).items():
        if not isinstance(arms, dict):
            continue
        for arm, leaf in arms.items():
            if not isinstance(leaf, dict):
                continue
            try:
                cur = int(leaf.get("ttl_s", 0) or 0)
            except (TypeError, ValueError):
                cur = 0
            if cur <= 0:
                targets.append((batch, arm))
    if not targets or dry_run:
        return {"ok": True, "backfilled": (0 if dry_run else len(targets)),
                "targets": ["%s.%s" % (b, a) for b, a in targets],
                "dry_run": bool(dry_run), "ttl_s": _ttl}
    import gk_state_patch as SP
    stamp = _now()
    inline = _inline_index(state_file)
    si = index_entries(state_file)
    n_ok, errors = 0, []
    for batch, arm in targets:
        leaf = dict((si.get(batch) or {}).get(arm) or {})
        leaf["ttl_s"] = _ttl
        leaf["backfilled_ts"] = stamp
        try:
            _sidecar_write(state_file, [{"op": "put", "batch_id": batch, "arm": arm,
                                         "leaf": leaf, "ts": stamp}])
        except Exception as e:  # noqa: BLE001 — 边界
            errors.append({"target": "%s/%s" % (batch, arm),
                           "error": "%s: %s" % (type(e).__name__, e)})
            continue
        # 内联热索引同步（若该叶仍在 state 内；sidecar-only 叶不重建内联）
        arms = inline.get(batch)
        if isinstance(arms, dict) and arm in arms:
            path = index_path(batch, arm)
            SP.cmd_set_nested(state_file, path + ".ttl_s", json.dumps(_ttl))
            reg = SP.cmd_set_nested(state_file, path + ".backfilled_ts",
                                    json.dumps(stamp))
            if not reg.get("ok"):
                errors.append({"target": "%s/%s" % (batch, arm),
                               "error": reg.get("error", "")})
                continue
        n_ok += 1
    return {"ok": True, "backfilled": n_ok, "ttl_s": _ttl,
            "targets": ["%s.%s" % (b, a) for b, a in targets],
            "errors": errors}


def reclaim(state_file: str, *, now: float = None, dry_run: bool = True) -> dict:
    """卫星片**动态回收**：依 per-arm 叶子的 `ttl_s` 判过期（卫星计划 §7）。

    语义（用户 2026-10-06「卫星存储库确保…被动态分配」/ finding `ECC-2CB9AA55C53C`）：
      · 扫描 `satellite_index` 各 per-arm 叶子；`ttl_s>0` 且 `now-(last_ts|first_ts)>ttl_s`
        ⟹ 列为 `would_reclaim`，否则 `live`。
      · **默认 `dry_run=True`** —— 卫星基址**入 claim 台账前**（遗漏③ `ECC-E1A0E4E1A97A`）
        **只报不删**（对齐 §7「未入台账前回收默认 dry-run」）。dry-run ⟹ **零写盘**。
      · `shard_reclaimable` = 该 kind 的**全部** per-arm 叶子均过期（**片级**判据）——
        多臂共享一片，**任一臂 live 即不得删整片**。
      · `dry_run=False` ⟹ 对过期叶子打**墓碑** `reclaimed_ts`（写更深叶子，可审计、append-only
        精神）；**片文件本版不物理删除**（片级回收仍待 claim 台账判活后另批，见返回值
        `shard_reclaimable`）。
    """
    import time as _time
    now = _time.time() if now is None else float(now)
    if _disabled():   # kill switch（§7 / ECC-F3AB40FD6CD7）：旁路回收半场（唯一破坏性面）
        return {"ok": True, "disabled": True, "reason": "GK_SATELLITE=0（kill switch）",
                "dry_run": bool(dry_run), "would_reclaim": [], "held": [], "live": [],
                "shard_reclaimable": []}
    si = index_entries(state_file)
    expired, live = [], []
    kind_total, kind_expired = {}, {}
    for batch, arms in (si or {}).items():
        if not isinstance(arms, dict):
            continue
        for arm, leaf in arms.items():
            if not isinstance(leaf, dict):
                continue
            if leaf.get("reclaimed_ts"):
                continue   # [R4/ECC-2A298C57FF7E] 已墓碑 ⟹ 幂等跳过（重跑不改墓碑）
            kind = str(leaf.get("kind", "") or "")
            kind_total[kind] = kind_total.get(kind, 0) + 1
            try:
                ttl = int(leaf.get("ttl_s", 0) or 0)
            except (TypeError, ValueError):
                ttl = 0
            age = _iso_age_s(str(leaf.get("last_ts") or leaf.get("first_ts") or ""), now)
            rec = {"batch_id": batch, "arm": arm, "kind": kind, "ttl_s": ttl,
                   "age_s": (int(age) if age is not None else None),
                   "shard": (shard_path(state_file, kind) if kind in KIND_SUFFIX else "")}
            if ttl > 0 and age is not None and age > ttl:
                expired.append(rec)
                kind_expired[kind] = kind_expired.get(kind, 0) + 1
            else:
                live.append(rec)
    # 判活锚（卫星计划 §7）：片被 **live claim** 覆盖 ⟹ `held`（即便 TTL 过期也不回收）。
    anchors = _live_claim_sids_for_shards(state_file)
    if anchors is None:
        # [T3/ECC-2A298C57FF7E] 台账不可判 ⟹ **fail-closed 拒刀**（禁 fail-open 误删在用片）。
        return {"ok": False, "refused": True,
                "reason": "claim ledger unavailable（fail-closed）",
                "dry_run": bool(dry_run), "would_reclaim": [], "held": [], "live": [],
                "shard_reclaimable": []}
    would, held, held_kinds = [], [], set()
    for rec in expired:
        s = rec.get("shard") or ""
        if s and s in anchors:
            held.append({"batch_id": rec["batch_id"], "arm": rec["arm"], "kind": rec["kind"],
                         "shard": s, "held_by": anchors[s]})
            held_kinds.add(rec["kind"])
        else:
            would.append(rec)
    # 片级可回收 = 该 kind 全臂过期 **且** 无 held 臂（多臂共享片）。
    shard_reclaimable = sorted(
        k for k, tot in kind_total.items()
        if tot > 0 and kind_expired.get(k, 0) == tot and k not in held_kinds)
    out = {"ok": True, "dry_run": bool(dry_run), "would_reclaim": would, "held": held,
           "live": live, "shard_reclaimable": shard_reclaimable}
    if dry_run or not would:
        return out
    tomb = []
    inline = _inline_index(state_file)
    for rec in would:
        tgt = "%s/%s" % (rec["batch_id"], rec["arm"])
        ts = _now()
        leaf = dict((si.get(rec["batch_id"]) or {}).get(rec["arm"]) or {})
        leaf["reclaimed_ts"] = ts
        # 墓碑先落侧车（冷索引事实源，侧车同键优先）；再同步内联（若该叶仍在 state）。
        try:
            _sidecar_write(state_file, [{"op": "put", "batch_id": rec["batch_id"],
                                         "arm": rec["arm"], "leaf": leaf, "ts": ts}])
        except Exception as e:  # noqa: BLE001 — 边界
            tomb.append({"target": tgt, "ok": False,
                         "error": "%s: %s" % (type(e).__name__, e)})
            continue
        arms = inline.get(rec["batch_id"])
        if isinstance(arms, dict) and rec["arm"] in arms:
            try:
                import gk_state_patch as SP
                reg = SP.cmd_set_nested(
                    state_file,
                    index_path(rec["batch_id"], rec["arm"]) + ".reclaimed_ts",
                    json.dumps(ts, ensure_ascii=False))
                tomb.append({"target": tgt, "ok": bool(reg.get("ok")),
                             "error": reg.get("error", "")})
            except Exception as e:  # noqa: BLE001 — 边界
                tomb.append({"target": tgt, "ok": False,
                             "error": "%s: %s" % (type(e).__name__, e)})
        else:
            tomb.append({"target": tgt, "ok": True, "error": ""})
    out["tombstoned"] = tomb
    return out


# ── 容量标定 + 索引 GC（2026-11-01 owner 裁定「卫星上限」）────────────────────
# 容量口径（owner 2026-11-01 明确复述，取代「10 轮 × 6 臂」这种抽象写法）：
#   **一轮** = 6 个 subagent（**档位 4**，单臂 token 预算跑满）产生的 history 数据总量 × **120%** 余量。
#     单臂 history 实测 10.9–12.7KB ⟹ 取上抬值 16KB；一轮 = 6 × 16KB × 1.2 = **117,964 B**。
#   **一片（卫星片）** = **10 轮** = 1,179,640 B（≈1.12 MB）；叶子数上限仍 = 10 × 6 = 60 臂/kind。
# 缺口（实测 2026-11-01，本仓）：197 个 per-arm 叶子，192 条 `ttl_s=3600` 全过期、0 墓碑，
#   而 base 下 3 个片文件**全部不存在** ⟹ 叶子全是**悬空登记**（54,510 B ≈ 主 state 10.8%），
#   且 `reclaim` 只打墓碑、**从不删叶子** ⟹ 索引只增不减（连墓碑也永久占位）。
# 处置：本段补两条**只读优先**的面 ——
#   `verify_shards`：dangling（片不存在）/ orphan（片存在但无叶子）/ over_capacity；
#   `gc_index`：删「已墓碑」与「悬空」两类叶子（这两类无任何读面价值：读 union 走片文件本身，
#   不查索引）；**过期但片存在**的叶子保留（可回溯），越容量只报不删（片级物理删除仍未裁）。
SAT_ROUNDS_BUDGET = 10
SAT_ARMS_PER_ROUND = 6
SAT_MAX_ARMS_PER_KIND = SAT_ROUNDS_BUDGET * SAT_ARMS_PER_ROUND           # 60
SAT_ARM_BUDGET_BYTES = 16 * 1024                 # 单臂：档位4 跑满实测 10.9–12.7KB 的上抬值
SAT_ROUND_HEADROOM_PCT = 120                     # 一轮 = 6 臂 × 120% 余量
SAT_ROUND_BUDGET_BYTES = (SAT_ARMS_PER_ROUND * SAT_ARM_BUDGET_BYTES
                          * SAT_ROUND_HEADROOM_PCT // 100)              # 115,200
SAT_SHARD_BUDGET_BYTES = SAT_ROUNDS_BUDGET * SAT_ROUND_BUDGET_BYTES      # 1,152,000


def verify_shards(state_file: str) -> dict:
    """卫星**一致性 + 容量**体检（**只读**，0 写盘）。

    - `dangling[]`：叶子登记了 kind，但对应片文件不存在（索引指向空气）—— 读面价值 = 0
    - `orphan_shards[]`：片文件存在且非空，但该 kind **无任何**叶子引用（无法按索引回溯）
    - `over_capacity{kind: {leaves, cap}}`：叶子数超 `SAT_MAX_ARMS_PER_KIND`
    - `ok` = 三者皆空（存在性/容量任一异常即 false，**不静默当干净**）
    """
    si = index_entries(state_file)
    shard_bytes, referenced = {}, {}
    for kind in KIND_SUFFIX:
        p = shard_path(state_file, kind)
        shard_bytes[kind] = os.path.getsize(p) if os.path.isfile(p) else None
    dangling, per_kind = [], {}
    for batch, arms in (si or {}).items():
        if not isinstance(arms, dict):
            continue
        for arm, leaf in arms.items():
            if not isinstance(leaf, dict):
                continue
            kind = str(leaf.get("kind") or "")
            if shard_bytes.get(kind) is None:
                dangling.append({"batch_id": batch, "arm": arm, "kind": kind,
                                 "shard": shard_path(state_file, kind)
                                 if kind in KIND_SUFFIX else ""})
                continue
            per_kind[kind] = per_kind.get(kind, 0) + 1
            referenced[kind] = True
    orphan = [k for k in KIND_SUFFIX if shard_bytes.get(k) and not referenced.get(k)]
    over = {k: {"leaves": n, "cap": SAT_MAX_ARMS_PER_KIND}
            for k, n in sorted(per_kind.items()) if n > SAT_MAX_ARMS_PER_KIND}
    return {"ok": not dangling and not orphan and not over,
            "dangling": dangling, "dangling_count": len(dangling),
            "orphan_shards": orphan,
            "over_capacity": over,
            "capacity": {"max_arms_per_kind": SAT_MAX_ARMS_PER_KIND,
                         "arm_budget_bytes": SAT_ARM_BUDGET_BYTES,
                         "round_budget_bytes": SAT_ROUND_BUDGET_BYTES,
                         "shard_budget_bytes": SAT_SHARD_BUDGET_BYTES},
            "shard_bytes": shard_bytes,
            "leaves": sum(per_kind.values()) + len(dangling)}


def gc_index(state_file: str, dry_run: bool = True, max_per_kind: int = 0) -> dict:
    """卫星索引 **GC**：删「已墓碑」/「悬空」叶 + 把内联超 cap 的最旧叶溢出到冷侧车。

    ⚠ 写面例外（**受控**）：`satellite_index` 的唯一常规写面是定点 `set-nested`，但它**无删除
    语义** ⟹ 删叶子只能整键重写。本函数因此是全仓**唯一**对 `satellite_index` 做删除的写者：
    持 `state_lock` 读-改-写、只动该键、同批重算 `_checksum`（同 `_write_checksum` 算法）。
    「过期但片存在」的叶子**不删**（保留可回溯性）；越容量只报不删。
    冷侧车删除走 `{"op":"del"}` 追加（append-only），不重写侧车。
    """
    cap = int(max_per_kind or 0) or SAT_MAX_ARMS_PER_KIND
    si = index_entries(state_file)
    shard_exists = {k: os.path.isfile(shard_path(state_file, k)) for k in KIND_SUFFIX}
    removed, kept, over = [], [], {}
    for batch, arms in (si or {}).items():
        if not isinstance(arms, dict):
            continue
        for arm, leaf in arms.items():
            if not isinstance(leaf, dict):
                continue
            kind = str(leaf.get("kind") or "")
            if leaf.get("reclaimed_ts"):
                removed.append({"batch_id": batch, "arm": arm, "kind": kind,
                                "why": "tombstoned"})
            elif kind in KIND_SUFFIX and not shard_exists.get(kind):
                removed.append({"batch_id": batch, "arm": arm, "kind": kind,
                                "why": "dangling"})
            else:
                kept.append({"batch_id": batch, "arm": arm, "kind": kind})
    for kind in KIND_SUFFIX:
        n = sum(1 for k in kept if k["kind"] == kind)
        if n > cap:
            over[kind] = {"leaves": n, "cap": cap}
    _rm_preview = {(r["batch_id"], r["arm"]) for r in removed}
    spill = [c for c in _spill_candidates(_inline_index(state_file))
             if (c[0], c[1]) not in _rm_preview]
    out = {"ok": True, "dry_run": bool(dry_run),
           "removed": removed, "removed_count": len(removed),
           "kept": len(kept), "over_capacity": over,
           "would_spill": ["%s/%s" % (b, a) for b, a, _l in spill],
           "capacity": {"max_arms_per_kind": cap,
                        "inline_max_per_kind": INLINE_LEAVES_MAX_PER_KIND}}
    if dry_run:
        return out
    _rm = {(r["batch_id"], r["arm"]) for r in removed}
    if _rm:
        try:
            _sidecar_write(state_file, [{"op": "del", "batch_id": b, "arm": a,
                                         "ts": _now()} for b, a in _rm])
        except Exception as e:  # noqa: BLE001 — 边界
            out["ok"] = False
            out["error"] = "侧车删除写失败：%s: %s" % (type(e).__name__, e)
            return out
        if not _rewrite_inline_index(state_file, _rm):
            out["ok"] = False
            out["error"] = "内联索引删除写失败"
            return out
    spilled = _spill_inline(state_file)
    out["applied"] = len(removed)
    out["spilled"] = spilled
    out["leaves_after"] = sum(len(a) for a in index_entries(state_file).values()
                              if isinstance(a, dict))
    return out


if __name__ == "__main__":
    # B6（2026-10-27，RED-MIGRATE-INLINE）：模块自有 CLI。
    # 取代 gatekeeper-cli.sh 的 `python3 -c "import gk_satellite as S; print(...)"` 薄壳
    # —— **不用**「模块名+函数名」泛化派发（那会新开任意函数执行面）。
    import argparse
    import json

    _p = argparse.ArgumentParser(prog="gk_satellite.py")
    _s = _p.add_subparsers(dest="cmd", required=True)
    _r = _s.add_parser("reclaim")
    _r.add_argument("--state", required=True)
    _r.add_argument("--dry-run", action="store_true")
    _b = _s.add_parser("backfill-ttl")
    _b.add_argument("--state", required=True)
    _b.add_argument("--dry-run", action="store_true")
    _g = _s.add_parser("gc", help="索引 GC：删墓碑/悬空叶子 + 容量体检（缺省 dry-run）")
    _g.add_argument("--state", required=True)
    _g.add_argument("--dry-run", action="store_true")
    _g.add_argument("--max-per-kind", type=int, default=0)
    _v = _s.add_parser("verify", help="卫星一致性 + 容量体检（只读）")
    _v.add_argument("--state", required=True)
    _a = _p.parse_args()
    if _a.cmd == "reclaim":
        _out = reclaim(_a.state, dry_run=_a.dry_run)
    elif _a.cmd == "backfill-ttl":
        _out = backfill_ttl(_a.state, dry_run=_a.dry_run)
    elif _a.cmd == "gc":
        _out = gc_index(_a.state, dry_run=_a.dry_run, max_per_kind=_a.max_per_kind)
    else:
        _out = verify_shards(_a.state)
    print(json.dumps(_out, ensure_ascii=False))
