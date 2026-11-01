#!/usr/bin/env python3
"""
gk_moa_aggregate.py — MoA 聚合器（Reference-Aggregator，2026-08-28）
=====================================================================
对齐 zthl-harness-adapter-plan 的 governance/moa/ 设计（Hermes MoA 同构）：
  - subagent ECC 报告 = reference（advisory，有界字段随档位 _ECC_BOUNDS 缩放）
  - 主 agent = aggregator（acting，读取聚合引用后裁决）
  - 本脚本 = 聚合前的治理三层：
      pre_check  : AggregatorPreCheck — 投毒清洗（跨租户/指令注入/角色伪装标记红action）
      audit      : MoATraceAudit — 溯源（subagent_ids / 时间 / 预算 / 置信度）
      inject     : _attach_reference_guidance — 生成注入主 agent 上下文的聚合引用块

关键点（用户质询 2026-08-28）：
  - ECC 输出有界（runner 侧档位界限权威裁切），聚合端**保留有界全文，不二次截断**。
  - 同时 N 个 max-tier subagent（如 3 个 plan-refinement）→ 全部作为独立 reference 聚合，
    HMAC 在 CLI 写入 subagent_history 时已验（tampered 拒绝）；此处只做投毒清洗 + 溯源。

用法:
  python3 scripts/gk_moa_aggregate.py [--state FILE] [--recent N] [--role ROLE] [--md] [--out FILE]
  默认读 STATE_FILE env 或自动探测激活 state；输出 JSON（--md 输出可读聚合报告）。
"""
import argparse
import functools
import hashlib
import json
import math
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

# ── 编码层归一化单一事实源（gk_norm；P1 接入 2026-10-06）────────────────────────
# `sanitize_text` 若纯字面匹配，全角 / 零宽 / Unicode Tags 走私全漏（红队 RED-POISON-M-P1/P2）。
# 纪律：归一化**只用于匹配**；落库走 `strip_invisible`（剥隐形载体、**不做 NFKC** ⟹ 不动
#   中文全角标点）。gk_norm 不可用 ⟹ 退化为字面（不阻断聚合）。
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:  # noqa: SIM105
    from gk_norm import decode_candidates as _decode_candidates   # type: ignore
    from gk_norm import fold_confusables as _fold_confusables     # type: ignore
    from gk_norm import normalize as _norm_text       # type: ignore
    from gk_norm import spotlight_delimit as _spotlight_delimit  # type: ignore
    from gk_norm import strip_invisible as _strip_invisible  # type: ignore
except Exception:  # noqa: BLE001
    def _norm_text(_t):  # noqa: ANN001, ANN202
        return _t

    def _strip_invisible(_t):  # noqa: ANN001, ANN202
        return _t

    def _spotlight_delimit(_t, *, marker=""):  # noqa: ANN001, ANN202
        return _t

    def _fold_confusables(_t):  # noqa: ANN001, ANN202
        return _t

    def _decode_candidates(_t):  # noqa: ANN001, ANN202
        return [_t]

# ── 投毒清洗模式（pre_check / AggregatorPreCheck）──────────────────────
# 2026-10-31（P2c 第 6 份归一）：词表移入单一事实源 `gk_foreign_content.POISON_PATTERNS`
#   （原注释「对齐 subagent_runner _FOREIGN_USER_PATTERNS」= 双份漂移的证据）。
# 命中 → 标记 [REDACTED]，保留字段其余内容（聚合不丢信息，只去毒）。
REDACT_TAG = "[REDACTED]"
try:  # noqa: SIM105  —— 单源不可用时不阻断聚合（与 gk_norm 同一降级纪律）
    from gk_foreign_content import POISON_PATTERNS as _POISON_PATTERNS  # type: ignore
except Exception:  # noqa: BLE001
    _POISON_PATTERNS = []


def _surfaces(text: str) -> list:
    """检测面候选（确定性）：字面 / NFKC / NFKC+同形折叠 / 各解包候选（ROT13 + Base64）。"""
    norm = _norm_text(text)
    folded = _fold_confusables(norm)
    surfaces = [text, norm, folded]
    for s in (norm, folded):
        surfaces.extend(_decode_candidates(s))
    return surfaces


def poison_labels(text: str) -> list:
    """返回命中的投毒模式标签（多候选面，确定性）；空 = 未见已知模式。

    与 `sanitize_text` 共用同一面与同一词表（单源）；`gk_finding` 二阶校验（写入时污点扫描）复用。
    """
    if not isinstance(text, str):
        text = str(text)
    surfaces = _surfaces(text)
    return sorted({label for pat, label in _POISON_PATTERNS
                   if any(re.search(pat, s, re.IGNORECASE) for s in surfaces)})


def sanitize_text(text: str) -> str:
    """投毒清洗：标记已知注入/污染模式为 [REDACTED]（保留字段其余可见内容）。

    P1（2026-10-06）：匹配前先 `gk_norm.normalize`（NFKC + 剥零宽 + 剥 Tags）——
    全角 / 零宽 / Unicode Tags 走私（红队 RED-POISON-M-P2）不再漏检；落库走
    `strip_invisible`（**只**剥隐形载体、**不做 NFKC** ⟹ 中文全角标点逐字保留）。
    T5-c（2026-10-06）：检测面**扩为多候选**（`_surfaces`：字面/NFKC/同形折叠/解包）⟹ 封
    同形字（`_PM_P2_HOMO`）与编码走私（ROT13/Base64）；结构伪装（chat 模板/role 标签）入词表。
    编码走私 = 归一/折叠/解包后命中而原文按字面正则不中 ⟹ 整段标 [REDACTED]（走私本身即强信号）。
    """
    if not isinstance(text, str):
        return str(text)
    surfaces = _surfaces(text)
    out = text
    encoded_hit = False
    for pat, _label in _POISON_PATTERNS:
        if not any(re.search(pat, s, re.IGNORECASE) for s in surfaces):
            continue
        new_out = re.sub(pat, REDACT_TAG, out, flags=re.IGNORECASE)
        if new_out == out:
            # 仅靠归一/折叠/解包命中、原文按字面正则不中 = 编码走私（全角/零宽/Tags/同形/编码）
            encoded_hit = True
        out = new_out
    out = _strip_invisible(out)
    if encoded_hit:
        out = REDACT_TAG
    return out


def sanitize_reference(entry: dict) -> dict:
    """逐字段清洗 reference（task/conclusion/evidence/findings/next_steps/access_violations）。"""
    e = dict(entry)
    e["task"] = sanitize_text(e.get("task", ""))[:_TASK_KEEP]
    e["conclusion"] = sanitize_text(e.get("conclusion", ""))
    ev = e.get("evidence") or []
    cleaned_ev = []
    for it in ev:
        if isinstance(it, dict):
            cleaned_ev.append({
                "file": sanitize_text(str(it.get("file", "")))[:120],
                "lines": sanitize_text(str(it.get("lines", "")))[:60],
                "status": it.get("status", "confirmed"),
            })
        else:
            cleaned_ev.append(sanitize_text(str(it))[:180])
    e["evidence"] = cleaned_ev
    f = e.get("findings") or {}
    if isinstance(f, dict):
        e["findings"] = {
            k: [sanitize_text(str(x))[:200] for x in (v if isinstance(v, list) else [])]
            for k, v in f.items()
        }
    e["next_steps"] = [sanitize_text(str(x))[:200] for x in (e.get("next_steps") or [])]
    if e.get("access_violations"):
        e["access_violations"] = [
            {k: sanitize_text(str(v))[:120] for k, v in a.items()}
            for a in e["access_violations"][:10]
        ]
    return e


def mark_ingest_taint(ref: dict) -> dict:
    """T5-A5 入站**统一打标**（摄入口单一入口，`aggregate` 与红队 P8 共用）。

    - **与检测解耦**：不可信内容**无条件**标 `provenance="untrusted"` —— A5（对抗后缀 GCG）等
      **不可检测**载荷打穿词表 ⟹ taint **不得**依赖 `poison_labels` 命中（否则检测一失败即漏标）。
    - **Spotlighting（卫生层，非墙）**：给**分隔视图** `spotlight`（marker 固定 ⟹ 确定性），
      **不改**原 `conclusion`（保渲染/测试零回归）。ChatInject arXiv:2509.22830 证明可绕。
    """
    ref["provenance"] = "untrusted"
    _concl = str(ref.get("conclusion") or "")
    if _concl:
        ref["spotlight"] = _spotlight_delimit(_concl, marker="UNTRUSTED")
        ref["spotted"] = True
    return ref


# ── 引用异常标记（投毒清洗第二层，2026-08-28）─────────────────────────────
# 正则红action只能抓强信号显式注入；对无法确定性判定的深层投毒（条件植入/压缩凸显/
# 虚假先例/合规事实注入等），聚合器改为「标记可疑引用」而非盲信——主 agent（aggregator）
# 拿到 suspect 标记后对可疑引用降权/交叉验证。分类详见 red-findings §4.9。
def task_fingerprint(task: str) -> str:
    """任务归属指纹（F-REV-8，2026-09-11）：规范化（首尾去空白 + 空白折叠）后 sha256 前 12 hex。

    用途 = **回读点归属校验**（XSPI re-read gap 的本仓实例化）：MoA 前提是"同一问题的 N 份
    独立回答"，跨任务混聚是语义错误 —— 若某任务的输出被投毒，缺归属校验即可跨任务内化。
    注（F-REV-53，2026-09-14）：CLI 落库时**不再截断** `subagent_history[].task` —— 原 `[:200]`
    使 standing 通道（固定 boilerplate 前缀 > 200 字符，区分信息在尾部）**全部坍缩为同一
    指纹**（实测 20/20 条），且 `--task` 传全量原文时与存储副本不符（零 references）⇒ 归属
    绑定**双向失效**。指纹须**可从存储记录重算**（禁另落派生字段 = 第二事实源）。
    本机制是归属**绑定**（binding），不是归属证明。
    """
    norm = " ".join((task or "").split())
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:12]


# F-REV-53 同判据（2026-10-04，A1 分析）：数据面**禁** `[:300]` 头截断 —— 窄任务在**尾部**，
#   头截断使 6 臂 task 坍缩成同一段 preflight boilerplate（HTML/MD 两通道双双失效）。
_TASK_KEEP = 4000  # 数据面保留上限（显示面由 _task_display / split_narrow_task 定界）


def split_narrow_task(task: str) -> str:
    """A1-R2：从派发 task 中剥出**窄任务**（无则返回 ""，由调用方回落 = fail-loud）。

    实测 task = 『【preflight 证据摘要】…(a)(b)(c)…』 + 空行 + 『plan-refinement: <plan> — <窄任务>』。
    取**最后一个空行段落**，并去 `plan-refinement: <plan> — ` 头。
    ⚠ **禁**按「同批最长公共前缀(LCP)」剥离 —— G1『相同对』的窄任务**定义上逐字相同**，
      LCP 会把窄任务本身吞进公共前缀，恰在**最需要区分**的组上失效。
    """
    t = str(task or "")
    if not t.strip():
        return ""
    seg = [s.strip() for s in t.split("\n\n") if s.strip()]
    if len(seg) < 2:
        return ""
    cand = " ".join(seg[-1].split())
    if not cand or cand == " ".join(t.split()):
        return ""
    m = re.match(r"^plan-refinement:\s*\S+\s*[—\-–]\s*(.+)$", cand)
    return (m.group(1).strip() if m else cand)


# ── §18.1 批身份（batch identity，2026-10-03，ECC-5538DD07B709 RC1/N1）──────────
# 批 = 一次 MoA 派发单元。身份须在**派发时**定并随每条 subagent_history 落库
# （聚合端只能重算者才算「可从记录复原」⟹ plan/窄任务/纪元由派发侧提供）。
BATCH_BUCKET_S = 600  # 派发纪元分桶秒（同桶各臂共享 batch_id；默认 10 分钟）

_RE_PLAN_KEY = re.compile(r"plan-refinement:\s*(\S+)")


def plan_key_from_task(task: str) -> str:
    """从派发 task 提取计划键（batch 作用域）；非 plan-refinement 通道 → 空串。"""
    m = _RE_PLAN_KEY.search(str(task or ""))
    return m.group(1) if m else ""


# ── 计划身份**单一真源**（2026-10-30，user 裁定「多源多实现漂移」）───────────────
# 病根：同一「计划身份」在本文件曾有 4 种表示 ——
#   ① 裸路径串（调用方传入，形态不定：主仓绝对 / worktree 绝对 / 仓相对）
#   ② `_resolve_plan_path` 产出的 `os.path.abspath`
#   ③ `_pending_for_plan` 手写的 `os.path.basename`
#   ④ `plan_key_from_task` 正则提取的原始形态
#   ⟹ 6 个消费点各选其一/组合、零契约 ⟹ 形态一变各点得失不一致。
# 实测（2026-10-30，19 个 state / 142 条 history）：可提取 126 条，其中**相对 79 / 绝对 47**
#   ⟹ 两种形态长期并存；余 16 条属红队/audit/FIX/preflight 通道，**本就无计划语义**（非兼容负担）。
# 事故（当日）：`chain_head` 把相对入参归一成绝对，聚合端拿绝对去裸子串匹配 history 里的
#   相对/worktree 路径 ⟹ 0 命中 ⟹ `batch_resolved=""` + `refs=0` ⟹ 误判「基础设施缺陷」。
# 处置：`plan_identity()` = 唯一规范化点；`plan_match()` = 唯一比较点（三层边界，禁裸子串散落）。

def plan_identity(path_or_task: str) -> str:
    """计划身份 = basename 去 `.md` —— **唯一规范化点，禁第二实现**。

    接受四种形态：主仓绝对 / worktree 绝对 / 仓相对 / 派发 task 全文（`plan-refinement: <p> — …`）。
    `basename` 是唯一在四种形态下都不变的片段；plan 文件名自带日期，碰撞可忽略。
    """
    s = str(path_or_task or "").strip()
    if not s:
        return ""
    m = _RE_PLAN_KEY.search(s)
    if m:
        s = m.group(1)
    # 跨平台分隔符归一（2026-10-30）：state 里的路径可能来自 Windows 侧（`C:\...`），
    # 而本脚本多跑在 WSL/POSIX，`os.path.basename` 不认反斜杠 ⟹ 会把整串当文件名。
    s = s.replace("\\", "/")
    # 形似路径 → 取 basename 去 `.md`
    if "/" in s or s.endswith(".md"):
        b = os.path.basename(s)
        return b[:-3] if b.endswith(".md") else b
    # 已归一化 key 的**幂等通路**（2026-10-30）：`plan_identity(plan_identity(x)) == plan_identity(x)`。
    #   裸名（无分隔符、无扩展名）若为纯 ASCII 安全字符，即视为已是身份，原样返回；
    #   含空白 / 中文 / 全角标点的长文本（preflight 摘要、红队任务描述等）⟹ 身份不可得 ⟹ ""。
    if re.fullmatch(r"[A-Za-z0-9._-]+", s):
        return s
    return ""


def plan_match(entry_task: str, target_plan: str) -> tuple:
    """`(是否命中, 匹配方式)` —— **唯一比较点，禁裸子串散落**。

    三条边界（不可放宽，放宽即混批）：
      · `identity`          —— 双侧 identity 可得且相等（主判据）
      · `legacy_substring`  —— 任一侧 identity 不可得 ⟹ 回退子串（旧/无计划通道兜底，留痕）
      · `identity_mismatch` —— 双侧可得但**不等** ⟹ 拒（**绝不回退**：回退会把两个不同计划
        混进同一批，比失配更危险）
    """
    ti = plan_identity(entry_task)
    pi = plan_identity(target_plan)
    if ti and pi:
        return (ti == pi, "identity" if ti == pi else "identity_mismatch")
    return (str(target_plan or "") in str(entry_task or ""), "legacy_substring")


def batch_epoch_bucket(epoch=None, bucket_s: int = BATCH_BUCKET_S) -> int:
    """派发纪元秒 → 桶序号（同桶各臂共享 batch_id）。"""
    e = time.time() if epoch in (None, "") else float(epoch)
    return int(e) // max(int(bucket_s), 1)


def compute_batch_id(plan_path, narrow_tasks=(), epoch=None,
                     bucket_s: int = BATCH_BUCKET_S) -> str:
    """§18.1 批身份 = sha256(plan + '\\n' + '\\n'.join(sorted(narrow)) + '\\n' + 桶)[:12]。

    narrow_tasks 接受 list / 换行或逗号分隔 str；规范化（去空 + 排序）后入哈希
    ⟹ 同批各臂给同一 plan/窄任务/纪元桶即得同一 id（记录可复原）。
    """
    if isinstance(narrow_tasks, str):
        _nt = [x.strip() for x in re.split(r"[\n,]", narrow_tasks) if x.strip()]
    else:
        _nt = [str(x).strip() for x in (narrow_tasks or []) if str(x).strip()]
    payload = "%s\n%s\n%d" % (str(plan_path or ""), "\n".join(sorted(_nt)),
                              batch_epoch_bucket(epoch, bucket_s))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


# F-REV-41（2026-09-13）：CLI 落库的 HMAC 校验态 → 报告可读标签。
# 原实现无此字段，恒标 "verified_at_write"（零生效假绿）；现区分「已验签」与「未验签」两态。
_HMAC_STATUS_LABEL = {
    "valid": "verified_at_write",
    "no_hmac": "unsigned_no_hmac",
    "skip": "unverified_no_key",
    "invalid": "invalid",
}


# `ECC-C70ECCD4F7DC`（2026-09-27）：conclusion 视为「实质载体」的最小长度 —— `no_conclusion`
#   的 20 只判「有无结论」；plan-refinement 报告的**唯一实质载体**常是 conclusion（结构化
#   `challenges`/`verdicts`/… 全空而 conclusion 是 3000 字完整 verdicts）⟹ 须有独立阈值判
#   「是否完整结论」。200 取在「一句摘要（如 `_mk_entry` 的 31 字）↔ 完整结论（实测 3000 字）」
#   之间；低于它仍按零实质标记（负臂 `test_zero_findings_still_flagged_when_no_substance` 钉住）。
_CONCLUSION_SUBSTANCE_MIN = 200


def _suspect_flags(entry: dict) -> list[str]:
    flags = []
    ev = entry.get("evidence") or []
    _concl = str(entry.get("conclusion", "") or "")
    # ECC-8AA064279810（2026-09-26）＋ §18-N2（2026-10-03，ECC-5538DD07B709 RC3）：**判据口径错位**
    #   —— plan-refinement 报告的实质住 `conclusion`/`challenges`/`verdicts`/`kept`/`slashed`/
    #   `seven_dim_score`（`findings[]`/`evidence[]` **本就空** —— 它不是 code-review 型报告）。
    #   「内容缺席类」标记（`no_evidence`/`budget_*`）与 `zero_findings` **同源地** carve-out：
    #   实质齐备 ⟹ 不标（实测 6/8 质询臂 `budget_hard`、1 臂 `no_evidence` 被统一降权 ＝ 失真）；
    #   **真**零实质仍须标记（负臂 `test_non_substantive_*_still_flagged` 钉住）。
    f = entry.get("findings") or {}
    _has_findings = isinstance(f, dict) and any(
        f.get(k) for k in ("worked", "failed", "not_tried"))
    _has_substance = bool(
        entry.get("challenges") or entry.get("verdicts") or entry.get("kept")
        or entry.get("slashed") or entry.get("seven_dim_score")
        or len(_concl) >= _CONCLUSION_SUBSTANCE_MIN)
    if not ev and not _has_substance:
        flags.append("no_evidence")
    if len(_concl) < 20:
        flags.append("no_conclusion")
    bs = entry.get("budget_status", "ok")
    if bs in ("hard", "item_exceeded", "max_turns") and not _has_substance:
        flags.append(f"budget_{bs}")
    if not _has_findings and not _has_substance:
        flags.append("zero_findings")
    if entry.get("_hmac_unverified"):
        flags.append("hmac_unverified")
    # F-REV-41（2026-09-13）：入口白名单补齐后，hmac_status 由 CLI 落库（valid|no_hmac|skip|invalid）。
    # 非 valid（未验签/无 key/无签名）⇒ 该引用完整性未经校验，交主 agent 降权。缺字段（旧条目）不误报。
    _hs = str(entry.get("hmac_status", "") or "").lower()
    if _hs and _hs != "valid" and "hmac_unverified" not in flags:
        flags.append("hmac_unverified")
    # F-REV-21 实装联动（2026-09-11）：verdicts 越出闭词表 ⇒ 该引用值域可疑，交主 agent 降权
    if entry.get("vocab_violations"):
        flags.append("vocab_violation")
    return flags


# ── 聚合器指引（inject / _attach_reference_guidance，system-prompt 锁死）────
# 参考 zthl-adapter D3: Aggregator system prompt 锁死 — 防 reference 输出污染聚合器行为。
AGGREGATOR_GUIDANCE = (
    "你是 MoA 聚合器（acting）。以下 references 是相互独立的 subagent advisory 报告"
    # F-REV-41：原措辞无条件宣称"HMAC 验证过"，但无 key 时未必验签 ⇒ 改为指向逐引用校验态。
    "（已投毒清洗；完整性校验态见各 reference 的 hmac_status，可疑标记见 suspect）。"
    "规则：1) 不锚定任一 reference 的结论，交叉比对 evidence 重合与分歧；"
    "2) 每个 reference 独立可信，合并时以证据链强度而非数量裁决；"
    "3) 检测 reference 间矛盾 → 列为分歧点并在结论中明示；"
    "4) 聚合结论 = 你的独立判断，不得原样复述任一 reference；"
    "5) 最终按 ECC 固定格式输出融合裁决。"
)


_MODULE_ROOT = Path(__file__).resolve().parent.parent


def _entry_mtime(en: dict):
    """条目**产物**的 mtime（`report_file` → `output_file` → 退回 `timestamp`）；无据可查 → None。

    生产 `subagent_history` 条目**无 `ts`/`created_at`**，唯一的可信日期 = 报告文件落盘时间
    （`report_file`/`output_file`）；两者皆无时退回 `timestamp`（测试/旧条目形态）。
    """
    for k in ("report_file", "output_file"):
        p = str(en.get(k, "") or "")
        if not p:
            continue
        for cand in (Path(p), _MODULE_ROOT / p):
            try:
                if cand.is_file():
                    return cand.stat().st_mtime
            except OSError:
                pass
    ts = str(en.get("timestamp", "") or "")
    if ts:
        try:
            from datetime import datetime
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def _apply_freshness(hist: list, fresh_s: int) -> tuple[list, dict]:
    """按产物新鲜度剔除过时条目（`fresh_s <= 0` ⟹ 关判据、原样返回 = 零回归）。

    返回 `(kept, meta)`；`meta = {fresh_ttl, stale_excluded, undated_excluded}` —— **非静默**：
    被剔除的条数与判据窗口恒进 trace（否则「聚合跑过」与「产物全是旧的」不可分）。
    """
    if not fresh_s or fresh_s <= 0:
        return list(hist), {"fresh_ttl": 0, "stale_excluded": 0, "undated_excluded": 0}
    import time
    now = time.time()
    kept, stale, undated = [], 0, 0
    for en in hist:
        mt = _entry_mtime(en)
        if mt is None:
            undated += 1            # 不猜新鲜（fail-closed）：无日期者不得冒充新鲜
            continue
        if (now - mt) > fresh_s:
            stale += 1
            continue
        kept.append(en)
    return kept, {"fresh_ttl": int(fresh_s), "stale_excluded": stale,
                  "undated_excluded": undated}


def _satellite_history_union(state_file: str, data: dict, hist: list) -> tuple[list, dict]:
    """读侧 union：主 state `subagent_history` ⊕ 卫星 history 片（单源 `gk_satellite.KIND_SUFFIX`）。

    卫星计划 §4（2026-10-06）：「读侧 union 须单源单实现 + 缺片 fail-loud」。卫星片 =
    **出窗归档**（append-only）⟹ 聚合必须并见，否则少臂 = **读分裂**（F-REV-63
    `MU_BACKCAST_NEGATIVE` 类；实测批 `2a8b9e701e67`：主 state 4 + 卫星 2 = 6）。
    归档（较旧）**前置**、live 置后 ⟹ `--recent` 切片优先 live。缺片（`satellite_index`
    声明有 `history` 记录而片不在）⟹ `RuntimeError`（禁静默按部分批聚合）。无索引且无片 ⟹
    原样返回（多数 state 无卫星）。
    """
    info = {"shard": "", "archived": 0}
    try:
        import gk_satellite as SAT
    except Exception:  # noqa: BLE001 — 旧基线无卫星中枢模块 ⟹ 按片名单源**同形名**回退
        SAT = None
    if SAT is None:
        shard = str(state_file) + ".history-archive.jsonl"
        idx = {}
    else:
        shard = SAT.shard_path(state_file, "history")
        # [ECC-0A7EBDA60149] 读面**单源**：经中枢 `index_entries`（禁第二读实现直读
        #   `gate_data.satellite_index`）。旧基线无中枢模块 ⟹ 无卫星索引 ⟹ idx={}。
        # ECC-B396ADC532F7（2026-10-07 质询跨臂共识）：**合法回退仅「无模块」**；中枢存在时
        #   的**读失败须冒泡**（fail-closed）—— 原宽 `except` 把读失败吞成 `{}` ⟹ `expected=0`
        #   ⟹ 下方缺片 fail-loud **静默失效**（= §4/§10 明禁的静默部分聚合 / 读分裂）。
        idx = SAT.index_entries(state_file)
    info["shard"] = shard
    expected = 0
    if isinstance(idx, dict):
        for _arms in idx.values():
            if not isinstance(_arms, dict):
                continue
            for _leaf in _arms.values():
                if isinstance(_leaf, dict) and str(_leaf.get("kind", "")) == "history":
                    try:
                        expected += int(_leaf.get("records", 0) or 0)
                    except (TypeError, ValueError):
                        pass
    sp = Path(shard)
    if not sp.is_file():
        if expected:
            raise RuntimeError(
                "卫星 history 片缺失（satellite_index 声明 %d 条）：%s" % (expected, shard))
        return hist, info
    sat = []
    for line in sp.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:  # noqa: BLE001 — 片 append-only：坏行/半行跳过（读侧容错）
            continue
        if isinstance(e, dict):
            sat.append(e)
    # t4(a)（2026-10-17，`ECC-2E9DA8D90CB2`）：主 state 现为**元数据投影**（写侧全量已落片、
    #   `conclusion` 被剥除）。同 `subagent_id` 在片内是**全文**、在 live 是**占位** ⟹ 读侧须
    #   **原位替换**（而非按 live 去重丢弃片内全文），否则 `--recent` 取到占位 = 结论丢失。
    live = list(hist)
    slot = {}
    for _i, _e in enumerate(live):
        slot.setdefault(str(_e.get("subagent_id", "")), _i)
    added = []
    for e in sat:
        sid = str(e.get("subagent_id", ""))
        if sid and sid in slot:
            _i = slot[sid]
            if not str(live[_i].get("conclusion") or "") and e.get("conclusion"):
                live[_i] = e
            continue
        added.append(e)
    info["archived"] = len(added)
    return added + live, info


def history_union(state_file: str, data: dict) -> tuple[list, dict]:
    """**统一读面**（standard 序列门禁 + MOA 聚合共用）：主 state ⊕ 卫星 history 片。

    单源 = `_satellite_history_union`（**禁第二实现**）。`ECC-2EC7FD463D29` 的读侧半场：
    写侧已把溢出条目落 `history` 片（CLI 落库段 / `gk_task_gate._retain_pipeline`），
    standard 序列若仍只读 `gate_data.subagent_history` 即「写卫星、读 base」= 读分裂
    ⟹ 溢出后 live 变空，ECO-RESEARCH/ECO-EDIT 前置与 plan-refinement 点检误判。
    """
    gd = (data or {}).get("gate_data") or {}
    return _satellite_history_union(state_file, data, gd.get("subagent_history") or [])


def collect_entries(state_file: str, recent: int | None, role: str | None,
                    task: str = "", allow_cross_task: bool = False,
                    fresh_s: int = 0, plan: str = "", batch: str = "") -> tuple[list[dict], dict]:
    """从 state gate_data.subagent_history 取 entries（可选 --recent/--role/--fresh 过滤）。

    F-REV-8（2026-09-11）**回读点归属约束**（原实现仅 role 子串 + recent 时间窗，无归属校验）：
      - `task` 非空 → 只取指纹与之一致的条目（CLI `--task` 显式锚定）；
      - `task` 为空 → 以**最近一条**的指纹为锚，只保留同指纹条目（**缺省拒跨任务聚合**）；
      - `allow_cross_task=True` → 显式放开（trace 记 `cross_task_allowed`，审计可见）。
    返回 (entries, attribution)：attribution 进 trace（锚指纹 / 排除条数 / 模式），**不静默排除**。

    新鲜度（2026-09-28，`ECC-<moa-fresh>`）：`fresh_s > 0` ⟹ 按**产物 mtime** 剔除过时条目
    （`report_file` → `output_file` → 退回 `timestamp`）；无据可查者**不猜新鲜**（`undated_excluded`）。
    `fresh_s <= 0` = 关判据（行为逐字不变）。三个计数字段恒进 attribution（**非静默**）。
    """
    _no_fresh = {"fresh_ttl": 0, "stale_excluded": 0, "undated_excluded": 0}
    if not state_file or not Path(state_file).is_file():
        return [], {"mode": "no_state", **_no_fresh}
    try:
        d = json.loads(Path(state_file).read_text(encoding="utf-8"))
    except Exception:
        return [], {"mode": "unreadable", **_no_fresh}
    hist = d.get("gate_data", {}).get("subagent_history", []) or []
    hist, _sat = _satellite_history_union(state_file, d, hist)
    if role:
        hist = [x for x in hist if role in str(x.get("task", ""))]
    if recent and recent > 0:
        hist = hist[-recent:]
    hist, _fresh = _apply_freshness(hist, fresh_s)
    _fresh = {**_fresh, "satellite_archived": _sat["archived"]}
    if not hist:
        return [], {"mode": "empty", **_fresh}
    # §18.1（2026-10-03）：批锚最具体 ⟹ 先于 cross_task/plan/task 判定；精确取该批。
    if batch:
        _b = str(batch).strip()
        kept = [x for x in hist if str(x.get("batch_id", "")) == _b]
        if kept:
            return kept, {"mode": "batch_bound", "batch_id": _b, "batch_size": len(kept),
                          "excluded_other_batches": len(hist) - len(kept), **_fresh}
        # ECC-449948814679（2026-10-10）：**批号双轨** —— `--batch` 若传的是**流水线批号**
        #   `pr-<epoch>-<hex>`（见 `gate_data.task_pipeline[].batch` / enqueue 回执）而非
        #   `subagent_history[].batch_id` 指纹，原实现**静默**返回 0 条 ⟹ 下游把「批号写错」
        #   误归因为「批内一致度不足 / 基础设施缺陷」（实测落 `ECC-37985D9A67BE` = 此类）。
        #   现未知批号**不静默**：返回 `batch_unresolved` + 可用 `batch_id` 清单，交
        #   `aggregate()` 落 `error`/`hint`（rc≠0），并由 `main()` 的 `_emit` 门**禁落 finding**。
        _sizes: dict = {}
        for x in hist:
            _k = str(x.get("batch_id", "") or "")
            _sizes[_k] = _sizes.get(_k, 0) + 1
        _avail = [k for k, _ in sorted(_sizes.items(), key=lambda kv: (-kv[1], kv[0])) if k]
        return [], {"mode": "batch_unresolved", "batch_id": _b,
                    "available_batch_ids": _avail, "excluded_other_batches": len(hist), **_fresh}
    if allow_cross_task:
        return hist, {"mode": "cross_task_allowed", "excluded_other_tasks": 0, **_fresh}
    # §18（2026-10-02）：按**计划**锚聚合 —— 6 臂 3 组窄任务（组①相同对 / 组②与组①子空间正交且
    #   互补 / 组③污染组）之 task **必然不同** ⟹ 逐字指纹结构上不可聚齐 6 臂（ECC-096264506280）。
    #   锚 = 计划路径子串（各臂 task 均含 `plan-refinement: <plan> — …`），task 指纹降为子分组。
    if plan:
        _p = str(plan).strip()
        # 2026-10-30（单一真源）：原实现 `_p in task` 裸子串 —— 与 `_resolve_plan_path` 的绝对化、
        #   history 里的相对/worktree 形态三者不齐 ⟹ 0 命中。改用 `plan_match()` 三层边界，
        #   并把各层命中数落 `match_ways`（**非静默**：可据此判定是否退化到 legacy 兜底）。
        kept = []
        _ways = {}
        for x in hist:
            _hit, _how = plan_match(str(x.get("task", "")), _p)
            _ways[_how] = _ways.get(_how, 0) + 1
            if _hit:
                kept.append(x)
        return kept, {"mode": "plan_bound", "anchor": _p, "anchor_from": "plan",
                      "anchor_identity": plan_identity(_p), "match_ways": _ways,
                      "excluded_other_tasks": len(hist) - len(kept), **_fresh}
    if task:
        anchor_src, anchor_from = task, "cli_task"
    else:
        anchor_src, anchor_from = str(hist[-1].get("task", "")), "latest_entry"
    anchor = task_fingerprint(anchor_src)
    kept = [x for x in hist if task_fingerprint(str(x.get("task", ""))) == anchor]
    return kept, {"mode": "task_bound", "anchor": anchor, "anchor_from": anchor_from,
                  "excluded_other_tasks": len(hist) - len(kept), **_fresh}


def batch_sections(entries: list[dict]) -> dict:
    """§18.1 按 batch_id 分节：批边界 + 规模 + 权重恒进 trace（非静默）。

    可比性：仅**同批同规模**等权（weight=1.0）；单臂批（size==1）降权（0.5）并单列。
    """
    groups: dict[str, list] = {}
    for e in entries:
        groups.setdefault(str(e.get("batch_id", "") or ""), []).append(e)
    batches = [{"batch_id": bid, "size": len(es), "single_arm": len(es) == 1,
                "weight": 1.0 if len(es) > 1 else 0.5,
                "ids": [str(x.get("subagent_id", "")) for x in es]}
               for bid, es in groups.items()]
    batches.sort(key=lambda b: (-b["size"], b["batch_id"]))
    mode = ("all_batches" if len(batches) > 1
            else ("single_batch" if batches and batches[0]["batch_id"] else "unbatched"))
    return {"mode": mode, "batches": batches, "mixed_batches": len(batches) > 1,
            "single_arm_batches": [b["batch_id"] for b in batches if b["single_arm"]]}


# ── §18.3 组别身份（arm_group，2026-10-04，ECC-class）──────────────────────────
# 6 臂 3 组（G1 相同对 / G2 正交互补 / G3 污染组）**不可从聚合数据机检**——实测 batch
#   83560f4b99f7：窄任务指纹簇（{#5926,#5929}）≠ 真组；而真组③若为「题面称…已裁定/已
#   verified」此类模板注入，`_POISON_PATTERNS` 0 命中、suspect 0 ⟹ 组③结构性不可见。
# 裁定（2026-10-04 用户）：身份在**派发时**由编排方给定并随 entry 落库（对齐 §18.1
#   batch_id 单源手法：可从记录复原、禁第二事实源），聚合/渲染端**只读不猜**。
_ARM_GROUP_LABEL = {"G1": "相同对", "G2": "正交互补", "G3": "污染组"}


def arm_group_label(raw, delta=None) -> str:
    """arm_group 原值 → 可读标签；空 → 空串（UNKNOWN，禁反推）；未知取值**原样显**（禁吞）。

    W2A-P2（2026-10-16）：`delta`（per-arm 长度平移 Δ）非空 ⟹ 追加 `·Δ<d>`，使**消融腿**
    (组,Δ) 在聚合端**可分离**；`delta` 缺省 `None` ⟹ 逐字零回归。
    """
    g = str(raw or "").strip()
    d = "" if delta is None else str(delta).strip()
    if not g and not d:
        return ""
    lbl = _ARM_GROUP_LABEL.get(g, g) if g else ""
    if d:
        return ("%s·Δ%s" % (lbl, d)) if lbl else ("Δ%s" % d)
    return lbl


def arm_group_chip(raw) -> str:
    """组别 chip 文案：`G1·相同对`；空 → `—（未落库）`；未知 → 原样。"""
    g = str(raw or "").strip()
    if not g:
        return "—（未落库）"
    lbl = _ARM_GROUP_LABEL.get(g, "")
    return ("%s·%s" % (g, lbl)) if lbl else g


def arm_groups(refs: list[dict]) -> list[dict]:
    """组视图：按 (arm_group, arm_delta) 分节（缺失归『—（未落库）』）；同输入同输出（sorted 锚，
    禁插入序）。

    W2A-P2（2026-10-16）：分节键加入 `arm_delta`（消融腿 (组,Δ) 可分离）；`arm_delta` 缺失 ⟹
    逐字零回归（键退化为原 arm_group 标签）。
    """
    buckets: dict = {}
    for r in refs:
        d = str(r.get("arm_delta", "") or "").strip()
        key = (arm_group_label(r.get("arm_group"), d), d)
        buckets.setdefault(key, []).append(str(r.get("subagent_id", "")))
    return [{"group": k[0] or "—（未落库）", "delta": k[1], "size": len(ids), "ids": sorted(ids)}
            for k, ids in sorted(buckets.items(), key=lambda kv: (kv[0][0] == "", kv[0][0]))]


# ── S1 跨臂去重聚类 + 三组语义（2026-10-06，见 docs/plans/2026-10-06-moa-aggregate-substance-plan.md）──
# 缺陷（本会话实测）：`aggregate()` 逐 entry append，结论层**零去重 / 零聚类 / 零一致度**；
#   `arm_group` 聚合端零消费 ⟹ 6 臂散装（观感 = 「MoA 没聚合出任何有效信息」）。
# 修法（确定性、零 LLM、零新依赖）：归一化 → 字符 shingle → Jaccard → **单链接**成簇。
#   依据：Six Sigma Agent（`sim≥τ` 聚类「fast, deterministic, no LLM calls」）+
#   arXiv 2602.09341（语义去重折叠冗余，防「众口一词的错」confabulation）+ Raven-ADK
#   SelfConsistency（一致度不足 ⟹ **弃权**而非硬判）。
#   三组语义：G1 相同对 = 一致性；G2 正交互补 = **覆盖度**；G3 = 明确投毒（**元数据**）。
#   矛盾探测**去 G3 标签**（P2，2026-10-06）：G1/G2/G3 与人类评审**全通道皆可污染** ⟹
#   判据改为**标签无关**（verdicts 与逐 F 多数相左 / 非最大簇且 size≥2）。**只读**
#   conclusion/arm_group/verdicts/subagent_id，不读分数锚（双盲纪律）。
_CLUSTER_TAU = 0.6                 # Jaccard 相似度阈值（字符 shingle）
_CLUSTER_MIN_AGREE = 2.0 / 3.0     # 最大簇权重低于此 ⟹ 弃权（对齐 SelfConsistency 默认 2/3）
_CLUSTER_SHINGLE = 2               # 字符 shingle 长度


def _norm_for_cluster(text) -> str:
    """聚类用归一化：小写 / 去空白 / 去标点（保留 word 字符 + CJK）。"""
    t = str(text or "").lower()
    t = re.sub(r"\s+", "", t)
    return re.sub(r"[^\w\u4e00-\u9fff]+", "", t)


def _shingles(text, n: int = _CLUSTER_SHINGLE) -> set:
    t = _norm_for_cluster(text)
    if not t:
        return set()
    if len(t) <= n:
        return {t}
    return {t[i:i + n] for i in range(len(t) - n + 1)}


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


# ── 证据同源度（W2A 金字塔仪器，2026-10-18）────────────────────────────────
# L1-L3 实跑缺口：`rho` 只在旁路脚本里从 `SOURCES:` 行抠，生产聚合器不输出 ⟹
#   同源回声（agreement 高 + 证据有效样本量≈1）会被读成真收敛。
# 口径：逐臂 source 集合 = conclusion / evidence / sources 里的 URL，归一化为
#   `host+path`（去 scheme / www. / query / fragment / 末尾斜杠）；两两 Jaccard
#   均值 = `rho`；Kish 有效样本量 `n_eff_evidence = n/(1+(n-1)ρ)`。
# 纪律（禁冒充）：无任何 URL ⟹ rho/n_eff 均为 `None`，不得记 0（0 会被读成"独立"）。
_URL_RE = re.compile(r"https?://[^\s<>\"'）)\]]+", re.I)
_FALSE_CONV_AGREE = 0.8


def _source_key(url: str) -> str:
    u = str(url or "").strip()
    if not u:
        return ""
    u = u.split("#", 1)[0].split("?", 1)[0]
    m = re.match(r"https?://([^/]+)(/.*)?$", u, re.I)
    if not m:
        return ""
    host = m.group(1).lower()
    if ":" in host:
        host = host.split(":", 1)[0]
    if host.startswith("www."):
        host = host[4:]
    path = (m.group(2) or "/").rstrip("/") or "/"
    return host + path


def _ref_sources(ref: dict) -> set:
    parts = [str(ref.get("conclusion") or "")]
    ev = ref.get("evidence")
    if isinstance(ev, list):
        for it in ev:
            if isinstance(it, dict):
                f = str(it.get("file") or "")
                l = str(it.get("lines") or "")
                # 兼容旧数据（runner 曾把字符串 evidence "https://x" 按首个 ':' 拆成
                #   file="https" / lines="//x"）⟹ 读侧原位拼回，否则 URL 永远测不到。
                if f.strip().lower() in ("http", "https") and l.startswith("//"):
                    f, l = f + ":" + l, ""
                parts.append(" ".join(x for x in (f, l, str(it.get("note") or "")) if x))
            else:
                parts.append(str(it))
    src = ref.get("sources")
    if isinstance(src, list):
        parts.extend(str(x) for x in src)
    keys = set()
    for t in parts:
        for u in _URL_RE.findall(t):
            k = _source_key(u.rstrip(".,;:，。；、"))
            if k:
                keys.add(k)
    return keys


def source_overlap(refs: list[dict]) -> dict:
    """逐臂 source 集合的两两 Jaccard 均值 + Kish 有效证据样本量。

    `n_with_sources < 2` ⟹ rho / n_eff_evidence = None（未测量，禁冒充独立）。
    """
    items = list(refs or [])
    sets = [s for s in (_ref_sources(r) for r in items) if s]
    n = len(items)
    out = {
        "n_refs": n,
        "n_with_sources": len(sets),
        "source_coverage": round(len(sets) / n, 4) if n else 0.0,
        "rho": None,
        "n_eff_evidence": None,
    }
    if len(sets) < 2:
        return out
    vals = [_jaccard(sets[i], sets[j])
            for i in range(len(sets)) for j in range(i + 1, len(sets))]
    rho = round(sum(vals) / len(vals), 4)
    ns = len(sets)
    out["rho"] = rho
    out["n_eff_evidence"] = round(ns / (1 + (ns - 1) * rho), 4)
    return out


# ── 三组窄任务的分组指标（2026-10-19）──────────────────────────────────────
# 三组语义不同 ⟹ 不能用一个全局 rho 判所有组：
#   G1 相同对：rho 高、agreement 高 = **预期一致**（不是 false convergence）；
#   G2 正交互补：rho 高 = 冗余（两臂覆盖重叠），rho 低 = 正常；
#   G3 污染组：agreement 低或出现矛盾 = 污染被检出。
_GROUP_SEMANTICS = {
    "G1": {"role": "identical_pair", "expect_rho": "high"},
    "G2": {"role": "orthogonal_complement", "expect_rho": "low"},
    "G3": {"role": "pollution", "expect_rho": None},
}
_GROUP_REDUNDANT_RHO = 0.5
_GROUP_MIN_AGREE = 0.66
_VERDICT_RE = re.compile(r"\b(support|refute|abstain)\b|支持|反驳|弃权", re.I)
_VERDICT_CN = {"支持": "SUPPORT", "反驳": "REFUTE", "弃权": "ABSTAIN"}


def _verdict_labels(ref: dict) -> set:
    """逐臂裁决标签：优先结构化 `verdicts`，否则从 conclusion 文本提取（中英）。"""
    v = ref.get("verdicts")
    if isinstance(v, dict) and v:
        labs = {str(x).upper() for x in v.values()}
        return {x for x in labs if x in ("SUPPORT", "REFUTE", "ABSTAIN")}
    out = set()
    for m in _VERDICT_RE.finditer(str(ref.get("conclusion") or "")):
        tok = (m.group(1) or m.group(0)).lower()
        out.add(_VERDICT_CN.get(tok, tok.upper()))
    return out


def _group_status(group: str, rho, agreement, contradictions,
                  verdict_divergent=False) -> str:
    if rho is None:
        return "unmeasured"
    if group == "G1":
        if rho >= _GROUP_REDUNDANT_RHO and (agreement or 0.0) >= _GROUP_MIN_AGREE:
            return "expected_consistency"
        return "pair_diverged"
    if group == "G2":
        return "redundant" if rho >= _GROUP_REDUNDANT_RHO else "ok"
    if (contradictions or verdict_divergent
            or (agreement is not None and agreement < _GROUP_MIN_AGREE)):
        return "pollution_flagged"
    return "pollution_undetected"


def group_metrics(refs: list[dict]) -> dict:
    """按 `arm_group` 分组复用同一仪器（cluster_references/source_overlap）。

    返回 `{"G1": {...}, "G2": {...}, "G3": {...}}`；无该组成员 ⟹ `status=absent`。
    禁第二套 rho：组内指标直接取 `consensus` 的 `rho` / `agreement` / `contradictions`。
    """
    items_all = list(refs or [])
    out = {}
    for g, sem in _GROUP_SEMANTICS.items():
        items = [r for r in items_all
                 if str(r.get("arm_group", "") or "").strip().upper() == g]
        entry = {
            "group": g,
            "semantics": dict(sem),
            "n_refs": len(items),
            "rho": None,
            "n_eff_evidence": None,
            "source_coverage": None,
            "agreement": None,
            "status": "absent",
        }
        if items:
            c = cluster_references(items)["consensus"]
            entry.update({
                "rho": c.get("rho"),
                "n_eff_evidence": c.get("n_eff_evidence"),
                "source_coverage": c.get("source_coverage"),
                "agreement": c.get("agreement"),
                "n_eff": c.get("n_eff"),
            })
            entry["status"] = _group_status(
                g, entry["rho"], entry["agreement"],
                c.get("contradictions"),
                verdict_divergent=(len({lab for r in items
                                        for lab in _verdict_labels(r)
                                        if lab != "ABSTAIN"}) >= 2))
        out[g] = entry
    return out


# ── 逐断言裁决（2026-10-19）──────────────────────────────────────────────────
# 首轮 24 份结论里，每条断言的裁决都写在散文里（"断言 1 = support"）；
# 生产聚合只吃 F1-F7 与全局 agreement ⟹ 逐断言分歧被平均掉。本仪器把散文里的
# (assertion_id, verdict) 抽成矩阵，供论文报「哪条断言真分歧」。
_ASSERTION_RE = re.compile(
    r"断言\s*#?\s*([1-9]\d*)[^。；\n]{0,120}?(support|refute|abstain)", re.I)
_ASSERTION_RE_REV = re.compile(
    r"(support|refute|abstain)[^。；\n]{0,30}?断言\s*#?\s*([1-9]\d*)", re.I)


def assertion_metrics(refs: list[dict], n_assertions: int = 5) -> dict:
    """从结论文本抽取逐断言裁决矩阵（每臂每断言取首个裁决，防重复计数）。

    返回 `{n_refs, n_with_assertions, n_assertions, per_assertion}`；无任何命中 ⟹
    `n_with_assertions=0`（未测量，不冒充 0 票）。
    """
    items = list(refs or [])
    per = {i: {"support": 0, "refute": 0, "abstain": 0}
           for i in range(1, n_assertions + 1)}
    n_with = 0
    for r in items:
        text = str(r.get("conclusion") or "")
        found = {}
        # 结构化 `assertions` 优先（规范实验）；散文正则可回退补缺。
        struct = r.get("assertions")
        if isinstance(struct, list):
            for a in struct:
                if not isinstance(a, dict):
                    continue
                try:
                    i = int(a.get("id", a.get("assertion_id")))
                except (TypeError, ValueError):
                    continue
                v = str(a.get("verdict", "")).strip().lower()
                if 1 <= i <= n_assertions and v in ("support", "refute", "abstain"):
                    found.setdefault(i, v)
        for m in _ASSERTION_RE.finditer(text):
            i = int(m.group(1))
            if 1 <= i <= n_assertions and i not in found:
                found[i] = m.group(2).lower()
        for m in _ASSERTION_RE_REV.finditer(text):
            i = int(m.group(2))
            if 1 <= i <= n_assertions and i not in found:
                found[i] = m.group(1).lower()
        if found:
            n_with += 1
        for i, v in found.items():
            per[i][v] += 1
    out = {"n_refs": len(items), "n_with_assertions": n_with,
           "n_assertions": n_assertions, "per_assertion": {}}
    for i in range(1, n_assertions + 1):
        c = per[i]
        total = sum(c.values())
        maj = max(c, key=c.get) if total else None
        out["per_assertion"][str(i)] = {
            **c, "total": total, "majority": maj,
            "agreement": (round(c[maj] / total, 4) if total and maj else None),
        }
    return out


# ── 实际正交（2026-10-19）：从每臂结构化 assertions[] **反算** ────────────────
# 下发前的 `covers` 划分只证明「声明范围」正交；模型可能越界（任务只问 1-2、
# 结论却顺手答了 3）。本仪器用**实际输出的 assertion id 集合**计算实证正交：
#   A_g = ⋃ assertions(组 g)；realized_disjoint = (A_G1 ∩ A_G2 == ∅)
#   out_of_scope = A_g − declared(g)（需窄任务清单提供 covers）
# 无结构化 assertions ⟹ measured=False（未测量，不冒充“正交”）。
_ARM_MARK_RE = re.compile(r"【本臂窄任务（(G[123])｜id=([^】]*)）】")


def _arm_marker(ref: dict):
    return _ARM_MARK_RE.search(str(ref.get("task", "") or ""))


def _arm_group_of(ref: dict) -> str:
    g = str(ref.get("arm_group", "") or "").strip().upper()
    if g in ("G1", "G2", "G3"):
        return g
    m = _arm_marker(ref)
    return m.group(1) if m else ""


def _task_identity(ref: dict) -> str:
    """归一化的**窄任务题面**（用于判断「各臂是否在回答同一个问题」）。

    先取 `split_narrow_task`（剥 preflight 头 / 计划前缀），落到 `task` 全量再归一化。
    空串 = 无题面证据（不参与「同题」判定）。
    """
    t = split_narrow_task(str(ref.get("task", "") or ""))
    if not t:
        t = str(ref.get("task", "") or "")
    # 组标记（G#｜id=…）逐臂不同，但**不构成题目差异** ⟹ 先剥标记再比题面。
    t = _ARM_MARK_RE.sub("", t)
    return " ".join(t.split())


def _struct_assertion_ids(ref: dict) -> set:
    ids = set()
    struct = ref.get("assertions")
    if not isinstance(struct, list):
        return ids
    for a in struct:
        if not isinstance(a, dict):
            continue
        try:
            i = int(a.get("id", a.get("assertion_id")))
        except (TypeError, ValueError):
            continue
        if i > 0:
            ids.add(i)
    return ids


def _int_set(raw) -> set:
    out = set()
    for x in (raw or []):
        try:
            out.add(int(x))
        except (TypeError, ValueError):
            continue
    return out


def orthogonality_metrics(refs: list[dict], declared_by_id: dict | None = None,
                          declared_groups: dict | None = None,
                          coverage_target=None) -> dict:
    """由**实际** assertions[] 反算 G1/G2 正交（不接受「声明即事实」）。

    `declared_by_id` = {narrow_id: covers}；`declared_groups` = {G#: ⋃covers}；
    `coverage_target` = 目标断言 id 集。缺声明 ⟹ 只算 realized，scope/declared 维
    落 None（未测量）。
    """
    items = list(refs or [])
    realized = {"G1": set(), "G2": set()}
    n_with = 0
    scope_violations = []
    for r in items:
        g = _arm_group_of(r)
        if g not in realized:
            continue
        ids = _struct_assertion_ids(r)
        if not ids:
            continue
        n_with += 1
        realized[g] |= ids
        m = _arm_marker(r)
        nid = m.group(2) if m else ""
        if declared_by_id and nid and nid in declared_by_id:
            extra = ids - set(declared_by_id[nid])
            if extra:
                scope_violations.append({
                    "subagent_id": str(r.get("subagent_id", "") or ""),
                    "group": g, "narrow_id": nid,
                    "assertions": sorted(extra),
                })
    meas = n_with > 0
    inter = (realized["G1"] & realized["G2"]) if meas else None
    union = (realized["G1"] | realized["G2"]) if meas else set()
    out = {
        "measured": meas,
        "n_refs": len(items),
        "n_with_assertions": n_with,
        "G1": {"realized": sorted(realized["G1"])},
        "G2": {"realized": sorted(realized["G2"])},
        "realized_intersection": sorted(inter) if inter is not None else None,
        "realized_disjoint": None if inter is None else not inter,
        "realized_union": sorted(union),
        "declared_disjoint": None,
        "declared_covers_target": None,
        "missing_from_realized": None,
        "scope_violations": scope_violations,
    }
    if declared_groups:
        d1 = set(declared_groups.get("G1") or [])
        d2 = set(declared_groups.get("G2") or [])
        out["G1"]["declared"] = sorted(d1)
        out["G2"]["declared"] = sorted(d2)
        if d1 and d2:
            out["declared_disjoint"] = not (d1 & d2)
        target = _int_set(coverage_target)
        if target and d1 and d2:
            out["declared_covers_target"] = (d1 | d2) == target
            if meas:
                out["missing_from_realized"] = sorted(target - union)
    return out


def _narrow_declarations(state_file: str):
    """读 state 的窄任务清单 → ({id: covers}, {G#: ⋃covers}, coverage_target)。"""
    by_id, groups, target = {}, {"G1": set(), "G2": set(), "G3": set()}, []
    try:
        d = json.loads(Path(state_file).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return by_id, groups, target
    gd = d.get("gate_data") or {}
    for t in (gd.get("narrow_tasks") or []):
        if not isinstance(t, dict):
            continue
        cov = _int_set(t.get("covers"))
        nid = str(t.get("id", "") or "")
        if nid:
            by_id[nid] = cov
        g = str(t.get("group", "") or "").strip().upper()
        if g in groups:
            groups[g] |= cov
    target = sorted(_int_set(gd.get("coverage_target")))
    return by_id, groups, target


# ── 相关性闸（锚定闸，2026-10-06）────────────────────────────────────────────
# 前提（owner 裁定 + RCA/A8）：**默认输入存在污染信息**（人给的散文多为一知半解、
#   半对半错）⟹ 不能按列表项条数直接计缺陷；每条须与**批内证据词表**有锚定重叠才计入，
#   零重叠 ⟹ 隔离为 `unverified`（不计分、也不丢弃，可审计）。
# 与 `_shingles`（字符 2-gram；聚类用）**分工不同**：2-gram 对「零重叠」判定过宽（公共字
#   必然命中）⟹ 锚定闸须用更长判别单元（ASCII 词/路径段 ≥3；CJK 4-gram）。
_ASCII_TOK = re.compile(r"[A-Za-z_][A-Za-z0-9_./:-]{2,}")
_CJK_RUN = re.compile(r"[\u4e00-\u9fff]{2,}")
_REL_CJK_N = 4


def _relevance_tokens(text) -> set:
    """锚定闸 token（确定性）：ASCII 词/符号/路径段（≥3 字符）+ CJK 4-gram。"""
    s = str(text or "")
    out = set()
    for m in _ASCII_TOK.finditer(s):
        w = m.group(0).lower()
        out.add(w)
        for seg in re.split(r"[/.:-]+", w):
            if len(seg) >= 3:
                out.add(seg)
    for m in _CJK_RUN.finditer(s):
        run = m.group(0)
        if len(run) < _REL_CJK_N:
            out.add(run)
        else:
            for i in range(len(run) - _REL_CJK_N + 1):
                out.add(run[i:i + _REL_CJK_N])
    return out


def _refs_of(obj) -> list:
    """从聚合结果 / state 取 references（两形态皆可，单源）。"""
    if not isinstance(obj, dict):
        return []
    refs = obj.get("references")
    if isinstance(refs, list):
        return refs
    return (obj.get("gate_data") or {}).get("subagent_history") or []


def _latest_divergence(state_file):
    """本计划**最近一轮** `adjudicate` 的 divergence（双盲 `|agent−human|`）——P-meta 测量污染代理。

    只读 `gate_data.human_calibration_log[]` 末条含 divergence 者（单源，与 `gk_audit_state`
    同键）；缺失 / 不可读 ⟹ `None` ⟹ 调用方**不落** p_meta 通道（**不冒充已覆盖**）。
    """
    try:
        with open(state_file, encoding="utf-8") as fh:
            d = json.load(fh)
        recs = (d.get("gate_data") or {}).get("human_calibration_log") or []
        for r in reversed(recs if isinstance(recs, list) else []):
            if isinstance(r, dict) and r.get("divergence") is not None:
                return r["divergence"]
    except Exception:  # noqa: BLE001  —— 边界：state 不可读 ⟹ 无 p_meta（不阻断）
        return None
    return None


# ── p_art 观测量：**本批产物**缺陷率（T5/WS2，2026-10-06）────────────────────────
# ⚠ 设计更正（2026-10-06，测试暴露）：**不**把仓级 bomb 折入 `p_art` —— bomb 是**全局、与批无关**
#   的源码迁移债；折入批级 tilt 会退化为**常数**（实测 `bomb_total≥_BOMB_REF` ⟹ 饱和 1.0 ⟹
#   `agreement_eff` 恒 0、失去判别力）。类别错误：批级 p_art 应量**本批产出**是否被污染。
#   bomb（仓级产物健康）登记为**未来独立信号**，不作批级通道（见 plan §3.1/§6）。
def _finding_batch(f: dict) -> str:
    """从 finding 取**批身份**（单源次序：结构化 facet `batch:` → 锚 `batch:`）。

    修（2026-10-10，`ECC-0BA041A4284E`）：生产者 `emit_aggregate_finding` 的
    `root_key = sha256(plan|batch)[:16]`（批号**不可读**）⟹ 原按 `batch in root_key` 取批
    **恒空**（实测 p_art 通道死）。改读**可读载体**；旧账（09-14 起）也带 `batch:` 锚
    ⟹ 免 root_key 兜底、无假匹配（12 位十六进制批号撞 16 位哈希子串）风险。
    """
    for x in (f.get("facets") or []):
        s = str(x)
        if s.startswith("batch:"):
            return s.split(":", 1)[1]
    for a in (f.get("anchors") or []):
        s = str(a)
        if s.startswith("batch:"):
            return s.split(":", 1)[1]
    return ""


def _latest_defect_rate(state_file, batch):
    """p_art 观测量：**本批产物**缺陷率 = 批内 `rejected` / 批内 finding 总数。

    「产物」= 本批 MoA 落下的 finding（`batch:` facet / 锚 = 该批，见 `_finding_batch`）；
    缺陷 = 复验失败（`status == "rejected"`）。无本批 finding ⟹ `None`（**不冒充**）。
    **读侧 union**（2026-10-26，D 子计划 §14.4-5）：主账 + `*.finding-archive.jsonl` 溢出片
    （单源 = `gk_finding.load_findings_union`）—— 原只读主账 ⟹ 已溢出的本批 finding 漏读，
    `p_art` 会静默变 `None`（与 `MU_BACKCAST_NEGATIVE` 同族的读分裂）。只读、不写盘、不抛。
    """
    try:
        import gk_finding
        fs = gk_finding.load_findings_union(state_file)
    except Exception:  # noqa: BLE001  —— 边界：state 不可读 ⟹ 无 p_art
        return None
    _b = str(batch or "")
    if not isinstance(fs, list) or not _b:
        return None
    scoped = [f for f in fs
              if isinstance(f, dict) and _finding_batch(f) == _b]
    if not scoped:
        return None
    rej = sum(1 for f in scoped if str(f.get("status")) == "rejected")
    return rej / len(scoped)


def _ref_text(r: dict) -> str:
    """一个 ref 的全部可用文本（证据 / 任务 / 结论 / 质询三件套 / findings）拼成文档。"""
    if not isinstance(r, dict):
        return ""
    parts: list = []
    for e in (r.get("evidence") or []):
        parts.append(e.get("file", "") if isinstance(e, dict) else str(e))
    for k in ("task", "conclusion"):
        parts.append(str(r.get(k, "")))
    for k in ("challenges", "kept", "slashed"):
        parts.extend(str(x) for x in (r.get(k) or []))
    f = r.get("findings") or {}
    if isinstance(f, dict):
        for k in ("worked", "failed", "not_tried"):
            parts.extend(str(x) for x in (f.get(k) or []))
    return " \n ".join(parts)


def context_vocab(obj) -> set:
    """**锚定硬下限**词表：全部 ref 文本的 token 并集（零重叠 ⟹ 直接判 out）。"""
    v: set = set()
    for r in _refs_of(obj):
        v |= _relevance_tokens(_ref_text(r))
    return v


# ── BM25 稀疏相关性（2026-10-06）────────────────────────────────────────────
# 「语料清洗 → 高维 token 空间算相关性」的**零依赖**实现（对齐 owner 裁定：不用 LLM 自带
#   BPE/embeddings —— 前者仍是子词频率、后者需装模型破「零依赖/离线自足」）。
# 每 ref = 一篇文档；query = 待判散文条目。取**最大** BM25 分（最匹配的那一臂）。
# 简化：文档存 token **集合**（词频恒 1）⟹ 退化为「IDF 加权命中 + 长度归一」，仍满足
#   「稀有锚比公共词更有判别力」。阈值 τ 默认 0（= 锚定闸生效），τ>0 需跨批标定。
_BM25_K1 = 1.5
_BM25_B = 0.75


def _bm25_docs(refs: list) -> tuple[list, list]:
    docs, lens = [], []
    for r in refs:
        t = _relevance_tokens(_ref_text(r))
        docs.append(t)
        lens.append(len(t))
    return docs, lens


def bm25_relevance(query, docs: list, lens: list,
                   *, k1: float = _BM25_K1, b: float = _BM25_B) -> float:
    """query 对文档集的**最大** BM25 分（IDF 加权 + 长度归一）；空语料 ⟹ 0.0。"""
    n = len(docs)
    if not n:
        return 0.0
    avgdl = (sum(lens) / n) or 1.0
    qt = _relevance_tokens(query)
    if not qt:
        return 0.0
    best = 0.0
    for d, dl in zip(docs, lens):
        if not d:
            continue
        s = 0.0
        for t in qt:
            if t not in d:
                continue
            df = sum(1 for x in docs if t in x)
            idf = math.log(1.0 + (n - df + 0.5) / (df + 0.5))
            s += idf * (1.0 * (k1 + 1)) / (1.0 + k1 * (1 - b + b * dl / avgdl))
        if s > best:
            best = s
    return round(best, 4)


def relevance_judge(query, refs: list, *, min_score: float = 0.0) -> dict:
    """锚定闸（硬下限）+ BM25（分级）**与**判定 ⟹ `{"anchor","bm25","in"}`。

    - `anchor` = 与批内词表的共享 token 数（0 ⟹ 无论 BM25 多高都判 out，防公共词误放）；
    - `bm25`  = 最大 BM25 分（落 facet，供后续 τ 标定）；
    - `in`    = `anchor > 0 and bm25 >= min_score`。
    """
    docs, lens = _bm25_docs(refs)
    vocab = set().union(*docs) if docs else set()
    qt = _relevance_tokens(query)
    shared = len(qt & vocab)
    sc = bm25_relevance(query, docs, lens)
    _in = bool(shared) and sc >= float(min_score)
    return {"anchor": shared, "bm25": sc, "in": _in,
            "weak": bool(_in) and (shared <= 1 or sc < 1.0)}


_VERDICT_PREFIX = (
    ("PASS", "PASS"), ("OK", "PASS"),
    ("WARN", "WARN"), ("SUSPECT", "WARN"), ("PARTIAL", "WARN"), ("UNCERTAIN", "WARN"),
    ("BLOCK", "BLOCKED"), ("FAIL", "BLOCKED"), ("REJECT", "BLOCKED"),
)


def _canon_verdict(v) -> str:
    """把带散文后缀的裁决值归一（"OK（#3…" → PASS；"suspect（…" → WARN）。

    首轮实跑 1/11 臂在 `verdicts` 里写散文（runner 按纪律保留原文 + 记 vocab_violation），
    若聚合侧直接按原串计数，F1-F7 会被拆成互不相交的伪值 ⟹ 共识不可读。
    """
    s = str(v or "").strip().upper()
    if not s:
        return ""
    for pre, out in _VERDICT_PREFIX:
        if s.startswith(pre):
            return out
    return s[:64]


def _ref_signature_tokens(ref: dict) -> tuple:
    """S1-2（2026-10-06）：**结构化签名** token 集 —— 优先 `verdicts`(F1-F7)，再
    `challenges`/`kept`/`slashed` 条目 shingle，最后才退回 `conclusion` 文本 shingle。

    动机（真实 6 臂批 `2a8b9e701e67` 实测）：plan-refinement 臂结论是各 ~3000 字**长散文**，
    按整段文本聚类 ⟹ 6 臂 6 簇（零合并，「聚合没信息」）；而**一致/分歧住在结构化字段里**
    （本批 6 臂 verdicts 齐备、ch/kept/sl 各 4-5 条）。改按结构化字段聚类 ⟹ 本批得 5+1 簇
    （G3 离群可识别）。返回 `(tokens, source)`；`source ∈ verdicts|items|conclusion`。
    """
    v = ref.get("verdicts") or {}
    if isinstance(v, dict) and v:
        return {("V", str(k).upper(), _canon_verdict(val)) for k, val in v.items()}, "verdicts"
    items = []
    for k in ("challenges", "kept", "slashed"):
        for x in (ref.get(k) or []):
            items.append(str(x))
    if items:
        return {("S", s) for s in _shingles(" \n ".join(items))}, "items"
    return {("C", s) for s in _shingles(ref.get("conclusion", ""))}, "conclusion"


def _avg_linkage_lw(sim, n: int, tau: float) -> list:
    """**平均连接凝聚（Lance-Williams 增量 + 最大堆）**——与朴素 `O(n³)` 版**逐项等价**。

    朴素版每轮重扫全部簇对、并对成员对逐个求和 ⟹ `O(n³)`。本版按 LW 闭式增量维护簇间平均相似：
        s(AB,C) = (|A|·s(A,C) + |B|·s(B,C)) / (|A|+|B|)
    堆键 = `(-avg, rep_a, rep_b)`；`rep` = 簇内**最小原始下标**（= 朴素版 `groups` 的排序键 ⟹ 并列时
    取 (rep_a,rep_b) 最小者，与朴素版「按序扫描取首个最大」一致）。复杂度 `O(n² log n)`（原 `O(n³)`）。
    惰性删堆：弹出项若簇已并/该对已被改写则跳过。
    """
    import heapq
    alive = {i: 1 for i in range(n)}          # rep → size
    members = {i: [i] for i in range(n)}      # rep → member 列表（首元素 = rep）
    smat, heap = {}, []

    def key(x, y):
        return (x, y) if x < y else (y, x)

    for a in range(n):
        for b in range(a + 1, n):
            v = float(sim[a][b])
            smat[(a, b)] = v
            heap.append((-v, a, b))
    heapq.heapify(heap)

    while len(alive) > 1:
        best = None
        while heap:
            negv, a, b = heapq.heappop(heap)
            v = -negv
            if a not in alive or b not in alive or smat.get((a, b)) != v:
                continue
            best = (v, a, b)
            break
        if best is None or best[0] < tau:
            break
        _, a, b = best
        sa, sb = alive[a], alive[b]
        tot = sa + sb
        for c in list(alive.keys()):
            if c == a or c == b:
                continue
            nv = (sa * smat[key(a, c)] + sb * smat[key(b, c)]) / tot
            kk = key(a, c)
            smat[kk] = nv
            heapq.heappush(heap, (-nv, kk[0], kk[1]))
        for c in list(alive.keys()):
            if c != b:
                smat.pop(key(b, c), None)
        members[a] = members[a] + members[b]
        del members[b]
        alive[a] = tot
        del alive[b]

    groups = [members[r] for r in alive]
    groups.sort(key=lambda g: (-len(g), g[0]))
    return groups


def _avg_linkage(sim, n: int, tau: float) -> list:
    """平均连接凝聚聚类（对外入口）：委托 Lance-Williams 增量实现 `_avg_linkage_lw`。"""
    return _avg_linkage_lw(sim, n, tau)


def _verdict_consensus(refs: list[dict]) -> dict:
    """S1-2：逐 F1-F7 的**批内判定分布**（计数 / 多数 / 是否一致）——「聚合出了什么」的可读载体。"""
    from collections import Counter
    per = {}
    for code, _label in _F17:
        c = Counter()
        for r in refs:
            v = r.get("verdicts")
            val = v.get(code) if isinstance(v, dict) else None
            if val:
                c[_canon_verdict(val)] += 1
        if c:
            per[code] = {"counts": dict(sorted(c.items())),
                         "majority": c.most_common(1)[0][0],
                         "unanimous": len(c) == 1}
    return per


# A8-①（P-2，`ECC-715E4C8DD7C2`）：**臂数轴**有效样本量下限 —— `n_eff` 低于此 ⟹ 独立臂不足
#   （折叠 / 隐蔽耦合），高一致度**不可**读作真收敛。门当前**只暴露**（`independence_ok`），
#   **不**并入 `abstain`（折叠进默认 abstain 会反转 unanimous-consensus 语义 ⟹ 属 owner 决策）。
_N_EFF_MIN = 2.0


def cluster_references(refs: list[dict], tau: float = _CLUSTER_TAU,
                       min_agreement: float = _CLUSTER_MIN_AGREE,
                       pollution_tilt: float = None,
                       strict_independence: bool = False) -> dict:
    """按**结构化字段签名**对 references 聚类；返回 `{clusters, consensus}`。

    S1-2（2026-10-06）：签名优先 `verdicts`，其次 `challenges/kept/slashed`，最后才 `conclusion`；
    连接 = **平均连接**（抗链式）。一致度 = **逐 F 多数占比均值**（有 verdicts 时），否则退化为
    最大簇权重。纯函数、确定性（无 LLM / 无网络 / 无随机 / 零新依赖）。

    矛盾探测（P2，2026-10-06）：**去 G3 标签**（G1/G2/G3 与人类评审全通道皆可污染；G3 = 明确
    投毒，不作判据）—— 判据 = ① 有 verdicts 时与逐 F 多数相左，或 ② 无 verdicts 时
    「非最大簇 且 size≥2」；G3 仅作 `clusters[].arm_groups` 元数据。

    A8-④（2026-10-06）：`pollution_tilt` = **批级、全臂**的**合成**污染落地率 κ_tilt
    （三通道 `p_in` 输入 / `p_art` 产物 / `p_meta` 测量合成 `tilt_total`，单一来源
    = `gk_moa_kappa.combined_tilt`）——污染存在于 **G1/G2/G3 与人类评审**全部通道，
    G3 只是**明确投毒**，**不作判据** ⟹ 一致度乘性折扣 `agreement_eff = agreement·(1−κ_tilt)`；
    `None` ⟹ 无折扣（逐字零回归）。**不**从 `arm_group` 推导 κ。
    ⚠ 数据现状（2026-10-06 晚，接通后）：ledger **静态样本仅 `p_in`**；`p_meta` 另由
    实时 `divergence`（`gate_data.human_calibration_log`）**派生**、`p_art` 待调用方供
    `defect_rate`（后验）。⟹ 有 divergence 时实效 = **P-in ⊕ P-meta**；无则退化为 P-in。
    仍**不冒充**：观测缺失的通道不落值（不按 0 计入，只跳过）。
    """
    items = list(refs or [])
    n = len(items)
    # 2026-10-21（`ECC-65986D800D26`）：**题面异构**批 —— 每个臂回答的是**不同问题**
    #   （plan-refinement 的 Q1/Q2+Q3/Q4 各自成题）时，跨臂「一致/矛盾/有效样本量」
    #   都不成立：没有两臂回答同一问题，就不存在复现，也不存在分歧。实测病象：
    #   Q4 单臂（与另两臂不同题）被标成 `contradiction c1`，`n_eff=1.8` 把
    #   「题目不同」误报成「臂不独立」。判据 = 所有臂都有题面且两两不同。
    tids = [_task_identity(r) for r in items]
    task_heterogeneous = bool(n >= 2 and all(tids) and len(set(tids)) == n)
    sigs, sources = [], []
    for r in items:
        t, s = _ref_signature_tokens(r)
        sigs.append(t)
        sources.append(s)
    sim = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            v = _jaccard(sigs[i], sigs[j])
            sim[i][j] = sim[j][i] = v
    groups = _avg_linkage(sim, n, tau)
    clusters = []
    cverdicts = []
    for idxs in groups:
        gc: dict[str, int] = {}
        for i in idxs:
            g = str(items[i].get("arm_group", "") or "").strip() or "—"
            gc[g] = gc.get(g, 0) + 1
        rep = idxs[0]
        rv = items[rep].get("verdicts")
        cverdicts.append({str(k).upper(): str(x).upper() for k, x in rv.items()}
                         if isinstance(rv, dict) else {})
        clusters.append({
            "id": "c%d" % len(clusters),
            "size": len(idxs),
            "members": [str(items[i].get("subagent_id", "")) for i in idxs],
            "representative_id": str(items[rep].get("subagent_id", "")),
            "representative_text": str(items[rep].get("conclusion", "") or ""),
            "signature_source": sources[rep],
            "arm_groups": dict(sorted(gc.items())),
            "distinct_tasks": len({tids[i] for i in idxs if tids[i]}),
            "weight": round(len(idxs) / n, 4) if n else 0.0,
            "contradiction": False,
        })
    total = sum(c["size"] for c in clusters)
    top = clusters[0] if clusters else None
    top_w = top["weight"] if top else 0.0
    vc = _verdict_consensus(items)
    # 矛盾探测（P2，2026-10-06：**去 G3 标签**）——G1/G2/G3 与人类评审**全通道皆可污染**，
    #   G3 只是明确投毒 ⟹ 不作判据。标签无关判据：
    #     ① 有 verdicts：该簇代表 verdict 与逐 F 多数**相左**（语义矛盾）；
    #     ② 无 verdicts：非最大簇 且 size ≥ 2（真实竞争共识；单例「噪音 vs 真矛盾」不可区分）。
    for c, cv in zip(clusters, cverdicts):
        is_top = c is top
        # 题面异构 ⟹ 任何跨臂 verdict 差异都是「题目不同」，不是矛盾（禁误标 P）。
        same_question = not task_heterogeneous
        if vc and cv:
            c["contradiction"] = bool(
                same_question and not is_top and any(
                    code in vc and vc[code]["majority"] != cv.get(code)
                    for code in cv))
        else:
            c["contradiction"] = bool(
                same_question and not is_top and c["size"] >= 2)
    agreement = top_w
    if vc:
        fracs = []
        for code in vc:
            m = vc[code]["majority"]
            fracs.append(vc[code]["counts"].get(m, 0) / max(sum(vc[code]["counts"].values()), 1))
        agreement = round(sum(fracs) / len(fracs), 4)
    # A8-④ 乘性污染折扣（2026-10-06）：agreement_eff = agreement·(1−κ_tilt)。
    #   **批级、全臂**（污染存在于 G1/G2/G3 与人类评审**全部通道**；G3 只是**明确投毒**，不作判据）——
    #   κ_tilt = **批级合成**落地率（三通道 `p_in`/`p_art`/`p_meta`；单一来源 = `gk_moa_kappa`，
    #   见 `combined_tilt`），**不**从 arm_group 推导。
    #   ⚠ 数据现状（接通后）：ledger 静态样本仅 `p_in`；`p_meta` 由实时 `divergence` 派生
    #   （见 aggregate 调用点），`p_art` 待调用方 `defect_rate` ⟹ 有 divergence 时实效 = P-in ⊕ P-meta。
    #   `pollution_tilt is None` ⟹ 无折扣（逐字零回归；κ_tilt=0 亦同）。
    _pt = 0.0 if pollution_tilt is None else max(0.0, min(1.0, float(pollution_tilt)))
    agreement_eff = round(agreement * (1.0 - _pt), 4)
    # A8-①（P-2，`ECC-715E4C8DD7C2`）：臂数轴**有效样本量**（Kish）n_eff = n²/Σsize² —— 从**已算**的
    #   簇大小复算（§9.5 AP2「禁重复规划」：复用既有聚类，不另起估计器）。折叠越多 ⟹ n_eff 越小。
    n_eff_raw = round((total ** 2) / sum(c["size"] ** 2 for c in clusters), 4) if total else 0.0
    # 题面异构 ⟹ 臂数轴 Kish 无效（各臂不是同一问题的复现）：`n_eff` 记 None（未测量），
    #   原始值保留在 `n_eff_raw` 仅供审计，不参与 independent 判据。
    n_eff = None if task_heterogeneous else n_eff_raw
    # A8-①（`ECC-8B2C819EDE7D`）：opt-in **硬门** —— `strict_independence=True` 时
    #   `n_eff < _N_EFF_MIN` 并入 `abstain`（**缺省 False ⟹ 逐字零回归**，不反转
    #   unanimous-consensus 语义）。题面异构时该门不适用（已在 `_task_split` 单独弃权）。
    # 题面异构（2026-10-21）：agreement 是**跨臂同题**的一致度；题目不同 ⟹ 分母无意义，
    #   不得据此判 `_low_agree`（否则 abstain_reason 会同时报 agreement，误导下游归因）。
    _low_agree = bool(not task_heterogeneous and agreement_eff < min_agreement)
    _low_indep = bool(strict_independence and not task_heterogeneous
                      and n_eff_raw < _N_EFF_MIN)
    _task_split = bool(task_heterogeneous)
    _abstain = _low_agree or _low_indep or _task_split
    _abstain_reason = ",".join([r for r, on in (("agreement", _low_agree),
                                               ("independence", _low_indep),
                                               ("task_heterogeneous", _task_split)) if on])
    # 证据同源度（2026-10-18）：裁决高一致但证据有效样本量不足 ⟹ 同源回声，
    #   `false_convergence=True`。未测到 source ⟹ None（不判）。
    _so = source_overlap(items)
    _false_conv = (None if (task_heterogeneous or _so["n_eff_evidence"] is None)
                   else bool(agreement >= _FALSE_CONV_AGREE
                             and _so["n_eff_evidence"] < _N_EFF_MIN))
    consensus = {
        "n_refs": total,
        "n_clusters": len(clusters),
        "top_id": top["id"] if top else "",
        "top_weight": top_w,
        "agreement": agreement,
        "agreement_eff": agreement_eff,
        "pollution_tilt": _pt,
        "min_agreement": round(min_agreement, 4),
        # A8-①（P-2）：臂数轴 Kish 有效样本量 + 独立度门（**只暴露**，不并入 abstain；见 `_N_EFF_MIN` 注）。
        # 题面异构 ⟹ `n_eff`/`independence_ok` 记 None（未测量，禁冒充），原始值留 `n_eff_raw`。
        "n_eff": n_eff,
        "n_eff_raw": n_eff_raw,
        "n_eff_min": _N_EFF_MIN,
        "independence_ok": (None if task_heterogeneous
                            else bool(n_eff_raw >= _N_EFF_MIN)),
        # 题面异构（2026-10-21）：各臂回答不同问题 ⟹ 跨臂一致度不可比，只可逐臂读。
        "task_heterogeneous": task_heterogeneous,
        "task_count": len({t for t in tids if t}),
        "agreement_scope": ("task_heterogeneous" if task_heterogeneous else "batch"),
        "agreement_comparable": (not task_heterogeneous),
        # W2A 金字塔（2026-10-18）：证据同源度 —— 裁决独立 ≠ 证据独立。
        "rho": _so["rho"],
        "n_eff_evidence": _so["n_eff_evidence"],
        "source_coverage": _so["source_coverage"],
        "false_convergence": _false_conv,
        "abstain": _abstain,               # P7：一致度不足（+ strict 时 独立度不足）⟹ 弃权，不硬判
        "abstain_reason": _abstain_reason,  # `agreement` / `independence` / 两者（逗号分隔）/ ""
        "coverage_g2": sum(1 for c in clusters if "G2" in c["arm_groups"]),
        "contradictions": [c["id"] for c in clusters if c["contradiction"]],
        "verdict_consensus": vc,
    }
    return {"clusters": clusters, "consensus": consensus}


def _task_display(task: str, width: int = 200) -> str:
    """§18-N3（2026-10-03，`ECC-5538DD07B709` RC4）：任务行的**可区分**显示。

    原 `task[:200]` 在 standing 模板前缀 >200 字符时使所有 reference 任务行**逐字相同**
    ⟹ 聚合器无法从报告做归属（F-REV-53 落库侧已去截断，此处是**显示面**复发）。
    修法：单行化后超长则 head+tail 省略（保留**尾部**区分信息，与 F-REV-53 同判据）。
    """
    t = " ".join(str(task or "").split())
    if len(t) <= width:
        return t
    head = width // 2
    tail = width - head
    return t[:head].rstrip() + " …[" + str(len(t)) + "字]… " + t[-tail:].lstrip()


def render_md(agg: dict) -> str:
    L = []
    L.append("# MoA 聚合器输出（多 subagent references → 主 agent 裁决输入）\n")
    # ECC-4A6DA8F310F5（2026-10-10）：原 `--md` 通道**只**渲染 references，不渲染 `error`/`hint`
    #   ⟹ 未知批号 / task 零命中时 md 面看不到任何错误信息（仅 rc=1 可见 = 半静默）。补齐前置块。
    if agg.get("error"):
        L.append(f"> ⚠ **聚合错误**：`{agg.get('error')}`")
        if agg.get("hint"):
            L.append(">")
            L.append(f"> {agg['hint']}")
        L.append("")
    tr = agg.get("trace", {})
    L.append("| 维度 | 值 |")
    L.append("|:--|:--|")
    L.append(f"| references 数 | {tr.get('count', 0)} |")
    L.append(f"| suspect 引用数 | {tr.get('suspect_count', 0)} |")
    L.append(f"| 来源 | {tr.get('source', '')} |")
    L.append(f"| subagent_ids | {', '.join(tr.get('ids', [])[:6]) or '—'} |")
    # F-REV-8：归属留痕 —— 聚合边界在报告里可见（防跨任务混聚无痕）
    at = tr.get("attribution", {}) or {}
    L.append(f"| 归属校验 | mode={at.get('mode', '?')} · anchor={at.get('anchor', '—')} "
             f"({at.get('anchor_from', '—')}) · 排除异任务 {at.get('excluded_other_tasks', 0)} 条 |")
    # 新鲜度留痕（2026-09-28）：判据窗口 + 被剔除条数 —— 防「静默剔除」不可审计。
    L.append(f"| 新鲜度 | ttl={at.get('fresh_ttl', 0)}s · 排除过时 {at.get('stale_excluded', 0)} 条 "
             f"· 无日期 {at.get('undated_excluded', 0)} 条 |")
    # §18.1：批分节留痕 —— 批边界/规模/权重/跨批放开态在报告里可见（防跨批混聚无痕）
    _bt = tr.get("batch", {}) or {}
    _bs = " · ".join("%s(size=%d,w=%s)" % (x.get("batch_id") or "unbatched", x.get("size", 0),
                                          x.get("weight", 1.0))
                     for x in _bt.get("batches", [])) or "—"
    L.append(f"| 批分节 | mode={_bt.get('mode', '?')} · 跨批放开={_bt.get('cross_batch_allowed', False)} "
             f"· {_bs} |")
    L.append("")
    # §3 G3（2026-10-26）：MD 原只知「有几批」，看不到逐批一致度 ⟹ 补表（与 HTML 同源 = `batch_sections`）
    _secs = agg.get("batch_sections") or []
    if _secs:
        L.append("**批分节逐批读数**（顶层共识 = 最大批，见 `batch_sections`）\n")
        L.append("| 批 | 臂数 | 权重 | 簇 | 一致度 | 弃权 |")
        L.append("|:--|--:|--:|--:|--:|:--|")
        for _s in _secs:
            _c = _s.get("consensus") or {}
            L.append("| %s | %s | %s | %s | %s | %s |" % (
                _s.get("batch_id") or "unbatched", _s.get("n_refs"), _s.get("weight"),
                _c.get("n_clusters", 0), _c.get("agreement", _c.get("top_weight", "")),
                "是" if _c.get("abstain") else "否"))
        L.append("")
    L.append("## 聚合器指引（锁死，防 reference 污染）\n")
    L.append(agg.get("aggregator_guidance", ""))
    L.append("")
    for i, r in enumerate(agg.get("references", []), 1):
        L.append(f"## Reference {i} — `{r.get('subagent_id','')}`\n")
        _narrow = split_narrow_task(r.get("task", ""))
        _rbs = str(r.get("budget_status", ""))
        _rtt, _rtb = r.get("total_tokens", 0), r.get("token_budget")
        L.append(f"- 任务: {_task_display(_narrow or r.get('task',''))} "
                 f"· 指纹 {task_fingerprint(_narrow or r.get('task',''))}")
        L.append(f"- 置信度: {r.get('confidence','')} · 预算: {_rbs} "
                 f"({_rtt}/{_rtb or '—'} tokens, "
                 f"{r.get('total_items',0)}/{r.get('item_budget') or '—'} items)")
        if (_rbs in ("hard", "item_exceeded", "max_turns")
                or (isinstance(_rtb, (int, float)) and isinstance(_rtt, (int, float))
                    and _rtb and _rtt > _rtb)):
            L.append("- 预算耗尽 · 输出可能截断（UNKNOWN,≠否定）")
        _rnt = (r.get("findings") or {}).get("not_tried") or []
        if _rnt:
            L.append(f"- 未读到 {len(_rnt)} 项（UNKNOWN,≠否定）")
        for _v in (r.get("vocab_violations") or []):
            if isinstance(_v, dict):
                L.append(f"- 词表外判定 {_v.get('key','')} = {str(_v.get('raw',''))[:120]}"
                         f"（{_v.get('reason','')}）")
        # F-REV-41（2026-09-13）：MD 通道原只打 hmac_status、漏 suspect ⇒ 人读聚合报告看不到
        # 可疑标记（与 assessment §8.3 "主 agent 可审计每引用可信度" 的 md 面半失效）。补齐。
        _sus = r.get("suspect") or []
        L.append(f"- HMAC: {r.get('hmac_status','')} · suspect: {', '.join(_sus) if _sus else '—'}")
        L.append("")
        L.append("### 结论\n")
        L.append((r.get("conclusion", "") or "—").strip())
        L.append("")
        ev = r.get("evidence") or []
        if ev:
            L.append("### 证据\n")
            for e in ev:
                if isinstance(e, dict):
                    L.append(f"- `{e.get('file','')}:{e.get('lines','')}` ({e.get('status','')})")
                else:
                    L.append(f"- {e}")
            L.append("")
        f = r.get("findings") or {}
        if isinstance(f, dict) and any(f.get(k) for k in ("worked", "failed", "not_tried")):
            L.append("### 发现\n")
            for t in ("worked", "failed", "not_tried"):
                for x in (f.get(t) or []):
                    L.append(f"- [{t}] {x}")
            L.append("")
        if r.get("next_steps"):
            L.append("### 下一步\n")
            for x in r["next_steps"]:
                L.append(f"- {x}")
            L.append("")
    L.append("---\n")
    L.append("> 主 agent（聚合器）读取以上独立 references 后，按聚合器指引输出融合裁决。")
    return "\n".join(L)


def aggregate(state_file: str, recent: int | None, role: str | None,
              task: str = "", allow_cross_task: bool = False, fresh_s: int = 0,
              plan: str = "", batch: str = "", allow_cross_batch: bool = False,
              strict_independence: bool = False) -> dict:
    entries, attribution = collect_entries(state_file, recent, role, task,
                                           allow_cross_task, fresh_s, plan, batch)
    refs = []
    for en in entries:
        # F-REV-41（2026-09-13）：原实现 `"verified_at_write" if not en.get("_hmac_unverified")`
        # 恒真（_hmac_unverified 从未落库）⇒ 无 key 未验签也标 verified。现按 CLI 落库的
        # hmac_status 显式映射：valid→已验签；no_hmac/skip/invalid→未验签（不冒充已验证）。
        ref = sanitize_reference(en)
        _hs = str(en.get("hmac_status", "") or "").lower()
        if _hs:
            ref["hmac_status"] = _HMAC_STATUS_LABEL.get(_hs, _hs)
        else:
            ref["hmac_status"] = "unverified" if en.get("_hmac_unverified") else "unknown"
        ref["suspect"] = _suspect_flags(en)  # 投毒清洗第二层：可疑引用标记（主 agent 降权/交叉验证）
        mark_ingest_taint(ref)   # T5-A5：入站统一打标（与检测解耦）+ Spotlighting 分隔视图
        refs.append(ref)
    out = {
        "mode": "moa_aggregate",
        "aggregator_guidance": AGGREGATOR_GUIDANCE,
        "references": refs,
        # T5-A5：聚合输出**整体** = 不可信来源（摄取边界留痕，与检测无关）——消费方据
        #   `provenance` 决定下游（派生 finding 亦为 untrusted ⟹ 后果性汇点须 declassify）。
        "provenance": "untrusted",
        "taint_boundary": "ingest",
        "trace": {
            "count": len(refs),
            "ids": [r.get("subagent_id", "") for r in refs],
            "source": state_file,
            "sanitized": True,
            "suspect_count": sum(1 for r in refs if r["suspect"]),
            # F-REV-8：回读点归属留痕（模式 / 锚指纹 / 被排除的异任务条数）
            "attribution": attribution,
            # §18.1：批边界 / 规模 / 权重 / 跨批放开态恒进 trace（非静默，防跨批混聚无痕）
            "batch": {**batch_sections(entries),
                      "cross_batch_allowed": bool(allow_cross_batch)},
        },
    }
    # S1（2026-10-06）：跨臂去重聚类 + 三组语义（clusters/consensus）并入聚合输出
    # A8-④（2026-10-06）：**批级** κ_tilt 由 ledger 按批 id 解析（单一来源 = gk_moa_kappa.batch_tilt）；
    #   未知批 / ledger 不可用 ⟹ `None` ⟹ 无折扣（**不阻断**）。**不**从 arm_group 推导
    #   （污染三通道 `p_in`/`p_art`/`p_meta` 遍及 G1/G2/G3 与人类评审，G3 只是明确投毒）。
    #   合成 `tilt_total = 1 − Π(1−κ_tilt_i)`；ledger 缺 `channels` ⟹ legacy 仅 P-in（零回归）。
    _pt = None
    if batch:
        try:
            from gk_moa_kappa import batch_tilt as _batch_tilt
            # 接通三通道（2026-10-06，WS2）：p_in=投毒命中率（现场 refs）/ p_meta=**滞后**的双盲
            #   divergence（上一轮 adjudicate）/ p_art=缺陷产物率（findings⊕bomb）。缺观测的通道
            #   **不落值**（不冒充已覆盖）；ledger 通道与 live 按通道 merge（live 覆盖，防双计）。
            _n_refs = len(refs)
            _n_poison = sum(1 for r in refs if poison_labels(_ref_text(r)))
            _poison_rate = (_n_poison / _n_refs) if _n_refs else None
            _pt = _batch_tilt(str(batch),
                              divergence=_latest_divergence(state_file),
                              defect_rate=_latest_defect_rate(state_file, str(batch)),
                              poison_rate=_poison_rate)
        except Exception:  # noqa: BLE001 — 边界：ledger 不可用 ⟹ 退化为无折扣（不阻断）
            _pt = None
    _cl = cluster_references(refs, pollution_tilt=_pt, strict_independence=strict_independence)
    out["clusters"] = _cl["clusters"]
    out["consensus"] = _cl["consensus"]
    _gm_refs = refs   # 分组指标与顶层共识同源（跨批门后改为所取批的臂）
    # §18.4（2026-10-11，ECC-9BD2FA550A78）：plan_bound 跨批**不静默混票**。
    #   病象：trace 只记 `mixed_batches`，但 consensus 仍对全臂混算；`--allow-cross-batch`
    #   在该路径为 no-op（加不加结果逐字相同，只翻 trace 布尔）⟹ 违反 §18.1「缺省按批
    #   分节（不混票）；跨批仅同 plan_path 且显式放开」。触发 = 同计划多轮质询（W2A 实测
    #   12 臂混成 6 簇，agreement 0.619 vs 分批 0.643/0.667）⟹ 分值失真、熔断判据被污染。
    #   修法：① **分节** —— 逐批各算 clusters/consensus，落 `batch_sections`（可核载体）；
    #         ② **门** —— 缺省顶层共识取**首批（最大批）**并 fail-loud
    #            （`error=cross_batch_requires_ack`）；仅显式放开才合并（零回归：单批不变）。
    _bs = out["trace"]["batch"]
    if _bs.get("mixed_batches"):
        _sections = []
        for _b in _bs["batches"]:
            _ids = set(_b["ids"])
            _brefs = [r for r in refs if str(r.get("subagent_id", "")) in _ids]
            _bcl = cluster_references(_brefs, pollution_tilt=None,
                                      strict_independence=strict_independence)
            _sections.append({"batch_id": _b["batch_id"], "n_refs": len(_brefs),
                              "weight": _b["weight"],
                              "clusters": _bcl["clusters"], "consensus": _bcl["consensus"]})
        out["batch_sections"] = _sections
        if not allow_cross_batch:
            _top = _sections[0]  # batches 已按 size 降序 ⟹ 最大批
            out["clusters"] = _top["clusters"]
            out["consensus"] = _top["consensus"]
            _keep = set(_bs["batches"][0].get("ids") or [])
            _gm_refs = [r for r in refs
                        if str(r.get("subagent_id", "")) in _keep]
            out["error"] = "cross_batch_requires_ack"
            out["hint"] = ("同计划多批（%d 批，共 %d 臂）：缺省**按批分节、不混票** —— 顶层共识 "
                           "= 最大批（batch_id=%s）之节，逐批见 `batch_sections`。确需跨批比较请"
                           "显式加 `--allow-cross-batch`（trace 记 cross_batch_allowed）。"
                           % (len(_sections), len(refs), _top["batch_id"]))
    # 禁静默：显式 --task 锚定却零命中 → 报错而非返回空聚合
    if task and attribution.get("mode") == "task_bound" and not refs:
        out["error"] = "no_entry_matches_task"
        out["hint"] = ("该 task 指纹在 subagent_history 中无匹配（须传与落库一致的 task 原文；"
                       "落库侧自 F-REV-53 起不再截断）")
    # ECC-449948814679（2026-10-10）：显式 --batch 锚定却零命中 → **不静默**（rc≠0 + 提示可用批号）。
    #   防「批号写错」被下游误归因为「批内一致度不足 / 基础设施缺陷」并落误归因 finding。
    if batch and attribution.get("mode") == "batch_unresolved":
        out["error"] = "no_entry_matches_batch"
        out["hint"] = ("该批号在 subagent_history 中无匹配。`--batch` 吃的是 "
                       "`subagent_history[].batch_id`（聚合指纹，如 2162344a94db），**不是** "
                       "enqueue 回执 / `task_pipeline[].batch` 的流水线批号 `pr-<epoch>-<hex>`。"
                       "可用 batch_id：" + (", ".join(attribution.get("available_batch_ids") or []) or "（无）"))
    # 三组窄任务的分组指标（2026-10-19）：G1/G2/G3 语义不同，**不得**用单一全局
    #   rho 判所有组。与顶层 consensus 同源（跨批门后取所取批的臂）。
    out["group_metrics"] = group_metrics(_gm_refs)
    # 逐断言裁决矩阵（2026-10-19）：结论散文里的 support/refute/abstain 不再被全局
    #   agreement 平均掉；论文按断言报分歧。
    out["assertion_metrics"] = assertion_metrics(_gm_refs)
    # 实际正交（2026-10-19）：声明正交之外，再由**每臂实际 assertions[]** 反算；
    #   二者不一致（越界裁决 / 实际重叠 / 漏覆盖）必须在报告里显形，而非只看清单。
    _decl_by_id, _decl_groups, _decl_target = _narrow_declarations(state_file)
    out["orthogonality_metrics"] = orthogonality_metrics(
        _gm_refs, _decl_by_id, _decl_groups, _decl_target)
    return out


# ── 聚合落 finding（Infra-1a，2026-10-05，ECC-1F540718AEE5）────────────────────
# MoA 聚合原**只出"给主 agent 的引导"**（AGGREGATOR_GUIDANCE），自己不落 finding
#   ⟹ 每轮质询的结果不沉淀为**可跨轮比对**的台账 ⟹ RCA 的 μ_n（每轮新增压力）无从取数，
#   收敛评估器只能空转（本仓实测：4 轮 7 维均值 52→51→57→58，μ_n=[8,10,9,9] ρ≈1）。
# 本函数 = 把一次聚合落成一条 ECC finding（单一台账），**锚 = (plan, batch)**，供
#   `cross_round_convergence` 按批序取 μ_n 并算 ρ̂。幂等由 `root_key` 保证（同批重跑合并，
#   异批复用同一 root_key 前缀但异批段 ⟹ 不互相覆盖）。
# ── S2 finding 实质化（2026-10-06）──────────────────────────────────────────
# 缺陷（本会话实测）：`emit_aggregate_finding` 只落**一行计数台账**，无分类 / 无优化项 /
#   无详情文本（「怎么什么都没有」）。
# 修法（确定性、零 LLM）：由 `clusters`/`consensus` + 逐臂运行态信号推出
#   ① 分类 `plan-error` / `infra-defect` / `unknown`；② `optimization_items[]`
#   （每项 `carrier ∈ {P,L,M}`，对齐 group-dispatch §11 三向分流纪律）；③ `detail_text`
#   （簇代表 + 成员臂 + 三组分布；落 `source_note`）。载体 → 类（group-dispatch §11）：
#   P=计划文本 ⟹ plan-error；L=机检规则 / M=机制修复 ⟹ infra-defect。
_CARRIER_CLASS = {"P": "plan-error", "L": "infra-defect", "M": "infra-defect"}
# 载体简写释义（单一事实源 = group-dispatch §11 三向分流：(P) 计划文本修正 / (L) PW-SN 机检规则 /
#   (M) 同步机制修复）。渲染侧**必须**随缩写给出释义 —— 否则页面出现裸 `M`/`P`，人评者无从解读。
_CARRIER_LABEL = {"P": "计划文本", "L": "机检规则", "M": "机制修复"}
_CARRIER_LEGEND = "载体 P=计划文本 · L=机检规则 · M=机制修复（group-dispatch §11 三向分流）"
_BUDGET_BAD = ("hard", "item_exceeded", "max_turns")
# L（机检规则）面 = 逐臂**机检层**的缺失/失败（引用完整性词表，同 `_suspect_flags` 口径）。
_QUAL_SUSPECTS = ("hmac_unverified", "no_evidence", "zero_findings", "no_conclusion")
# 机检层**失败**取值（`machine_check.{verification,evidence_anchor}` 的 status；其余值视为通过）。
_MECH_BAD = ("incomplete", "failed", "fail", "error", "broken", "missing", "invalid", "timeout")


def _arm_mech_bad(r: dict) -> str:
    """L（机检规则）信号：该臂**机检层**是否未通过；返回具名理由（无 ⟹ 空串）。

    证据面 = 已落库 `machine_check`（`_ENTRY_KEYS` 单源）：`dump_ok` 为假、或
    `verification` / `evidence_anchor` 的 status 命中 `_MECH_BAD`；或 `suspect` 命中引用完整性词表。
    只认**显式失败**值（未知 status 不判失败 —— 防假阳）。
    """
    mc = r.get("machine_check")
    if isinstance(mc, dict):
        if mc.get("dump_ok") is False:
            return "dump_ok=false 落盘校验未过"
        for key in ("verification", "evidence_anchor"):
            v = str(mc.get(key) or "").strip().lower()
            if v in _MECH_BAD:
                return "%s=%s" % (key, v)
    sus = sorted(set(r.get("suspect") or []) & set(_QUAL_SUSPECTS))
    if sus:
        return "引用完整性机检命中 " + ",".join(sus)
    return ""


def assess_findings(agg: dict) -> dict:
    """S2：把一次聚合判定为 plan-error / infra-defect / unknown，并产出优化项与详情文本。

    纯确定性（零 LLM / 零依赖）。只读 `references`/`clusters`/`consensus`/`trace`。
    """
    refs = list((agg or {}).get("references") or [])
    cons = (agg or {}).get("consensus") or {}
    clusters = (agg or {}).get("clusters") or []
    attr = ((agg or {}).get("trace") or {}).get("attribution") or {}
    items: list[dict] = []

    # ① L（机检规则）：逐臂**机检层**未通过（引用完整性 / verification / evidence_anchor / 落盘）
    _bad = [x for x in (_arm_mech_bad(r) for r in refs) if x]
    if _bad:
        items.append({"carrier": "L", "action": "补/修机检规则：臂级机检层未通过（防复发）",
                      "evidence": "%d 臂：%s" % (len(_bad), "；".join(sorted(set(_bad))[:3]))})
    # ② M（机制修复）：批级**机制**信号（预算截停 / 收敛 / 污染隔离）
    n_budget = sum(1 for r in refs if str(r.get("budget_status") or "ok") in _BUDGET_BAD)
    if n_budget:
        items.append({"carrier": "M", "action": "修复预算/轮次截停机制（防输出截断）",
                      "evidence": "%d 臂预算耗尽" % n_budget})
    # 题面异构（2026-10-21，`ECC-0D9E26B22529`）：各臂回答**不同窄任务** ⟹ 跨臂一致度
    #   不可比，弃权不是收敛机制缺陷。原实现无条件把 abstain 归因「批内一致度不足（基础设施
    #   缺陷）」⟹ 异构批被误登记为 infra-defect 优化项。
    _het = bool(cons.get("task_heterogeneous"))
    if cons.get("abstain") and not _het:
        items.append({"carrier": "M", "action": "修收敛机制：批内一致度不足（A8/RCA：基础设施缺陷）",
                      "evidence": "top_weight=%s < min_agreement=%s"
                                  % (cons.get("top_weight"), cons.get("min_agreement"))})
    _tilt = float(cons.get("pollution_tilt", 0.0) or 0.0)
    if _tilt > 0.0:
        items.append({"carrier": "M", "action": "修复污染探测/隔离机制（批级污染率>0）",
                      "evidence": "pollution_tilt=%.3f" % _tilt})
    # ③ P（计划文本）：臂间**判定分歧**（contradiction 簇）优先；否则簇级实质分歧。
    #    2026-10-10（ECC-81F6D83D153B）：`contradictions` 语义（P2/去 G3 标签后）= 与逐 F 多数
    #    **相左的判定** = 计划文本分歧，**不是**污染 ⟹ 归 P（原误归 M「污染探测/隔离机制」）。
    _cs = [str(x) for x in (cons.get("contradictions") or [])]
    if _cs:
        items.append({"carrier": "P", "action": "澄清计划文本：臂间**判定分歧**（contradiction 簇）",
                      "evidence": "contradictions=%s" % ",".join(_cs)})
    elif int(cons.get("n_clusters", 0) or 0) >= 2 and not cons.get("abstain"):
        items.append({"carrier": "P", "action": "澄清计划文本的模糊点（臂间实质分歧）",
                      "evidence": "%d 簇" % int(cons.get("n_clusters") or 0)})

    # ④ 分类 = 主导载体类；**平局不偏置**（1:1 无主导 ⟹ unknown + `class-tie:` 留痕）；无信号 ⟹ unknown。
    #    原实现 `infra >= plan ⟹ infra-defect` 在 1:1 时**隐式偏 infra-defect**（已去掉）。
    cls, _tie = "unknown", ""
    if items:
        cc = {"plan-error": 0, "infra-defect": 0}
        for it in items:
            cc[_CARRIER_CLASS[it["carrier"]]] += 1
        if cc["infra-defect"] == cc["plan-error"]:
            _tie = "plan-error:%d/infra-defect:%d" % (cc["plan-error"], cc["infra-defect"])
        else:
            cls = "infra-defect" if cc["infra-defect"] > cc["plan-error"] else "plan-error"

    # ④ 详情文本（人可读版：分节 + 结论簇 + 成员臂 + 三组分布 + 优化项）
    _anchor = str(attr.get("anchor") or attr.get("batch_id") or "")
    if _het:
        _scale_verdict = ("⟹ 题面异构（%d 个不同窄任务），不做一致度裁决"
                          % int(cons.get("task_count") or 0))
    elif cons.get("abstain"):
        _scale_verdict = "⟹ 一致度不足，弃权"
    else:
        _scale_verdict = "⟹ 过阈值"
    lines = ["MoA 聚合批裁决详情",
             "· 归属：模式=%s，锚=%s" % (attr.get("mode", ""), _anchor),
             "· 规模：引用 %d 臂；聚成 %d 个结论簇；最大簇权重 %.2f（弃权阈值 %.2f）%s"
             % (cons.get("n_refs", 0), cons.get("n_clusters", 0),
                float(cons.get("top_weight", 0.0) or 0.0),
                float(cons.get("min_agreement", 0.0) or 0.0),
                _scale_verdict),
             "· 结论簇（按规模降序）："]
    for c in sorted(clusters, key=lambda x: -int(x.get("size", 0) or 0)):
        grp = " ".join("%s×%d" % (g, k) for g, k in (c.get("arm_groups") or {}).items())
        lines.append("   - 簇 %s：%d 臂 · 权重 %.2f%s；组分布 [%s]；成员 %s；代表(%s)=%s"
                     % (c.get("id"), c.get("size"), float(c.get("weight", 0.0) or 0.0),
                        " · 矛盾" if c.get("contradiction") else "", grp,
                        ",".join(str(m) for m in (c.get("members") or [])),
                        c.get("representative_id"),
                        " ".join(str(c.get("representative_text", "")).split())[:160]))
    if items:
        lines.append("· 优化项：")
        for it in items:
            lines.append("   - [%s·%s·%s] %s ｜ 证据：%s"
                         % (it["carrier"], _CARRIER_LABEL.get(it["carrier"], ""),
                            _CARRIER_CLASS[it["carrier"]], it["action"], it["evidence"]))
    if _tie:
        lines.append("· 分类平局（不偏置）：%s ⟹ unknown（无主导载体类）" % _tie)
    # ③ 论证入台账：辩证论证摘要并进详情文本（→ source_note），供跨轮比对。
    _dl = dialectic(agg)
    _dt = _dl.get("thesis")
    if _dt:
        _da, _dr = _dl.get("antithesis"), _dl["resolution"]
        _g3s = ("%d 臂（%d 落在非主簇）" % (_dl["g3"]["n"], _dl["g3"]["n_out"])
                if _dl["g3"]["n"] else "无污染组臂")
        if _het:
            _合 = "弃权（题面异构，跨臂一致度不可比）"
        elif _dr["abstain"]:
            # 判据量可能是 agreement（逐 F 多数）或 top_weight（主簇权重）；渲染须报**实际
            # 越界的那一个**，否则出现「0.76 < 0.67」式自相矛盾。
            _合 = ("弃权（主簇权重 %.2f < %.2f）" % (_dr["weight"], _dr["threshold"])
                   if _dr["agreement"] >= _dr["threshold"]
                   else "弃权（一致度 %.2f < %.2f）" % (_dr["agreement"], _dr["threshold"]))
        else:
            _合 = "收敛（一致度 %.2f ≥ %.2f）" % (_dr["agreement"], _dr["threshold"])
        lines.append("· 辩证：正题=主簇 %s（%d 臂）；反题=%s；污染=%s；合题=%s"
                     % (_dt.get("id"), int(_dt.get("size", 0) or 0),
                        ("次簇 %s（%d 臂）" % (_da.get("id"), int(_da.get("size", 0) or 0)))
                        if _da else "无（全体同簇）", _g3s, _合))
    detail = "\n".join(lines)[:2000]   # 有界：落 source_note → state，防撞 STATE_SIZE_WALL 总墙
    # S7 修：测量量**结构化落 facet**（`refs:`/`clusters:`/`weight:`）⟹ 趋势读侧不再靠
    #   对人类可读 source_note 的正则（措辞一变即静默退化 0）。
    n_refs = int(cons.get("n_refs", 0) or 0)
    n_cl = int(cons.get("n_clusters", 0) or 0)
    w = float(cons.get("top_weight", 0.0) or 0.0)
    _facets = (["classification:" + cls] + ["carrier:" + it["carrier"] for it in items]
               + ["refs:%d" % n_refs, "clusters:%d" % n_cl, "weight:%.2f" % w])
    if _tie:
        _facets.append("class-tie:" + _tie)
    return {"classification": cls, "optimization_items": items, "detail_text": detail,
            "facets": _facets}


def _plan_anchor(plan: str) -> str:
    """计划锚**归一**（2026-10-26）：绝对 worktree / skills 绝对 / 相对路径 ⟹ `docs/plans/<basename>`。

    实测同一计划（`2026-10-04-audit-bureau-plan.md`）在台账并存三种写法；旧实现对**原始串**
    取 sha256 ⟹ 同计划落 3 个 root_key ⟹ `register` 的 root_key 幂等失效（RC0 里同计划多条）。
    非 `docs/plans/` 形态退回 basename —— 至少跨「绝对/相对」可比。
    """
    s = str(plan or "").replace("\\", "/").strip()
    if not s:
        return ""
    m = re.search(r"(?:^|/)docs/plans/([^/]+)$", s)
    return "docs/plans/" + m.group(1) if m else s.rsplit("/", 1)[-1]


def emit_aggregate_finding(state_file: str, agg: dict, *, plan: str = "",
                           batch: str = "", cross_batch_allowed: bool = False) -> dict:
    """把一次 MoA 聚合结果落成一条 ECC finding（供**跨轮收敛比对**消费）。

    - **锚 = (plan, batch)**：批身份优先；两者皆空 ⟹ **fail-loud**（不落无锚 finding）。
    - **幂等**：`root_key = "moa-agg:<batch>"`（**批指纹为键**；plan-only 调用退回 `<plan>`）⟹ 同批重跑按根因指纹**合并**（不新增镜像），**计划改名不重复记账**（`ECC-F06E509BF5F3`）。
      2026-10-26：plan-only 的 plan 先经 `_plan_anchor` 归一（绝对 worktree / skills 绝对 / 相对 ⟹
      `docs/plans/<basename>`）—— 否则同一计划的三种写法各生成一个 root_key，幂等失效。
    - **source = `review`**（MoA 聚合属审查面）；长文本出处走 `source_note`。
    - **S2**：落 `facets`（`classification:*` + `carrier:*`）与 `source_note`（详情文本，含簇/三组分布）。
    - **B（2026-10-06）**：落 `release_state="provisional"` —— **硬门**：未 `release_approved`
      者**不得**进「可下发实装」集（人评 `finding release-approve` = 唯一放行通路；
      消费方入口 = `gk_finding.release_set`）。
    """
    _p = str(plan or "").strip()
    _b = str(batch or "").strip()
    _pk = _plan_anchor(_p)   # 计划锚归一：跨 worktree / 绝对 / 相对同一键（见 `_plan_anchor`）
    if not _p and not _b:
        return {"ok": False, "error": "no_anchor",
                "hint": "plan/batch 至少给一个（禁无锚 finding）"}
    # G2（2026-10-10，`ECC-0BA041A4284E`）：批身份**统一到聚合指纹**（`sha256[:12]`，12 位十六进制）。
    #   流水线批号（`pr-<epoch>-<hex>`）**禁**作批锚 —— 与 §18.2「按 `batch_id` 读组」、
    #   `aggregate --batch`（`ECC-449948814679`）及 `gk_moa_kappa` 的 `batch` 键同空间；
    #   异空间锚会使跨批比对分到两套不可对齐的组。
    if _b and not re.fullmatch(r"[0-9a-f]{12}", _b):
        return {"ok": False, "error": "batch_not_fingerprint",
                "hint": ("批锚须为聚合指纹 batch_id（sha256(plan+窄任务+纪元桶)[:12]，12 位十六进制）；"
                         "`pr-<epoch>-<hex>` 是流水线批号，须改用 subagent_history[].batch_id")}
    tr = (agg or {}).get("trace", {}) or {}
    _n = int(tr.get("count", 0) or 0)
    _susp = int(tr.get("suspect_count", 0) or 0)
    _cons = (agg or {}).get("consensus", {}) or {}
    _nc = int(_cons.get("n_clusters", 0) or 0)
    assessment = assess_findings(agg)   # S2：分类 + 优化项 + 详情文本
    anchors = ([("batch:" + _b)] if _b else []) + ([("plan:" + _pk)] if _pk else [])
    # 身份 facet（2026-10-10，`ECC-0BA041A4284E`）：批/计划**结构化可读**（对齐 §18.2
    #   「`batch_id` 作字段」）⟹ 跨批比对按 `batch_id` 读组（`_finding_batch`/`_finding_plan`
    #   单源消费）。`cross-batch:0|1` **恒落**（记跨批放开态，§18.1 溯源，非静默）——
    #   恒落而非仅 True 时落 ⟹ 同 root_key 重跑可**后写覆盖**，不留 stale `cross-batch:1`。
    _facets = list(assessment["facets"])
    if _b:
        _facets.append("batch:" + _b)
    if _pk:
        _facets.append("plan:" + _pk)
    _facets.append("cross-batch:" + ("1" if cross_batch_allowed else "0"))
    title = "MoA聚合批裁决: batch=%s n=%d clusters=%d suspect=%d %s" % (
        _b or "-", _n, _nc, _susp, assessment["classification"])
    # root_key 约束（gk_finding._ROOT_KEY_MAX）：**无空白且 ≤64 字** ⟹ 长 plan 路径须哈希压缩。
    # 幂等键**以批指纹为主**（`ECC-F06E509BF5F3`，2026-10-16）：批 id 是**内容寻址**的全局唯一键，
    #   而 plan 是**可变呈现属性** ⟹ 原式把 plan 并入键 ⟹ **计划改名被误判成新批**（实测：产出
    #   两条同标题、不同 id）。plan-only 调用（无 batch）⟹ 退回 plan 作键，保持唯一性。
    import hashlib as _hl
    _key_src = _b if _b else ("plan-only:" + (_pk or "-"))
    root_key = "moa-agg:" + _hl.sha256(_key_src.encode("utf-8")).hexdigest()[:16]
    import gk_finding  # 惰性 import：避免顶层循环依赖
    rec = gk_finding.register(
        state_file, title, "review", root_key=root_key, anchors=anchors,
        facets=_facets, source_note=assessment["detail_text"],
        # ECC-95277E21EF31（2026-10-11）：批裁决 finding 属 `source=review`
        #   （∈ `gk_finding._COVER_REQUIRED_SOURCES`）⟹ 须登记**应拦审查层**，否则每条
        #   finding 恒 `cover_layers=[]` + `gap=true`（实测默认 state 65/67 条皆空）。
        #   MoA 聚合 = `plan-refinement`（REVIEW_LAYERS **L2** code-to-spec）的产物层。
        #   ⚠ `gk_finding._split_layers` 只认 str / list（**tuple 会被 `str()` 成垃圾**）。
        cover_layers="L2",
        release_state="provisional",
        provenance="untrusted")   # T5-a：MoA 聚合 finding 摄取的是**逐臂外部内容** ⟹ 不可信来源
    return {"ok": True, "finding": rec}


# ── T1 链骨架（正本 `docs/plans/2026-10-14-moa-chain-automation-plan.md` §3-T1）──────────────
# 目的：把「聚合 → 落 ecc-finding → P/L/M 分组 → 熔断判决 → 单一封套」从**手敲散点**收敛为
#   **一次调用**（挂既有 `moa-aggregate --chain`，**零新增 _CMD_REG**）。T2-T7 为后续任务：
#   本骨架已落 `批锚自解析 / 聚合 / 落 finding / P/L/M 分组 / 熔断(只读评估器)`；HTML(T4)/
#   散文二次合并(T5)/预检(T6)/对偶回收(T7) 接受参数并标 `pending`，**禁**在骨架里假装已实装。
# ⚠ **链到此为止：本链只产 finding + P/L/M 分组（治理判决），不改任何被测机制代码。**
#   `carrier=L`（机检规则）/`carrier=P`（计划文本）可在链内或主 agent 直接落刀；
#   **`carrier=M`（机制修复）通常是跨文件、需先红后绿的改动 ⟹ 此处应「建族 + 派 coder」**：
#     ① 新建/选 `references/agent-families/F-*.json`（`match.any` 命中 → 自动判族）；
#     ② `finding register <title> review` 拿 fid；
#     ③ `apply-worktree <fid> --code-fix --family <F> --state <state>` 建 worktree 并编译窄任务；
#     ④ 执行回包 `next`（`monitor --subagent --role coder ...`）派 coder，完成后主 agent 审 diff + 跑测试 + 合并。
#   也可以不建族：**主 agent 自己改**（小改动 / 单文件）或**人类研究员亲自改**（涉裁决面）。
#   判据：改多个文件、需要 test_first 红先臂、或想保留「族」的可复用窄任务模板 ⟹ 建族派 coder。
_CARRIERS = ("L", "P", "M")   # P/L/M 载体分组（T2 出口口径）


def latest_batch_fingerprint(state_file: str, task: str = "") -> str:
    """从 `subagent_history` 解析**最近一轮**的批锚指纹（`batch_id`）—— **禁调用方手抄**。

    同批逐臂入 history ⟹ 顺序遍历取**最后**出现者（append-only）；`task` 非空时只看 task 含该
    子串的臂（计划内轮次过滤）。找不到 ⟹ `""`（调用方据此 fail-loud，禁静默取错批）。
    """
    try:
        s = json.loads(Path(state_file).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — 只读解析失败 ⟹ 无批锚（由调用方 fail-loud）
        return ""
    hist = (s.get("gate_data") or {}).get("subagent_history") or []
    b = ""
    for rec in hist:
        if not isinstance(rec, dict):
            continue
        bid = str(rec.get("batch_id") or "").strip()
        if not bid or not re.fullmatch(r"[0-9a-f]{12}", bid):
            continue   # 同 emit_aggregate_finding：只认聚合指纹，拒流水批号
        if task and not plan_match(str(rec.get("task") or ""), task)[0]:
            continue
        b = bid
    return b


def plm_groups(agg: dict) -> dict:
    """`carrier:L/P/M` 分面**分组导出**（T2 出口；骨架先复用 `assess_findings`，禁第二实现）。"""
    items = (assess_findings(agg) or {}).get("optimization_items") or []
    out = {c: [] for c in _CARRIERS}
    for it in items:
        c = str(it.get("carrier") or "").strip().upper()
        out.setdefault(c, []).append({"action": it.get("action"), "evidence": it.get("evidence")})
    return out


# ── T15（2026-10-29，user 裁定「链头入参」）：`--from-plan` —— 从**计划文本**起跑的一键链路 ──
# 痛点：`--chain` 只从 **subagent 产物**（`gate_data.subagent_history`）起跑 ⟹ 「一键跑完质询」
#   仍要手敲三段（plan-lint → plan-refinement --run → moa-aggregate --chain）。
# 处置：链前加**入参**，链路 = **plan-lint(PW-SN) → 派臂 → 本 `chain()` 聚合 → 链尾 HTML**。
#   - 机检门 fail-closed：high/medium>0 ⟹ **零派臂**（不烧 6 臂去质询一份机检不过的计划）。
#   - 派臂**委托**既有统一入口 `plan-refinement <plan> --run --no-aggregate`
#     （preflight / 入队 / 裁决 / 下发全在那一处；**禁第二实现**），本处只解析其回执。
#   - `runner` 可注入（测试 stub）；缺省 = `_default_arm_runner`。
def _resolve_plan_path(plan: str) -> str:
    """计划路径定位（绝对/相对 cwd/技能根/`docs/plans/`）；定位失败 ⟹ `""`（调用方 fail-loud）。"""
    raw = str(plan or "").strip()
    if not raw:
        return ""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cands = [raw]
    if not os.path.isabs(raw):
        cands += [os.path.join(root, raw), os.path.join(root, "docs", "plans", raw),
                  os.path.join(root, "docs", "plans", raw + ".md")]
    for c in cands:
        if os.path.isfile(c):
            return os.path.abspath(c)
    return ""


def _chain_note(state_file: str, step: str, deadline: float, plan: str = "",
                info: str = "") -> None:
    """**阶段性状态回传**（2026-10-29，user 令「所有命令必须有超时限制和阶段性状态回传」）。

    两个通道，均复用既有 subagent 管线口径（`SUBAGENT_MAX_RUNTIME` / `${STATE_FILE}.subagent-run`）：
      ① stderr 单行进度（`main` 的链模式已把 stdout 重定向到 stderr ⟹ 不污染单封套 JSON）；
      ② `${state_file}.chain-run`（`PID|STEP|START|DEADLINE|PLAN`）供外部 `tail`/看门狗读取。
    """
    print("[moa-chain] step=%s%s" % (step, (" " + info) if info else ""),
          file=sys.stderr, flush=True)
    if not state_file:
        return
    try:
        with open(state_file + ".chain-run", "w", encoding="utf-8") as fh:
            fh.write("%d|%s|%d|%d|%s\n" % (os.getpid(), step, int(time.time()),
                                           int(deadline), plan or ""))
    except OSError:
        pass


def _chain_clear(state_file: str) -> None:
    if not state_file:
        return
    try:
        os.remove(state_file + ".chain-run")
    except OSError:
        pass


def _pending_for_plan(state_file: str, plan: str) -> list:
    """本计划**已入队但未下发**的 pending 记录（供链头**续跑**，禁重复入队）。"""
    if not state_file or not plan:
        return []
    try:
        s = json.loads(Path(state_file).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — 读失败 ⟹ 视为无 pending（走正常入队路径）
        return []
    tp = (s.get("gate_data") or {}).get("task_pipeline") or []
    out = []
    for r in tp:
        if not isinstance(r, dict) or str(r.get("status") or "") != "pending":
            continue
        tgt = str(r.get("target") or r.get("plan") or "")
        if not tgt:
            continue
        # 2026-10-30（单一真源）：原实现手写 `tgt == plan or basename(tgt) == basename(plan)`，
        #   与另两处裸子串实现不一致（这也是当日「链头 resume 成功、聚合 refs=0」的同源分裂）。
        #   统一走 `plan_match()`；判据由 basename 相等放宽为 identity 相等（去 `.md`），行为只增不减。
        if plan_match(tgt, plan)[0]:
            out.append(r)
    return out


def _default_arm_runner(plan: str, *, task: str = "", role: str = "plan-refinement",
                        arms_per_group: int = 0, state_file: str = "",
                        resume: bool = False) -> dict:
    """缺省派臂 = **委托**唯一入口 `plan-refinement <plan> --run --no-aggregate`。

    返回 `{ok, rc, dispatched?, error?, stderr_tail?}`；**不**在此实现 preflight/入队/下发。

    **超时（2026-10-29，user 令「所有命令必须有超时限制」）**：外层 `communicate(timeout=…)`，
    超时即 `killpg` 整组（bash 子进程 + 其 python 孙进程），返回具名 `dispatch_timeout`
    —— 原实现是无界阻塞（实测 2.5min 静默退出后仍无回执），禁再回到无界。
    优先复用既有 subagent 口径 `SUBAGENT_MAX_RUNTIME`（+600s 余量），可用 `GK_CHAIN_DISPATCH_TIMEOUT` 覆盖。
    `GK_CHAIN_CLI` 仅供测试注入替身脚本（缺省 = 本仓 `gatekeeper-cli.sh`）。
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cli = os.environ.get("GK_CHAIN_CLI") or os.path.join(root, "gatekeeper-cli.sh")
    if resume:
        # 续跑：本计划已有 pending（上次入队后派发失败/超时）⟹ 只下发，**不再入队**（防重复 6 臂）。
        cmd = ["bash", cli, "plan-refinement", plan,
               "--adjudicate", "last-batch", "--decision", "approve"]
    else:
        cmd = ["bash", cli, "plan-refinement", plan,
               "--run", "--task-from-plan", "--no-aggregate"]
        if arms_per_group:
            cmd += ["--arms-per-group", str(int(arms_per_group))]
    env = dict(os.environ)
    if state_file:
        env["STATE_FILE"] = state_file
    try:
        _base = int(os.environ.get("SUBAGENT_MAX_RUNTIME", "3600") or 3600)
    except ValueError:
        _base = 3600
    try:
        _to = int(os.environ.get("GK_CHAIN_DISPATCH_TIMEOUT", "") or (_base + 600))
    except ValueError:
        _to = _base + 600
    t0 = time.time()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=env, start_new_session=True)
    except OSError as e:   # 解释器/脚本缺失 ⟹ 具名失败（禁静默当已派发）
        return {"ok": False, "error": type(e).__name__}
    try:
        out_s, err_s = proc.communicate(timeout=_to)
    except subprocess.TimeoutExpired:
        # 整组杀：只杀直接子进程会留下 cmd_monitor/subagent_runner 孙进程继续烧 API。
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:  # noqa: BLE001
            proc.kill()
        try:
            out_s, err_s = proc.communicate(timeout=30)
        except Exception:  # noqa: BLE001
            out_s, err_s = "", ""
        return {"ok": False, "error": "dispatch_timeout", "timeout_s": _to,
                "elapsed_s": round(time.time() - t0, 1), "stderr_tail": (err_s or "")[-400:]}
    rc = proc.returncode
    out: dict = {}
    lines = (out_s or "").strip().splitlines()
    if lines:
        try:
            out = json.loads(lines[-1])
        except Exception:  # noqa: BLE001 — 非 JSON 回执 ⟹ 无结构化结果（rc 兜底判定）
            out = {}
    ok = rc == 0 and bool(out.get("ok"))
    _adj = out.get("adjudicate")
    return {"ok": ok, "rc": rc, "elapsed_s": round(time.time() - t0, 1),
            "dispatched": (_adj.get("dispatched") if isinstance(_adj, dict) else None),
            "error": None if ok else (out.get("error") or "dispatch_failed"),
            "stderr_tail": "" if ok else (err_s or "")[-400:]}



def chain_head(plan: str, *, state_file: str = "", task: str = "",
               role: str = "plan-refinement", arms_per_group: int = 0,
               runner=None, deadline: float = 0.0) -> dict:
    """链头：**机检门（PW-SN）→ 派臂**；返回 `{ok, plan, lint?, dispatch?}`。

    - 机检**单一源** = `gk_plan_lint.lint`（与 `plan-lint` 命令同源，禁第二套规则）。
    - `high/medium > 0` ⟹ `error=plan_lint_blocking` 且**零派臂**（fail-closed）。
    - 派臂失败 ⟹ `error=arms_failed`（链上游据此**不产出 HTML**）。
    - `deadline`：绝对时间戳（0 = 不设）；机检后与派臂后各检一次，超时 ⟹ `chain_deadline_exceeded`。
    """
    p = _resolve_plan_path(plan)
    if not p:
        return {"ok": False, "error": "plan_missing", "plan": str(plan or "")}
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _chain_note(state_file, "head:lint:start", deadline, plan=p)
    try:
        import gk_plan_lint as _PL
        findings = _PL.lint(p, repo, task=task or "")
    except Exception as e:  # noqa: BLE001 — 机检不可用 ⟹ fail-closed（禁静默放行派臂）
        return {"ok": False, "error": "plan_lint_unavailable", "plan": p,
                "detail": type(e).__name__}
    lint = {"high": sum(1 for _, lv, _ in findings if lv == "high"),
            "medium": sum(1 for _, lv, _ in findings if lv == "medium"),
            "info": sum(1 for _, lv, _ in findings if lv == "info"),
            "findings": [{"check": c, "level": lv, "detail": d}
                         for (c, lv, d) in findings if lv in ("high", "medium")][:50]}
    _chain_note(state_file, "head:lint:done", deadline, plan=p,
                info="high=%d medium=%d" % (lint["high"], lint["medium"]))
    if lint["high"] or lint["medium"]:
        return {"ok": False, "error": "plan_lint_blocking", "plan": p, "lint": lint}
    if deadline and time.time() > deadline:
        return {"ok": False, "error": "chain_deadline_exceeded", "plan": p, "lint": lint}
    run = runner or _default_arm_runner
    # 续跑判定（2026-10-29）：上次入队后派发失败会留下 pending ⟹ 只下发，**不再入队**
    #   （否则每重试一次就多 6 臂）。判定只读 state，单一源 = `_pending_for_plan`。
    _pend = _pending_for_plan(state_file, p)
    _resume = bool(_pend)
    _chain_note(state_file, "head:dispatch:start", deadline, plan=p,
                info="resume=%s pending=%d" % (_resume, len(_pend)))
    try:
        d = run(p, task=task or "", role=role, arms_per_group=arms_per_group,
                state_file=state_file, resume=_resume) or {}
    except Exception as e:  # noqa: BLE001 — runner 异常 ⟹ 具名失败（禁当成已派臂）
        return {"ok": False, "error": "arms_failed", "plan": p, "lint": lint,
                "dispatch": {"error": type(e).__name__}}
    _chain_note(state_file, "head:dispatch:done", deadline, plan=p,
                info="ok=%s elapsed=%ss" % (bool(d.get("ok")), d.get("elapsed_s")))
    if not d.get("ok"):
        return {"ok": False, "error": "arms_failed", "plan": p, "lint": lint, "dispatch": d}
    return {"ok": True, "plan": p, "lint": lint, "resume": _resume,
            "dispatch": {k: d.get(k) for k in ("ok", "rc", "dispatched", "elapsed_s")}}


def chain(state_file: str, *, plan: str = "", batch: str = "", role: str = "plan-refinement",
          task: str = "", cross_batch: bool = False, html_path: str = "",
          prose_file: str = "", no_html: bool = False, from_plan: str = "",
          arms_per_group: int = 0, runner=None) -> dict:
    """**T1 链骨架**：`批锚自解析 → 聚合 → 落 finding → P/L/M 分组 → 熔断判决(只读评估器) → 单一封套`。

    `--from-plan`（T15，2026-10-29）：链**头**从计划文本起跑 —— `plan-lint` 机检门 → 派臂
    （委托 `plan-refinement --run`）→ 再走本节聚合/HTML。机检阻断或派臂失败 ⟹ **不产出 HTML**。

    - **批锚自解析**：`--batch` 缺省 ⟹ 从 `subagent_history` 取最近一轮指纹（禁手抄）。
    - **落 finding**：有锚 ⟹ **必落**（B 保护锁语义，无抑制口）。
    - **熔断判决（T3 约束，owner 2026-10-14）**：**只读** `gk_convergence_estimator.evaluate`；
      **不默认熔断** —— 仅当评估器 `ok=True 且 verdict="block"`（r̂≥1 self-lock）才置 `breaker=True`；
      缺 T*/≥2 epoch 等 ⟹ 如实回报 `UNKNOWN`，**不**熔断。
    - T4（HTML，缺省导出 / `--no-html` opt-out）/ T5（散文二次合并：`--prose <file>` / `-`=stdin
      ⟹ 并入台账，root_key 幂等）**已实装**；T6/T7/T9/T10 待做（**不假装已实装**）。
    """
    steps: dict = {}
    # 2026-10-29（user 令「所有命令必须有超时限制和阶段性状态回传」）：链级 deadline + 进度回报。
    #   deadline 缺省沿用既有 subagent 口径（`SUBAGENT_MAX_RUNTIME` + 900s 余量），
    #   可用 `GK_CHAIN_DEADLINE`（秒）覆盖；进度写 stderr + `${state}.chain-run`。
    _t0 = time.time()
    try:
        _base = int(os.environ.get("SUBAGENT_MAX_RUNTIME", "3600") or 3600)
    except ValueError:
        _base = 3600
    try:
        _deadline = _t0 + int(os.environ.get("GK_CHAIN_DEADLINE", "") or (_base + 900))
    except ValueError:
        _deadline = _t0 + _base + 900
    _chain_note(state_file, "start", _deadline, plan=(plan or from_plan),
                info="pid=%d" % os.getpid())
    # T15（2026-10-29）：`--from-plan` 链头 —— 机检门 + 派臂；失败 ⟹ **提前返回**（零 HTML）。
    # 2026-10-30 回归修：`head` 原仅在 `from_plan` 非空时绑定，但下面 `plan = plan or from_plan or
    #   head.get("plan")` 无条件执行 ⟹ 无 `--plan/--from-plan` 时 `UnboundLocalError`（`--chain`
    #   缺省路径直接崩）。空字典兜底保持「无入参 ⟹ 走批锚自解析/no_anchor」语义不变。
    head: dict = {}
    if (from_plan or "").strip():
        head = chain_head(from_plan, state_file=state_file, task=task, role=role,
                          arms_per_group=arms_per_group, runner=runner, deadline=_deadline)
        steps["head"] = head
        if not head.get("ok"):
            _chain_note(state_file, "fail", _deadline, plan=from_plan,
                        info="error=%s" % head.get("error"))
            _chain_clear(state_file)
            return {"mode": "moa_chain", "ok": False, "error": head.get("error"),
                    "head": head, "plan": from_plan, "batch": (batch or "").strip(),
                    "steps": steps}
        # 2026-10-30（单一真源）：原序 `plan or head.get("plan") or from_plan` 优先取 head 的
    #   `_resolve_plan_path` 结果 = **绝对路径**，覆盖了调用方原始相对入参 ⟹ 下游
    #   `latest_batch_fingerprint` / `collect_entries` 拿绝对去匹配 history 里的相对 / worktree
    #   形态 ⟹ 双处 0 命中 ⟹ `batch_resolved=""` + `refs=0`（当日误判「基础设施缺陷」的根因）。
    #   现改为**优先保留原始入参**；仅在无入参时才用 head 解析值。路径存在性校验仍由 head 完成
    #   （`_resolve_plan_path` 失败 ⟹ 提前 return `plan_missing`），不削弱 fail-loud。
    plan = plan or from_plan or head.get("plan")
    if _deadline and time.time() > _deadline:
        _chain_clear(state_file)
        return {"mode": "moa_chain", "ok": False, "error": "chain_deadline_exceeded",
                "plan": plan, "steps": steps}
    # 批锚过滤子串：`--from-plan` 且未显式给 `--task` 时按**计划路径**过滤（派发臂 task 内含计划路径）。
    _bfilter = (plan or "") if ((from_plan or "").strip() and not (task or "").strip()) else (task or "")
    b = (batch or "").strip() or latest_batch_fingerprint(state_file, _bfilter)
    steps["batch_resolved"] = b
    if not b and not (plan or "").strip():
        return {"mode": "moa_chain", "ok": False, "error": "no_anchor",
                "hint": "plan/batch 至少给一个，或 history 内需有可解析的批锚指纹", "steps": steps}
    agg = aggregate(state_file, None, role, task, False, 0, plan, b, cross_batch, False)
    if agg.get("error"):
        return {"mode": "moa_chain", "ok": False, "error": agg["error"],
                "batch": b, "plan": plan, "steps": steps}
    tr = agg.get("trace", {}) or {}
    cons = agg.get("consensus", {}) or {}
    steps["aggregate"] = {"refs": tr.get("count"), "clusters": cons.get("n_clusters"),
                          "agreement": cons.get("agreement"), "abstain": cons.get("abstain")}
    _chain_note(state_file, "aggregate:done", _deadline, plan=plan,
                info="refs=%s clusters=%s" % (tr.get("count"), cons.get("n_clusters")))
    steps["finding"] = emit_aggregate_finding(state_file, agg, plan=plan, batch=b,
                                              cross_batch_allowed=cross_batch)   # 保护锁：有锚必落
    # T13（2026-10-16，C 计划 §3-T13）：链尾**中文嵌入向量落盘** —— 令 `principal` 的中文近重复
    #   召回对新 finding 可用（补 Jaccard 中文盲区）。**契约存在时**才维护（opt-in by presence：
    #   缺 `<state>.finding-embeddings.jsonl` ⟹ 不强制起 Node，标 `disabled`，**不假绿**）；
    #   不可用 ⟹ 具名 `error`。**单一源** = `gk_finding_embed.run`（**禁第二实现**，确定性全量
    #   重建 = 覆盖新 finding 的超集，幂等）。置于 `principal` 之前 ⟹ 本轮 RC 即可用新向量。
    _emb_path = state_file + ".finding-embeddings.jsonl"
    if not os.path.exists(_emb_path):
        steps["embeddings"] = {"status": "disabled", "reason": "NO_CONTRACT", "path": _emb_path}
    else:
        try:
            import gk_finding_embed as _E
            _er = _E.run(state_file)
            steps["embeddings"] = {"status": "written" if _er.get("ok") else "error",
                                   "vectors": _er.get("vectors"), "targets": _er.get("targets"),
                                   "path": _er.get("path") or _emb_path,
                                   "error": _er.get("error") if not _er.get("ok") else None,
                                   "source": "gk_finding_embed.run"}
        except Exception as e:  # noqa: BLE001 — 嵌入面不可用 ⟹ 具名 error（禁静默假绿）
            steps["embeddings"] = {"status": "error", "error": type(e).__name__,
                                   "path": _emb_path, "source": "gk_finding_embed.run"}
    # T11（2026-10-16，C 计划 §3-T11）：链尾**RC 塌缩出口** —— 复用 `gk_finding.principal`
    #   （**单一源**，零新增 `_CMD_REG`）提取台账级主要矛盾：`root_key` 精确成组 + 锚集 Jaccard
    #   （平均连接凝聚）+ 嵌入粗筛。**无合格 RC**（仅单例/孤项）⟹ `principal=None`（fail-loud，
    #   不冒充）；不可用 ⟹ 具名 `UNKNOWN`（禁默认值）。≠ 臂级簇（§1-2）。
    try:
        import gk_finding as _F
        _pr = _F.principal(state_file, plan)
        steps["principal"] = {"principal": _pr.get("principal"),
                              "root_causes": len(_pr.get("root_causes") or []),
                              "orphans": len(_pr.get("orphans") or []),
                              "stats": _pr.get("stats"),
                              "ok": bool(_pr.get("ok")),
                              "source": "gk_finding.principal"}
    except Exception as e:  # noqa: BLE001 — RC 面不可用 ⟹ 具名 UNKNOWN（禁冒默认值）
        steps["principal"] = {"principal": None, "ok": False, "status": "UNKNOWN",
                              "error": type(e).__name__, "source": "gk_finding.principal"}
    steps["plm"] = plm_groups(agg)   # T2 出口
    try:
        import gk_convergence_estimator as _C
        ev = _C.evaluate(state_file)
    except Exception as e:  # noqa: BLE001 — 评估器不可用 ⟹ 无判决（**禁**当成熔断）
        ev = {"ok": False, "error": "EVALUATOR_UNAVAILABLE", "hint": type(e).__name__}
    breaker = bool(ev.get("ok")) and ev.get("verdict") == "block"   # 只认评估器算出的 block
    steps["convergence"] = {"verdict": ev.get("verdict") or ev.get("error") or "UNKNOWN",
                            "r_hat": ev.get("r_hat"), "n_star": ev.get("n_star"),
                            "breaker": breaker, "source": "gk_convergence_estimator.evaluate"}
    # C2 轮次止损（2026-10-27，owner 令「C2 接入改自动」）：链内**默认**跑早停判定
    #   `r̂ ≥ r_min` 连续 K 轮 ⟹ `NO_CONVERGENCE` + `switch_to="M"` + 落 `noconv:` finding。
    #   μ 源 = `_trend_from_state` 的 **moa-agg:** 行（测量 finding）；`noconv:` 行 mu=0，
    #   混入会污染比值 ⟹ 显式过滤。kill switch 沿用 `GK_CONV_EARLY_STOP=0`（只出判决不落账）。
    try:
        import gk_convergence_evaluator as _CE
        _mus = [int(x.get("mu") or 0) for x in _trend_from_state(state_file, plan=plan)
                if str(x.get("root_key", "")).startswith("moa-agg:")]
        _es = _CE.no_convergence_finding(state_file, plan, _mus, batch=b)
        _esf = _es.get("finding") or {}
        steps["early_stop"] = {"verdict": _es.get("verdict"),
                               "r_hat": _es.get("r_hat"), "r_min": _es.get("r_min"),
                               "k_rounds": _es.get("k_rounds"), "trailing_k": _es.get("trailing_k"),
                               "rounds": len(_mus), "switch_to": _es.get("switch_to"),
                               "suppressed": bool(_es.get("suppressed")),
                               "finding": _esf.get("id") or _esf.get("finding"),
                               "source": "gk_convergence_evaluator.no_convergence_finding"}
    except Exception as e:  # noqa: BLE001 — 评估器不可用 ⟹ 具名 UNKNOWN（**禁**当成熔断）
        steps["early_stop"] = {"verdict": "UNKNOWN", "error": type(e).__name__,
                               "source": "gk_convergence_evaluator.no_convergence_finding"}
    # T4（2026-10-15，C 计划 §3-T4）：链尾**缺省**导出 HTML（`--no-html` opt-out）；路径规则化。
    #   原实现收 `html_path` 却只标 `pending(T4)` = **收参不干活**（假状态）—— 现真写盘；
    #   写盘失败**如实报 `error`**（禁静默标 written）。
    if no_html:
        steps["html"] = {"requested": False, "status": "disabled", "path": ""}
    else:
        try:
            _hp = _chain_html_path(html_path, state_file, b or plan)
            Path(_hp).parent.mkdir(parents=True, exist_ok=True)
            # §3 G2（2026-10-26）：链尾 HTML 原**未传 trend** ⟹ 缺省导出的页面没有跨轮趋势图
            #   （只有 `--html` 走 `_emit_html` 才带）。趋势源与 `_emit_html` 同源（只读 state）。
            Path(_hp).write_text(
                render_html(agg, {"plan": plan, "batch": b},
                            trend=_trend_from_state(state_file, plan=plan)),
                encoding="utf-8")
            steps["html"] = {"requested": True, "status": "written", "path": _hp}
        except Exception as e:  # noqa: BLE001 — 写盘失败 ⟹ 如实报（fail-loud 值，不假绿）
            steps["html"] = {"requested": True, "status": "error",
                             "error": type(e).__name__, "path": html_path}
    # T5（2026-10-15，C 计划 §3-T5）：链尾接收散文（文件或 `-`=stdin）⟹ 自动 `from-prose`
    #   （单源 = `gk_prose_findings.convert`）→ 并入台账（`gk_finding.register`，root_key=`prose:<hash>`
    #   **幂等**：register 双档合并）。空/不可读**如实报**（禁静默假绿）；非空但 0 条 ⟹ 具名 `empty`
    #   （与 S4 空栏护栏同口径，下游 `finding score` 不会静默全 PASS）。
    if not prose_file:
        steps["prose"] = {"requested": False, "status": "disabled", "count": 0}
    else:
        try:
            _text = (sys.stdin.read() if prose_file == "-"
                     else Path(prose_file).read_text(encoding="utf-8"))
            import gk_prose_findings as _PF
            import gk_finding as _F
            # T12（2026-10-15，C 计划 §3-T12）：**默认启用 BM25 相关性闸** —— 外源散文逐条过
            #   `relevance_judge`（锚定硬下限 + BM25）⟹ 落 `relevance:in|out` / `bm25:` / `anchor:`
            #   facet（单源 = `_refs_of(agg)`，**禁第二实现**）；判 out ⟹ 下游 score 隔离为
            #   unverified（**不冒充相关**）。无 refs ⟹ 全部 out（无证据锚 ⟹ 未验证，禁默认放行）。
            _fs = _PF.convert(_text, plan=plan, batch=b, refs=_refs_of(agg))
            _ids = []
            for _f in _fs:
                _r = _F.register(state_file, _f["title"], _f["source"],
                                 root_key=_f["root_key"], anchors=_f["anchors"],
                                 facets=_f["facets"], source_note=_f["source_note"],
                                 provenance="untrusted")   # T5-a：散文来源不可信
                _ids.append((_r or {}).get("id") or _f["root_key"])
            steps["prose"] = {"requested": True, "file": prose_file,
                              "status": "merged" if _fs else "empty",
                              "count": len(_fs), "ids": _ids}
        except Exception as e:  # noqa: BLE001 — 不可读/转换失败 ⟹ 如实报（fail-loud，不假绿）
            steps["prose"] = {"requested": True, "file": prose_file, "status": "error",
                              "count": 0, "error": type(e).__name__}
    # T9（2026-10-15，C 计划 §3-T9 / R2）：链尾**κ 通道接通** —— 读该批 ledger 行 →
    #   `gk_moa_kappa.combined_tilt`（`tilt_total=1−Π(1−κ_tilt_i)`，**单源禁第二实现**）；
    #   **无行 / 无可估通道 ⟹ 具名拒估**（`UNKNOWN`），**不冒充**（R2/R3）。
    try:
        import gk_moa_kappa as _K
        _krow = next((s for s in _K.load_ledger() if s.get("batch") == b), None)
        if _krow is None:
            steps["kappa"] = {"status": "UNKNOWN", "reason": "NO_LEDGER_ROW",
                              "channel": "combined_tilt", "tilt_total": None,
                              "source": "gk_moa_kappa.combined_tilt"}
        else:
            _kt = _K.combined_tilt(_krow)
            steps["kappa"] = {"status": "estimated" if _kt is not None else "UNKNOWN",
                              "reason": "" if _kt is not None else "NO_CHANNEL",
                              "channel": "combined_tilt", "tilt_total": _kt,
                              "n_events": _krow.get("n_events"),
                              "source": "gk_moa_kappa.combined_tilt"}
    except Exception as e:  # noqa: BLE001 — κ 面不可用 ⟹ 具名拒估（禁冒默认值）
        steps["kappa"] = {"status": "UNKNOWN", "reason": "KAPPA_UNAVAILABLE",
                          "channel": "combined_tilt", "tilt_total": None,
                          "error": type(e).__name__,
                          "source": "gk_moa_kappa.combined_tilt"}
    # T10（2026-10-15，C 计划 §3-T10 / R4）：链尾**完整性出口** —— 按 `arm_group` 汇总臂
    #   `overall_score` → `gk_moa_integrity.arm_dispersion`（ANOVA F + 置换 p，**单源**）；
    #   缺分数 / <2 组 ⟹ 估计器自带 `UNDER-POWERED` 声明（**禁冒充** SEPARATED）。
    try:
        import gk_moa_integrity as _I
        _sg: dict = {}
        _n_missing = 0
        for _r in _refs_of(agg):
            if not isinstance(_r, dict):
                continue
            _sc = arm_score(_r)   # T14（2026-10-15）：**单源**（自报优先，缺 ⟹ seven_dim 派生）
            if _sc is None:
                _n_missing += 1   # 禁静默：缺分**计数**（可机检，不无声 continue）
                continue
            _g = str(_r.get("arm_group") or "").strip() or "UNGROUPED"
            _sg.setdefault(_g, []).append(_sc)
        _it = dict(_I.arm_dispersion(_sg), metric="arm_score",
                   n_missing=_n_missing,
                   source="gk_moa_integrity.arm_dispersion")
        if _n_missing:
            _it["missing_reason"] = "ARM_SCORE_MISSING"
        steps["integrity"] = _it
    except Exception as e:  # noqa: BLE001
        steps["integrity"] = {"check": "arm_dispersion", "verdict": "UNKNOWN",
                              "error": type(e).__name__,
                              "source": "gk_moa_integrity.arm_dispersion"}
    _chain_note(state_file, "done", _deadline, plan=plan,
                info="elapsed=%.1fs html=%s" % (time.time() - _t0,
                                                (steps.get("html") or {}).get("status")))
    _chain_clear(state_file)
    return {"mode": "moa_chain", "ok": True, "batch": b, "plan": plan,
            "breaker": breaker, "steps": steps}


def _chain_html_path(html_path: str, state_file: str, anchor: str) -> str:
    """T4 路径规则（**禁手改**）：显式 `html_path` 优先；否则 `<state 目录>/moa-chain-<锚>.html`。

    `锚` = 批指纹（12-hex）或计划名，净化到 `[A-Za-z0-9._-]`（防路径注入 / 超长）。
    """
    p = str(html_path or "").strip()
    if p:
        return p
    _dir = str(Path(state_file).resolve().parent) if state_file else "."
    _a = re.sub(r"[^A-Za-z0-9._-]", "_", str(anchor or "chain"))[:80] or "chain"
    return os.path.join(_dir, "moa-chain-%s.html" % _a)


# ── 跨轮收敛比对（Infra-1b，2026-10-05，ECC-1F540718AEE5 / RCA=A8）─────────────
# 依 RCA（Residual Convergence Axiom）：μ_n = 第 n 轮**新增压力**；r̂ = (μ_N/μ_0)^{1/N}（stock 比）；
#   N* = ⌈ln(μ_0/μ_tgt)/ln(1/r̂)⌉。**判据 = 连续 ≥min_rounds 次 r̂≥r_min ⟹ 不收敛早停**。
# 本仓实测（组派发议题 4 轮）：μ=[8,10,9,9] ⟹ r̂≈1.04 ⟹ **应在 R2 早停**（实际跑到 R4，
#   浪费 R3/R4 ≈ 7M+ tok）⟹ 本函数 = 把该预判从"文本"变"机制"。
# **机制正本 = `references/convergence-evaluator.md`**（§5 循环早停；**禁放 docs/plans**）——
#   本函数 = 其 **MoA 侧薄入口**；质询轮次循环侧的编排层见 `gk_convergence_evaluator.py`。
def cross_round_convergence(stock_seq, *, mu_tgt: int = 1) -> dict:
    """RCA **单源**（对齐 09-14 §1.2「判决量唯一=r̂」；**不新造 ρ**）。

    质询（RCA 参数轮 `d8c0cfd1bb29` arm-2）判定：原实现的 `ρ̂`（flow 轴）与正本
    「ρ 只留衰减率、flow 比 deprecated」**撞口径** ⟹ 改为**直接复用** stock 轴单源。

    判决量 `r̂ = stock_ratio(stock_seq)`（相邻轮 μ **存量**的几何均值，来自
    `gk_convergence_estimator` 单源）；**μ 不降（r̂ ≥ 1）⟹ 不收敛（self-lock）⟹ 早停**。
    - `stock_seq`：按**轮序**排的每轮**存量** μ_n（= 该轮末 `open+in_progress` 计数）。
    - `N_star`：`n_star(r̂, μ_末, mu_tgt)`（单源）；`r̂ ≥ 1` ⟹ None（= ∞）。
    """
    from gk_convergence_estimator import stock_ratio, n_star as _n_star
    mus = [int(x) for x in stock_seq]
    r_hat, r_reason = stock_ratio(mus)
    if r_hat is None:
        return {"mu": mus, "r_hat": None, "early_stop": False,
                "N_star": None, "reason": r_reason}
    mu0 = mus[-1] if mus else 0
    n, n_reason = _n_star(r_hat, max(mu0, 1), mu_tgt)
    early = r_hat >= 1.0
    return {"mu": mus, "r_hat": r_hat, "early_stop": early, "N_star": n,
            "reason": ("r_ge_1_self_lock" if early else n_reason)}


def convergence_finding(state_file: str, plan: str, stock_seq, *,
                        mu_tgt: int = 1) -> dict:
    """跨轮比对：若判定**不收敛** ⟹ 落一条 `NO-CONVERGENCE` finding（fail-loud 早停信号）。

    - 判决量 = `r̂`（RCA 单源，见 `cross_round_convergence`）；**不新造 ρ**。
    - 收敛中（r̂<1）⟹ 不落账（只回报指标）。
    - 锚 = `plan:<plan>`；`root_key="noconv:<hash>"` ⟹ 幂等；**测量 finding**（不计入 μ）。
    """
    r = cross_round_convergence(stock_seq, mu_tgt=mu_tgt)
    if not r["early_stop"]:
        return {"ok": True, **r}
    import gk_finding
    import hashlib as _hl
    title = "审查轮次不收敛: plan=%s r_hat=%s mu=%s" % (
        plan or "-", ("%.3f" % r["r_hat"]) if r["r_hat"] is not None else "None", r["mu"])
    rec = gk_finding.register(
        state_file, title, "review",
        root_key="noconv:" + _hl.sha256((plan or "-").encode("utf-8")).hexdigest()[:16],
        anchors=["plan:" + (plan or "-")],
        source_note="RCA early-stop r_hat=%s N*=%s"% (r["r_hat"], r["N_star"]))
    return {"ok": True, "finding": rec, **r}


# ── 验收聚合（`--accept`，ECC-BAB89429DFD1 / 设计 §11.5，2026-09-23）──────────────
# 用户裁定「MoA 职责就是聚合验收」：原 MoA 只聚合 subagent **报告**，验收器 `_accept_cli.sh`
# 是**独立**脚本 ⟹ 并发 coder 收口要主 agent 手工两步。`--accept` = **单入口**：
#   ① 逐 worktree 跑**受影响子集** —— 复用 `_accept_cli.sh <file>...` 的显式文件形态
#      （判定单一事实源仍是 `_accept_baseline.txt` + accept_cli，**不新造第二套 diff/基线逻辑**）；
#   ② 合并为统一裁决封套（`accept.per_worktree` + `accept.global`）。
# ⚠ A7 不破：本模式**只聚合证据**，最终验收权仍在主 agent（acting）。
# ⚠ fail-loud：「无输入」≠「无失败」——未给 `--worktrees`（或空串）时 `global.verdict` 恒
#    `"unknown"`，**禁止静默判 pass**（本仓既有纪律；同 `_accept_cli.sh` exit 2 的语义）。
ACCEPT_CLI = Path(__file__).resolve().parent / "_accept_cli.sh"
# `_accept_cli.sh` 退出码语义 → 裁决态：0 = 无新增失败；1 = 有新增失败（真回归）；2 = 环境/参数错误。
_ACCEPT_RC_VERDICT = {0: "pass", 1: "fail"}


def _split_csv(raw: str) -> list[str]:
    """逗号分隔 → 去空白去空项（`--worktrees` / `--accept-files` 共用）。"""
    return [x.strip() for x in str(raw or "").split(",") if x.strip()]


def _parse_accept_section(out: str, header: str) -> list[str]:
    """从 `_accept_cli.sh` 输出取 `[accept] <header>...` 段之后的逐用例名（缩进 2 空格行）。

    只解析**既有**输出格式（`  <testid>` 与 pytest `-rfE` 同源），不修改 accept_cli 语义。
    """
    ids: list[str] = []
    active = False
    for line in (out or "").splitlines():
        if line.lstrip().startswith("[accept]"):
            active = header in line
            continue
        if active and line.startswith("  ") and line.strip():
            ids.append(line.strip())
    return sorted(set(ids))


def _accept_one_worktree(wt: str, files: list[str], timeout: int) -> dict:
    """单 worktree 跑受影响子集（显式文件形态）。

    缺该 worktree 自己的 `scripts/_accept_cli.sh` ⇒ 记 `unavailable` 且 verdict=`unknown`
    （**fail-loud**：缺输入面不冒充 pass）。子进程失败/超时同样降为 `unknown`（禁静默 pass）。
    路径不存在与「worktree 内缺验收器」分开报（两种病不同因，诊断面不合并；verdict 恒 unknown）。
    """
    rec: dict = {"worktree": wt, "rc": None, "verdict": "unknown", "new_failures": [],
                 "fixed": [], "summary": "", "error": ""}
    if not Path(wt).is_dir():
        rec["error"] = f"worktree 路径不存在（拼写错误/未创建）: {wt}"
        return rec
    script = Path(wt) / "scripts" / "_accept_cli.sh"
    if not script.is_file():
        rec["error"] = f"worktree 内缺 scripts/_accept_cli.sh: {script}"
        return rec
    cmd = ["bash", script.name, *files]
    try:
        r = subprocess.run(cmd, cwd=str(script.parent), capture_output=True,
                           text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        rec["error"] = f"accept 超时（>{timeout}s）"
        return rec
    except OSError as exc:
        rec["error"] = f"accept 执行失败: {exc}"
        return rec
    out = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
    rec["rc"] = r.returncode
    rec["verdict"] = _ACCEPT_RC_VERDICT.get(r.returncode, "unknown")
    rec["new_failures"] = _parse_accept_section(out, "NEW 失败")
    rec["fixed"] = _parse_accept_section(out, "FIXED")
    rec["summary"] = next((ln for ln in out.splitlines() if ln.lstrip().startswith("[accept]")), "")
    if rec["verdict"] == "unknown":
        tail = (out.strip().splitlines() or [""])[-1][:200]
        rec["error"] = f"accept 退出码 {r.returncode}（2=环境/参数错误 ⟹ 不判 pass）: {tail}"
    return rec


def _accept_full_regression(tree: str, timeout: int) -> dict:
    """合并树上跑**全量**回归（`_accept_cli.sh --full`）—— 补「逐 worktree 受影响子集」的盲区。

    ECC-2FB0B4D0F356：并发 coder 各跑各的受影响子集 ⟹ **跨族交互**只在合并后暴露，既有
    `--accept` 不覆盖。判定单一事实源仍是 `_accept_cli.sh`（本函数只调用 + 解析，不新造第二套）。
    缺合并树 / 缺 `<tree>/scripts/_accept_cli.sh` ⟹ `rc=None` / `verdict="unknown"`（**fail-loud**：
    缺输入面不冒充 pass，同 `_accept_one_worktree`）；超时 / OSError 同样降 `unknown`。
    """
    rec: dict = {"tree": tree, "rc": None, "verdict": "unknown", "new_failures": [],
                 "fixed": [], "summary": "", "error": ""}
    if not Path(tree).is_dir():
        rec["error"] = f"合并树路径不存在（拼写错误/未创建）: {tree}"
        return rec
    script = Path(tree) / "scripts" / "_accept_cli.sh"
    if not script.is_file():
        rec["error"] = f"合并树内缺 scripts/_accept_cli.sh: {script}"
        return rec
    try:
        r = subprocess.run(["bash", script.name, "--full"], cwd=str(script.parent),
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        rec["error"] = f"全量回归超时（>{timeout}s）"
        return rec
    except OSError as exc:
        rec["error"] = f"全量回归执行失败: {exc}"
        return rec
    out = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
    rec["rc"] = r.returncode
    rec["verdict"] = _ACCEPT_RC_VERDICT.get(r.returncode, "unknown")
    rec["new_failures"] = _parse_accept_section(out, "NEW 失败")
    rec["fixed"] = _parse_accept_section(out, "FIXED")
    rec["summary"] = next((ln for ln in out.splitlines() if ln.lstrip().startswith("[accept]")), "")
    if rec["verdict"] == "unknown":
        tail = (out.strip().splitlines() or [""])[-1][:200]
        rec["error"] = f"全量回归退出码 {r.returncode}（2=环境/参数错误 ⟹ 不判 pass）: {tail}"
    return rec


def accept_reports(worktrees: list[str], state_file: str = "",
                   files: list[str] | None = None, timeout: int = 3600) -> dict:
    """聚合验收：逐 worktree 跑受影响子集 → 统一裁决封套（单入口，A7 不破）。"""
    wts = [w for w in (worktrees or []) if str(w).strip()]
    fl = [f for f in (files or []) if str(f).strip()]
    per = [_accept_one_worktree(w, fl, timeout) for w in wts]
    new_failures = sorted({f for p in per for f in p["new_failures"]})
    fixed = sorted({f for p in per for f in p["fixed"]})
    if not wts:
        # fail-loud：「无输入」≠「无失败」⟹ 拒绝判定 pass（本仓纪律）
        verdict, reason = "unknown", "无 --worktrees（或空串）⟹ 无验收输入，拒绝判 pass（fail-loud）"
    elif any(p["verdict"] == "fail" for p in per):
        verdict, reason = "fail", "至少一个 worktree 报 NEW 失败（双重复核后的真回归）"
    elif all(p["verdict"] == "pass" for p in per):
        verdict, reason = "pass", "全部 worktree 无新增失败（与基线一致）"
    else:
        verdict, reason = "unknown", "有 worktree 裁决态未知（缺 accept 脚本/超时/退出码 2）⟹ 不判 pass"
    return {
        "mode": "moa_accept",
        "ok": True,
        "accept": {
            "per_worktree": per,
            "global": {
                "verdict": verdict,
                "new_failures": new_failures,
                "fixed": fixed,
                "worktrees": wts,
                "files": fl,
                "reason": reason,
            },
        },
        "trace": {"source": state_file, "accept_cli": str(ACCEPT_CLI),
                  "worktree_count": len(wts), "timeout_s": timeout},
    }


# ── 人工裁定页（`--html`；ECC-4C1E8A27B9D3，2026-09-24 用户裁定；S3-4 2026-10-06 改版）──
# 定位：MoA 聚合**之后**的一次性页面（读完即弃，`file://` 直开）。
# 三条硬约束（与 scripts/test_gk_moa_aggregate.TestHumanAdjudicatePage 同源，改一处即红）：
#   ① 自足 —— 单文件内联 CSS/JS、零外部资源引用（离线可开）；
#   ② 双盲 —— **不**渲染 agent 侧分数锚（divergence / HUMAN_OVERSCORE 由 CLI `adjudicate` 事后算）；
#   ③ 零新写通路 —— 出口只有「下载 prose.txt + 复制命令链」，state 仍只有 CLI 一个写入口。
# S3-4（owner 裁定「不要再让我评分」）：**取消逐项评分 UI**（F1-F7 下拉 + 滑杆 + decision）；
#   人只写**散文结论**，经 `finding from-prose` → `finding score` → `adjudicate` 生成批级裁定分。
# F1-F7 标签单一事实源 = plan-refinement/SKILL.md §二 + §四（本表仅复述，**勿在此新增维度**）。
_F17 = (("F1", "范围蔓延"), ("F2", "伪依赖"), ("F3", "假验证"), ("F4", "绕过现有设施"),
        ("F5", "过度假设"), ("F6", "无回退"), ("F7", "框架锁定"))

# ── 通用分析框架（消费方指引；§18.5；2026-10-30 去标签化重写）──────────────────
# 单一事实源 = `monitor-schemas/ECC-WRITE.json`（判断可闭合侧的**形式**判据）。本表
#   **仅复述**其 7 条 requires 与 purpose 纪律（对齐 `_F17` 的「复述 + 单源指针」惯例，勿新增维度）。
# 用途 = 人评页的**消费方指引**：教人评者用中立的分析视角读 6 臂收敛（核心张力 / 转化条件/…）。
# ⚠ 2026-10-30（owner 裁定）：本项目是**开源协作项目**，通用方法论不绑定任何特定意识形态标签
#   ⟹ 原「马原」抬头与教条式措辞**移除**，改为中性自然语言；判据语义不变（仅措辞去标签化）。
# ⚠ 解耦纪律（PW-SN §4 D5 + ecc-write-spec §1）：本框架**禁**写入 `state.gate_data.ecc_findings[]`，
#   亦**禁**落成 EccOutput 形态；人评页只是 `EccOutput` 的消费方。
_ECC_ARG = (
    ("principal", "核心症结恰 1 条（禁并列 —— 并列 = 尚未定位核心问题）"),
    ("resolution", "转化/闭合条件写明（形如「在 X 条件下成立/闭合」；禁无条件断言）"),
    ("facts_judgement", "事实（命令+stdout / file:line）与判断（是否真缺陷 / 归属域）可分辨"),
    ("closure_oracle", "闭合是否需人审：mechanical（确定性 oracle 可判）/ judgment（需人的判断）；空 = 未分类"),
    ("root_key", "根因指纹（无空白、≤64 字符），非散文；有则按根因合并判重"),
    ("source_token", "来源 = 白名单短 token（manual/crossr/crossrev/red/review/audit/monitor/subagent-promoted）"),
    ("discipline", "**不判判断对错**（LLM 判 LLM = 自指）；机器填事实、人填判断"),
)

# 分析视角（通用辩证方法，自然语言；**只作阅读提示，不产生新判据**）：
#   来源 = 一组被广泛使用的一般方法论（系统/过程/张力/扬弃/现象与本质/因果/趋势与可能/实践检验/
#   形式与内容），剥离特定学派与政治语汇 ⟹ 开源协作与国际读者均可直接使用。
_DIALECTIC_LENSES = (
    ("联系与系统", "先问「它和什么互相影响」：局部与整体、结构与功能、内部与外部条件。孤立结论通常不可靠。"),
    ("过程与阶段", "判断处在哪个阶段、朝哪个方向变化；区分缓慢积累与临界拐点，别把阶段性结论当终局。"),
    ("张力与转化", "找出核心张力（唯一）及其对立面；写清两者在什么条件下共存、在什么条件下互相转化。"),
    ("扬弃与迭代", "对既有方案不做全盘接受或全盘否定：保留仍有效的部分、替换已失效的部分；"
                  "新方案须能解释旧方案解释不了的现象。"),
    ("现象与本质", "把可观察事实（命令输出、文件行号）与推断（根因、归属）分开；用反例穿透表象。"),
    ("因果与条件", "区分相关与因果；标明必要条件/充分条件；做反事实检验（去掉某条件是否仍成立）。"),
    ("趋势与波动", "区分稳定趋势与随机波动；评估每种可能性的实现条件，而不是只押一条路径。"),
    ("实践与检验", "结论须可被检验：给出可复现的验证动作；被证伪时保留信息并修正模型，而不是辩护。"),
    ("形式与内容", "形式服务内容：既不用格式完备替代实质证据，也不用实质正确掩盖形式缺陷。"),
)
_ECC_SOURCE_HINT = "单一事实源 monitor-schemas/ECC-WRITE.json（本页仅作消费指引，禁写入 ecc_findings）"

# ── 散文条目解析（C 扩，2026-10-09 owner 裁定）：**单源** —— CLI（gk_prose_findings）与
#    页面 JS 计数共用本处两个正则（页面经 _json_embed 注入，禁另写第二套判据）。
#    · marker：`-`/`*`/`+` / `1.` `1)` `1、` / `一、`（中文序号） / `（1）` `(1)` / `①`…`⑳`；
#    · heading：`#`~`######` 标题行（段落模式下除外，不入 finding）。
_MARKER_RE = re.compile(
    r"^\s*(?:[-*+]|\d+[.)、]|[一二三四五六七八九十百]+[、.)）]"
    r"|[（(]\s*(?:\d+|[一二三四五六七八九十百]+)\s*[)）]"
    r"|[①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳])\s*(.*)$")
_HEAD_RE = re.compile(r"^\s*#{1,6}\s")


def parse_items(prose: str) -> list:
    """散文 → 条目串列表（**确定性、零 LLM**；CLI 与页面 JS 计数共此单源）。

    · 列表项（`-`/`*`/`1.`/`一、`/`（1）`/`①`）与普通段落**都**成条；
      标题行不入。**混合输入不再静默丢弃普通段落**（M1，2026-10-20）。
    · 段落按空行/标题/列表项边界分段，段内换行合并。
    """
    lines = str(prose or "").splitlines()
    out, buf = [], []

    def _flush():
        if buf:
            out.append(" ".join(buf))
            buf.clear()

    for raw in lines:
        if _HEAD_RE.match(raw) or not raw.strip():
            _flush()
            continue
        m = _MARKER_RE.match(raw)
        if m:
            _flush()
            body = (m.group(1) or "").strip()
            if body:
                out.append(body)
            continue
        buf.append(raw.strip())
    _flush()
    return out


_CSS = """
:root{--bg:#fdf6e3;--fg:#3f4a52;--mut:#7d8a8f;--line:#e4dcc4;--card:#fffdf6;
--ok:#6c8a00;--warn:#a9761a;--bad:#c0392b;--acc:#268bd2;
--bnn-bg:#e9f2fa;--bnn-fg:#20506e;--wn-bg:#fbece9;--wn-fg:#8a2820;
--pre-bg:#f6efdb;--th-bg:#f3ecd8;--inp-bg:#fffdf6;--svg-bg:#fbf6e8;
--tt-bg:rgba(255,253,246,0.97);--zebra:rgba(125,138,143,.06)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.6 system-ui,"Segoe UI",Roboto,"Noto Sans SC",sans-serif}
.wrap{width:100%;max-width:none;margin:0 auto;padding:24px 20px 80px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:28px 0 10px;
padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:13.5px;margin:18px 0 8px;font-weight:600}
.banner{border:1px solid var(--acc);background:var(--bnn-bg);border-radius:8px;
padding:10px 14px;margin:14px 0;color:var(--bnn-fg)}
.banner-warn{border:1px solid var(--bad);background:var(--wn-bg);border-radius:6px;
padding:8px 12px;margin-top:8px;color:var(--wn-fg);font-size:12px}
.meta{color:var(--mut);font-size:12px}
.nav{display:flex;flex-wrap:wrap;align-items:center;gap:4px 14px;margin:10px 0;font-size:12.5px}
.nav a{color:var(--acc);text-decoration:none;border-bottom:1px dotted var(--acc)}
.nav a:hover{color:var(--fg)}
.nav-gap{flex:1}
.nav button{margin:0}
/* ── ① 顶部 KPI 带（2026-10-31）：新用户 3 秒抓重点 ── */
.kpi{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
.kpi .k{flex:1 1 150px;min-width:130px;background:var(--card);border:1px solid var(--line);
border-radius:8px;padding:8px 12px}
.kpi .k span{display:block;color:var(--mut);font-size:11.5px}
.kpi .k b{display:block;font-size:20px;font-weight:700;
font-family:ui-monospace,Consolas,monospace;font-variant-numeric:tabular-nums}
.kpi .k.ok b{color:var(--ok)}.kpi .k.warn b{color:var(--warn)}.kpi .k.bad b{color:var(--bad)}
/* ── ③ 三视图分段切换（2026-10-31）：内容恒在 DOM，隐藏只靠 CSS ── */
.tabs{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}
.tabs button{background:var(--card);border:1px solid var(--line);color:var(--fg);
border-radius:999px;padding:5px 14px;font-size:13px;cursor:pointer;margin:0}
.tabs button[aria-selected=true]{background:var(--acc);border-color:var(--acc);color:#fff}
.vw{display:block}
body[data-view=mat] .vw-chart,body[data-view=mat] .vw-prose{display:none}
body[data-view=chart] .vw-mat,body[data-view=chart] .vw-prose{display:none}
body[data-view=prose] .vw-mat,body[data-view=prose] .vw-chart{display:none}
abbr[title]{cursor:help;text-decoration:underline dotted var(--mut);text-underline-offset:2px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;
padding:14px;margin:12px 0}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
.chip{font-size:12px;padding:2px 8px;border-radius:999px;border:1px solid var(--line);color:var(--mut)}
.chip.warn{border-color:var(--warn);color:var(--warn)}
.chip.bad{border-color:var(--bad);color:var(--bad)}
.chip.ok{border-color:var(--ok);color:var(--ok)}
pre{background:var(--pre-bg);border:1px solid var(--line);border-radius:6px;
padding:10px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:12.5px}
/* ── ④ 表格密度三件套：数字对齐 / 斑马纹 / sticky 表头 ── */
table{width:100%;border-collapse:collapse;font-size:12.5px;font-variant-numeric:tabular-nums}
tbody tr:nth-child(even)>td{background:var(--zebra)}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{background:var(--th-bg);color:var(--fg);font-weight:600}
table th{position:sticky;top:0;z-index:1}
tbody tr.rowwarn>td{background:rgba(192,57,43,.07)}
tbody tr.rowwarn>td:first-child{box-shadow:inset 2px 0 0 var(--bad)}
details{margin:8px 0}summary{cursor:pointer;color:var(--mut)}
.axis{display:grid;grid-template-columns:190px 130px 1fr;gap:8px;align-items:center;
padding:6px 0;border-bottom:1px solid var(--line)}
select,input[type=text],textarea{background:var(--inp-bg);color:var(--fg);
border:1px solid var(--line);border-radius:6px;padding:5px 7px;font-size:13px;width:100%}
textarea{min-height:54px;font-family:inherit}
.big{font-size:26px;font-weight:700;font-family:ui-monospace,Consolas,monospace}
button{background:var(--acc);color:#fff;border:0;border-radius:6px;
padding:7px 13px;font-size:13px;cursor:pointer;margin:4px 8px 4px 0}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--fg)}
button:disabled{opacity:.45;cursor:not-allowed}
.chart{margin:12px 0;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px}
.chart figcaption{color:var(--mut);font-size:12px;margin-bottom:6px}
.chart figcaption b{color:var(--fg)}
.chart svg{display:block;background:var(--svg-bg);border-radius:6px}
.echart{width:100%;overflow:hidden}
/* ── ⑤ 深色主题（2026-10-31）：body[data-dark] 覆盖令牌 ── */
body[data-dark]{--bg:#14181c;--fg:#dbe2e6;--mut:#8b98a0;--line:#2b3238;--card:#1b2126;
--ok:#9dbb1f;--warn:#d79a2b;--bad:#e06555;--acc:#58a6e0;
--bnn-bg:#12242f;--bnn-fg:#9cc7e6;--wn-bg:#2a1614;--wn-fg:#e8968a;
--pre-bg:#161b20;--th-bg:#22292f;--inp-bg:#161b20;--svg-bg:#161b20;
--tt-bg:rgba(27,33,38,0.97);--zebra:rgba(139,152,160,.07)}
body[data-dark] button.ghost{color:var(--fg)}
body[data-dark] .tabs button[aria-selected=true]{color:#0d1117}
.c-hd{fill:var(--mut);font-size:12px;font-weight:600}
.c-lab{fill:var(--mut);font-size:12px}
.c-t{fill:var(--fg);font-size:12px}
.c-line{stroke:var(--line);stroke-width:1}
.c-grid{stroke:var(--line);stroke-width:1;stroke-dasharray:3 3;opacity:.7}
.c-ax{stroke:var(--mut);stroke-width:1}
.c-arc{fill:var(--acc)}
.c-arc.c-contr{fill:var(--bad)}
.c-pt{stroke:var(--card);stroke-width:1.5;opacity:.85}
.c-pt.c-g1{fill:var(--acc)}
.c-pt.c-g2{fill:var(--ok)}
.c-pt.c-g3{fill:var(--bad)}
.c-pt.c-gx{fill:var(--mut)}
.c-ptw{fill:var(--warn);stroke:var(--card);stroke-width:1.5}
.c-solid{fill:none;stroke:var(--acc);stroke-width:2}
.c-dash{fill:none;stroke:var(--warn);stroke-width:2;stroke-dasharray:5 4}
.c-scale-lo{fill:var(--acc);opacity:.2;stroke:var(--line);stroke-width:1}
.c-scale-hi{fill:var(--acc);opacity:.95;stroke:var(--line);stroke-width:1}
.c-scale-t{fill:var(--mut);font-size:11px}
.c-heat{fill:var(--acc)}
.c-heat.c-contr{fill:var(--bad)}
.c-num{fill:var(--fg);font-size:12px;font-weight:600}
.c-sub{fill:var(--mut);font-size:11px}
.c-tot{fill:var(--mut);font-size:12px}
.c-red{fill:var(--bad)}
"""

_JS = """
(function(){
  var GK_MARKER_SRC=__MARKER_SRC__,GK_HEAD_SRC=__HEAD_SRC__;
  function val(id){var e=document.getElementById(id);return e?e.value:"";}
  function set(id,v){var e=document.getElementById(id);if(e)e.value=v;}
  function copyText(t,btn,label){
    function fb(){var a=document.createElement("textarea");a.value=t;document.body.appendChild(a);
      a.select();document.execCommand("copy");document.body.removeChild(a);}
    if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).catch(fb);}
    else{fb();}
    var idle=btn.getAttribute("data-idle")||btn.textContent;
    btn.setAttribute("data-idle",idle);btn.textContent=label;
    setTimeout(function(){btn.textContent=idle;},1500);
  }
  function cmdText(){
    var dir=val("dir").trim()||".";
    var mode=val("mode")||"reject";
    var ctx=val("ctx").trim();
    var NL=String.fromCharCode(10);
    var c1='bash gatekeeper-cli.sh finding from-prose --file prose.txt --out '+dir+'/findings.json';
    if(ctx){c1+=' --context '+ctx;}
    return c1+NL
         + 'bash gatekeeper-cli.sh finding score --file '+dir+'/findings.json --out-dir '+dir
         + ' --direction '+mode+NL
         + 'bash gatekeeper-cli.sh adjudicate --verdicts-file '+dir+'/verdicts.json'
         + ' --concessions-file '+dir+'/concessions.json'
         + ' --score <上一步 score÷100，如 88→0.88> --decision "人工结论见 prose.txt" --blind';
  }
  /* ① 空 findings 护栏：实时数**条目**；0 条 ⟹ 显式红框告警（禁静默全 PASS 放行）。
     判据**单源**：marker/heading 正则由 Python（_MARKER_RE/_HEAD_RE）注入（与 gk_prose_findings 同源）。
     · 列表模式：仅标记行成条；· 段落模式（纯散文）：按空行分段成条。 */
  function countItems(t){
    var LF=String.fromCharCode(10);
    var ls=String(t||"").split(LF),i,n=0,MK=new RegExp(GK_MARKER_SRC),HD=new RegExp(GK_HEAD_SRC);
    var hasM=false;
    for(i=0;i<ls.length;i++){if(MK.test(ls[i])){hasM=true;break;}}
    if(hasM){
      for(i=0;i<ls.length;i++){var m=MK.exec(ls[i]);
        if(m&&(m[1]||"").trim())n++;}
      return n;
    }
    var buf=false;
    for(i=0;i<ls.length;i++){
      if(HD.test(ls[i])||!ls[i].trim()){if(buf){n++;buf=false;}continue;}
      buf=true;
    }
    if(buf)n++;
    return n;
  }
  function refreshWarn(){
    var pw=document.getElementById("prose-warn");if(!pw)return;
    var v=val("prose");
    if(!v.trim()){pw.style.display="none";pw.textContent="";return;}
    var n=countItems(v);pw.style.display="";
    if(n>0){pw.className="meta";
      pw.textContent="已识别 "+n+" 条结论项 ⟹ 将产出 "+n+" 条 finding。";}
    else{pw.className="banner-warn";
      pw.textContent="⚠ 当前散文无可解析条目（列表项 - / 1. / 一、，或按空行的自然段）⟹ 将产出 0 条 finding ⟹ 评分恒为 100 全 PASS 放行。";}
  }
  function refresh(){var pre=document.getElementById("cmd");if(pre)pre.textContent=cmdText();refreshWarn();}
  var dp=document.getElementById("dl-p");
  if(dp)dp.addEventListener("click",function(){
    var a=document.createElement("a");
    a.href=URL.createObjectURL(new Blob([val("prose")],{type:"text/plain"}));
    a.download="prose.txt";document.body.appendChild(a);a.click();document.body.removeChild(a);
  });
  var cp=document.getElementById("copy");
  if(cp)cp.addEventListener("click",function(){copyText(cmdText(),this,"已复制命令链");});
  var cpp=document.getElementById("copy-p");
  if(cpp)cpp.addEventListener("click",function(){copyText(val("prose"),this,"已复制散文");});
  ["dir","prose","ctx","mode"].forEach(function(id){
    var e=document.getElementById(id);
    if(!e)return;
    e.addEventListener("input",refresh);e.addEventListener("change",refresh);});
  var KEY="gk-moa-prose-"+document.body.getAttribute("data-key");
  try{var raw=localStorage.getItem(KEY);
    if(raw){var o=JSON.parse(raw);set("prose",o.prose||"");if(o.dir)set("dir",o.dir);
      if(o.ctx)set("ctx",o.ctx);if(o.mode)set("mode",o.mode);}}catch(e){}
  var _save_t=null;
  function save(){try{localStorage.setItem(KEY,
    JSON.stringify({prose:val("prose"),dir:val("dir"),ctx:val("ctx"),mode:val("mode")}));}catch(e){}}
  ["dir","prose","ctx","mode"].forEach(function(id){
    var e=document.getElementById(id);if(!e)return;
    e.addEventListener("input",function(){clearTimeout(_save_t);_save_t=setTimeout(save,400);});
    e.addEventListener("change",function(){clearTimeout(_save_t);_save_t=setTimeout(save,400);});});
  window.addEventListener("pagehide",save);
  var ea=document.getElementById("exp-all"),ca=document.getElementById("col-all");
  function setAll(v){var ds=document.querySelectorAll("div.wrap details");for(var i=0;i<ds.length;i++)ds[i].open=v;}
  if(ea)ea.addEventListener("click",function(){setAll(true);});
  if(ca)ca.addEventListener("click",function(){setAll(false);});
  /* i18n 中英开关：**静态 UI 词典**（离线可开，零外呼）。只翻 UI 骨架（
     `[data-i18n]` 标注的导航/章节标题/按钮）；结论文本与分析数据**不翻**（保持原文可审计）。 */
  var I18N={
    "nav-mat":"1 · Aggregation material","nav-sum":"Batch substance summary",
    "nav-prose":"2 · Human conclusion","nav-out":"3 · Export",
    "exp-all":"Expand all","col-all":"Collapse all",
    "h-mat-refs":"1 · Aggregation material · reports","h-mat-accept":"1 · Aggregation material · accept",
    "h-prose":"2 · Human conclusion (prose)","h-out":"3 · Export (no new write path)",
    "h-dialectic":"Dialectic (thesis / antithesis / pollution / synthesis)",
    "h-agg":"Aggregate detail (clusters / agreement / 3 groups)",
    "h-finding":"ecc-finding detail","h-runstatus":"subagent runtime status",
    "h-sum":"Batch substance summary",
    "b-dl":"Download prose.txt","b-copy":"Copy prose","b-cmd":"Copy command chain",
    "tab-mat":"Material","tab-chart":"Charts","tab-prose":"Adjudicate"};
  function applyLang(l){
    var els=document.querySelectorAll("[data-i18n]");
    for(var i=0;i<els.length;i++){var el=els[i],k=el.getAttribute("data-i18n");
      if(!el.getAttribute("data-zh"))el.setAttribute("data-zh",el.textContent);
      el.textContent=((l==="en")&&I18N[k])?I18N[k]:el.getAttribute("data-zh");}
    document.documentElement.lang=(l==="en")?"en":"zh-CN";
    var lb=document.getElementById("lang");if(lb)lb.textContent=(l==="en")?"中文":"EN";
  }
  var LKEY="gk-moa-lang";
  var lb=document.getElementById("lang");
  if(lb)lb.addEventListener("click",function(){
    var cur="zh";try{cur=localStorage.getItem(LKEY)||"zh";}catch(e){}
    var nx=(cur==="en")?"zh":"en";
    try{localStorage.setItem(LKEY,nx);}catch(e){}
    applyLang(nx);});
  try{if((localStorage.getItem(LKEY)||"zh")==="en")applyLang("en");}catch(e){}
  /* ── ③ 三视图分段切换（2026-10-31 观感升级）：内容恒在 DOM，隐藏只靠 CSS。
     进图表视图须重建 ECharts（容器隐藏时 init ⟹ 0 宽错位）。零轮询（沿用 T-b 约束）。 */
  function setView(v){
    if(v!=="mat"&&v!=="chart"&&v!=="prose"){v="prose";}
    document.body.setAttribute("data-view",v);
    try{localStorage.setItem("gk-moa-view",v);}catch(e){}
    var ts=document.querySelectorAll(".tabs button");
    for(var i=0;i<ts.length;i++){
      ts[i].setAttribute("aria-selected",
        ts[i].getAttribute("data-view")===v?"true":"false");}
    if(v==="chart"&&typeof window.__gkChartsRebuild==="function"){
      window.__gkChartsRebuild();}
  }
  var _tb=document.querySelectorAll(".tabs button");
  for(var i=0;i<_tb.length;i++){
    (function(b){b.addEventListener("click",function(){
      setView(b.getAttribute("data-view"));});})(_tb[i]);}
  var VMAP={"sec-mat":"mat","sec-sum":"mat","sec-prose":"prose","sec-out":"prose"};
  var _na=document.querySelectorAll(".nav a[href^='#']");
  for(var i=0;i<_na.length;i++){
    (function(a){a.addEventListener("click",function(){
      var v=VMAP[a.getAttribute("href").slice(1)];
      if(v){setView(v);}});})(_na[i]);}
  /* ── ⑤ 深色主题（2026-10-31）：切换 + 持久化 + 跟随系统缺省。事件驱动，零轮询。 ── */
  var DKEY="gk-moa-dark";
  function applyDark(on){
    if(on){document.body.setAttribute("data-dark","1");}
    else{document.body.removeAttribute("data-dark");}
    var b=document.getElementById("dark");
    if(b){b.textContent=on?"☀ 浅色":"☾ 深色";}
    if(typeof window.__gkChartsRebuild==="function"){window.__gkChartsRebuild();}
  }
  var dbtn=document.getElementById("dark");
  if(dbtn){dbtn.addEventListener("click",function(){
    var on=!document.body.hasAttribute("data-dark");
    try{localStorage.setItem(DKEY,on?"dark":"light");}catch(e){}
    applyDark(on);});}
  var _dk=null;try{_dk=localStorage.getItem(DKEY);}catch(e){}
  if(!_dk){
    _dk=(window.matchMedia&&window.matchMedia("(prefers-color-scheme: dark)").matches)
        ?"dark":"light";}
  applyDark(_dk==="dark");
  var _vw=null;try{_vw=localStorage.getItem("gk-moa-view");}catch(e){}
  setView(_vw||"prose");
  refresh();
})();
"""


# `ECC-03560D2993C2`（2026-09-27）：双盲人评页的**渲染侧**遮蔽。
#   约束②声称「不渲染 agent 侧分数锚」，但 conclusion 被原样渲染，而 plan-refinement 各臂的
#   conclusion 是**含 7 维分的 JSON**（实测命中 `score`/`scope` 键）⟹ 人评侧仍看到 agent 分值
#   ⟹ divergence / HUMAN_OVERSCORE 失去双盲意义。修法 = 渲染前对分数键值做遮蔽（**只改渲染，
#   落盘数据不动** —— 证据可回溯）。
_BLIND_SCORE_KEYS = ("score", "score_pct", "scope", "seven_dim_score",
                     "total_score", "divergence")


def _blind_conclusion(text: str) -> str:
    """遮蔽 conclusion 文本内的**分数键值片段**（`"score": 87` → `[已遮蔽]`）。

    整个片段（含**键名**）一并替换 —— 既有双盲臂 `test_double_blind_hides_agent_side_score`
    已钉「页面不得出现 `seven_dim_score` 等字面量」，只遮蔽数值仍会漏出键名；只对**数值**取值
    生效 ⟹ 非数值（如 `"scope": "F1-F7"`）与普通正文不受影响。
    """
    for k in _BLIND_SCORE_KEYS:
        text = re.sub(r'"?%s"?\s*[:：]\s*-?\d+(?:\.\d+)?' % re.escape(k),
                      '[已遮蔽]', text)
    return text


def arm_score(a: dict):
    """臂级标量分（**单源**）：优先模型自报 `overall_score`；缺 ⟹ 由 `seven_dim_score` 均值归一
    派生 `round(mean/100, 4)`；两者皆无 ⟹ `None`（不猜）。

    T14（2026-10-15，finding `ECC-03DF9BDC3A1B`）：原为 `merge_sealed_agent_score` **内嵌闭包**
    ⟹ 派生只落 seal 槽（`gd._sealed_agent_score.score`）、**从不回写** `subagent_history`
    （CLI 落库 `gatekeeper-cli.sh:4844` 裸透传 runner 的 `None`）⟹ `_refs_of(history)` 取不到分
    ⟹ `arm_dispersion` 恒 `UNDER-POWERED`（T10 名义接通、实质空转）。提为模块级 ⟹ **落库面与
    seal 面同口径**、禁第二实现。
    """
    os_ = a.get("overall_score")
    if os_ is None:
        sd = a.get("seven_dim_score") or {}
        vals = [v for v in sd.values() if isinstance(v, (int, float))]
        if vals:
            os_ = round(sum(vals) / len(vals) / 100.0, 4)
    return os_


def arm_observables(out: dict, *, delta=0, stride=None, gold=None, block=8, provider="") -> dict:
    """臂装配侧**消融观测量**（W2A-P2 D 子计划 §14.7-D-1「接线先行」）—— §2 五件在**臂装配侧**
    产出，非事后从 verdicts 推（治「仪器与结果变量两条通道从未会合」，§14.7.1）。

    只读 runner 载荷 `out`；返回**有界** dict（供 `subagent_history[].arm_obs` 落库）：
      · `arm_phase` —— φ = Δ mod S（**单源** `gk_evidence.per_arm_phases`，base_len=0/n=1）；
        `stride` 缺/非法 ⟹ `None` = **UNKNOWN**（**不** fail-loud：本处是观测非拒跑）。
      · `det_F1` —— `gold` 非空且 conclusion 可读 ⟹ `gk_moa_judge.score`；
        缺 gold / conclusion ⟹ `None` + `det_f1_reason`（**禁**默认 0.0 假绿）。
      · `cache` —— 逐调用 usage → `gk_cache_observe.observe` 摘要；零可归属 usage ⟹
        `usage_status="UNKNOWN"`（**禁**静默 0；对齐 F-A① fail-closed 纪律）。

    `gk_moa_judge` / `gk_cache_observe` / `gk_evidence` 逐调用本地 import（无模块级硬依赖）。
    """
    res = {"arm_phase": None}
    try:
        from gk_evidence import per_arm_phases
        ph = per_arm_phases(int(delta), 1, 0, stride)   # φ = Δ mod S（单源；本臂 Δ 即 base_len）
        res["arm_phase"] = ph[0] if ph else None
    except Exception:
        res["arm_phase"] = None

    conclusion = ""
    if isinstance(out, dict):
        c = out.get("conclusion")
        if not (isinstance(c, str) and c.strip()):
            pay = out.get("agent_payload")
            c = pay.get("conclusion") if isinstance(pay, dict) else ""
        conclusion = c if isinstance(c, str) else ""
    gl = gold or []
    if gl and conclusion:
        try:
            from gk_moa_judge import score as _jscore
            res["det_F1"] = _jscore(gl, conclusion)["det_F1"]
        except Exception as e:                                   # noqa: BLE001
            res["det_F1"] = None
            res["det_f1_reason"] = "judge_error:%s" % e
    else:
        res["det_F1"] = None
        res["det_f1_reason"] = "no_gold" if not gl else "no_conclusion"

    calls = []
    prov = provider or (out.get("provider") if isinstance(out, dict) else "") or ""
    if isinstance(out, dict):
        tu = out.get("token_usage")
        raw = (tu.get("calls") if isinstance(tu, dict) else None) or out.get("usage_calls") or []
        for j, u in enumerate(raw):
            if isinstance(u, dict):
                calls.append({"turn": j, "provider": prov, "l": 0, "usage": u})
    cache = {"calls": len(calls), "usage_status": "OBSERVED" if calls else "UNKNOWN"}
    if calls:
        try:
            from gk_cache_observe import observe as _cobs
            _rows, summ = _cobs(calls, block=block, stride=int(stride) if stride else 0)
            cache["cache_hit_ratio"] = summ.get("cache_hit_ratio")
            cache["invalidations"] = len(summ.get("invalidation_points") or [])
            cache["block_crossings"] = summ.get("block_crossings")
            cache["warmup_calls"] = summ.get("warmup_calls")
            cache["steady_calls"] = summ.get("steady_calls")
            cache["steady_cache_hit_ratio"] = summ.get("steady_cache_hit_ratio")
            cache["cache_target"] = summ.get("cache_target")
            cache["cache_status"] = summ.get("cache_status")
        except Exception as e:                                   # noqa: BLE001
            cache["usage_status"] = "UNKNOWN"
            cache["cache_reason"] = "observe_error:%s" % e
    res["cache"] = cache
    return res


def merge_sealed_agent_score(prev: dict, arm: dict, batch_id: str = "",
                             sealed_at=None) -> dict:
    """把一条 plan-refinement 臂的盲评**并入** `_sealed_agent_score`（T-c，2026-10-06，owner 裁定）。

    缺陷：原 CLI 落盘为**单槽覆盖** ⟹ 该槽 = **最后完成的那条臂**（任意单臂冒充「agent 侧」，
    实测本批 0.4471 即某单臂 7 维均）⟹ `adjudicate` 的 divergence 基准随完成顺序漂移。
    修法：**同批**（`batch_id` 一致）⟹ 臂间 **running mean**；跨批 / 无批 ⟹ 重置为该臂
    （单臂时与旧语义**逐字等价** ⟹ 零回归）。返回形状保持不变（`score`/`verdicts`/
    `confidence`/`conclusion`/`evidence_count`/`sealed_at`/`subagent_id`/`sealed`），
    新增透明键 `batch_id`/`arm_count`/`arm_ids` ⟹ D10（`gk_audit_state`）/`appeal`/
    `mediation` 消费者零回归。

    纯函数：零 I/O、零 time（`sealed_at` 由调用方注入）。
    """
    sc = arm_score(arm)   # T14（2026-10-15）：单源（模块级）—— 与 CLI 落库面同口径
    sid = str(arm.get("subagent_id", "") or "")
    bid = str(batch_id or arm.get("batch_id", "") or "")
    _p = prev or {}
    same = (bool(bid) and str(_p.get("batch_id", "") or "") == bid
            and isinstance(_p.get("score"), (int, float)) and isinstance(sc, (int, float)))
    if same:
        n = int(_p.get("arm_count", 1) or 1)
        merged = round((_p["score"] * n + sc) / (n + 1), 4)
        arms = list(_p.get("arm_ids") or []) + [sid]
        acnt = n + 1
    else:
        merged, arms, acnt = sc, [sid], 1
    return {
        "score": merged,
        "verdicts": arm.get("verdicts", {}),
        "confidence": arm.get("confidence", "medium"),
        "conclusion": arm.get("conclusion", ""),
        "evidence_count": len(arm.get("evidence", []) or []),
        "sealed_at": sealed_at if sealed_at is not None else _p.get("sealed_at"),
        "subagent_id": sid,
        "batch_id": bid,
        "arm_count": acnt,
        "arm_ids": arms,
        "sealed": True,
    }


# ── §18.4 无方向内联图（A2 分析落刀，2026-10-04）──────────────────────────
# 三张**模块级纯函数**图：签名 `(data)->str`、零 I/O、零 time、显式 sorted 锚（禁 state 插入序）。
#   ① 人评侧裁决矩阵 —— **不渲 arm 侧裁决**（`verdicts` 是 agent 判断锚，渲出即给人评侧种锚）。
#   ② 结论差异聚类 —— **无方向**结构重合度（不渲分数、不判多数倾向）。
#   ③ 身份状态图 —— 组别/批/预算态/证据完备度（全非判断量，判据在 _suspect_flags）。
# 禁：外链（`<image href>`/`xlink:href`/`<use>`/`url(`/`<script src>`）；颜色只用 _CSS 变量；
#   文本节点与属性俱不过 `_BLIND_SCORE_KEYS` 字面量（含 figcaption）。SVG `<text>` 不换行
#   ⟹ Python 侧定界 + 固定字宽系数（禁 JS 库量宽）。
_SVG_FS = 13
_SVG_ROW = 24
_SVG_LAB = 190   # 行首标签槽宽（与 .axis 网格 190px 同尺度）
_SVG_COL = 92


def _svg_w(s, fs: int = _SVG_FS) -> float:
    """确定性文本宽：CJK≈1.0×fs，ASCII≈0.56×fs。"""
    return sum((1.0 if ord(c) > 0x2E7F else 0.56) * fs for c in str(s))


def _svg_esc(s) -> str:
    import html as _h
    return _h.escape(str(s))


def _short_id(s, n: int = 16) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[:n - 1] + "…"


def _svg_identity_states(refs: list[dict], trace: dict) -> str:
    """图③ 身份与状态：**散点**（x=总 tokens · y=证据条数 · 点径=证据量 · 色=组）。

    `ECC-BF39D6698097`（C 期 §12.4-3）：对齐 ECharts 主路观感（原为表格）。
    无悬停 ⟹ 小字直标 `subagent_id`；预算耗尽 / suspect 另加暖色描边圈（详情仍见
    「subagent 运行态」面板，信息不丢）；缺字段渲 0，不渲 ok 判断（本图只渲结构量）。
    """
    pts = []
    for r in refs:
        tt = r.get("total_tokens")
        tt = float(tt) if isinstance(tt, (int, float)) else 0.0
        ev = len(r.get("evidence") or [])
        bs = str(r.get("budget_status", "") or "")
        tb = r.get("token_budget")
        exh = (bs in ("hard", "item_exceeded", "max_turns")
               or (isinstance(tb, (int, float)) and isinstance(tt, (int, float)) and tb and tt > tb))
        pts.append((tt, ev, str(r.get("subagent_id", "")),
                    str(r.get("arm_group", "") or ""), bool(exh or (r.get("suspect") or []))))
    w, h = 720, 320
    ml, mr, mt, mb = 56, 28, 26, 44
    pw, ph = w - ml - mr, h - mt - mb
    xmax = max([p[0] for p in pts] + [1.0])
    ymax = max([p[1] for p in pts] + [1])
    o = ['<figure class="chart"><figcaption>图③ 身份与状态（散点：x=总 tokens · y=证据条数 · '
         '点径=证据量 · 色=组；暖圈=预算耗尽/suspect；小字=subagent_id）</figcaption>',
         '<svg viewBox="0 0 %d %d" width="100%%" role="img">' % (w, h)]
    for k in range(5):
        gy = mt + int(ph * k / 4)
        o.append('<line x1="%d" y1="%d" x2="%d" y2="%d" class="c-grid"/>' % (ml, gy, ml + pw, gy))
        o.append('<text x="%d" y="%d" text-anchor="end" class="c-sub">%d</text>'
                 % (ml - 6, gy + 4, int(round(ymax * (4 - k) / 4.0))))
    o.append('<line x1="%d" y1="%d" x2="%d" y2="%d" class="c-ax"/>' % (ml, mt, ml, mt + ph))
    o.append('<line x1="%d" y1="%d" x2="%d" y2="%d" class="c-ax"/>' % (ml, mt + ph, ml + pw, mt + ph))
    o.append('<text x="%d" y="%d" text-anchor="middle" class="c-sub">证据条数 ↑ · 总 tokens →</text>'
             % (ml + pw // 2, h - 10))
    for (tt, ev, sid, g, warn) in pts:
        cx = ml + int(pw * (tt / (xmax or 1.0)))
        cy = mt + ph - int(ph * (ev / (ymax or 1)))
        rr = 4 + min(int(ev), 12)
        cls = {"G1": "c-g1", "G2": "c-g2", "G3": "c-g3"}.get(g, "c-gx")
        o.append('<circle cx="%d" cy="%d" r="%d" class="c-pt %s"/>' % (cx, cy, rr, cls))
        if warn:
            o.append('<circle cx="%d" cy="%d" r="%d" class="c-ptw"/>' % (cx, cy, rr + 3))
        o.append('<text x="%d" y="%d" class="c-sub">%s</text>'
                 % (cx + rr + 4, cy + 4, _svg_esc(_short_id(sid, 12))))
    o.append('</svg></figure>')
    return "".join(o)


def _svg_divergence_clusters(refs: list[dict], trace: dict) -> str:
    """图② 结论差异聚类（**无方向**）：按窄任务指纹分簇，渲**环形**（对齐 ECharts 主路）。

    `ECC-BF39D6698097`（C 期 §12.4-3）：原为横条 ⟹ 改环形（扇区弧 + 占比 + 中心汇总 + 右侧成员）。
    只渲**结构性重合度**（同指纹=同题），不渲分值、不判「多数倾向何判」（禁 directional）；
    ≥2 臂同题者以 `c-contr` 暖红扇区提示**潜在分歧**（与主路 `contradiction` 同色系）。
    """
    import math
    cl: dict[str, list[str]] = {}
    for r in refs:
        t = str(r.get("task", ""))
        fp = task_fingerprint(split_narrow_task(t) or t)
        cl.setdefault(fp, []).append(_short_id(str(r.get("subagent_id", "")), 18))
    rows = sorted(cl.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    total = sum(len(v) for _, v in rows) or 1
    w, h = 720, 300
    cx, cy, r_out, r_in = 150, 152, 118, 74
    o = ['<figure class="chart"><figcaption>图② 结论差异聚类（环形：各簇占比 · '
         '暖红=≥2 臂同题〔潜在分歧〕；无方向·仅结构重合度）</figcaption>',
         '<svg viewBox="0 0 %d %d" width="100%%" role="img">' % (w, h)]
    ang, pad = -math.pi / 2, 0.5
    for i, (fp, ids) in enumerate(rows):
        frac = len(ids) / total
        a0, a1 = ang, ang + frac * 2 * math.pi
        s0, s1 = a0 + pad / 2, a1 - pad / 2
        big = 1 if (s1 - s0) > math.pi else 0
        if s1 <= s0:
            s0, s1, big = a0, a1, 0
        x0, y0 = cx + r_out * math.cos(s0), cy + r_out * math.sin(s0)
        x1, y1 = cx + r_out * math.cos(s1), cy + r_out * math.sin(s1)
        x2, y2 = cx + r_in * math.cos(s1), cy + r_in * math.sin(s1)
        x3, y3 = cx + r_in * math.cos(s0), cy + r_in * math.sin(s0)
        cls = "c-arc c-contr" if len(ids) >= 2 else "c-arc"
        o.append('<path d="M %.1f %.1f A %d %d 0 %d 1 %.1f %.1f L %.1f %.1f '
                 'A %d %d 0 %d 0 %.1f %.1f Z" class="%s"/>'
                 % (x0, y0, r_out, r_out, big, x1, y1, x2, y2, r_in, r_in, big, x3, y3, cls))
        mid = (a0 + a1) / 2
        lx, ly = cx + (r_out + 12) * math.cos(mid), cy + (r_out + 12) * math.sin(mid)
        anchor = "start" if math.cos(mid) >= 0 else "end"
        o.append('<text x="%.1f" y="%.1f" text-anchor="%s" class="c-t">%s %d%%</text>'
                 % (lx, ly + 4, anchor, _svg_esc(fp), int(round(frac * 100))))
        ang = a1
    o.append('<text x="%d" y="%d" text-anchor="middle" class="c-hd">%d 簇</text>' % (cx, cy - 2, len(rows)))
    o.append('<text x="%d" y="%d" text-anchor="middle" class="c-sub">共 %d 臂</text>' % (cx, cy + 16, total))
    lx0 = 316
    o.append('<text x="%d" y="24" class="c-hd">簇 → 成员臂</text>' % lx0)
    for i, (fp, ids) in enumerate(rows):
        y = 46 + 18 * i
        o.append('<text x="%d" y="%d" class="c-lab">%s：%s</text>'
                 % (lx0, y, _svg_esc(fp), _svg_esc(" ".join(ids))))
    o.append('</svg></figure>')
    return "".join(o)


def _svg_group_cluster_heatmap(agg: dict) -> str:
    """图④ 组 × 结论簇 贡献热力图（**无方向**）：行 = arm_group，列 = 去重簇，格 = 簇归属臂数。

    S8（2026-10-06，owner 需求「看 3 组 subagent 分别对最终结论做了什么贡献」）：
      只消费 `clusters[].arm_groups`（簇归属 = **结构量**），不读任何 agent 侧分数锚（双盲纪律）。
      行 = refs 里**实际出现**的组（G1/G2/G3 序；缺失归『—（未落库）』，**禁反推**）；
      列 = `clusters`（规模降序 ⟹ c0 主簇在最左；红列 = `contradiction` 矛盾簇）；
      格 = 该组落在该簇的臂数；填色 `--acc` 按 `count / 全局最大` 线性映射不透明度（零值留空）。
      行合计（= 该组臂数）/ 列合计（= 该簇规模）/ 右下总计（= refs 数）**恒等对账**（可机检）。
    """
    refs = list((agg or {}).get("references") or [])
    clusters = list((agg or {}).get("clusters") or [])
    if not refs or not clusters:
        return ""
    cons = (agg or {}).get("consensus") or {}
    top_id = str(cons.get("top_id", ""))
    rows: list[str] = []
    for r in refs:
        g = str(r.get("arm_group", "") or "").strip() or "—"
        if g not in rows:
            rows.append(g)
    _ord = {"G1": 0, "G2": 1, "G3": 2}
    rows.sort(key=lambda g: (_ord.get(g, 9), g))
    ncol = len(clusters)
    lab_w, cell_w, cell_h, head_h, tot_w = 112, 76, _SVG_ROW, 30, 68
    w = lab_w + cell_w * ncol + tot_w
    h = head_h + cell_h * (len(rows) + 1) + 34
    o = ['<figure class="chart"><figcaption>图④ 组 × 结论簇 贡献热力图'
         '（仅簇归属计数；c0=主簇=多数结论，红列=矛盾簇）</figcaption>',
         '<svg viewBox="0 0 %d %d" width="100%%" role="img">' % (w, h),
         '<text x="4" y="18" class="c-hd">组 \\ 簇</text>',
         '<text x="%d" y="18" text-anchor="middle" class="c-hd">合计</text>'
         % (lab_w + cell_w * ncol + tot_w // 2)]
    for j, c in enumerate(clusters):
        cx = lab_w + cell_w * j + cell_w // 2
        is_top = str(c.get("id", "")) == top_id
        contr = bool(c.get("contradiction"))
        o.append('<text x="%d" y="13" text-anchor="middle" class="%s">%s</text>'
                 % (cx, "c-red" if contr else "c-hd",
                    _svg_esc("%s%s" % (c.get("id", ""), " 主" if is_top else ""))))
        o.append('<text x="%d" y="27" text-anchor="middle" class="c-sub">n=%d</text>'
                 % (cx, int(c.get("size", 0))))
    # 全局最大 = 全部格中的最高臂数（跨簇可比 ⟹「1 票」视觉上弱于「2 票」；D6/D7 口径）
    gmax = max([int(v or 0) for c in clusters
                for v in (c.get("arm_groups") or {}).values()] + [0])
    for i, g in enumerate(rows):
        y = head_h + cell_h * i
        o.append('<text x="4" y="%d" class="c-t">%s</text>'
                 % (y + 16, _svg_esc(arm_group_chip("" if g == "—" else g))))
        rowtot = 0
        for j, c in enumerate(clusters):
            v = int((c.get("arm_groups") or {}).get(g, 0) or 0)
            rowtot += v
            if v <= 0:
                continue
            x = lab_w + cell_w * j
            op = (0.25 + 0.65 * (v / gmax)) if gmax else 0.25
            o.append('<rect x="%d" y="%d" width="%d" height="%d" class="c-heat%s"'
                     ' fill-opacity="%.2f"/>'
                     % (x + 3, y + 3, cell_w - 6, cell_h - 6,
                        " c-contr" if c.get("contradiction") else "", op))
            o.append('<text x="%d" y="%d" text-anchor="middle" class="c-num">%d</text>'
                     % (x + cell_w // 2, y + 16, v))
        o.append('<text x="%d" y="%d" text-anchor="middle" class="c-tot">%d</text>'
                 % (lab_w + cell_w * ncol + tot_w // 2, y + 16, rowtot))
    yt = head_h + cell_h * len(rows)
    o.append('<text x="4" y="%d" class="c-lab">列合计</text>' % (yt + 16))
    for j, c in enumerate(clusters):
        o.append('<text x="%d" y="%d" text-anchor="middle" class="c-tot">%d</text>'
                 % (lab_w + cell_w * j + cell_w // 2, yt + 16, int(c.get("size", 0))))
    o.append('<text x="%d" y="%d" text-anchor="middle" class="c-tot">%d</text>'
             % (lab_w + cell_w * ncol + tot_w // 2, yt + 16, len(refs)))
    # `ECC-BF39D6698097`（C 期 §12.4-3）：色标图例（低→高）—— 与格填色同源（全局最大 `gmax`
    #   归一，与 `_heat_cells` 同一口径），使「深=多票」可被读图者一眼校准。
    _ly = yt + _SVG_ROW + 6
    o.append('<text x="4" y="%d" class="c-scale-t">低</text>' % (_ly + 10))
    o.append('<rect x="26" y="%d" width="30" height="12" class="c-scale-lo"/>' % _ly)
    o.append('<rect x="56" y="%d" width="30" height="12" class="c-scale-hi"/>' % _ly)
    o.append('<text x="92" y="%d" class="c-scale-t">高（格色 = 组臂数 / 全局最大 %d）</text>'
             % (_ly + 10, gmax))
    o.append('</svg></figure>')
    return "".join(o)


# ── S9（2026-10-06）：图表后端 = 内联 Apache ECharts（vendor `assets/echarts.min.js`）──
# 动机（owner）：「手写 SVG 不好看，要饼图 / 散点 / 动态图」。硬约束不变：**自足 / 零外链 / 离线可开**
#   ⟹ 不外链 CDN，改为 vendor 单文件并**全页只内联一次**（禁每图重复内联）。
# 去 Plotly：原 `_trend_block` 用 `include_plotlyjs=True` 内联 ~3.5MB plotly.js ⟹ 单库化（ECharts ~1MB）。
# 降级：vendor 缺失 ⟹ 回退既有手写 SVG（`_svg_*` / `_trend_svg`），页面仍自足可开（见 `test_*_degrade_*`）。
# 双盲纪律不破：所有图形只吃**结构量**（簇归属 / 预算 / 证据条数），不含 agent 侧分数锚。
_ECHARTS_ASSET = Path(__file__).resolve().parent.parent / "assets" / "echarts.min.js"

# 图表初始化脚本（数据经 `__DATA__` 注入；渲染期一次成形，零外部请求）。
_ECHARTS_INIT_JS = r"""
(function(){
  if(!window.echarts){return;}
  var D=__DATA__;
  var PAL=['#268bd2','#6c8a00','#a9761a','#c0392b','#6c71c4','#2aa198'];
  var CS=[];                       /* 已建实例：重建前 dispose；窗口 resize 时统一 resize() */
  function mk(id){
    var e=document.getElementById(id);
    if(!e||!e.clientWidth){return null;}   /* 隐藏容器（视图未切到图表）⟹ 不 init（0 宽错位） */
    var c=echarts.init(e);
    if(c){CS.push(c);}
    return c;}
  /* build 时读 body[data-dark]（2026-10-31 深色主题）；每次重建先 dispose 旧实例（禁叠加）。 */
  function build(){
  var DARK=!!document.body.getAttribute('data-dark');
  var MUT=DARK?'#9aa5ad':'#7d8a8f', FG=DARK?'#dfe6ea':'#3f4a52', LINE=DARK?'#39414a':'#e4dcc4';
  var CARD=DARK?'#14181c':'#fdf6e3';
  var AX={axisLabel:{color:MUT},axisLine:{lineStyle:{color:LINE}},
          splitLine:{lineStyle:{color:LINE}},nameTextStyle:{color:MUT}};
  function bg(){return {backgroundColor:'transparent',textStyle:{color:FG,fontSize:12}};}
  /* `ECC-93F54BA38157`（C 期(ii)）：统一 tooltip / 图例样式 —— 四图共用 ⟹ 观感一致（圆角 + 卡片底）。 */
  var TT={backgroundColor:DARK?'rgba(28,32,36,0.97)':'rgba(255,253,246,0.97)',
          borderColor:LINE,borderRadius:6,
          padding:[6,9],textStyle:{color:FG,fontSize:12}};
  var LG={top:0,left:'center',textStyle:{color:MUT},icon:'roundRect',itemWidth:10,itemHeight:10};
  CS.forEach(function(c){try{c.dispose();}catch(e){}});
  CS=[];
  /* 自动缩放（2026-10-08）：数据驱动 min/max + 8% 边距 —— 预算爆表臂（raw tokens 极大）
     不再把其余点挤到边缘，顶点标签也不越过绘图区（治「超界飞天」）。scale:true 兜底不做 0 强制。
     `isInt`（如「证据条数」）⟹ 取整边界，避免 y 轴出现小数刻度。 */
  function _pad(ns,isInt){
    var a=(ns||[]).filter(function(v){return typeof v==='number'&&isFinite(v);});
    if(!a.length){return {scale:true};}
    var lo=Math.min.apply(null,a), hi=Math.max.apply(null,a), r=hi-lo;
    if(r<=0){r=(Math.abs(hi)||1)*0.2;}
    var p=r*0.08, mn=lo-p, mx=hi+p;
    if(lo>=0&&mn<0){mn=0;}          /* 非负量（tokens / 条数）不引入负轴 */
    if(isInt){mn=Math.floor(mn);mx=Math.ceil(mx);}
    return {min:mn,max:mx,scale:true};
  }

  /* 图② 结论差异聚类 —— 环形饼图（红 = 矛盾簇；中心汇总簇数/臂数） */
  var e2=mk('fig-clusters');
  if(e2){var _n=D.cl.reduce(function(a,x){return a+(x.value||0);},0);
    e2.setOption(Object.assign(bg(),{
    tooltip:Object.assign({},TT,{trigger:'item',formatter:function(p){var d=p.data,g=d.groups||{};
      var gs=Object.keys(g).map(function(k){return k+'×'+g[k];}).join(' ');
      return '<b>'+d.name+'</b> · '+d.value+' 臂<br>组分布 '+gs
        +'<br><span style="color:'+MUT+'">'+(d.members||[]).join(', ')+'</span>';}}),
    graphic:[
      {type:'text',left:'center',top:'43%',silent:true,
       style:{text:D.cl.length+' 簇',fill:FG,fontSize:14,fontWeight:'bold',textAlign:'center'}},
      {type:'text',left:'center',top:'51%',silent:true,
       style:{text:'共 '+_n+' 臂',fill:MUT,fontSize:11,textAlign:'center'}}],
    series:[{type:'pie',radius:['44%','70%'],center:['50%','54%'],
      label:{color:FG,formatter:'{b}  {c} 臂  ({d}%)'},labelLine:{lineStyle:{color:LINE}},
      data:D.cl.map(function(x){var o={name:x.name,value:x.value,groups:x.groups,members:x.members};
        if(x.contr){o.itemStyle={color:'#c0392b'};}return o;}),
      animationDuration:900}]
  }));}

  /* 图③ 身份与状态 —— 散点图（x=总 tokens · y=证据条数 · 点径=证据量 · 色=组） */
  var e3=mk('fig-arms');
  if(e3){
    var byG={};D.pts.forEach(function(p){(byG[p.g]=byG[p.g]||[]).push(p);});
    var keys=Object.keys(byG);
    e3.setOption(Object.assign(bg(),{
      tooltip:Object.assign({},TT,{trigger:'item',formatter:function(pa){var d=pa.data;
        return '<b>'+d.id+'</b><br>组 '+d.g+'<br>预算 '+d.budget+' '+d.v[0]+'/'+(d.bud==null?'—':d.bud)
          +'<br>证据 '+d.v[1]+' 条 · item '+(d.items==null?'—':d.items)
          +'<br>HMAC '+d.hmac+((d.suspect&&d.suspect.length)?'<br>suspect '+d.suspect.join(','):'');}}),
      legend:Object.assign({},LG,{data:keys}),
      grid:{left:66,right:22,top:46,bottom:14,containLabel:true},
      xAxis:Object.assign({type:'value',name:'total_tokens',nameLocation:'middle',nameGap:26},AX,
                          _pad(D.pts.map(function(p){return p.tok;}),false)),
      yAxis:Object.assign({type:'value',name:'证据条数',minInterval:1,
                           nameLocation:'middle',nameGap:34},AX,
                          _pad(D.pts.map(function(p){return p.ev;}),true)),
      series:keys.map(function(g,i){return {name:g,type:'scatter',
        symbolSize:function(v,pa){return 10+2.4*Math.min((pa.data&&pa.data.ev)||0,10);},
        data:byG[g].map(function(p){return {value:[p.tok,p.ev],v:[p.tok,p.ev],ev:p.ev,id:p.id,
          g:p.g,budget:p.budget,bud:p.bud,items:p.items,hmac:p.hmac,suspect:p.suspect};}),
        itemStyle:{color:PAL[i%PAL.length],opacity:0.9},
        label:{show:true,position:'top',color:MUT,fontSize:10,
               formatter:function(pa){return pa.data.id.slice(-5);}},
        animationDuration:900};})
    }));
  }

  /* 图④ 组 × 结论簇 —— 热力图（颜色服务端算好：全局最大归一；红=矛盾簇） */
  var e4=mk('fig-heat');
  if(e4){e4.setOption(Object.assign(bg(),{
    tooltip:Object.assign({},TT,{position:'top',formatter:function(pa){
      return D.h.rows[pa.value[1]]+' × '+D.h.cols[pa.value[0]]+'<br>'+pa.value[2]+' 臂';}}),
    grid:{left:12,right:20,top:34,bottom:28,containLabel:true},
    graphic:[{type:'text',right:6,bottom:2,silent:true,
      style:{text:'低 → 高（格色 = 组臂数 / 全局最大）',fill:MUT,fontSize:10}}],
    xAxis:{type:'category',name:'结论簇',nameLocation:'middle',nameGap:24,data:D.h.cols,
           axisLabel:{color:MUT},axisLine:{lineStyle:{color:LINE}},splitArea:{show:false}},
    yAxis:{type:'category',name:'组',nameLocation:'middle',nameGap:44,data:D.h.rows,
           axisLabel:{color:MUT},axisLine:{lineStyle:{color:LINE}},splitArea:{show:false}},
    series:[{type:'heatmap',data:D.h.cells,
      label:{show:true,color:FG,formatter:function(pa){return pa.value[2]>0?pa.value[2]:'';}},
      itemStyle:{borderColor:CARD,borderWidth:2},animationDuration:900}]
  }));}

  /* 跨轮趋势 —— 折线（入场动画） */
  var e5=mk('fig-trend');
  if(e5&&D.tr.length){e5.setOption(Object.assign(bg(),{
    tooltip:Object.assign({},TT,{trigger:'axis'}),legend:Object.assign({},LG),
    grid:{left:8,right:8,top:44,bottom:12,containLabel:true},
    xAxis:Object.assign({type:'category',boundaryGap:false,
      data:D.tr.map(function(t){return t.x;})},AX),
    yAxis:[Object.assign({type:'value',name:'引用数',nameGap:14},AX,
                         _pad(D.tr.map(function(t){return t.mu;}),true)),
           Object.assign({type:'value',name:'一致度',min:0,max:1,nameGap:14},AX)],
    series:[{name:'引用数 n',type:'line',smooth:true,symbol:'circle',symbolSize:8,
             lineStyle:{width:2},data:D.tr.map(function(t){return t.mu;}),
             areaStyle:{opacity:0.18},animationDuration:1400},
            {name:'一致度 top_weight',type:'line',yAxisIndex:1,smooth:true,symbol:'circle',
             symbolSize:8,lineStyle:{width:2},data:D.tr.map(function(t){return t.w;}),
             animationDuration:1400}]
  }));}

  }  /* end build() */

  /* 窗口 resize / 浏览器缩放 ⟹ 逐个 resize()，防画布按初始像素宽溢出卡片（观感错位根因）。
     注册在 build 外（只一次；禁随重建叠加）。 */
  window.addEventListener('resize',function(){
    CS.forEach(function(c){try{c.resize();}catch(e){}});});

  /* 视图切到「图表」/ 深色切换 ⟹ 重建（隐藏容器 init ⟹ 0 宽错位；深色须重读主题色）。 */
  window.__gkChartsRebuild=function(){
    var h=document.getElementById('fig-clusters')||document.getElementById('fig-arms')
          ||document.getElementById('fig-heat')||document.getElementById('fig-trend');
    if(!h||!h.clientWidth){return;}   /* 仍隐藏 ⟹ 留待切入再建（禁 0 宽 init） */
    build();};
  /* 首屏默认 prose 视图（图表隐藏）⟹ 不建；若 DOM 已可见（如默认改图表）则即建。 */
  var _h0=document.getElementById('fig-clusters')||document.getElementById('fig-arms')
          ||document.getElementById('fig-heat')||document.getElementById('fig-trend');
  if(_h0&&_h0.clientWidth){build();}
})();
"""


@functools.lru_cache(maxsize=1)
def _echarts_js() -> str:
    """读 vendor 的 `assets/echarts.min.js`（静态资产，非 state）；缺失 ⟹ 空串（触发 SVG 降级）。"""
    try:
        return _ECHARTS_ASSET.read_text(encoding="utf-8")
    except OSError:
        return ""


def _json_embed(obj) -> str:
    """JSON 内嵌进 `<script>` 的安全化（`</` 转义，禁提前闭合脚本块）。"""
    return json.dumps(obj, ensure_ascii=False).replace("</", "<\\/")


def _attribution_rows(refs: list[dict]) -> list[str]:
    """热力图行序：**实际出现**的 arm_group（G1/G2/G3 序，缺省末位；禁反推未出现的组）。"""
    rows: list[str] = []
    for r in refs:
        g = str(r.get("arm_group", "") or "").strip() or "—"
        if g not in rows:
            rows.append(g)
    _ord = {"G1": 0, "G2": 1, "G3": 2}
    return sorted(rows, key=lambda g: (_ord.get(g, 9), g))


def _heat_cells(refs: list[dict], clusters: list[dict]) -> tuple[list, list]:
    """热力矩阵：返回 `(行键, cells)`（列标签由调用方按 `consensus.top_id` 补「主」标）。

    颜色**服务端算好**（D7：`count / 全局最大` 线性映射不透明度；矛盾簇用 `--bad` 红），
    使归一化规则可被单测断言（不依赖浏览器 JS）。
    """
    rows = _attribution_rows(refs)
    gmax = max([int(v or 0) for c in clusters
                for v in (c.get("arm_groups") or {}).values()] + [0])
    cells = []
    for j, c in enumerate(clusters):
        ag = c.get("arm_groups") or {}
        base = "248,81,73" if c.get("contradiction") else "56,139,253"
        for i, g in enumerate(rows):
            v = int(ag.get(g, 0) or 0)
            if v > 0:
                op = (0.25 + 0.65 * (v / gmax)) if gmax else 0.25
                col = "rgba(%s,%.2f)" % (base, op)
            else:
                col = "rgba(42,47,54,0.35)"
            cells.append({"value": [j, i, v], "itemStyle": {"color": col}})
    return rows, cells


def _charts_block(refs: list[dict], trace: dict, agg: dict, trend: list | None) -> str:
    """四个图形（图②环形 / 图③散点 / 图④热力 / 趋势折线）——ECharts 主路，SVG 降级。"""
    import html as _h
    esc = _h.escape
    js = _echarts_js()
    clusters = list((agg or {}).get("clusters") or [])
    if not js:                      # 降级：vendor 缺失 ⟹ 手写 SVG（仍自足离线）
        return (_svg_divergence_clusters(refs, trace) + _svg_identity_states(refs, trace)
                + _svg_group_cluster_heatmap(agg) + _trend_block(trend))
    cons = (agg or {}).get("consensus") or {}
    data = {
        "cl": [{"name": str(c.get("id", "")), "value": int(c.get("size", 0)),
                "contr": bool(c.get("contradiction")),
                "groups": {str(k): int(v) for k, v in (c.get("arm_groups") or {}).items()},
                "members": [str(x) for x in (c.get("members") or [])]} for c in clusters],
        "pts": [{"id": str(r.get("subagent_id", "")), "g": arm_group_chip(r.get("arm_group")),
                 "tok": int(r.get("total_tokens") or 0), "bud": r.get("token_budget"),
                 "ev": len(r.get("evidence") or []), "items": r.get("total_items"),
                 "hmac": str(r.get("hmac_status", "")),
                 "budget": str(r.get("budget_status", "") or "—"),
                 "suspect": list(r.get("suspect") or [])} for r in refs],
        "tr": [{"x": str(t.get("round", "")), "mu": t.get("mu"), "w": t.get("top_weight")}
               for t in (trend or [])],
    }
    o = ['<figure class="chart"><figcaption><b>图② 结论差异聚类</b>（环形图：各簇占比 · '
         '红=矛盾簇；悬停看成员）</figcaption>'
         '<div id="fig-clusters" class="echart" style="height:260px"></div></figure>',
         '<figure class="chart"><figcaption><b>图③ 身份与状态</b>（散点：x=total_tokens · '
         'y=证据条数 · 点径=证据量 · 色=组；悬停看明细）</figcaption>'
         '<div id="fig-arms" class="echart" style="height:320px"></div></figure>']
    if clusters:
        rows, cells = _heat_cells(refs, clusters)
        cols = [str(c.get("id", "")) + (" 主" if str(c.get("id", "")) == str(cons.get("top_id", ""))
                                        else "") for c in clusters]
        data["h"] = {"cols": cols,
                     "rows": [_short_id(arm_group_chip("" if g == "—" else g), 22) for g in rows],
                     "cells": cells}
        _rtot = ["%s=%d" % (arm_group_chip("" if g == "—" else g),
                            sum(int((c.get("arm_groups") or {}).get(g, 0) or 0) for c in clusters))
                 for g in rows]
        _ctot = ["%s=%d" % (c.get("id", ""), int(c.get("size", 0))) for c in clusters]
        o.append('<figure class="chart"><figcaption><b>图④ 组 × 结论簇 贡献热力图</b>'
                 '（仅簇归属计数；红=矛盾簇）</figcaption>'
                 '<div id="fig-heat" class="echart" style="height:%dpx"></div>'
                 '<div class="meta">行合计（组臂数）%s · 列合计（簇规模）%s · 总计 %d（= refs 数）</div>'
                 '</figure>'
                 % (70 + 34 * max(len(rows), 1),
                    esc(" / ".join(_rtot)), esc(" / ".join(_ctot)), len(refs)))
    if trend:
        o.append('<figure class="chart"><figcaption><b>跨轮趋势</b>（引用数 / 一致度；'
                 '源 = moa-agg / noconv finding）</figcaption>'
                 '<div id="fig-trend" class="echart" style="height:300px"></div></figure>')
    o.append('<script>' + js + '</script>')
    o.append('<script>' + _ECHARTS_INIT_JS.replace("__DATA__", _json_embed(data)) + '</script>')
    return "".join(o)


def _html_run_status(refs: list[dict]) -> str:
    """S3（2026-10-06）：subagent 运行态面板。

    消费此前**从未上页**的 `machine_check` / `access_violations` / `budget_*`。
    **「是否启动」在 history 中无字段**（仅旁挂 run-file）⟹ 如实标「未知」，不伪造（缺失 ≠ 失败）。
    """
    import html as _h
    esc = _h.escape
    o = ['<h3 data-i18n="h-runstatus">subagent 运行态</h3><div class="card">'
         '<div class="meta">是否启动 = **未知**（落库条目无启动字段，仅旁挂 run-file）⟹ 缺失 ≠ 失败；'
         '预算态 / 读信息机制缺陷取自 machine_check / access_violations（UNKNOWN ≠ 否定）。</div>',
         '<table><tr><th>subagent</th><th>启动</th><th>预算态</th><th>读信息 / 机制</th>'
         '<th>suspect</th></tr>']
    for r in refs:
        mc = r.get("machine_check") or {}
        bs = str(r.get("budget_status", "") or "") or "—"
        tt, tb = r.get("total_tokens", 0), r.get("token_budget")
        exh = (bs in _BUDGET_BAD
               or (isinstance(tb, (int, float)) and isinstance(tt, (int, float)) and tb and tt > tb))
        avs = r.get("access_violations") or []

        def _st(v):
            if isinstance(v, dict):
                return str(v.get("status") or v.get("verdict") or "")
            return str(v or "")
        ver, anch = _st(mc.get("verification")), _st(mc.get("evidence_anchor"))
        o.append('<tr><td><code>' + esc(str(r.get("subagent_id", ""))) + '</code></td>'
                 '<td>未知（history 无启动字段）</td><td>'
                 + esc("%s %s/%s%s" % (bs, tt, tb if tb is not None else "—",
                                       " · 已截断" if exh else ""))
                 + '</td><td>' + esc("verification=%s · 证据锚=%s · 越权读 %d"
                                     % (ver or "—", anch or "—", len(avs)))
                 + '</td><td>' + esc(",".join(r.get("suspect") or []) or "—") + '</td></tr>')
    o.append('</table></div>')
    return "".join(o)


def _html_agg_detail(agg: dict) -> str:
    """S3：聚合详情（去重簇 / 一致度 / 三组分布 / 矛盾 / 弃权）。"""
    import html as _h
    esc = _h.escape
    cons = (agg or {}).get("consensus") or {}
    clusters = (agg or {}).get("clusters") or []
    if not clusters:
        return ""
    o = ['<h3 data-i18n="h-agg">聚合详情（去重簇 / 一致度 / 三组）</h3>'
         '<div class="card"><div class="chips">'
         '<span class="chip">簇 ' + str(cons.get("n_clusters", 0)) + '</span>'
         + '<span class="chip">最大簇权重 ' + str(cons.get("top_weight", 0)) + '</span>'
         + '<span class="chip">一致度 ' + str(cons.get("agreement", cons.get("top_weight", 0))) + '</span>'
         + '<span class="chip">G2 覆盖 ' + str(cons.get("coverage_g2", 0)) + '</span>'
         + '<span class="chip' + (' warn' if cons.get("contradictions") else '') + '">矛盾 '
         + str(len(cons.get("contradictions") or [])) + '</span>'
         + '<span class="chip' + (' bad' if cons.get("abstain") else '') + '">'
         + ('弃权（一致度不足）' if cons.get("abstain") else '过一致度阈') + '</span></div>',
         '<table><tr><th>簇</th><th>n</th><th>权重</th><th>签名源</th><th>组分布</th>'
         '<th>成员</th><th>代表</th></tr>']
    for c in clusters:
        grp = " ".join("%s×%d" % (g, k) for g, k in (c.get("arm_groups") or {}).items())
        o.append('<tr' + (' class="rowwarn"' if c.get("contradiction") else '') + '><td>'
                 + esc(str(c.get("id"))) + '</td><td>' + str(c.get("size"))
                 + '</td><td>' + str(c.get("weight")) + '</td><td>'
                 + esc(str(c.get("signature_source", ""))) + '</td><td>' + esc(grp)
                 + '</td><td><code>' + esc(",".join(str(m) for m in (c.get("members") or [])))
                 + '</code></td><td><code>' + esc(str(c.get("representative_id")))
                 + '</code></td></tr>')
    o.append('</table>')
    vc = cons.get("verdict_consensus") or {}
    o.append('<div class="meta">逐失败模式判定分布（批内一致度；S1-2）</div>'
             '<table><tr><th>码 · 失败模式</th><th>分布</th><th>多数</th><th>一致</th></tr>')
    for code, label in _F17:
        d = vc.get(code) or {}
        cnt = d.get("counts") or {}
        dist = " ".join("%s×%d" % (k, v) for k, v in cnt.items()) if cnt else "—"
        maj = str(d.get("majority") or "—")
        una = ("✓" if d.get("unanimous") else "✗") if cnt else "—"
        o.append('<tr><td>' + esc(code) + ' · ' + esc(label) + '</td><td>' + esc(dist)
                 + '</td><td>' + esc(maj) + '</td><td>' + una + '</td></tr>')
    o.append('</table>')
    o.append('</div>')
    return "".join(o)


def dialectic(agg: dict) -> dict:
    """② 辩证论证（确定性、零 LLM）：由**三组语义 + 结论簇**推出 正题/反题/污染/合题。

    - 正题（G1 相同对）= **主簇**（规模最大）的代表文本 —— 多数组的一致结论。
    - 反题（G2 正交互补）= **次簇**（次大）的代表文本 —— 与正题并存的实质分歧；无次簇 ⟹ 无分歧。
    - 污染（G3）= 污染组臂落在**非主簇**（含矛盾簇）⟹ 命中；全落主簇 ⟹ 未改变主结论。
    - 合题（转化条件）= 一致度 `top_weight` 与阈值 `min_agreement` 比较 ⟹ 收敛 / 弃权（P7）。
    """
    refs = list((agg or {}).get("references") or [])
    cons = (agg or {}).get("consensus") or {}
    clusters = sorted(list((agg or {}).get("clusters") or []),
                      key=lambda c: -int(c.get("size", 0) or 0))
    top = clusters[0] if clusters else None
    anti = clusters[1] if len(clusters) > 1 else None
    top_members = set(str(x) for x in (top.get("members") or [])) if top else set()
    g3 = [r for r in refs if str(r.get("arm_group", "") or "").strip() == "G3"]
    g3_out = [r for r in g3 if str(r.get("subagent_id", "")) not in top_members]
    return {
        "thesis": top,
        "antithesis": anti,
        "g3": {"n": len(g3), "n_out": len(g3_out),
               "ids_out": [str(r.get("subagent_id", "")) for r in g3_out]},
        "contradiction_ids": [str(c.get("id")) for c in clusters if c.get("contradiction")],
        "resolution": {"weight": float(cons.get("top_weight", 0.0) or 0.0),
                       # 判定权威 = consensus.abstain；其判据量 = agreement（有 verdicts 时为
                       # 逐 F 多数占比均值，**非** top_weight）⟹ 渲染须用同一量，否则出现
                       # 「0.50 ≥ 0.67」式自相矛盾。
                       "agreement": float(cons.get("agreement", cons.get("top_weight", 0.0)) or 0.0),
                       "threshold": float(cons.get("min_agreement", 0.0) or 0.0),
                       "abstain": bool(cons.get("abstain"))},
    }


def _html_dialectic(agg: dict) -> str:
    """② 辩证论证段（正题 / 反题 / 污染 / 合题）。结论文本经 `_blind_conclusion` 遮蔽分数锚。"""
    import html as _h
    esc = _h.escape
    d = dialectic(agg)
    top, anti = d["thesis"], d["antithesis"]
    if not top:
        return ""

    def _grp(c):
        return " ".join("%s×%d" % (k, v) for k, v in (c.get("arm_groups") or {}).items())

    def _rep(c):
        return esc(_blind_conclusion(" ".join(str(c.get("representative_text", "")).split())[:400]))

    o = ['<h3 id="sec-dialectic" data-i18n="h-dialectic">辩证论证（正题 / 反题 / 污染 / 合题）</h3>'
         '<div class="card" id="dialectic-card">',
         '<div><b>正题（G1 相同对 · 主簇 %s）</b>：%s</div>'
         '<div class="meta">支持 %d 臂 · 权重 %.2f · 组分布 %s</div>'
         % (esc(str(top.get("id"))), _rep(top), int(top.get("size", 0) or 0),
            float(top.get("weight", 0.0) or 0.0), esc(_grp(top)))]
    if anti:
        o.append('<div style="margin-top:8px"><b>反题（G2 正交互补 · 分歧簇 %s）</b>：%s</div>'
                 '<div class="meta">%d 臂 · 权重 %.2f · 组分布 %s</div>'
                 % (esc(str(anti.get("id"))), _rep(anti), int(anti.get("size", 0) or 0),
                    float(anti.get("weight", 0.0) or 0.0), esc(_grp(anti))))
    else:
        o.append('<div style="margin-top:8px"><b>反题（G2 正交互补）</b>：无 —— '
                 '全体归入同一结论簇，无实质分歧。</div>')
    g3 = d["g3"]
    if not g3["n"]:
        o.append('<div style="margin-top:8px"><b>污染（G3）</b>：本批无污染组臂。</div>')
    elif g3["n_out"]:
        o.append('<div style="margin-top:8px"><b>污染（G3）</b>：%d 臂为污染组，其中 %d 臂落在'
                 '<b>非主簇</b>（%s）⟹ 污染命中，须隔离后再论主结论。</div>'
                 % (g3["n"], g3["n_out"], esc(", ".join(g3["ids_out"]))))
    else:
        o.append('<div style="margin-top:8px"><b>污染（G3）</b>：%d 臂为污染组，全部落入主簇 '
                 '⟹ 污染<b>未改变</b>主结论。</div>' % g3["n"])
    if d["contradiction_ids"]:
        o.append('<div class="meta">矛盾簇：%s</div>'
                 % esc(", ".join(d["contradiction_ids"])))
    r = d["resolution"]
    _w = ('（最大簇权重 %.2f）' % r["weight"]) if abs(r["weight"] - r["agreement"]) > 1e-9 else ""
    if r["abstain"]:
        o.append('<div style="margin-top:8px"><b>合题（转化条件）</b>：批内一致度 %.2f &lt; 阈值 %.2f '
                 '%s ⟹ <b>弃权</b>：不得按任一单一结论推进，须人工裁决。</div>'
                 % (r["agreement"], r["threshold"], _w))
    else:
        o.append('<div style="margin-top:8px"><b>合题（转化条件）</b>：批内一致度 %.2f ≥ 阈值 %.2f '
                 '%s ⟹ <b>收敛</b>：按正题执行，反题与污染转为观察项。</div>'
                 % (r["agreement"], r["threshold"], _w))
    o.append('</div>')
    return "".join(o)


def _html_finding_detail(agg: dict) -> str:
    """S3：ecc-finding 详情（分类 + 优化项 + 详情文本）。"""
    import html as _h
    esc = _h.escape
    a = assess_findings(agg)
    cls = a["classification"]
    color = {"plan-error": "warn", "infra-defect": "bad"}.get(cls, "")
    o = ['<h3 data-i18n="h-finding">ecc-finding 详情</h3><div class="card"><div class="chips">'
         '<span class="chip ' + color + '">分类 ' + esc(cls) + '</span>'
         + '<span class="chip">优化项 ' + str(len(a["optimization_items"])) + '</span></div>']
    if a["optimization_items"]:
        o.append('<div class="meta">' + esc(_CARRIER_LEGEND) + '</div>'
                 '<table><tr><th>载体</th><th>类别</th><th>动作</th><th>证据</th></tr>')
        for it in a["optimization_items"]:
            _lb = _CARRIER_LABEL.get(str(it["carrier"]), "")
            o.append('<tr><td><code>' + esc(it["carrier"]) + '</code>'
                     + (esc("（" + _lb + "）") if _lb else "")
                     + '</td><td>'
                     + esc(_CARRIER_CLASS[it["carrier"]]) + '</td><td>' + esc(it["action"])
                     + '</td><td>' + esc(it["evidence"]) + '</td></tr>')
        o.append('</table>')
    o.append('<details open><summary>详情文本</summary><pre>'
             + esc(_blind_conclusion(a["detail_text"])) + '</pre></details></div>')
    return "".join(o)


def _trend_block(trend: list[dict]) -> str:
    """降级路径专用：跨轮趋势图（**内联 SVG**，零依赖）。

    S9（2026-10-06）：主路径已改 ECharts（见 `_charts_block`）；本函数仅在 vendor
    `assets/echarts.min.js` 缺失时兜底，保「自足 / 离线可开」不破。
    """
    if not trend:
        return ""
    return ('<figure class="chart"><figcaption>跨轮趋势（引用数 / 一致度；源 = moa-agg / noconv finding）'
            ' —— ECharts 资产缺失 ⟹ 已降级为内联 SVG</figcaption>'
            + _trend_svg(trend) + '</figure>')


def _trend_svg(trend: list[dict]) -> str:
    """降级图：内联 SVG **双序列**折线（引用数 + 一致度），带轴/刻度/图例（零依赖、离线可开）。

    `ECC-BF39D6698097`（C 期 §12.4-3）：原为单条裸折线 ⟹ 补齐左轴（引用数 n）+ 右轴（一致度
    top_weight，0–1）+ 轮次刻度 + 网格 + 图例。跨轮**分数差异即趋势**（同一序列内的逐轮变化）。
    """
    w, h = 720, 260
    ml, mr, mt, mb = 52, 30, 26, 40
    pw, ph = w - ml - mr, h - mt - mb
    mus = [float(t.get("mu") or 0) for t in trend]
    mx = max(mus) if mus else 1.0
    n = max(len(trend) - 1, 1)
    o = ['<svg viewBox="0 0 %d %d" width="100%%" role="img">' % (w, h)]
    for k in range(5):
        gy = mt + int(ph * k / 4)
        o.append('<line x1="%d" y1="%d" x2="%d" y2="%d" class="c-grid"/>' % (ml, gy, ml + pw, gy))
        o.append('<text x="%d" y="%d" text-anchor="end" class="c-sub">%d</text>'
                 % (ml - 6, gy + 4, int(round(mx * (4 - k) / 4.0))))
        o.append('<text x="%d" y="%d" class="c-sub">%.2f</text>'
                 % (ml + pw + 6, gy + 4, (4 - k) / 4.0))
    o.append('<line x1="%d" y1="%d" x2="%d" y2="%d" class="c-ax"/>' % (ml, mt, ml, mt + ph))
    o.append('<line x1="%d" y1="%d" x2="%d" y2="%d" class="c-ax"/>' % (ml, mt + ph, ml + pw, mt + ph))
    p_mu, p_w = [], []
    for i, t in enumerate(trend):
        x = ml + int(pw * i / n)
        y1 = mt + ph - int(ph * (float(t.get("mu") or 0) / (mx or 1.0)))
        y2 = mt + ph - int(ph * max(0.0, min(1.0, float(t.get("top_weight") or 0))))
        p_mu.append("%d,%d" % (x, y1))
        p_w.append("%d,%d" % (x, y2))
        o.append('<text x="%d" y="%d" text-anchor="middle" class="c-sub">%s</text>'
                 % (x, h - 12, _svg_esc(str(t.get("round", "")))))
    o.append('<polyline class="c-solid" points="%s"/>' % " ".join(p_mu))
    o.append('<polyline class="c-dash" points="%s"/>' % " ".join(p_w))
    for pt in p_mu:
        cx, cy = pt.split(",")
        o.append('<circle cx="%s" cy="%s" r="3" class="c-pt c-g1"/>' % (cx, cy))
    for pt in p_w:
        cx, cy = pt.split(",")
        o.append('<circle cx="%s" cy="%s" r="3" class="c-ptw"/>' % (cx, cy))
    o.append('<text x="%d" y="18" class="c-lab">引用数 n（实线，左轴） / '
             '一致度 top_weight（虚线，右轴 0–1）</text>' % ml)
    o.append('</svg>')
    return "".join(o)


# ── ② 术语 tooltip 单源词典（2026-10-31 观感升级）────────────────────────────
# banner / KPI 带里的 jargon 就地可懂；释义**只讲本页语义**，不泄 agent 侧分数锚。
_ABBR_ZH = {
    "divergence": "偏离度：人评分与 agent 自评分之差（CLI adjudicate 事后计算，本页不渲染）",
    "HUMAN_OVERSCORE": "人评分高于 agent 自评（over-score）",
    "HUMAN_UNDERSCORE": "人评分低于 agent 自评（under-score）",
    "adjudicate": "终审：CLI 按换算后分数与散文结论落 verdicts/concessions JSON（三步链第三步）",
    "suspect": "可疑臂：HMAC / 归属校验未过的引用（不参与共识）",
    "MoA": "Mixture-of-Agents：多臂聚合（引用互评 → 结论簇 → 批级共识）",
    "KPI": "关键读数带：臂数 / 一致度 / 判定 / 趋势方向（3 秒抓重点）",
}


def _abbr(term: str) -> str:
    """术语就地 tooltip（单源 helper）：词典命中 ⟹ `<abbr title="中文释义">term</abbr>`；
    未收录 ⟹ 原样返回（禁散写字符串 —— 释义只在 `_ABBR_ZH` 维护）。"""
    import html as _h
    zh = _ABBR_ZH.get(term)
    if not zh:
        return term
    return '<abbr title="%s">%s</abbr>' % (_h.escape(zh, quote=True), term)


def _kpi_band(agg: dict, refs: list, trend: list | None) -> str:
    """① 顶部 KPI 带（2026-10-31 观感升级，owner 裁定「是的就这么搞」）：
    新用户 3 秒抓重点。**值全部取自 agg/trend（禁猜）**：
      · refs 模式 —— 臂数=references 长、一致度=consensus.agreement（缺省 top_weight 兜底）、
        判定=abstain⟹弃权、趋势方向=trend 末轮−首轮 top_weight（↓/→/↑）、suspect 计数；
      · accept 模式（`mode=moa_accept`）—— 裁决 / worktrees / 新增失败 / 修复。
    双盲：不读不渲任何 agent 侧分数锚（`test_kpi_band_double_blind` 钉首屏）。
    """
    cells: list[tuple[str, str, str]] = []          # (label, value, css-class)
    if agg.get("mode") == "moa_accept":
        g = (agg.get("accept") or {}).get("global") or {}
        vc = {"pass": "ok", "fail": "bad"}.get(str(g.get("verdict")), "warn")
        cells.append(("裁决", str(g.get("verdict", "unknown")), vc))
        cells.append(("worktrees", str(len(g.get("worktrees") or [])), ""))
        nf = g.get("new_failures") or []
        cells.append(("新增失败", str(len(nf)), "bad" if nf else "ok"))
        cells.append(("修复", str(len(g.get("fixed") or [])), "ok"))
    else:
        cons = agg.get("consensus") or {}
        cells.append(("臂数", str(len(refs)), ""))
        if cons.get("n_clusters") is not None:
            cells.append(("簇", str(cons.get("n_clusters")), ""))
        agr = cons.get("agreement")
        if agr is None:
            agr = cons.get("top_weight")            # 旧账无 agreement ⟹ 兜底（不猜新值）
        if agr is not None:
            cells.append(("一致度", str(agr),
                          "bad" if cons.get("abstain") else "ok"))
        cells.append(("判定", "弃权" if cons.get("abstain") else "收敛",
                      "bad" if cons.get("abstain") else "ok"))
        tr = [t for t in (trend or [])
              if isinstance(t, dict) and isinstance(t.get("top_weight"), (int, float))]
        if len(tr) >= 2:
            d = tr[-1]["top_weight"] - tr[0]["top_weight"]
            arrow = "↓" if d < -1e-9 else ("↑" if d > 1e-9 else "→")
            cells.append(("趋势",
                          "%s %s→%s" % (arrow, tr[0].get("round", "?"), tr[-1].get("round", "?")),
                          "bad" if d < -1e-9 else ("ok" if d > 1e-9 else "")))
        else:
            cells.append(("趋势", "—", ""))
        sus = (agg.get("trace") or {}).get("suspect_count") or 0
        cells.append(("suspect", str(sus), "bad" if sus else "ok"))
    out = ['<div id="kpi-band" class="kpi">']
    for lab, val, cls in cells:
        out.append('<div class="k%s"><span>%s</span><b>%s</b></div>'
                   % ((" " + cls) if cls else "", lab, val))
    out.append("</div>")
    return "".join(out)


def _html_batch_block(agg: dict) -> str:
    """批分节卡（OSS 前置计划 §3 G1，2026-10-26）：跨批门 banner + 逐批读数 + 归属标签。

    病象：混批缺省时 `render_html` 直接显示**最大批**的簇/一致度，页面无任何标签 ⟹ 人评者
    会读成全体共识（假读数）。数据源**只**吃 `agg["batch_sections"]` / `trace.batch`
    （禁从 refs 重算 = 禁第二实现）；单批 / 无批 ⟹ 只在有 `error` 时出 banner。
    """
    import html as _h
    esc = _h.escape
    o = []
    if agg.get("error"):
        o.append('<div class="banner"><b>聚合错误</b> <code>' + esc(str(agg["error"])) + '</code>'
                 + ('<div class="meta">' + esc(str(agg.get("hint") or "")) + '</div>'
                    if agg.get("hint") else "")
                 + '</div>')
    secs = agg.get("batch_sections") or []
    bt = ((agg.get("trace") or {}).get("batch") or {})
    if not secs and not bt.get("mixed_batches"):
        return "".join(o)
    _allowed = bool(bt.get("cross_batch_allowed"))
    o.append('<h3>批分节（跨轮可比载体 · 逐批读数）</h3><div class="card"><div class="chips">'
             + '<span class="chip">mode ' + esc(str(bt.get("mode", "?"))) + '</span>'
             + '<span class="chip">批数 ' + str(len(bt.get("batches") or [])) + '</span>'
             + '<span class="chip' + (' warn' if _allowed else '') + '">跨批放开 '
             + str(_allowed) + '</span>')
    if not _allowed and bt.get("batches"):
        # 顶层 consensus 已按门替换为**最大批**之节 ⟹ 页面必须显式标注归属，禁冒充全体
        o.append('<span class="chip bad">本页共识 = 最大批 '
                 + esc(str(bt["batches"][0].get("batch_id") or "unbatched")) + '</span>')
    o.append('</div>')
    if secs:
        o.append('<table><tr><th>批</th><th>臂数</th><th>权重</th><th>簇</th>'
                 '<th>一致度</th><th>弃权</th></tr>')
        for s in secs:
            c = s.get("consensus") or {}
            o.append('<tr><td><code>' + esc(str(s.get("batch_id") or "unbatched")) + '</code></td><td>'
                     + str(s.get("n_refs")) + '</td><td>' + str(s.get("weight")) + '</td><td>'
                     + str(c.get("n_clusters", 0)) + '</td><td>'
                     + esc(str(c.get("agreement", c.get("top_weight", "")))) + '</td><td>'
                     + ('是' if c.get("abstain") else '否') + '</td></tr>')
        o.append('</table>')
    o.append('</div>')
    return "".join(o)


def render_html(agg: dict, meta: dict | None = None, trend: list | None = None) -> str:
    """MoA 聚合结果 → 自足 HTML 人工裁定页（见本节头注三约束）。**纯函数**：不读不写 state。"""
    import html as _h
    esc = _h.escape
    meta = dict(meta or {})
    is_accept = agg.get("mode") == "moa_accept"
    acc = agg.get("accept") or {}
    rep = agg.get("report") or {}
    refs = agg.get("references") or []
    trace = agg.get("trace") or {}
    if not refs and isinstance(rep.get("references"), list):
        refs = rep["references"]
        if not trace:
            trace = rep.get("trace") or {}
    key = str((trace.get("attribution") or {}).get("anchor") or agg.get("mode") or "agg")[:24]

    o = ['<!DOCTYPE html>', '<html lang="zh-CN"><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width,initial-scale=1">',
         '<title>MoA 人工裁定页（散文结论 · 双盲）</title>', '<style>' + _CSS + '</style>',
         '</head>', '<body data-key="' + esc(key, quote=True) + '" data-view="prose">',
         '<div class="wrap">',
         '<h1>MoA 人工裁定页</h1>',
         '<div class="meta">模式 <code>' + esc(str(agg.get("mode", ""))) + '</code>'
         + (' · 目标 <code>' + esc(str(meta.get("target", ""))) + '</code>' if meta.get("target") else "")
         + ' · 生成 ' + esc(str(meta.get("generated_at", ""))) + '</div>',
         '<div class="banner"><b>双盲纪律</b>：本页<b>不含</b> agent 侧分数锚 —— 请先独立打分再提交。'
         + _abbr("divergence") + ' 与 ' + _abbr("HUMAN_OVERSCORE") + ' / ' + _abbr("HUMAN_UNDERSCORE")
         + ' 由 CLI 侧 <code>' + _abbr("adjudicate") + '</code> 事后计算。'
         '本页纯只读：不写 state，出口只有「导出散文 <code>prose.txt</code> + 复制三步命令链」。</div>',
         _kpi_band(agg, refs, trend),
         '<div class="nav"><a href="#sec-mat" data-i18n="nav-mat">一 · 聚合材料</a>'
         '<a href="#sec-sum" data-i18n="nav-sum">本批实质汇总</a>'
         '<a href="#sec-prose" data-i18n="nav-prose">二 · 人工结论</a>'
         '<a href="#sec-out" data-i18n="nav-out">三 · 出口</a>'
         '<span class="nav-gap"></span>'
         '<button class="ghost" id="dark" type="button">☾ 深色</button>'
         '<button class="ghost" id="lang">EN</button>'
         '<button class="ghost" id="exp-all" data-i18n="exp-all">全展开</button>'
         '<button class="ghost" id="col-all" data-i18n="col-all">全折叠</button></div>']
    # ③ 三视图分段（2026-10-31 观感升级）：材料 / 图表 / 裁定，默认停在裁定（owner 裁定）。
    #    内容恒在 DOM（隐藏只靠 CSS）⟹ 锚点 / grep / 检索不失效。
    o.append('<div class="tabs" role="tablist" aria-label="视图切换">'
             '<button type="button" class="ghost" id="tab-mat" data-view="mat"'
             ' aria-selected="false" data-i18n="tab-mat">材料</button>'
             '<button type="button" class="ghost" id="tab-chart" data-view="chart"'
             ' aria-selected="false" data-i18n="tab-chart">图表</button>'
             '<button type="button" class="ghost" id="tab-prose" data-view="prose"'
             ' aria-selected="true" data-i18n="tab-prose">裁定</button>'
             '</div>')
    # OSS 前置计划 §3 G1（2026-10-26）：跨批门 banner + 批分节卡（缺此 ⟹ 混批页静默显示最大批读数）。
    # 安全面 ⟹ 留在视图容器**外**（任何视图下都可见，禁随 tab 隐藏）。
    o.append(_html_batch_block(agg))
    # 三视图容器（2026-10-31）：vw-mat 前段 —— 与 vw-chart/vw-prose **兄弟**排布
    #   （嵌套进父容器 ⟹ 父 hidden 时子必 hidden，图表视图将空白）。材料被图表切成
    #   两段 vw-mat 是刻意取舍：既有臂钉死「图④/本批汇总须在 ref details 之前」，
    #   图表整体后移会破坏该序 ⟹ 只能中插；mat 视图下 chart 段隐藏 ⟹ 两段视觉连续。
    o.append('<div class="vw vw-mat">')

    # ── 一、材料面（人工判断的依据）──
    if is_accept:
        g = acc.get("global") or {}
        per = acc.get("per_worktree") or []
        vc = {"pass": "ok", "fail": "bad"}.get(str(g.get("verdict")), "warn")
        o += ['<h2 id="sec-mat"><span data-i18n="h-mat-accept">一、聚合材料</span>'
              ' · 验收聚合（MoA accept）</h2>',
              '<div class="card"><div>全局裁决 <span class="big">'
              + esc(str(g.get("verdict", "unknown"))) + '</span> '
              + '<span class="chip ' + vc + '">' + esc(str(g.get("reason", ""))) + '</span></div>',
              '<div class="chips"><span class="chip">worktrees ' + str(len(g.get("worktrees") or [])) + '</span>'
              + '<span class="chip ' + ('bad' if g.get("new_failures") else 'ok') + '">新增失败 '
              + str(len(g.get("new_failures") or [])) + '</span>'
              + '<span class="chip ok">修复 ' + str(len(g.get("fixed") or [])) + '</span></div>',
              '<table><tr><th>worktree</th><th>rc</th><th>verdict</th><th>新增失败</th><th>说明</th></tr>']
        for r in per:
            o.append('<tr><td><code>' + esc(str(r.get("worktree", ""))) + '</code></td><td>'
                     + esc(str(r.get("rc"))) + '</td><td>' + esc(str(r.get("verdict", ""))) + '</td><td>'
                     + esc(", ".join(r.get("new_failures") or []) or "—") + '</td><td>'
                     + esc(str(r.get("summary") or r.get("error") or "—")) + '</td></tr>')
        o += ['</table></div>']
    if refs:
        at = trace.get("attribution") or {}
        o += ['<h2 id="sec-mat"><span data-i18n="h-mat-refs">一、聚合材料</span>'
              ' · 报告聚合（' + str(len(refs)) + ' references）</h2>',
              '<div class="card"><div class="chips">'
              + '<span class="chip">suspect ' + str(trace.get("suspect_count", 0)) + '</span>'
              + '<span class="chip ' + ('warn' if at.get("excluded_other_tasks") else '') + '">归属 '
              + esc(str(at.get("mode", "?"))) + ' · 排除异任务 ' + str(at.get("excluded_other_tasks", 0)) + ' 条</span>'
              + '</div>']
        if agg.get("aggregator_guidance"):
            o.append('<details><summary>聚合器指引（锁死）</summary><pre>'
                     + esc(str(agg["aggregator_guidance"])) + '</pre></details>')
        # §18.3 组视图：arm_group 由**派发侧**落库，聚合端只读（缺失显式『—（未落库）』，禁反推）。
        _gv = arm_groups(refs)
        if _gv:
            o.append('<details open><summary>组视图（arm_group 派发落库，聚合端只读不猜）</summary><table>'
                     '<tr><th>组</th><th>臂数</th><th>subagent_id</th></tr>')
            for _g in _gv:
                o.append('<tr><td>' + esc(_g["group"]) + '</td><td>' + str(_g["size"])
                         + '</td><td><code>' + esc(", ".join(_g["ids"])) + '</code></td></tr>')
            o.append('</table></details>')
        # §18.5 通用分析框架消费指引（单源 monitor-schemas/ECC-WRITE.json；复述 + 指针）。
        # 2026-10-30：中立化 —— 「分析视角」在前（自然语言方法论），「形式判据」在后（机器可检形态）。
        o.append('<details open><summary>分析视角（通用方法 · 阅读提示）</summary>'
                 '<div class="meta">只用于定位分歧与盲区，不产生新判据、不改任何评分。</div><ul>')
        for _lk, _lv in _DIALECTIC_LENSES:
            o.append('<li><b>' + esc(_lk) + '</b>：' + esc(_lv) + '</li>')
        o.append('</ul></details>')
        o.append('<details><summary>ECC 论证框架（形式判据 · 消费方指引）</summary>'
                 '<div class="meta">' + esc(_ECC_SOURCE_HINT) + '</div><ul>')
        for _k, _v in _ECC_ARG:
            o.append('<li><code>' + esc(_k) + '</code> ' + esc(_v) + '</li>')
        o.append('</ul></details>')
        # §18.4 无方向图（身份状态 + 结论差异聚类）。（S3-4：原「图① 裁决矩阵」随逐项评分移除。）
        # S9（2026-10-06）：图②③④ + 跨轮趋势统一走 ECharts（vendor 内联一次；缺 vendor ⟹ SVG 降级）。
        # 2026-10-31：图表抽为独立 vw-chart 兄弟容器（禁嵌套在 vw-mat 内 ⟹ chart 视图会随父隐藏）；
        #   材料卡在此先闭合，细节块挪入后段新卡（div 不得跨 vw 容器边界）。
        o.append('</div>')                       # 闭材料卡（chips/组视图/分析框架）
        o.append('</div>')                       # 闭 vw-mat 前段
        o.append('<div class="vw vw-chart">')
        o.append(_charts_block(refs, trace, agg, trend))
        o.append('</div>')
        o.append('<div class="vw vw-mat">')      # 材料后段（细节块 + 本批汇总 + refs）
        o.append('<div class="card">')
        o.append(_html_agg_detail(agg))
        o.append(_html_dialectic(agg))
        o.append(_html_finding_detail(agg))
        o.append(_html_run_status(refs))
        o.append('</div>')
        # T-a（2026-10-06）：批级「本批实质汇总」—— challenges/kept/slashed 计数 + 应砍并集
        #   （候选 finding / 待砍项）。缺此面板则聚合页只剩结论与分数，owner 判为「没有效信息」。
        # T-b（2026-10-06 观感）：上移至 References **之前** —— 原置于 6 个折叠块之后（y≈5900），
        #   人评者先被材料淹没才看到批级实质；提前到材料卡之后即「读完材料即见实质」。
        _tot_ch = sum(len(x.get("challenges") or []) for x in refs)
        _tot_kp = sum(len(x.get("kept") or []) for x in refs)
        _tot_sl = sum(len(x.get("slashed") or []) for x in refs)
        if _tot_ch or _tot_kp or _tot_sl:
            o.append('<h3 id="sec-sum" data-i18n="h-sum">本批实质汇总</h3><div class="card"><div class="chips">'
                     + '<span class="chip">质询挑战 ' + str(_tot_ch) + '</span>'
                     + '<span class="chip">保留项 ' + str(_tot_kp) + '</span>'
                     + '<span class="chip warn">应砍项 ' + str(_tot_sl) + '</span></div>')
            _seen_sl, _uni_sl = set(), []
            for _r in refs:
                for _x in (_r.get("slashed") or []):
                    _t = sanitize_text(str(_x))
                    if _t and _t not in _seen_sl:
                        _seen_sl.add(_t)
                        _uni_sl.append(_t)
            if _uni_sl:
                o.append('<div class="meta">应砍并集（候选 finding / 待砍项）</div><ul>')
                for _t in _uni_sl:
                    o.append('<li>' + esc(_t) + '</li>')
                o.append('</ul>')
            o.append('</div>')
        for i, r in enumerate(refs, 1):
            sus = r.get("suspect") or []
            hs = str(r.get("hmac_status", ""))
            _task = str(r.get("task", ""))
            _narrow = split_narrow_task(_task)
            _fp = task_fingerprint(_narrow or _task)
            _bs = str(r.get("budget_status", ""))
            _tt, _tb = r.get("total_tokens", 0), r.get("token_budget")
            # surfacing①（2026-10-04）：预算耗尽须**中性可见**（不降权）—— RC3 carve-out
            #   只该免「降权」，不该顺手把「可能已截断」的事实也藏掉。
            _exhausted = (_bs in ("hard", "item_exceeded", "max_turns")
                          or (isinstance(_tb, (int, float)) and isinstance(_tt, (int, float))
                              and _tb and _tt > _tb))
            # surfacing②：未读到（UNKNOWN ≠ 否定）
            _nt = (r.get("findings") or {}).get("not_tried") or []
            _vv = r.get("vocab_violations") or []
            _bid = str(r.get("batch_id", "") or "")
            o.append('<details class="ref"><summary>Reference ' + str(i) + ' · <code>'
                     + esc(str(r.get("subagent_id", ""))) + '</code> · '
                     + esc(arm_group_chip(r.get("arm_group"))) + ' · HMAC ' + esc(hs)
                     + ((' · suspect ' + str(len(sus))) if sus else '')
                     + (' · 预算耗尽' if _exhausted else '') + '</summary>'
                     '<div class="card"><div class="chips">'
                     + '<span class="chip' + ('' if hs.startswith("已") else ' warn') + '">HMAC ' + esc(hs) + '</span>'
                     + '<span class="chip">置信度 ' + esc(str(r.get("confidence", ""))) + '</span>'
                     + '<span class="chip">cap ' + esc(str(_tb or "—")) + ' · item_cap '
                     + esc(str(r.get("item_budget") or "—")) + '</span>'
                     + '<span class="chip">批 ' + esc(_bid or "unbatched") + '</span>'
                     + '<span class="chip">组 ' + esc(arm_group_chip(r.get("arm_group"))) + '</span>'
                     + '<span class="chip">指纹 ' + esc(_fp) + '</span>'
                     + ('<span class="chip warn">预算耗尽 ' + esc(_bs) + ' ' + esc(str(_tt)) + '/'
                        + esc(str(_tb or "—")) + ' · 输出可能截断（UNKNOWN,≠否定）</span>' if _exhausted else '')
                     + ('<span class="chip warn">未读到 ' + str(len(_nt)) + ' 项（UNKNOWN,≠否定）</span>'
                        if _nt else '')
                     + "".join('<span class="chip bad">suspect: ' + esc(str(x)) + '</span>' for x in sus)
                     + '</div><div class="meta">窄任务 '
                     + esc(_blind_conclusion(_task_display(_narrow or _task, 200))) + '</div>')
            for _v in _vv:
                if isinstance(_v, dict):
                    o.append('<div class="meta">词表外判定 ' + esc(str(_v.get("key", ""))) + ' = '
                             + esc(_blind_conclusion(str(_v.get("raw", ""))[:120])) + '（'
                             + esc(str(_v.get("reason", ""))) + '）</div>')
            if _narrow:
                o.append('<details><summary>原始任务全文（含 preflight 前缀）</summary><pre>'
                         + esc(_blind_conclusion(sanitize_text(_task))) + '</pre></details>')
            o.append('<details><summary>结论全文</summary><pre>'
                     + esc(_blind_conclusion(str(r.get("conclusion", "")))) + '</pre></details>')
            ev = r.get("evidence") or []
            if ev:
                o.append('<details><summary>证据 ' + str(len(ev)) + ' 条</summary><table>'
                         '<tr><th>file</th><th>lines</th><th>status</th></tr>')
                for e in ev:
                    if isinstance(e, dict):
                        o.append('<tr><td><code>' + esc(str(e.get("file", ""))) + '</code></td><td>'
                                 + esc(str(e.get("lines", ""))) + '</td><td>'
                                 + esc(str(e.get("status", ""))) + '</td></tr>')
                    else:
                        o.append('<tr><td colspan="3">' + esc(str(e)) + '</td></tr>')
                o.append('</table></details>')
            f = r.get("findings") or {}
            if isinstance(f, dict) and any(f.get(k) for k in ("worked", "failed", "not_tried")):
                o.append('<details><summary>发现</summary><pre>')
                for t in ("worked", "failed", "not_tried"):
                    for x in (f.get(t) or []):
                        o.append(esc("[" + t + "] " + str(x)))
                o.append('</pre></details>')
            # T-a（2026-10-06）：plan-refinement 的**实质字段**（其 `findings[]` 按设计本就空，
            #   见 `_suspect_flags` L202-204）—— 不渲染则「发现」面板恒空，观感=「MoA 无信息」。
            _ch = r.get("challenges") or []
            _kp = r.get("kept") or []
            _sl = r.get("slashed") or []
            if _ch:
                o.append('<details><summary>质询挑战 ' + str(len(_ch)) + ' 条</summary><ol>')
                for _x in _ch:
                    o.append('<li>' + esc(_blind_conclusion(sanitize_text(str(_x)))) + '</li>')
                o.append('</ol></details>')
            if _kp:
                o.append('<details><summary>保留项 ' + str(len(_kp)) + ' 条</summary><ul>')
                for _x in _kp:
                    o.append('<li>' + esc(_blind_conclusion(sanitize_text(str(_x)))) + '</li>')
                o.append('</ul></details>')
            if _sl:
                o.append('<details open><summary>应砍项 ' + str(len(_sl)) + ' 条</summary><ul>')
                for _x in _sl:
                    o.append('<li>' + esc(_blind_conclusion(sanitize_text(str(_x)))) + '</li>')
                o.append('</ul></details>')
            o.append('</div></details>')
    if not refs and not acc:
        o.append('<div class="card">无聚合输入（references 与 accept 均空）⟹ 无材料可裁定。</div>')
    # 材料区收口：refs 分支已切前后两段（此处闭后段），无 refs 时闭前段 —— 恰好一个未闭 vw-mat。
    o.append('</div>')

    # ── 二、人工结论（散文）──  S3-4（2026-10-06，owner 裁定「不要再让我评分」）：
    #   取消逐项评分 UI（F1-F7 下拉 + 滑杆 + decision）—— 评分已由 MoA 聚合 + `finding score`
    #   从 findings **确定性生成**；人只写**散文结论**，经 `finding from-prose` → `finding score`
    #   得批级判定与分数。双盲：本页不渲 agent 侧任何分数锚。
    # 2026-10-31：裁定区（散文 + 出口）整体包 vw-prose（默认视图）。
    o.append('<div class="vw vw-prose">')
    o += ['<h2 id="sec-prose"><span data-i18n="h-prose">二、人工结论（散文）</span></h2>',
          '<div class="card"><div class="meta"><b>不再逐项打分</b> —— 批级 F1-F7 判定与分数由算法'
          '从 findings 生成。本页只收你的<b>散文结论</b>；导出后经 '
          '<code>finding from-prose</code> → <code>finding score</code> → <code>adjudicate</code>。'
          '列表项<b>必须</b>用 <code>-</code> / <code>1.</code> 开头（标题行与普通段落会被'
          '<b>整行忽略</b>，⟹ 产出 0 条 finding ⟹ 全 PASS 放行）；载体标记 '
          '<code>(P)</code>计划 / <code>(L)</code>机检 / <code>(M)</code>机制。</div>'
          '<textarea id="prose" style="min-height:220px" '
          'placeholder="例：- (P) T3 范围界定模糊，须收窄到原定模块。  - (M) 预算耗尽截停无告警，须补看门狗。"></textarea>'
          '<div id="prose-warn" class="banner-warn" style="display:none"></div>'
          '<div class="axis" style="grid-template-columns:190px 130px 1fr;margin-top:8px">'
          '<div>JSON 落盘目录</div><div class="meta">供命令引用</div>'
          '<div><input type="text" id="dir" value="."></div></div>'
          '<div class="axis" style="grid-template-columns:190px 130px 1fr">'
          '<div>结论方向</div><div class="meta">评分语义</div>'
          '<div><select id="mode">'
          '<option value="reject">驳回（列表项 = 缺陷，按现规则罚分）</option>'
          '<option value="allow">放行（列表项 = 已接受的观察项，不罚分）</option>'
          '<option value="abstain">弃权（不做判定，仅落台账）</option>'
          '</select></div></div>'
          '<div class="axis" style="grid-template-columns:190px 130px 1fr">'
          '<div>批上下文（相关性闸）</div><div class="meta">聚合 JSON / state，可空</div>'
          '<div><input type="text" id="ctx" value="" '
          'placeholder="填了则未锚定条目隔离为 unverified（不计缺陷）；空 = 不启用闸"></div>'
          '</div></div>']

    # ── 三、出口 ──
    o += ['<h2 id="sec-out"><span data-i18n="h-out">三、出口（零新写通路）</span></h2>', '<div class="card">',
          '<button id="dl-p" data-i18n="b-dl">下载 prose.txt</button>',
          '<button class="ghost" id="copy-p" data-i18n="b-copy">复制散文</button>',
          '<button class="ghost" id="copy" data-i18n="b-cmd">复制命令链</button>',
          '<pre id="cmd"></pre>',
          '<div class="meta">把 <code>prose.txt</code> 存到「JSON 落盘目录」，粘贴上面三步执行；'
          'state 写入仍只经 CLI（本页不落任何 state）。</div>',
          '</div>', '</div>', '</div>', '<script>'
          + _JS.replace("__MARKER_SRC__", _json_embed(_MARKER_RE.pattern))
               .replace("__HEAD_SRC__", _json_embed(_HEAD_RE.pattern))
          + '</script>', '</body></html>']
    return "\n".join(o)


def _open_candidates(s: str) -> list:
    """**系统默认程序**打开候选（单路优先，**无 explorer 兜底**）。

    WSL(`/mnt/<d>/...`) → `cmd.exe start`；其余 → `xdg-open`（native Windows 走 `os.startfile`，不经此表）。
    """
    out = []
    m = re.match(r"^/mnt/([a-zA-Z])/(.*)$", s)
    if m:
        win = m.group(1).upper() + ":\\" + m.group(2).replace("/", "\\")
        out.append(["cmd.exe", "/c", "start", "", win])
    out.append(["xdg-open", s])
    return out


def _open_in_browser(target) -> bool:
    """用**系统默认程序**打开文件或 URL（2026-09-24 用户裁定「需要自动打开」；2026-10-09 修）。

    2026-10-09（owner 裁定「去修系统默认，大概有 bug」）：
      · **存在护栏**：文件目标不存在 ⟹ 直接返回 False（防 `start`/浏览器把坏路径当 URL/搜索页打开
        —— 即「莫名其妙的谷歌」）；
      · **单路**：native Windows → `os.startfile`；WSL → `cmd.exe start`；其余 → `xdg-open`；
        **删 `explorer.exe` 兜底**（它可能落到非默认处理器）。
    纪律：**best-effort，永不因打开失败而让命令失败**（页面已写盘，打开只是便利面）；
    返回是否至少发起了一次调用（供 envelope 记 `opened`，可机检）。
    """
    is_url = isinstance(target, str) and "://" in target
    if is_url:
        s = target
    else:
        try:
            p = Path(target)
            if not p.exists():
                return False
            s = str(p.resolve())
        except OSError:
            return False
    if hasattr(os, "startfile"):        # native Windows：ShellExecute = 系统默认处理器
        try:
            os.startfile(s)             # type: ignore[attr-defined]
            return True
        except OSError:
            return False
    for c in _open_candidates(s):
        try:
            subprocess.Popen(c, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:  # noqa: BLE001 — best-effort 面，逐个候选退让
            continue
    return False


def _facet_value(rec: dict, name: str) -> str:
    """取 `facets` 里 `name:value` 的 value（结构化单源）；无 ⟹ 空串。"""
    for x in (rec.get("facets") or []):
        s = str(x)
        if s.startswith(name + ":"):
            return s.split(":", 1)[1]
    return ""


def _finding_plan(f: dict) -> str:
    """从 finding 取**计划键**（结构化 facet `plan:` → 锚 `plan:`）—— 跨批/跨轮比对分组单源。"""
    for x in (f.get("facets") or []):
        s = str(x)
        if s.startswith("plan:"):
            return s.split(":", 1)[1]
    for a in (f.get("anchors") or []):
        s = str(a)
        if s.startswith("plan:"):
            return s.split(":", 1)[1]
    return ""


def _trend_from_state(state_file: str, plan: str = "") -> list:
    """S3（2026-10-06）：从 state 的 `ecc_findings` 取 `moa-agg:`/`noconv:` **测量 finding 序列**
    （跨轮趋势源）。**只读**；无 state / 无 finding ⟹ 空（不进图表）。

    `ECC-0BA041A4284E`（2026-10-10，G3）：给 `plan` 则**只取该计划的序列** —— 否则 base 态
    多计划 finding 会被并成一条趋势线（跨计划混线）。缺省不变（零回归）。
    """
    if not state_file or not Path(state_file).is_file():
        return []
    try:
        import gk_finding
        # 读侧 union（遗漏⑤）：已溢出到 finding 片的簇也须进趋势线（否则趋势断代）。
        fs = gk_finding.load_findings_union(state_file) or []
    except Exception:
        return []
    out = []
    for f in fs:
        rk = str(f.get("root_key", "") or "")
        if not (rk.startswith("moa-agg:") or rk.startswith("noconv:")):
            continue
        if plan and _finding_plan(f) != str(plan):
            continue
        note = str(f.get("source_note", "") or "")
        m = re.search(r"引用=(\d+)\s+簇=\d+\s+一致度=([0-9.]+)", note)
        # 结构化 facet 优先；无则退回对人类可读 source_note 的正则（兼容旧账）。
        mu_s = _facet_value(f, "refs") or (m.group(1) if m else "")
        w_s = _facet_value(f, "weight") or (m.group(2) if m else "")
        try:
            wt = float(w_s)
        except (TypeError, ValueError):
            wt = 0.0
        out.append({"round": str(f.get("created_at", "") or "")[:19],
                    "mu": int(mu_s) if str(mu_s).isdigit() else 0,
                    "top_weight": wt, "root_key": rk})
    out.sort(key=lambda x: str(x.get("round", "")))
    return out


def _emit_html(agg: dict, out_path: str, omitted: bool = False, do_open: bool = True,
               state_file: str = "", do_serve: bool = False, port: int = 8765,
               out_dir: str = "", plan: str = "") -> int:
    """写人工裁定页 + 回报路径 +（默认）自动在宿主打开；`do_serve` 则起**一次性回环服务**。

    回报路径是**必须**的：页面在 `file://` 下打开，调用方拿不到路径就等于白跑。
    写失败 → fail-loud（禁静默当成功）。`omitted=True` = 聚合正文未落盘（未给 `--out`），
    显式记进 envelope（**不静默丢**，同本仓 fail-loud 纪律）。
    2026-09-24：`do_open` 默认 True（用户裁定「需要自动打开」）⟹ 写盘后 best-effort 打开，
    `envelope.opened` 记录实际是否发起（打开失败**不影响** rc）。
    2026-10-09（D，owner 裁定「点提交自动跑三步并交给我」）：`do_serve` ⟹ 起 127.0.0.1 回环服务，
    页面「提交」自动跑 `from-prose → score → adjudicate`，**回执打到本命令 stdout**（agent 读取通道）。
    """
    meta = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    trend = _trend_from_state(state_file, plan=plan)   # S3：跨轮趋势源（只读 state 的测量 finding）
    page = render_html(agg, meta, trend=trend)
    try:
        Path(out_path).write_text(page, encoding="utf-8")
    except OSError as exc:
        print(json.dumps({"ok": False, "error": f"html 写失败: {exc}"}, ensure_ascii=False))
        return 1
    trace = agg.get("trace") or {}
    env = {"ok": True, "html": str(Path(out_path).resolve()), "mode": agg.get("mode"),
           "reference_count": len(agg.get("references") or []), "trace": trace,
           "opened": False}
    if omitted:
        env["aggregate_omitted"] = True
        env["hint"] = "聚合正文未落盘（未给 --out）；须留档请重跑并加 --out <file>"
    if do_serve:
        env["serving"] = True
        print(json.dumps(env, ensure_ascii=False))
        rec = serve(page, port=port, out_dir=(out_dir or str(Path(out_path).parent)), do_open=do_open)
        print(json.dumps(rec, ensure_ascii=False))
        return 0 if rec.get("ok") else 1
    env["opened"] = _open_in_browser(Path(out_path)) if do_open else False
    print(json.dumps(env, ensure_ascii=False))
    return 0


def _should_open(args) -> bool:
    """自动打开的**默认闸**：显式 `--no-open` / env `GK_NO_OPEN=1` / pytest 运行中 ⟹ 不开。

    pytest 判据（`PYTEST_CURRENT_TEST` / `PYTEST_XDIST_WORKER`）随 pytest 自带——测试面**天然
    惰性**，无需测试逐条改（否则跑套件会自动弹出浏览器窗口）。真实使用（CLI 调用）= 默认打开。
    """
    if getattr(args, "no_open", False) or os.environ.get("GK_NO_OPEN"):
        return False
    if os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("PYTEST_XDIST_WORKER"):
        return False
    return True


# ── D：一键提交一次性回环服务（2026-10-09，owner 裁定「我只写散文、点提交，自动跑三步并交给你」）──
# 硬约束：`file://` 静态页**不能**执行命令 ⟹ 要「自动」须有本机回环服务（范式复用 sniffnet_webhook.py
#   的 HTTPServer/do_POST）。服务只在 127.0.0.1，供页 → 收提交 → 跑三步链 → 回执打到 stdout → 退出；
#   **state 写入仍只经 CLI**（本服务不落 state）。
_SERVE_JS = """
(function(){
  var b=document.getElementById("gk-submit"),out=document.getElementById("gk-submit-out");
  if(!b||!out)return;
  b.addEventListener("click",function(){
    b.disabled=true;b.textContent="提交中…";
    var v=function(id){var e=document.getElementById(id);return e?e.value:"";};
    var body=JSON.stringify({prose:v("prose"),mode:v("mode")||"reject",ctx:v("ctx"),dir:v("dir")||"."});
    fetch("/submit",{method:"POST",headers:{"Content-Type":"application/json"},body:body})
      .then(function(r){return r.json();})
      .then(function(j){out.style.display="";
        out.textContent=JSON.stringify(j,null,1);
        b.textContent=j.ok?"已提交（见回执）":"提交完成（有失败，见回执）";})
      .catch(function(e){out.style.display="";out.textContent="提交失败："+e;
        b.disabled=false;b.textContent="重试提交";});
  });
})();
"""


def render_serve_html(html: str) -> str:
    """给静态裁定页注入**提交控件**（仅 `--serve` 模式用；静态 `file://` 页不含）。"""
    widget = (
        '<div class="card" id="gk-serve-card">'
        '<button id="gk-submit">提交（自动跑三步链）</button>'
        '<div class="meta">点提交 ⟹ 本机服务自动跑 '
        '<code>finding from-prose → finding score → adjudicate</code>，回执见下方；'
        '本页不写 state。</div>'
        '<pre id="gk-submit-out" style="display:none"></pre></div>'
        '<script>' + _SERVE_JS + '</script>')
    # ECC-9FF31C13260D（2026-10-10）：原用 `replace("</body>", ..., 1)` 命中的是**首个**
    #   `</body>` —— 而裁定页把「下载 HTML」构造器整页源码嵌进 JS 字符串，其中已含一个
    #   转义的 `</body>`，导致注入 `<script>` 落在 ECharts 块内部 → 页面图表不渲染 +
    #   压缩 JS 被当正文显示（用户实测「图没了 + 输出全是乱码」）。改用 `rfind` 锚**文档级**
    #   结束标签；无 `</body>` 的片段直接追加。
    i = html.rfind("</body>")
    if i < 0:
        return html + widget
    return html[:i] + widget + html[i:]


def _cmd_from_prose(dir_: str, prose_file: str, ctx: str) -> list:
    c = ["finding", "from-prose", "--file", prose_file, "--out", os.path.join(dir_, "findings.json")]
    if ctx:
        c += ["--context", ctx]
    return c


def _cmd_score(dir_: str, mode: str) -> list:
    return ["finding", "score", "--file", os.path.join(dir_, "findings.json"),
            "--out-dir", dir_, "--direction", mode]


def _cmd_adjudicate(dir_: str, score01: str) -> list:
    return ["adjudicate", "--verdicts-file", os.path.join(dir_, "verdicts.json"),
            "--concessions-file", os.path.join(dir_, "concessions.json"),
            "--score", score01, "--decision", "人工结论见 prose.txt", "--blind"]


def _default_runner(argv: list):
    """默认执行器：`bash <SKILL_DIR>/gatekeeper-cli.sh <argv...>` ⟹ (rc, stdout)。"""
    cli = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gatekeeper-cli.sh")
    p = subprocess.run(["bash", cli, *argv], capture_output=True, text=True)
    return p.returncode, (p.stdout or "")


def _last_json(s: str):
    """取 stdout 末行 JSON（CLI 契约：末行 = 完整 JSON）；失败回 None。"""
    try:
        return json.loads((s or "").strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        return None


def _submit(out_dir: str, data: dict, runner) -> dict:
    """收提交 → **自动**按序跑三步链（无需用户手敲）→ 回执 dict。"""
    d = Path(out_dir); d.mkdir(parents=True, exist_ok=True)
    (d / "prose.txt").write_text(str(data.get("prose") or ""), encoding="utf-8")
    mode = str(data.get("mode") or "reject")
    ctx = str(data.get("ctx") or "")
    steps = []
    rc1, o1 = runner(_cmd_from_prose(str(d), str(d / "prose.txt"), ctx))
    steps.append({"step": "from-prose", "rc": rc1, "out": o1[-2000:]})
    rc2, o2 = runner(_cmd_score(str(d), mode))
    steps.append({"step": "score", "rc": rc2, "out": o2[-2000:]})
    j2 = _last_json(o2) or {}
    s100 = j2.get("score")
    score01 = "%.2f" % (float(s100) / 100.0) if isinstance(s100, (int, float)) else "0.00"
    rc3, o3 = runner(_cmd_adjudicate(str(d), score01))
    steps.append({"step": "adjudicate", "rc": rc3, "out": o3[-2000:]})
    j1 = _last_json(o1) or {}
    return {"ok": rc1 == 0 and rc2 == 0 and rc3 == 0, "dir": str(d),
            "items": j1.get("count"), "score": score01, "steps": steps}


def _make_handler(page_html: str, out_dir: str, runner):
    from http.server import BaseHTTPRequestHandler

    class _H(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype="application/json; charset=utf-8"):
            b = body if isinstance(body, bytes) else str(body).encode("utf-8")
            self.send_response(code); self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

        def do_GET(self):
            if self.path.split("?")[0] in ("/", "/index.html"):
                self._send(200, page_html, "text/html; charset=utf-8")
            else:
                self._send(404, json.dumps({"ok": False, "error": "not found"}))

        def do_POST(self):
            if self.path.split("?")[0] != "/submit":
                self._send(404, json.dumps({"ok": False, "error": "not found"})); return
            try:
                n = int(self.headers.get("Content-Length", 0) or 0)
                data = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
                rec = _submit(str(data.get("dir") or out_dir), data, runner)
            except Exception as exc:  # noqa: BLE001 — fail-loud 进回执，不吞
                rec = {"ok": False, "error": str(exc)}
            self._send(200, json.dumps(rec, ensure_ascii=False))
            self.server._receipt = rec

        def log_message(self, *args):
            pass

    return _H


def _make_server(page_html: str, port: int, out_dir: str, runner=None):
    from http.server import HTTPServer
    srv = HTTPServer(("127.0.0.1", int(port)),
                     _make_handler(page_html, out_dir, runner or _default_runner))
    srv._receipt = None
    return srv


def _serve_loop(srv) -> dict:
    """处理请求直到收到一次 **提交**（一次性）；返回回执。"""
    while getattr(srv, "_receipt", None) is None:
        srv.handle_request()
    return srv._receipt


def serve(html: str, port: int = 8765, out_dir: str = ".", do_open: bool = False, runner=None) -> dict:
    """起**一次性**回环服务（127.0.0.1）：供页 → 收提交 → 跑三步链 → 回执打到 stdout → 退出。"""
    srv = _make_server(render_serve_html(html), port, out_dir, runner)
    url = "http://127.0.0.1:%d/" % srv.server_address[1]
    print(json.dumps({"ok": True, "serving": url, "once": True,
                      "hint": "页面写散文→点提交；本服务自动跑三步后退出，回执见下一行"},
                     ensure_ascii=False))
    if do_open:
        _open_in_browser(url)
    try:
        return _serve_loop(srv)
    finally:
        srv.server_close()


def _covert_scan(state_file):
    """T4 隐蔽事件通道 warden 接线（§5；`ECC-143409BC4A8C`）。

    延迟导入 `gk_covert_warden`（避免硬依赖）；返回三轴封套
    `{storage,timing,behavioral,overall}`。实现**禁第二份**：单一落点 = `scripts/gk_covert_warden.py`。
    """
    try:
        import gk_covert_warden as _W
    except Exception as e:  # noqa: BLE001 — 边界：缺模块 ⟹ fail-loud 到封套
        return {"error": "covert warden 不可用：%s" % e}
    return _W.scan(state_file)


def main() -> int:
    # §18.2 判据 c3（2026-10-04）：declared-but-unresolved（指针 stale/dangling）⟹ 禁静默读 base。
    from gk_state_route import read_point_pointer_error
    _rp_err = read_point_pointer_error()
    if _rp_err:
        print(json.dumps(_rp_err, ensure_ascii=False))
        return 1
    p = argparse.ArgumentParser(description="MoA 聚合器：ECC references → 主 agent 聚合输入")
    p.add_argument("--state", default=os.environ.get("STATE_FILE", ""))
    p.add_argument("--recent", type=int, default=0, help="只取最近 N 条（0=全部）")
    p.add_argument("--role", default="", help="按 task 包含匹配过滤角色（如 plan-refinement）")
    p.add_argument("--task", default="", help="归属锚定：只聚合与该 task 指纹一致的 references（F-REV-8）")
    p.add_argument("--allow-cross-task", action="store_true",
                   help="显式放开跨任务聚合（默认拒绝；trace 记 cross_task_allowed）")
    p.add_argument("--plan", default="",
                   help="§18 计划锚：只聚合 task 含该计划路径的 references（6 臂 3 组；优先于逐字指纹）")
    # §18.1（2026-10-03，ECC-5538DD07B709 RC1/N1）：批锚 —— 精确取一批（优先于 --plan/--task）；
    #   缺省（同计划多批）按批分节不混票（trace.batch.mode=all_batches）；跨批仅显式放开。
    p.add_argument("--batch", default="",
                   help="§18.1 批锚：只取 batch_id 精确等于该值的 references（优先于 --plan/--task）")
    p.add_argument("--allow-cross-batch", action="store_true",
                   help="§18.1 显式放开跨批比较（默认按批分节不混票；trace 记 cross_batch_allowed）")
    # 2026-09-28（用户裁定「加新鲜度判断避免聚合到过时产物」）：`--recent N` 会按**位置**取件，
    #   异计划/上一轮的旧产物照样入选（实测：`--recent 6` 把上一轮 ③ 的 review 聚进来）。
    #   本旗标按**产物 mtime** 过滤（`report_file`→`output_file`→`timestamp`）；0=关（零回归）。
    p.add_argument("--fresh", type=int,
                   default=int(os.environ.get("GK_MOA_FRESH_TTL", "0") or 0),
                   help="只聚合产物 mtime 在该秒数内的 references（0=关；env GK_MOA_FRESH_TTL）")
    p.add_argument("--md", action="store_true", help="输出可读 Markdown 聚合报告")
    p.add_argument("--out", default="", help="写文件路径（默认 stdout）")
    # ── 验收聚合（ECC-BAB89429DFD1 §11.5）：MoA 从「报告聚合」扩为「报告 + 验收聚合」 ──
    p.add_argument("--accept", action="store_true",
                   help="验收聚合单入口：逐 worktree 跑受影响子集 → 统一裁决封套（单行 JSON）")
    p.add_argument("--worktrees", default="",
                   help="验收聚合：逗号分隔 worktree 路径（缺/空 ⟹ verdict=unknown，fail-loud）")
    p.add_argument("--accept-files", default="",
                   help="验收聚合：受影响文件（逗号分隔；空 = 交 _accept_cli.sh 默认面）")
    p.add_argument("--accept-timeout", type=int, default=3600, help="单 worktree 超时秒（默认 3600）")
    # ── 全量回归（ECC-2FB0B4D0F356，设计 §11.7-3）：逐 worktree 只跑**受影响子集** ⟹ 跨族合并
    #    后的全量面无人覆盖。本旗标 = opt-in：在**合并树**上补跑一次 `_accept_cli.sh --full`。
    p.add_argument("--full-regression", action="store_true",
                   help="验收聚合：额外在合并树跑全量回归（须与 --accept 同用；结果在 accept.full_regression）")
    p.add_argument("--merge-tree", default="", help="合并树路径（缺省 = 本仓根）")
    # ── 人工裁定页（ECC-4C1E8A27B9D3）：MoA 聚合后的**双盲人评面**（自足 HTML，读完即弃）──
    p.add_argument("--html", default="",
                   help="写自足 HTML 人工裁定页（零外部依赖/双盲/零新写通路；可与 --md/--out 同用）")
    # 2026-09-24（用户裁定「HTML 需要自动打开」）：默认写盘后自动在宿主浏览器打开；
    #   `--no-open` / env `GK_NO_OPEN=1` 关闭；pytest 运行中天然惰性（`_should_open`）。
    p.add_argument("--no-open", action="store_true",
                   help="禁止自动打开人评页（默认自动打开；env GK_NO_OPEN=1 同效）")
    # D（2026-10-09，owner 裁定「点提交自动跑三步并交给我」）：一次性回环服务（须与 --html 同用）。
    p.add_argument("--serve", action="store_true",
                   help="写盘后起**一次性**回环服务（127.0.0.1）：页面「提交」自动跑三步链 ⟹ 回执（须与 --html 同用）")
    p.add_argument("--port", type=int, default=8765, help="--serve 监听端口（0=随机；默认 8765）")
    # Infra-1c（2026-10-05，ECC-1F540718AEE5）：聚合落 finding + 跨轮收敛比对接线。
    p.add_argument("--emit-finding", action="store_true",
                   help="聚合后落一条 ecc-finding（锚=plan/batch；供跨轮收敛比对消费）")
    # T-b（2026-10-06，owner 裁定「每轮必落」）：**有锚（--batch/--plan）时默认落 finding**。
    # ── 保护锁（2026-10-14，`ECC-50A0C5A3F2A8`，用户令「不能抑制」）──────────────────────
    # ⛔ 旧 `--no-emit-finding`（opt-out）**已封闭**：有锚聚合**必落** finding，给出该 flag 即
    #   **fail-loud（rc=2，emit_finding_suppression_locked）**（既不静默忽略、也不放行）——防
    #   「跑完并发 → 聚合」链上 finding 被掐掉、跨轮收敛/台账静默缺口（事故：2026-10-14 聚合
    #   finding 被 `--no-emit-finding` 吞，owner 令「加保护锁不能抑制」）。
    #   无锚（既无 --batch 又无 --plan）⟹ 仍默认**不落**（`emit_aggregate_finding` 无锚会
    #   fail-loud，故不能盲开）——「无 finding 的纯演示聚合」请**去掉锚**，而非抑制。
    p.add_argument("--no-emit-finding", action="store_true",
                   help="⛔ 已封闭：有锚聚合禁抑制 finding（保护锁）；给出即 fail-loud（rc=2）")
    p.add_argument("--convergence", action="store_true",
                   help="跨轮收敛比对（RCA r̂(stock)/N*）；不收敛则落 NO-CONVERGENCE finding")
    p.add_argument("--mu", default="",
                   help="--convergence 的 μ_n 序列（逗号分隔，按轮序）")
    # T1（2026-10-14，ECC-PLAN `2026-10-14-moa-chain-automation-plan.md` §3-T1）：链骨架模式。
    p.add_argument("--chain", action="store_true",
                   help="T1 链骨架：批锚自解析→聚合→落 finding→P/L/M→熔断(只读评估器)→单一封套")
    # T15（2026-10-29，user 裁定「链头入参」）：`--from-plan <plan>` —— 链**从头**起跑：
    #   plan-lint(PW-SN，high/medium>0 即拒) → 派臂（委托 plan-refinement --run）→ 聚合 → HTML。
    p.add_argument("--from-plan", default="",
                   help="T15 链头入参：从计划文本起跑（plan-lint 机检门 → 派臂 → 聚合 → HTML），须与 --chain 同用")
    p.add_argument("--arms-per-group", type=int, default=0,
                   help="T15：透传 plan-refinement 的每组臂数 K（0=用其缺省）")
    # T2（2026-10-14，C 计划 §3-T2）：P/L/M 分组**独立出口**（复用 `plm_groups`，禁第二实现）。
    p.add_argument("--group", action="store_true",
                   help="T2：只导出 P/L/M 分组（carrier:L/P/M），供链消费")
    # T4（2026-10-14，C 计划 §3-T4）：链尾 HTML 自动导出**opt-out**。
    p.add_argument("--no-html", action="store_true",
                   help="T4：链尾不自动导出 HTML（缺省自动写盘到 state 域规则化路径）")
    # T5（2026-10-15，C 计划 §3-T5）：链尾散文接收 → 自动 from-prose → 并入台账（root_key 幂等）。
    p.add_argument("--prose", default="",
                   help="T5：散文文件（`-`=读 stdin）⟹ 自动 from-prose 并入台账（prose:<hash> 幂等）")
    # §5（ECC-143409BC4A8C）：T4 隐蔽事件通道 warden 接线 —— 三轴扫描并入聚合封套（`covert`）。
    p.add_argument("--covert-scan", action="store_true",
                   help="T4 covert warden 三轴扫描（Storage / Timing IND-STAT / Behavioral IND-INT）")
    # A8-①（ECC-8B2C819EDE7D）：opt-in 独立度硬门 —— n_eff < n_eff_min 并入 abstain（缺省关 ⟹ 零回归）。
    p.add_argument("--strict-independence", action="store_true",
                   help="A8-① 独立度硬门：n_eff < n_eff_min 时强制 abstain（缺省关）")
    args = p.parse_args()

    # ── 保护锁（2026-10-14，`ECC-50A0C5A3F2A8`，用户令「不能抑制」）──
    # 抑制口**已封闭**：有锚（--batch/--plan）聚合的 ecc-finding 强制落账，禁 `--no-emit-finding`。
    # fail-loud（不静默忽略、不放行）—— 逃生 = **去掉锚**（无锚本就不落），而非抑制。
    if args.no_emit_finding:
        print(json.dumps({"mode": "moa_aggregate", "ok": False,
                          "error": "emit_finding_suppression_locked",
                          "hint": "有锚（--batch/--plan）聚合的 ecc-finding 已由保护锁强制落账，"
                                  "禁 `--no-emit-finding` 抑制（2026-10-14 用户令）。"
                                  "如需无 finding 的纯演示聚合：去掉 --batch/--plan（无锚本就不落）。"},
                         ensure_ascii=False))
        return 2

    # fail-loud（负臂）：`--full-regression` 的落点只在 `--accept` 分支 ⟹ 单独给出时**拒绝**
    # 而不是静默忽略（静默忽略 = 用户以为跑了全量、实际零动作，正是本仓禁的「假验证」）。
    # T15（2026-10-29）：`--from-plan` 只在链模式有意义 —— 单独给出即拒绝（禁静默忽略）。
    if args.from_plan and not args.chain:
        print(json.dumps({"mode": "moa_chain", "ok": False,
                          "error": "--from-plan 必须与 --chain 同用",
                          "hint": "例：moa-aggregate --chain --state <state> --from-plan <plan>"},
                         ensure_ascii=False))
        return 2

    if args.chain:
        # T1 链骨架：单入口编排（批锚自解析→聚合→finding→P/L/M→熔断→封套）。stdout 单封套 JSON。
        if not args.state or not Path(args.state).is_file():
            print(json.dumps({"mode": "moa_chain", "ok": False,
                              "error": f"state 不存在: {args.state}"}, ensure_ascii=False))
            return 1
        # T8（2026-10-16，C 计划 §3-T8）：**单一回执** —— stdout **只**出**单行** JSON 封套。
        #   ① **守卫**：`chain()` 的子调用（emit_aggregate_finding / render_html / from-prose /
        #      register…）若向 stdout 打印，会把封套冲成**伪拼接 JSON** ⟹ 调用期
        #      `redirect_stdout(sys.stderr)`，子调用输出一律引到 stderr —— 使「stdout = 单一 JSON」
        #      由**机制**保证，而非依赖「子调用恰好不打印」。
        #   ② **形态**：单行（与 `--accept`/`--group` 分支「stdout 末行 = 完整 JSON」契约一致；
        #      原 `indent=2` 多行，与全仓单一回执契约不符）。
        import contextlib
        with contextlib.redirect_stdout(sys.stderr):
            res = chain(args.state, plan=args.plan, batch=args.batch,
                        role=args.role or "plan-refinement", task=args.task,
                        cross_batch=args.allow_cross_batch, html_path=args.html or "",
                        no_html=bool(args.no_html), prose_file=args.prose or "",
                        from_plan=args.from_plan or "",
                        arms_per_group=int(args.arms_per_group or 0))
        print(json.dumps(res, ensure_ascii=False))
        return 0 if res.get("ok") else 1

    if args.full_regression and not args.accept:
        print(json.dumps({"mode": "moa_accept", "ok": False,
                          "error": "--full-regression 必须与 --accept 同用"
                                   "（单独给出无落点 ⟹ 拒绝静默忽略）",
                          "hint": "例：--accept --worktrees <a,b> --full-regression"},
                         ensure_ascii=False))
        return 2

    if args.accept:
        # ⚠ 验收模式**不依赖 --state**（验收输入 = worktree 面，非 subagent_history）。
        acc = accept_reports(_split_csv(args.worktrees), args.state,
                             _split_csv(args.accept_files), args.accept_timeout)
        if args.full_regression:
            # 合并树缺省 = 本仓根（`scripts/` 的父目录）⟹ 零配置可用；可 --merge-tree 覆盖。
            tree = args.merge_tree or str(Path(__file__).resolve().parent.parent)
            # 契约（红先臂 + 族模板）：结果落 **`accept.full_regression`**（accept 封套内），
            # 与 `accept.per_worktree`/`accept.global` 同级 —— 单一封套，勿放顶层致消费侧分裂。
            acc["accept"]["full_regression"] = _accept_full_regression(tree, args.accept_timeout)
        if args.state and Path(args.state).is_file():
            # 单入口：同一回包内同时给「报告聚合」（references）与「验收聚合」（accept）
            rep = aggregate(args.state, args.recent, args.role, args.task, args.allow_cross_task,
                            args.fresh, args.plan, args.batch, args.allow_cross_batch,
                            args.strict_independence)
            acc["report"] = {"mode": rep.get("mode"), "references": rep.get("references", []),
                             "trace": rep.get("trace", {})}
            if rep.get("error"):
                acc["report"]["error"] = rep["error"]
        if args.html:
            # `--html` 模式：stdout **只**出 page envelope（单一 JSON 契约，见头注「禁伪拼接 JSON」）；
            # 聚合正文要留档请显式给 `--out`（否则记 aggregate_omitted，不静默丢）。
            if args.out:
                Path(args.out).write_text(json.dumps(acc, ensure_ascii=False), encoding="utf-8")
            return _emit_html(acc, args.html, omitted=not args.out, do_open=_should_open(args),
                              do_serve=args.serve, port=args.port, plan=args.plan,
                              out_dir=(str(Path(args.out).parent) if args.out else ""))
        text = json.dumps(acc, ensure_ascii=False)  # 单行（契约：stdout 末行须为完整 JSON）
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
        else:
            print(text)
        # A7 不破：裁决封套（verdict / per_worktree[].rc）承载判据；本模式 rc=0 = 封套已产出
        return 0

    if not args.state or not Path(args.state).is_file():
        print(json.dumps({"mode": "moa_aggregate", "error": f"state 不存在: {args.state}",
                          "hint": "传入 --state 或 STATE_FILE env"}, ensure_ascii=False))
        return 1

    agg = aggregate(args.state, args.recent, args.role, args.task, args.allow_cross_task,
                    args.fresh, args.plan, args.batch, args.allow_cross_batch,
                    args.strict_independence)
    # Infra-1c（2026-10-05，ECC-1F540718AEE5）：聚合落 finding + 跨轮收敛比对。
    # T-b（2026-10-06，owner 裁定「每轮必落」）+ 保护锁（2026-10-14，`ECC-50A0C5A3F2A8`）：
    #   **有锚（--batch/--plan）即必落** finding（**无任何抑制口**；`--no-emit-finding` 已入口 fail-loud）；
    #   无锚 ⟹ 不落（`emit_aggregate_finding` 无锚会 fail-loud，故不能盲开）。结果并入 agg。
    _emit = bool(args.batch or args.plan) and not agg.get("error")
    if _emit:
        agg["finding"] = emit_aggregate_finding(args.state, agg, plan=args.plan, batch=args.batch,
                                                cross_batch_allowed=args.allow_cross_batch)
    if args.convergence:
        _mu = [int(x) for x in _split_csv(args.mu)]
        agg["convergence"] = convergence_finding(args.state, args.plan, _mu)
    if args.covert_scan:
        # §5（ECC-143409BC4A8C）：T4 隐蔽事件通道 warden 三轴并入聚合封套（消费面 = 主 agent）。
        agg["covert"] = _covert_scan(args.state)
    # T2（2026-10-14，C 计划 §3-T2）：P/L/M 分组**独立出口** —— 只出分组（stdout 单一 JSON 封套），
    #   实现复用 `plm_groups`（= `assess_findings` 的 carrier 分面，**禁第二实现**）。
    if args.group:
        _g = plm_groups(agg)
        _text = json.dumps({"mode": "plm_groups", "ok": not agg.get("error"),
                            "plm": _g, "counts": {k: len(v) for k, v in _g.items()}},
                           ensure_ascii=False, indent=2)
        if args.out:
            Path(args.out).write_text(_text, encoding="utf-8")
        print(_text)
        return 1 if agg.get("error") else 0
    if args.md:
        text = render_md(agg)
    else:
        text = json.dumps(agg, ensure_ascii=False, indent=2)
    if args.html:
        # 同 accept 分支：stdout 只出 envelope（`--md`/聚合 JSON 与 envelope 混流 = 伪拼接 JSON）
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
        return _emit_html(agg, args.html, omitted=not args.out, do_open=_should_open(args),
                          state_file=args.state, do_serve=args.serve, port=args.port, plan=args.plan,
                          out_dir=(str(Path(args.out).parent) if args.out else ""))
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 1 if agg.get("error") else 0


if __name__ == "__main__":
    sys.exit(main())
