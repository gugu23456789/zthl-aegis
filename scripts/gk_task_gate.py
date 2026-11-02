#!/usr/bin/env python3
"""
gk_task_gate.py — 入站窄任务数据管道节点（2026-09-10，用户定案 L2）
==================================================================
缺口（F-REV-21）：`plan-refinement --task "<自由文本>"` 与 target 路径拼成
`full_task="plan-refinement: <target> — <task>"` 一次性下发（gatekeeper-cli.sh L5813-5815）
—— **无字段边界（无 IDL）、无入站校验**。agent 在 --task 里写「质询目标：…新增 MCP 兜底模式」
这类**断言**时，该断言与「路径/待查维度」在下游 subagent 眼里无区别 → 它去文档里找 MCP →
找不到 → 回「全文无 MCP 字样」→ 主 agent 反把注入产物报成"提案缺陷"（F-REV-18 勘误）。

本节点补的是**入站侧**（R0.2/R0.3 hook 是**出站命令门**，拦的是 agent 要执行的 shell；
--task 是**入站内容**，两者不在同一条链 → 扩展 hook 解决不了此类问题）:
  ① provenance  task 引用的专名（引号短语 / ASCII 专名）与**一切未知长串**（CJK ≥4 连续串）
                须能在 target ∪ source_docs 找到 —— 未命中 → injected_terms[] /
                novel_phrases[] → **均作阻断**（2026-09-10 用户定案"任何长串天然都具有
                隐藏危险内容的能力"）；--acknowledge-injected 可逐项**显式豁免**（禁通配）。
  ② leading     枚举式检查项（①…②…）+ 断言谓词 + 括号答案提示 = 引导性提问 / 结论泄漏
                → leading_flags[] → **同样阻断**（升阻断依据 = 实测定性：历史 11 条真实 task
                + 10 条干净任务零误报，本轮事故用例正确命中 2 模式）
  ③ poison      复用 gk_narrow_route._POISON_MARKERS（单一事实源）
  ④ bounded     复用 gk_narrow_route._NT_MAX_TASK_LEN

窄任务写法（降低豁免负担，实测得出）：
  · 维度名**尽量复用目标文档的既有词汇**（能直接命中语料 ⇒ 不触发 provenance/长串阻断）；
  · **避免 `①②③` 枚举与括号清单**（会触发 `enumerated_items` / `parenthetical_answer_hint`）——
    改用逗号分隔的散文式维度陈述；
  · 禁写"方案内容/预期结论/已知答案"（那就是引导性提问，正是本节点要拦的东西）。

数据流（硬门禁：未裁决不下发）::

  plan-refinement <target> --task "…"
       └─> check()  → 写 gate_data.task_pipeline[]  status=pending   ⇒ **不调 cmd_monitor**
  plan-refinement --adjudicate <id> --decision approve
       └─> 取回记录 → cmd_monitor --subagent <full_task>
  # N8（2026-09-14）：<id> 可省略 或用 'last' ⟹ 取队尾 pending（gate_data.last_pending_id）
  # T1/T9（2026-10-05）：submit --count N ⟹ 一次入队 N 条（批级共享 `batch` 键）；
  #     批级出口 `resolve-ids --id last-batch` ⟹ 整批显式 id（旧 'last' 单条语义零回归）。

流契约（N7，2026-09-14）::

  stdout = **ECC**（subagent 结构化结果；逐行 json.loads 解析，禁 raw_decode）
  stderr = **落盘通知**（output_file / report_file / note；gatekeeper-cli.sh:2943 以 `>&2` 写出）
  ⟹ 消费端**禁** `> out.json 2>&1` 并流（会造出"伪拼接 JSON"，掩盖 conclusion 截断）。

CLI:
  python3 gk_task_gate.py check --task <t> --target <doc> [--source-docs a,b] [--acknowledge A,B]
  python3 gk_task_gate.py submit --state <f>            # 记录 JSON 自 stdin
  python3 gk_task_gate.py get --state <f> --id <id>
  python3 gk_task_gate.py list --state <f>
  python3 gk_task_gate.py adjudicate --state <f> --id <id> --decision approve|fix|drop [--note <n>] [--prepare]
  python3 gk_task_gate.py commit --state <f> --id <id> [--decision approve] [--note <n>]
      # F-REV-22：approve 用 --prepare（只校验不落盘）→ 下发成功后再 commit 定格；
      # fix/drop 无下发风险 → adjudicate 直接落盘（commit 仅作通用定稿口）。

Exit codes: 0 = OK；1 = error；2 = blocked（provenance/poison/schema 未豁免）。
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# 复用窄任务清单层的投毒词表与长度上限（单一事实源；两者同属"下发前入站门"，
# 不复制常量——复制即第二份事实源，正是本仓禁的形态）
from gk_gate_project_type import get_project_type  # noqa: E402
from gk_json_utils import (dump_state, state_lock,  # noqa: E402
                          STATE_SIZE_WALL, canon_bytes, ser_bytes,
                          TASK_PIPE_MAX_BYTES as _TASK_PIPE_MAX_BYTES)
from gk_narrow_route import (_NT_MAX_TASK_LEN, _POISON_MARKERS,  # noqa: E402
                             validate_group_constraints)
import gk_satellite  # noqa: E402 — 卫星片名单源（P1 中枢）

_CJK = "\u4e00-\u9fff"
_TASK_PIPE_KEY = "task_pipeline"
# F-REV-51（2026-09-14）：task_pipeline 保留上限。原实现只 append 无上限 ⟹ state 单调增长
# → 撞 gk_narrow_route 的 state_oversized（state > 256KB）→ **所有窄任务下发硬阻断**
# （死锁：无 sanctioned 清理通道，且下发正是唯一会继续增长的操作）。
# 口径对齐 subagent_history 的 20 条截断先例（gatekeeper-cli.sh L2885）：
# **pending 恒定保留**（未决不得丢），已决记录只保留最近 N 条。
_TASK_PIPE_MAX_RESOLVED = 20
_TASK_PIPE_RESOLVED = ("approved", "fix_required", "dropped")
# F-REV-51 复发（2026-10-04）：计数上限不防 262,144 **总墙**（每条 decided 含 full_task ≈ 数 KB）。
# 实测 state 撞 268,056 B ⟹ dispatch 被 F-REV-51 拦。补**字节**上限 + 溢出归档
# （对齐 <state>.history-archive.jsonl 先例：append-only、可回溯、不静默丢弃）。
# 2026-11-02（owner 裁定「收紧 payload 配额」）：数值**不再本地定义** —— 单源 =
# `gk_json_utils.TASK_PIPE_MAX_BYTES`（= 墙 × 5% = 128KB，与 history/findings 同比例）。
# 漂移由 `test_gk_state_trim_lines.py` 逐值守。
_TASK_PIPE_ARCHIVE_SUFFIX = gk_satellite.KIND_SUFFIX["pipeline"]  # 单源 = 中枢（禁第二份字面量）

# ── ① provenance: 专名提取（高精度优先）────────────────────────────────────
# 引号短语：agent 用引号包起来的东西 = 它自称"文档里的某个东西"
# 捕获类排除 `,;`：豁免串是逗号分隔的 CSV，词条含逗号会破坏往返（→ 无法豁免的死锁）。
_QUOTE_RE = re.compile("[\u300c\u300e\u201c\u300a]([^\u300d\u300f\u201d\u300b,;]{2,60})[\u300d\u300f\u201d\u300b]")
# ASCII 专名 token（含大写 / 下划线 / 点 / 连字符 / 数字 / 长度>=6 → 专名性）
_ASCII_PN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.\-]{1,40}")
# 常见英文泛词（长度>=6 但非专名；避免"review/proposal"这类被误报）
_EN_STOP = {
    "should", "target", "review", "before", "please", "report", "output", "expect",
    "result", "detail", "change", "config", "module", "object", "string", "number",
    "source", "format", "commit", "status", "single", "branch", "public", "system",
}
# CJK 段（按非 CJK 切分）：长度>=4 的连续汉字串
_CJK_SEG_RE = re.compile(rf"[^{_CJK}]+")
# 纯标签段（**精确整段匹配**才丢弃；不切词——避免把"统一调用方式改造方案"切碎）
_FRAMING = {
    "质询目标", "质询维度", "检查项", "待质询", "质询", "目标", "维度", "检查", "要求",
    "约束", "预期", "结论", "答案", "注意", "说明", "背景", "问题", "建议", "风险",
    "范围", "验收", "回退", "现状", "方案", "以及", "并且", "但是", "因此", "所以",
}

# 路径片段（Windows 盘符 / POSIX 多段）——结构性引用，其存在性由 preflight
# （plan_doc + source_docs 实存校验）负责，**不属"文档内容断言"** → 提取前剥离。
# 不剥离则 `<home>` 会产出 Users/HP 两个假"注入专名"（实测误报）。
_PATH_WIN_RE = re.compile(r"[A-Za-z]:[\\/][^\s,;\uff0c\uff1b)\uff09\]\u3011]*")
_PATH_POSIX_RE = re.compile(r"(?:/[\w.~-]+)+/?")


def strip_paths(text: str) -> str:
    t = _PATH_WIN_RE.sub(" ", text or "")
    return _PATH_POSIX_RE.sub(" ", t)


# ── ② leading: 引导性提问 / 结论泄漏 ────────────────────────────────────────
_ENUM_RE = re.compile(r"(?:[\u2460-\u2469]|\(\s*\d{1,2}\s*\)|\uff08\s*\d{1,2}\s*\uff09"
                      r"|\uff08[一二三四五六七八九十]{1,2}\uff09)")
_ASSERT_RE = re.compile(r"(应为|应当是|应该是|必须|务必|已确认|事实上|显然|一定存在|肯定|就是|属于)")
_PAREN_RE = re.compile(r"[\uff08(]([^\uff09)]{4,120})[\uff09)]")


def _read_text(p: str) -> str:
    try:
        return Path(p).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def collect_material(target_path: str, source_docs: str) -> tuple:
    """读 target ∪ source_docs 文本。返回 (material_text, unreadable[])。"""
    texts, unreadable = [], []
    if target_path:
        t = _read_text(target_path)
        (texts.append(t) if t else unreadable.append(target_path))
    for d in [s.strip() for s in (source_docs or "").split(",") if s.strip()]:
        t = _read_text(d)
        (texts.append(t) if t else unreadable.append(d))
    return "\n".join(texts), unreadable


def _pn_like(tok: str) -> bool:
    """ASCII token 的"专名性"判定（防把常见英文词当专名）。"""
    if tok.lower() in _EN_STOP:
        return False
    if any(c.isupper() for c in tok):
        return True
    if any(c in "_.-" for c in tok):
        return True
    if any(c.isdigit() for c in tok):
        return True
    return len(tok) >= 6


def ascii_proper_nouns(text: str) -> list:
    out, seen = [], set()
    for m in _ASCII_PN_RE.finditer(text or ""):
        tok = m.group(0).strip("._-")
        if len(tok) < 2 or tok.lower() in seen or not _pn_like(tok):
            continue
        seen.add(tok.lower())
        out.append(tok)
    return out


def cjk_segments(text: str) -> list:
    out, seen = [], set()
    for seg in _CJK_SEG_RE.split(text or ""):
        if len(seg) < 4 or seg in _FRAMING or seg in seen:
            continue
        seen.add(seg)
        out.append(seg)
    return out


def ack_set(acknowledge: str) -> set:
    """显式豁免项集合（逗号分隔，大小写折叠）。可含 provenance 专名 与 leading 模式名。"""
    return {a.strip().lower() for a in (acknowledge or "").split(",") if a.strip()}


def provenance_check(task: str, material: str, acknowledge: str = "") -> dict:
    """专名/新串相对语料的成员判定。
    injected_terms = 引号短语 + ASCII 专名 未命中（高精度）
    novel_phrases  = CJK 长串 未命中（2026-09-10 用户定案：**任何长串都能藏危险内容** →
                     同样作阻断依据，不再只是 advisory）
    acknowledge    = 逗号分隔的显式豁免项（命中则移出阻断集并记入 acknowledged）。"""
    ack = ack_set(acknowledge)
    mat = (material or "").lower()
    if not mat:
        return {"skipped": "material_unreadable", "injected_terms": [],
                "novel_phrases": [], "acknowledged": []}
    scan = strip_paths(task)

    raw_hi = []
    for q in _QUOTE_RE.findall(scan):
        q = q.strip()
        if len(q) >= 2 and q.lower() not in mat:
            raw_hi.append(q)
    raw_hi += [t for t in ascii_proper_nouns(scan) if t.lower() not in mat]

    injected, acknowledged = [], []
    seen = set()
    for t in raw_hi:
        k = t.lower()
        if k in seen:
            continue
        seen.add(k)
        (acknowledged if k in ack else injected).append(t)

    novel, nseen, novel_ack = [], set(), []
    for s in cjk_segments(scan):
        if s.lower() in mat or s in nseen:
            continue
        nseen.add(s)
        (novel_ack if s.lower() in ack else novel).append(s)
    return {"injected_terms": injected[:12], "novel_phrases": novel[:16],
            "acknowledged": acknowledged + novel_ack}


def leading_check(task: str) -> list:
    """引导性提问 / 结论泄漏标记（启发式，非阻断）。"""
    task = task or ""
    flags = []
    marks = _ENUM_RE.findall(task)
    parts = _ENUM_RE.split(task)
    items = [re.sub(r"\s+", " ", s).strip()[:80] for s in parts[1:] if s.strip()]
    if len(marks) >= 2:
        flags.append({"pattern": "enumerated_items", "count": len(marks),
                      "sample": items[:3]})
    asserts = []
    for a in _ASSERT_RE.findall(task):
        if a not in asserts:
            asserts.append(a)
    if asserts:
        flags.append({"pattern": "assertive_claim", "terms": asserts})
    hints = []
    for it in items:
        for pm in _PAREN_RE.findall(it):
            if len(re.findall(r"[、,，/]", pm)) >= 2:
                hints.append(pm[:80])
    if hints:
        flags.append({"pattern": "parenthetical_answer_hint", "sample": hints[:3]})
    return flags


def poison_scan(task: str) -> list:
    t = (task or "").lower()
    return [m for m in _POISON_MARKERS if m.lower() in t]


def make_id(target: str, task: str) -> str:
    h = hashlib.sha1(f"{target}\x00{task}".encode("utf-8")).hexdigest()[:8]
    return f"pr-{int(time.time())}-{h}"


def check(task: str, target_path: str, source_docs: str = "",
          acknowledge: str = "") -> dict:
    """四项检查合一。返回 JSON-ready dict（含 block_reasons[]）。

    阻断面（2026-09-10 用户定案"拦截一切未知长串"）：
      provenance_injected      — 引号短语 / ASCII 专名 未在语料可证
      novel_phrase_ungrounded  — CJK 长串 未在语料可证（任何长串都能藏危险内容 ⇒ 同等阻断）
      leading_question         — 枚举式检查项 / 断言谓词 / 括号答案提示（实测零误报后方升为阻断）
      poison_marker / schema_violation — 复用窄任务层词表与上限
    豁免 = --acknowledge-injected（逗号分隔；provenance 词条 或 leading 模式名）；响应带
    acknowledge_hint 便于原样粘贴（**禁通配**——豁免必须逐项转录，确保人工读过）。"""
    task = str(task or "")
    material, unreadable = collect_material(target_path, source_docs)
    ack = ack_set(acknowledge)

    violations = []
    if len(task) > _NT_MAX_TASK_LEN:
        violations.append({"rule": "task_too_long",
                           "detail": f"{len(task)} > {_NT_MAX_TASK_LEN}"})
    poison = poison_scan(task)
    prov = provenance_check(task, material, acknowledge)
    all_lead = leading_check(task)
    leading = [f for f in all_lead if f["pattern"].lower() not in ack]
    lead_ack = [f["pattern"] for f in all_lead if f["pattern"].lower() in ack]
    acknowledged = list(prov.get("acknowledged", [])) + lead_ack

    block_reasons = []
    if prov.get("injected_terms"):
        block_reasons.append("provenance_injected")
    if prov.get("novel_phrases"):
        block_reasons.append("novel_phrase_ungrounded")
    if leading:
        block_reasons.append("leading_question")
    if poison:
        block_reasons.append("poison_marker")
    if violations:
        block_reasons.append("schema_violation")

    hint_items = (list(prov.get("injected_terms", []))
                  + list(prov.get("novel_phrases", []))
                  + [f["pattern"] for f in leading])
    # ── 加载安全网·阻断响应自引导（ECC-73F9BD85C30F）────────────────────────────
    # 缺口（实测定性）：阻断响应只报「哪里不合规」（block_reasons[]），**不给**「下一步敲什么
    #   命令」⟹ 调用面只能靠人记得 `--acknowledge` / 记得改写法（`pipeline_over_wall` 只报墙、
    #   不给可执行出口 = 同病根的另一现场）。现补三要素（正本 = references/
    #   plugin-loading-test-framework.md §5「阻断响应自引导协议」）：
    #   · usage  = 本节点 CLI 形态（与模块文档字符串「CLI:」段同源）
    #   · limits = **运行时真值**（`_NT_MAX_TASK_LEN` / `_TASK_PIPE_MAX_BYTES` / `STATE_SIZE_WALL`
    #              均为导入的单源常量）—— **禁**在文案里写死字面量（复制即第二事实源）
    #   · next   = 可执行出口，**允许多条备选**（未阻断 ⟹ 空列表 = 零噪声）
    # **纯加性**：既有键 / 判据 / 返回码逐字不变（`ok` 只是 `blocked` 的显式对偶，旧消费者可忽略）。
    _next = []
    if any(v.get("rule") == "task_too_long" for v in violations):
        _next.append(
            "task 超上限 %d（运行时真值）⟹ 改写为散文式维度陈述（去 ①②③ 枚举、去括号清单、"
            "去断言谓词，逗号分隔），再跑：gk_task_gate.py check --task '<新 task>' --target <plan>"
            % _NT_MAX_TASK_LEN)
    if prov.get("injected_terms") or prov.get("novel_phrases"):
        _next.append(
            "逐项豁免（禁通配，须原样转录 acknowledge_hint）再跑：gk_task_gate.py check "
            "--task '<同一 task>' --target <plan> --acknowledge '<acknowledge_hint>'")
    if leading:
        _next.append(
            "去引导式写法（散文式维度、不写结论/答案）再跑：gk_task_gate.py check "
            "--task '<新 task>' --target <plan>")
    if poison:
        _next.append(
            "移除投毒词命中项再跑：gk_task_gate.py check --task '<新 task>' --target <plan>")
    return {
        "ok": not block_reasons,
        "next": _next,
        "usage": "gk_task_gate.py check --task <t> --target <doc> [--source-docs a,b] "
                 "[--acknowledge A,B] [--emit-record] [--state <f>]",
        "limits": {"task_len_max": _NT_MAX_TASK_LEN,
                   "pipeline_max_bytes": _TASK_PIPE_MAX_BYTES,
                   "state_size_wall": STATE_SIZE_WALL},
        "check": "task_gate",
        "id": make_id(target_path, task),
        "task_len": len(task),
        "material_chars": len(material),
        "material_unreadable": unreadable,
        "injected_terms": prov.get("injected_terms", []),
        "novel_phrases": prov.get("novel_phrases", []),
        "acknowledged": acknowledged,
        "provenance_skipped": prov.get("skipped", ""),
        "leading_flags": leading,
        "poison": poison,
        "schema_violations": violations,
        "block_reasons": block_reasons,
        "blocked": bool(block_reasons),
        "acknowledge_hint": ",".join(hint_items),
    }


def build_record(gate: dict, target: str, plan_path: str, task: str, full_task: str,
                 source_docs: str, tier: str = "", r_phase: str = "",
                 project_type: str = "") -> dict:
    """check() 结果 + 下发上下文 → pending 记录（交 submit 入队；不在此处写 state）。

    r_phase / project_type = **序列相位绑定**（2026-09-10 用户定案）：记录入队时所在序列
    上下文；adjudicate 时与当前 state 比对，不符即拒 ⇒ 防"standing 入队 / standard 批准"
    这类跨序列跨相位误消费（task_pipeline 是持久通道，见 F-REV-10 追记）。"""
    return {
        "id": gate["id"],
        "target": target,
        "plan_path": plan_path,
        "task": task,
        "full_task": full_task,
        "source_docs": source_docs,
        "tier": tier or "",
        "r_phase": r_phase or "",
        "project_type": project_type or "",
        "injected_terms": gate.get("injected_terms", []),
        "novel_phrases": gate.get("novel_phrases", []),
        "leading_flags": gate.get("leading_flags", []),
        "poison": gate.get("poison", []),
        "schema_violations": gate.get("schema_violations", []),
        "acknowledged": gate.get("acknowledged", []),
        "block_reasons": gate.get("block_reasons", []),
        "status": "pending",
    }


def task_in_pipeline(state_file: str, task: str) -> bool:
    """该 task 是否命中 gate_data.task_pipeline[] 的某条 full_task（统一入口归属校验）。

    2026-10-05（用户令「堵上裸跑质询裸窄任务通道」）：`cmd_monitor` 的显式 `--role plan-refinement`
    守卫消费本函数 —— 只有经统一入口 `plan-refinement <plan> --task …`（→ gk_task_gate submit）
    入队的 `full_task` 才放行；裸拼的任务串一律 `BARE_PLAN_REFINEMENT` 拦截。读失败/无 pipeline
    ⟹ False（fail-closed）。single-source = 本函数（禁 bash 侧第二份解析）。

    2026-11-01（二轮返工，比较侧 CRLF 归一）：存量 full_task 在组装入 state 时
    已烙进 \r\n（CRLF 跨平台病灶，18 处实锤），而裁决派发侧 bash $() 捕获
    Windows python print 又留尾 \r —— bash 侧无论剥不剥 \r 都无法同时对
    「存量含 CRLF」与「存量干净」两种数据都对（一轮 tr -d '\r' 即因此方向错误）。
    正解：本函数比较前把两侧 \r\n/\r 归一为 \n 后再精确比 —— 对脏存量、
    干净传入都 MATCH；对真正不同的 task 仍不等（fail-closed 语义不变）。
    """
    def _norm(s: str) -> str:
        return (s or "").replace("\r\n", "\n").replace("\r", "\n")

    try:
        d = load_state(state_file)
    except Exception:
        return False
    tp = (d.get("gate_data", {}) or {}).get("task_pipeline") or []
    want = _norm(task)
    return any(_norm(e.get("full_task") or "") == want for e in tp)


# ────────────────────────── state 队列（gate_data.task_pipeline[]）──────────
def _checksum(d: dict) -> str:
    """与 gatekeeper-cli.sh _state_write / gk_gate_checksum.py 同算法（必须一致）。"""
    gd = json.dumps(d.get("gate_data", {}), sort_keys=True)
    return hashlib.sha256(gd.encode()).hexdigest()[:16]


def load_state(state_file: str) -> dict:
    with open(state_file, encoding="utf-8") as f:
        return json.load(f)


def save_state(state_file: str, d: dict) -> None:
    """原子写 + 校验和刷新。委托 gk_json_utils.dump_state（state 序列化单一事实源：
    fsync + os.replace + ensure_ascii=False / indent=STATE_INDENT / LF）——原为
    write_json_file(indent=2)，2026-09-22 R2 归口到单一出纳，否则它是形态抖动的第二源。
    写失败 → 抛（fail-loud，禁静默丢记录）。"""
    d["_checksum"] = _checksum(d)
    if not dump_state(state_file, d):
        raise OSError(f"state write failed: {state_file}")


def state_context(state_file: str) -> dict:
    """从 state 读序列相位上下文（r_phase = 顶层字段；project_type 走 gk_gate_project_type
    单源，不复制默认值）。读不到 → 空串（调用方按"未绑定"处理，不误拒）。"""
    try:
        d = load_state(state_file)
    except Exception:
        return {"r_phase": "", "project_type": ""}
    try:
        ptype = get_project_type(state_file)
    except Exception:
        ptype = ""
    return {"r_phase": str(d.get("r_phase") or ""), "project_type": str(ptype or "")}


def pipeline(state_file: str) -> list:
    d = load_state(state_file)
    lst = d.get("gate_data", {}).get(_TASK_PIPE_KEY, [])
    return lst if isinstance(lst, list) else []


def _trim_decided(lst: list) -> list:
    """原地裁 decided（计数 + 字节双上限），返回被裁记录（**不归档**）。

    拆自 `_retain_pipeline` 的裁剪核 —— 单源供 ① 真出窗（+归档）② 入队投影（只算大小，
    T10）。pending 恒定保留（永不出窗）；索引法（非 `id()`）以防重复对象。
    """
    dropped: list = []

    def _take(idxs):
        drop = set(idxs)
        dropped.extend(r for i, r in enumerate(lst) if i in drop)
        lst[:] = [r for i, r in enumerate(lst) if i not in drop]

    idx = [i for i, r in enumerate(lst)
           if isinstance(r, dict) and r.get("status") in _TASK_PIPE_RESOLVED]
    excess = len(idx) - _TASK_PIPE_MAX_RESOLVED
    if excess > 0:
        _take(idx[:excess])
    # 字节上限：继续从**最旧 decided** 出窗（pending 永不出窗）
    while len(json.dumps(lst, ensure_ascii=False).encode()) > _TASK_PIPE_MAX_BYTES:
        dij = [i for i, r in enumerate(lst)
               if isinstance(r, dict) and r.get("status") in _TASK_PIPE_RESOLVED]
        if not dij:
            break
        _take([dij[0]])
    return dropped


def _retain_pipeline(lst: list, state_file: str = "", gd: dict = None) -> int:
    """task_pipeline 保留上限（F-REV-51）：pending 恒定保留，已决按**计数 + 字节**双上限出窗。

    原地截断，返回被裁剪条数。索引法（非 id()）以防重复对象。
    2026-10-04（复发）：仅计数上限不足以防 262,144 总墙（decided 各含 full_task 数 KB）
    ⟹ 补字节上限；出窗者**归档**到 `<state>.task-pipeline-archive.jsonl`（append-only，
    对齐 history 先例）；归档写失败**不阻断**（否则落库全失），但留 stderr 痕。
    裁剪核 = `_trim_decided` 单源（T10 起投影门复用）。
    2026-10-06（P1 后续 · c5 收敛）：片写**收敛为调中枢** `gk_satellite.append`（禁第二直写者）；
    本函数在 `save_state` **之前**被调 ⟹ 索引**必须 in-tx 并入 `gd`**（传 `gd`），**禁**另起 state
    写（否则随后 `save_state` 覆盖索引 = lost update）。
    """
    dropped = _trim_decided(lst)
    if dropped and state_file:
        try:
            import gk_satellite as _sat
            # [P2 修 · ECC-2E31D62BCCB8] **per-arm 索引键**（与 CLI history 面同口径）：同批多臂
            #   **各占一叶**（`arm`=条目自身 id / `batch_id`=条目 batch）。原固定字面量
            #   `pipeline-overflow`/`state` 会把同批多臂**坍缩到同一叶**互相覆盖索引项 ⟹
            #   c5「片数==臂数」在 pipeline 路径不成立。
            _groups: dict = {}
            for _e in dropped:
                _b = str((_e or {}).get("batch") or "pipeline-overflow")
                _a = str((_e or {}).get("id") or "state")
                _groups.setdefault((_b, _a), []).append(_e)
            for (_b, _a), _recs in _groups.items():
                _r = _sat.append(state_file, "pipeline", _recs,
                                 batch_id=_b, arm=_a, gd=gd)
                if not _r.get("ok"):
                    sys.stderr.write("TASK_PIPE_ARCHIVE_FAILED n=%d: %s\n"
                                     % (len(_recs), _r.get("error")))
        except Exception as e:  # noqa: BLE001 — 归档失败不阻断落库
            sys.stderr.write("TASK_PIPE_ARCHIVE_FAILED n=%d: %s\n" % (len(dropped), e))
    return len(dropped)


def pipeline_walls(lst: list, d: dict) -> dict:
    """T10 pending 侧**双墙**体检（纯函数，0 写盘）。

    内壁 = `task_pipeline` 序列化字节 ≤ `_TASK_PIPE_MAX_BYTES`（65536，operative）；
    总墙 = **整份 state** canon 字节 ≤ `STATE_SIZE_WALL`（2026-10-16 裁定 ×10 后 = 2621440）。`over` = 越墙轴列表
    （`pipeline_inner` / `state_global`）。口径单源：`ser_bytes`（内壁，与 `_trim_decided`
    同参）/ `canon_bytes`（总墙，与 `state_size_report` 同源）。
    """
    pb, sb = ser_bytes(lst), canon_bytes(d)
    over = (["pipeline_inner"] if pb > _TASK_PIPE_MAX_BYTES else []) + \
           (["state_global"] if sb > STATE_SIZE_WALL else [])
    return {"pipeline_bytes": pb, "state_bytes": sb,
            "inner_wall": _TASK_PIPE_MAX_BYTES, "global_wall": STATE_SIZE_WALL,
            "over": over}


_GROUP_LABELS = ("G1", "G2", "G3")
# 逐臂 `full_task` 的组标记（`_group_expand_records` 写入）= 组别**单源**。
# 派发端禁止按 id 列表下标推组：`_adj_ids` 顺序可与入队序不一致
# （L0 实跑：n3 被标成 G2）。
_GROUP_MARK_RE = re.compile(r"【本臂窄任务（(G[123])｜id=([^】]*)）】")


def group_label_of_full_task(text: str) -> str:
    """从 full_task 的组标记还原 G1/G2/G3；无标记 ⟹ ""（调用方回退）。"""
    m = _GROUP_MARK_RE.search(str(text or ""))
    return m.group(1) if m else ""


def narrow_id_of_full_task(text: str) -> str:
    """从 full_task 的组标记还原窄任务 id；无标记 ⟹ ""。"""
    m = _GROUP_MARK_RE.search(str(text or ""))
    return (m.group(2) or "").strip() if m else ""


def load_narrow_tasks_meta(path: str) -> tuple:
    """读窄任务 sidecar，返回 `(entries, meta)`。

    meta 携带 `coverage_target` / `assertion_registry`（与 `gk_narrow_route.register` 的同名
    输入同源）—— 读侧复算组语义时需要它；裸数组形态 ⟹ 空 meta（将因缺 coverage_target 被拒）。
    """
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return [], {}
    meta = {}
    if isinstance(d, dict):
        meta["coverage_target"] = d.get("coverage_target")
        meta["assertion_registry"] = d.get("assertion_registry")
        d = d.get("narrow_tasks")
    return (d if isinstance(d, list) else []), meta


def load_narrow_tasks_file(path: str) -> list:
    """读窄任务 sidecar（JSON list 或 `{"narrow_tasks": [...]}`）；不可读/格式错 ⟹ []。

    sidecar 名约定 = `<plan>.narrow.json`（`plan.md` ⟹ `plan.narrow.json`）；由
    `plan-refinement` 自动发现并**优先**于 state 里的全局 `gate_data.narrow_tasks[]`
    （后者是跨计划共享面 ⟹ 直接复用会把上一份计划的窄任务嵌进本计划的臂）。
    """
    return load_narrow_tasks_meta(path)[0]


def narrow_tasks_for_scope(tasks: list, scope: str) -> list:
    """按 plan 归属过滤全局窄任务；`scope` 空 ⟹ 不过滤（旧语义）。

    `scope` 非空时**只**保留显式声明了 `plan`/`plan_path`/`target` 且与 scope
    同路径（或同名 basename）的条目。未声明归属的条目一律排除 ⟹ 无 sidecar 的
    计划不可静默复用其他计划登记的清单（跨计划污染，`ECC-81883BA000AB`）。
    """
    lst = tasks if isinstance(tasks, list) else []
    if not scope:
        return lst
    base = os.path.basename(scope)
    out = []
    for e in lst:
        if not isinstance(e, dict):
            continue
        vals = [str(e.get(k) or "") for k in ("plan", "plan_path", "target")]
        if any(v and (v == scope or os.path.basename(v) == base) for v in vals):
            out.append(e)
    return out


def _group_expand_records(record: dict, narrow_tasks: list, k: int) -> list:
    """T1 消费端（2026-10-05）：按 3 组×K 把 `narrow_tasks[]` 的任务**逐臂嵌入 `full_task`**。

    顺序映射（disp-plan §3「index→组 的显式映射」）：前 K 条 → G1，次 K 条 → G2，末 K 条 → G3。
    每臂 `full_task = 原 full_task + 「【本臂窄任务（G#｜id=…）】\\n<task>」` ⟹ **逐臂逐字不同**，
    使 `cmd_monitor` 的 `BARE_PLAN_REFINEMENT` 守卫（`task_in_pipeline` 按逐臂 full_task 命中
    `task_pipeline`）自然通过；组别在 fan-out 端按**入队序** index//K 还原（record 不落 arm_group，
    对齐 disp-plan §0「arm_group 仅 dispatch 期注入」）。
    """
    out = []
    # 显式 `group` 优先（2026-10-21，`ECC-81883BA000AB`）：sidecar 逐条声明 G1/G2/G3 时，
    #   按组取前 K 条 —— 否则 K=1 只会取到清单前 3 条（第 3 组的 Q4 被挤掉）。无 group
    #   字段 ⟹ 保持位置映射（旧语义零回归）。
    if narrow_tasks and all(isinstance(t, dict) and t.get("group") in _GROUP_LABELS
                            for t in narrow_tasks):
        picked = []
        for g in _GROUP_LABELS:
            picked.extend([t for t in narrow_tasks if t.get("group") == g][:k])
        if len(picked) >= 3 * k:
            narrow_tasks = picked
    for i in range(3 * k):
        nt = narrow_tasks[i] if isinstance(narrow_tasks[i], dict) else {}
        g = _GROUP_LABELS[i // k]
        tid = str(nt.get("id") or "")
        t = str(nt.get("task") or nt.get("name") or "")
        r = dict(record)
        r["full_task"] = "%s\n\n【本臂窄任务（%s｜id=%s）】\n%s" % (
            str(record.get("full_task") or ""), g, tid, t)
        out.append(r)
    return out


def submit(state_file: str, record: dict, count: int = 1,
           expand_groups: bool = False, k: int = 0,
           narrow_tasks_file: str = "", narrow_scope: str = "") -> dict:
    # 2026-09-25（选项 A）：读-改-写整体持锁（否则并发入队丢记录）。
    # T1（2026-10-05，n4）：`count=N` 一次入队 N 条 pending（MoA 3 组×K 臂的承载面）。
    #   · id 唯一性：>1 时对 2..N 条加盐 `-<i>`（同 target+task 同秒 `make_id` 会撞 id）；
    #   · 批级消解键：>1 时给每条落 `batch`=基础 id（T9 `resolve_ids('last-batch')` 的单源键，
    #     见 §3「映射非 record 字段」——`batch` 是**批身份**，非 arm_group；单条不加 ⟹ 零回归）。
    # T1 消费端（2026-10-05）：`expand_groups=True` 且 `narrow_tasks[]` ≥ 3×K ⟹ 逐臂嵌入组任务
    #   （见 `_group_expand_records`）；否则**回退同名复制**（旧语义零回归，`group_tasks:false`）。
    try:
        n = int(count)
    except (TypeError, ValueError):
        n = 1
    if n < 1:
        n = 1
    try:
        kk = int(k)
    except (TypeError, ValueError):
        kk = 0
    with state_lock(state_file):
        d = load_state(state_file)
        gd = d.setdefault("gate_data", {})
        lst = gd.setdefault(_TASK_PIPE_KEY, [])
        if not isinstance(lst, list):
            return {"ok": False, "error": "task_pipeline_not_list"}
        records, group_tasks = None, False
        narrow_source = ""
        if expand_groups and kk >= 1:
            # 2026-10-28（窄任务门治理）：K 下限 = 2（每组 ≥2 才能构成「相同对 / 互补对」）。
            #   K=1 只有显式声明才放行（stderr 留痕 WARN ARMS_PER_GROUP_K1_EXPLICIT）；否则 fail-closed。
            if kk < 2 and os.environ.get("GK_ALLOW_ARMS_PER_GROUP_1") != "1":
                return {"ok": False, "error": "k_below_min", "need_min": 2, "got": kk,
                        "hint": "3 组 MoA 要求每组 ≥2 条（G1 相同对 / G2 互补对都要成对）；"
                                "确需 K=1 请显式 export GK_ALLOW_ARMS_PER_GROUP_1=1（留痕）"}
            if kk < 2:
                # 显式声明才走到这里：留痕（语义约束一条不减，只放宽每组条数下限）。
                sys.stderr.write("WARN ARMS_PER_GROUP_K1_EXPLICIT k=%d（GK_ALLOW_ARMS_PER_GROUP_1=1）\n" % kk)
            if narrow_tasks_file:
                # sidecar 优先（2026-10-21，`ECC-81883BA000AB`）：`gate_data.narrow_tasks[]`
                # 是跨计划共享面，直接复用会把上一份计划的窄任务嵌进本计划的臂。sidecar
                # 给了就必须自足：不足 3×K ⟹ fail-closed，**不回退**全局清单（禁静默混源）。
                nt, _nt_meta = load_narrow_tasks_meta(narrow_tasks_file)
                narrow_source = "sidecar"
                if len(nt) < 3 * kk:
                    return {"ok": False, "error": "narrow_tasks_file_insufficient",
                            "file": narrow_tasks_file, "need": 3 * kk, "got": len(nt),
                            "hint": "sidecar 须含 ≥3×K 条 {id,task}；禁止回退 state 全局清单"}
            else:
                nt = gd.get("narrow_tasks") or []
                # 无 sidecar 时按 plan 归属过滤（scope 非空）：不属于本计划的条目
                # （含未声明归属的旧条目）一律不参与 ⟹ 无 sidecar 的计划 fail-closed，
                # 而不是静默复用别的计划的清单。
                nt = narrow_tasks_for_scope(nt, narrow_scope)
                narrow_source = "state_scoped" if narrow_scope else "state"
                # register 落盘的派生元数据（单源，供读侧复算，禁第二份推导）
                _nt_meta = {"coverage_target": gd.get("narrow_coverage_target"),
                            "assertion_registry": gd.get("narrow_assertion_registry")}
            # 2026-10-28（读侧复算，堵 P1/P2）：**语义校验不能只在写侧**。原读侧唯一判据是
            #   `len(nt) >= 3*K` ⟹ 手写 sidecar（裸 {id,task}）或整表替换 state 都能让「数量够但
            #   语义空」的清单进队。此处对**两种载体**都跑同一 `validate_group_constraints`
            #   （单源，禁第二实现）；非 grouped 模式亦视为不合格（旧清单须显式逃生）。
            #   顺序：先够不够（narrow_tasks_insufficient），再合不合格（narrow_groups_invalid）
            #   —— 两个错误面各自可操作，不混成一句。
            if isinstance(nt, list) and len(nt) >= 3 * kk:
                _cons = validate_group_constraints(
                    nt, _nt_meta.get("coverage_target"), _nt_meta.get("assertion_registry"),
                    min_k=kk)
                if not (_cons.get("mode") == "grouped" and _cons.get("ok")):
                    if os.environ.get("GK_ALLOW_NARROW_LEGACY") != "1":
                        return {"ok": False, "error": "narrow_groups_invalid",
                                "narrow_source": narrow_source, "constraints": _cons,
                                "hint": "窄任务须为三组（G1 相同对 / G2 正交互补 / G3 污染）并通过"
                                        "组约束；注册走 `state-patch --narrow-register <json>`。"
                                        "确需旧式无组清单请显式 export GK_ALLOW_NARROW_LEGACY=1（留痕）"}
                    sys.stderr.write(
                        "WARN narrow_groups_invalid 被 GK_ALLOW_NARROW_LEGACY=1 放行: %s\n"
                        % json.dumps(_cons.get("violations") or [], ensure_ascii=False)[:300])
                records = _group_expand_records(record, nt, kk)
                group_tasks = True
            elif os.environ.get("GK_ALLOW_GROUP_FALLBACK") != "1":
                # 2026-10-14（用户裁定，**改契约**）：expand 求 3×K 条窄任务而清单不足 ⟹ **fail-closed**。
                #   原为静默回退同名复制（旧 fail-soft 契约，被 test_gk_task_gate_group_tasks arm3 钉死）
                #   ⟹ 把「3 组 MoA」静默降级成 3×K 个**同题**样本（组别只剩 index 标签）= 假 MoA。
                #   显式逃生 `GK_ALLOW_GROUP_FALLBACK=1` 保留无清单的合法旧语义（显式而非静默）。
                return {"ok": False, "error": "narrow_tasks_insufficient",
                        "need": 3 * kk, "got": len(nt) if isinstance(nt, list) else 0,
                        "narrow_source": narrow_source, "narrow_scope": narrow_scope,
                        "hint": "先登记窄任务清单（≥3×K 条）：`<plan>.narrow.json` sidecar，"
                                "或 state-patch --narrow-register <json>（条目须带 plan/plan_path 归属）；"
                                "或 GK_ALLOW_GROUP_FALLBACK=1 显式降级为同名复制"}
        if records is None:
            records = [dict(record) for _ in range(n)]
        total = len(records)
        base = str(record.get("id") or "")
        # 先把 id/batch/时间戳定形（投影门须按**最终**记录形态计量）
        for i, r in enumerate(records):
            if i > 0:
                r["id"] = "%s-%d" % (base, i)
            r.setdefault("status", "pending")
            r.setdefault("created_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            if total > 1:
                r["batch"] = base
        # T10（n4 §2-T10 / §10-M2）：pending 侧**双墙投影门**（先证后落）—— append 前先证合规。
        #   投影 =「既有 pipeline + 新批」过一遍 decided 裁剪（复用 `_trim_decided` 单源）
        #   ⟹ 与真落刀后的稳态同尺寸。越墙 ⟹ fail-loud 拒整批、**零写盘**（pending 恒定保留，
        #   出口 = 先消解既有 pending（adjudicate/commit）或裁 decided 后重试）。
        _probe = list(lst) + list(records)
        _trim_decided(_probe)
        _d_probe = dict(d)
        _gd_probe = dict(gd)
        _gd_probe[_TASK_PIPE_KEY] = _probe
        _d_probe["gate_data"] = _gd_probe
        walls = pipeline_walls(_probe, _d_probe)
        if walls["over"]:
            return {"ok": False, "error": "pipeline_over_wall", **walls,
                    "hint": "pending 越墙：先消解既有 pending（adjudicate/commit）或裁 decided "
                            "后重试（pending 恒定保留，不自动丢）"}
        # —— 落刀（真出窗 + 归档）——
        ids, first = [], None
        for r in records:
            lst.append(r)
            if first is None:
                first = r
            ids.append(r.get("id", ""))
        pruned = _retain_pipeline(lst, state_file, gd)   # F-REV-51：已决超上限 → 原地裁剪 + 溢出归档（索引 in-tx 并入 gd）
        # N8（2026-09-14）：入队 id 自动透传 —— 记 last_pending_id，供下一段
        # （--adjudicate / --adjudicate last）省去手抠 <id>（state 单源，无新约定）。
        gd["last_pending_id"] = ids[-1] if ids else ""
        save_state(state_file, d)
        return {"ok": True, "record": first, "ids": ids,
                "queue_len": len(lst), "pruned": pruned, "group_tasks": group_tasks,
                "narrow_source": narrow_source, "budget": walls}


def resolve_id(state_file: str, rid: str) -> str:
    """N8（2026-09-14）入队 id 自动透传。

    空串 或 'last' ⟹ 取**队尾 pending**（回退 `gate_data.last_pending_id`）；
    显式 id 原样返回（向后兼容）。id 形如 `pr-<ts>-<hex8>`，故 'last' 不与其冲突。
    """
    if rid and rid != "last":
        return rid
    rows = [r for r in pipeline(state_file) if isinstance(r, dict)]
    for r in reversed(rows):
        if r.get("status") == "pending":
            return str(r.get("id") or "")
    d = load_state(state_file)
    return str((d.get("gate_data") or {}).get("last_pending_id") or "")


def resolve_ids(state_file: str, rid: str) -> list:
    """T9（2026-10-05）：**批级消解出口**（M1：原只取队尾单条、无 batch 维度）。

    · `rid == "last-batch"` ⟹ 队尾 pending 所属**批**的全部 pending id（入队序）；
      「批」由 `submit(count>1)` 落的 `batch` 键单源界定（见 submit）。无 `batch` 键
      （单条 / 旧记录）⟹ 回退 `[last]`（**单条**，与旧语义同）。
    · 其余（空 / `'last'` / 显式 id）⟹ `[resolve_id(state_file, rid)]` —— **旧单条语义零回归**（§4-R9）。

    ⚠ 只改**新增**面：`resolve_id` 本体不动（旧路径 `--adjudicate last` 逐字不变）。
    """
    if rid != "last-batch":
        return [resolve_id(state_file, rid)]
    last = resolve_id(state_file, "last")
    if not last:
        return []
    rec = find_record(state_file, last)
    b = str((rec or {}).get("batch") or "")
    if not b:
        return [last]
    return [str(r.get("id") or "") for r in pipeline(state_file)
            if isinstance(r, dict) and r.get("status") == "pending"
            and str(r.get("batch") or "") == b]


def find_record(state_file: str, rid: str) -> dict:
    for r in pipeline(state_file):
        if isinstance(r, dict) and r.get("id") == rid:
            return r
    return {}


def adjudicate(state_file: str, rid: str, decision: str, note: str = "",
               persist: bool = True) -> dict:
    """裁决记录。approve + persist=False（CLI --prepare）→ **只校验不落盘**，返回下发载荷；
    下发成功后须调 commit() 才把状态定格为 approved（F-REV-22：修"先落盘后下发"顺序缺陷）。"""
    mapping = {"approve": "approved", "fix": "fix_required", "drop": "dropped"}
    if decision not in mapping:
        return {"ok": False, "error": f"unknown decision '{decision}'",
                "valid": sorted(mapping)}
    rid = resolve_id(state_file, rid)   # N8：空 或 'last' ⟹ 队尾 pending
    # 2026-09-25（选项 A）：读-改-写整体持锁（早退分支在 `with` 内 return 会正常释放锁）。
    with state_lock(state_file):
        d = load_state(state_file)
        target = None
        for r in d.get("gate_data", {}).get(_TASK_PIPE_KEY, []) or []:
            if isinstance(r, dict) and r.get("id") == rid:
                target = r
                break
        if target is None:
            return {"ok": False, "error": f"no pending task '{rid}'"}

        # ── 序列相位绑定比对（2026-09-10 用户定案）：入队上下文 ≠ 当前上下文 → 拒 ──
        # 记录未绑定（空串）= 旧记录 → 跳过（向后兼容，不误拒）。
        cur = state_context(state_file)
        mism = []
        for key, label in (("r_phase", "r_phase"), ("project_type", "project_type")):
            rec_v = str(target.get(key) or "")
            cur_v = str(cur.get(key) or "")
            if rec_v and cur_v and rec_v != cur_v:
                mism.append(f"{label} {rec_v} → {cur_v}")
        if mism:
            return {"ok": False, "error": "phase_mismatch", "detail": "; ".join(mism),
                    "record_context": {k: target.get(k) for k in ("r_phase", "project_type")},
                    "current_context": cur,
                    "hint": "记录入队上下文与当前 state 不符（跨序列/跨相位误消费防护）"
                            "→ 在当前上下文中重新入队（会重跑入站门）"}

        # ── F-REV-22：approve 的下发给定 —— 先下发、成功后才落状态 ──
        # 原实现无条件先写 status=approved；下发的 review-channel preflight 一旦阻断
        # （如 CONTEXT_STALE_OR_UNSIGNED），记录已被消费成 approved 却**从未派发**（滞留），
        # 且只能靠"adjudicate 无 status 过滤、重跑再派发"侥幸补救。现 approve 走
        # persist=False：只校验相位/存在性并返回 full_task/tier，状态保持 pending；
        # 下发成功后由 commit() 定格。失败 → 记录留 pending，修好即可重试（或 drop）。
        if decision == "approve" and not persist:
            return {"ok": True, "dispatch": True, "deferred": True,
                    "full_task": target.get("full_task", ""),
                    "tier": target.get("tier", ""),
                    "record": target,
                    "next": f"commit --state <f> --id {rid} --decision approve"}

        target["status"] = mapping[decision]
        target["decision"] = decision
        target["decided_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if note:
            target["note"] = note
        # F-REV-51 复发（2026-10-04）：同 commit —— decided 增长即触发上限 + 归档
        # [P1 修 · ECC-96CEAA0CC833] 本函数是 `_retain_pipeline` 的**第三个**调用点（旁：submit/commit）。
        #   须 in-tx 传 `gd`：否则中枢走 standalone 经 set-nested 写 state，随后 `save_state(d)`
        #   （本函数开头的旧快照，不含 satellite_index）把索引**静默抹除** = lost update。
        _gd = d.get("gate_data", {})
        _retain_pipeline(_gd.setdefault(_TASK_PIPE_KEY, []), state_file, _gd)
        save_state(state_file, d)
        return {"ok": True, "record": target,
                "dispatch": decision == "approve",
                "full_task": target.get("full_task", "")}


def commit(state_file: str, rid: str, decision: str = "approve", note: str = "") -> dict:
    """下发成功后落状态（F-REV-22）：把记录定格为 approved/fix_required/dropped。
    由调用方在**下发成功之后**调用，故不会产生「已批准但未派发」的滞留记录。"""
    mapping = {"approve": "approved", "fix": "fix_required", "drop": "dropped"}
    if decision not in mapping:
        return {"ok": False, "error": f"unknown decision '{decision}'",
                "valid": sorted(mapping)}
    rid = resolve_id(state_file, rid)   # N8：空 或 'last' ⟹ 队尾 pending
    # 2026-09-25（选项 A）：读-改-写整体持锁。
    with state_lock(state_file):
        d = load_state(state_file)
        target = None
        for r in d.get("gate_data", {}).get(_TASK_PIPE_KEY, []) or []:
            if isinstance(r, dict) and r.get("id") == rid:
                target = r
                break
        if target is None:
            return {"ok": False, "error": f"no pending task '{rid}'"}
        target["status"] = mapping[decision]
        target["decision"] = decision
        target["decided_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if note:
            target["note"] = note
        # F-REV-51 复发（2026-10-04）：decided 增长也须触发上限（原只在 submit 触发）
        _gd = d.get("gate_data", {})
        _retain_pipeline(_gd.setdefault(_TASK_PIPE_KEY, []), state_file, _gd)
        save_state(state_file, d)
        return {"ok": True, "record": target, "dispatch": decision == "approve",
                "full_task": target.get("full_task", "")}


def list_pending(state_file: str) -> dict:
    rows = [{"id": r.get("id"), "status": r.get("status"),
             "target": Path(str(r.get("target", ""))).name,
             "injected": len(r.get("injected_terms", []) or []),
             "novel": len(r.get("novel_phrases", []) or []),
             "leading": len(r.get("leading_flags", []) or []),
             "acked": len(r.get("acknowledged", []) or [])}
            for r in pipeline(state_file) if isinstance(r, dict)]
    return {"ok": True, "queue_len": len(rows),
            "pending": [r for r in rows if r.get("status") == "pending"],
            "all": rows}


# ────────────────────────── CLI ──────────────────────────
def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="入站窄任务数据管道节点")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="四项检查（不写 state）")
    c.add_argument("--task", default="")
    c.add_argument("--target", default="", help="target 文档路径（读作语料）")
    c.add_argument("--source-docs", default="")
    c.add_argument("--acknowledge", default="", help="显式豁免的注入项（逗号分隔）")
    c.add_argument("--emit-record", action="store_true",
                   help="未阻断时输出 pending 记录 JSON（供 submit 入队）而非检查报告")
    c.add_argument("--target-name", default="", help="记录内 target 显示名（默认同 --target）")
    c.add_argument("--full-task", default="", help="拼装后的下发文本（记录用）")
    c.add_argument("--tier", default="")
    c.add_argument("--state", default="",
                   help="state 文件：读入队上下文（r_phase / project_type）作相位绑定")

    s = sub.add_parser("submit", help="追加 pending 记录（记录 JSON 自 stdin；调用方持锁）")
    s.add_argument("--state", required=True)
    s.add_argument("--count", type=int, default=1,
                   help="T1：一次入队 N 条（id 加盐唯一 + 落 batch 键）；缺省 1 = 旧语义")
    s.add_argument("--expand-groups", action="store_true",
                   help="T1 消费端：按 3×K 从 gate_data.narrow_tasks[] 逐臂嵌入组任务；"
                        "条目不足 ⟹ 回退同名复制（group_tasks:false，零回归）")
    s.add_argument("--k", type=int, default=0,
                   help="每组臂数 K（--expand-groups 时用；缺省 0 ⟹ 不展开）")
    s.add_argument("--narrow-tasks-file", default="",
                   help="窄任务 sidecar（JSON list 或 {narrow_tasks:[...]}）；优先于 state 全局清单，"
                        "不足 3×K ⟹ fail-closed（不回退，禁跨计划混源）")
    s.add_argument("--narrow-scope", default="",
                   help="无 sidecar 时按该 plan 路径过滤 state 全局 narrow_tasks[]；"
                        "不匹配/未声明归属的条目一律排除 ⟹ 无 sidecar 的计划 fail-closed")

    g = sub.add_parser("get", help="取单条记录")
    g.add_argument("--state", required=True)
    g.add_argument("--id", required=True)

    ri = sub.add_parser("resolve-ids", help="T9：批级/单条 id 消解（last-batch ⟹ 整批）")
    ri.add_argument("--state", required=True)
    ri.add_argument("--id", default="",
                    help="'last-batch' ⟹ 队尾 pending 所属批的全部 id；其余同 resolve_id")

    l = sub.add_parser("list", help="列队列")
    l.add_argument("--state", required=True)

    a = sub.add_parser("adjudicate", help="裁决")
    a.add_argument("--state", required=True)
    a.add_argument("--id", default="",
                   help="N8：省略 或 'last' ⟹ 队尾 pending（state 单源 last_pending_id）")
    a.add_argument("--decision", required=True, choices=["approve", "fix", "drop"])
    a.add_argument("--note", default="")
    a.add_argument("--prepare", action="store_true",
                   help="F-REV-22：仅 approve —— 只校验并返回下发载荷，不落状态（下发成功后由 commit 定格）")

    cm = sub.add_parser("commit", help="下发成功后落状态（F-REV-22）")
    cm.add_argument("--state", required=True)
    cm.add_argument("--id", default="",
                    help="N8：省略 或 'last' ⟹ 队尾 pending")
    cm.add_argument("--decision", default="approve", choices=["approve", "fix", "drop"])
    cm.add_argument("--note", default="")

    args = p.parse_args(sys.argv[1:] if argv is None else argv)

    try:
        if args.cmd == "check":
            out = check(args.task, args.target, args.source_docs, args.acknowledge)
            if args.emit_record and not out["blocked"]:
                ctx = state_context(args.state) if args.state else {"r_phase": "", "project_type": ""}
                rec = build_record(out, args.target_name or args.target, args.target,
                                   args.task, args.full_task, args.source_docs, args.tier,
                                   r_phase=ctx["r_phase"], project_type=ctx["project_type"])
                print(json.dumps(rec, ensure_ascii=True))
                return 0
            print(json.dumps(out, ensure_ascii=True))
            return 2 if out["blocked"] else 0
        if args.cmd == "submit":
            raw = sys.stdin.read()
            rec = json.loads(raw) if raw.strip() else {}
            out = submit(args.state, rec, count=args.count,
                         expand_groups=args.expand_groups, k=args.k,
                         narrow_tasks_file=args.narrow_tasks_file or "",
                         narrow_scope=args.narrow_scope or "")
            print(json.dumps(out, ensure_ascii=True))
            return 0 if out.get("ok") else 1
        if args.cmd == "get":
            rec = find_record(args.state, args.id)
            ok = bool(rec)
            print(json.dumps({"ok": ok, "record": rec} if ok
                             else {"ok": False, "error": "not_found"}, ensure_ascii=True))
            return 0 if ok else 1
        if args.cmd == "resolve-ids":
            ids = resolve_ids(args.state, args.id)
            print(json.dumps({"ok": True, "ids": ids}, ensure_ascii=True))
            return 0
        if args.cmd == "list":
            print(json.dumps(list_pending(args.state), ensure_ascii=True))
            return 0
        if args.cmd == "adjudicate":
            if args.prepare and args.decision != "approve":
                print(json.dumps({"ok": False, "error": "--prepare 仅适用于 --decision approve"},
                                 ensure_ascii=True))
                return 1
            out = adjudicate(args.state, args.id, args.decision, args.note,
                             persist=not args.prepare)
            print(json.dumps(out, ensure_ascii=True))
            return 0 if out.get("ok") else 1
        if args.cmd == "commit":
            out = commit(args.state, args.id, args.decision, args.note)
            print(json.dumps(out, ensure_ascii=True))
            return 0 if out.get("ok") else 1
    except Exception as e:  # noqa: BLE001 — CLI 边界：任何异常都要 fail-loud 成 JSON
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"},
                         ensure_ascii=True))
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
