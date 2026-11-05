#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""计划写入安全网（PW-SN）linter（确定性层）。

对**计划文档**做机检，与 `plan-refinement`（LLM 质询层）对偶：
质询层判语义（D5 单源 / D6 偏差），本层判**机检项**（锚点/编号/开关/消费者/判据可执行性）。

依据：`references/plan-writing-safety-net.md`「七轨对位表」的『机检』列。
实测口径：2026-09-14 12 臂实验的 18 条命中中，**11 条（61%）**只靠 `rg`/行比对/清单差集即可拦下。

用法:
    python scripts/gk_plan_lint.py <plan.md> [--repo <skill_root>] [--json]
退出码:
    0 = 无 high/medium finding；1 = 有
级别:
    high   = 明确错误（锚点越界 / **锚点断言与符号不同源（漂移）** / 假设撞号 /
             新开关无默认值 / 消费者数不符 / **META 块缺失或 phases 空** / **符号撞车**）
    medium = 可疑（判据无可执行命令 / 列表编号重复 / **META 缺字段** / **名称挂多符号**）
    info   = 提示（外部不可核引用 —— 须声明为外部依赖或改为仓内锚；
             **断言字面值未在所锚文件逐字出现 ⟹ 该锚不可校验**（F-REV-67 ①）；
             **裸符号锚遇符号多义（同符多实现）⟹ 不可判定**（F-REV-67 ②））

锚引用提取 = `iter_anchor_refs()` **单一事实源**（与 `gk_doc_align.anchor_existence` 共用；
分工见该函数上方注释 —— 漂移检测只在 doc-align，本模块只做**可判定断言**）。
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys

CHECK_ANCHOR = "L-ANCHOR"        # F2 证据：file:line 锚点可解
CHECK_ASSUME = "L-ASSUME"        # F3 假设：定义处编号唯一
CHECK_SWITCH = "L-SWITCH"        # F4 恢复：新开关须有默认值 + §6 行
CHECK_CONSUMER = "L-CONSUMER"    # F1 范围：自称"N 消费者"须与实测 import 数一致
CHECK_CRITERION = "L-CRITERION"  # 7 维：判据须含可执行命令
CHECK_NUMBER = "L-NUMBER"        # 结构：同一编号块内唯一
CHECK_META = "L-META"            # F8 元数据：`<!-- META -->` 头块 + 必备字段可解析
CHECK_SYMBOL = "L-SYMBOL"        # 符号：符号表内 / 跨文档 **同符异义**（撞车，2026-09-14）
CHECK_DEP = "L-DEP-FINDING"      # §17 机械依赖门：声明块内 depends_on_closed 未 close ⟹ 拒落刀
CHECK_LABEL = "L-LABEL"          # 段标题尾部的「（<前缀><数字>）」标签：同族基标签 <前缀>1 全文缺席 ⟹ 悬空
CHECK_PLAN_LETTER = "L-PLAN-LETTER"   # 跨计划引用任务号须带计划字母前缀（`ECC-F5255744DDD3`，2026-10-16）
# ── PW-SN 增量（Infra-3，2026-10-05；规则源 = `docs/plans/2026-10-04-...plan §9`）──
CHECK_PW_LANDING = "PW-LANDING"          # PW-2 幻影落刀点：落刀点列路径须实存
CHECK_PW_SEC = "PW-BARE-SEC"             # PW-3 裸节号/错引：带日期文档只有 § 无 `.md` 路径
CHECK_PW_LANDING_DUP = "PW-LANDING-DUP"  # PW-4 落刀点重叠（双拆）：同 token 出现在 ≥2 行任务
CHECK_PW_ASSUME = "PW-ASSUME"            # PW-8 假设三要素（依据/可测/状态）
CHECK_PW_CONST = "PW-CONST"              # PW-9 常量名实存（墙/上限语境）
# PW-10/11/12（2026-10-08，承 §23.8.2 L 类）—— edit-budget §23 一轮质询的防复发机检。
CHECK_PW_WRITE_IMPL = "PW-WRITE-IMPL"    # PW-10 幻影单源（「单源/委托 fn」在生产侧零出现）
CHECK_PW_WRITE_ONLY = "PW-WRITE-ONLY"    # PW-11 只写不读（read_*/count_* 生产侧零出现）
CHECK_PW_FORM_SUFFIX = "PW-FORM-SUFFIX"  # PW-12 形态清单后缀覆盖（.seal 未入 _ARTIFACT_SUFFIXES）
CHECK_VERSION = "L-VERSION"             # 口径：同一计划内 `DRAFT-<n>` 版本号唯一（多值 ⟹ 口径互斥）
# ── PW-SN 增量（F3，2026-10-15）：**下发门预演** —— 防 task 下发失败（D §14.7 F-D 回流）──
CHECK_PW_DISPATCH = "PW-DISPATCH"       # PW-13 下发门预演：语料可证 / 长串未证 / 语料不可读 / 状态域路由

_EXT = r"(?:py|sh|md|json|ts|js|tsx|txt|yaml|yml)"
_RE_ANCHOR = re.compile(r"([A-Za-z0-9_./\\-]+\.%s):[#]?L?(\d+)(?:-L?(\d+))?" % _EXT)

# ── 行锚自校验（F2/D2「行号处字面值 == 断言」）────────────────────────────
# 断言字面值须与锚点**同源**（作者显式绑定）。三种高置信绑定形态，宁缺毋滥：
#   ①  同 backtick 绑定：`file.py:123 sym`  /  `sym`（`file.py:123`）
#   ②  紧随括号内代码片段：`file.py:123`（… `break 2` …）—— 片段含空格/运算符者
#   ③  裸符号锚：`sym:123`  /  `sym`（**`:123`**）—— sym 须在仓内**唯一**定义
_RE_ANCHOR_SYM = re.compile(
    r"`([A-Za-z0-9_./\\-]+\.%s):[#]?L?(\d+)(?:-L?(\d+))?\s+([A-Za-z_][A-Za-z0-9_]*)\s*`" % _EXT)
# ── A2（2026-09-28，ECC-F68E6BEE4F68）：`path#L123 sym`（**无冒号**）形态的绑定口径 ──
# 与上面两条写侧口径**分开定义**，且**只**给重钉面（`gk_doc_align._bound_symbol` 的 fallback）
#   用：上面两条被 `plan-lint` 的 `anchor_findings` 消费 ⟹ 就地开宽会动到冻结计数面
#   （同本模块 `anchor_no_assertion` 那条的 R-16 D-3 教训）。故此处**另立**、不动它们。
# 组布局与各自的原口径逐字同构（`_ANCHOR_SYM_HASHL`：1=文件 2=起 3=止 4=符号）。
_RE_ANCHOR_SYM_HASHL = re.compile(
    r"`([A-Za-z0-9_./\\-]+\.%s)#L(\d+)(?:-L?(\d+))?\s+([A-Za-z_][A-Za-z0-9_]*)\s*`" % _EXT)
_RE_SYM_BEFORE_HASHL = re.compile(
    r"`([A-Za-z_][A-Za-z0-9_]{2,})`[^`\n|]{0,14}`([A-Za-z0-9_./\\-]+\.%s)#L(\d+)(?:-L?(\d+))?`" % _EXT)
# ①b 符号前置绑定：`sym` … `file.py:123`（间隔**不得含 `|`** —— 防**表格邻格**符号被错绑）
_RE_SYM_BEFORE = re.compile(
    r"`([A-Za-z_][A-Za-z0-9_]{2,})`[^`\n|]{0,14}`([A-Za-z0-9_./\\-]+\.%s):[#]?L?(\d+)(?:-L?(\d+))?`" % _EXT)
# ③b 符号前置 + 裸行锚：`sym`（**`:123`**）（间隔同样禁 `|`）
_RE_SYM_BAREB = re.compile(
    r"`([A-Za-z_][A-Za-z0-9_]{2,})`\s*[（(][^`()（）\n|]{0,10}`:L?(\d+)(?:-L?(\d+))?`")
_RE_SYM_ANCHOR = re.compile(r"`([A-Za-z_][A-Za-z0-9_]{2,}):[#]?L?(\d+)(?:-L?(\d+))?`")
_RE_LITERAL = re.compile(r"`([^`\n]{2,48})`")
_RE_FRAGMENT = re.compile(r"[ =><|&;]")
# 代码特征：**非**字母数字/空白字符（真标点）或代码关键字 —— 用于把 " vs " 这类**散文**排除
_RE_CODE_PUNCT = re.compile(r"[^\w\s]")
_RE_CODE_KEYWORD = re.compile(
    r"\b(?:break|continue|return|pass|raise|yield|await|async|else|elif|except|finally|lambda|"
    r"def|class|import|from|assert|None|True|False)\b")
_RE_DEF_PY = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\b")
_RE_DEF_SH = re.compile(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{")
# 定义处：行首 bullet + 反引号/星号包裹的 [ASSUMPTION-N]
_RE_ASSUME_DEF = re.compile(r"^\s*[-*]\s+\*{0,2}`?\[?ASSUMPTION-(\d+)\]?`?\*{0,2}")
_RE_SWITCH = re.compile(r"\bGK_[A-Z0-9_]+\b")
# 模块名 + 同句「被 N 消费者」——两者必须来自**同一句**，避免把邻句计数错配到本模块
_RE_CONSUMER = re.compile(r"`?(gk_[a-z_]+)`?[^`\n。]{0,48}?被\s*\*{0,2}(\d+)\*{0,2}\s*消费者")
_RE_NUMLIST = re.compile(r"^\s*(\d+)\.\s")
_RE_EXEC = re.compile(r"(pytest|rg |grep |python|bash |gatekeeper-cli\.sh|`[^`]*`|BLOCK|==|<=|>=|_probe|\.py\b|\.sh\b)")

# ── 锚引用提取：**单一事实源**（2026-09-15）────────────────────────────────────
# 收口 PW-SN §6 挂账「锚校验与 `gk_doc_align.anchor_existence` 实现单源化（消双正则漂移）」。
# 两消费者**只允许**通过 `iter_anchor_refs()` 取锚，禁各自新增正则 —— 分工边界（防双源）：
#   · 本模块 `L-ANCHOR`  = **写侧可判定断言**（绑定形态 + 逐字字面值；有人改代码就须刷锚）
#                          ⟹ 阻断（high/medium），管辖**单一计划文档**；
#   · `gk_doc_align.anchor_existence` = **仓级内容漂移提示**（file_missing / line_over_eof /
#                          邻域词 content_drift）⟹ **WARN 不阻断**，管辖 `docs/plans/*.md`。
#   ⟹ 二者**判据所有权唯一**：同一事实**只由一处做阻断判决**；漂移检测**只在 doc-align**，
#      本模块**不**实现任何模糊/邻域匹配（防第二漂移事实源）。
RE_ANCHOR_LOOSE = re.compile(r"([\w\-./]+\.(?:py|sh|md|json)):(\d+)(?:-(\d+))?")

# ── A2（2026-09-28，ECC-F68E6BEE4F68）：`#L` 形态 —— **只喂重钉面**，不进 WARN 计数面 ──
# 为什么不直接开宽 `RE_ANCHOR_LOOSE`：它的召回面产出 `N/M 锚漂移`，该串是收敛评估的**冻结
#   比对串** ⟹ 开宽须与 `t-star freeze` 同批落刀（同类先例见本文件 `anchor_no_assertion`
#   那条的 R-16 D-3 注）。而 `path:L` 与 `path#L` 两形态**互不重叠** ⟹ 单开一条只认 `#L`
#   的口径即可：重钉面拿增量、WARN 面一个数都不变（实测本批 202 处漂移里 85 处是 `#L`）。
# 组布局与 `RE_ANCHOR_LOOSE` **逐字同构**：(1)=文件、(2)=起始行、(3)=结束行或 None。
RE_ANCHOR_HASHL = re.compile(r"([\w\-./]+\.(?:py|sh|md|json))#L(\d+)(?:-L?(\d+))?")


def iter_anchor_refs(text, loose=False, hashl_only=False):
    """产出锚引用 Match（`group(1)` = 文件、`group(2)` = 起始行、`group(3)` = 结束行或 None）。

    strict（默认）= `L-ANCHOR` 写侧口径：认 `L123` / `#L123` / `123-456` + 宽扩展名集（`_RE_ANCHOR`）；
    loose=True  = doc-align 仓级审计口径：仅 `123` / `123-456` + ext 子集（`RE_ANCHOR_LOOSE`，
                  **逐字保持其 2026-09-13 起的原语义**，不改其召回面）。
    hashl_only=True = **A2（2026-09-28，ECC-F68E6BEE4F68）**：只认 `path#L123` /
                  `path#L1022-L1029`（`RE_ANCHOR_HASHL`）—— 专供 `anchor_rebase_plan`，
                  **不参与** `anchor_existence` 的 WARN 计数（见 `RE_ANCHOR_HASHL` 上方注释）。
    """
    if hashl_only:
        return RE_ANCHOR_HASHL.finditer(text)
    return (RE_ANCHOR_LOOSE if loose else _RE_ANCHOR).finditer(text)


# ── R-13 载体（2026-09-15）：锚类 finding 的**机检分类计数** + **裸行锚段级分类**────
# 背景（REV-11 两臂独立命中，登记 R-13）：T11 的两条失败条件**双失载体** ——
#   ① 裸锚计数当年只靠人工 `rg | wc -l`，且「记账性引用」**无任何机检分类** ⟹ 基线不可判；
#   ② 本批把两条静默降级为 info 后，`main()` 只在 high/medium 返回 1 ⟹ 条件② 永不触发。
# 修法（用户裁定 2026-09-15：P1 落刀 + P2 绑段级 delivery；**不**升阻断面）：
#   计数在**追加 finding 的同一处**自增（无字符串匹配 ⟹ 无第二事实源）；
#   `bare_anchor_stats` 给「记账段 vs 落刀点段」的**段级机检分类**。
ANCHOR_REASONS = (
    "literal_absent_from_file",   # F-REV-67 ①：断言字面值未在所锚文件逐字出现（info）
    "literal_outside_range",      # 已绑定后漂移 ⟹ 行锚自校验失败（high）
    "symbol_ambiguous",           # F-REV-67 ②：裸符号锚同符多实现（info）
    "symbol_def_mismatch",        # 裸符号锚越出符号本体（high）
    "line_over_eof",              # 锚点越过文件行数（high）
    "external_unresolvable",      # 仓内不可定位 ⟹ 外部引用（info；**按文件聚合**，故计 finding 条数）
    # F-REV-69（2026-09-16）：`file:NNN` 且**无任何断言字面值/符号绑定** ⟹ 不进
    # `_verify_literal` ⟹ 只查存在性 + EOF ⟹ **行漂移不可见**（第四条逃逸路径）。
    # ⚠ 本项会抬 `anchor_findings` 计数 ⟹ 与 T11 条件② 冻结基线**同批**落刀（R-16 D-3）。
    "anchor_no_assertion",        # 无可校验断言（info）
)

_RE_BARE_ANCHOR = re.compile(r"`:\d+")
_RE_SECTION = re.compile(r"^#{2,3}\s+(.*)$")


# ── 锚重钉建议收集器（2026-10-31，owner 令「plan-lint 机制谨慎修，但少数关键位置仍需行号」）──
# 病根：本模块报 `symbol_def_mismatch` / `literal_outside_range` 时**已算出**正确位置
#   （`_verify_def_at` 的 `dline`、`_verify_literal` 的 `near`），却只写进 detail 字符串 ⟹
#   每次漂移都要人肉读 detail、手算偏移、逐条改（实测 2026-10-31 一次 +21 行改动触发 6 处）。
# 修法（**不新增检测、不改阻断、不改 findings 契约**）：
#   · `_anchor_finding` 增可选 `repair` ⟹ 有则旁挂收集（findings 仍是 4 元组）；
#   · detail 增「建议重钉为 `file:NNN`」一句（人可直读直改）；
#   · `main --anchor-plan` 输出结构化清单（字段与 `gk_doc_align.anchor_rebase_plan` 对齐，
#     供 `gk_anchor_rebase.py --map` 或 agent 批量落刀）。
# ⚠ 本收集器**不参与**判定 —— 只记录「若人决定重钉，该钉到哪」。判据所有权仍在原函数。
_REPAIR_HINTS: list = []


def anchor_repair_hints():
    """返回并清空本轮收集的锚重钉建议（调用方保证「一轮 lint 一份清单」）。"""
    out = list(_REPAIR_HINTS)
    _REPAIR_HINTS.clear()
    return out


def _anchor_finding(findings, level, detail, reason, repair=None):
    """锚类 finding **带 reason 码**（4 元组）；由 `lint()` 去重后折算计数、并**降回 3 元组**输出。

    reason 与 detail **同址产生** ⟹ 无字符串匹配（无第二事实源）；**去重后**才计数 ⟹
    `anchor_findings` 各项之和 **== 可见 L-ANCHOR 条数**（初版按 append 事件计，实测
    `gatekeeper-cli.sh` 同文案锚被去重 ⟹ 计数 22 vs 可见 17，**故改为去重后计**）。

    `repair`（2026-10-31，可选）：`{ref, verdict, declared_symbol, symbol_hit_line,
    symbol_hits_total}` —— 仅旁挂到 `_REPAIR_HINTS`，**不进 findings 元组** ⟹ 既有消费点零影响。
    """
    findings.append((CHECK_ANCHOR, level, detail, reason))
    if repair:
        _REPAIR_HINTS.append(repair)


def bare_anchor_stats(doc):
    """裸行锚（`` `:NNN ``）计数：`total` / `delivery` / `ledger`（R-13；T11 条件① 的载体）。

    分类口径 = **段级**：以 `### 8.x` 留痕段为**记账段**（这些段的存在本身即为记录旧错值），
    其余段 = `delivery`（落刀点面）。**已知局限（勿当纯净值）**：段级只到"段" —— `§2.1` 这类
    "草案段"内**仍混有记账行**（2026-09-15 实测该段 83 处）⟹ `delivery` 仍含虚高成分。
    """
    total = delivery = ledger = 0
    sec = ""
    for ln in doc.splitlines():
        m = _RE_SECTION.match(ln)
        if m:
            sec = m.group(1).strip()
        c = len(_RE_BARE_ANCHOR.findall(ln))
        if not c:
            continue
        total += c
        if re.match(r"^8\.", sec):
            ledger += c
        else:
            delivery += c
    return {"total": total, "delivery": delivery, "ledger": ledger}



def _read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


# 2026-11-01：仓库内真实存在 `.venv-*/`（5,603 个 .py / 81MB）—— 原白名单只挡**精确名**
# `.venv` ⟹ `_build_def_index` 逐文件读 venv 源码；WSL `/mnt/c`（9p）实测单次 `plan-lint` 4m40s，
# 使 `plan-refinement` 前置门看起来「静默无输出」。venv 不是被审查的仓内源码 ⟹ 一律跳过。
_SKIP_DIRS = {"__pycache__", "node_modules", ".mypy_cache", "site-packages",
              "dist-packages", ".tox", ".nox", ".eggs"}


def _is_skipped_dir(name):
    return name == ".git" or name in _SKIP_DIRS or name.startswith(".venv")


def _iter_files(repo, exts=None):
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if not _is_skipped_dir(d)]
        for f in files:
            if exts is None or f.endswith(tuple(exts)):
                yield os.path.join(root, f)


def _build_index(repo):
    """basename -> 绝对路径（多份时保留全部）。"""
    idx = {}
    for p in _iter_files(repo):
        idx.setdefault(os.path.basename(p), []).append(p)
    return idx


def _lines_of(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return None


def _read_lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except OSError:
        return None


def _build_def_index(repo):
    """仓内 `def name` / `name() {` 定义索引。

    返回 `{"by_name": name -> [(path, line)], "by_file": path -> [line, ...]}`；
    后者用于把 `sym:line` 的**断言区间**判定为「落在该符号**本体**内」（见 `_verify_def_at`）。
    """
    by_name, by_file = {}, {}
    for p in _iter_files(repo, (".py", ".sh")):
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                for i, ln in enumerate(fh, 1):
                    m = _RE_DEF_PY.match(ln) or _RE_DEF_SH.match(ln)
                    if m:
                        by_name.setdefault(m.group(1), []).append((p, i))
                        by_file.setdefault(p, []).append(i)
        except OSError:
            continue
    return {"by_name": by_name, "by_file": by_file}


def _resolve_path(rel, repo, index):
    cand = os.path.join(repo, rel)
    if os.path.isfile(cand):
        return cand
    # §9-6（`2026-10-07-precheck-lazy-index-plan`）：`index` 可为 **callable**（惰性）—— 仅当
    #   **直连失败**（basename 兜底）时才触发其首次构建；`dict` 形态（既有调用点 `lint()`）逐字兼容。
    idx = index() if callable(index) else index
    hits = idx.get(os.path.basename(rel)) or []
    return hits[0] if hits else None


def _lazy_index(repo):
    """惰性仓索引（§9-6）：仅当**直连解析失败**（basename 兜底）时才 `_build_index(repo)` 全仓 walk。

    返回**零参可调用** `get()`（`_resolve_path` 识别 callable 形参）；同一实例多次调用只 walk 一次
    （闭包缓存）。用于「标题行锚」两路（`gk_finding._scan_drift` / `scan_title_anchors`）—— 其锚多为
    **仓内相对路径** ⟹ 直连 `isfile` 即命中 ⟹ 全仓 walk 被**完全省掉**。
    """
    box = {}

    def get():
        if not box:
            box["i"] = _build_index(repo)
        return box["i"]

    return get


def _looks_code_fragment(s):
    """像**代码片段**（非散文/标识符/路径）：无 CJK、含字母数字、且含**真标点**或**代码关键字**。

    例：`break 2` / `>&2` / `2>/dev/null` 命中；` + `（纯运算符）、` vs `（散文）不命中。
    """
    if not (2 <= len(s) <= 48):
        return False
    if any("\u4e00" <= ch <= "\u9fff" for ch in s):
        return False
    if "://" in s or s.startswith("http"):
        return False
    if not re.search(r"[A-Za-z0-9_]", s):
        return False  # 纯运算符/空白（如 ` + `）非断言字面值
    if not _RE_FRAGMENT.search(s):
        return False
    return _RE_CODE_PUNCT.search(s) is not None or _RE_CODE_KEYWORD.search(s) is not None


def _verify_literal(rel, lo, hi, sym, repo, index, findings, form):
    """断言字面值 `sym` 须落在锚点区间 [lo,hi]；否则报**最近命中行 + 偏移**（漂移检测）。

    防假阳：字面值**不在所锚文件**出现 ⟹ 视为邻句提及、非本锚断言 ⟹ **降级为 info**（不阻断）。
    2026-09-15（F-REV-67 ①）：原为**静默 return** ⟹ "断言打错字"与"真错锚"一并消失。实测
    `gd['ecc_findings'] = existing`（带空格）vs 代码 `=existing` ⟹ 该锚连漂 **6 轮**零告警。
    现改为 info 明示**不可校验 ≠ 已校验**（内容漂移面见 doc-align `anchor_existence`）。
    """
    if len(sym) < 3:
        return
    path = _resolve_path(rel, repo, index)
    if path is None:
        return  # 外部锚：由 info 覆盖
    lines = _read_lines(path)
    if lines is None:
        return
    lo_i, hi_i = lo, int(hi) if hi else lo
    if any(sym in ln for ln in lines[lo_i - 1:hi_i]):
        return
    hits = [i for i, ln in enumerate(lines, 1) if sym in ln]
    if not hits:
        _anchor_finding(findings, "info",
                        f"{rel}:{lo}{'-' + hi if hi else ''} 断言 `{sym}` **未在所锚文件逐字出现**"
                        f" ⟹ 该锚**不可校验**（≠ 已校验；请改为逐字取自代码或改用可判定形态；"
                        f"内容漂移面见 `doc-align anchor_existence`）", "literal_absent_from_file")
        return
    # 漂移检测：优先取锚点**之后**的最近命中（插入造成 +N 漂移是常见形态），
    # 否则回退到锚点之前最近命中；避免被锚点附近**注释提及**抢答。
    after = [i for i in hits if i >= lo]
    near = min(after) if after else min(hits, key=lambda i: abs(i - lo))
    off = near - lo
    _ref = f"{rel}:{lo}{'-' + hi if hi else ''}"
    _anchor_finding(findings, "high",
                    f"{_ref} 断言 `{sym}` 未落在锚点区间；"
                    f"最近命中 :{near}（offset {'+' if off >= 0 else ''}{off}，全文 {len(hits)} 处）"
                    f" —— 行锚自校验失败（{form}）；**建议改为「符号 + 字段名」写法（去行号绑定，"
                    f"一次消除且以后不再漂）**；若必须保留行号则重钉为 `{rel}:{near}`",
                    "literal_outside_range",
                    repair={"ref": _ref, "verdict": "content_drift",
                            "declared_symbol": sym, "symbol_hit_line": near,
                            "symbol_hits_total": len(hits)})


def _verify_def_at(sym, lo, hi, def_index, findings, form):
    """裸符号锚：sym 在仓内**唯一**定义时，断言区间须落在该符号**本体**内。

    本体 = [`def sym` 行, 同文件下一个 def 行 − 1]（再以文件行数封顶）。`sym:line` / `sym:lo-hi`
    的常见语义 = 「sym 的某处代码」⟹ 落在本体内即通过；越出（漂移/绑错）⟹ 报定义处与偏移。
    """
    defs = (def_index.get("by_name") or {}).get(sym) or []
    if len(defs) != 1:
        # 0 = 非仓内定义名（外部/散文）⟹ 静默（同 §4.1「无依据可校验 ≠ 已校验」，勿造噪音）。
        # ≥2 = **同符多实现（双事实源）** ⟹ 原实现静默 return（防假阳），代价是**最该报警的形态被藏起来**
        #   （2026-09-15，F-REV-67 ②）：实测 `_is_retryable` 在 `gatekeeper-cli.sh:337` 与
        #   `gk_monitor_api.py:46` 各有一份定义（= G5 双实现），故 `_is_retryable:336` 静默逃逸。
        #   ⟹ 降级为 info（不阻断），提请改用 `file:line sym` 显式指名。
        if len(defs) > 1:
            where = "、".join(f"{os.path.basename(p)}:{i}" for p, i in defs[:4])
            _anchor_finding(findings, "info",
                            f"`{sym}:{lo}` 裸符号锚**不可判定**：`{sym}` 仓内 **{len(defs)} 处定义**"
                            f"（{where}）⟹ 疑似**同符多实现（双事实源）**；请改用 `file:NNN {sym}` 显式指名",
                            "symbol_ambiguous")
        return
    p, dline = defs[0]
    lo_i, hi_i = lo, int(hi) if hi else lo
    later = [d for d in (def_index.get("by_file") or {}).get(p, []) if d > dline]
    n = _lines_of(p) or 0
    body_end = min([x - 1 for x in later] + [n]) if n else (min(later) - 1 if later else 10 ** 9)
    if dline <= lo_i and hi_i <= body_end:
        return
    off = dline - lo
    _bn = os.path.basename(p)
    # ⚠ repair.ref 必须与**文档原文形态**一致（裸符号锚 = `sym:NNN`，无文件名），
    #   否则 `gk_anchor_rebase.py --map old=new` 在文档里找不到 `old`（2026-10-31 实测：
    #   误写成 `gk_advance.py:1244` 时，原文 `_run_standard:1244` 不匹配 ⟹ 静默 not_found）。
    _ref = f"{sym}:{lo}{'-' + hi if hi else ''}"
    _anchor_finding(findings, "high",
                    f"`{sym}:{lo}{'-' + hi if hi else ''}` 越出 `{sym}` 本体"
                    f"（实测 `def {sym}` 在 {_bn}:{dline}，本体止于 :{body_end}）"
                    f"（offset {'+' if off >= 0 else ''}{off}） —— 行锚自校验失败（{form}）；"
                    f"**建议改为「符号 + 字段名」写法（去行号绑定，一次消除且以后不再漂）**；"
                    f"若必须保留行号则重钉为 `{_bn}:{dline}`",
                    "symbol_def_mismatch",
                    repair={"ref": _ref, "verdict": "content_drift",
                            "declared_symbol": sym, "symbol_hit_line": dline,
                            "symbol_hits_total": len(defs), "target_file": _bn})


def _check_anchor_symbol(doc, repo, index, def_index, findings):
    """行锚自校验（D2）：锚点处的字面值须与断言**同源**（见文件头三形态）。"""
    bound = set()
    checked = set()   # F-REV-69：已获**断言校验**的 (rel, lo)（= ①/② 绑定命中者）

    def _bind(rel, lo, hi, sym, form):
        bound.add((rel, lo))
        checked.add((rel, lo))
        _verify_literal(rel, lo, hi, sym, repo, index, findings, form)

    # ① 同 backtick 绑定 / 符号前置绑定
    for m in _RE_ANCHOR_SYM.finditer(doc):
        _bind(m.group(1).replace("\\", "/"), int(m.group(2)), m.group(3), m.group(4), "同 backtick 绑定")
    for m in _RE_SYM_BEFORE.finditer(doc):
        _bind(m.group(2).replace("\\", "/"), int(m.group(3)), m.group(4), m.group(1), "符号前置绑定")
    # ③ 裸符号锚（前置符号 + 裸行锚 / 裸 `sym:line`）
    for m in _RE_SYM_BAREB.finditer(doc):
        _verify_def_at(m.group(1), int(m.group(2)), m.group(3), def_index, findings, "符号前置 + 裸行锚")
    for m in _RE_SYM_ANCHOR.finditer(doc):
        _verify_def_at(m.group(1), int(m.group(2)), m.group(3), def_index, findings, "裸符号锚")
    # ② 紧随括号内代码片段（仅当该锚未被高置信绑定覆盖）
    for m in iter_anchor_refs(doc):
        rel, lo, hi = m.group(1).replace("\\", "/"), int(m.group(2)), m.group(3)
        if (rel, lo) in bound:
            continue
        seg = re.split(r"[）)\n；;]", doc[m.end():], maxsplit=1)[0]
        if seg.startswith("`"):
            seg = seg[1:]  # 去掉锚点自身的收尾反引号，避免与后续片段错配
        for lm in _RE_LITERAL.finditer(seg):
            if _looks_code_fragment(lm.group(1)):
                _verify_literal(rel, lo, hi, lm.group(1), repo, index, findings, "紧随括号内代码片段")
                checked.add((rel, lo))
                break
    # ④ F-REV-69（2026-09-16）：仓内 `file:NNN` 锚**未获任何断言校验** ⟹ 只查了
    #    存在性 + EOF ⟹ 行漂移不可见 ⟹ 报 info（建议补 `file.ext:NNN 符号` 绑定）。
    #    外部不可定位锚**排除**（已由 `check_anchor` 聚合为 external_unresolvable）。
    seen = set()
    for m in iter_anchor_refs(doc):
        rel, lo = m.group(1).replace("\\", "/"), int(m.group(2))
        if (rel, lo) in checked or (rel, lo) in seen:
            continue
        seen.add((rel, lo))
        if _resolve_path(rel, repo, index) is None:
            continue
        _anchor_finding(findings, "info",
                        f"{rel}:L{lo} 无可校验断言（只查存在性 + EOF ⟹ 行漂移不可见）"
                        f" —— 建议补「{rel}:{lo} 符号」绑定",
                        "anchor_no_assertion")


def check_anchor(doc, repo, index, findings, def_index=None):
    """F2：`file:line` 锚点须可解 + **断言自校验**（行号处字面值 == 断言）。

    仓内可定位 ⟹ 校验行范围（high）+ 行锚自校验（high）；不可定位 ⟹ 归为**外部引用**，
    按文件聚合为一条 info（外部依赖须显式声明，不得伪装成仓内锚）。
    """
    seen = set()
    external = {}
    for m in iter_anchor_refs(doc):
        rel, lo, hi = m.group(1).replace("\\", "/"), int(m.group(2)), m.group(3)
        if (rel, lo, hi) in seen:
            continue
        seen.add((rel, lo, hi))
        path = _resolve_path(rel, repo, index)
        if path is None:
            external.setdefault(rel, []).append(lo)
            continue
        n = _lines_of(path)
        if n and (lo > n or (hi and int(hi) > n)):
            _anchor_finding(findings, "high",
                            f"{rel}:{m.group(2)}{'-' + hi if hi else ''} 超出 {os.path.basename(path)} 行数 {n}",
                            "line_over_eof")
    for rel, los in sorted(external.items()):
        _anchor_finding(findings, "info",
                        f"{rel}：{len(los)} 处仓内不可定位 ⟹ 外部/不可核引用"
                        f"（须声明外部依赖或改仓内锚）", "external_unresolvable")
    _check_anchor_symbol(doc, repo, index, def_index or {}, findings)


def check_assume(doc, findings):
    """F3：**定义处**的 ASSUMPTION 编号必须唯一（引用处不计）。"""
    seen = {}
    for ln in doc.splitlines():
        m = _RE_ASSUME_DEF.match(ln)
        if m:
            seen[int(m.group(1))] = seen.get(int(m.group(1)), 0) + 1
    for i, c in sorted(seen.items()):
        if c > 1:
            findings.append((CHECK_ASSUME, "high",
                             f"ASSUMPTION-{i} 有 {c} 处**定义**（撞号：同号多语义）"))


_OUTSIDE_TEXT_CACHE = {}


def _outside_text(repo, plan_path):
    """`.py/.sh/.json/.md` 正文并集（**排除本文档自身**）；同一次 lint 内只读一遍。

    `check_switch`（F4）与 `check_pw_const`（PW-9）的判据同为「本仓**别处**是否出现过该名字」
    ⟹ 共用同一份语料；原实现各自全仓读一遍（WSL `/mnt/c` 实测两遍合计 ≈50s，占单次 lint 八成）。
    """
    key = (os.path.abspath(repo), os.path.abspath(plan_path))
    if key not in _OUTSIDE_TEXT_CACHE:
        parts = []
        for p in _iter_files(repo, (".py", ".sh", ".json", ".md")):
            if os.path.abspath(p) == key[1]:
                continue
            try:
                parts.append(_read(p))
            except OSError:
                continue
        _OUTSIDE_TEXT_CACHE[key] = "\n".join(parts)
    return _OUTSIDE_TEXT_CACHE[key]


def check_switch(doc, plan_path, repo, findings):
    """F4：文档点名的新开关须①全仓可查 或 ②在 §6 开关表显式登记默认值。

    注意：**必须排除本文档自身**（否则文档里提一次即"命中" ⟹ 检查恒绿）。
    """
    blob = _outside_text(repo, plan_path)
    for s in sorted(set(_RE_SWITCH.findall(doc))):
        # PW-1 豁免（Infra-3，2026-10-05）：标「拟设（+同批实装）」的回退 env **不报** ——
        # 该形态是**计划期声明**（载体与开关同批实装），非"新引入却漏给默认值"。
        if any((s in ln and "拟设" in ln) for ln in doc.splitlines()):
            continue
        in_table = re.search(r"\|\s*`?~{0,2}" + re.escape(s) + r"~{0,2}`?\s*\|", doc) is not None
        if blob.count(s) <= 0 and not in_table:
            findings.append((CHECK_SWITCH, "high",
                             f"{s}：**仓内（除本文档）0 命中**且 §6 无登记 ⟹ 新引入但未给默认值/省略时行为"))


def check_consumer(doc, repo, findings):
    """F1：自称「被 N 消费者消费」须与实测消费者数一致。

    消费者 = 除模块自身与本文档外，**import 该模块** 或 **引用 `<mod>.py`** 的 .py/.sh 文件
    （覆盖 import 与 subprocess 两类消费）。模块名与计数须取自**同一句**，避免跨句错配。
    """
    claims = {}
    for ln in doc.splitlines():
        for m in _RE_CONSUMER.finditer(ln):
            mod, n = m.group(1), int(m.group(2))
            claims[mod] = max(claims.get(mod, 0), n)
    if not claims:
        return
    consumers = {}
    for p in _iter_files(repo, (".py", ".sh")):
        try:
            txt = _read(p)
        except OSError:
            continue
        base = os.path.splitext(os.path.basename(p))[0]
        for mod in claims:
            if base == mod:  # 模块自身不计
                continue
            if (re.search(r"^\s*(?:from|import)\s+" + re.escape(mod) + r"\b", txt, re.M)
                    or (mod + ".py") in txt):
                consumers.setdefault(mod, set()).add(p)
    for mod, claim in sorted(claims.items()):
        actual = len(consumers.get(mod, ()))
        if actual < claim:
            findings.append((CHECK_CONSUMER, "medium",
                             f"`{mod}`：文档自称被 {claim} 消费者消费，实测消费者 {actual} 处"))


def check_criterion(doc, findings):
    """7 维：§3 验收判据的每条须含可执行命令/表达式。"""
    in_sec = False
    for ln in doc.splitlines():
        if re.match(r"^##\s*§?3\b", ln):
            in_sec = True
            continue
        if in_sec and re.match(r"^##\s", ln):
            break
        if in_sec and re.match(r"^\d+\.\s+\*\*", ln) and not _RE_EXEC.search(ln):
            findings.append((CHECK_CRITERION, "medium",
                             f"判据无可执行命令/表达式：{ln.strip()[:76]}"))


def check_number(doc, findings):
    """结构：同一**连续编号块**内编号须唯一（跨块重复是正常的）。"""
    run, start = [], None
    for i, ln in enumerate(doc.splitlines(), 1):
        m = _RE_NUMLIST.match(ln)
        if m:
            if not run:
                start = i
            run.append(int(m.group(1)))
            continue
        if run:
            _flush_number_run(run, start, findings)
            run, start = [], None
    if run:
        _flush_number_run(run, start, findings)


def _flush_number_run(run, start, findings):
    seen = {}
    for n in run:
        seen[n] = seen.get(n, 0) + 1
    dups = sorted(n for n, c in seen.items() if c > 1)
    if dups:
        findings.append((CHECK_NUMBER, "medium",
                         f"编号块（自 L{start}，共 {len(run)} 项）重复号 {dups}"))


# ── 悬空标签（L-LABEL，2026-10-04）──────────────────────────────────────────
# 病灶（PLAND 计划实测）：`## §8 预算（D7）` 的「（D7）」是从别计划抄来的 deliverable
#   编号 —— 本文从未定义 D1..D6，标签**悬空**（读者无处可查）。
# 判据（窄口径，防误报）：**只**看**段标题尾部**的「（<前缀><数字>）」标签（前缀 1-4 个
#   ASCII 字母、数字 1-3 位）；数字 >1 且全文**不含同族基标签 `<前缀>1`** ⟹ 悬空（medium）。
#   标题内嵌（非尾部）与散文括号不判（如「（治四轮⑤…）」）。
_RE_HEAD_TAG = re.compile(r"^#{2,6}\s+\S.*?[（(]\s*([A-Za-z]{1,4})(\d{1,3})\s*[）)]\s*$", re.M)


def check_label(doc, findings):
    for m in _RE_HEAD_TAG.finditer(doc):
        prefix, num = m.group(1), int(m.group(2))
        if num <= 1:
            continue                       # `P1` 即族基，定义存在
        if re.search(r"\b%s1\b" % re.escape(prefix), doc):
            continue                       # 全文出现过同族 `P1` ⟹ 编号表已定义（非悬空）
        findings.append((CHECK_LABEL, "medium",
                         f"悬空标签「（{prefix}{num}）」：全文未出现同族基标签 `{prefix}1`"
                         "（疑似从别处抄来的编号，本文无对应定义）"))


# ── 跨计划任务号须带计划字母（L-PLAN-LETTER，2026-10-16，`ECC-F5255744DDD3`）──────
# 病灶（实测）：任务号 **跨计划撞车**（计划 B 的 `T13` = claim 自动释放 vs 计划 C 的 `T13` =
#   中文嵌入）⟹ 归档 subagent 报告时无法从裸 `T13` 判归属（本会话实被咬）。
# 判据（**窄口径，防误报**）：逐行；**同一行**同时 (a) 命中**别的**计划文件名
#   （`<date>-<slug>.md` 且 ≠ 本文件 basename）与 (b) 裸任务号 `T<数字>`（`T` 前非 `-`/字母，
#   即非 `C-T13` 形态）⟹ medium。行内无跨计划文件名 ⟹ 不判（本计划内裸 `T13` 合法，零误报）。
_RE_PLAN_FILE = re.compile(r"(\d{4}-\d{2}-\d{2}-[A-Za-z0-9._-]+\.md)")
_RE_BARE_TASK = re.compile(r"(?<![-\w])T(\d{1,3})\b")


def check_plan_letter(doc, findings, plan_file=""):
    base = os.path.basename(plan_file or "")
    for ln in (doc or "").splitlines():
        others = sorted({f for f in _RE_PLAN_FILE.findall(ln) if f != base})
        if not others:
            continue
        for m in _RE_BARE_TASK.finditer(ln):
            findings.append((CHECK_PLAN_LETTER, "medium",
                             f"跨计划引用任务号须带**计划字母前缀**（如 `C-T13`）；本行裸 `T{m.group(1)}`"
                             f"（同行引用 `{others[0]}`）—— `ECC-F5255744DDD3`"))


_RE_DRAFT = re.compile(r"DRAFT\s*[-–—]?\s*(\d+)")


def check_version(doc, findings):
    """L-VERSION（2026-10-07，防复发；finding `ECC-0F4B6863913D`）：同一计划内 `DRAFT-<n>`
    版本号须**唯一**。口径互斥（如 §0 状态行 `DRAFT-6` 与 §15 记录 `DRAFT-5` 并存）⟹ 读者
    无法判定正本版本 = 审计署计划实测现场。

    级别 = **info**（非阻断）：先观察误报（沿革叙述「DRAFT-0 → DRAFT-1」等合法多值），
    对齐本仓「实测零误报后方升为阻断」纪律。
    """
    nums = sorted({int(m.group(1)) for m in _RE_DRAFT.finditer(doc or "")})
    if len(nums) > 1:
        findings.append((CHECK_VERSION, "info",
                         "DRAFT 版本口径互斥：同文档并存 "
                         + "、".join("DRAFT-%d" % n for n in nums)
                         + " ⟹ 正本版本不可判（应全文统一，或对沿革显式标注『快照/历史』）"))


def check_meta(doc, findings, plan_file=""):
    """L-META（F8）：`<!-- META -->` 头块存在 + 必备字段可解析。

    解析**复用** `gk_route_center._parse_meta`（**单一事实源**；禁第二解析器 —— 本仓明禁
    「同一对象两个事实源」）。规则：
      - 无 META 块 ⟹ high（F8 元数据缺失）；
      - 有块但 `phases` 空 ⟹ high（路由 / 序列节点依赖该字段）；
      - 缺 `target_repo` / `project_type` / `worktree_needed` ⟹ medium；
      - `state_domain` 强制面（2026-09-26 ECC-F2E2F9E07AC2 断点② **松绑**）：原门**只挂**
        `worktree_needed=true`，`worktree_needed=false` 的**跨仓**计划（如 zthl-adapter）连
        「应声明域」的机检都被 SKIP ⟹ finding 可静默错落技能默认 state。现为
        「`worktree_needed=true` **或** `target_repo` 指向他仓」皆须显式声明（自指判定复用
        `gk_route_center.is_foreign_repo` 单源），且**报出可推导域**（断点① 的单源推导
        `derive_state_domain`）供作者直接采用。
    解析器不可导入 ⟹ **fail-soft 不报**（宁漏勿误）。
    """
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from gk_route_center import _parse_meta
    except Exception:
        return
    meta = _parse_meta(doc)
    if not meta:
        findings.append((CHECK_META, "high",
                         "缺 `<!-- META -->` 头块（F8：计划元数据未声明）"))
        return
    if not str(meta.get("phases") or "").strip():
        findings.append((CHECK_META, "high", "META 缺 `phases`（路由 / 序列节点依赖）"))
    for f in ("target_repo", "project_type", "worktree_needed"):
        if not str(meta.get(f) or "").strip():
            findings.append((CHECK_META, "medium", f"META 缺字段 `{f}`"))
    # REV-3 §12.4：`edit_budget_declared`（C1 载体）—— 存在则须为 int ∈ [0, DECLARED_HARD_CAP]。
    raw_d = meta.get("edit_budget_declared")
    if raw_d is not None and str(raw_d).strip() != "":
        try:
            from gk_route_center import DECLARED_HARD_CAP
        except Exception:
            DECLARED_HARD_CAP = 24
        try:
            _dv = int(str(raw_d).strip())
        except (TypeError, ValueError):
            _dv = None
        if _dv is None or _dv < 0 or _dv > DECLARED_HARD_CAP:
            findings.append((CHECK_META, "medium",
                             "META `edit_budget_declared` 非法（须 ∈ [0, %d]）：%r"
                             % (DECLARED_HARD_CAP, raw_d)))
    dom = str(meta.get("state_domain") or "").strip()
    wt = str(meta.get("worktree_needed") or "").strip().lower() == "true"
    # P16（2026-10-01：**已撤销**，owner 同日裁定）。原实现 = 对 `worktree_needed=true` 而缺
    #   `edit_budget_declared` 报一条 `L-META` **info**。撤销两条理由（均为实测）：
    #   ① **判据重载**：`worktree_needed` 已被用于门控 `state_domain` 机检（见下 `if not dom and
    #      (wt or foreign)`）⟹ 在同一字段上再叠一层「批规模」语义 = 加码重载（该字段的门控语义
    #      本仓已有分析主张松绑）。
    #   ② **双清单漂移**：该字段**不在** CLI 启动块的 META 解析清单（`gatekeeper-cli.sh` 的
    #      `for k in [...]`）内，与 `gk_route_center._META_FIELDS` **不同源** ⟹ P16 立于一个
    #      **未被启动块解析**的字段上。META 双清单同源化**另立 finding**（不在本处修）。
    foreign, derived = False, ""
    try:
        from gk_route_center import derive_state_domain, is_foreign_repo
        foreign = is_foreign_repo(str(meta.get("target_repo") or ""))
        derived = derive_state_domain(meta, plan_file)
    except Exception:
        pass
    self_skill = bool(str(meta.get("target_repo") or "").strip()) and not foreign
    if not dom and self_skill and not wt:
        # §18.2 判据 c6（2026-10-04）：技能自指 + `worktree_needed=false` 的子计划原**不要求域**
        #   ⟹ 并发会话共享 base state（抢锁 `LOCK_TIMEOUT=5s` + 多域台账分裂，实测交集仅 21/113）
        #   ⟹ 报 **high**（可阻断；原缺口②：级别仅 medium 非阻断）。
        extra = f"；可推导域 `{derived}`" if derived else ""
        findings.append((CHECK_META, "high",
                         f"META 未声明 `state_domain`（技能自指 + worktree_needed=false ⟹ 并发会话"
                         f"将共享 base state：抢锁 + 多域台账分裂；见 ECC-46C22B11AD85）{extra}"))
    elif not dom and (wt or foreign):
        why = "worktree_needed=true" if wt else "target_repo 指向他仓"
        extra = f"；可推导域 `{derived}`" if derived else ""
        findings.append((CHECK_META, "medium",
                         f"META 未声明 `state_domain`（{why} ⟹ finding 归属域须显式，"
                         f"否则跨仓 finding 静默落技能默认 state）{extra}"))
    # ── 现状 / 缺口登记（2026-09-26 只读取证，**不改语义**）──────────────────────────────
    # · **已修（断点②）**：门由「仅 `worktree_needed=true`」**扩到** `wt or foreign` ⟹ 跨仓计划
    #   （`target_repo` 指向他仓）也被要求显式声明域。
    # · **缺口（两处，均未修）**：
    #   ① 判据面**未覆盖并发**：技能自指（`target_repo: skill`）+ `worktree_needed: false` 的
    #      子计划（如本计划 12 份中的 11 份）**不要求域** ⟹ 并发会话共享 base state ⟹ 抢锁
    #      （`LOCK_TIMEOUT=5s` 超时 fail-loud）+ 多域台账分裂（实测交集仅 21/113）。
    #   ② 级别仅 `medium`（WARN）**非阻断** ⟹ 作者可无视。
    # · 锚：`ECC-7FF005759CE2`（`worktree_needed` 门禁单向，在册孤儿域）/ `ECC-46C22B11AD85`（RC3）
    #   / `ECC-F2E2F9E07AC2`；正本方案 §4.13.30 二（洞 1/2/3）。


_RE_TBL_SEP = re.compile(r"^[\s:|-]+$")


def _symbol_tables(text):
    """解析 markdown **符号表**（表头须同时含「符号」与「专有名称」列）⟹ [(sym, name), ...]。"""
    rows, si, ni = [], None, None
    for ln in text.splitlines():
        s = ln.strip()
        if not s.startswith("|"):
            si = ni = None
            continue
        cells = [c.strip().strip("`").strip() for c in s.strip("|").split("|")]
        if si is None:
            if any(c.startswith("符号") for c in cells) and any("专有名称" in c for c in cells):
                si = next(j for j, c in enumerate(cells) if c.startswith("符号"))
                ni = next(j for j, c in enumerate(cells) if "专有名称" in c)
            continue
        if len(cells) <= max(si, ni) or all(_RE_TBL_SEP.match(c) for c in cells):
            continue
        rows.append((cells[si], cells[ni]))
    return rows


def check_symbol(doc, plan_path, repo, findings):
    """L-SYMBOL（2026-09-14 新增）：**符号撞车检测**（同一符号被赋多个含义）。

    机制 = **符号表驱动**（表头含「符号」+「专有名称」）：
      ① 表内同一符号 ≥2 个不同专有名称 ⟹ high；
      ② 表内同一专有名称挂 ≥2 个符号 ⟹ medium；
      ③ 跨文档：扫 `repo/docs/plans/*.md` 的符号表，同符号异名 ⟹ high（带来源文档）。
    **覆盖声明**（对齐 L-ANCHOR「无依据可校验 ≠ 已校验」）：本检**仅在作者建表时生效**
    —— 无符号表 ⟹ 不报（避免散落正文的希腊符噪声）；故效力依赖 §4.1 式**建表纪律**。
    """
    sym2names, name2syms = {}, {}
    for sym, name in _symbol_tables(doc):
        if not sym or not name:
            continue
        sym2names.setdefault(sym, set()).add(name)
        name2syms.setdefault(name, set()).add(sym)
    for sym, names in sorted(sym2names.items()):
        if len(names) > 1:
            findings.append((CHECK_SYMBOL, "high",
                             f"符号 `{sym}` 撞车：本文档表内 {len(names)} 个名称（"
                             + " / ".join(sorted(names)) + "）"))
    for name, syms in sorted(name2syms.items()):
        if len(syms) > 1:
            findings.append((CHECK_SYMBOL, "medium",
                             f"专有名称「{name}」挂 {len(syms)} 个符号（"
                             + " / ".join(sorted(syms)) + "）"))
    if not sym2names:
        return
    own = os.path.abspath(plan_path)
    for p in sorted(glob.glob(os.path.join(repo, "docs", "plans", "*.md"))):
        if os.path.abspath(p) == own:
            continue
        try:
            other = _read(p)
        except OSError:
            continue
        for sym, name in _symbol_tables(other):
            if sym in sym2names and name and name not in sym2names[sym]:
                findings.append((CHECK_SYMBOL, "high",
                                 f"符号 `{sym}` 跨文档撞车：本文档（"
                                 + " / ".join(sorted(sym2names[sym]))
                                 + f"）vs {os.path.basename(p)}（{name}）"))


_RE_DEP_HDR = re.compile(r"^#{2,4}\s*依赖门\s*$", re.M)
_RE_FENCE = re.compile(r"```[A-Za-z0-9_+-]*\s*\n(.*?)```", re.S)


def _dep_declaration(doc):
    """取 `### 依赖门` 标题后**第一段** fenced JSON 块；缺标题/缺块/坏 JSON ⟹ `None`。"""
    m = _RE_DEP_HDR.search(doc or "")
    if not m:
        return None
    fm = _RE_FENCE.search(doc[m.end():])
    if not fm:
        return None
    try:
        d = json.loads(fm.group(1))
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


def _resolve_state_file(repo):
    """位置无关的**权威 state**（§17-6 P2）：env `STATE_FILE`（存在则用）→ 被治理仓
    **主 worktree** 根（`git rev-parse --git-common-dir` 的父）→ `<root>/.gatekeeper.state`。
    **禁**用脚本自身位置 —— worktree 副本会指向不存在的 `<worktree>/.gatekeeper.state`
    ⟹ 依赖门全判 missing（worktree=missing / 主树=high 的位置相关假分歧）。
    """
    env = os.environ.get("STATE_FILE", "")
    if env and os.path.isfile(env):
        return env
    root = repo
    try:
        r = subprocess.run(["git", "-C", repo, "rev-parse", "--path-format=absolute",
                            "--git-common-dir"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            root = os.path.dirname(r.stdout.strip())
    except Exception:  # noqa: BLE001 — 非 git / 无 git ⟹ 回落 repo（行为不劣化）
        pass
    # git 在 Windows 上输出正斜杠（`C:/…/.git`），直接 os.path.join 会拼出
    # `C:/…\.gatekeeper.state` 混用分隔符 ⟹ 统一成宿主原生形态（POSIX 不变）。
    return os.path.join(os.path.normpath(root), ".gatekeeper.state")


def _dep_missing_code(state_file, fid):
    """`missing` 细分（§17-6 P2 四码）：purged / renamed / never-registered / wrong-root。"""
    try:
        import gk_finding as gf
        events = gf._journal_events(state_file)
    except Exception:  # noqa: BLE001 — 读不到 journal ⟹ 归 wrong-root
        return "wrong-root"
    purged, seen, renamed = set(), False, False
    for e in events:
        if e.get("event") == "epoch":
            purged.update(str(x) for x in (e.get("purged_fids") or []))
        if str(e.get("fid", "")) == fid:
            seen = True
        if e.get("event") == "rename" and str(e.get("from", "")) == fid:
            renamed = True
    if fid in purged:
        return "purged"
    if renamed:
        return "renamed"
    if not seen:
        return "never-registered"
    return "wrong-root"


def _journal_has_event(state_file, fid):
    """fid 是否在 finding-journal 有**前序事件**（§17-4：co_land 的 `closed` 须有 lifecycle 留痕，
    防「裸 JSON 幻影 closed」= 状态门与日志门配对）。journal 缺失/损坏 ⟹ False（fail-closed）。"""
    try:
        import gk_finding as gf
        events = gf._journal_events(state_file)
    except Exception:  # noqa: BLE001 — 读不到 ⟹ 不可配对
        return False
    return any(str(e.get("fid", "")) == fid for e in events)


def check_dep_gate(doc, state_file, findings):
    """§17 **机械依赖门**（`L-DEP-FINDING`；spec = state-single-authority 计划「附-1」）。

    `ECC-57A1D39ABB4E`：计划文档 `### 依赖门` 声明块内 `depends_on_closed` 任一 ID 在**权威源**
    `status != closed`（且未被 `waiver` 覆盖）⟹ `high`（`main()` 既有「high/medium ⟹ exit 1」=
    「§17 拒落刀」）。**纯读**、`_CMD_REG` 不变；缺声明块 ⟹ **零 finding**（opt-in，不追溯存量计划）。

    权威源 = `gk_finding.status_map()`（`close()` 单一写入口所在账的**全源**枚举）；**禁**直读裸 JSON。

    同批门 `co_land`（C1，与 `depends_on_closed` 解耦；§17-4 收窄 2026-10-04）：任一 ID
    `status != "closed"`（含 missing）**或** closed 无 finding-journal 前序事件 ⟹ `high`。
    语义 = 「修复已落**且已闭**、并有 lifecycle 留痕 ⟹ 可与本批同批 close」；`verified` 在生产
    状态机无写入口（幻影分支）+ 幻影臂 `test_co_land_verified_ok` 已删。
    """
    decl = _dep_declaration(doc)
    if not decl:
        return
    ids = [str(x).strip() for x in (decl.get("depends_on_closed") or []) if str(x).strip()]
    co = [str(x).strip() for x in (decl.get("co_land") or []) if str(x).strip()]
    if not ids and not co:
        return
    waived = set()
    for w in (decl.get("waiver") or []):
        if (isinstance(w, dict) and str(w.get("id", "")).strip()
                and str(w.get("reason", "")).strip() and str(w.get("authorized_by", "")).strip()):
            waived.add(str(w["id"]).strip())
    if not os.path.isfile(state_file):
        findings.append((CHECK_DEP, "high",
                         f"依赖门：权威 state 根解析到不存在的文件（missing:wrong-root {state_file}）"
                         "⟹ §17 拒落刀"))
        return
    try:
        import gk_finding as gf
        smap = gf.status_map(state_file)
    except Exception as e:  # noqa: BLE001 — 权威源不可读 ⟹ fail-loud（不静默放行）
        findings.append((CHECK_DEP, "high",
                         f"依赖门：权威源不可读（{e}）⟹ 无法判定依赖/同批"))
        return
    for fid in ids:
        if fid in waived:
            findings.append((CHECK_DEP, "info", f"依赖门：{fid} 经 waiver 豁免（owner 裁定留痕）"))
            continue
        st = smap.get(fid)
        if st != "closed":
            tag = st if st else ("missing:" + _dep_missing_code(state_file, fid))
            findings.append((CHECK_DEP, "high",
                             f"依赖门：{fid} status={tag} ≠ closed ⟹ §17 拒落刀"))
    # 同批门（co_land，C1；§17-4 收窄 2026-10-04）：判据 = `status == "closed"` **且**
    #   finding-journal 有前序事件配对 —— `verified` 在生产状态机**无写入口**（幻影分支，
    #   原 `∉ {verified, closed}` 的 verified 侧不可达 ⟹ 已删 + 幻影臂 `test_co_land_verified_ok`
    #   已删）；journal 配对防「裸 JSON 幻影 closed」。missing/其它 ⟹ high。
    for fid in co:
        st = smap.get(fid)
        if st == "closed":
            if _journal_has_event(state_file, fid):
                continue
            findings.append((CHECK_DEP, "high",
                             f"同批门：{fid} status=closed 但 finding-journal 无前序事件配对"
                             " ⟹ 同批约束未满足"))
            continue
        tag = st if st else ("missing:" + _dep_missing_code(state_file, fid))
        findings.append((CHECK_DEP, "high",
                         f"同批门：{fid} status={tag} ≠ closed（§17-4 收窄：仅 closed 可同批）"
                         " ⟹ 同批约束未满足"))


# ── PW-SN 增量（Infra-3，2026-10-05）────────────────────────────────────────
# 规则源 = `docs/plans/2026-10-04-plan-refine-group-dispatch-plan.md §9`（PW-1..PW-9）。
# **分诊裁定（用户 2026-10-05）**：只落**可机检的 6 条**（PW-1/2/3/4/8/9）；
# PW-5（恒真/退化判据）/ PW-6（自洽性）/ PW-7（数量声明缺源）判**启发式 ⟹ 不机检**（答 §7-Q6）。
_RE_PW_PATH = re.compile(r"`([A-Za-z0-9_./\\-]+\.(?:py|sh|md|json))`")
_RE_PW_SEC = re.compile(r"§\s?\d+(?:\.\d+)*")
_RE_PW_DATE = re.compile(r"20\d{2}-\d{2}-\d{2}")
_RE_PW_MD = re.compile(r"[A-Za-z0-9_./\\-]+\.md")
_RE_PW_CONST = re.compile(r"`([A-Z][A-Z0-9_]{4,})`")
_RE_PW_CTX = re.compile(r"墙|上限|常量|阈值|默认|cap|MAX")
_RE_PW_BASIS = re.compile(r"§\s?\d|[A-Za-z0-9_./\\-]+\.(?:py|sh|md|json):[#]?L?\d+")
_RE_PW_MEASURE = re.compile(r"pytest|命令|实测|==|<=|>=|`[^`]*`|\d")
_RE_PW_STATUS = re.compile(r"待消解|已消解|未消解|待证|已实测|待验证|已验")
# PW-3：**带日期文档名「紧邻」§**（中间无 `.md`）—— 窄口径，避自指 `§N` / 远距离日期注误报。
_RE_PW_DATED_SEC = re.compile(r"20\d{2}-\d{2}-\d{2}[\w.-]*\s*§\s?\d+(?:\.\d+)*")


def _col_rows(doc, header_key):
    """抽 markdown 表中**表头含 header_key** 的那一列 ⟹ [(row_idx, cell), ...]。"""
    rows, ci = [], None
    for ln in doc.splitlines():
        s = ln.strip()
        if not s.startswith("|"):
            ci = None
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if ci is None:
            hit = [j for j, c in enumerate(cells) if header_key in c]
            if hit:
                ci = hit[0]
            continue
        if all(_RE_TBL_SEP.match(c) for c in cells):
            continue
        if len(cells) > ci:
            rows.append((len(rows), cells[ci]))
    return rows


def check_pw_landing(doc, repo, index, findings):
    """PW-2 幻影落刀点：任务表「落刀点」列的**仓内路径**（含 `/`）须实存。

    **窄口径**：只判含 `/` 的路径 token —— 裸 basename / 缩写（含 `...`，如
    `2026-09-14-...subplan.md`）属散文提及，**不作落刀点路径判**（防误报）。
    """
    for ri, cell in _col_rows(doc, "落刀点"):
        for m in _RE_PW_PATH.finditer(cell):
            rel = m.group(1).replace("\\", "/")
            if "/" not in rel:
                continue
            if _resolve_path(rel, repo, index) is None:
                findings.append((CHECK_PW_LANDING, "high",
                                 f"幻影落刀点：落刀点列 `{rel}` 仓内不存在（PW-2）"))


def check_pw_landing_dup(doc, findings):
    """PW-4 落刀点重叠（双拆）：**同一落刀点单元格**（归一化后）出现在 ≥2 行任务 ⟹ medium。

    **窄口径**：比对**整个落刀点单元格**（非单 token）—— 多任务合法共享同一文件不报。
    """
    seen = {}
    for ri, cell in _col_rows(doc, "落刀点"):
        norm = re.sub(r"[\s`*]", "", cell)
        if norm:
            seen.setdefault(norm, []).append(ri)
    for norm, rws in sorted(seen.items()):
        if len(rws) > 1:
            findings.append((CHECK_PW_LANDING_DUP, "medium",
                             f"落刀点重叠（双拆）：同一落刀点出现在 {len(rws)} 行任务（PW-4）：{norm[:60]}"))


def check_pw_bare_section(doc, findings):
    """PW-3 裸节号/错引：**带日期文档名紧邻 `§N`** 且中间**无 `.md` 路径** ⟹ medium。

    **窄口径**：只认「`<dated-slug> §N`」紧邻形态 —— 自指 `§N`（本文档内）与远距离日期注**不报**。
    """
    for i, ln in enumerate(doc.splitlines(), 1):
        for m in _RE_PW_DATED_SEC.finditer(ln):
            if ".md" in m.group(0):
                continue
            findings.append((CHECK_PW_SEC, "medium",
                             f"裸节号/错引（PW-3）：L{i} 带日期文档名紧邻 `§` 却无 `.md` 路径："
                             f"{m.group(0)[:60]}"))
            break


def check_pw_assume(doc, findings):
    """PW-8 假设三要素：`[ASSUMPTION-N]` **定义行**须含 依据 / 可测 / 状态。"""
    for ln in doc.splitlines():
        if not _RE_ASSUME_DEF.match(ln):
            continue
        miss = []
        if not _RE_PW_BASIS.search(ln):
            miss.append("依据")
        if not _RE_PW_MEASURE.search(ln):
            miss.append("可测")
        if not _RE_PW_STATUS.search(ln):
            miss.append("状态")
        if miss:
            findings.append((CHECK_PW_ASSUME, "medium",
                             f"假设缺三要素 {miss}（PW-8）：{ln.strip()[:70]}"))


def check_pw_const(doc, plan_path, repo, findings):
    """PW-9 常量名实存：`墙/上限/常量/阈值/默认` 语境的全大写常量名须仓内实存。

    **拟设豁免**（对齐 PW-1）：标「拟设（+同批实装）」的行不判 —— 其载体与开关同批实装。
    """
    cands = set()
    for ln in doc.splitlines():
        if "拟设" in ln:
            continue
        if _RE_PW_CTX.search(ln):
            cands.update(_RE_PW_CONST.findall(ln))
    if not cands:
        return
    allblob = _outside_text(repo, plan_path)
    for c in sorted(cands):
        if allblob.count(c) <= 0:
            findings.append((CHECK_PW_CONST, "medium",
                             f"常量名 `{c}` 在「墙/上限/常量/阈值/默认」语境被引用，"
                             "但仓内（除本文档）0 命中（PW-9）"))


def _iter_prod_text(repo, exts=(".py", ".sh")):
    """生产侧（**非测试**）文本并集 —— PW-10/PW-11 的判定语料。"""
    parts = []
    for p in _iter_files(repo, exts):
        b = os.path.basename(p)
        if b.startswith("test_") or b.endswith("_test.py"):
            continue
        try:
            parts.append(_read(p))
        except OSError:
            continue
    return "\n".join(parts)


def _all_repo_text(repo, plan_path="", exts=(".py", ".sh", ".md")):
    """全仓文本并集（含测试；**排除本文档**）—— PW-10 判定语料。"""
    plan_abs = os.path.abspath(plan_path) if plan_path else ""
    parts = []
    for p in _iter_files(repo, exts):
        if plan_abs and os.path.abspath(p) == plan_abs:
            continue
        try:
            parts.append(_read(p))
        except OSError:
            continue
    return "\n".join(parts)


_RE_PW_WRITE_CTX = re.compile(r"单源|委托|唯一实现|同一实现")
_RE_PW_WRITE_FN = re.compile(r"`(?:[\w./-]+\.py::|gk_[a-z_]+\.)([a-z_][a-z0-9_]{4,})`")


def check_pw_write_impl(doc, plan, repo, findings):
    """PW-10 幻影单源（2026-10-08）：计划以「单源/委托 <fn>」措辞引用，但 `<fn>` 在**全仓**（含测试）
    **零出现** ⟹ 幻影引用（**high**）。

    ⚠ **窄口径**（防误报，对齐 §14.3）：只认 `gk_*.fn` / `*.py::fn` 具名形态，且**全仓零出现**才报
    ⟹ 「测试专用 helper」（如 `_unit_of`）与 `test_*` 具名**天然不报**（首版宽口径在真态计划上误报 3 条，已收窄）。
    「声称复用但生产调用点 = 0」判**启发式 ⟹ 不机检** —— 子进程 / CLI 字符串委托天然无 `fn(` 调用，
    无法与「真幻影」区分（承 disp-plan §14.3 PW-5/6/7 先例）。
    """
    cands = set()
    for ln in doc.splitlines():
        if "拟设" in ln or not _RE_PW_WRITE_CTX.search(ln):
            continue
        for m in _RE_PW_WRITE_FN.finditer(ln):
            fn = m.group(1)
            if fn.startswith("test_"):
                continue
            cands.add(fn)
    if not cands:
        return
    blob = _all_repo_text(repo, plan)
    for fn in sorted(cands):
        if fn not in blob:
            findings.append((CHECK_PW_WRITE_IMPL, "high",
                             f"计划以「单源/委托」引用 `{fn}`，但全仓（含测试）零出现 ⟹ 幻影引用（PW-10）"))


def check_pw_write_only(doc, repo, findings):
    """PW-11 只写不读（2026-10-08）：计划引入的 `read_*` / `count_*` 读侧函数在**生产侧**（非测试）
    零出现 ⟹ 「空转闸机」风险（**medium**；对照 §20.1）。"""
    cands = set()
    for ln in doc.splitlines():
        for m in re.finditer(r"`((?:read|count)_[a-z0-9_]{2,})`", ln):
            cands.add(m.group(1))
    if not cands:
        return
    prod = _iter_prod_text(repo)
    for fn in sorted(cands):
        if fn not in prod:
            findings.append((CHECK_PW_WRITE_ONLY, "medium",
                             f"计划引入读侧函数 `{fn}`，生产侧（非测试）零出现 ⟹ "
                             "空转闸机风险（PW-11）"))


def check_pw_form_suffix(doc, repo, findings):
    """PW-12 形态清单后缀覆盖（2026-10-08）：计划涉及 `.seal` 旁挂封印，但
    `gk_state_forms._ARTIFACT_SUFFIXES` 未收 `.seal` ⟹ 封印被误判**可写 domain** 风险（**medium**）。

    对照 `ECC-8F359340A5B9`（finding 侧 `_LEDGER_ARTIFACT_SUFFIXES` 已收 `.seal`，`state_forms` 侧未收）。
    """
    if not re.search(r"\.seal`|\.seal\b", doc):
        return
    sf = os.path.join(repo, "scripts", "gk_state_forms.py")
    if not os.path.exists(sf):
        return
    try:
        src = _read(sf)
    except OSError:
        return
    if '".seal"' not in src:
        findings.append((CHECK_PW_FORM_SUFFIX, "medium",
                         "计划涉及 `.seal` 旁挂封印，但 gk_state_forms._ARTIFACT_SUFFIXES 无 \".seal\" "
                         "⟹ 封印可能被判可写 domain（PW-12）"))


def check_dispatch_readiness(plan, repo, findings, task="", source_docs=""):
    """PW-13 **下发门预演**（F3，2026-10-15）：把 `gk_task_gate check` 的阻断面与状态域
    路由**前置到计划交付时**（`plan-lint`），而非下发到 `plan-refinement --task` 才炸。

    缺口（D §14.7 F-D）：`plan-lint`（PW-SN）与下发门（`gk_task_gate`）此前**不在同一条链**
    ⟹ 计划交付「全绿」，下发却因 novel_phrase / 语料不可读 / 状态域落错被拒，只能人工反复
    拼命令试。

    `task` 为空 ⟹ 零 finding（**opt-in**，不追溯存量计划；与 `check_dep_gate` 同构）。
    判据：
      · `block_reasons` 非空（provenance_injected / novel_phrase_ungrounded /
        leading_question / poison_marker / schema_violation）⟹ `high`（下发**必被拒**）
      · `material_unreadable` 非空 ⟹ `high`（语料不可读 ⟹ 出处门失效，fail-closed）
      · 计划声明 `state_domain` 但默认路由**未命中该域** ⟹ `medium`（下发落基 state / 组批退化）
    门节点/路由中枢不可用 ⟹ `medium` 报「不可预演」（不静默放行，也不升 high 免误阻断）。
    """
    task = (task or "").strip()
    if not task:
        return
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    # ── ① 下发门预演（单源 = gk_task_gate.check，禁第二实现）──
    try:
        import gk_task_gate as tg
        rep = tg.check(task, plan, source_docs or "")
    except Exception as e:  # noqa: BLE001 — 门节点不可用 ⟹ 报「不可预演」（不静默）
        findings.append((CHECK_PW_DISPATCH, "medium",
                         f"下发门预演不可执行（{e}）⟹ 无法判定 task 是否会被拒（PW-13）"))
        return
    reasons = rep.get("block_reasons") or []
    if reasons:
        bits = ["block_reasons=" + ",".join(map(str, reasons))]
        for key in ("novel_phrases", "injected_terms"):
            if rep.get(key):
                bits.append(f"{key}=" + "|".join(map(str, rep[key][:6])))
        if rep.get("leading_flags"):
            bits.append("leading=" + "|".join(
                str(f.get("pattern", "")) for f in rep["leading_flags"][:6]))
        if rep.get("poison"):
            bits.append("poison=" + "|".join(map(str, rep["poison"][:6])))
        if rep.get("schema_violations"):
            bits.append("schema=" + "|".join(
                str(v.get("rule", "")) for v in rep["schema_violations"][:6]))
        if rep.get("acknowledge_hint"):
            bits.append("acknowledge_hint=" + str(rep["acknowledge_hint"]))
        findings.append((CHECK_PW_DISPATCH, "high",
                         "下发门预演：task 将被 `gk_task_gate` 拒（" + "；".join(bits)
                         + "）（PW-13）"))
    if rep.get("material_unreadable"):
        findings.append((CHECK_PW_DISPATCH, "high",
                         "下发门预演：语料不可读 material_unreadable="
                         + "|".join(map(str, rep["material_unreadable"][:6]))
                         + " ⟹ 出处门失效（fail-closed）（PW-13）"))
    # ── ② 状态域路由预演（防「声明域却落基 state」/ 组批退化）──
    try:
        from gk_route_center import _parse_meta
        meta = _parse_meta(_read(plan)) or {}
    except Exception:  # noqa: BLE001 — 无可解析 META ⟹ 不判（check_meta 另有专条）
        return
    dom = str(meta.get("state_domain") or "").strip()
    if not dom:
        return
    try:
        import gk_route_center as rc
        rs = rc.resolve_state(skill_dir=repo, extra_roots=[])
    except Exception as e:  # noqa: BLE001 — 路由中枢不可用 ⟹ 报「不可预演」
        findings.append((CHECK_PW_DISPATCH, "medium",
                         f"状态域路由预演不可执行（domain={dom}）：{e}（PW-13）"))
        return
    src = str(rs.get("source") or "")
    if src not in ("state_domain", "plan_pointer"):
        sf = str(rs.get("expected") or rs.get("current") or "")
        n = None
        if sf:
            try:
                with open(sf, encoding="utf-8") as fh:
                    nt = (json.load(fh).get("gate_data") or {}).get("narrow_tasks")
                n = len(nt) if isinstance(nt, list) else None
            except Exception:  # noqa: BLE001 — 不可读 ⟹ 不可判定
                n = None
        extra = f"；该 state narrow_tasks={n}" if n is not None else ""
        findings.append((CHECK_PW_DISPATCH, "medium",
                         f"状态域路由预演：计划声明 `state_domain={dom}` 但默认路由未命中"
                         f"（source={src or '<none>'}）⟹ 下发落基 state / 组批退化{extra}（PW-13）"))


def lint(plan, repo, stats=None, task="", source_docs=""):
    """返回 findings 列表（3 元组 `(check, level, detail)`；**契约不变**）。

    `stats`（可选，R-13）：传 dict ⟹ 在同一处填充**机检计数字段**
    （`anchor_findings` 各 reason 计数）；`None` ⟹ 零开销、行为与既有调用点逐字一致。
    """
    doc = _read(plan)
    # 2026-11-01：全仓 basename 索引改**惰性**（§9-6 已有 `_lazy_index`，此处此前未接）——
    #   计划里的锚几乎都是仓内相对路径 ⟹ `_resolve_path` 直连 `isfile` 即命中 ⟹ 全仓 walk 可**完全省掉**。
    index = _lazy_index(repo)
    def_index = _build_def_index(repo)
    _OUTSIDE_TEXT_CACHE.clear()   # 一次 lint 一份语料（防跨调用返回过期内容）
    findings = []
    _REPAIR_HINTS.clear()   # 2026-10-31：一轮 lint 一份清单（防跨调用累积）
    check_anchor(doc, repo, index, findings, def_index)
    check_assume(doc, findings)
    check_switch(doc, plan, repo, findings)
    check_consumer(doc, repo, findings)
    check_criterion(doc, findings)
    check_number(doc, findings)
    check_label(doc, findings)
    check_plan_letter(doc, findings, plan)
    check_version(doc, findings)
    check_meta(doc, findings, plan)
    check_symbol(doc, plan, repo, findings)
    check_pw_landing(doc, repo, index, findings)
    check_pw_bare_section(doc, findings)
    check_pw_landing_dup(doc, findings)
    check_pw_assume(doc, findings)
    check_pw_const(doc, plan, repo, findings)
    # PW-10/11/12（2026-10-08）：幻影单源 / 只写不读 / 形态清单后缀覆盖（edit-budget §23 回流 L 类）。
    check_pw_write_impl(doc, plan, repo, findings)
    check_pw_write_only(doc, repo, findings)
    check_pw_form_suffix(doc, repo, findings)
    # PW-13（F3，2026-10-15）：下发门预演 —— task 缺省空 ⟹ 零 finding（opt-in，零回归）。
    check_dispatch_readiness(plan, repo, findings, task=task, source_docs=source_docs)
    check_dep_gate(doc, _resolve_state_file(repo), findings)
    # ── 三面一致性闸（最小接线；GK_TRI_CONSISTENCY=0 关闭，默认 1）──
    # 见 docs/plans/2026-10-06-tri-consistency-gate-plan.md §0.3/T3。
    if os.environ.get("GK_TRI_CONSISTENCY", "1") != "0":
        try:
            import gk_tri_consistency as _tri
            for _v in _tri.check_verdict_domain():
                findings.append(("tri-consistency", "WARN", _v))
        except Exception:
            pass
    # 去重（同一条可能被多个 check 命中）+ **去重后**折算锚类计数
    # （锚类 finding 为 4 元组 `(check, level, detail, reason)`；输出一律降回 3 元组 ⟹ 契约不变）
    uniq, out, counts = set(), [], {}
    for f in findings:
        key = f[:3]
        if key in uniq:
            continue
        uniq.add(key)
        out.append(key)
        if len(f) == 4:
            counts[f[3]] = counts.get(f[3], 0) + 1
    if stats is not None:
        stats["anchor_findings"] = counts
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("plan")
    ap.add_argument("--repo", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--json", action="store_true")
    # 2026-10-29：供 **CLI 前置门**内嵌（单行 JSON，可与其它字段拼进同一个回包）；
    #   `--json` 保持 indent=2 的既有可读契约不变（零回归）。
    ap.add_argument("--json-compact", action="store_true")
    ap.add_argument("--stats", action="store_true",
                    help="只打印机检计数字段（R-13 载体：裸行锚段级分类 + 锚类计数）；"
                         "等价于 `rg -o -N '`:[0-9]+' <plan> | wc -l` 的可复现替代且多带分类")
    # PW-13（F3，2026-10-15）：下发门预演 —— 交付前以「将下发的 task」预跑 gk_task_gate，
    #   把 novel_phrase / 语料不可读 / 状态域落错等**下发失败因由**前置暴露。
    #   缺省空 ⟹ 零 finding（opt-in，零回归）。
    ap.add_argument("--task-file", default="",
                    help="将下发的窄任务文本文件（PW-13 预演；空 = 跳过）")
    ap.add_argument("--source-docs", default="",
                    help="下发门语料（逗号分隔路径；同 plan-refinement --source-docs）")
    # 2026-10-31（owner 令「plan-lint 谨慎修，但关键位置仍需行号作文辅助定位与漂移证据」）：
    #   只读输出**重钉清单**，不写文件、不改阻断。字段与 `gk_doc_align.anchor_rebase_plan`
    #   对齐（ref / verdict / declared_symbol / symbol_hit_line / symbol_hits_total），
    #   供人直改或 `gk_anchor_rebase.py --map old=new,...` 机械落刀。
    ap.add_argument("--anchor-plan", action="store_true",
                    help="输出锚重钉清单（JSON）：repin = 有符号绑定且已定位新行；"
                         "无输出 = 无漂移。不改文件、不改 exit code")
    # 2026-10-31（owner 令「JSON 不得变成一大坨被截断」）：默认 20 条 + 显式 truncated 标记。
    ap.add_argument("--anchor-limit", type=int, default=20,
                    help="--anchor-plan 最多输出条数（默认 20；0 = 全量）")
    ap.add_argument("--anchor-detail", action="store_true",
                    help="--anchor-plan 附 items（symbol / hits）；默认只给 map 短串")
    a = ap.parse_args()

    _task = ""
    if a.task_file:
        try:
            with open(a.task_file, encoding="utf-8", errors="replace") as fh:
                _task = fh.read()
        except OSError as e:
            print(json.dumps({"ok": False, "error": "task_file_unreadable",
                              "path": a.task_file, "detail": str(e)}, ensure_ascii=False))
            return 2

    if a.stats:
        # 只读：**不**改既有 stdout 契约与 exit code（故独立 flag，不塞进 --json）
        doc = _read(a.plan)
        st = {}
        lint(a.plan, a.repo, st)
        print(json.dumps({"plan": os.path.basename(a.plan),
                          "bare_anchor": bare_anchor_stats(doc),
                          "anchor_findings": st.get("anchor_findings", {})},
                         ensure_ascii=False, indent=2))
        return 0

    findings = lint(a.plan, a.repo, task=_task, source_docs=a.source_docs)

    # 2026-10-31：重钉清单（只读）。**先于**常规输出返回 ⟹ 可与 `--json` 组合但后者被忽略。
    if a.anchor_plan:
        _seen, _all = set(), []
        for _h in anchor_repair_hints():
            _k = _h.get("ref")
            if _k in _seen:
                continue
            _seen.add(_k)
            _all.append(_h)
        # 输出契约（owner 令「不得一大坨」）：
        #   · `map` 是**唯一必需字段**，每项 `old=new` 短串 ⟹ 可直接喂
        #     `gk_anchor_rebase.py --map`，100 条约 3KB（indent 也不会爆）；
        #   · `items` 仅在 `--anchor-detail` 时给（含 symbol / hits），默认省略；
        #   · 超限**显式** `truncated: true` + `hint` 指向 `--anchor-limit 0`，绝不静默截断。
        _map = []
        for h in _all:
            _ref = str(h.get("ref") or "")
            _nl = h.get("symbol_hit_line")
            # 目标文件名：`_verify_def_at` 给 `target_file`（裸符号锚的 ref 不含文件名）；
            # `_verify_literal` 的 ref 自带文件名 ⟹ 回退切分。
            _tf = h.get("target_file") or (_ref.rsplit(":", 1)[0] if ":" in _ref else "")
            if _tf and isinstance(_nl, int) and _nl > 0:
                _map.append(f"{_ref}={_tf}:{_nl}")
        _lim = a.anchor_limit if a.anchor_limit and a.anchor_limit > 0 else 0
        _out = {"plan": os.path.basename(a.plan), "count": len(_map),
                "map": (_map[:_lim] if _lim else _map)}
        if _lim and len(_map) > _lim:
            _out["truncated"] = True
            _out["shown"] = _lim
            _out["hint"] = f"仅前 {_lim} 条（合计 {len(_map)}）；--anchor-limit 0 取全量"
        if a.anchor_detail:
            _out["items"] = [{"ref": h.get("ref"), "sym": h.get("declared_symbol"),
                              "to": h.get("symbol_hit_line"), "hits": h.get("symbol_hits_total")}
                             for h in _all[:(_lim or len(_all))]]
        print(json.dumps(_out, ensure_ascii=False, indent=(None if a.json_compact else 2)))
        return 0

    if a.json or a.json_compact:
        print(json.dumps([{"check": c, "level": lv, "detail": d} for c, lv, d in findings],
                         ensure_ascii=False, indent=(None if a.json_compact else 2)))
    else:
        lv_rank = {"high": 0, "medium": 1, "info": 2}
        print(f"# 计划写入安全网 linter: {os.path.basename(a.plan)}")
        print(f"findings = {len(findings)}"
              f" (high={sum(1 for _, lv, _ in findings if lv == 'high')}"
              f" medium={sum(1 for _, lv, _ in findings if lv == 'medium')}"
              f" info={sum(1 for _, lv, _ in findings if lv == 'info')})")
        for c, lv, d in sorted(findings, key=lambda x: lv_rank[x[1]]):
            print(f"  [{lv:6}] {c}: {d}")
    blocking = [f for f in findings if f[1] in ("high", "medium")]
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
