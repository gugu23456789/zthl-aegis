#!/usr/bin/env python3
"""
Gatekeeper Doc-Align — 文档特化类确定性检测引擎（bashpy 同档，2026-08-26）
======================================================================
monitor --align 的升格实现：0 API、纯静态扫描、JSON 检查项输出。

定位: ECO-DOC 阶段的新陈代谢校验面 — 检测「文档/论文框架 vs 当前实现」漂移。
2026-08-28 合并 audit --docs 文档审查引擎（gk_audit_docs.check_docs 的 C1-C5
7 项检查全部吸纳），统一 doc-align 为文档一致性 + 漂移的单一入口。

检查器（31 项 = run_all 静态注册数的**唯一事实源**；`comment_code_mismatch` 双向判等，
       见该检查器 ④。audit_docs 的 7 项经 `for r in check_audit_docs_merged()` **一次
       append** 展开 ⟹ 静态计数 31 = 下表 1–28 行中 audit_docs 的 7 行折为 1 个单位，
       另含 3 项后加检查：`skill_duty_pointer`、`gk_facts` 事实块比对、
       `retired_doc_export` 退役文档不得留在导出面）:
 1. papers_framework_drift   — 论文框架 vs 当前架构事实（2026-10-27 起一篇已归档；
                               在册篇目建事实清单，部分篇目在 SKIP 内 ⟹ 检查面 = 在册且未 skip 的篇目）
 2. cli_protocol_commands    — references/cli-protocol.md 命令数 vs gatekeeper-cli.sh _CMD_REG
 3. review_dual_source       — stage-3-review vs requesting-code-review 的 L1-L9 唯一源一致性
 4. skill_optimizer_status   — SKILL.md 优化器状态表 未实现项登记（INFO，随实现滚动）
 5. stale_layering_refs      — 活跃文档 L1-L7/7 层审查 陈旧引用扫描（ecc-*/analysis 历史除外）
 6. skill_command_count      — SKILL.md '支持 N 命令' vs _CMD_REG 实际数
 7. audit_docs_cli_protocol  — [审] cli-protocol.md 声明命令数 vs 表格行数（文档内部自洽）
 8. audit_docs_extension_reg — [审] extension-registry.md CLI 命令表条目数
 9. audit_docs_arch_map      — [审] architecture-overview.md references/ 文件地图 vs 实际文件
10. audit_docs_meta_audit    — [审] meta-routing AUDIT-STATE/AUDIT-REPORT 阶段覆盖
11. audit_docs_meta_red      — [审] meta-routing RED-SCOPE/RED-REPORT 阶段覆盖
12. audit_docs_meta_15phase  — [审] meta-routing 15-phase standing（ECO-RESEARCH→RED-REPORT）覆盖
13. audit_docs_bashpy_taxo   — [审] bashpy-problem-taxonomy.md 分类学结构（权威源/基线/双循环）
14. crossref_drift           — 关键文档（评估/安全网/模板/batch8/red-findings）互引锚点漂移
                              （目标 .md 存在 + §N 章节号命中；用户质询"引用链漂移是谁在查"驱动）
15. symbol_index_existence   — [索] 架构文档引用符号 vs gitnexus 索引实存（WARN 不阻断）
16. cross_review_matrix      — [矩] L1-L9 × 约束-难度矩阵确定性命令存在性
17. eval_matrix              — [矩] E1-E4 子集评估器规格结构 + 列共享 schema
18. sequence_node_map        — [路] 序列节点安全网 map/车站播报/下一站过时（2026-10-28 扩面：
                              references/*.md 全量 + 双向 + monitor-schemas + 旧站名渗透）
19. comment_code_mismatch    — [路] 注释-代码错配（引用目标实存 + docstring 检查器计数**判等**）
20. route_center_alignment   — [路] 5 层路由文档 ↔ 代码一致
21. tenant_isolation         — [租] scopes 租户根双形态重复/嵌套（WARN）
22. doc_freshness            — [新] references 安全网总表回流最近登记批次（F-REV-20 前身）
23. shell_python_serialization — [序] shell→python 三引号源码内插零容忍（F-REV-20）
24. anchor_existence         — [锚] 文档 path:line 锚存在性（WARN 不阻断）
25. plan_landing_drift       — [计] 计划落刀点 vs 代码实况（ECC-PLAND，WARN）
26. subagent_unlogged        — [报] subagent 报告 ↔ 派发账本（近期未入账 FAIL）
27. stage_duty_map           — [段] 段职责表 ↔ STAGE 分支 gate-id 双向比对（表未落地 WARN；沿用 T10/A-2）
28. force_teaching           — [力] references 不得把 `advance --force` 教成常规路径（缺豁免语境 WARN）

用法:
  python3 scripts/gk_doc_align.py [--skill-dir D] [--papers-dir P] [--summary] [--strict]

输出: {"ok": true, "issues": N, "warns": M, "checks": [...]}
exit code: 1 if issues > 0（FAIL 项计 issue）；`--strict` 时 WARN 亦计失败
           （2026-10-28：旧行为 WARN 恒不阻断 ⟹ 151 条锚漂移/17 条计划漂移可以「issues=0」假绿）
"""
import ast
import inspect
import json
import os
import re
import sys
import time
from pathlib import Path

from gk_json_utils import extract_last_json, extract_markdown_int, extract_markdown_table
from gk_json_utils import read_state_file
import gk_host_paths as _host_paths  # noqa: E402  跨宿主路径形态/用户目录单源

# ── 论文框架事实清单（**私有面**，2026-10-28 G7b 裁剪）────────────────────────
# 清单正文已搬到 `scripts/gk_paper_facts.py`（含 PAPER_FACTS / _paper_plan / 检查器），
# 并在 `references/oss-export-whitelist.json` 的 `exclude_globs` 中排除 —— 公开包里的
# 「通用文档对齐引擎」不再携带稿件章节/术语指纹（§5.4.3 G7b）。
# 导出面（无该模块）由下方 `_paper_checker()` 显式降级为 `SKIP`，**不**伪装成 PASS。

# SKILL.md 优化器状态表已知未实现项（INFO 登记，随实现滚动更新）
# 2026-08-27 校正×2: T42/T45/T46 等价实现于 2 个 spz 项目 CI 管线+模版（spz_gatekeeper ci.yml
# zizmor/failure()日志/smoke重试/challenge gate + spz2glb test-wasm-build build.log）；
# T44 auto-fix=安全网雏形（wasm-pre-check P0-P6 --auto-fix 已实现）。剩余缺口 = W9 通用流程级
# auto-fix 循环（80% 确定性修复 + 20% default subagent LLM 兜底→standard 序列，R-T8 前置）。
KNOWN_UNIMPLEMENTED = ["W9"]


# ── 通用工具 ─────────────────────────────────────────────────────────
def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _count_cmd_reg(cli_text: str) -> int:
    # 口径 = `_CMD_REG[...]=` **赋值行**数（读取/注释里的 `_CMD_REG[...]` 不计——`ECC-439C8B7CF048` D2）。
    # 命令名含连字符（self-check/doc-align/stage-detail 等）；**并须容纳数字/大写**：
    # 原 `[a-z-]+` 遇 `stage2`/`Probe` 类名即**静默漏计**（`ECC-439C8B7CF048` D3）。
    return len(re.findall(r"_CMD_REG\[[A-Za-z0-9_-]+\]=", cli_text))


# ── 检查器 1: 论文框架漂移（私有面按需加载）──────────────────────────
def _paper_checker():
    """按需取私有面检查器；导出面（无 `gk_paper_facts.py`）返回 None。

    失败模式纪律：**不做**「导入失败就伪造 PASS」——那是假绿；返回 None 的调用方必须
    显式 SKIP 并写明原因（公开包确实没有论文事实清单）。
    """
    try:
        from gk_paper_facts import check_papers_framework_drift as _fn
        return _fn
    except ImportError:
        return None


def check_papers_framework_drift(papers_dir: str) -> dict:
    """论文框架 vs 当前架构事实（实现单源 = 私有面 `gk_paper_facts.py`）。"""
    fn = _paper_checker()
    if fn is None:
        return {"check": "papers_framework_drift", "status": "SKIP",
                "detail": "论文事实清单未随包（私有面 gk_paper_facts.py 不存在）— 跳过"}
    # 2026-11-08（v0.9.8.3 发布实测）：外部论文目录是**本机私有依赖**（`GK_PAPERS_DIR`
    #   默认指向 Downloads 下的论文仓副本），在他人机器/CI/导出树上必然不存在。
    #   原实现把它算 WARN ⟹ `gk_doc_release --strict`（= WARN 也阻断）在干净环境**恒红**，
    #   发布门被一条"无法检测"卡死。无法检测 ≠ 发现漂移 ⟹ 统一按 SKIP 计（附原因），
    #   与 `symbol_index_existence`（gitnexus 不可用）同语义。
    if not Path(papers_dir).is_dir():
        # 不回显具体路径：它是本机绝对路径（含用户名），输出面不落盘。
        return {"check": "papers_framework_drift", "status": "SKIP",
                "detail": "外部论文目录不存在 — 外部依赖缺失，漂移无法检测 ⟹ SKIP"}
    r = fn(papers_dir)
    if r.get("status") == "WARN" and "无在册篇目" in str(r.get("detail", "")):
        # 无公开篇目 = 无可核对项，不是缺陷；发布门按 SKIP 计（不假绿也不假红）。
        r.update(status="SKIP",
                 detail=str(r.get("detail", "")) + "（无可核对项 ⟹ SKIP）")
    return r


# ── 检查器 2: CLI 命令数 ─────────────────────────────────────────────
def check_cli_protocol_commands(skill_dir: str) -> dict:
    """docs/cli-protocol.md 命令数 vs gatekeeper-cli.sh _CMD_REG 实际数。"""
    result = {"check": "cli_protocol_commands"}
    cli = Path(skill_dir) / "gatekeeper-cli.sh"
    proto = Path(skill_dir) / "references" / "cli-protocol.md"
    if not cli.exists() or not proto.exists():
        result["status"] = "FAIL"
        result["detail"] = "gatekeeper-cli.sh 或 cli-protocol.md 缺失"
        return result
    actual = _count_cmd_reg(_read(cli))
    proto_text = _read(proto)
    m = re.search(r"\*\*Commands\*\*:\s*(\d+)", proto_text)
    doc = int(m.group(1)) if m else None
    # 2026-11-01：命令表 ↔ `_CMD_REG` **集合等价**（原只比数量 ⟹ 换名/漏行仍假绿）。
    # 表行形如 `| 1 | \`cmd_pre_check\` | …`；注册表键是连字符形态 ⟹ 归一后比较。
    rows = {x.replace("_", "-").lower()
            for x in re.findall(r"(?m)^\|\s*\d+\s*\|\s*`(?:cmd_)?([a-z0-9_]+)`", proto_text)}
    reg = set(re.findall(r"(?m)^_CMD_REG\[([a-z0-9-]+)\]", _read(cli)))
    missing = sorted(reg - rows)
    extra = sorted(rows - reg)
    result["missing"] = missing[:10]
    result["extra"] = extra[:10]
    if doc is None:
        result["status"] = "FAIL"
        result["detail"] = "cli-protocol.md 缺 Commands 计数（docgen 未生成）"
    elif actual != doc:
        result["status"] = "WARN"
        result["detail"] = f"命令数漂移: _CMD_REG={actual} vs cli-protocol={doc} — 跑 docgen"
    elif missing:
        result["status"] = "FAIL"
        result["detail"] = "命令表缺 %d 个已注册命令（跑 docgen）: %s" % (
            len(missing), ", ".join(missing[:6]))
    elif extra:
        result["status"] = "WARN"
        result["detail"] = "命令表含 %d 个未注册行（历史残留，跑 docgen）: %s" % (
            len(extra), ", ".join(extra[:6]))
    else:
        result["status"] = "PASS"
        result["detail"] = f"命令表与 _CMD_REG 集合等价 ({actual})"
    return result


# ── 检查器 3: 双源 L 层唯一源一致性 ──────────────────────────────────
def check_review_dual_source(skill_dir: str, review_skill_dir: str,
                             release: bool = False) -> dict:
    """stage-3-review（流程壳）引用 requesting-code-review（L1-L9 唯一源），且两边都含 L1-L9。

    `release=True`：stage-3-review.md 属导出排除面（stage 指南合并为 `stages.md`）⟹
    公开树缺席降级 SKIP。
    """
    result = {"check": "review_dual_source"}
    stage3 = Path(skill_dir) / "references" / "stage-3-review.md"
    reqcr = Path(review_skill_dir) / "SKILL.md"
    if not stage3.exists():
        if release:
            result["status"] = "SKIP"
            result["detail"] = ("release 模式：references/stage-3-review.md 属导出排除面"
                                "（stage 指南已合并为 stages.md）⟹ 公开树缺席是预期")
            return result
        result["status"] = "FAIL"
        result["detail"] = "stage-3-review.md 缺失"
        return result
    s3 = _read(stage3)
    if not reqcr.exists():
        result["status"] = "SKIP" if release else "WARN"
        result["detail"] = ("requesting-code-review 未安装（外部兄弟技能，发布门不可验证）⟹ SKIP"
                            if release else
                            "requesting-code-review 缺失 — stage-3-review 应引用但不可验证")
        return result
    rc = _read(reqcr)
    s3_links = "requesting-code-review" in s3
    s3_l9 = "L1-L9" in s3
    # A8（2026-10-28）：端口档形态已两分 —— 仓内归档 = **剥了正文的指针**（指向
    # `stage-3-review.md`）；运行时兄弟技能仍可能是 superpowers 全本（含 `Nine-Layer` 表）。
    # 判据接受**任一**形态：两者都证明「这份档能定位到 L1-L9 方法学」。
    rc_pin = ("stage-3-review.md" in rc) or ("Nine-Layer" in rc)
    problems = []
    if not s3_links:
        problems.append("stage-3-review 未引用 requesting-code-review")
    if not s3_l9:
        problems.append("stage-3-review 缺 L1-L9")
    if not rc_pin:
        problems.append("requesting-code-review 端口档未指向 stage-3-review.md（方法学指针缺失）")
    if problems:
        result["status"] = "FAIL" if not s3_links else "WARN"
        result["detail"] = "; ".join(problems)
    else:
        result["status"] = "PASS"
        result["detail"] = "双源一致: requesting-code-review 指针 → stage-3-review（L1-L9 唯一源）"
    return result


# ── 检查器 4: 优化器状态表登记 ───────────────────────────────────────
def check_skill_optimizer_status(skill_dir: str) -> dict:
    """SKILL.md 优化器状态表未实现项（T44-T46 等）登记为 INFO（已知负债，随实现滚动）。"""
    result = {"check": "skill_optimizer_status"}
    skill = Path(skill_dir) / "SKILL.md"
    if not skill.exists():
        result["status"] = "FAIL"
        result["detail"] = "SKILL.md 缺失"
        return result
    text = _read(skill)
    unimpl = [t for t in KNOWN_UNIMPLEMENTED if f"{t}" in text]
    result["status"] = "INFO"
    result["detail"] = f"优化器未实现项登记: {unimpl if unimpl else '无'}"
    result["known_unimplemented"] = unimpl
    return result


# ── 检查器 5: 陈旧层数引用扫描 ───────────────────────────────────────
# 2026-08-26 收敛后 L 层 = L1-L9（requesting-code-review 唯一源）。活跃文档中残留
# "L1-L7"/"7 层审查" 即漂移；ecc-*/analysis 历史记录除外（当轮审查事实，不可改写）。
STALE_PATTERNS = ["L1-L7", "7 层审查", "7层审查", "six-layer", "Six-Layer", "六层"]


def check_stale_layering_refs(skill_dir: str) -> dict:
    """扫描活跃文档中的 L1-L7/7 层审查 陈旧引用（排除 ecc-*/analysis 历史记录）。"""
    result = {"check": "stale_layering_refs"}
    refs = Path(skill_dir) / "references"
    plans = Path(skill_dir) / "docs" / "plans"
    targets = list(refs.glob("*.md"))
    if plans.is_dir():
        targets += list(plans.glob("*.md"))
    targets.append(Path(skill_dir) / "SKILL.md")
    hits = []
    for p in targets:
        name = p.name
        if name.startswith("ecc-") or "analysis" in str(p).lower():
            continue  # 历史记录：当轮审查事实，不属漂移
        text = _read(p)
        for pat in STALE_PATTERNS:
            for line in text.splitlines():
                if pat in line:
                    hits.append(f"{name}:{pat}")
                    break  # 每文件每模式一条（文件级漂移标记）
    if hits:
        result["status"] = "WARN"
        result["detail"] = f"{len(hits)} 处陈旧层数引用: " + ", ".join(hits[:14])
        result["stale"] = hits
    else:
        result["status"] = "PASS"
        result["detail"] = "活跃文档无 L1-L7/7 层审查 陈旧引用"
    return result


# ── 检查器: 退役文档不得留在公开导出面 ──────────────────────────────
# 2026-11-05（用户质询「flows-abc 已经退役了，放出去不是误导吗」）：
#   文件地图/引用漂移只查「链接还在不在」，**不查「这份文档该不该对外」**——于是
#   flows-a-b-c.md 正文写着「已合并至 meta-routing-protocol」却仍以 status: public
#   进公开索引；ecc-impact-v7.md 这类内部裁定同样默认随包导出。本检查补这一面：
#   正文含退役标记 ⟹ 必须命中 oss-export-whitelist 的四类排除之一，否则 FAIL。
_RETIRED_MARKERS = ("已退役", "已废弃", "已合并至", "status: deprecated", "status: retired")


def check_retired_doc_export(skill_dir: str) -> dict:
    """退役文档不得留在公开导出面（`references/*.md`）。

    判据 = 正文含 `_RETIRED_MARKERS` ⟹ 必须被 `references/oss-export-whitelist.json`
    的 exclude_names / prefixes / suffixes / globs 之一覆盖（与 `oss_scrub.is_excluded`
    同语义，四类都按原样匹配，不新增第二套排除规则）。
    """
    result = {"check": "retired_doc_export"}
    refs = Path(skill_dir) / "references"
    try:
        wl = json.loads((refs / "oss-export-whitelist.json").read_text(encoding="utf-8"))
        names = {e["pattern"] for e in wl.get("exclude_names", [])}
        prefixes = tuple(e["pattern"] for e in wl.get("exclude_prefixes", []))
        suffixes = tuple(e["pattern"] for e in wl.get("exclude_suffixes", []))
        globs = [re.compile(e["pattern"]) for e in wl.get("exclude_globs", [])]
    except Exception as e:
        return {**result, "status": "SKIP", "detail": "导出白名单不可读：%s" % e}

    def _excluded(rel: str) -> bool:
        return (rel in names or (prefixes and rel.startswith(prefixes))
                or (suffixes and rel.endswith(suffixes))
                or any(rx.search(rel) for rx in globs))

    leaked, retired = [], []
    for p in sorted(refs.glob("*.md")):
        if not any(m in _read(p) for m in _RETIRED_MARKERS):
            continue
        retired.append(p.name)
        if not _excluded("references/" + p.name):
            leaked.append(p.name)
    if leaked:
        result.update({"status": "FAIL",
                       "detail": "退役文档仍在导出面（删除或加入 exclude_globs）: "
                                 + ", ".join(leaked[:8]),
                       "leaked": leaked, "retired": retired})
    else:
        result.update({"status": "PASS",
                       "detail": "退役文档 %d 份均已脱离导出面" % len(retired),
                       "retired": retired})
    return result


# ── 检查器 6: SKILL.md 命令数对账 ────────────────────────────────────
def check_skill_command_count(skill_dir: str) -> dict:
    """SKILL.md '支持 N 命令' 常量 vs _CMD_REG 实际数（架构概览漂移面）。"""
    result = {"check": "skill_command_count"}
    skill = Path(skill_dir) / "SKILL.md"
    cli = Path(skill_dir) / "gatekeeper-cli.sh"
    if not skill.exists() or not cli.exists():
        result["status"] = "FAIL"
        result["detail"] = "SKILL.md 或 gatekeeper-cli.sh 缺失"
        return result
    m = re.search(r"支持\s*(\d+)\s*命令", _read(skill))
    doc = int(m.group(1)) if m else None
    actual = _count_cmd_reg(_read(cli))
    if doc is None:
        result["status"] = "FAIL"
        result["detail"] = "SKILL.md 缺 '支持 N 命令' 常量（漂移检测无法锚定）"
    elif doc == actual:
        result["status"] = "PASS"
        result["detail"] = f"命令数一致 ({actual})"
    else:
        # 2026-09-05 升级 WARN→FAIL：命令数漂移 = 用户可见文档失配（曾以 WARN 被 doc-align exit 0
        # 掩盖、仅单测暴露——SKILL.md 42 vs _CMD_REG 43 案例）；docgen 只同步 cli-protocol，
        # SKILL.md 命令清单需人工同步 → 漂移即阻断（对齐本模块 FAIL=需修复语义）。
        result["status"] = "FAIL"
        result["detail"] = f"SKILL.md 命令数={doc} vs _CMD_REG={actual} — 需同步（SKILL.md 命令清单人工补，docgen 已更新 cli-protocol）"
    return result


# ── 检查器 7-13: 文档审查引擎合并（audit --docs 7 项，2026-08-28）─────────
# 吸纳 gk_audit_docs.check_docs 的 C1-C5（cli-protocol 自洽 / extension-registry /
# architecture-overview 文件地图 / meta-routing 3 项 / bashpy 分类学结构）。
# 归一化为 doc-align 的 PASS/FAIL 状态；FAIL 计 issue（exit 1 驱动 docgen 修复）。
_IMPORT_AUDIT_DOCS = None


def _load_audit_docs():
    global _IMPORT_AUDIT_DOCS
    if _IMPORT_AUDIT_DOCS is None:
        try:
            import gk_audit_docs
            _IMPORT_AUDIT_DOCS = gk_audit_docs
        except Exception as e:
            _IMPORT_AUDIT_DOCS = e
    return _IMPORT_AUDIT_DOCS


# ── 检查器 14: 交叉引用链漂移（2026-08-28，用户质询驱动）─────────────
# 定位：评估文档/安全网/模板/batch8/red-findings 之间的互引锚点（§N/N.M 章节号 + 文件路径）
# 若失效 → 引用链静默漂移（用户质询"引用链链接漂移是交叉审查在做？"——答：L1-L9/audit --crossr
# 均不检测，此为确定性缺口，按评估文档 §12 归口规则"静态存在性类→doc-align"补齐）。
# 覆盖：源文档引用的 .md 目标存在 + 章节号锚点（§N / N.M / 非数字锚点）在目标标题/正文出现。
_CROSSREF_DOCS = [
    "docs/plans/2026-08-28-security-hardening-assessment.md",   # 8 域评估（权威总索引）
    "docs/plan-backup/2026-06-22-batch8-python-migration-plan.md",
    "docs/plan-backup/2026-08-27-red-findings-gap-closure-hslsn.md",
    "references/security-measures.md",
    "references/sequence-node-safety-net-template.md",
    "references/meta-routing-protocol.md",
    "references/architecture-overview.md",
    "references/oss-hooks.md",                                 # 开源 hook 契约（2026-11-03）
    "references/oss-moa-phase-provenance.md",                  # MoA 污染 provenance 口径（2026-11-03）
]


def _build_md_index(skill_dir: str) -> dict:
    """仓内 .md 可解析索引（docs/ + references/ + 根 SKILL.md）：裸文件名引用解析用。"""
    index: dict[str, list] = {}
    root_skill = Path(skill_dir) / "SKILL.md"
    if root_skill.exists():
        index.setdefault(root_skill.name, []).append(str(root_skill))
    for root in (Path(skill_dir) / "docs", Path(skill_dir) / "references"):
        if not root.is_dir():
            continue
        for p in sorted(root.rglob("*.md")):
            index.setdefault(p.name, []).append(str(p))
    return index


def _export_excluded(rel: str, skill_dir) -> bool:
    """公开导出**排除面**判定（单一事实源 = 随包导出的 `references/oss-export-whitelist.json`）。

    为何不 `import oss_scrub`（2026-11-09）：该脚本自身不导出（反查词表），公开树内 import 必失败
    ⟹ 排除判定静默失效 ⟹ 公开树 doc 门恒红（夜间 bench-nightly 实际失败点）。
    """
    try:
        from oss_export_surface import is_excluded as _ex
        return bool(_ex(rel, str(skill_dir)))
    except Exception:  # noqa: BLE001 — 边界：判定不可用 ⟹ 不豁免（保守）
        return False


def check_crossref_drift(skill_dir: str) -> dict:
    """关键文档互引锚点漂移检测：锚点式引用（path.md §N / #N）目标存在 + 章节命中。

    语义（2026-08-28 实扫校准，避免误报）：
    - 只检测「路径 + 紧邻 §/# 锚点」形态（挂载链均为该形态）；裸路径/历史提交引文/
      外部源码树（如 DSH docs/cordis-*）不属引用链，跳过。
    - 路径前缀 docs/、references/ 解析于本仓；裸文件名经仓内索引解析；索引外裸名
      （如 project_rules.md 全局规则）视为外部引用跳过。
    - 数字锚点取前导数字宽松匹配（防版本号/正文误报平衡）；非数字锚点字面匹配。
    """
    result = {"check": "crossref_drift"}
    issues = []

    def _doc_excluded(rel: str) -> bool:
        """公开包裁剪掉的私仓文档：缺失不算漂移（单一事实源 = 随包导出的白名单 JSON）。"""
        return _export_excluded(rel, skill_dir)

    index = _build_md_index(skill_dir)
    for doc in _CROSSREF_DOCS:
        p = Path(skill_dir) / doc
        if not p.exists():
            if not _doc_excluded(doc):
                issues.append(f"{doc}: 源文档缺失")
            continue
        text = _read(p)
        # `#` 锚点必须紧贴 `.md`（`SKILL.md#Agent`）；树形图里的 `SKILL.md   # Agent`
        # 是代码注释，不是锚点（2026-11-02 修误报）。
        for m in re.finditer(
                r"([A-Za-z0-9_./\-]+\.md)(?:§\s*|#)([^\s，。；;、)）`]+)", text):
            target, anchor = m.group(1), m.group(2)
            if target.startswith("docs/") or target.startswith("references/"):
                cands = [str(Path(skill_dir) / target)]
            else:
                cands = index.get(target, [])
            if not cands:
                continue  # 外部/全局引用（project_rules.md 等）不判定漂移
            exists = [c for c in cands if Path(c).exists()]
            if not exists:
                issues.append(f"{doc} → {target}: 目标文件缺失")
                continue
            sec = re.match(r"\d+(?:\.\d+)*", anchor)
            if sec:
                # 数字锚点：宽松命中（§N / N.M / 标题 N.M 形态）
                pat = r"§?\s*" + re.escape(sec.group()) + r"(?=[\s.、，。:：)）(（/§])"
            else:
                pat = re.escape(anchor)
            if not any(re.search(pat, _read(Path(c))) for c in exists):
                issues.append(f"{doc} → {target} §{anchor}: 章节锚点未命中")
        # 2026-11-02：主机绝对路径 = 公开包不可移植（旧 /mnt/c/Users/<name>、<home> 等）
        # 例外（2026-11-09）：`## 路由白名单基线` 是**代码常量镜像**（安全锚），其值本身
        #   就是主机路径；这里不当作「可移植性指引」扫描，否则 ⑦ 与 14 互相打架。
        scan_text = _read(p)
        if doc == "references/meta-routing-protocol.md":
            _bm = re.search(r"## 路由白名单基线(.*?)(?=\n## |\Z)", scan_text, re.DOTALL)
            if _bm:
                scan_text = scan_text[:_bm.start()] + scan_text[_bm.end():]
        if not _doc_excluded(doc):
            for hm in re.finditer(r"(/mnt/[a-z]/|/home/[^/\s]+/|/root/|[A-Za-z]:\\\\Users\\\\)", scan_text):
                issues.append(f"{doc}: 主机绝对路径 {hm.group(0)}（公开包不可移植）")
    if issues:
        result["status"] = "WARN"
        result["detail"] = f"{len(issues)} 处引用链漂移: " + "; ".join(issues[:10])
        result["drift"] = issues
    else:
        result["status"] = "PASS"
        result["detail"] = f"关键文档 {len(_CROSSREF_DOCS)} 篇互引锚点无漂移"
    return result


def check_audit_docs_merged(skill_dir: str, release: bool = False) -> list[dict]:
    """审计文档审查引擎 7 项 → doc-align check 条目（check 前缀 audit_docs_*）。"""
    mod = _load_audit_docs()
    if isinstance(mod, Exception):
        return [{"check": "audit_docs_import", "status": "FAIL",
                 "detail": f"gk_audit_docs 导入失败: {mod}"}]
    try:
        out = mod.check_docs(skill_dir, release=release)
    except Exception as e:
        return [{"check": "audit_docs_run", "status": "FAIL",
                 "detail": f"check_docs 执行失败: {e}"}]
    converted = []
    for c in out.get("docs_checks", []):
        doc = c.get("doc", "?")
        check_name = c.get("check", "?")
        if c.get("error"):
            status = "FAIL"
            detail = f"{doc}/{check_name} 读取失败: {c['error']}"
        elif c.get("match"):
            status = "PASS"
            detail = (f"{doc}/{check_name}: declared={c.get('declared')} "
                      f"actual={c.get('actual')}")
        else:
            status = "FAIL"
            parts = [f"{doc}/{check_name} 不一致"]
            if c.get("declared") is not None or c.get("actual") is not None:
                parts.append(f"declared={c.get('declared')} actual={c.get('actual')}")
            if c.get("missing"):
                parts.append(f"missing={c['missing'][:6]}")
            if c.get("extra"):
                parts.append(f"extra={c['extra'][:6]}")
            detail = "; ".join(parts)
        converted.append({
            "check": f"audit_docs_{check_name.replace(' ', '_').lower()}",
            "status": status,
            "detail": detail,
            "source": f"gk_audit_docs/{doc}",
        })
    return converted


# ── 聚合 ─────────────────────────────────────────────────────────────
def check_cross_review_matrix(skill_dir: str) -> dict:
    """L1-L9 × 约束-难度矩阵机制实装（2026-09-01，stage-3-review.md 矩阵非纯文本）。

    用户质询"stage-3 的 L1-L9×约束-难度矩阵是纯文本？文本需要更新扩展整理，机制
    也需要实装"。机制 = 矩阵每层登记"确定性命令"，本检查器验证这些命令在
    gatekeeper-cli.sh _CMD_REG 注册表中**实存**（命令存在性，非仅文档描述）：
      - PASS：全部命令存在
      - WARN：有命令未注册（文档登记超前于实现，提示补实装）
      - SKIP：gatekeeper-cli.sh 不可读
    确定性 0 API。与矩阵文本（references/stage-3-review.md）同步维护。
    """
    # 层 → 该层确定性命令（基础检查命令，取自矩阵"确定性命令"列）。
    # 2026-09-05 C1 单源化：共享 gk_self_check.REVIEW_LAYER_MATRIX（E4 四件套同源，
    # 防双写——改注册表一处生效；本函数保留 SKIP 降级语义）
    cli = Path(skill_dir) / "gatekeeper-cli.sh"
    if not cli.exists():
        return {"check": "cross_review_matrix", "status": "SKIP",
                "detail": "gatekeeper-cli.sh 不可读 — 命令存在性检查跳过"}
    try:
        text = cli.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return {"check": "cross_review_matrix", "status": "SKIP",
                "detail": f"gatekeeper-cli.sh 读取失败: {e}"}
    try:
        from gk_self_check import REVIEW_LAYER_MATRIX as MATRIX_COMMANDS
    except Exception as e:
        return {"check": "cross_review_matrix", "status": "SKIP",
                "detail": f"gk_self_check 不可导入（REVIEW_LAYER_MATRIX 单源）: {e}"}
    # _CMD_REG[cmd]=... 提取注册命令名
    registered = set(re.findall(r"_CMD_REG\[([a-z0-9-]+)\]=", text))
    missing_any = []
    for layer, cmds in MATRIX_COMMANDS.items():
        missing = [c for c in cmds if c not in registered]
        if missing:
            missing_any.append(f"{layer}:{','.join(missing)}")
    result = {"check": "cross_review_matrix",
              "layers": len(MATRIX_COMMANDS),
              "missing": missing_any}
    if missing_any:
        result["status"] = "WARN"
        result["detail"] = ("矩阵确定性命令未注册: " + "; ".join(missing_any)
                            + "（文档登记超前于实现 — 需补实装）")
    else:
        result["status"] = "PASS"
        result["detail"] = f"矩阵全部确定性命令已注册（{len(MATRIX_COMMANDS)} 层）"
    return result


# ── 2026-09-06 扩展：E1-E4 子集评估器规格 lint ─────────────────────────
def check_eval_matrix(skill_dir: str, release: bool = False) -> dict:
    """E1-E4 子集评估器规格结构 lint（2026-09-06 实装，check_cross_review_matrix sibling）。

    定位（e1e4-evaluator-matrix.md = plan-refinement SCR 质询协议子集评估器的单源规格，
    doc_freshness(C6) 守护对象）——把「规格结构漂移」（E1-E4 行标记缺失 / 绑定句被改弱 /
    pairwise 去相关段丢失 / ASSUMPTION 三件套 A1-A5 缺登记 / 新鲜度登记行回退）变为可检出：
      - lint 缺任一结构件 → FAIL + 缺项明细（doc-align 检查项面，同 doc_freshness）
      - E4 共享 gk_self_check.REVIEW_LAYER_MATRIX 单源（import 失败 → SKIP 降级，
        同上方 check_cross_review_matrix 的 L465-469 语义）；spec 第 1 节须含列共享
        schema 声明（引用 REVIEW_LAYER_MATRIX 键集 → 与代码层枚举无空交集；宽松：
        声明存在即可，不逐层核对 cell 状态）
      - 反建设 A4（不新建 CLI）：gatekeeper-cli.sh _CMD_REG 提取命令集无 eval 前缀
        新命令 → 含则 WARN
    确定性 0 API（纯静态正则，无网络）。
    """
    result = {"check": "eval_matrix"}
    spec = Path(skill_dir) / "references" / "e1e4-evaluator-matrix.md"
    if not spec.exists():
        if release:
            result["status"] = "SKIP"
            result["detail"] = ("release 模式：references/e1e4-evaluator-matrix.md 属导出排除面"
                                "（references 压缩，owner 2026-10-30）⟹ 公开树缺席是预期")
            return result
        result["status"] = "FAIL"
        result["detail"] = "references/e1e4-evaluator-matrix.md（E1-E4 子集评估器规格）缺失"
        return result
    try:
        text = spec.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        result["status"] = "FAIL"
        result["detail"] = f"e1e4-evaluator-matrix.md 读取失败: {e}"
        return result
    # ① 结构 lint：E1-E4 行标记 / 绑定句 / pairwise 段 / [ASSUMPTION]+A1-A5 / 守护行
    lints = [
        ("| E1 | 行标记", r"^\| E1 \|", re.MULTILINE),
        ("| E2 | 行标记", r"^\| E2 \|", re.MULTILINE),
        ("| E3 | 行标记", r"^\| E3 \|", re.MULTILINE),
        ("| E4 | 行标记", r"^\| E4 \|", re.MULTILINE),
        ("绑定句", "绑定句", 0),
        ("**pairwise 去相关**", r"\*\*pairwise 去相关\*\*", 0),
        ("[ASSUMPTION]", r"\[ASSUMPTION\]", 0),
        ("A1:", r"^A1:", re.MULTILINE),
        ("A2:", r"^A2:", re.MULTILINE),
        ("A3:", r"^A3:", re.MULTILINE),
        ("A4:", r"^A4:", re.MULTILINE),
        ("A5:", r"^A5:", re.MULTILINE),
        ("EVAL-MATRIX 追加 守护行", r"^> \*\*EVAL-MATRIX 追加（2026-09-06", re.MULTILINE),
    ]
    missing = [label for label, pat, flags in lints if not re.search(pat, text, flags)]
    if missing:
        result["status"] = "FAIL"
        result["detail"] = ("e1e4-evaluator-matrix.md 结构缺项: " + "、".join(missing)
                            + "（单源规格契约被破坏 — 需补结构）")
        result["missing"] = missing
        return result
    # ② E4 共享 REVIEW_LAYER_MATRIX 单源（import 失败 → SKIP 降级，同 cross_review_matrix）
    try:
        from gk_self_check import REVIEW_LAYER_MATRIX as MATRIX_COMMANDS
    except Exception as e:
        return {"check": "eval_matrix", "status": "SKIP",
                "detail": f"gk_self_check 不可导入（REVIEW_LAYER_MATRIX 单源）: {e}"}
    problems = []
    # 列共享 schema 声明：spec 第 1 节引用 REVIEW_LAYER_MATRIX 键集（与代码层枚举
    # 无空交集）。宽松——声明存在即可（cell 状态逐层核对不属本 lint）
    m_sec = re.search(r"^## 1\.\s*[^\n]*\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL)
    sec1 = m_sec.group(1) if m_sec else ""
    if not re.search(r"REVIEW_LAYER_MATRIX|\bL\d{1,2}\b|\bPR\b", sec1):
        problems.append("spec 第 1 节未声明列共享 schema"
                        "（REVIEW_LAYER_MATRIX 键引用缺失 = 与代码层枚举空交集）")
    # ③ 反建设 A4：不新建 CLI — _CMD_REG 提取命令集无 eval 前缀新命令
    eval_cmds = []
    cli = Path(skill_dir) / "gatekeeper-cli.sh"
    if cli.exists():
        cli_text = _read(cli)
        eval_cmds = sorted(c for c in set(re.findall(r"_CMD_REG\[([a-z0-9-]+)\]=", cli_text))
                           if c.startswith("eval"))
    result["layers"] = len(MATRIX_COMMANDS)
    if problems:
        result["status"] = "FAIL"
        if eval_cmds:
            problems.append("反建设违约（A4 不新建 CLI）: _CMD_REG 注册 " + "、".join(eval_cmds))
        result["detail"] = "；".join(problems)
        result["eval_cmds"] = eval_cmds
    elif eval_cmds:
        result["status"] = "WARN"
        result["detail"] = ("反建设违约（A4 不新建 CLI）: _CMD_REG 注册 eval 前缀命令 "
                            + "、".join(eval_cmds) + " — 规格要求不新建 CLI，应移除注册")
        result["eval_cmds"] = eval_cmds
    else:
        result["status"] = "PASS"
        result["detail"] = (f"E1-E4 规格结构完整 + 列共享 REVIEW_LAYER_MATRIX "
                            f"（{len(MATRIX_COMMANDS)} 层）schema 声明 + 无 eval 前缀 CLI 反建设命令")
    return result


# ── 2026-09-02 扩展：序列节点安全网 map 过时检测 ──────────────────────
def _extract_routes_nodes(script_text: str) -> dict:
    """从 gk_node_guard.py 源码提取 _ROUTES 节点表（route → nodes 列表）。"""
    m = re.search(r"_ROUTES\s*=\s*\{(.*?)\n\}", script_text, re.DOTALL)
    if not m:
        return {}
    body = m.group(1)
    routes = {}
    for rm in re.finditer(r'"([\w-]+)"\s*:\s*\{[^}]*?"nodes"\s*:\s*\[(.*?)\]', body, re.DOTALL):
        name = rm.group(1)
        nodes = re.findall(r'"([A-Z0-9_-]+)"', rm.group(2))
        routes[name] = nodes
    return routes


def _extract_node_registry(script_text: str) -> dict:
    """提取 _CHECKLISTS / _GATES / _SAFETY 键集（节点 → 配置存在性）。"""
    out = {}
    for var in ("_CHECKLISTS", "_GATES", "_SAFETY"):
        m = re.search(rf"{var}\s*=\s*\{{(.*?)\n\}}", script_text, re.DOTALL)
        keys = set(re.findall(r'"([A-Z0-9_-]+)"\s*:', m.group(1))) if m else set()
        out[var] = keys
    return out


# 节点声明扫描的**文档豁免**（2026-10-28）：这些文档的表格单元里放的是**分类学/攻击面族名**
# （`RED-MIGRATE-DANGER` 等），不是序列站点。豁免只按**文档角色**（分类学表）而不是按 token
# 前缀白名单 —— 后者会给真实未注册站名开后门。
_NODE_CLAIM_SKIP_DOCS = frozenset({"bashpy-problem-taxonomy.md"})
# 逐字召回面（协议/总路线图文档）：正文任意位置提到的节点都算「文档声明」——保留 2026-09-02
# 起的原语义与召回面；其余参考文档只认**表格单元**（防红队检查项 ID 的行内散文误判）。
_NODE_CLAIM_FULLTEXT_DOCS = frozenset({"meta-routing-protocol.md", "stage-3-review.md"})


def check_sequence_node_map(skill_dir: str) -> dict:
    """序列节点安全网总路线图过时检测（2026-09-02，用户质询"map 总路线图和各个站点
    车站播报、下一站文本是否过时"驱动）。

    检测面：
      ① NODE_REGISTRY 注册 vs 文档（meta-routing-protocol.md / stage-3-review.md）声明的节点
         —— 文档列出但 _ROUTES 未注册 = 文档超前；_ROUTES 注册但文档未列 = 文档滞后
      ② 车站播报/下一站一致性：_CHECKLISTS/_GATES/_SAFETY 键 ⊆ _ROUTES 全部节点
         （节点缺 checklist/gate/safety 配置 = 车站播报信息缺失）
      ③ 各序列（standing/standard/red/audit/plugin-a/b/c）节点数与文档声明对比
    """
    result = {"check": "sequence_node_map"}
    sd = Path(skill_dir)
    ng = sd / "scripts" / "gk_node_guard.py"
    if not ng.exists():
        return {"check": "sequence_node_map", "status": "SKIP",
                "detail": "gk_node_guard.py 不可读"}
    try:
        text = ng.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return {"check": "sequence_node_map", "status": "SKIP",
                "detail": f"gk_node_guard.py 读取失败: {e}"}
    routes = _extract_routes_nodes(text)
    if not routes:
        return {"check": "sequence_node_map", "status": "FAIL",
                "detail": "_ROUTES 节点表解析失败"}
    reg = _extract_node_registry(text)
    all_nodes = sorted({n for nodes in routes.values() for n in nodes})
    all_set = set(all_nodes)
    problems = []
    # 别名（A4 旧站名）—— 只允许出现在「回退/历史」语境，**不得**作为 _ROUTES 节点或 schema 名。
    # 单源 = **被检文件本身**（`gk_node_guard.py` 的 `ECO_ALIASES`），不 import 生产模块
    # （夹具/临时技能目录应只受自己那份源码约束，导入真模块会把生产状态泄进单测）。
    _am = re.search(r"ECO_ALIASES\s*=\s*\{(.*?)\n\}", text, re.DOTALL)
    alias = set(re.findall(r'"([A-Z0-9_-]+)"\s*:', _am.group(1))) if _am else set()
    # ① 文档声明节点 vs _ROUTES 注册
    # 排除：检查项 ID（RED-HOOK-17 / F81-01 等数字后缀）+ 检查项前缀段（RED-HOOK/RED-PY 等
    # 既有检查器名，非节点）——文档里这类 token 是检查项编号，不是序列节点。
    # 2026-10-28（消灭局限）：扫描面从 2 份固定文档 → **references/*.md 全量**。为避免把
    #   红队检查项 ID（RED-ROUTE-05 / RED-MIGRATE-SWALLOW 等**行内散文**）误判成节点，声明面
    #   只取**表格单元**里的 token：整格等于节点名，或格内是 `A → B / C` 形式的纯节点链。
    _node_tok = r"(?:AUDIT|RED|ECO)-[A-Z0-9-]+"
    _RE_CELL_NODE = re.compile(r"^(?:%s)$" % _node_tok)
    _RE_CHAIN_SPLIT = re.compile(r"\s*(?:→|->|,|、|/)\s*")

    def _cells_claims(line: str) -> set:
        out = set()
        for cell in line.split("|"):
            c = cell.strip().strip("*` ")
            if not c:
                continue
            if _RE_CELL_NODE.match(c):
                out.add(c)
                continue
            if re.search(r"→|->", c):
                for part in _RE_CHAIN_SPLIT.split(c):
                    p = part.strip().strip("*` ")
                    if _RE_CELL_NODE.match(p):
                        out.add(p)
        return out

    for dp in sorted((sd / "references").glob("*.md")):
        if dp.name in _NODE_CLAIM_SKIP_DOCS:
            continue
        try:
            dtext = dp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if dp.name in _NODE_CLAIM_FULLTEXT_DOCS:
            # 协议/总路线图类文档：正文任意位置提到的节点都算声明（旧的逐字召回面）
            doc_nodes = set(re.findall(_node_tok, dtext))
        elif "|" in dtext:
            doc_nodes = set()
            for line in dtext.splitlines():
                if "|" in line:
                    doc_nodes |= _cells_claims(line)
        else:
            continue
        if not doc_nodes:
            continue
        unregistered = [
            n for n in sorted(doc_nodes) if n not in all_set
            and n not in alias                          # 旧名（回退形态）不算未注册
            and not re.search(r"-\d+$", n)              # 检查项 ID（RED-HOOK-17 等）
            and not re.search(r"^(RED-HOOK|RED-PY|RED-HINT)$", n)  # 检查器前缀段
        ]
        if unregistered:
            problems.append(f"references/{dp.name} 声明节点未注册: {unregistered[:6]}")
    # ①b 双向：**standing** 序列的每个节点必须出现在总路线图（meta-routing-protocol.md）——
    #    A4 合并后这是唯一「站名改动」高频面（旧实现完全不查反向 = 文档滞后不可见）。
    #    只判 standing：plugin/migrate 等其它序列由各自文档承载，不在总图逐节点罗列。
    _mpr = sd / "references" / "meta-routing-protocol.md"
    if _mpr.exists():
        try:
            mtext = _mpr.read_text(encoding="utf-8", errors="replace")
            missing_doc = [n for n in routes.get("standing", [])
                           if not re.search(r"\b" + re.escape(n) + r"\b", mtext)]
            if missing_doc:
                problems.append(f"meta-routing-protocol.md 未收录 standing 节点: {missing_doc[:6]}")
        except OSError:
            pass
    # ①c 别名渗透：_ROUTES 里出现旧站名（A4 合并后应只剩 4 站 canonical 名）
    bad_alias = sorted({n for nodes in routes.values() for n in nodes} & alias)
    if bad_alias:
        problems.append(f"_ROUTES 含旧站名（应走 canon_eco）: {bad_alias[:6]}")
    # ①d monitor-schemas ↔ **standing** 节点（新增/改名站点必须带 schema；反向漏挂同样报）
    _ms = sd / "monitor-schemas"
    if _ms.is_dir():
        _stems = {p.stem for p in _ms.glob("*.json")}
        _standing = set(routes.get("standing", []))
        _orphan_schema = sorted(s for s in _stems
                                if re.match(r"^(ECO|RED|AUDIT)-", s)
                                and s not in all_set and s not in alias)
        if _orphan_schema:
            problems.append(f"monitor-schemas 含未注册节点 schema: {_orphan_schema[:6]}")
        _missing_schema = sorted(n for n in _standing if n not in _stems)
        if _missing_schema:
            problems.append(f"standing 节点缺 monitor-schema: {_missing_schema[:6]}")
    # ② 车站播报配置完整性（每个注册节点应有 checklist；终站 DONE 无 checklist 合理）
    TERMINALS = {"DONE", "(cycle complete)", "(cycle start)"}
    missing_cfg = [n for n in all_nodes
                   if n not in reg.get("_CHECKLISTS", set()) and n not in TERMINALS]
    if missing_cfg:
        problems.append(f"车站播报缺 checklist 配置: {missing_cfg[:6]}")
    # ③ 序列节点数摘要
    seq_summary = {r: len(v) for r, v in routes.items()}
    result["routes"] = routes
    result["seq_summary"] = seq_summary
    if problems:
        result["status"] = "WARN"
        result["detail"] = "；".join(problems)
    else:
        result["status"] = "PASS"
        result["detail"] = (f"节点注册一致（{len(routes)} 序列 / {len(all_nodes)} 节点，"
                            f"车站播报配置齐备）")
    return result


# ── 2026-09-02 扩展：注释-代码错配精细检测 ────────────────────────────
def _comment_chunks(py_text: str) -> list:
    """提取 Python 源码中的注释文本：docstring（三引号块）+ # 注释行。
    只取注释，不取代码体（防把 cmd_/reg 等代码变量当引用）。"""
    chunks = []
    # docstring 块（模块级/函数级，不跨文件嵌套处理——足够本次检测）
    for m in re.finditer(r'"""(.*?)"""', py_text, re.DOTALL):
        chunks.append(m.group(1))
    # # 注释行（含行尾注释）
    for line in py_text.split("\n"):
        i = line.find("#")
        if i >= 0:
            chunks.append(line[i:])
    return chunks


def _refs_from_comment(text: str) -> list:
    """从注释文本提取引用 token。返回 [(ref, kind)]。
    kind: script（gk_*.py）/ cmd（cmd_* 命令）/ func（反引号函数调用）。"""
    refs = []
    # gk_*.py 脚本引用：跳过跨仓库带路径前缀引用（git-workflow/scripts/gk_x.py 属他仓库）
    for m in re.finditer(r"(?:^|[\s`'/\\])gk_[a-z0-9_]+\.py", text):
        # 匹配文本（含前缀分隔符）：前缀含路径分隔符 → 跨仓库引用，跳过
        full = m.group(0)
        if "/" in full or "\\" in full:
            continue
        ref = m.group(0).strip(" `'/\n")
        refs.append((ref, "script"))
    # cmd_* 命令引用（注释语境：非注册命令名 = 错配候选）。
    # 跳过占位符（cmd_xxx / cmd_yyy / cmd_foo 等——docstring 举例非真实命令名）。
    # 跳过模块限定/变量前导引用（gk_pr_score.cmd_verify 等 = python 模块函数，非 bash CLI；
    # 对齐 script 引用的跨仓库限定跳过先例——2026-09-07 批③ ⑥ 对接, comment_code_mismatch 根因）。
    for m in re.findall(r"(?<![A-Za-z0-9_.])cmd_[a-z0-9_-]+", text):
        if re.fullmatch(r"cmd_(xxx|yyy|foo|bar|demo|example)", m):
            continue
        refs.append((m, "cmd"))
    # 反引号包裹的函数调用（gk_xxx() / resolve_xxx() / check_xxx()）
    for m in re.findall(r"`([a-z][a-z0-9_]*)\(\)`", text):
        refs.append((m, "func"))
    return refs


def _func_defined(func: str, py: Path, skill_dir: Path) -> bool:
    """函数在**本文件或 `scripts/` 任一模块**定义？

    2026-10-13（`ECC-092EC2A72A3F`）：原只查本文件 + 3 个路由中枢 ⟹ **跨模块**引用被系统性
    误判为「缺失」（实测 `claim_ttl_s` 在 `gk_git_lease.py`、`verify` 在 `gk_finding.py`）。
    """
    candidates = [py]
    try:
        candidates += sorted((skill_dir / "scripts").glob("*.py"))
    except OSError:
        pass
    for c in candidates:
        if c.exists():
            try:
                if f"def {func}(" in c.read_text(encoding="utf-8", errors="replace"):
                    return True
            except OSError:
                continue
    return False


def check_comment_code_mismatch(skill_dir: str, release: bool = False) -> dict:
    """注释-代码错配精细检测（2026-09-02，用户"你经常误删注释改错注释"驱动）。

    检测面（只做**实存**校验，防注释引用已删符号 = 错配）：
      ① 注释/docstring 引用的 gk_*.py 脚本 → 文件实存（跨仓库带路径引用跳过）
      ② 注释引用 cmd_* 命令 → gatekeeper-cli.sh cmd_xxx() 函数定义实存
      ③ 注释引用反引号函数调用 → def 实存
      ④ docstring 声称的"检查器 N 项"计数 vs run_all 实际注册数（ast 解析）
    设计取舍：不校验语义（注释说法 vs 代码行为），只校验**引用目标存在性**——
    误删/改名后注释引用悬空 = 确定性错配信号；行号类引用不做（易碎且常为估算）。
    注意：测试夹具文件（test_*.py）跳过——其注释引用假名属用例设计，非错配；
    cmd_* 占位符（cmd_xxx 等 docstring 举例）跳过——非真实命令名。
    """
    result = {"check": "comment_code_mismatch"}
    sd = Path(skill_dir)
    problems = []
    scanned = 0
    # 2026-10-13（`ECC-092EC2A72A3F`）：③ 的反引号 `name()` 也会匹配**内置函数**（`str()`/
    #   `compile()`/`id()`）⟹ 非本仓模块函数，须跳过（否则系统性假阳性）。
    import builtins as _bi
    _builtins = set(dir(_bi))
    # 跨仓库已知脚本白名单（git-workflow 等兄弟仓库 loader，注释引用属合法跨仓库引用）
    cross_repo_scripts = set()
    cli_text = _read(sd / "gatekeeper-cli.sh")
    cross_repo_scripts |= set(re.findall(r"[\w-]+/scripts/(gk_[a-z0-9_]+\.py)", cli_text))
    for py in sd.glob("scripts/*.py"):
        if py.name.startswith("test_"):
            continue
        t = _read(py)
        cross_repo_scripts |= set(re.findall(r"[\w-]+/scripts/(gk_[a-z0-9_]+\.py)", t))
    # ① 脚本引用实存 + ③ 函数引用实存：扫描 scripts/*.py 注释（跳过测试夹具文件）
    for py in sorted(sd.glob("scripts/*.py")):
        if py.name.startswith("test_"):
            continue  # 测试夹具引用假名属用例设计，非错配
        try:
            t = py.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        for chunk in _comment_chunks(t):
            for ref, kind in _refs_from_comment(chunk):
                if kind == "script":
                    if not (sd / "scripts" / ref).exists() and ref not in cross_repo_scripts:
                        # 公开树：被导出排除的脚本（如 gk_paper_*）缺席是预期，不算错配。
                        if not (release and _export_excluded("scripts/" + ref, sd)):
                            problems.append(f"{py.name} 注释引用脚本缺失: {ref}")
                elif kind == "func":
                    # 跳过**内置**（`str()`…）+ **方法调用**（本文件出现 `.<name>(` ⟹ 是方法，
                    # 如 `exists()`/`read_text()`），二者都非本仓模块函数（`ECC-092EC2A72A3F`）。
                    if (ref not in _builtins and f".{ref}(" not in t
                            and not _func_defined(ref, py, sd)):
                        problems.append(f"{py.name} 注释引用函数缺失: {ref}()")
    # ② cmd_* 命令 → cmd_xxx() bash 函数定义（非 _CMD_REG——cmd_ 是函数名不是注册名）
    cmd_defs = set(re.findall(r"cmd_[a-z0-9_-]+(?=\(\)\s*\{)", cli_text))
    # 2026-10-13（`ECC-092EC2A72A3F`）：`cmd_*` 亦可能是 **CLI 内的非命令 token**（`case` 值 /
    #   旗标，如 `cmd_target_mismatch` 是 `reason` 值）⟹ 收 CLI 全文 token 集，命中即非「缺失」。
    cli_tokens = set(re.findall(r"cmd_[a-z0-9_-]+", cli_text))
    for py in sorted(sd.glob("scripts/*.py")):
        if py.name.startswith("test_"):
            continue
        try:
            t = py.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for chunk in _comment_chunks(t):
            for ref, kind in _refs_from_comment(chunk):
                if kind == "cmd" and cmd_defs:
                    # CLI 函数定义 ∪ CLI 内任意 token ∪ **`scripts/` python `def`**（如
                    #   `cmd_set_nested`/`cmd_worktrees_extra`）⟹ 三者皆非「CLI 命令缺失」。
                    if (ref not in cmd_defs and ref not in cli_tokens
                            and not _func_defined(ref, py, sd)):
                        problems.append(f"{py.name} 注释引用命令函数缺失: {ref}")
    # ④ docstring 检查器计数（ast 解析 run_all 静态注册数；audit_docs 展开为动态，
    # 声称数 ≥ 静态注册数即 PASS——声称缩水才是过时信号）
    self_text = _read(sd / "scripts" / "gk_doc_align.py")
    cnt_m = re.search(r"检查器（(\d+) 项", self_text)
    if cnt_m:
        declared = int(cnt_m.group(1))
        static = 0
        try:
            tree = ast.parse(self_text)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == "run_all":
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                                and sub.func.attr == "append":
                            static += 1
                        elif isinstance(sub, ast.For) and isinstance(sub.iter, ast.Call):
                            static += 1  # for r in check_xxx_merged() 展开的批量检查器
                    break
        except SyntaxError:
            pass
        if declared != static:
            # 2026-10-28（消灭局限）：旧判据只查 `declared < static`（只抓「声称缩水」）⟹
            # 声称**多于**实际注册（虚报覆盖面）恒绿，是审计层的假绿面。现**双向**判等。
            problems.append(
                f"doc-align docstring 声称 {declared} 项检查器，run_all 静态注册 {static} 项"
                f"（不等 ⟹ 文档与实际覆盖面不一致）")
    result["scanned"] = scanned
    result["problems"] = problems
    if problems:
        result["status"] = "WARN"
        result["detail"] = "；".join(problems)
    else:
        result["status"] = "PASS"
        result["detail"] = f"注释引用全部实存（扫描 {scanned} 脚本，无悬空引用）"
    return result


# ── 2026-09-02 扩展：元数据路由文档 ↔ 代码一致性 ─────────────────────
def check_route_center_alignment(skill_dir: str) -> dict:
    """元数据统一路由检测匹配（2026-09-02，用户"扩展元数据统一路由检测匹配，检测
    5 层路由文档与对应代码是否一致"驱动）。

    检测面：
      ① meta-routing-protocol.md 声明的五层函数（resolve_plan/resolve_repo/
         resolve_worktree/resolve_state/resolve_narrow）→ gk_route_center.py def 实存
      ② 文档 L4 优先级顺序（plan 指针 → worktree 匹配 → 归属校验 → safety_net）
         vs resolve_state 实际实现顺序（gk_state_route.py 源码步骤注释）
      ③ CLI 契约子命令（route-all/resolve-plan/...）→ main() 分发实存
      ④ 测试文件存在 + 声称用例数
      ⑤ DEV_WORKTREE_ROOTS 双副本差分（route_center vs state_route，单副本篡改）
      ⑥ gatekeeper-cli.sh 不应再内嵌 worktree fallback 第三副本（2026-09-04 L3 接线后：
         出现 `[ -d ...worktrees... ]` 字面量 = 第三副本复活/注入 → WARN）
      ⑦ 路由白名单基线文档（meta-routing-protocol.md「路由白名单基线」）
         ↔ 代码常量值（MAIN_REPO_WSL/DEV_WORKTREE_ROOTS/SEARCH_DIRS，改码不改文档 → 值失配）
    """
    result = {"check": "route_center_alignment"}
    sd = Path(skill_dir)
    rc = sd / "scripts" / "gk_route_center.py"
    if not rc.exists():
        return {"check": "route_center_alignment", "status": "FAIL",
                "detail": "gk_route_center.py 缺失 — 元数据路由中枢未实装"}
    try:
        rtext = rc.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return {"check": "route_center_alignment", "status": "SKIP",
                "detail": f"gk_route_center.py 读取失败: {e}"}
    problems = []
    # ① 五层函数实存
    LAYER_FUNCS = ["resolve_plan", "resolve_repo", "resolve_worktree",
                   "resolve_state", "resolve_narrow"]
    missing = [f for f in LAYER_FUNCS if f"def {f}(" not in rtext]
    if missing:
        problems.append(f"五层链函数缺失: {missing}")
    # ② CLI 子命令实存
    SUB_CMDS = ["route-all", "resolve-plan", "resolve-repo", "resolve-worktree",
                "resolve-state", "resolve-narrow"]
    present_cmd = [c for c in SUB_CMDS
                   if re.search(r'if cmd == "' + re.escape(c) + r'"', rtext)]
    if len(present_cmd) != len(SUB_CMDS):
        problems.append(f"CLI 子命令缺失: {sorted(set(SUB_CMDS) - set(present_cmd))}")
    # ③ L4 优先级顺序（文档声明 vs gk_state_route 实现）
    meta = sd / "references" / "meta-routing-protocol.md"
    if meta.exists():
        try:
            mt = meta.read_text(encoding="utf-8", errors="replace")
        except OSError:
            mt = ""
        sr = sd / "scripts" / "gk_state_route.py"
        sr_has_worktree = "worktree 匹配路由" in (sr.read_text(encoding="utf-8", errors="replace") if sr.exists() else "")
        doc_has_worktree = "worktree 匹配" in mt
        if sr_has_worktree and not doc_has_worktree:
            problems.append("L4 worktree 匹配已实现但文档未声明")
        if doc_has_worktree and not sr_has_worktree:
            problems.append("L4 文档声明 worktree 匹配但实现缺失")
    # ④ 测试存在性
    t = sd / "scripts" / "test_gk_route_center.py"
    test_ok = t.exists()
    if not test_ok:
        problems.append("test_gk_route_center.py 缺失")
    # ⑤ 白名单跨副本一致性（2026-09-02 红队：DEV_WORKTREE_ROOTS 前缀白名单
    #    在 route_center 与 state_route 双副本——单副本被篡改可被差分捕获，
    #    是"白名单被篡改怎么办"的第一道独立防线）
    sr = sd / "scripts" / "gk_state_route.py"
    stext = sr.read_text(encoding="utf-8", errors="replace") if sr.exists() else ""

    def _roots_of(text: str) -> list:
        m = re.search(r"DEV_WORKTREE_ROOTS\s*=\s*\((.*?)\)", text, re.DOTALL)
        if not m:
            return []
        roots = []
        for s in m.group(1).split(","):
            s = re.sub(r"#.*", "", s).strip().strip("'\"")
            if s:
                roots.append(s.replace("\\", "/").rstrip("/"))
        return roots

    roots_rc = _roots_of(rtext)
    roots_sr = _roots_of(stext)
    if roots_rc != roots_sr:
        problems.append(f"DEV_WORKTREE_ROOTS 双副本不一致: route_center={roots_rc} "
                        f"vs state_route={roots_sr}（单副本篡改迹象）")
    # ⑥ L3 接线（2026-09-04 方案 A）：bash 不再持有 worktree 根第三副本——原 FEATURE_PREFIX
    #     fallback（`[ -d "...worktrees/..." ]`）已移除，单一事实源 = gk_route_center.resolve_worktree
    #     （GATEKEEPER_WORKTREE_ROOT env / DEV_WORKTREE_ROOTS 目录扫描，⑤/⑦ 覆盖）。
    #     bash 若再出现内嵌 worktree fallback 字面量 = 第三副本复活/注入（双事实源漂移）→ WARN。
    cli_t = sd / "gatekeeper-cli.sh"
    cli_text = cli_t.read_text(encoding="utf-8", errors="replace")[:16000] if cli_t.exists() else ""
    bm = re.search(r'\[ -d "([^"]*worktrees[^"]*)" \]', cli_text)
    if bm:
        problems.append(f"gatekeeper-cli.sh 重新出现内嵌 worktree fallback 目录: {bm.group(1)} "
                        f"（L3 已统一路由中枢——bash 第三副本不应复活）")
    # ⑦ 文档权威基线 ↔ 代码常量值（2026-09-02 红队 D 层：篡改代码常量不改文档 → 值失配检出；
    #    文档登记于 meta-routing-protocol.md「路由白名单基线」，改常量必须同步改文档）。
    #    2026-11-09 fail-loud 硬化：原实现有五处静默通道 —— meta 缺失 / 读取失败 / 章节缺失 /
    #    单元格缺失或为空 / MAIN_REPO_WSL 无字面量（运行时解析）⟹ v0.9.4 整段删除基线后本检查
    #    假绿约一周。现在「不可核对」一律入 problems（WARN；--strict 下阻断），不得短路到 PASS。
    if not meta.exists():
        problems.append("meta-routing-protocol.md 缺失 — ⑦ 路由白名单基线不可核对（fail-loud）")
    elif not mt:
        problems.append("meta-routing-protocol.md 不可读 — ⑦ 路由白名单基线不可核对（fail-loud）")
    elif not re.search(r"## 路由白名单基线(.*?)(?=\n## |\Z)", mt, re.DOTALL):
        problems.append("meta-routing-protocol.md 缺「## 路由白名单基线」章节 — "
                        "⑦ 路由白名单基线不可核对（fail-loud）")
    else:
        baseline_sec = re.search(r"## 路由白名单基线(.*?)(?=\n## |\Z)",
                                 mt, re.DOTALL).group(1)

        def _doc_cell(text: str, name: str) -> str:
            m = re.search(r"\|\s*`" + re.escape(name) + r"`\s*\|\s*([^|]*)\s*\|", text, re.DOTALL)
            return m.group(1) if m else ""

        def _doc_vals(cell: str) -> list:
            return [re.sub(r"[\\/]+$", "", v.replace("\\", "/")).lower()
                    for v in re.findall(r"`([^`]*)`", cell)]

        def _code_single(text: str, name: str) -> str:
            m = re.search(name + r"\s*=\s*\"([^\"]*)\"", text)
            return m.group(1).replace("\\", "/").rstrip("/").lower() if m else ""

        def _code_tuple(text: str, name: str) -> set:
            m = re.search(name + r"\s*=\s*\((.*?)\)", text, re.DOTALL)
            out = set()
            if not m:
                return out
            for s in m.group(1).split(","):
                s = re.sub(r"#.*", "", s).strip().strip("'\"")
                if s:
                    out.add(s.replace("\\", "/").rstrip("/").lower())
            return out

        # MAIN_REPO_WSL：文档「运行时解析」哨兵 ⟹ 代码须有运行时赋值且无硬编码字面量；
        # 否则按字面量精确比对（两侧任一无值都算不可核对）。
        mr_cell = _doc_cell(baseline_sec, "MAIN_REPO_WSL")
        if not mr_cell.strip():
            problems.append("文档基线缺 MAIN_REPO_WSL 单元格 — 不可核对（fail-loud）")
        elif "运行时" in mr_cell:
            assigns = re.findall(r"(?m)^MAIN_REPO_WSL\s*=\s*(.+)$", rtext)
            runtime = any(("_main_repo_wsl()" in a) or ("_main_repo(" in a) for a in assigns)
            literals = [a.strip() for a in assigns if re.fullmatch(r'"[^"]+"', a.strip())]
            if not runtime:
                problems.append("MAIN_REPO_WSL 文档声明运行时解析但代码无运行时赋值 — "
                                "不可核对（fail-loud）")
            if literals:
                problems.append(f"MAIN_REPO_WSL 文档声明无字面量但代码硬编码: {literals}（fail-loud）")
        else:
            mr_code = _code_single(rtext, "MAIN_REPO_WSL")
            mr_doc = _doc_vals(mr_cell)
            if not mr_doc:
                problems.append("文档基线 MAIN_REPO_WSL 单元格无可比对值（fail-loud）")
            elif not mr_code:
                problems.append("代码 MAIN_REPO_WSL 无字面量 — 与文档基线不可比对（fail-loud）")
            elif mr_code != mr_doc[0]:
                problems.append(f"MAIN_REPO_WSL 偏离文档基线: 代码={mr_code} vs 文档={mr_doc[0]}"
                                f"（常量篡改或基线未同步）")
        # DEV_WORKTREE_ROOTS（⑤ 已查双副本一致；此处查文档基线）
        roots_doc = set(_doc_vals(_doc_cell(baseline_sec, "DEV_WORKTREE_ROOTS")))
        roots_code = {v.lower() for v in _roots_of(rtext)}
        if not roots_doc:
            problems.append("文档基线 DEV_WORKTREE_ROOTS 缺失或无可比对值（fail-loud）")
        elif not roots_code:
            problems.append("代码 DEV_WORKTREE_ROOTS 缺失或为空 — 与文档基线不可比对（fail-loud）")
        elif roots_code != roots_doc:
            problems.append(f"DEV_WORKTREE_ROOTS 偏离文档基线: 代码={sorted(roots_code)} "
                            f"vs 文档={sorted(roots_doc)}（常量篡改或基线未同步）")
        # SEARCH_DIRS（集合）
        sdirs_doc = set(_doc_vals(_doc_cell(baseline_sec, "SEARCH_DIRS")))
        sdirs_code = _code_tuple(rtext, "SEARCH_DIRS")
        if not sdirs_doc:
            problems.append("文档基线 SEARCH_DIRS 缺失或无可比对值（fail-loud）")
        elif not sdirs_code:
            problems.append("代码 SEARCH_DIRS 缺失或为空 — 与文档基线不可比对（fail-loud）")
        elif sdirs_code != sdirs_doc:
            problems.append(f"SEARCH_DIRS 偏离文档基线: 代码={sorted(sdirs_code)} "
                            f"vs 文档={sorted(sdirs_doc)}（搜索目录被篡改或基线未同步）")
    result["layer_funcs"] = [f for f in LAYER_FUNCS if f"def {f}(" in rtext]
    result["test_exists"] = test_ok
    if problems:
        result["status"] = "WARN"
        result["detail"] = "；".join(problems)
    else:
        result["status"] = "PASS"
        result["detail"] = "五层链函数/CLI 子命令/L4 优先级/测试文件/白名单跨副本/文档基线 全部一致"
    return result


# ── 检查器: shell↔python 序列化内插（F-REV-20，2026-09-10 用户定案 L1）──────
# 活体三引号内插 = `'''` 紧跟 `$`；转义形式 `'''\$var'''`（仅注释里引用旧写法）不算。
_SERIAL_INJECT_PAT = re.compile(r"'''\$")


def check_shell_python_serialization(skill_dir: str) -> dict:
    """F-REV-20：CLI/shell 内联 python **禁止**把 shell 变量以三引号字面量内插。

    缺陷：`json.loads('''$var''')` —— var 含反斜杠（如 `<home>`）时 python
    **编译期**即 `SyntaxError: truncated \\UXXXXXXXX escape`，且调用点普遍带
    `2>/dev/null || true` → 静默失败 → 门禁链断裂/证据丢失（F-REV-18 即此因，
    实测另有 7 处吃外部/半外部文本：--verdicts/--concessions/LLM 产出/gitnexus 输出）。
    统一约定 = JSON over env：`VAR="$v" python3 -c "…os.environ.get('VAR','')"`。
    扫描面 = gatekeeper-cli.sh + scripts/*.sh。FAIL 阻断（该缺陷必然导致静默失败）。
    """
    result = {"check": "shell_python_serialization"}
    targets = [Path(skill_dir) / "gatekeeper-cli.sh"]
    sdir = Path(skill_dir) / "scripts"
    if sdir.is_dir():
        targets += sorted(sdir.glob("*.sh"))
    hits = []
    for p in targets:
        if not p.is_file():
            continue
        for i, line in enumerate(_read(p).splitlines(), 1):
            # 只查活体代码：忽略注释里对旧写法的引用（如 `# 原 json.loads('''$x''') 三引号注入`）——
            # 这类注释是修复留痕，本身不构成注入。
            code = line.split("#", 1)[0]
            if _SERIAL_INJECT_PAT.search(code):
                hits.append(f"{p.name}:{i}")
    if hits:
        result["status"] = "FAIL"
        result["detail"] = (
            f"{len(hits)} 处 shell 变量三引号内插 python 源码（F-REV-20 禁）: "
            + ", ".join(hits[:12])
            + " — 改用 JSON over env（VAR=\"$v\" python3 -c … os.environ.get('VAR')）"
        )
        result["hits"] = hits
    else:
        result["status"] = "PASS"
        result["detail"] = "无 shell→python 三引号源码内插（统一 JSON over env）"
    return result


def check_red_arm_templates(skill_dir: str) -> dict:
    """红先测试模版漂移检查（2026-09-23，用户裁定「红先测试模版需要被 doc-align 检查是否存在漂移」）。

    单一事实源 = `references/red-arm-templates.json`；消费方 = `scripts/gk_red_arm_gen.py`。
    漂移面（FAIL=需修复）：
      ① 登记表缺失/不可解析/无模板；
      ② 单条模板 body 内的占位符集合 ≠ 声明的 `placeholders`（**声明与体漂移**——
         本检查上线当天就抓到 `func-boundary-slice` 声明 `{lang}` 而 body 未用）；
      ③ id 空/重复；
      ④ **第二份名单漂移**：`gk_red_arm_gen.template_ids()` ≠ 登记表 id 序列（防有人绕过登记表另列清单）。
    文档面（WARN 不阻断）：SKILL.md 未引用该登记表 ⟹ 提示补登记。
    """
    result = {"check": "red_arm_templates"}
    reg_p = Path(skill_dir) / "references" / "red-arm-templates.json"
    gen_p = Path(skill_dir) / "scripts" / "gk_red_arm_gen.py"
    if not reg_p.exists():
        # 公开面（导出树）该登记表已闭源，生成器亦不在包内 ⟹ 检查不可判，显式 SKIP。
        # 私仓缺登记表仍是 FAIL（生成器在 ⟹ 属真实缺陷，不得静默）；
        # skill_dir 本身不存在属调用侧配置错误（来源不可判）⟹ 仍 FAIL，不得借 SKIP 静默。
        if gen_p.exists() or not Path(skill_dir).is_dir():
            result["status"] = "FAIL"
            result["detail"] = "缺 references/red-arm-templates.json（红先模版登记表）"
        else:
            result["status"] = "SKIP"
            result["detail"] = ("红先模板登记表未随包（公开面 red-arm-templates.json / "
                                "gk_red_arm_gen.py 均不存在）— 跳过")
        return result
    try:
        reg = json.loads(_read(reg_p))
        tmpls = reg.get("templates") or []
    except Exception as e:  # noqa: BLE001
        result["status"] = "FAIL"
        result["detail"] = f"登记表解析失败: {type(e).__name__}: {e}"
        return result
    if not tmpls:
        result["status"] = "FAIL"
        result["detail"] = "登记表无模板"
        return result
    ids = [str(t.get("id") or "") for t in tmpls]
    if any(not i for i in ids) or len(ids) != len(set(ids)):
        result["status"] = "FAIL"
        result["detail"] = f"模版 id 空或重复: {ids}"
        return result
    # ⑤ 分类器元数据（2026-11-09）：`classify` 只读本表 keywords/when/desc ⟹ 任一为空
    #   会让「自动判定复用/新增」静默退化（无关键词 = 永远判 new）。旧条目须同批补齐。
    for t in tmpls:
        if not isinstance(t.get("keywords"), list) or not t["keywords"]:
            result["status"] = "FAIL"
            result["detail"] = f"模版 {t.get('id')} 缺 keywords（分类器单源，旧条目需补）"
            return result
        if not str(t.get("when") or "").strip() or not str(t.get("desc") or "").strip():
            result["status"] = "FAIL"
            result["detail"] = f"模版 {t.get('id')} 缺 when/desc（分类与说明不可为空）"
            return result
    for t in tmpls:
        body_ph = set(re.findall(r"\{[A-Za-z0-9_]+\}", str(t.get("body") or "")))
        decl = set(str(x) for x in (t.get("placeholders") or []))
        if body_ph != decl:
            result["status"] = "FAIL"
            result["detail"] = (f"模版 {t.get('id')} 声明与体漂移: body={sorted(body_ph)} "
                                f"≠ declared={sorted(decl)}")
            return result
    # ④ 第二份名单漂移（消费方必须读登记表，而非另列清单）
    if not gen_p.exists():
        result["status"] = "FAIL"
        result["detail"] = "缺 scripts/gk_red_arm_gen.py（登记表的唯一消费方）"
        return result
    try:
        sys.path.insert(0, str(Path(skill_dir) / "scripts"))
        import gk_red_arm_gen as _gen
        got = _gen.template_ids(_gen.load_registry(str(reg_p)))
    except Exception as e:  # noqa: BLE001
        result["status"] = "FAIL"
        result["detail"] = f"消费方不可用（禁第二份名单）: {type(e).__name__}: {e}"
        return result
    if got != ids:
        result["status"] = "FAIL"
        result["detail"] = f"第二份名单漂移: gen={got} ≠ registry={ids}"
        return result
    # 文档面（WARN 不阻断）
    skill_md = Path(skill_dir) / "SKILL.md"
    if skill_md.exists() and "red-arm-templates" not in _read(skill_md):
        result["status"] = "WARN"
        result["detail"] = (f"登记表自洽（{len(ids)} 模板: {', '.join(ids)}），"
                            "但 SKILL.md 未引用 red-arm-templates（文档面未登记，建议补）")
        return result
    result["status"] = "PASS"
    result["detail"] = f"红先模版登记表自洽（{len(ids)} 模板: {', '.join(ids)}）"
    return result


# ── A-2（T10，2026-10-29）：段职责表 ↔ STAGE 分支 gate-id 双向比对 ────────────────
# 病根（Q4 质询第 3 条）：`gk_advance.py::_structural_gates` 只有 `fail()` 字符串，
#   **没有**「段职责注释」这一对象 ⟹ 判据只能落在 **gate-id 清单**上，注释锚不可用。
# 契约（表 = 单源 `references/meta-routing-protocol.md` 的 STAGE-DUTY-MAP 块）：
#   · 表未落地（A-1/T3 未完成）⟹ **WARN**（方案 A：否则新检查器上线当天卡死全仓 doc-align）；
#   · 表落地但与代码不等 ⟹ **FAIL**（漏登 / 多登 / 未映射字面量 / 转换集合不一致，
#     均须精确报出**段名 + gate-id**，不得只报「有漂移」）。
_STAGE_DUTY_BEGIN = "<!-- STAGE-DUTY-MAP:BEGIN -->"
_STAGE_DUTY_END = "<!-- STAGE-DUTY-MAP:END -->"

# fail 字面量 → gate-id。**顺序敏感**：长前缀先匹配（`final plan backup missing`
#   必须先于 `plan backup missing`，否则前者会被归成后者）。
_GATE_ID_RULES = (
    ("worktree not registered", "worktree_registered"),
    ("worktree not accessible", "worktree_accessible"),
    ("worktree not found", "worktree_exists"),
    ("branch is main", "branch_not_main"),
    ("branch name empty", "branch_nonempty"),
    ("uncommitted changes", "no_uncommitted_changes"),
    ("CI trigger not registered", "ci_trigger_registered"),
    ("no files changed in last commit", "diff_nonempty"),
    ("sprint_contract missing", "sprint_contract_declared"),
    ("PR not merged", "pr_merged"),
    ("final plan backup missing", "final_plan_backup_exists"),
    ("plan backup missing", "plan_backup_exists"),
)


def _gate_id_of(literal: str) -> str:
    """fail 字面量 → gate-id；未映射返回 ""（调用方须 FAIL：新增 fail 必须同时登记规则与表）。"""
    for needle, gid in _GATE_ID_RULES:
        if needle in literal:
            return gid
    return ""


def _stage_transitions_from_code(skill_dir: str) -> tuple:
    """AST 抽 `_structural_gates` 的 (转换 → [gate-id])。返回 (per_transition, unmapped[], err)。

    `unmapped` = 出现 fail() 但 `_GATE_ID_RULES` 未覆盖的字面量（含所在转换），
    用于「代码新增门禁未登记」这一红面。
    """
    p = Path(skill_dir) / "scripts" / "gk_advance.py"
    if not p.exists():
        return None, [], "scripts/gk_advance.py 缺失"
    try:
        tree = ast.parse(_read(p))
    except SyntaxError as e:
        return None, [], f"gk_advance.py 语法错误: {e}"
    fn = None
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == "_structural_gates":
            fn = n
            break
    if fn is None:
        return None, [], "未找到 _structural_gates（锚失效 ⟹ 判据须重校）"

    def transition_of(test) -> tuple:
        cur = to = None
        for x in ast.walk(test):
            if isinstance(x, ast.Compare) and len(x.comparators) == 1 \
                    and isinstance(x.left, ast.Name) and x.left.id in ("current", "to"):
                c = x.comparators[0]
                if isinstance(c, ast.Constant) and isinstance(c.value, str):
                    if x.left.id == "current":
                        cur = c.value
                    else:
                        to = c.value
        return (cur, to) if cur and to else (None, None)

    per, unmapped = {}, []
    for node in fn.body:
        if not isinstance(node, ast.If):
            continue
        cur = node
        while isinstance(cur, ast.If):           # elif 链 = 嵌套 orelse[0]
            a, b = transition_of(cur.test)
            if a and b:
                key = "%s→%s" % (a, b)
                ids = per.setdefault(key, [])
                # ⚠ 只扫**本分支 body**：`ast.walk(cur)` 会下探到嵌套 orelse（后续 elif），
                #   把下游分支的 fail() 误记到本转换（初始实现即踩此坑）。
                for st in cur.body:
                    for sub in ast.walk(st):
                        if not (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                                and sub.func.id == "fail" and sub.args):
                            continue
                        arg = sub.args[0]
                        lit = (arg.value if isinstance(arg, ast.Constant)
                               and isinstance(arg.value, str) else "")
                        gid = _gate_id_of(lit) if lit else ""
                        if not gid:
                            unmapped.append({"transition": key, "literal": lit or "<非字面量>"})
                        elif gid not in ids:
                            ids.append(gid)
            cur = (cur.orelse[0] if len(cur.orelse) == 1 and isinstance(cur.orelse[0], ast.If)
                   else None)
    return per, unmapped, ""


def _parse_stage_duty_table(text: str):
    """解析 STAGE-DUTY-MAP 块 → (转换 → {gate-id})；无块返回 ({}, "标记块缺失")。"""
    i = text.find(_STAGE_DUTY_BEGIN)
    j = text.find(_STAGE_DUTY_END, i + 1) if i != -1 else -1
    if i == -1 or j == -1:
        return {}, "标记块缺失"
    rows = {}
    for line in text[i + len(_STAGE_DUTY_BEGIN):j].splitlines():
        ln = line.strip()
        if not ln.startswith("|"):
            continue
        cells = [c.strip() for c in ln.strip("|").split("|")]
        if len(cells) < 2 or set(cells[0]) <= set(":- ") or cells[0] in ("转换", "transition"):
            continue
        tr = cells[0].replace(" ", "").replace("->", "→").replace("—>", "→")
        ids = {x for x in re.split(r"[,\s]+", cells[-1]) if x and x not in ("-", "—", "无")}
        rows[tr] = ids
    return rows, ""


def check_stage_duty_map(skill_dir: str) -> dict:
    """段职责表 ↔ STAGE 分支 gate-id 双向比对（T10 / A-2，2026-10-29）。

    两侧：文档侧 = `references/meta-routing-protocol.md` 的 STAGE-DUTY-MAP 块；
         代码侧 = `gk_advance.py::_structural_gates` 的 `fail()` 字面量（经 `_GATE_ID_RULES` 归一）。
    """
    result = {"check": "stage_duty_map"}
    doc_p = Path(skill_dir) / "references" / "meta-routing-protocol.md"
    adv_p = Path(skill_dir) / "scripts" / "gk_advance.py"
    code, unmapped, err = _stage_transitions_from_code(skill_dir)
    if code is None:
        # 三态分流（T10 第④条红臂，2026-10-31）—— 判据**锚失效应 FAIL，不得 SKIP**：
        #   ① skill_dir 不存在   → FAIL（调用侧错误）
        #   ② gk_advance.py 缺失 → SKIP（公开面导出树本就不带该文件 ⟹ 客观不可判，非缺陷）
        #   ③ 文件在但抽不出     → FAIL（`_structural_gates` 改名/语法错 ⟹ **判据本身失效**，
        #      此时 SKIP 等于「看不见就说没问题」，是本检查唯一的静默假绿面）
        # 判据用**文件存在性**而非 `err` 字符串匹配：后者一改文案就失准，前者是客观事实。
        if not Path(skill_dir).is_dir():
            result["status"] = "FAIL"
            result["detail"] = f"skill_dir 不存在: {skill_dir}"
        elif not adv_p.exists():
            result["status"] = "SKIP"
            result["detail"] = (f"代码面不可判（{err}）— 跳过：公开面导出树不带 gk_advance.py，"
                                "属客观不可判而非缺陷")
        else:
            result["status"] = "FAIL"
            result["detail"] = (f"判据锚失效（{err}）— 不得 SKIP：gk_advance.py 存在却抽不出 "
                                "_structural_gates，此时「表与代码一致」不可证，"
                                "SKIP 会变成静默假绿")
        return result
    if not doc_p.exists():
        result["status"] = "WARN"
        result["detail"] = "段职责表未落地（A-1/T3 未完成）：references/meta-routing-protocol.md 缺失"
        return result
    table, why = _parse_stage_duty_table(_read(doc_p))
    if not table:
        result["status"] = "WARN"
        result["detail"] = (f"段职责表未落地（A-1/T3 未完成）：STAGE-DUTY-MAP {why}"
                            f"（代码侧已抽出 {len(code)} 段 {sum(len(v) for v in code.values())} 个 gate-id）")
        return result
    if unmapped:
        result["status"] = "FAIL"
        result["detail"] = ("代码新增门禁未登记（fail 字面量无 gate-id 映射）: "
                            + "；".join(f"{u['transition']} → {u['literal'][:60]}" for u in unmapped[:5]))
        result["unmapped"] = unmapped
        return result
    problems = []
    for tr in sorted(set(code) - set(table)):
        problems.append(f"{tr}: 表漏登整段（代码侧有 {len(code[tr])} 个 gate-id）")
    for tr in sorted(set(table) - set(code)):
        problems.append(f"{tr}: 表多登整段（代码侧无此转换）")
    for tr in sorted(set(code) & set(table)):
        miss = sorted(set(code[tr]) - table[tr])
        extra = sorted(table[tr] - set(code[tr]))
        if miss:
            problems.append(f"{tr}: 表漏登 gate-id {miss}")
        if extra:
            problems.append(f"{tr}: 表多登 gate-id {extra}")
    if problems:
        result["status"] = "FAIL"
        result["detail"] = "段职责表与代码不等: " + "；".join(problems)
        return result
    n_gate = sum(len(v) for v in code.values())
    result["status"] = "PASS"
    result["detail"] = f"段职责表与代码一致（{len(code)} 段 / {n_gate} 个 gate-id）"
    return result


def check_skill_duty_pointer(skill_dir: str) -> dict:
    """SKILL.md 段职责表指针存在性（T3-b，2026-10-31）。

    T3 裁定（G3/r2-g3b）：SKILL.md 面**只留指针 + 机检指针存在性**，否决双写。
    理由：段职责表单源 = `references/meta-routing-protocol.md` 的 STAGE-DUTY-MAP 块；
    SKILL.md 若再抄一份全表，两处必然漂移，而 doc-align 只查 references 单源
    ⟹ SKILL.md 那份无人看 = 假绿（原 T3 交付面即栽在这：references 面已落、
    SKILL.md 面零落，1/2 交付被文档自证完成）。
    故 SKILL.md 只保留指针行；本检查钉死「指针仍在」——防止后续提交把指针删掉
    或改成失效表述（段职责表对路由/门禁来源的读者失联）。
    """
    result = {"check": "skill_duty_pointer"}
    p = Path(skill_dir) / "SKILL.md"
    if not p.exists():
        result["status"] = "FAIL"
        result["detail"] = "SKILL.md 缺失 — 段职责表指针无处可指"
        return result
    text = _read(p)
    has_doc = "meta-routing-protocol.md" in text
    has_map = "STAGE-DUTY-MAP" in text
    if has_doc and has_map:
        result["status"] = "PASS"
        result["detail"] = "SKILL.md 指针在（meta-routing-protocol.md + STAGE-DUTY-MAP）"
    elif not has_doc:
        result["status"] = "FAIL"
        result["detail"] = ("SKILL.md 段职责表指针丢失：未提及 references/meta-routing-protocol.md"
                            "（T3-b 裁定 = 只留指针；表单源在 references，指针断 ⟹ 读者失联）")
    else:
        result["status"] = "FAIL"
        result["detail"] = ("SKILL.md 提及 meta-routing-protocol.md 但未标 STAGE-DUTY-MAP"
                            "（指针过泛，读者定位不到段职责表块）")
    return result


# 计划点名臂名的「否定上下文」豁免词（同行出现即视为历史引用，不判缺失）
# 2026-11-08 扩：`待建 / 未落地 / TBD` —— 文档**显式声明**"该臂尚未存在"时，本检查的
#   语义（防"文书声称已落刀、实际零命中"）已满足：作者没有把它当已落地。原词表只有
#   "已删/退役"一类历史引用 ⟹ 诚实的"待建"标注反被判 FAIL，逼作者删掉规划信息（劣化）。
_ARM_EXEMPT_CTX = ("已删", "已移除", "弃用", "退役", "失效", "revert", "回退",
                   "待建", "未落地", "尚未落地", "TBD")
# family schema 的**字段名**（`test_first` / `test_file`）不是臂名：活跃计划里出现时不应判缺失
_ARM_NAME_EXEMPT = frozenset({"test_first", "test_file"})


def check_plan_arm_names_exist(skill_dir: str) -> dict:
    """计划点名臂名实存检查（2026-10-04，finding `ECC-C6CAD0E7E6B6` / P0-3 判据载体类）。

    面：`docs/plans/*.md`（**仅最新 3 份 = 活跃面**）里**反引号点名**的 `test_*` 标识符，须在某
    `scripts/test_*.py` 有 `def <name>(`（含**类方法**）或同名**文件茎**实存。治「文书声称某臂已落刀，实际文件零命中」（P0-3 假绿形态；
    `check_anchor_existence` 只查**锚**，不查散文里的臂名）。
    豁免：同行含 `已删/弃用/退役/失效/revert` 等否定上下文者跳过（历史引用不判缺失）。
    """
    result = {"check": "plan_arm_names_exist"}
    plans = Path(skill_dir) / "docs" / "plans"
    scripts = Path(skill_dir) / "scripts"
    if not plans.is_dir():
        result["status"] = "SKIP"
        result["detail"] = "无 docs/plans（未登记计划面）"
        return result
    defined = set()
    for tp in scripts.glob("test_*.py"):
        defined.add(tp.stem)  # 文件茎：计划常以 `test_gk_finding` 指代**测试文件**
        # 含**类方法**（`^def ` 会漏掉缩进的 `    def test_x(self)`）
        defined |= set(re.findall(r"(?m)^\s*def (test_[A-Za-z0-9_]+)\(", _read(tp)))
    name_re = re.compile(r"`(test_[A-Za-z0-9_]+)`")
    missing: dict = {}
    # 只扫**最新 3 份计划**（`YYYY-MM-DD` 前缀 ⟹ 名字序 = 日期序）= 活跃面。
    # 更早的计划视为历史：常引用已退役/改名的臂，以及 `test_first`/`test_file` 等
    # **family schema 字段名**（非臂名）——对它们 FAIL 会误伤，故不判。
    for doc in sorted(plans.glob("*.md"))[-3:]:
        for ln in _read(doc).splitlines():
            if any(x in ln for x in _ARM_EXEMPT_CTX):
                continue
            for name in name_re.findall(ln):
                if name in _ARM_NAME_EXEMPT:
                    continue
                if name not in defined:
                    missing.setdefault(name, set()).add(doc.name)
    if missing:
        result["status"] = "FAIL"
        result["detail"] = "计划点名的臂在 scripts/test_*.py 零命中（文实分裂）: " + "; ".join(
            f"{n}({','.join(sorted(ds))})" for n, ds in sorted(missing.items()))
        return result
    result["status"] = "PASS"
    result["detail"] = f"计划点名臂名全部实存（实存 {len(defined)} 个 test_* 名）"
    return result


def check_contract_enum_impl_binding(skill_dir: str) -> dict:
    """契约↔实现集合等价检查（2026-10-04，finding `ECC-614F297C9792` / P0-2 类）。

    单一事实源 = `references/doc-align-contracts.json`；每实例声明
    `(impl, impl_regex, expect[])`：从实现源码抽取的集合须 **==** 声明集合（**双向**）。
    治「契约表非全函数 / 实现多产者未登记」（本批 rc=3 四产者无表行无臂即此类漏网）。
    无登记表 ⟹ SKIP（不阻断未登记契约的仓）。
    """
    result = {"check": "contract_enum_impl_binding"}
    reg_p = Path(skill_dir) / "references" / "doc-align-contracts.json"
    if not reg_p.exists():
        result["status"] = "SKIP"
        result["detail"] = "无 references/doc-align-contracts.json（未登记契约）"
        return result
    try:
        reg = json.loads(_read(reg_p))
        inst = reg.get("instances") or []
    except Exception as e:  # noqa: BLE001
        result["status"] = "FAIL"
        result["detail"] = f"契约登记表解析失败: {type(e).__name__}: {e}"
        return result
    if not inst:
        result["status"] = "FAIL"
        result["detail"] = "契约登记表无实例"
        return result
    bad = []
    for it in inst:
        iid = str(it.get("id") or "?")
        ip = Path(skill_dir) / str(it.get("impl") or "")
        if not ip.exists():
            bad.append(f"{iid}: 实现文件缺失 {it.get('impl')}")
            continue
        try:
            got = set(re.findall(str(it.get("impl_regex") or r"(?!x)x"), _read(ip)))
        except re.error as e:
            bad.append(f"{iid}: 正则非法 {e}")
            continue
        exp = set(str(x) for x in (it.get("expect") or []))
        if got != exp:
            bad.append(f"{iid}: 实现 {sorted(got)} ≠ 契约 {sorted(exp)}")
    if bad:
        result["status"] = "FAIL"
        result["detail"] = "；".join(bad)
        return result
    result["status"] = "PASS"
    result["detail"] = f"契约↔实现集合等价（{len(inst)} 实例）"
    return result


# ── 报告 ↔ 派发账本对账（2026-10-28，方案 B ③ / A 收口）─────────────────────
# 判据：`docs/analysis/subagent/*.md` 中「晚于账本起点」的报告，必须能追溯到
#   ① 任一治理 state 的 `subagent_history`（含 `<state>.history-archive*.jsonl` 与
#      `.subagent-history.archive-*.json`）；或
#   ② `gate_data.dispatch_tickets[].report_file`（B：授权→产物绑定，见
#      `gk_dispatch_ticket.record_report`）。
# 破坏面 = 报告落盘但账本零记录（绕过 CLI/runner 的直调产物）。
# 分级：近 `fresh_h` 小时内未入账 ⟹ FAIL（活跃违规）；更早的 ⟹ WARN（存量）；
#   历史存量由 `docs/analysis/subagent-unlogged-baseline.json` **显式冻结**（可审计、可增删，
#   与 `_accept_baseline.txt` 同模式）—— 不冻结则恒红 123 条，门禁失去判别力。
SUBAGENT_BASELINE_REL = "docs/analysis/subagent-unlogged-baseline.json"


def _state_roots(skill_dir: str) -> list:
    """账本读取根：本目录 + `git worktree list` 里的主树（linked worktree 兜底）。

    病象（2026-10-28，并发会话实测）：`.gatekeeper.state*` 被 gitignore ⟹ **linked worktree
    没有 state** ⟹ 在 worktree 里跑 doc-align 只能看到 0~1 个 state，`unlogged` 暴涨并 FAIL，
    而 `test_happy_path_real_skill` 在 worktree 恒红 —— 「开发在工作树、验完 ff 进 master」
    的流程被自己的对账臂卡死。修法：按 `git worktree list --porcelain` 首项兜底读主树 state
    （只读、不改写；读两处并集，避免 worktree 自己的域 state 被忽略）。
    """
    roots = [Path(skill_dir)]
    try:
        import subprocess
        out = subprocess.run(["git", "-C", str(skill_dir), "worktree", "list", "--porcelain"],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:  # noqa: BLE001 — 非 git 目录 / git 不可用 ⟹ 只用本目录
        return roots
    for line in out.splitlines():
        if not line.startswith("worktree "):
            continue
        p = Path(line[len("worktree "):].strip())
        try:
            if p.is_dir() and p.resolve() not in [r.resolve() for r in roots]:
                roots.append(p)
        except OSError:
            continue
    return roots


def _subagent_ledger(skill_dir: str) -> tuple:
    """聚合**全部治理 state**的记账面：`report_file` basenames + 有效文件 mtime。"""
    base = Path(skill_dir)
    names, mtimes = set(), []

    def _take(rec) -> None:
        if not isinstance(rec, dict):
            return
        rf = str(rec.get("report_file") or "")
        if not rf:
            return
        names.add(os.path.basename(rf))
        if os.path.exists(rf):
            mtimes.append(os.path.getmtime(rf))

    roots = _state_roots(skill_dir)
    for root in roots:
        for p in sorted(root.glob(".gatekeeper.state*")):
            if p.name.endswith((".lock", ".jsonl", ".seal", ".tmp", ".log", ".dispatch")):
                continue
            try:
                if p.stat().st_size > 20 * 1024 * 1024:
                    continue
                d = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(d, dict):
                continue
            gd = d.get("gate_data") if isinstance(d.get("gate_data"), dict) else {}
            for r in (gd.get("subagent_history") or []):
                _take(r)
            # B：票据账本里绑定的报告同样算「已入账」（授权→产物）
            for r in (gd.get("dispatch_tickets") or []):
                _take(r)
    for root in roots:
        for p in sorted(root.glob(".gatekeeper.state*.history-archive*.jsonl")):
            try:
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for line in lines:
                if not line.strip():
                    continue
                try:
                    _take(json.loads(line))
                except json.JSONDecodeError:
                    continue
        for p in sorted(root.glob(".gatekeeper.state*.subagent-history.archive-*.json")):
            try:
                v = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            recs = v if isinstance(v, list) else (v.get("subagent_history") or [])
            for r in recs:
                _take(r)
    return names, mtimes


def check_subagent_unlogged(skill_dir: str, fresh_h: float = 24.0) -> dict:
    """报告 ↔ 账本对账（A：常驻 WARN + 近期 FAIL + 历史基线冻结）。"""
    base = Path(skill_dir)
    reports = sorted((base / "docs" / "analysis" / "subagent").glob("*.md"))
    r = {"check": "subagent_unlogged"}
    if not reports:
        r.update(status="PASS", detail="无 subagent 报告")
        return r
    names, mtimes = _subagent_ledger(skill_dir)
    if not mtimes:
        r.update(status="WARN",
                 detail="账本无有效报告指针（history 为空或报告已移走）— 无法对账")
        return r
    cutoff = min(mtimes)
    base_names, frozen_at = set(), 0.0
    try:
        bj = json.loads((base / SUBAGENT_BASELINE_REL).read_text(encoding="utf-8"))
        base_names = {os.path.basename(str(x)) for x in (bj.get("files") or [])}
        frozen_at = float(bj.get("frozen_at") or 0)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        base_names, frozen_at = set(), 0.0
    now = time.time()
    in_scope, unlogged = 0, []
    for p in reports:
        try:
            mt = p.stat().st_mtime
        except OSError:
            continue
        if mt < cutoff:
            continue
        in_scope += 1
        if p.name in names:
            continue
        # 基线只冻结**冻结时点之前**的同名文件：冻结后被重写的同名报告仍须报（防洗白）
        if p.name in base_names and mt <= frozen_at:
            continue
        unlogged.append((p.name, now - mt))
    fresh = [n for n, age in unlogged if age <= fresh_h * 3600]
    r.update(scope=in_scope, ledger=len(names), baselined=len(base_names),
             unlogged=len(unlogged), fresh_h=fresh_h)
    if fresh:
        r.update(status="FAIL",
                 detail=(f"{len(fresh)} 份报告在 {fresh_h:g}h 内落盘但**无派发记录**"
                         f"（绕过 CLI/runner 的直调）：" + ", ".join(fresh[:8])),
                 fresh=fresh)
    elif unlogged:
        r.update(status="WARN",
                 detail=(f"{len(unlogged)} 份报告未入账（存量，未在基线冻结）："
                         + ", ".join(n for n, _ in unlogged[:8])),
                 files=[n for n, _ in unlogged][:20])
    else:
        r.update(status="PASS",
                 detail=(f"{in_scope} 份在册报告均已入账"
                         f"（ledger={len(names)}，baseline={len(base_names)}）"))
    return r


_FORCE_TEACH_EXEMPT = ("仅当", "门禁", "人工终裁", "兜底", "反例", "历史", "红队",
                       "原始 prompt", "正常路径", "禁止", "禁用", "不要")


def check_force_teaching(skill_dir: str) -> dict:
    """[力] `references/**/*.md` 不得把 `advance --force` 教成**常规路径**（WARN）。

    背景（2026-10-31 实测）：`references/stage-6-r6-flow.md` 的文件头对照表写「R6 合规 =
    逐 stage 推进，无 force」，正文三处却把 `advance --force DONE` 当标准步骤 —— 同一文档
    自相矛盾，且 `--force` 会**同时短路 monitor 与熵门**（经济/监控面顺势失效）。
    已按本检查口径订正；本检查用于**防复发**（同类文档漂移不再靠人眼）。

    判定：命中 `advance --force` 的行，其 **±2 行**内须出现豁免语
    （`仅当/门禁/人工终裁/兜底/反例/历史/红队/正常路径/禁止/禁用/不要`）。
    WARN 不阻断（历史红队记录/失败反例属证据性引用）。
    """
    result = {"check": "force_teaching", "status": "PASS", "findings": []}
    root = Path(skill_dir)
    ref = root / "references"
    if not ref.exists():
        result["status"] = "WARN"
        result["detail"] = "references/ not found"
        return result
    for p in sorted(ref.rglob("*.md")):
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, ln in enumerate(lines):
            if not re.search(r"advance\s+--force", ln):
                continue
            ctx = "\n".join(lines[max(0, i - 2): i + 3])
            if any(tok in ctx for tok in _FORCE_TEACH_EXEMPT):
                continue
            result["findings"].append({
                "file": str(p.relative_to(root)),
                "line": i + 1,
                "text": ln.strip()[:160],
            })
    if result["findings"]:
        result["status"] = "WARN"
        result["detail"] = f"{len(result['findings'])} 处 `advance --force` 缺豁免语境"
    return result


def check_gk_facts(skill_dir: str) -> dict:
    """GK-FACTS 事实块 ↔ 活文件（2026-11-01）。生成器单源 = `gk_docgen_facts.py`。"""
    try:
        import gk_docgen_facts as F
    except Exception as e:  # noqa: BLE001
        return {"check": "gk_facts", "status": "FAIL",
                "detail": "gk_docgen_facts 不可导入: %s" % type(e).__name__}
    try:
        return F.check(skill_dir)
    except Exception as e:  # noqa: BLE001
        return {"check": "gk_facts", "status": "FAIL",
                "detail": "事实块比对异常: %s" % type(e).__name__}


def run_all(skill_dir: str, papers_dir: str, review_skill_dir: str,
            release: bool = False) -> dict:
    issues = 0
    checks = []

    r = check_papers_framework_drift(papers_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    r = check_cli_protocol_commands(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    r = check_review_dual_source(skill_dir, review_skill_dir, release=release)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    checks.append(check_skill_optimizer_status(skill_dir))

    r = check_stale_layering_refs(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    r = check_skill_command_count(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 2026-09-23：红先模版登记表漂移（用户裁定「红先测试模版需要被 doc-align 检查是否存在漂移」）
    r = check_red_arm_templates(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 2026-10-29（T10/A-2）：段职责表 ↔ `_structural_gates` 分支的 gate-id 双向比对。
    #   表未落地（A-1/T3 未完成）⟹ WARN 不阻断；表与代码不等 ⟹ FAIL（精确报段名 + gate-id）。
    r = check_stage_duty_map(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 2026-10-31（T3-b）：SKILL.md 段职责表**指针**存在性 —— 只留指针、否决双写。
    #   指针被删/失效 ⟹ FAIL（读者从 SKILL.md 找不到段职责表 = 交付面失联）。
    r = check_skill_duty_pointer(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 2026-11-01（用户裁定「两份文档应为自动生成产物」）：GK-FACTS 事实块 ↔ 活文件。
    #   手写数字不再被接受：块由 `gk_docgen_facts.py --write` 生成，本检查只比对。
    checks.append(check_gk_facts(skill_dir))

    # 2026-10-04：文本↔实现等价性两类机械面 —— 臂名实存（ECC-C6CAD0E7E6B6）
    #   与契约↔实现集合等价（ECC-614F297C9792）；FAIL 均计入 issues
    r = check_plan_arm_names_exist(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    r = check_contract_enum_impl_binding(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 2026-11-05：退役文档不得留在公开导出面（flows-a-b-c / ecc-impact-v7 实测漏出）
    r = check_retired_doc_export(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 2026-08-28: 文档审查引擎 7 项并入（audit --docs C1-C5）
    for r in check_audit_docs_merged(skill_dir, release=release):
        if r["status"] == "FAIL":
            issues += 1
        checks.append(r)

    # 2026-08-28: 引用链漂移检测（§12 归口"静态存在性类→doc-align"落地；WARN 不阻断）
    checks.append(check_crossref_drift(skill_dir))

    # 2026-09-01 L6 扩展实装：架构文档引用符号 vs gitnexus 索引实存交叉验证
    # （stage-3-review 扩展点"L6 gitnexus context 交叉验证"——WARN 不阻断，索引过期时提示重跑 analyze）
    checks.append(check_symbol_index_existence(skill_dir))

    # 2026-09-01 矩阵机制实装：L1-L9 × 约束-难度矩阵确定性命令存在性校验
    checks.append(check_cross_review_matrix(skill_dir))
    checks.append(check_eval_matrix(skill_dir, release=release))  # 2026-09-06 E1-E4 子集评估器规格 lint（sibling）

    # 2026-09-02 元数据统一路由检测匹配扩展（用户质询三连）：
    # ① 序列节点安全网 map/车站播报/下一站过时检测
    checks.append(check_sequence_node_map(skill_dir))
    # ② 注释-代码错配精细检测（误删/改错注释）
    checks.append(check_comment_code_mismatch(skill_dir, release=release))
    # ③ 5 层路由文档 ↔ 代码一致性
    checks.append(check_route_center_alignment(skill_dir))

    # 2026-09-05 租户隔离（域 token 门小步；与余烬系统对应，评审选项定案）——
    # scopes 租户根双形态重复/嵌套 = 跨租户读取面；实现复用 gk_self_check（单一事实源）
    try:
        from gk_self_check import check_tenant_isolation as _tenant_check
        r = _tenant_check(skill_dir)
    except Exception:
        r = {"check": "tenant_isolation", "status": "SKIP",
             "detail": "依赖导入失败 — 租户隔离检查跳过"}
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 2026-09-06 C6: doc_freshness — references 安全网总表须回流最近登记批次时间戳
    #   （release=True 时该总表属导出排除面 ⟹ 缺席降级 SKIP，见 check_doc_freshness docstring）
    r = check_doc_freshness(skill_dir, release=release)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 2026-09-10 F-REV-20（用户定案 L1）: shell→python 三引号源码内插零容忍
    # （该缺陷 100% 导致静默失败：编译期 SyntaxError 被 2>/dev/null 吞 → 门禁链断裂）
    r = check_shell_python_serialization(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 2026-09-13 缺陷1 实装: anchor_existence — 文档 path:line 锚存在性检查
    # （第三轮质询实证行号手打漂移 → 审计层假绿；WARN 不阻断）
    # 2026-11-02（发布门）：`release=True` 时只扫公开 references/；docs/plans 不进公开导出面，
    #   其历史锚漂移不应阻断发布（完整内部检查仍走默认 `doc-align`）。
    checks.append(check_anchor_existence(skill_dir,
                                         docs_subdir=("references" if release else "docs/plans")))
    # `ECC-PLAND`（2026-10-13 落刀）：计划↔实现漂移检测器（挂 doc-align，**不新增 CLI 命令**）
    if release:
        checks.append({"check": "plan_landing_drift", "status": "SKIP",
                       "detail": "release 模式：docs/plans 不在公开导出面，跳过历史计划漂移"})
    else:
        checks.append(check_plan_landing_drift(skill_dir))

    # 2026-10-28（对账）：subagent 报告 ↔ 派发账本（近期未入账 ⟹ FAIL；存量基线冻结 ⟹ WARN）
    if release:
        checks.append({"check": "subagent_unlogged", "status": "SKIP",
                       "detail": "release 模式：docs/analysis/subagent 不在公开导出面，跳过"})
    else:
        r = check_subagent_unlogged(skill_dir)
        if r["status"] == "FAIL":
            issues += 1
        checks.append(r)

    # 2026-10-31：`advance --force` 教学漂移（WARN 不阻断；stage-6-r6-flow 自相矛盾的防复发）
    checks.append(check_force_teaching(skill_dir))

    return {"ok": True, "issues": issues,
            "warns": sum(1 for c in checks if str(c.get("status")) == "WARN"),
            "checks": checks}


# 锚引用**提取函数** = 单一事实源 `gk_plan_lint.iter_anchor_refs`（2026-09-15；收口
# PW-SN §6 挂账「锚校验与 gk_doc_align.anchor_existence 实现单源化（消双正则漂移）」）。
# 本模块**只**以 `loose=True` 调用该函数（= 本检查 2026-09-13 起的原语义，召回面**不变**）；
# **禁**在此就地新增/改写锚正则，**也禁**直接 import 模式常量自跑 `finditer`
# （REV-11 arm-2：常量级单源在 `loose` 语义为该收口 F-REV-68 而改时即失效 ⟹ 须**函数级**单源）。
# 分工边界见 `gk_plan_lint.iter_anchor_refs` 上方注释：
# 本检查 = 仓级**内容漂移提示**（WARN 不阻断）；可判定断言（阻断）归 `L-ANCHOR`。
from gk_plan_lint import iter_anchor_refs  # noqa: E402
_ANCHOR_STOPWORDS = frozenset((
    "the", "and", "for", "with", "line", "file", "this", "that", "from",
    "into", "path", "post", "prev", "next", "last", "first", "call",
    "http", "https", "self", "true", "false", "none", "null", "json",
    "import", "return", "while", "assert", "detail", "status", "entry",
))


def anchor_rebase_plan(drifted: list[dict]) -> dict:
    """F2（2026-09-17）：漂移记录 → **待重钉清单**（REV-7/REV-9「每轮入口刷新锚基线」的载体）。

    只读、零 API、**不新增门禁**。分两类：
    - `repin`  — **只在锚有「声明符号」且该符号在目标文件内确有命中时**才出；`suggested_line`
                取该符号的**最近命中行**（规则同 `gk_plan_lint._verify_literal`：优先取锚点
                之后的最近命中，否则取全文件最近）—— 这是 `path:NNN sym` 的**断言语义本身**；
    - `manual` — 机器给不出唯一真值的，带 `reason`：
        * `file_missing` 无目标文件 / `line_over_eof` 行号越界（另带 `eof_lines` 供人判新行）；
        * `range_ref` 区间引用 `path:A-B` —— **无符号绑定**者机器给不出跨度的新位置，入此
          （`ECC-F1AEA5F5F0AC`）；**有绑定**者见下条 `repin_range`；
        * `range_ref_inverted` 倒置区间 `path:A-B` 且 **A > B**（正文数字写错；实测 conv-eval
          `gatekeeper-cli.sh:4210-4150` 的链接文本本应是 `#L4110-L4131`）⟹ 保跨度会算出
          **负跨度**（实测 `span=-59`、建议 `(5459,5399)`）⟹ 垃圾值，一律拒；
        * `no_symbol_binding` 裸锚 `path:NNN` —— 无断言符号可校验，无从知道它该指哪；
        * `symbol_absent_from_file` 有绑定但该符号在目标文件里**一次都没出现**（典型 = 断言打错字）。
    - `repin_range` — 2026-09-19 新增：**有符号绑定**的区间引用 `path:A-B sym`。该形态
      **同时**给出符号与跨度 ⟹ 起点 = 符号的最近命中行、长度 = 原跨度，机器**能**给出新位置
      （原先一律入 `manual.range_ref` —— 对「无绑定区间」是正确处置，对本形态则过保守）。
      ⚠ `hits_total` 高处仍须人核：实测 `gatekeeper-cli.sh:6589 L2` 的绑定不成立
      （`L2` 是**文档自己的段落标签**"L2 入站门"，非代码符号），机械重钉会钉到无关行。

    2026-09-19 **ECC-0895762624EB**：原 `repin` 取 `nearest_hit`（关键词最近命中）⟹ 实测不可信
    （锚 `gk_doc_align.py:1160 check_anchor_existence`：正确目标 = 该符号在文件内的命中行，
      而启发式给 1115 = 它的**调用点**；
    `gk_plan_lint.py:439` 在文档里是**被引用的历史值/证据**，启发式给 :12/:23）⟹ 机械重钉既装错锚、
    又改写证据。**⚠ 中途一版误取「符号定义行」，实测立即塌陷**：conv-eval 四条不同锚
    （`gatekeeper-cli.sh:6539/:6019/:444/:6027` 各绑 `_conv_state_path`）会被一起压到定义行 464
    —— 与本条要修的 `range_ref` 塌陷同类。现口径 = 「**断言语义内的最近命中行 or 不猜**」，
    且**裸锚一律不猜**：后者自动把「引用历史值」的证据锚挡在 `repin` 之外。
    每项字段 = `doc` / `doc_line` / `ref` / 建议新行（`suggested_line`）+ `offset` / `hits_total`。
    """
    plan: dict = {"count": len(drifted), "repin": [], "repin_range": [], "manual": []}
    for a in drifted:
        ref = str(a.get("ref") or "")
        base = {"doc": a.get("doc"), "doc_line": a.get("doc_line"),
                "ref": ref, "verdict": a.get("verdict")}
        # A2（2026-09-28，ECC-F68E6BEE4F68）：形态无关 —— `path:A-B` 与 `path#LA-LB` 都要认
        #   （分组语义不变：1 = 起始行、2 = 结束行）。
        rng = re.search(r"(?::|#L)(\d+)(?:-L?)(\d+)$", ref)
        if a.get("verdict") != "content_drift":
            item = {**base, "action": "manual", "reason": a.get("verdict")}
            if a.get("eof_lines") is not None:
                item["eof_lines"] = a["eof_lines"]
            plan["manual"].append(item)
        elif rng:
            _os, _oe = int(rng.group(1)), int(rng.group(2))
            _span = _oe - _os + 1
            _sym, _hit = a.get("declared_symbol"), a.get("symbol_hit_line")
            if _span <= 0:
                # 2026-09-19：倒置区间（正文数字写错）—— 保跨度会得**负跨度**（实测
                # `gatekeeper-cli.sh:4210-4150` → `(5459,5399)`、`span=-59`）⟹ 一律拒，不入
                # `repin_range`；真值须人按链接/读码定（该例链接 `#L4110-L4131` 才是原意）。
                plan["manual"].append({**base, "action": "manual", "reason": "range_ref_inverted",
                                       "orig_start": _os, "orig_end": _oe})
            elif _sym and _hit:
                # 2026-09-19（S1-a 二阶段）：**有绑定**的区间引用 —— 起点 = 符号最近命中行，
                # 长度 = 原跨度 ⟹ 机器**能**给出新位置（无绑定者仍走 manual.range_ref）。
                # ⚠ 本分支**不**替代人核：`hits_total` 高者仍须逐条读码 —— 符号绑定只是
                #   正则的**形态**判据，不保证语义（实测 `gatekeeper-cli.sh:6589 L2` 即误绑：
                #   `L2` 是文档自己的段落标签，全文 38 处命中纯属巧合）。
                plan["repin_range"].append({**base, "action": "repin_range",
                                            "symbol": _sym,
                                            "suggested_start": int(_hit),
                                            "suggested_end": int(_hit) + (_span - 1),
                                            "orig_start": _os, "orig_end": _oe, "span": _span,
                                            "offset": int(_hit) - _os,
                                            "hits_total": a.get("symbol_hits_total")})
            else:
                plan["manual"].append({**base, "action": "manual", "reason": "range_ref",
                                       "orig_start": _os, "orig_end": _oe, "span": _span})
        elif not a.get("declared_symbol"):
            plan["manual"].append({**base, "action": "manual", "reason": "no_symbol_binding"})
        elif not a.get("symbol_hit_line"):
            plan["manual"].append({**base, "action": "manual",
                                   "reason": "symbol_absent_from_file",
                                   "symbol": a.get("declared_symbol")})
        else:
            _hit = int(a["symbol_hit_line"])
            _lo_m = re.search(r"(?::|#L)(\d+)$", ref)
            plan["repin"].append({**base, "action": "repin",
                                  "symbol": a.get("declared_symbol"),
                                  "suggested_line": _hit,
                                  "offset": (_hit - int(_lo_m.group(1))) if _lo_m else None,
                                  "hits_total": a.get("symbol_hits_total")})
    return plan


# ── 计划↔实现漂移检测器（`ECC-PLAND`，2026-10-13 落刀）────────────────────────
def _looks_like_target(tok: str) -> bool:
    """token 像**文件路径**（含分隔符 + 已知后缀）？"""
    tok = tok.strip()
    return ("/" in tok or "\\" in tok) and re.search(r"\.(py|sh|md|json|js|ts)$", tok) is not None


def _plan_targets(text: str) -> list:
    """抽计划文本里的「落刀点」→ [(t_item, target_relpath, declared_symbol)]。

    面（`ECC-PLAND` §2.1）：§3 `### T<n> …` 段的 `**文件**` 行 + §0.3 落刀点表行
    （跳过含「不改 / 不动 / 排除」的行 —— 那是**显式排除面**，非落刀点）。
    """
    out = []
    for m in re.finditer(r"(?ms)^###\s+(T\d+[^\n]*)\n(.*?)(?=^###\s|\Z)", text):
        t_item, body = m.group(1).strip(), m.group(2)
        fmm = re.search(r"\*\*文件\*\*[：:](.*)", body)
        if not fmm:
            continue
        line = fmm.group(1)
        sm = re.search(r"新增\s*`([^`]+)`", line)
        sym = sm.group(1) if sm else ""
        for tok in re.findall(r"`([^`]+)`", line):
            tgt, tsym = (tok.split("::", 1) if "::" in tok else (tok, sym))
            if _looks_like_target(tgt):
                out.append((t_item, tgt.replace("\\", "/").lstrip("./"), tsym))
                break
    for m in re.finditer(r"(?m)^\|\s*`([^`]+)`\s*\|(.*)$", text):
        row = m.group(2)
        if any(k in row for k in ("不改", "不动", "排除")):
            continue
        tgt, tsym = (m.group(1).split("::", 1) if "::" in m.group(1) else (m.group(1), ""))
        if _looks_like_target(tgt):
            out.append(("§0.3", tgt.replace("\\", "/").lstrip("./"), tsym))
    return out


def _landing_verdict(sd: Path, target: str, sym: str, plan_stem: str) -> tuple:
    """落刀点判定 → (verdict, why)。verdict ∈ {ok, suspect, landed_stale}。"""
    p = sd / target
    if not p.is_file():
        return "ok", "目标不存在"
    try:
        body = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "ok", "目标不可读"
    marks = []
    if plan_stem and plan_stem in body:
        marks.append(f"引计划 basename `{plan_stem}`")
    if re.search(r"\bDRAFT-\d+", body):
        marks.append("含 `DRAFT-N`")
    if sym and re.search(r"(?m)^\s*def\s+" + re.escape(sym) + r"\b", body):
        marks.append(f"已定义声明符号 `{sym}`")
    if marks:
        return "landed_stale", "、".join(marks)
    return "suspect", "目标在但无落刀痕"


def check_plan_landing_drift(skill_dir: str) -> dict:
    """计划↔实现漂移检测器（`ECC-PLAND` §2.1；2026-10-13 落刀）。

    现场（2026-10-04 干净质询）：一份计划称「T1/T2/T4/T5 待落刀」，而代码里**早已存在** ⟹
    「计划状态断言 vs 代码实况」漂移，doc-align 原有检查器**无一项覆盖** ⟹ 立本器。

    输入 = `docs/plans/*.md`（含 `<!-- META`）的 §0.3 落刀点表 + §3 `### T<n>` 段 `**文件**`
    点名的 `file`（可带 `::symbol`）。判定（§2.1）：目标**不存在** ⟹ `ok`；存在且含**落刀痕**
    （文本引本计划 basename / `DRAFT-N`，或该步声明的新符号已 `def`）⟹ `landed_stale`(high)；
    存在但无落刀痕（可能别的计划建的）⟹ `suspect`(low，**仅此** ⟹ INFO，不污染 WARN 面)。
    开关 `GK_PLAND_DRIFT=0` ⟹ SKIP。含 `landed_stale` ⟹ WARN。
    """
    result = {"check": "plan_landing_drift"}
    if os.environ.get("GK_PLAND_DRIFT", "1") == "0":
        result["status"] = "SKIP"
        result["detail"] = "GK_PLAND_DRIFT=0 —— 跳过计划落刀漂移检测"
        return result
    sd = Path(skill_dir)
    plans_dir = sd / "docs" / "plans"
    if not plans_dir.is_dir():
        result["status"] = "SKIP"
        result["detail"] = "无 docs/plans（未登记计划面）"
        return result
    items = []
    for md in sorted(plans_dir.glob("*.md")):
        try:
            text = md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "<!-- META" not in text:
            continue
        for t_item, target, sym in _plan_targets(text):
            verdict, why = _landing_verdict(sd, target, sym, md.stem)
            items.append({"plan": md.name, "t_item": t_item, "target": target,
                          "verdict": verdict, "why": why})
    result["items"] = items
    stale = [it for it in items if it["verdict"] == "landed_stale"]
    suspect = [it for it in items if it["verdict"] == "suspect"]
    if stale:
        result["status"] = "WARN"
        result["detail"] = (f"{len(stale)} 处落刀语义过期（计划称待落刀，目标已在且含落刀痕）: "
                            + "; ".join(f"{it['plan']}:{it['target']}" for it in stale[:8]))
    elif suspect:
        result["status"] = "INFO"
        result["detail"] = (f"{len(suspect)} 处 suspect（目标存在但无落刀痕，可能别计划建的）: "
                            + "; ".join(f"{it['plan']}:{it['target']}" for it in suspect[:8]))
    else:
        result["status"] = "PASS"
        result["detail"] = f"计划落刀点无过期（核 {len(items)} 个落刀点）"
    return result


def check_anchor_existence(skill_dir: str, docs_subdir: str = "docs/plans",
                           extra_roots=None) -> dict:
    """anchor_existence — 文档内 `path:line` 引用锚的确定性检查（缺陷1，2026-09-13 实装）。

    背景（第三轮质询实证）：计划/审计文档行号手打 → 编辑后漂移 → 审计层引用失效 =
    "锚点已核"假绿。本检查器把锚当作可校验断言：
      1. file_missing   — 被引文件不存在；
      2. line_over_eof  — 行号 > 文件 EOF（给出行数）；
      3. content_drift  — 行号存在但引用行上下文关键词（引用 token 邻域 ≥4 字符词，
                          ±2 行窗口）全部未命中 → WARN + 给关键词在全文件最近命中行；
      4. unchecked      — 邻域无可提取关键词（纯符号/路径），仅做了 1/2 校验，不算漂移。
    扫描面 = skill_dir/docs_subdir 下 *.md（计划文档为行号引用重灾区）；单文件读缓存；
    确定性 0-API。status：0 锚 → SKIP；有任一漂移 → WARN（不阻断）；否则 PASS。

    2026-09-26（`ECC-1FA6B6E7D15C` B 侧）：新增可选 `extra_roots`（**仓外 repo 根**列表）——
    仓外计划（如 `.codex/docs/plans/`）此前完全在机检面之外（旧实现只以 `skill_dir` 为根）。
    语义：扫描面加 `<root>/<docs_subdir>`，**且**被引文件（rel）的解析基址加 `<root>`
    （故仓外计划里引**自己仓**的文件也能解析）。返回 dict 新增 `roots`（本次用的 repo 根）。
    ⚠ 不传 `extra_roots` ⟹ 与既有行为**逐字一致**（扫描面与解析基址都不变）。
    """
    result = {"check": "anchor_existence"}
    _extras = [str(r) for r in (extra_roots or []) if str(r).strip()]
    base_roots = [Path(skill_dir)] + [Path(r) for r in _extras]
    result["roots"] = [str(r) for r in base_roots]
    docs_dirs = [d for d in (Path(r) / docs_subdir for r in base_roots) if d.is_dir()]
    if not docs_dirs:
        result["status"] = "SKIP"
        result["detail"] = f"docs 子目录不存在: {docs_subdir}"
        return result
    # 2026-09-19 ECC-0895762624EB：重钉的**唯一可信依据** = 该锚**声明符号**在目标文件内的
    # **最近命中行**（规则同 `gk_plan_lint._verify_literal`：优先取锚点**之后**的最近命中，
    # 否则取全文件最近）。这**不是**猜谜 —— 它就是 `path:NNN sym` 形态的**断言语义本身**：
    # 该形态断言「NNN 处有 sym」，**不是**「sym 的定义处」。
    # ⚠ 我第一版误把它当「定义处」，实测立刻塌陷：conv-eval 四条不同锚
    #   （`gatekeeper-cli.sh:6539/:6019/:444/:6027` 各绑 `_conv_state_path`）会被一起压到定义行 464。
    # 原 `nearest_hit`（关键词最近命中）亦可信度不足 —— 实测 `gk_doc_align.py:1160 check_anchor_existence`
    #   正确目标 = 该符号在文件内的命中行，而启发式给 1115（调用点）；`gk_plan_lint.py:439` 是文档引用的**历史值/证据**。
    # 绑定正则**复用 `gk_plan_lint`**（单一事实源，防第二套绑定口径）；无绑定（裸 `path:NNN`）不猜。
    from gk_plan_lint import (_RE_ANCHOR_SYM, _RE_SYM_BEFORE,
                             _RE_ANCHOR_SYM_HASHL, _RE_SYM_BEFORE_HASHL)

    def _bound_symbol(line_text: str, rel_path: str, lineno: int):
        """doc 行内**锚→声明符号**的绑定（高置信形态之一）；无绑定 ⟹ None。"""
        for mm in _RE_ANCHOR_SYM.finditer(line_text):
            if mm.group(1).replace("\\", "/") == rel_path and int(mm.group(2)) == lineno:
                return mm.group(4)
        for mm in _RE_SYM_BEFORE.finditer(line_text):
            if mm.group(2).replace("\\", "/") == rel_path and int(mm.group(3)) == lineno:
                return mm.group(1)
        # A2（2026-09-28，ECC-F68E6BEE4F68）：`path#L123 sym`（无冒号）形态的**重钉面专属**
        #   绑定 —— 与上面两条写侧口径分开（它们被 `plan-lint` 的 `anchor_findings` 消费，
        #   开宽会动到冻结计数面）。上面两条对本形态**永不**命中 ⟹ 无重叠、无副作用。
        for mm in _RE_ANCHOR_SYM_HASHL.finditer(line_text):
            if mm.group(1).replace("\\", "/") == rel_path and int(mm.group(2)) == lineno:
                return mm.group(4)
        for mm in _RE_SYM_BEFORE_HASHL.finditer(line_text):
            if mm.group(2).replace("\\", "/") == rel_path and int(mm.group(3)) == lineno:
                return mm.group(1)
        return None

    files_cache: dict[str, list[str]] = {}
    # A2（2026-09-28，ECC-F68E6BEE4F68）：两套累加器 —— `_l` = loose（WARN 计数面），
    #   `_h` = `#L`（只喂重钉面）。循环体内按 match 形态把 `anchors` / `drifted` 两个局部名
    #   **别名**到对应累加器 ⟹ 下方 6 个 append 点全部零改动。
    anchors_l, drifted_l = [], []
    anchors_h, drifted_h = [], []
    for md in sorted({m for d in docs_dirs for m in d.glob("*.md")}, key=lambda p: str(p)):
        try:
            text = md.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for ln, line in enumerate(text.splitlines(), 1):
            # A2（2026-09-28，ECC-F68E6BEE4F68）：**同一遍扫描体内跑两条口径** —— `path:L`
            #   （loose，喂 WARN 计数面）**先**，`path#L`（新口径，只喂重钉面）**后**；两者召回
            #   面互不重叠 ⟹ 无重复计数。漂移判据实现**只有这一份**（禁第二漂移事实源）。
            for m in list(iter_anchor_refs(line, loose=True)) + \
                    list(iter_anchor_refs(line, hashl_only=True)):
                # 形态由 match 自身判定（不引入第二套模式标志）；`#L` 走重钉面累加器。
                anchors, drifted = ((anchors_h, drifted_h) if "#L" in m.group(0)
                                    else (anchors_l, drifted_l))
                ref_path, s_line, e_line = m.group(1), int(m.group(2)), m.group(3)
                rel = ref_path.replace("\\", "/").lstrip("./")
                # 2026-09-26（`ECC-1FA6B6E7D15C`）：解析基址 = 全部 repo 根（技能仓 + extra_roots）
                # —— 仓外计划里引**自己仓**的文件才解析得到；extra_roots 为空 ⟹ 与旧实现逐字一致。
                cand = [b / rel for b in base_roots] + \
                       [b / "scripts" / Path(rel).name for b in base_roots]
                target = next((c for c in cand if c.is_file()), None)
                # A2：`ref` 必须**逐字保留原文锚形态** —— `apply_edits` 按文本替换（rule #6），
                #   `#L` 锚若写成 `path:NEW` 就永远 `not_found`。
                _sep, _rsep = ("#L", "-L") if "#L" in m.group(0) else (":", "-")
                a = {"doc": md.name, "doc_line": ln, "ref": f"{ref_path}{_sep}{s_line}"
                     + (f"{_rsep}{e_line}" if e_line else "")}
                a["declared_symbol"] = _bound_symbol(line, ref_path, s_line)
                if target is None:
                    a["verdict"] = "file_missing"
                    drifted.append(a)
                    continue
                key = str(target)
                if key not in files_cache:
                    try:
                        files_cache[key] = target.read_text(
                            encoding="utf-8", errors="replace").splitlines()
                    except Exception:
                        files_cache[key] = []
                body = files_cache[key]
                if s_line > len(body) or (e_line and int(e_line) > len(body)):
                    a["verdict"] = "line_over_eof"
                    a["eof_lines"] = len(body)
                    drifted.append(a)
                    continue
                # 关键词命中：引用 token 邻域词 × 目标行 ±2 窗口
                lo = max(0, m.start() - 40)
                hi = min(len(line), m.end() + 40)
                words = [w.lower() for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}",
                                                       line[lo:hi])
                         if w.lower() not in _ANCHOR_STOPWORDS
                         and w.lower() not in ref_path.lower()][:3]
                if not words:
                    a["verdict"] = "unchecked"
                    anchors.append(a)
                    continue
                win = "\n".join(body[max(0, s_line - 3):s_line + 2]).lower()
                if any(w in win for w in words):
                    a["verdict"] = "ok"
                    anchors.append(a)
                else:
                    a["verdict"] = "content_drift"
                    a["probe_words"] = words
                    for w in words:
                        hit = next((i for i, t in enumerate(body, 1)
                                    if w in t.lower()), None)
                        if hit is not None:
                            a["nearest_hit"] = f"{Path(rel).name}:{hit}"
                            break
                    # 声明符号的**最近命中行**（规则与 `gk_plan_lint._verify_literal` 逐字一致：
                    # 优先取锚点**之后**的最近命中，否则取全文件最近）⟹ 重钉目标由此而来，可判、可复算。
                    _sym = a.get("declared_symbol")
                    if _sym:
                        _occ = [i for i, t in enumerate(body, 1) if _sym in t]
                        if _occ:
                            _after = [i for i in _occ if i >= s_line]
                            a["symbol_hit_line"] = (min(_after) if _after
                                                    else min(_occ, key=lambda i: abs(i - s_line)))
                            a["symbol_hits_total"] = len(_occ)
                    drifted.append(a)
    # ── 分级（ECC-E98B8F59E750）+ T2 改口径（`ECC-PLAND` §2.3）─────────────────
    #   A2 先例：**另立字段**；`anchors_total`（收敛评估的冻结比对串 `N/M 锚漂移` 的**分母**）
    #   **一个数都不变** —— 分级只是「同一份 drifted 的再切分」，不新增/不删锚。
    #   T0 = 硬断（file_missing / line_over_eof）—— 确定性错；
    #   T1 = 可重钉（content_drift **且**有 declared_symbol，符号仍在文件内）—— 真漂移、可重钉；
    #   T2 = 无断言 content_drift —— **不可判定**（文档编辑副产品）。
    #   `ECC-PLAND` §2.3：`drifted` 改 **T0+T1**（原 T0+T1+T2）；T2 移入新键 `unasserted`
    #   （留明细、不入漂移面）⟹ 分母不变、**分子变小** = 噪声真的从漂移面消失。
    _t0 = [a for a in drifted_l if a.get("verdict") in ("file_missing", "line_over_eof")]
    _t1 = [a for a in drifted_l if a.get("verdict") == "content_drift"
           and a.get("declared_symbol")]
    _t2 = [a for a in drifted_l if a.get("verdict") == "content_drift"
           and not a.get("declared_symbol")]
    _drift_core = _t0 + _t1
    result["anchors_total"] = len(anchors_l) + len(drifted_l)
    result["anchors"] = anchors_l
    result["drifted"] = _drift_core
    result["unasserted"] = _t2
    if result["anchors_total"] == 0:
        result["status"] = "SKIP"
        result["detail"] = "docs/plans 无 path:line 锚引用"
    elif _drift_core:
        result["status"] = "WARN"
        result["detail"] = (f"{len(_drift_core)}/{result['anchors_total']} 锚漂移"
                            + "（T0 硬断/T1 可重钉；"
                            + f"另 {len(_t2)} 条无断言 content_drift 入 `unasserted`，不计入漂移）")
    else:
        result["status"] = "PASS"
        result["detail"] = (f"{result['anchors_total']} 锚全部命中"
                            + (f"（{len(_t2)} 条无断言 content_drift 入 `unasserted`）" if _t2 else ""))
    # F2（2026-09-17）：批次入口自动对账 —— 出「待重钉清单」供照改（只读；kill switch 可关）
    if os.environ.get("GK_ANCHOR_REBASE", "") != "0":
        # A2：重钉面 = loose 漂移 **加** `#L` 漂移增量（两者共用上面同一份判据实现）。
        result["rebase_plan"] = anchor_rebase_plan(drifted_l + drifted_h)
    result["tiers"] = {
        "counts": {"t0": len(_t0), "t1": len(_t1), "t2": len(_t2), "total": len(drifted_l)},
        "t0": _t0, "t1": _t1, "t2": _t2,
    }
    return result


def check_symbol_index_existence(skill_dir: str) -> dict:
    """L6 扩展实装（2026-09-01，完整版）：架构文档引用符号 vs gitnexus 索引 context 交叉验证。

    演进（2026-09-01 两轮）：
      v1（初版）     — 仅 CONTAINS 存在性探测（count>0 即 PASS）→ 用户质询"阉割版"
      v2（升级）     — 存在 + CALLS 入边（0 入边 = 孤立/死代码候选隔离标记）
      v3（完整版）   — 存在 + 入边 + **调用者构成**：全部调用者都是测试文件
                     = 测试自循环掩盖死代码候选（Bridge R7.5 verify_integration.py 教训）
    从 SKILL.md/stage-3-review.md/架构文档提取 `gk_*.py` 脚本名 + 反引号函数名引用，
    cypher 三查询（存在 + CALLS 入边 + 调用者文件清单）。WARN 不阻断（索引可能过期 →
    提示 analyze --force 重建）；cypher 失败/无索引 → status SKIP 非 FAIL。确定性 0 API。
    """
    result = {"check": "symbol_index_existence"}
    files = [Path(skill_dir) / "SKILL.md",
             Path(skill_dir) / "references" / "stage-3-review.md",
             Path(skill_dir) / "references" / "cli-protocol.md"]
    texts = []
    for f in files:
        if f.exists():
            texts.append(_read(f))
    joined = "\n".join(texts)
    # 提取 gk_*.py 脚本名（反引号或裸引用）→ 统一去掉包裹反引号
    gk_scripts = sorted(set(m.strip("`") for m in re.findall(r"`?gk_[a-z0-9_]+\.py`?", joined)))
    # 提取反引号内的函数名（含字母/下划线，≥3 字符，排除文件名/命令名）
    func_refs = sorted(set(
        m for m in re.findall(r"`([a-z][a-z0-9_]{3,})`", joined)
        if m not in ("ok", "status", "error", "true", "false", "stderr", "stdout")
        and not m.startswith("gk_") and ".sh" not in m and "gatekeeper" not in m
    ))
    probes = gk_scripts + func_refs[:20]
    if not probes:
        result["status"] = "PASS"
        result["detail"] = "文档无可提取符号引用"
        return result
    missing = []
    isolated = []
    test_only = []
    for sym in probes:
        try:
            q = f"MATCH (n) WHERE n.name CONTAINS '{sym}' RETURN count(n) AS c"
            d = _gx_cypher(q)
            cnt = _extract_markdown_int(d)
            if cnt == 0:
                missing.append(sym)
                continue
            # context 级：CALLS 入边（谁调用该符号）→ 0 入边 = 孤立/死代码候选
            q2 = ("MATCH (n)<-[r:CodeRelation {type:'CALLS'}]-(caller) "
                  f"WHERE n.name CONTAINS '{sym}' RETURN count(r) AS c")
            d2 = _gx_cypher(q2)
            inc = _extract_markdown_int(d2)
            if inc == 0:
                isolated.append(sym)
                continue
            # 完整版 v3：调用者构成 — 全为测试文件 = 测试自循环掩盖死代码（R7.5 教训）
            q3 = ("MATCH (caller)-[:CodeRelation {type:'CALLS'}]->(n) "
                  f"WHERE n.name CONTAINS '{sym}' RETURN DISTINCT caller.filePath AS f LIMIT 20")
            d3 = _gx_cypher(q3)
            md3 = d3.get("markdown", "")
            caller_files = [row[0] for row in extract_markdown_table(md3) if row and row[0]]
            if caller_files and all(
                    ("test" in f.lower() or "tests/" in f.replace("\\", "/"))
                    for f in caller_files):
                test_only.append(sym)
        except Exception:
            result["status"] = "SKIP"
            result["detail"] = "gitnexus cypher 不可用（无索引/未装）— 符号实存检查跳过"
            result["probed"] = len(probes)
            return result
    problems = missing + isolated + test_only
    result["probed"] = len(probes)
    result["missing"] = missing
    result["isolated"] = isolated
    result["test_only"] = test_only
    if problems:
        result["status"] = "WARN"
        detail = []
        if missing:
            detail.append(f"索引缺失 {len(missing)}: {missing[:8]}")
        if isolated:
            detail.append(f"孤立(无调用者) {len(isolated)}: {isolated[:8]}")
        if test_only:
            detail.append(f"仅测试调用(测试自循环候选) {len(test_only)}: {test_only[:8]}")
        result["detail"] = "文档引用符号 " + "；".join(detail) + "（索引过期? 跑 gitnexus analyze --force / 死代码候选需核验）"
    else:
        result["status"] = "PASS"
        result["detail"] = f"文档引用符号全部实存且有调用者（{len(probes)} 个探针: {probes[:6]}…）"
    return result


def _gx_cypher(query: str) -> dict:
    """Windows node.exe 直调 gitnexus cypher（Windows 下无 shell 转义；subagent_runner 同款）。

    F-REV-75（2026-09-16，用户裁定「同根因修」）：node/js/repo **不再自探测** —— 原硬编码
    `/mnt/d/Program Files/nodejs/node.exe` + 写死 repo 正是技能自身禁令（gatekeeper-cli.sh
    L1275）点名的「第二份探测」。改为消费 CLI（`_gx_subagent_gx_env`）注入的
    GX_NODE/GX_JS/GX_REPO；缺失 → raise（调用方本就在 try/except 内降级，语义不变）。

    JSON 提取收敛到 gk_json_utils.extract_last_json（2026-09-01）：多 JSON/warn 后置
    均取最后完整对象；无 JSON → raise RuntimeError。
    """
    import subprocess as _sp
    _node = os.environ.get("GX_NODE", "") or ""
    _js = os.environ.get("GX_JS", "") or ""
    _repo = os.environ.get("GX_REPO", "") or ""
    _miss = [n for n, v in (("GX_NODE", _node), ("GX_JS", _js), ("GX_REPO", _repo)) if not v]
    if _miss:
        raise RuntimeError("gitnexus unavailable: " + "/".join(_miss) +
                           " 未注入（本路径须经 gatekeeper-cli.sh 调用 —— CLI 自动注入；F-REV-75）")
    r = _sp.run([_node, _js, "cypher", query, "-r", _repo],
                capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError((r.stdout or r.stderr)[:120])
    out = r.stdout or ""
    obj = extract_last_json(out)
    if obj is None:
        raise RuntimeError("no JSON")
    return obj


def _extract_markdown_int(d: dict) -> int:
    """从 cypher markdown 表提取末行数字（共享 gk_json_utils 实现）。"""
    n = extract_markdown_int(d)
    return n if n is not None else 0


def summarize(result, width: int = 140) -> str:
    """人读视图（`ECC-F2BDAFB8899C`）：每检查一行 `<check>: <status> — <detail>`。

    全量 JSON（2026-10-12 实测逾 1.7 万行）不可一次读完 ⟹ 本函数把检查清单压成可一眼读完的
    N 行（头行 = issues/checks[/warn] 计数），供 `doc-align --summary`。纯函数、**不改**检查逻辑。

    `ECC-439C8B7CF048` D7（2026-10-13）：原 `detail[:137]+"..."` 把多条目清单**从中间斩断**
    （papers_framework_drift 7 项 / comment_code_mismatch 多文件）⟹ 可操作信息丢失。改为对超宽
    detail **换行续排（悬挂缩进）**，内容**零丢失**；头行补 `warn=N`（否则 4 条 WARN 被 issues=0 掩盖）。
    """
    checks = result.get("checks") or []
    warn = sum(1 for c in checks if str(c.get("status")) == "WARN")
    head = "doc-align: issues=%s checks=%d" % (result.get("issues"), len(checks))
    if warn:
        head += " warn=%d" % warn
    lines = [head]
    for c in checks:
        detail = str(c.get("detail") or "").replace("\n", " ")
        prefix = "%-44s %-5s " % (c.get("check", "?"), c.get("status", "?"))
        if len(prefix) + len(detail) <= width:
            lines.append(prefix + detail)
            continue
        indent = " " * len(prefix)
        avail = max(20, width - len(prefix))
        rows, cur = [], ""
        for tok in re.split(r"(?<=, )", detail):      # 条目边界优先在 ", " 处断
            while len(tok) > avail:                   # 单条目仍超宽 ⟹ 硬切（零丢失）
                if cur:
                    rows.append(cur); cur = ""
                rows.append(tok[:avail]); tok = tok[avail:]
            if cur and len(cur) + len(tok) > avail:
                rows.append(cur); cur = tok
            else:
                cur += tok
        if cur:
            rows.append(cur)
        for k, ch in enumerate(rows):
            lines.append((prefix if k == 0 else indent) + ch)
    return "\n".join(lines)


def main(argv=None):
    # ③ preflight-evidence 子命令（2026-09-06 E1-E4 证据注入任务模式；doc-align run_all
    # 之外的分发面，不注册进 run_all/检查器列表 —— gatekeeper-cli.sh cmd_plan_refinement
    # 经 bash 直调此 CLI 面，注入成功 stdout 非空，未命中 stdout 为空）
    _argv = list(sys.argv[1:] if argv is None else argv)
    if _argv and _argv[0] == "preflight-evidence":
        sys.exit(_preflight_evidence_cli(_argv[1:]))
    skill_dir = os.environ.get("SKILL_DIR", str(Path(__file__).resolve().parent.parent))
    papers_dir = os.environ.get("PAPERS_DIR", "")
    review_skill_dir = os.environ.get("REVIEW_SKILL_DIR", "")

    args = _argv  # argv 注入统一源（param → sys.argv[1:]），防双读 sys.argv 形态漂移
    summary = False
    strict = False
    release = False
    i = 0
    while i < len(args):
        if args[i] == "--skill-dir" and i + 1 < len(args):
            skill_dir = args[i + 1]; i += 2
        elif args[i] == "--papers-dir" and i + 1 < len(args):
            papers_dir = args[i + 1]; i += 2
        elif args[i] == "--review-skill-dir" and i + 1 < len(args):
            review_skill_dir = args[i + 1]; i += 2
        elif args[i] == "--summary":
            summary = True; i += 1
        elif args[i] == "--release":
            release = True; i += 1
        elif args[i] == "--strict":
            # 2026-10-28（消灭局限）：WARN 纳入失败判据。旧行为只数 FAIL ⟹
            # `issues=0` 可以同时伴随 151 条锚漂移 / 17 条计划漂移（实测），审计层假绿。
            strict = True; i += 1
        else:
            i += 1

    if not papers_dir:
        # 2026-10-31（公开面去标识）：原默认路径写死**私有仓名** —— 公开面不得携带私有路径
        # （可移植性 + 去标识）。改三级来源（公开树零私有字面量）：
        #   ① `GK_PAPERS_DIR`（唯一显式配置位）
        #   ② `GK_PAPERS_REPO`（可选）→ 探测 `<home>/Downloads/<repo>/papers` 双形态
        #   ③ `scripts/_papers.local`（gitignored，本机值；与 `_accept_py.local` 同模式）
        # 都缺 ⟹ 空（各检查器按缺稿报 gap，不静默假绿）。
        papers_dir = (os.environ.get("GK_PAPERS_DIR") or "").strip()
        if not papers_dir:
            _repo = (os.environ.get("GK_PAPERS_REPO") or "").strip()
            if _repo:
                _p = os.path.join(_host_paths.user_home(), "Downloads", _repo, "papers")
                for _c in (_p, _host_paths.win_abs_to_wsl(_p)):
                    if Path(_c).is_dir():
                        papers_dir = _c
                        break
        if not papers_dir:
            try:
                papers_dir = Path(os.path.dirname(os.path.abspath(__file__)),
                                  "_papers.local").read_text(encoding="utf-8").strip()
            except OSError:
                papers_dir = ""

    if not review_skill_dir:
        # 2026-10-29 去硬编码：`GK_REVIEW_SKILL_DIR` > `<用户目录>/.trae/skills/<skill>`
        review_skill_dir = (os.environ.get("GK_REVIEW_SKILL_DIR") or "").strip()
        if not review_skill_dir:
            _rs = os.path.join(_host_paths.user_home(), ".trae", "skills",
                               "requesting-code-review")
            for _c in (_rs, _host_paths.win_abs_to_wsl(_rs)):
                if (Path(_c) / "SKILL.md").exists():
                    review_skill_dir = _c
                    break

    result = run_all(skill_dir, papers_dir, review_skill_dir, release=release)
    if summary:
        print(summarize(result))
    else:
        # 2026-10-31：打印面限流（函数回包不变；见 `_clip_for_stdout` 头注的边界说明）
        print(json.dumps(_clip_for_stdout(result), indent=2, ensure_ascii=False))
    bad = result["issues"] > 0 or (strict and result.get("warns", 0) > 0)
    sys.exit(1 if bad else 0)


def check_doc_freshness(skill_dir: str, release: bool = False) -> dict:
    """doc_freshness（2026-09-06 C6）：references 安全网总表新鲜度守护。

    背景（评估 §15.6 ⑧ f6）：security-measures.md 曾停更 11 天无任何检查器发现（靠人工质询
    才回流），doc-align 对其仅有存在性/引用链检查无内容新鲜度。本检查器把"停更"变为可检出：
    - 总表须含最近登记批次时间戳字面（RECENT_BATCH_TS——新批次须 bump，防呆同 pin 案例）
    - 总表须含 ≥1 行机制登记行（`> **C# 追加` / `> **C#+A#` 形态，机制 id 回流面）
    FAIL = 总表停更未回流（须补"最近登记批次"登记行）。真实库含 doc_freshness 检测结论段
    也计入（本检查器自身回流的锚）。

    `release=True`（发布门，2026-11-09）：该总表属**导出排除面**（`oss-export-whitelist.json`，
    owner 2026-11-02 裁定仅私仓留存）⟹ 公开树缺席是**预期**，降级 SKIP；私仓（release=False）
    仍 FAIL（内部必须存在且回流）。
    """
    RECENT_BATCH_TS = "2026-09-25"   # 最近登记批次（…→ 09-13 C11 XSPI → 09-25 C12 hook-xenv §15.3-Q3：持久化块日志分母源 + 总表四列网表扩列）
    # 2026-09-25 C12 bump：持久化块日志（误报率分母源）+ 四列网表（层/判据/误报率口径/守方）回流后须同步，防呆 pin 面即本行
    result = {"check": "doc_freshness"}
    total = Path(skill_dir) / "references" / "security-measures.md"
    if not total.exists():
        if release:
            result["status"] = "SKIP"
            result["detail"] = ("release 模式：references/security-measures.md 属导出排除面"
                                "（oss-export-whitelist，owner 2026-11-02 裁定仅私仓留存）⟹ "
                                "公开树缺席是预期，跳过存在性/新鲜度检查")
            return result
        result["status"] = "FAIL"
        result["detail"] = "references/security-measures.md（安全网总表）缺失"
        return result
    try:
        text = total.read_text(encoding="utf-8")
    except OSError as e:
        result["status"] = "FAIL"
        result["detail"] = "总表不可读: " + str(e)
        return result
    has_ts = RECENT_BATCH_TS in text
    reg_lines = re.findall(r"^> \*\*C\d+(?:\+\s*A\d+)? (?:追加|不适配判定)", text, re.MULTILINE)
    has_reg = bool(reg_lines)
    # Q3-②（hook-xenv §15.3-Q3）：四列网表守护 —— 防四列（层/判据/误报率口径/守方）落成
    #   第二份停更表：总表须含「四列网表」节 + 唯一事实源声明（C6 当初防的失败模式同款）。
    has_four_col = ("四列网表" in text) and ("唯一事实源" in text)
    if not has_ts or not has_reg or not has_four_col:
        result["status"] = "FAIL"
        result["detail"] = ("安全网总表未回流最近登记批次（RECENT_BATCH_TS=" + RECENT_BATCH_TS
                            + " 缺失=" + str(not has_ts) + "；机制登记行缺失=" + str(not has_reg)
                            + "；四列网表/唯一事实源声明缺失=" + str(not has_four_col)
                            + "）→ 总表补新鲜度登记行 + 四列网表节（security-measures.md 参考来源前）")
        result["missing_batch_ts"] = not has_ts
        result["missing_registration_line"] = not has_reg
        result["missing_four_col_view"] = not has_four_col
        return result
    result["status"] = "PASS"
    result["detail"] = ("总表已回流最近登记批次 " + RECENT_BATCH_TS + "，机制登记行 "
                        + str(len(reg_lines)) + " 条（含 " + "、".join(reg_lines[:2]) + "…）；四列网表在位")
    return result


# ── 2026-09-06 ③ E1-E4 证据注入任务模式（references/e1e4-evaluator-matrix.md §2 实装）──
# 触发判定 + 【preflight 证据摘要】构建 + task 前置注入全部落本模块（doc-align 内新增
# sibling，禁第二文件双写）。确定性 0-API（纯读本地文件/state，无网络）；单源失败 →
# 该行 N/A + 读取入口注明（不抛、不阻塞质询）。A2 无新管道：不注册任何 _CMD_REG 命令。
_EV_MATRIX_MARKERS = ("审查层矩阵", "E1-E4")
_EV_MATRIX_PLAN_BASENAME = "e1e4-evaluator-matrix.md"
_EV_DETAIL_CLIP = 160
_EV_CONTRACT_ANCHOR = "subagent_runner.py:1222-1231（evidence 格式要求 / ReLocation）"


def _src_ref(func, fallback: str) -> str:
    """证据出处 file:line 文本（file:start-end 形态，对齐 evidence 契约）。

    源码/行号不可得（非文件模块等）→ 返回带函数名的出处字符串回退。
    """
    try:
        src, start = inspect.getsourcelines(func)
        fname = Path(inspect.getsourcefile(func) or "").name or "?"
        return f"{fname}:{start}-{start + len(src) - 1}"
    except Exception:
        return fallback


def _clip(text, limit: int = _EV_DETAIL_CLIP) -> str:
    """单行裁切（detail 入证据行前；压行数/防注入文本膨胀）。"""
    text = str(text).strip().replace("\n", " ")
    return text[:limit] + ("…" if len(text) > limit else "")


# ── stdout 限流（2026-10-31，owner 令「JSON 不得变成一大坨被截断」）─────────────
# 病根：`main()` 直接 `json.dumps(result, indent=2)` 全量打印。`result` 含
#   `rebase_plan.{repin,repin_range,manual}` 与 `tiers.{t0,t1,t2}`；实测漂移 200+ 时
#   单次 stdout 可达数百 KB ⟹ 终端/工具回包必被截断，**关键头部（issues/warns）反被埋掉**。
# 边界（**只改打印面，绝不改函数回包**）：`gk_anchor_rebase.py:100` 直接消费
#   `check_anchor_existence()["rebase_plan"]` ⟹ 函数级截断会造成**漏改锚**（比截断更坏）。
#   故限流只作用于深拷贝副本；`run_all` / `check_anchor_existence` 返回值逐字不变。
# 关法：`GK_DOC_ALIGN_JSON_CAP=0`（全量）。超限**显式** `_stdout_truncated`，绝不静默。
def _clip_for_stdout(result):
    """返回**打印用副本**：超长列表截到 cap 条，并附 `_stdout_truncated` 说明。"""
    try:
        cap = int(os.environ.get("GK_DOC_ALIGN_JSON_CAP", "30") or "30")
    except ValueError:
        cap = 30
    if cap <= 0 or not isinstance(result, dict):
        return result
    try:
        out = json.loads(json.dumps(result, ensure_ascii=False))
    except (TypeError, ValueError):
        return result
    cut = []

    def _cap_list(lst, label):
        if isinstance(lst, list) and len(lst) > cap:
            cut.append("%s:%d" % (label, len(lst)))
            return lst[:cap]
        return lst

    # 递归裁剪：体积大头既可能是**顶层列表**（tiers.t0），也可能是**嵌套 dict 内的列表**
    #   （实测 `checks[28].rebase_plan.repin` 146 条 / `unasserted` 340 条）。
    #   `anchors` 是「全量锚目录」人几乎不读 ⟹ 单独收窄到 5 条样例。
    _small = {"anchors": 5}

    def _trim(obj, path, depth=0):
        if depth > 5:
            return obj
        if isinstance(obj, list):
            for it in obj:                      # 递归进入 list 内的 dict（checks[*] 即此形态）
                if isinstance(it, dict):
                    _trim(it, path, depth + 1)
            return obj
        if isinstance(obj, dict):
            for k, v in list(obj.items()):
                _lim = _small.get(k, cap)
                if isinstance(v, list):
                    if len(v) > _lim:
                        cut.append("%s.%s:%d" % (path, k, len(v)) if path else "%s:%d" % (k, len(v)))
                        v = v[:_lim]
                        obj[k] = v
                    for it in v:                # 截断后继续下钻（rebase_plan.repin[0] 等）
                        if isinstance(it, dict):
                            _trim(it, "%s.%s" % (path, k) if path else k, depth + 1)
                elif isinstance(v, dict):
                    _trim(v, "%s.%s" % (path, k) if path else k, depth + 1)
            return obj
        return obj

    for k in list(out.keys()):
        if k in ("issues", "warns", "ok"):
            continue
        out[k] = _cap_list(out[k], k)
    _trim(out, "")
    if cut:
        out["_stdout_truncated"] = {
            "cap": cap, "fields": cut,
            "hint": "仅 stdout 限流；函数回包与 gk_anchor_rebase 消费面不受影响。"
                    "全量：GK_DOC_ALIGN_JSON_CAP=0",
        }
    return out


def is_eval_matrix_object(target: str = "", task: str = "", plan_path: str = "") -> bool:
    """③ 证据注入触发判定：质询对象是否为「审查层矩阵」。

    判定依据（任一命中即 True；与 e1e4-evaluator-matrix.md §2「证据注入任务模式
    规格（plan-refinement 侧）」对齐，实现与 docstring 同步维护）：
      1. target/--task 文本含标记「审查层矩阵」或「E1-E4」；
      2. 目标 plan 文件 basename == e1e4-evaluator-matrix.md（规格单源文件名）；
    若 cmd 层无法判定 → inject_preflight_evidence 的 force 布尔开关，或环境变量
    GK_EV_MATRIX_EVIDENCE=1 强制注入。确定性 0-API（纯文本判定，无网络）。
    """
    if os.environ.get("GK_EV_MATRIX_EVIDENCE") in ("1", "true", "True"):
        return True
    combined = " ".join(x for x in (target, task, plan_path) if x)
    if any(m in combined for m in _EV_MATRIX_MARKERS):
        return True
    try:
        base = Path(str(plan_path or "")).name
    except Exception:
        base = ""
    return base == _EV_MATRIX_PLAN_BASENAME


def _resolve_state_file(skill_dir: str, state_file: str) -> str:
    """state 路径解析：显式参数 → GK_STATE_FILE/STATE_FILE env → <skill_dir>/.gatekeeper.state。"""
    if state_file:
        return state_file
    env_sf = os.environ.get("GK_STATE_FILE") or os.environ.get("STATE_FILE") or ""
    return env_sf or str(Path(skill_dir) / ".gatekeeper.state")


def _read_state_safe(state_file: str):
    """读 state JSON → (dict|None, err)。文件缺失/解析失败/顶层非对象 → (None, err)。"""
    try:
        p = Path(state_file)
        if not p.exists():
            return None, f"state 文件不存在: {state_file}"
        # 2026-11-03（M1）：WAL-aware（checkpoint + `<state>.wal` replay）。
        data = read_state_file(state_file)
        if "error" in data:
            return None, f"state 读取失败: {_clip(str(data['error']), 100)}"
        if not isinstance(data, dict):
            return None, f"state 顶层非 JSON 对象: {state_file}"
        return data, ""
    except Exception as e:
        return None, f"state 读取失败: {type(e).__name__}: {_clip(str(e), 100)}"


# §5 单构建器通道参数化（2026-09-13 正解实装）：preflight 证据块只此一个构建器，
# e1e4 / standing / system 三通道为参数面而非第二构建器（"分叉=第二构建器"与 §3 单源禁双写冲突）。
# 2026-11-03：新增 "system" = 408 分析帧（references/research-408.md 四轴），
# 用于交叉审查/计划质询的"如何优化"分析；E1/E2/E4 证据与 E3 流程事实不随之替代。
_PREFLIGHT_CHANNELS = ("e1e4", "standing", "system")

# 408 四轴（确定性常量；与 references/research-408.md §一 逐轴同构，禁第二套措辞）
_RESEARCH_408_AXES = (
    ("数据结构", "选型/不变量/时间空间复杂度；先建模再选型"),
    ("计算机组成", "内存层次/写放大/fsync/原子替换/批量合并"),
    ("操作系统", "进程线程/锁粒度/死锁超时/崩溃一致性/恢复幂等"),
    ("计算机网络", "跨进程跨机才答重试/幂等/一致性；单机写 N/A"),
)
_RESEARCH_408_DISCIPLINE = "量化写放大、崩溃点显式、缓存非事实源、N/A 写出、结论可证伪"


def _research_408_lines() -> list:
    """408 分析帧证据行（确定性；advisory，不参与任何门禁）。"""
    out = ["(e) 408 分析帧（advisory；只做分析提示，不参与门禁）:"]
    for axis, question in _RESEARCH_408_AXES:
        out.append(f"- {axis}: {question}")
    out.append(f"- 纪律: {_RESEARCH_408_DISCIPLINE}")
    out.append("- 出处: references/research-408.md"
               "（帧判定单源 gk_advance.classify_research_frame）")
    return out


def _resolve_research_frame(task_text: str = "", *, target: str = "",
                            plan_path: str = "", project_type: str = "") -> str:
    """自动通道选择用：返回 408 / generic（单源 = gk_advance.classify_research_frame）。

    导入失败/判定异常 ⟹ generic（宁可不注入，也不误判为 408）。
    """
    try:
        from gk_advance import classify_research_frame
        r = classify_research_frame(task_text, project_type=project_type,
                                    target=target, plan_path=plan_path)
        return str((r or {}).get("frame") or "generic")
    except Exception:  # noqa: BLE001 — 判定不可用 ⟹ 不升级为 408
        return "generic"


def _roundlog_lines(sf: str, show_red_hits: bool) -> list:
    """(b) round-log 分量（gk_node_guard.round_log_from_gate_data 复用；两通道共享）。

    show_red_hits=False → e1e4 既有输出原样（零回归判据）；standing 恒 True。
    单源失败 → N/A 行 + 读取入口注明，不抛。
    """
    out = []
    rl_prov = "gk_node_guard.py round_log_from_gate_data"
    rl_fn = None
    try:
        from gk_node_guard import round_log_from_gate_data
        rl_fn = round_log_from_gate_data
        rl_prov = _src_ref(rl_fn, rl_prov)
    except Exception as e:
        rl_prov = f"{rl_prov}（import 失败: {_clip(str(e), 120)}）"
    out.append("(b) round-log（C5/STAGE_3：审查轮次 ≥2 + 轮间红队挖洞语义）:")
    data, err = _read_state_safe(sf)
    if rl_fn is None or err:
        why = err if err else "gk_node_guard 不可导入"
        out.append(f"- round-log: N/A（{why} — 读取入口 {rl_prov} ← state gate_data"
                   + ".subagent_history / ecc_findings source=red）")
        return out
    try:
        rl = rl_fn((data or {}).get("gate_data") or {})
        row = (f"- round-log: status={rl.get('status')} rounds={rl.get('rounds')} "
               + f"inter_red={rl.get('inter_red')}")
        if show_red_hits:
            row += f" red_hits={rl.get('red_hits')}"
        detail = _clip(rl.get("detail") or "", 120)
        if detail:
            row += f"（{detail}）"
        out.append(row + f"（出处 {rl_prov} ← state {_clip(sf, 90)} gate_data）")
    except Exception as e:
        out.append(f"- round-log: N/A（证据源异常 {type(e).__name__}: {_clip(str(e), 120)}"
                   + f" — 读取入口 {rl_prov}）")
    return out


def _build_e1e4_evidence(sdir: str, sf: str) -> list:
    """e1e4 通道分量（原 build_eval_matrix_preflight_evidence 三段，输出零回归）。"""
    lines = []
    # (a) doc-align 当前状态（本模块 run_all sibling；出处 = 各 check 函数 file:line）
    lines.append("(a) doc-align 当前状态（doc-align run_all sibling）:")
    for label, fn in (
        ("eval_matrix", check_eval_matrix),
        ("cross_review_matrix", check_cross_review_matrix),
        ("doc_freshness", check_doc_freshness),
    ):
        prov = _src_ref(fn, f"gk_doc_align.py {label}")
        try:
            r = fn(sdir)
            lines.append(f"- {label}: {r.get('status', '?')} — {_clip(r.get('detail', ''))}"
                         + f"（出处 {prov}）")
        except Exception as e:
            lines.append(f"- {label}: N/A（证据源异常 {type(e).__name__}: {_clip(str(e), 120)}"
                         + f" — 出处 {prov}）")
    lines += _roundlog_lines(sf, show_red_hits=False)
    # (c) E2 finding family=EVAL-MATRIX（绑定句登记面；读取/登记入口注明 file:line）
    lf_prov = "gk_finding.py load_findings_union"
    reg_prov = "gk_finding.py register"
    lf_ok = False
    try:
        # 读侧 union（遗漏⑤）：溢出到 finding 片的 EVAL-MATRIX finding 也算「现存」。
        from gk_finding import load_findings_union as load_findings, register
        lf_prov = _src_ref(load_findings, lf_prov)
        reg_prov = _src_ref(register, reg_prov)
        lf_ok = True
    except Exception as e:
        lf_prov = f"{lf_prov}（import 失败: {_clip(str(e), 120)}）"
    lines.append("(c) E2 finding family=EVAL-MATRIX（绑定句登记面；读取/登记入口 file:line）:")
    _, err = _read_state_safe(sf)
    if not lf_ok or err:
        lines.append(f"- E2 finding family=EVAL-MATRIX: N/A（{err if err else 'gk_finding 不可导入'}"
                     + f" — 读取入口 {lf_prov} ← state.gate_data.ecc_findings）")
        return lines
    try:
        ev = [f for f in load_findings(sf)
              if str(f.get("family") or "") == "EVAL-MATRIX"]
        if ev:
            lines.append(f"- E2 finding family=EVAL-MATRIX 现存 {len(ev)} 条"
                         + f"（读取入口 {lf_prov}；登记入口 {reg_prov} ← state.gate_data.ecc_findings）:")
            for f in ev[:5]:
                lines.append("  - [" + str(f.get("id")) + "] " + _clip(f.get("title") or "", 80)
                             + "（status=" + str(f.get("status") or "") + " source="
                             + str(f.get("source") or "") + " cover_layers="
                             + str(f.get("cover_layers") or []) + " gap="
                             + str(f.get("gap") or False) + "）")
            if len(ev) > 5:
                lines.append(f"  - … 其余 {len(ev) - 5} 条省略（共 {len(ev)} 条）")
        else:
            lines.append("- E2 finding family=EVAL-MATRIX: 现存 0 条"
                         + f"（读取入口 {lf_prov}；登记入口 {reg_prov} ← state.gate_data.ecc_findings）")
    except Exception as e:
        lines.append("- E2 finding family=EVAL-MATRIX: N/A（证据源异常 "
                     + f"{type(e).__name__}: {_clip(str(e), 120)} — 读取入口 {lf_prov}）")
    return lines


def _narrow_tasks_for_preflight(gd: dict, plan_path: str) -> tuple[list, str]:
    """窄任务清单（preflight 显示面）—— 与派发同源：sidecar 优先，其次按 plan 归属过滤。

    2026-10-21（`ECC-65986D800D26`）：原实现无条件读 `gate_data.narrow_tasks[]`（跨计划
    共享面）⟹ 新计划的质询臂在证据摘要里看到**上一份计划**的 `w2a-web-n1..n3`，属观测面
    污染。无 `plan_path`（非计划通道）⟹ 保留旧行为（全局清单）。
    """
    if not plan_path:
        return gd.get("narrow_tasks") or [], "state"
    try:
        import gk_task_gate as _G  # 单源：sidecar 读取 / 归属过滤（禁第二实现）
        stem = plan_path[:-3] if str(plan_path).endswith(".md") else str(plan_path)
        for cand in (stem + ".narrow.json", str(plan_path) + ".narrow.json"):
            if os.path.isfile(cand):
                return _G.load_narrow_tasks_file(cand), "sidecar"
        return _G.narrow_tasks_for_scope(gd.get("narrow_tasks") or [], plan_path), "state_scoped"
    except Exception as e:  # noqa: BLE001 — 证据源异常只降级并留痕，不阻断
        sys.stderr.write(f"[gk_doc_align] WARN narrow preflight: {e}\n")
        return [], "unavailable"


def _build_standing_evidence(sdir: str, sf: str, plan_path: str = "") -> list:
    """standing 通道分量（§5 最小清单 a/b/c；2026-09-13 实装）。

    (a) ember replay reconcile 意外项 + gate verdict——勘误（§17）：gk_ember_replay
        **无 "verdicts" 字段**，注入面 = reconcile.anomalies 意外项，禁编造 verdicts；
    (b) round-log 摘要（rounds/inter_red/red_hits，与 e1e4 共享 _roundlog_lines）；
    (c) 窄任务/异常回填状态（gate_data.narrow_tasks 条目 + subagent_history 尾条派发状态）。
    """
    lines = []
    # (a) ember reconcile 意外项（出处 gk_ember_replay.py resolve_ember/reconcile_ember）
    er_prov = "gk_ember_replay.py resolve_ember / reconcile_ember"
    lines.append("(a) ember replay reconcile 意外项（c8+ finding_journal 对账；无 verdicts 字段"
                 "——意外项=anomalies）:")
    try:
        from gk_ember_replay import reconcile_ember, resolve_ember
        er_prov = (_src_ref(resolve_ember, "gk_ember_replay.py resolve_ember") + " / "
                   + _src_ref(reconcile_ember, "gk_ember_replay.py reconcile_ember"))
        loc = resolve_ember(sdir)
        if not loc.get("ok"):
            lines.append(f"- ember reconcile: N/A（{loc.get('error')} — 读取入口 {er_prov}"
                         + f" ← {_clip(sdir, 90)}）")
        else:
            rec = reconcile_ember(loc["path"])
            anoms = (rec.get("reconcile") or {}).get("anomalies") or []
            verdict = (rec.get("gate") or {}).get("verdict") or rec.get("verdict") or "?"
            lines.append(f"- ember reconcile: verdict={verdict} anomalies={len(anoms)}"
                         + f"（出处 {er_prov} ← {_clip(str(loc.get('path')), 90)}）")
            for a in anoms[:5]:
                body = a.get("reason") or a.get("detail") or a.get("status") or a
                lines.append("  - [" + str(a.get("fid")) + "] " + _clip(body, 120))
            if len(anoms) > 5:
                lines.append(f"  - … 其余 {len(anoms) - 5} 条省略（共 {len(anoms)} 条）")
    except Exception as e:
        lines.append(f"- ember reconcile: N/A（证据源异常 {type(e).__name__}: "
                     + f"{_clip(str(e), 120)} — 读取入口 {er_prov}）")
    # (b) round-log（standing 版含 red_hits）
    lines += _roundlog_lines(sf, show_red_hits=True)
    # (c) 窄任务/异常回填状态
    data, err = _read_state_safe(sf)
    if err:
        lines.append("(c) 窄任务/异常回填状态（source=unavailable）:")
        lines.append(f"- narrow_tasks: N/A（{err} — 读取入口 _read_state_safe ← {sf}）")
        return lines
    gd = (data or {}).get("gate_data") or {}
    nt, _nt_src = _narrow_tasks_for_preflight(gd, plan_path)
    lines.append("(c) 窄任务/异常回填状态（source=%s；gate_data.narrow_tasks + "
                 "subagent_history 尾条派发状态）:" % _nt_src)
    if isinstance(nt, list) and nt:
        for t in nt[:5]:
            if isinstance(t, dict):
                lines.append(f"- narrow_task[{t.get('id')}]: tier={t.get('tier')}"
                             + f" task={_clip(t.get('task') or '', 60)}")
    else:
        lines.append("- narrow_tasks: 空（本计划无 sidecar/归属条目 — source=%s）" % _nt_src)
    hist = gd.get("subagent_history")
    tail = hist[-1] if isinstance(hist, list) and hist and isinstance(hist[-1], dict) else None
    if tail is not None:
        lines.append(f"- last_dispatch: role={tail.get('role')}"
                     + f" budget_status={tail.get('budget_status')}"
                     + f" total_tokens={tail.get('total_tokens')}"
                     + "（出处 state.gate_data.subagent_history[-1]）")
    else:
        lines.append("- last_dispatch: 无记录（state.gate_data.subagent_history 空）")
    return lines


def build_preflight_evidence(skill_dir: str, state_file: str = "",
                             channel: str = "e1e4", plan_path: str = "") -> str:
    """构建【preflight 证据摘要】确定性块（③；0-API；供注入方前置到质询 task 文本）。

    单构建器通道参数化（§5 正解实装 2026-09-13；2026-11-03 增 system）：channel ∈ _PREFLIGHT_CHANNELS——
      - "e1e4"：E1-E4 证据探针分量（触发面谓词 is_eval_matrix_object；输出零回归）：
          (a) doc-align 当前状态行（check_eval_matrix / cross_review_matrix / doc_freshness）；
          (b) round-log（C5/STAGE_3 轮次语义）；
          (c) E2 finding family=EVAL-MATRIX 现存条目；
      - "standing"：standing 通用质询分量（§5 最小清单，不依赖 E1-E4 触发面）：
          (a) ember replay reconcile 意外项 + gate verdict；
          (b) round-log 摘要（含 red_hits）；
          (c) 窄任务/异常回填状态；
          (d) 锚存在性/漂移；
          (e) **408 分析帧**（新增 2026-11-03，advisory）；
      - "system"：只注入 (e) 408 分析帧（交叉审查/计划质询的"如何优化"分析面）。

    分量（每行均含 file:line 出处或出处字符串，对齐 subagent_runner evidence 契约
    _EV_CONTRACT_ANCHOR）。降级语义：单源失败 → 该行 N/A + 读取入口注明（不抛异常）；
    state 缺省解析见 _resolve_state_file。非法 channel → 回退 "e1e4"（回退开关语义，
    stderr 记 WARN 不静默）。返回 str（组件恒输出，恒非空）。
    """
    if channel not in _PREFLIGHT_CHANNELS:
        sys.stderr.write(f"[gk_doc_align] WARN preflight channel={channel!r} 非法"
                         + f"（合法 {_PREFLIGHT_CHANNELS}）→ 回退 e1e4\n")
        channel = "e1e4"
    sdir = str(skill_dir)
    sf = _resolve_state_file(sdir, state_file)
    head = {
        "e1e4": "【preflight 证据摘要】对象=审查层矩阵（E1-E4）",
        "standing": "【preflight 证据摘要】通道=standing（通用质询）",
        "system": "【preflight 证据摘要】通道=system（408 分析帧）",
    }[channel]
    lines = [head + " — plan-refinement 质询 preflight 确定性 0-API 预取；"
             "证据行含 file:line 出处，契约=" + _EV_CONTRACT_ANCHOR]
    if channel == "e1e4":
        lines += _build_e1e4_evidence(sdir, sf)
    elif channel == "system":
        lines += _research_408_lines()
    else:
        lines += _build_standing_evidence(sdir, sf, plan_path)
        # (d) 锚存在性/漂移（ECC-8E0B6C408BC4；分级字段 = ECC-E98B8F59E750 单源）。
        #   质询前置此前**不含**锚检（只调 preflight-evidence）⟹ 锚漂移不可见；复用**既有**
        #   check_anchor_existence（单源，禁第二实现）。⚠ **只报 T0/T1**，不把 T2 灌进质询：
        #   T2 = 无断言 content_drift（实测占 68%）—— 无断言可核，是文档编辑的副产品而非错，
        #   灌进来只会淹没信号。分级判据**只在** check_anchor_existence 内（此处只读 `tiers`，
        #   禁再算一遍）；完整清单（含 T2）仍可由独立 `doc-align` 取得 ⟹ 非静默丢弃。
        lines.append("(d) 锚存在性/漂移（check_anchor_existence；与串行器 L6 同源）:")
        try:
            _ae = check_anchor_existence(sdir)
            _tr = _ae.get("tiers") or {}
            _cnt = _tr.get("counts") or {}
            lines.append(f"- anchor_existence: T0硬断={_cnt.get('t0', 0)}"
                         + f" T1可重钉={_cnt.get('t1', 0)}"
                         + f" anchors={_ae.get('anchors_total', 0)}"
                         + f"（出处 gk_doc_align.py check_anchor_existence ← {_clip(sdir, 90)}）")
            for _a in (_tr.get("t0") or [])[:3]:
                lines.append("  - T0 " + _clip(f"{_a.get('doc')}:{_a.get('doc_line')}"
                                               f" → {_a.get('ref')} [{_a.get('verdict')}]", 140))
        except Exception as _e:  # noqa: BLE001 — 边界：证据源异常只 N/A 不阻断
            lines.append(f"- anchor_existence: N/A（证据源异常 {type(_e).__name__}: "
                         + f"{_clip(str(_e), 120)}）")
        # (e) 408 分析帧（2026-11-03）：standing 自维护类质询默认走 408；advisory 不参与门禁。
        lines += _research_408_lines()
    return "\n".join(lines)


def inject_preflight_evidence(task_text: str, *, target: str = "", plan_path: str = "",
                              skill_dir: str | None = None, state_file: str = "",
                              force: bool = False, channel: str | None = None,
                              project_type: str = "") -> str:
    """③ 证据注入：按通道在 task 文本前注入【preflight 证据摘要】。

    通道解析（§5 单构建器参数化）：显式 channel > env GATEKEEPER_PREFLIGHT_CHANNEL
    （回退开关，F6）> **auto**（2026-11-03）。非法值 → 回退 e1e4（stderr WARN 不静默）。
      - auto 选择：project_type=standing → standing；命中 E1-E4 标记 → e1e4（显式意图优先）；
        否则 `classify_research_frame` 判 408 → system；其余 e1e4。
      - e1e4：触发 = force=True 或 is_eval_matrix_object(target, task_text, plan_path)
        命中（--task 标记「审查层矩阵」/「E1-E4」，或目标 basename = e1e4-evaluator-matrix.md）；
        未触发 → 原样返回 task_text（向后兼容：既有 plan-refinement 输出结构零改动）。
      - standing：通用质询即触发面，跳过 E1-E4 谓词恒注入（standing 证据分量 + 408 帧）。
      - system：408 分析帧（四轴）；由 auto 在系统类任务上选中，也可显式指定。
    触发 → 返回「摘要块 + 空行 + task_text」；块首含 plan-refinement 角色标记，保证
    subagent_history 200 字符截断窗口内角色/checkpoint（cmd_plan_refinement ckpt）检测
    语义不丢。证据块 = build_preflight_evidence（确定性 0-API，单源 N/A 降级）。
    skill_dir 缺省 = 本模块所在技能仓库根；state_file 解析见 _resolve_state_file。
    """
    ch = channel or os.environ.get("GATEKEEPER_PREFLIGHT_CHANNEL") or ""
    if ch and ch not in _PREFLIGHT_CHANNELS:
        sys.stderr.write(f"[gk_doc_align] WARN preflight channel={ch!r} 非法 → 回退 e1e4\n")
        ch = "e1e4"
    if not ch:
        if str(project_type or "").strip().lower() == "standing":
            ch = "standing"
        elif is_eval_matrix_object(target=target, task=task_text, plan_path=plan_path):
            ch = "e1e4"
        elif _resolve_research_frame(task_text, target=target, plan_path=plan_path,
                                    project_type=project_type) == "408":
            ch = "system"
        else:
            ch = "e1e4"
    if ch == "e1e4" and not force and not is_eval_matrix_object(target=target, task=task_text, plan_path=plan_path):
        return task_text
    sdir = skill_dir or str(Path(__file__).resolve().parent.parent)
    summary = build_preflight_evidence(sdir, state_file=state_file, channel=ch,
                                       plan_path=plan_path)
    if not summary:
        return task_text
    return summary + "\n\n" + task_text


def _preflight_evidence_cli(argv: list) -> int:
    """preflight-evidence CLI 分发面（③；gatekeeper-cli.sh cmd_plan_refinement 直调）。

    用法: python3 gk_doc_align.py preflight-evidence --task-text T [--plan-path P]
          [--target TGT] [--skill-dir D] [--state-file S] [--project-type PT] [--force]
          [--channel e1e4|standing|system]
    channel 缺省 = env GATEKEEPER_PREFLIGHT_CHANNEL > auto（2026-11-03：standing 项目 →
    standing；E1-E4 标记 → e1e4；408 帧 → system；其余 e1e4）。
    e1e4 命中触发 → stdout 打印【preflight 证据摘要】+ 原 task 文本（stdout 非空）；
    standing / system 恒触发；e1e4 未命中 → stdout 为空（bash 侧零改动向后兼容）；
    缺 --task-text → usage JSON exit 2。确定性 0-API。
    bash 侧不可 pytest，故 CLI 契约在本模块以函数 + 测试锁定。
    """
    skill_dir = str(Path(__file__).resolve().parent.parent)
    task_text = target = plan_path = state_file = ""
    channel = None
    project_type = ""
    force = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--task-text" and i + 1 < len(argv):
            task_text = argv[i + 1]
            i += 2
        elif a == "--target" and i + 1 < len(argv):
            target = argv[i + 1]
            i += 2
        elif a == "--plan-path" and i + 1 < len(argv):
            plan_path = argv[i + 1]
            i += 2
        elif a == "--skill-dir" and i + 1 < len(argv):
            skill_dir = argv[i + 1]
            i += 2
        elif a == "--state-file" and i + 1 < len(argv):
            state_file = argv[i + 1]
            i += 2
        elif a == "--channel" and i + 1 < len(argv):
            channel = argv[i + 1]
            i += 2
        elif a == "--project-type" and i + 1 < len(argv):
            project_type = argv[i + 1]
            i += 2
        elif a == "--force":
            force = True
            i += 1
        else:
            i += 1
    if not task_text:
        print(json.dumps({"ok": False, "error": "preflight-evidence 缺 --task-text"},
                         ensure_ascii=False))
        return 2
    out = inject_preflight_evidence(task_text, target=target, plan_path=plan_path,
                                    skill_dir=skill_dir, state_file=state_file,
                                    force=force, channel=channel,
                                    project_type=project_type)
    if out != task_text:
        print(out)
    return 0


if __name__ == "__main__":
    main()
