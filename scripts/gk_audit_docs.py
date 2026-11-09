#!/usr/bin/env python3
"""
gk_audit_docs.py — Document alignment audit (batch8 R-T6 Phase 4b, 2026-08-20)
==============================================================================
Migrates `cmd_audit --docs` bash heredoc (4 deterministic checks) to a
standalone Python module. 0 API calls, deterministic.

Contract (compatible with bash heredoc, same as docs/analysis/2026-08-10-audit-4to5-contract-changes.md C6):
  {"docs_checks":[{"doc":..., "check":..., "declared":..., "actual":..., "match":bool,
                   "missing":[...], "extra":[...], "error":...}],
   "summary":{"total":N, "matches":M, "failures":F}}

Checks:
  C1: cli-protocol.md — declared command count vs actual table rows
  C2: extension-registry.md — CLI 命令表 ⊇ _CMD_REG（每个已注册命令须有条目；2026-09-13 真比对）
  C3: architecture-overview.md — references/ file map vs actual files
  C4: meta-routing-protocol.md — AUDIT-*/RED-*/15-phase standing coverage

Usage:
  python3 scripts/gk_audit_docs.py [--skill-dir <dir>]
  SKILL_DIR env 亦可指定（CLI 调用时传入，避免 heredoc 硬编码 /mnt/c 路径）。

Exit codes: 0 = OK (JSON on stdout), 1 = error JSON.
2026-08-20: 迁移自 cmd_audit --docs bash heredoc (L5039-5114)。
  修复点: ① 路径参数化（原 heredoc 硬编码 <home>/.trae/...）；
  ② 持久化改由 CLI 侧 _state_write 落盘（见 cmd_audit --docs 调用处）。
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_SKILL = Path(__file__).resolve().parent.parent


def _tracked_ref_md(skill_dir: Path, ref_dir: Path) -> set:
    """references/ 下**入库**（git-tracked）的 .md 文件名集合。

    2026-10-03 修（N2b）：原用 os.listdir 枚举磁盘 ⟹ gitignored 本地产物
    （references/ecc-audit-*.md，见 .gitignore:57）也被算「实际」⟹ 任一新审计报告
    落地即判不一致（时间/环境依赖）。文件图只描述**仓库内容** ⟹ 改以 git ls-files
    为准；非 git 环境（tmp 沙箱）回退磁盘枚举，语义不变。
    """
    try:
        r = subprocess.run(["git", "-C", str(skill_dir), "ls-files", "references/"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return {p.split("/", 1)[1] for p in r.stdout.splitlines()
                    if p.startswith("references/") and "/" not in p.split("/", 1)[1]
                    and p.endswith(".md")}
    except Exception:
        pass
    return {f for f in os.listdir(ref_dir) if f.endswith(".md")}


def check_docs(skill_dir: str = str(DEFAULT_SKILL), release: bool = False) -> dict:
    """4 deterministic doc checks. Return docs_checks + summary.

    `release=True`（公开导出树内跑发布门，2026-11-09）：导出**排除面**的文档缺席是**预期**，
    相关检查降级为 `skipped`（match=True），不作为漂移。排除面判定走
    `oss_export_surface.is_excluded`（消费随包导出的白名单 JSON；`oss_scrub.py` 本身不导出）。
    """
    checks = []
    sd = Path(skill_dir)
    ref_dir = sd / "references"

    # C1: cli-protocol.md — declared command count vs _CMD_REG
    cli_path = ref_dir / "cli-protocol.md"
    try:
        cli_text = cli_path.read_text(encoding="utf-8", errors="replace")
        cmd_count_match = re.search(r"\*\*Commands\*\*:\s*(\d+)", cli_text)
        declared = int(cmd_count_match.group(1)) if cmd_count_match else 0
        actual_cmds = len(re.findall(r"^\|\s*\d+\s+\|", cli_text, re.MULTILINE))
        checks.append({"doc": "cli-protocol.md", "check": "command count",
                       "declared": declared, "actual": actual_cmds,
                       "match": declared == actual_cmds})
    except Exception as e:
        checks.append({"doc": "cli-protocol.md", "check": "read",
                       "error": str(e), "match": False})

    # C2: extension-registry.md — CLI 命令表 vs _CMD_REG（真比对，2026-09-13）
    # 原实现 `"match": True` 硬编码 ⇒ doc-align 恒 PASS 零断言（F-REV-40 空转）。
    # 契约 = 每个已注册命令（_CMD_REG 键）必须在 registry「### CLI 命令」表中有条目；
    # registry 内的额外行（planned 命令 / 内部 helper / ember-replay-audit）允许存在。
    # `cmd_<n>` 归一为 `<n>`（registry 历史用 `cmd_push` 指 push）。
    ereg_path = ref_dir / "extension-registry.md"
    cli_sh = sd / "gatekeeper-cli.sh"
    try:
        ereg_text = ereg_path.read_text(encoding="utf-8", errors="replace")
        reg_cmds = set(re.findall(r"_CMD_REG\[([a-z-]+)\]=",
                                  cli_sh.read_text(encoding="utf-8", errors="replace")))
        seg = ereg_text.split("### CLI 命令")[1].split("###")[0]
        listed = {re.sub(r"^cmd_", "", m).lower()
                  for m in re.findall(r"^\|\s*([A-Za-z_][\w.-]*)\s*\|", seg, re.MULTILINE)}
        missing = sorted(c for c in reg_cmds if c not in listed)
        checks.append({"doc": "extension-registry.md", "check": "CLI entries",
                       "declared": len(reg_cmds), "actual": len(listed),
                       "missing": missing[:10], "match": not missing})
    except Exception as e:
        checks.append({"doc": "extension-registry.md", "check": "read",
                       "error": str(e), "match": False})

    # C3: architecture-overview.md — references/ file map vs actual files
    # 2026-08-15 fix: 只取 references/ 子树段落（避开根级 SKILL.md + SKILL.md.bak 误匹配）
    arch_path = ref_dir / "architecture-overview.md"
    try:
        arch_text = arch_path.read_text(encoding="utf-8", errors="replace")
        ref_seg = arch_text.split("├── references/")[1].split("├── monitor-schemas/")[0]
        doc_files = set(re.findall(r"[\u251c\u2514]\u2500\u2500\s*([\w-]+\.md)(?=\s|$)", ref_seg))
        doc_files |= set(re.findall(r"references/([\w-]+\.md)(?=\s|$)", ref_seg))
        actual_files = _tracked_ref_md(sd, ref_dir)

        def _export_excluded(name: str) -> bool:
            """导出面排除的文档：在公开树里缺席是**预期**，不算文件地图漂移。"""
            try:
                from oss_export_surface import is_excluded as _ex
                return bool(_ex("references/" + name, str(sd)))
            except Exception:
                return False

        missing = sorted(f for f in actual_files - doc_files if not _export_excluded(f))
        extra = sorted(f for f in doc_files - actual_files if not _export_excluded(f))
        checks.append({"doc": "architecture-overview.md", "check": "file map",
                       "declared": len(doc_files), "actual": len(actual_files),
                       "match": len(missing) == 0 and len(extra) == 0,
                       "missing": missing[:10], "extra": extra[:10]})
    except Exception as e:
        checks.append({"doc": "architecture-overview.md", "check": "read",
                       "error": str(e), "match": False})

    # C4: meta-routing-protocol.md — standing plan phases coverage
    meta_path = ref_dir / "meta-routing-protocol.md"
    try:
        meta_text = meta_path.read_text(encoding="utf-8", errors="replace")
        has_audit_phases = "AUDIT-STATE" in meta_text and "AUDIT-REPORT" in meta_text
        has_red_phases = "RED-SCOPE" in meta_text and "RED-REPORT" in meta_text
        # A4（2026-10-28）：standing 4 站口径——接受规范名，旧名保留兼容存量文档
        has_standing_15 = (("ECO-RESEARCH" in meta_text or "ECO-SCAN" in meta_text)
                           and "RED-REPORT" in meta_text)
        checks.append({"doc": "meta-routing-protocol.md", "check": "AUDIT-* phases",
                       "match": has_audit_phases})
        checks.append({"doc": "meta-routing-protocol.md", "check": "RED-* phases",
                       "match": has_red_phases})
        checks.append({"doc": "meta-routing-protocol.md", "check": "15-phase standing",
                       "match": has_standing_15})
    except Exception as e:
        checks.append({"doc": "meta-routing-protocol.md", "check": "read",
                       "error": str(e), "match": False})

    # C5: bashpy-problem-taxonomy.md — 分类学结构（权威源指针/统计基线/双循环维护）
    # 2026-08-27 新增: 分类学维护任务落点批次（batch8+meta-routing）+ 统计口径确定性核验。
    taxo_path = ref_dir / "bashpy-problem-taxonomy.md"
    if release and not taxo_path.exists():
        checks.append({"doc": "bashpy-problem-taxonomy.md", "check": "taxonomy structure",
                       "match": True, "skipped": True,
                       "reason": "导出排除面（references 压缩，owner 2026-10-30）⟹ 公开树缺席是预期"})
    else:
        try:
            taxo_text = taxo_path.read_text(encoding="utf-8", errors="replace")
            has_authority = "migration-issues.md" in taxo_text and "权威源" in taxo_text
            has_baseline = all(k in taxo_text for k in ["174", "435", "RED-MIGRATE-INLINE", "RED-MIGRATE-SWALLOW", "RED-MIGRATE-DANGER", "RED-MIGRATE-FD"])
            has_dual_loop = "循环 A" in taxo_text and "循环 B" in taxo_text and "维护任务" in taxo_text
            checks.append({"doc": "bashpy-problem-taxonomy.md", "check": "taxonomy structure",
                           "match": has_authority and has_baseline and has_dual_loop,
                           "authority_pointer": has_authority, "baseline_counts": has_baseline,
                           "dual_loop_maintenance": has_dual_loop})
        except Exception as e:
            checks.append({"doc": "bashpy-problem-taxonomy.md", "check": "read",
                           "error": str(e), "match": False})

    # C6: batch8 回写（十一）↔ 评估文档 §10 登记对齐（2026-08-30 新增）
    # 用户要求"0828-0830 详细记录见评估文档几十轮记录；审计序列应可审计这些"。
    # 审计点：① 回写（十一）含指向评估文档 §10 的明确指针；② §10 段登记 bullet 条数 ≥20
    #（几十轮记录存在性，直接统计 "- **" 登记条目；2026-08-31 口径从"编号标记"改为 bullet
    #  条数——编号标记是子集：缺第 1/2/21 次编号、第 25 次无编号，bullet 实扫 37 更贴切）；
    # ③ 回写（十一）声称区间/验收数字在 §10 有锚点
    #（第十九次登记 = 区间起点 + git-workflow 安全网末条 = 区间终点 + 965 passed = 验证声明）。
    plan_doc = sd / "docs" / "plan-backup" / "2026-06-22-batch8-python-migration-plan.md"
    assess_doc = sd / "docs" / "plans" / "2026-08-28-security-hardening-assessment.md"
    if release and not (plan_doc.exists() and assess_doc.exists()):
        checks.append({"doc": "2026-06-22-batch8-python-migration-plan.md",
                       "check": "batch8 回写（十一）↔ 评估文档 §10 登记对齐",
                       "match": True, "skipped": True,
                       "reason": "docs/ 整体属导出排除面 ⟹ 公开树缺席是预期"})
    else:
        try:
            plan_text = plan_doc.read_text(encoding="utf-8", errors="replace")
            assess_text = assess_doc.read_text(encoding="utf-8", errors="replace")
            wb11 = ""
            for para in plan_text.split(">"):
                if "2026-08-30 回写（十一）" in para:
                    wb11 = para
                    break
            has_pointer = ("security-hardening-assessment.md" in wb11) and ("§10" in wb11)
            sec10_seg = assess_text.split("## §10", 1)[1].split("## §11", 1)[0]
            bullet_count = len(re.findall(r"^\- \*\*", sec10_seg, re.MULTILINE))
            register_marks = len(re.findall(r"第[一二三四五六七八九十]+次登记", sec10_seg))
            anchors = {
                "first (第19次)": "第十九次登记" in sec10_seg,
                "last (git-workflow 安全网)": "git-workflow 技能加载安全网" in sec10_seg,
                "verification (965 passed)": "965 passed" in sec10_seg,
            }
            checks.append({"doc": "2026-06-22-batch8-python-migration-plan.md",
                           "check": "batch8 回写（十一）↔ 评估文档 §10 登记对齐",
                           "pointer": has_pointer, "bullet_count": bullet_count,
                           "register_marks": register_marks,
                           "anchors": anchors,
                           "match": has_pointer and bullet_count >= 20 and all(anchors.values())})
        except Exception as e:
            checks.append({"doc": "2026-06-22-batch8-python-migration-plan.md",
                           "check": "read", "error": str(e), "match": False})

    total = len(checks)
    matches = sum(1 for c in checks if c.get("match"))
    return {"docs_checks": checks,
            "summary": {"total": total, "matches": matches, "failures": total - matches}}


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    skill_dir = os.environ.get("SKILL_DIR", str(DEFAULT_SKILL))
    if "--skill-dir" in args:
        i = args.index("--skill-dir")
        if i + 1 < len(args):
            skill_dir = args[i + 1]
    try:
        print(json.dumps(check_docs(skill_dir)))
    except Exception as e:
        print(json.dumps({"docs_checks": [], "summary": {"total": 0, "matches": 0,
                                                         "failures": 1, "error": str(e)}}))
        sys.exit(1)


if __name__ == "__main__":
    main()
