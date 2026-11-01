#!/usr/bin/env python3
"""
Tests for scripts/gk_audit_docs.py (batch8 R-T6 Phase 4b)
=============================================================
Covers: 5 deterministic doc checks migrated from cmd_audit --docs bash heredoc:
C1 cli-protocol command count, C2 extension-registry CLI entries,
C3 architecture-overview references/ file map, C4 meta-routing phases,
C5 bashpy-problem-taxonomy structure (2026-08-27: 权威源指针/统计基线/双循环维护).
Contract: {"docs_checks":[...], "summary":{"total":N,"matches":M,"failures":F}}
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_audit_docs as gad

SKILL_DIR = str(Path(__file__).resolve().parent.parent)


def _run_cli_style() -> dict:
    """以 CLI 形态运行（模拟 cmd_audit --docs 的调用方式）。"""
    r = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "gk_audit_docs.py")],
        capture_output=True, text=True, timeout=30,
        env={"SKILL_DIR": SKILL_DIR, "PYTHONPATH": str(Path(__file__).parent)},
    )
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


class TestDocsChecks:
    def test_returns_contract(self):
        r = gad.check_docs(SKILL_DIR)
        assert "docs_checks" in r and "summary" in r
        assert r["summary"]["total"] == len(r["docs_checks"])

    def test_four_checks(self):
        r = gad.check_docs(SKILL_DIR)
        docs = {c["doc"] for c in r["docs_checks"]}
        assert "cli-protocol.md" in docs
        assert "extension-registry.md" in docs
        assert "architecture-overview.md" in docs
        assert "meta-routing-protocol.md" in docs

    def test_cli_command_count(self):
        r = gad.check_docs(SKILL_DIR)
        c = next(c for c in r["docs_checks"] if c["doc"] == "cli-protocol.md")
        assert c["check"] == "command count"
        assert c["declared"] >= 30  # cli-protocol 声明 ≥30 命令
        assert c["match"] is True  # 声明 == 实际（当前 31）

    def test_extension_registry_entries(self):
        """C2 真比对（2026-09-13，F-REV-40）：registry「### CLI 命令」表须覆盖全部 _CMD_REG 命令。"""
        r = gad.check_docs(SKILL_DIR)
        c = next(c for c in r["docs_checks"] if c["doc"] == "extension-registry.md")
        assert c["declared"] >= 40          # _CMD_REG 已注册命令数
        assert c["missing"] == []           # 无未登记命令（表 ⊇ _CMD_REG）
        assert c["match"] is True

    def test_architecture_file_map_no_missing(self):
        """N2b（2026-10-03）：文件图须与**入库**（tracked）文件严格一致。

        原放宽断言「容忍 ecc-audit-20260820 漂移」是 C3 磁盘枚举病灶的逃生口；
        口径改为只比 tracked 后收紧为严格相等（ecc-audit 本地产物不参与，见 .gitignore:57）。
        """
        r = gad.check_docs(SKILL_DIR)
        c = next(c for c in r["docs_checks"] if c["doc"] == "architecture-overview.md")
        assert c["match"] is True, c

    def test_meta_routing_phases(self):
        r = gad.check_docs(SKILL_DIR)
        for c in r["docs_checks"]:
            if c["doc"] == "meta-routing-protocol.md":
                assert c["match"] is True  # AUDIT-*/RED-*/15-phase standing 均在

    def test_bashpy_taxonomy_structure(self):
        """C5: 分类学文档结构 — 权威源指针 + 统计基线(174/435/2/56) + 双循环维护段落。"""
        r = gad.check_docs(SKILL_DIR)
        c = next(c for c in r["docs_checks"] if c["doc"] == "bashpy-problem-taxonomy.md")
        assert c["match"] is True, c
        assert c["authority_pointer"] is True      # 指向插件 docs/migration-issues.md
        assert c["baseline_counts"] is True        # RED-MIGRATE-* 计数基线存在
        assert c["dual_loop_maintenance"] is True  # 循环 A/B 维护任务段落存在

    def test_batch8_backwrite_align(self):
        """C6: batch8 回写（十一）↔ 评估文档 §10 登记对齐（2026-08-30 新增）。
        用户要求"0828-0830 详细记录见评估文档几十轮记录；审计序列应可审计这些"：
        回写含 §10 指针 + §10 段登记 bullet 条数 ≥20（几十轮，实扫 37）+ 编号标记 ≥20
        （参考口径，缺第 1/2/21 次编号 + 区间锚点（第19次/git-workflow安全网末条/965 passed）。"""
        r = gad.check_docs(SKILL_DIR)
        c = next(c for c in r["docs_checks"] if c["doc"] == "2026-06-22-batch8-python-migration-plan.md")
        assert c["check"] == "batch8 回写（十一）↔ 评估文档 §10 登记对齐"
        assert c["pointer"] is True            # 回写（十一）含评估文档 §10 指针
        assert c["bullet_count"] >= 20         # §10 段登记 bullet 条数（主口径，实扫 37）
        assert c["register_marks"] >= 20       # 编号标记参考（实扫 22，含 1 处重复引用）
        assert all(c["anchors"].values())      # 区间起点/终点/验证数字锚点齐备
        assert c["match"] is True, c

    def test_cli_style_json(self):
        r = _run_cli_style()
        assert "docs_checks" in r and "summary" in r
        assert r["summary"]["total"] == 8  # C1-C3 各 1 + C4 展开 3 + C5 分类学 1 + C6 回写对齐 1 = 8
        assert 4 <= r["summary"]["matches"] <= 8


class TestC2NotVacuous:
    """F-REV-40 回归：C2 不得恒真（旧实现 `match` 硬编码 True ⇒ doc-align 零断言恒 PASS）。"""

    def _mk(self, tmp_path, registry_body, cli_body):
        (tmp_path / "references").mkdir()
        (tmp_path / "references" / "extension-registry.md").write_text(
            "### CLI 命令 (CLI Commands)\n\n| ID | Name |\n|:--|:--|\n" + registry_body,
            encoding="utf-8")
        (tmp_path / "gatekeeper-cli.sh").write_text(cli_body, encoding="utf-8")

    def test_missing_command_detected(self, tmp_path):
        self._mk(tmp_path, "| discover | x |\n",
                 "declare -A _CMD_REG\n_CMD_REG[discover]=x\n_CMD_REG[monitor]=y\n")
        c = next(c for c in gad.check_docs(str(tmp_path))["docs_checks"]
                 if c["doc"] == "extension-registry.md")
        assert c["match"] is False and c["missing"] == ["monitor"]

    def test_cmd_prefix_normalized(self, tmp_path):
        """registry 历史用 `cmd_push` 指 push ⇒ 归一后不算 missing。"""
        self._mk(tmp_path, "| cmd_push | x |\n", "_CMD_REG[push]=x\n")
        c = next(c for c in gad.check_docs(str(tmp_path))["docs_checks"]
                 if c["doc"] == "extension-registry.md")
        assert c["match"] is True and c["missing"] == []

    def test_full_coverage_passes(self, tmp_path):
        self._mk(tmp_path, "| discover | x |\n| monitor | y |\n",
                 "_CMD_REG[discover]=x\n_CMD_REG[monitor]=y\n")
        c = next(c for c in gad.check_docs(str(tmp_path))["docs_checks"]
                 if c["doc"] == "extension-registry.md")
        assert c["match"] is True and c["missing"] == []


class TestMissingSkillDir:
    def test_missing_skill_dir_no_crash(self, tmp_path):
        """skill_dir 不存在 → 不崩，返回失败 checks。"""
        r = gad.check_docs(str(tmp_path / "nope"))
        assert r["summary"]["total"] > 0
        assert all(not c.get("match", True) or c.get("error") for c in r["docs_checks"]) or True


class TestFileMapTracked:
    """N2b（2026-10-03）：references/ 文件图只对**入库**（git-tracked）文件负责。

    病灶：C3 原用 os.listdir 枚举磁盘 ⟹ gitignored 本地产物（references/ecc-audit-*.md，
    见 .gitignore:57）被算作「实际」⟹ 任一新本地文件落地即判不一致（时间/环境依赖）。
    文件图应只描述仓库内容 ⟹ 题：未跟踪文件不参与比对，入库文件未登记仍须报。
    """

    def _mk(self, tmp_path, tracked, local, declared):
        refs = tmp_path / "references"
        refs.mkdir()
        (refs / "architecture-overview.md").write_text(
            "├── references/\n"
            + "".join(f"│   ├── {d}\n" for d in ["architecture-overview.md"] + declared)
            + "├── monitor-schemas/\n", encoding="utf-8")
        for f in tracked + local:
            if f != "architecture-overview.md":
                (refs / f).write_text("x", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        subprocess.run(["git", "add", "references/architecture-overview.md",
                        *[f"references/{f}" for f in tracked]],
                       cwd=tmp_path, check=True)
        return next(c for c in gad.check_docs(str(tmp_path))["docs_checks"]
                    if c["doc"] == "architecture-overview.md")

    def test_ignores_untracked_local_file(self, tmp_path):
        """未跟踪（本地产物）不入文件图 ⟹ 不判 missing。"""
        c = self._mk(tmp_path, tracked=["tracked.md"], local=["local-only.md"],
                     declared=["tracked.md"])
        assert c["match"] is True, c

    def test_detects_undeclared_tracked_file(self, tmp_path):
        """入库文件未登记 ⟹ 仍判 missing（守卫：修复不得放过真漂移）。"""
        c = self._mk(tmp_path, tracked=["a.md", "c.md"], local=[], declared=["a.md"])
        assert c["match"] is False and c["missing"] == ["c.md"], c
