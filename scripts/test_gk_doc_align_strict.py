#!/usr/bin/env python3
"""test_gk_doc_align_strict.py — doc-align「假绿局限」回归臂（2026-10-28）

三个被消灭的局限（对应 `gk_doc_align` 的 2026-10-28 改动）：
  ① WARN 恒不阻断 ⟹ `issues=0` 可以与 152 条锚漂移 / 17 条计划漂移并存（假绿）。现 `--strict`；
  ② `sequence_node_map` 只扫 2 份固定文档、且**单向**（文档多报能查、文档少报不能查）；
     现 references/*.md 全量（表格单元口径）+ standing 反向 + monitor-schema + A4 旧站名渗透；
  ③ `comment_code_mismatch` 的检查器计数只查「声称缩水」（虚报覆盖面恒绿）；现双向判等。

为什么单独成文件：`test_gk_doc_align.py` 已 94KB，新判据独立成臂便于定位；两文件共用
同一被测模块，不引入第二实现。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))


class _Fixture:
    """最小技能目录夹具（scripts/gk_node_guard.py + references/*.md + monitor-schemas/）。"""

    NG_TEMPLATE = """
_ROUTES = {
    "standing": {"name": "x", "nodes": %(nodes)s, "loop": True},
}
_CHECKLISTS = %(checklists)s
_GATES = {}
_SAFETY = {}
%(aliases)s
"""

    def build(self, tmp_path, nodes=("ECO-RESEARCH", "ECO-DOC"), ref_texts=None,
              schemas=None, aliases_block=""):
        scripts = tmp_path / "scripts"
        scripts.mkdir(parents=True)
        checklists = "{\n" + "".join('    "%s": ["a"],\n' % n for n in nodes) + "}"
        src = self.NG_TEMPLATE % {
            "nodes": "[" + ", ".join('"%s"' % n for n in nodes) + "]",
            "checklists": checklists,
            "aliases": aliases_block,
        }
        (scripts / "gk_node_guard.py").write_text(src, encoding="utf-8")
        refs = tmp_path / "references"
        refs.mkdir(parents=True)
        for name, txt in (ref_texts or {}).items():
            (refs / name).write_text(txt, encoding="utf-8")
        if schemas is not None:
            ms = tmp_path / "monitor-schemas"
            ms.mkdir()
            for s in schemas:
                (ms / (s + ".json")).write_text("{}", encoding="utf-8")
        return str(tmp_path)


class TestSequenceNodeMapExpansion(_Fixture):
    def test_old_station_name_in_routes_warns(self, tmp_path):
        """A4 合并后 `_ROUTES` 只应出现 canonical 站名；旧名渗透必须报（旧实现完全不查）。"""
        from gk_doc_align import check_sequence_node_map
        sd = self.build(
            tmp_path, nodes=("ECO-SCAN", "ECO-READ"),
            aliases_block='ECO_ALIASES = {\n    "ECO-SCAN": "ECO-RESEARCH",\n    "ECO-READ": "ECO-RESEARCH",\n}')
        r = check_sequence_node_map(sd)
        assert r["status"] == "WARN" and "旧站名" in r["detail"], r

    def test_table_cell_claim_in_any_ref_doc(self, tmp_path):
        """扩面：任意 references/*.md 的**表格单元**里出现未注册节点 = 声明漂移。"""
        from gk_doc_align import check_sequence_node_map
        sd = self.build(tmp_path, ref_texts={
            "some-route-doc.md": "| 站 | 说明 |\n|---|---|\n| RED-GHOST | x |\n"})
        r = check_sequence_node_map(sd)
        assert r["status"] == "WARN" and "RED-GHOST" in r["detail"], r

    def test_arrow_chain_cells_are_claims(self, tmp_path):
        """`A → B` 纯节点链单元同样算声明（车站图常见形态）。"""
        from gk_doc_align import check_sequence_node_map
        sd = self.build(tmp_path, ref_texts={
            "map.md": "| 序列 | 流转 |\n|---|---|\n| standing | ECO-RESEARCH → RED-GHOST |\n"})
        r = check_sequence_node_map(sd)
        assert r["status"] == "WARN" and "RED-GHOST" in r["detail"], r

    def test_prose_check_ids_are_not_claims(self, tmp_path):
        """红队检查项 ID 出现在**行内散文**中不得误判成节点（精度臂）。"""
        from gk_doc_align import check_sequence_node_map
        sd = self.build(tmp_path, ref_texts={
            "security.md": "| 面 | 检查项 |\n|---|---|\n| 路由 | RED-ROUTE-05/07 与 RED-TAXONOMY 命中 |\n"})
        r = check_sequence_node_map(sd)
        assert r["status"] == "PASS", r

    def test_standing_missing_from_master_map_warns(self, tmp_path):
        """反向：standing 节点未出现在总路线图 = 文档滞后（旧实现单向 ⟹ 看不见）。"""
        from gk_doc_align import check_sequence_node_map
        sd = self.build(tmp_path, ref_texts={
            "meta-routing-protocol.md": "只有 ECO-RESEARCH 提到"})
        r = check_sequence_node_map(sd)
        assert r["status"] == "WARN" and "未收录 standing 节点" in r["detail"], r

    def test_standing_node_without_schema_warns(self, tmp_path):
        """standing 新站必须带 monitor-schema（A4 改名高频面）。"""
        from gk_doc_align import check_sequence_node_map
        sd = self.build(tmp_path, schemas=["ECO-RESEARCH"])   # 缺 ECO-DOC
        r = check_sequence_node_map(sd)
        assert r["status"] == "WARN" and "缺 monitor-schema" in r["detail"], r

    def test_schema_for_unregistered_node_warns(self, tmp_path):
        from gk_doc_align import check_sequence_node_map
        sd = self.build(tmp_path, schemas=["ECO-RESEARCH", "ECO-DOC", "RED-GHOST"])
        r = check_sequence_node_map(sd)
        assert r["status"] == "WARN" and "未注册节点 schema" in r["detail"], r


class TestStrictExitCode:
    def test_strict_counts_warn_as_failure(self, monkeypatch):
        import gk_doc_align as DA
        monkeypatch.setattr(DA, "run_all",
                            lambda *a, **k: {"ok": True, "issues": 0, "warns": 2, "checks": []})
        with pytest.raises(SystemExit) as e:
            DA.main(["--strict", "--summary"])
        assert e.value.code == 1

    def test_non_strict_ignores_warn(self, monkeypatch):
        import gk_doc_align as DA
        monkeypatch.setattr(DA, "run_all",
                            lambda *a, **k: {"ok": True, "issues": 0, "warns": 2, "checks": []})
        with pytest.raises(SystemExit) as e:
            DA.main(["--summary"])
        assert e.value.code == 0

    def test_run_all_reports_warns(self, monkeypatch, tmp_path):
        """`run_all` 必须回吐 warns 计数（否则 strict 无从判定）。"""
        import gk_doc_align as DA
        monkeypatch.setattr(DA, "check_papers_framework_drift",
                            lambda p: {"check": "x", "status": "WARN", "detail": ""})
        r = DA.run_all(str(tmp_path), str(tmp_path), str(tmp_path))
        assert r["warns"] >= 1
