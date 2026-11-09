#!/usr/bin/env python3
"""
test_gk_c47_ext.py — C4/C6/C7 扩展测试（2026-09-06）
覆盖: C4 red_meta_scan 三态（SKIP 无 scopes / WARN registry↔scopes 嵌套=V3 越权读面 / PASS
+ 直读 scopes 启发式 01）、C6 doc_freshness 三态（PASS / FAIL 缺最近批次 ts / FAIL 缺机制登记行）。
V1/V2（A8/A7 聚合器崩溃与 sentinel 吞决）已由 C3 批既有用例覆盖（test_red_attacks 191）；
V4（doc-align 子检查器 FAIL 不 exit 0）由 test_gk_doc_align CLI 纪律用例覆盖——本文件不重复。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_self_check as gsc  # noqa: E402
from gk_doc_align import check_doc_freshness  # noqa: E402


# ─── C4: RED-META 越权读探测三态 ─────────────────────────────────────────────
def _scopes(tmp, roots=("<home>/proj-a",)):
    projs = []
    for r in roots:
        projs.append({"name": r.split("/")[-1], "state_file": r + "/.gatekeeper.state",
                      "markers": [r + "/.gitnexus"]})
    return {"governed_projects": projs}


def _registry(tmp, paths):
    return [{"name": "r" + str(i), "path": p} for i, p in enumerate(paths)]


class TestRedMetaC4:
    def test_skip_without_projects(self, tmp_path):
        sc = tmp_path / "sc.json"
        sc.write_text(json.dumps({"governed_projects": []}), encoding="utf-8")
        r = gsc.red_meta_scan(str(tmp_path), str(sc), "")
        assert r["status"] == "SKIP"

    def test_pass_clean_roots_no_nesting(self, tmp_path):
        """registry 路径与 scopes 根无交叠 + 扫描目录无 py 脚本 → PASS 无候选。"""
        sc = tmp_path / "sc.json"
        sc.write_text(json.dumps(_scopes(tmp_path)), encoding="utf-8")
        rg = tmp_path / "rg.json"
        rg.write_text(json.dumps(_registry(tmp_path, ["D:/other/proj"])), encoding="utf-8")
        # 探测目录指向无 scripts 的空 dir（隔离真实 skill 的直读点噪音）
        r = gsc.red_meta_scan(str(tmp_path), str(sc), str(rg))
        assert r["status"] == "PASS"
        assert r["findings"] == []

    def test_warn_registry_nested_into_scopes_root(self, tmp_path):
        """V3 攻击面：gitnexus registry 登记路径嵌套 scopes 租户根（A 租户读 B 根前缀）→ RED-META-02。"""
        sc = tmp_path / "sc.json"
        sc.write_text(json.dumps(_scopes(tmp_path, ["<home>/proj-a"])), encoding="utf-8")
        rg = tmp_path / "rg.json"
        # registry 路径是 scopes 根的父前缀 → 越权读面候选（#19 只见 scopes 内部，此源交叉才显性）
        rg.write_text(json.dumps(_registry(tmp_path, ["<home>"])), encoding="utf-8")
        r = gsc.red_meta_scan(str(tmp_path), str(sc), str(rg))
        assert r["status"] == "WARN"
        assert any(f["id"] == "RED-META-02" for f in r["findings"])

    def test_scope_reader_heuristic_01(self, tmp_path):
        """直读 scopes 的 py 代码点被枚举（warn/info 分级，供 L10b 核对归一单源）。"""
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "no_norm.py").write_text(
            "import json\n"
            "d = json.load(open('.gatekeeper.scopes.json'))\n"
            "root = d['governed_projects'][0]['state_file']\n"
            "if root.startswith('<home>'): pass\n", encoding="utf-8")
        (scripts / "with_norm.py").write_text(
            "from gk_self_check import _gx_norm_path\n"
            "d = json.load(open('.gatekeeper.scopes.json'))\n"
            "r = _gx_norm_path(d['state_file'])\n", encoding="utf-8")
        sc = tmp_path / "sc.json"
        sc.write_text(json.dumps(_scopes(tmp_path)), encoding="utf-8")
        rg = tmp_path / "rg.json"
        rg.write_text(json.dumps([]), encoding="utf-8")
        r = gsc.red_meta_scan(str(tmp_path), str(sc), str(rg))
        f01 = [f for f in r["findings"] if f["id"] == "RED-META-01"]
        assert len(f01) >= 2
        by_file = {f["title"].split(":")[0].replace("直读 scopes 代码点 ", ""): f for f in f01}
        assert by_file["no_norm.py"]["severity"] == "warn"   # 无归一调用 → 高嫌疑
        assert by_file["with_norm.py"]["severity"] == "info"  # 有归一单源 → 低
        assert r["status"] == "WARN"

    def test_scope_reader_info_only_passes(self, tmp_path):
        """L10b 裁决语义：仅 info 候选（文件自带归一调用）→ PASS（非越权读面）。"""
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "with_norm.py").write_text(
            "from gk_self_check import _gx_norm_path\n"
            "d = json.load(open('.gatekeeper.scopes.json'))\n"
            "r = _gx_norm_path(d['state_file'])\n", encoding="utf-8")
        sc = tmp_path / "sc.json"
        sc.write_text(json.dumps(_scopes(tmp_path)), encoding="utf-8")
        rg = tmp_path / "rg.json"
        rg.write_text(json.dumps([]), encoding="utf-8")
        r = gsc.red_meta_scan(str(tmp_path), str(sc), str(rg))
        f01 = [f for f in r["findings"] if f["id"] == "RED-META-01"]
        assert f01 and all(f["severity"] == "info" for f in f01)
        assert r["status"] == "PASS"

    def test_scope_reader_noise_masked(self, tmp_path):
        """注释/docstring/常量定义含 scopes 字样 ≠ 直读点 → 不列候选（L10b 裁决噪声类过滤）。"""
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "noise.py").write_text(
            "# 注释引用 .gatekeeper.scopes.json 说明\n"
            '"""docstring 引用 .gatekeeper.scopes.json 说明"""\n'
            'SCOPES_FILE = ".gatekeeper.scopes.json"\n'
            "x = 1\n", encoding="utf-8")
        sc = tmp_path / "sc.json"
        sc.write_text(json.dumps(_scopes(tmp_path)), encoding="utf-8")
        rg = tmp_path / "rg.json"
        rg.write_text(json.dumps([]), encoding="utf-8")
        r = gsc.red_meta_scan(str(tmp_path), str(sc), str(rg))
        assert r["status"] == "PASS"
        assert r["findings"] == []


# ─── C6: doc_freshness 三态 ──────────────────────────────────────────────────
class TestDocFreshnessC6:
    def _total(self, tmp_path, text):
        refs = tmp_path / "references"
        refs.mkdir()
        f = refs / "security-measures.md"
        f.write_text(text, encoding="utf-8")
        return f

    def test_pass_fresh_total(self, tmp_path):
        # RECENT_BATCH_TS 现为 2026-09-25（C12 hook-xenv Q3 持久化块日志+四列网表 bump）——fixture 须携带该字面量 + 四列网表节
        text = ("# T\n\n> **C12 追加（2026-09-25）**：机制登记行\n\n"
                "## 安全网四列网表（层 / 判据 / 误报率口径 / 守方）\n\n"
                "> **唯一事实源声明**：本节为四列视图唯一承载。\n\n## 参考来源\n")
        self._total(tmp_path, text)
        r = check_doc_freshness(str(tmp_path))
        assert r["status"] == "PASS"

    def test_fail_missing_four_col_view(self, tmp_path):
        """四列网表/唯一事实源声明缺失（Q3-② 新守护）=> FAIL。"""
        text = "# T\n\n> **C12 追加（2026-09-25）**：机制登记行\n\n## 参考来源\n"
        self._total(tmp_path, text)
        r = check_doc_freshness(str(tmp_path))
        assert r["status"] == "FAIL"
        assert r.get("missing_four_col_view") is True

    def test_fail_missing_batch_ts(self, tmp_path):
        """总表有登记行但缺最近批次时间戳（2026-09-05 未回流）→ FAIL（停更检出）。"""
        text = "# T\n\n> **C9 追加（2026-09-05）**：旧批次\n"
        self._total(tmp_path, text)
        r = check_doc_freshness(str(tmp_path))
        assert r["status"] == "FAIL"
        assert r.get("missing_batch_ts") is True

    def test_fail_missing_registration_line(self, tmp_path):
        text = "# T\n\n时间戳 2026-09-25 存在但无机制登记行形态。\n"
        self._total(tmp_path, text)
        r = check_doc_freshness(str(tmp_path))
        assert r["status"] == "FAIL"
        assert r.get("missing_registration_line") is True

    def test_fail_missing_total_file(self, tmp_path):
        r = check_doc_freshness(str(tmp_path))
        assert r["status"] == "FAIL"
        assert "缺失" in r["detail"]

    def test_release_mode_missing_total_is_skip(self, tmp_path):
        """发布门（release=True）：总表属导出排除面 ⟹ 公开树缺席降级 SKIP，不阻断公开包。"""
        r = check_doc_freshness(str(tmp_path), release=True)
        assert r["status"] == "SKIP"
        assert "导出排除面" in r["detail"]
