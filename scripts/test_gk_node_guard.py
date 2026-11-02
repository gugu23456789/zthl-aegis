"""
test_gk_node_guard.py — Tests for gk_node_guard.py (序列节点安全网承载, 2026-08-27)
================================================================================
覆盖：节点注册校验 / 总运行线路 / 车站播报 / 前置产物 G 谓词 / 模板五元组 SN=⟨G,B,C,D⟩
+ 源文档磁盘解析（仓根锚定，F-REV-15）+ subagent 4 档梯度表静态断言（SUBA_TIERS，30MB 硬上限）。
"""
import ast
import datetime
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_node_guard
from gk_node_guard import node_guard, register_check, route_map, station_announcement


class TestRegister:
    """序列节点注册（修复 advance 未知节点全放行 bypass）。"""

    def test_known_eco_node(self):
        r = register_check("ECO-READ")
        assert r["ok"] is True
        assert r["node"]["route"] == "standing"
        assert r["node"]["next"] == "ECO-EDIT"

    def test_known_standard_node(self):
        r = register_check("STAGE_2")
        assert r["ok"] is True
        assert r["node"]["route"] == "standard"
        assert r["node"]["next"] == "STAGE_3"

    def test_unknown_node_blocked(self):
        r = register_check("FOO")
        assert r["ok"] is False
        assert "UNKNOWN_NODE" in r["error"]
        assert "known_routes" in r

    def test_eco_loop_wrap(self):
        """ECO-DOC 回绕 → 下一站 ECO-RESEARCH（loop=True；2026-10-28 A4：5 站并 4 站）。"""
        r = register_check("ECO-DOC")
        assert r["ok"] is True
        assert r["node"]["next"] == "ECO-RESEARCH"
        assert r["node"]["loop"] is True

    def test_standard_terminal(self):
        r = register_check("DONE")
        assert r["ok"] is True
        assert r["node"]["next"] == "(cycle complete)"

    def test_standard_full_coverage(self):
        """S11/S12（2026-09-05）：standard 全站（STAGE_0..DONE）gate/checklist/safety 实配，
        非 _node_defaults 空壳兜底；guard 接入 advance 依赖每站注册齐备。"""
        nodes = ["STAGE_0", "STAGE_1", "STAGE_2", "STAGE_3", "STAGE_4", "STAGE_5", "DONE"]
        for i, n in enumerate(nodes):
            r = register_check(n)
            assert r["ok"] is True and r["node"]["route"] == "standard"
            assert r["node"]["loop"] is False
            assert r["node"]["gate"] != "顺序门禁", f"{n} gate 落空壳兜底"
            assert r["node"]["gate"], f"{n} gate 空"
            assert r["node"]["checklist"], f"{n} checklist 空壳"
            assert r["node"]["safety"], f"{n} safety 空壳"
            nxt = nodes[i + 1] if i + 1 < len(nodes) else "(cycle complete)"
            assert r["node"]["next"] == nxt

    def test_red_engine_scan_stations(self):
        """2026-08-28 红队引擎扩展 4 站 + 2026-08-31 RED-DIFF 差分对拍站注册。"""
        r = register_check("RED-POISON")
        assert r["ok"] is True
        assert r["node"]["route"] == "red"
        assert r["node"]["next"] == "RED-REGISTRY"
        assert "audit --red poison" in " ".join(r["node"]["checklist"])
        assert register_check("RED-REGISTRY")["ok"] is True
        assert register_check("RED-GHOST")["ok"] is True
        c = register_check("RED-COVERAGE")
        assert c["ok"] is True
        assert c["node"]["next"] == "RED-DIFF"
        d = register_check("RED-DIFF")
        assert d["ok"] is True
        assert d["node"]["route"] == "red"
        assert d["node"]["next"] == "RED-INTEGRITY"
        assert "audit --red diff" in " ".join(d["node"]["checklist"])
        i = register_check("RED-INTEGRITY")
        assert i["ok"] is True
        assert i["node"]["next"] == "RED-AIG"
        assert "audit --red integrity" in " ".join(i["node"]["checklist"])
        # A9（2026-10-28）：RED-AIG 车道终站（不可信样本只在 KVM 沙箱内跑）
        a = register_check("RED-AIG")
        assert a["ok"] is True
        assert a["node"]["route"] == "red"
        assert a["node"]["next"] == "(cycle complete)"
        assert "audit --red aig" in " ".join(a["node"]["checklist"])
        assert "GK_KVM_IMAGE" in " ".join(a["node"]["checklist"])


class TestRouteMap:
    """流程总运行线路（地铁总运行路线，Phase 3.5d route_template 实装）。"""

    def test_all_routes(self):
        r = route_map()
        assert r["ok"] is True
        # 2026-10-01：新增 `zthl` 路线（zthl-adapter 计划 ZH1-ZH4；H3 开工的 advance 前置门）
        # 2026-10-12：新增 `w2a-p2` 路线（D 计划 META `phases: W2A-P2`；见 test_w2a_p2_route）
        assert set(r["routes"]) == {"standing", "standard", "red", "audit", "plugin-a", "plugin-b",
                                    "plugin-c", "zthl", "w2a-p2"}

    def test_audit_route_owner_declared(self):
        """D7-B（2026-10-27）：audit 路线登记派发归属；节点集/loop 不变。"""
        r = route_map("audit")
        assert r["ok"] is True, r
        assert r["owner"] == "skill.2026-10-04-audit-bureau-plan", r
        assert r["nodes"] == ["AUDIT-STATE", "AUDIT-MEMORY", "AUDIT-CROSSR", "AUDIT-REPORT"], r
        assert r["loop"] is False, r

    def test_route_owner_mismatch_with_hint_is_rejected(self, monkeypatch):
        """E4（2026-10-28，6 臂质询）：`owner` 必须有**读侧消费点**。

        病象：`owner` 只有产点 + `route_map` 透传，`gatekeeper-cli.sh` 全文零命中 ⟹ 装饰标签
        （与本计划判删 `offline_human` / I-1 / I-3 的标准自相矛盾）。本臂钉死消费语义：
        路线 `owner` 与其节点 hint 的 `owner` 必须一致，否则 `route_map` fail-loud。
        """
        import gk_advance as A
        monkeypatch.setitem(A._HINT_PHASES["AUDIT-STATE"], "owner", "skill.wrong-plan")
        r = route_map("audit")
        assert r["ok"] is False, r
        assert "route_owner_mismatch" in r["error"], r

    def test_route_owner_hint_without_route_owner_is_rejected(self, monkeypatch):
        """E4 反方向：节点声明了 owner 而路线没登记 ⟹ 同样拒（防半迁移）。"""
        monkeypatch.delitem(gk_node_guard._ROUTES["audit"], "owner")
        r = route_map("audit")
        assert r["ok"] is False, r
        assert "route_owner_missing" in r["error"], r

    def test_route_owner_unchecked_when_advance_unimportable(self, monkeypatch):
        """2026-10-28 质询（B3/D6 轮，5 臂共识）：`_owner_consistency` 的
        `except Exception: return ""` 是 **fail-open** —— gk_advance 不可导入时
        归属漂移会被判「一致」⟹ 装饰标签复发。改为 fail-loud（`route_owner_unchecked`）。"""
        import sys
        monkeypatch.setitem(sys.modules, "gk_advance", None)
        r = route_map("audit")
        assert r["ok"] is False, r
        assert "route_owner_unchecked" in r["error"], r

    def test_zthl_route(self):
        """2026-10-01：`zthl` 路线登记（计划 META `project_type: zthl-adapter` / `phases: ZH1..ZH4`）。

        动因（实测）：登记前 `advance ZH1` 报 `UNKNOWN_NODE: 'ZH1' 未注册`（硬阻断）⟹
        zthl-adapter 计划的相位在状态机上不可达。本臂钉死路线/节点/首末站语义。
        """
        r = route_map("zthl")
        assert r["ok"] is True
        assert r["nodes"] == ["ZH1", "ZH2", "ZH3", "ZH4"]
        assert r["loop"] is False
        assert register_check("ZH1")["ok"] is True
        assert register_check("ZH1")["node"]["next"] == "ZH2"
        assert register_check("ZH1")["node"]["prev"] == "(cycle start)"
        assert register_check("ZH4")["node"]["next"] == "(cycle complete)"
        assert "H3" in " ".join(register_check("ZH1")["node"]["checklist"])

    def test_w2a_p2_route(self):
        """2026-10-12：`w2a-p2` 路线登记（D 计划 META `phases: W2A-P2`）。

        动因（实测）：`discover --plan` 对 D 计划报 `unknown R-phase — plan declares
        phases: W2A-P2`；登记前 `advance W2A-P2` 被《序列节点安全网》`UNKNOWN_NODE` 硬阻断
        ⟹ 实验相位在状态机上不可达。本臂钉死路线/节点/首末站语义（对齐 zthl 先例）。
        """
        r = route_map("w2a-p2")
        assert r["ok"] is True
        assert r["nodes"] == ["W2A-P2"]
        assert r["loop"] is False
        assert register_check("W2A-P2")["ok"] is True
        assert register_check("W2A-P2")["node"]["next"] == "(cycle complete)"
        assert register_check("W2A-P2")["node"]["prev"] == "(cycle start)"

    def test_plugin_a_route(self):
        """2026-08-29 循环 A 插件自维护路线（ECO 双文档同步，loop 回绕）。"""
        r = route_map("plugin-a")
        assert r["ok"] is True
        assert r["nodes"] == ["ECO-SCAN-PLUGIN", "ECO-EDIT-PLUGIN", "ECO-DOC-PLUGIN"]
        assert r["loop"] is True
        assert register_check("ECO-DOC-PLUGIN")["node"]["next"] == "ECO-SCAN-PLUGIN"

    def test_plugin_b_route(self):
        """2026-08-29 循环 B 上岗执行路线（cmd_migrate 三连，终站）。"""
        r = route_map("plugin-b")
        assert r["ok"] is True
        assert r["nodes"] == ["MIGRATE-ANALYZE", "MIGRATE-VERIFY", "MIGRATE-AUDIT"]
        assert r["loop"] is False
        assert register_check("MIGRATE-AUDIT")["node"]["next"] == "(cycle complete)"

    def test_plugin_c_route(self):
        """2026-08-31 循环 C SWE-RB 上岗执行路线（swe-rb 三连，终站）。"""
        r = route_map("plugin-c")
        assert r["ok"] is True
        assert r["nodes"] == ["SRB-ANALYZE", "SRB-VERIFY", "SRB-AUDIT"]
        assert r["loop"] is False
        assert register_check("SRB-AUDIT")["node"]["next"] == "(cycle complete)"

    def test_standing_route(self):
        r = route_map("standing")
        assert r["ok"] is True
        assert r["nodes"] == ["ECO-RESEARCH", "ECO-EDIT", "ECO-VERIFY", "ECO-DOC"]
        assert r["loop"] is True

    def test_red_route_14_stations(self):
        """红队序列 16 站全链路（9 攻击/检测站 + 4 引擎扫描站 + RED-DIFF 差分对拍 + RED-INTEGRITY 完整性模式 + RED-AIG A9 KVM 沙箱车道）。"""
        r = route_map("red")
        assert r["ok"] is True
        assert r["nodes"] == ["RED-SCOPE", "RED-SURFACE", "RED-CONSTRAINTS", "RED-EXPLOIT",
                              "RED-POSTEX", "RED-REPORT", "RED-HINT", "RED-HOOK", "RED-PY",
                              "RED-POISON", "RED-REGISTRY", "RED-GHOST", "RED-COVERAGE",
                              "RED-DIFF", "RED-INTEGRITY", "RED-AIG"]
        assert r["loop"] is False

    def test_unknown_route(self):
        r = route_map("nonexistent")
        assert r["ok"] is False


class TestStation:
    """单节点车站播报（当前站 + 下一站预报 + 进入门禁 + checklist）。"""

    def test_announce_eco_edit(self):
        a = station_announcement("ECO-EDIT", "ECO-RESEARCH")
        assert a["ok"] is True
        assert a["station"] == "ECO-EDIT"
        assert a["prev"] == "ECO-RESEARCH"
        assert a["next"] == "ECO-VERIFY"
        assert "plan-refinement" in a["gate"].lower()  # ECO-RESEARCH→ECO-EDIT checkpoint 门禁
        assert a["checklist"]  # Phase 3.5d checklist 注入

    def test_announce_legacy_alias_still_works(self):
        """2026-10-28 A4：旧站名作别名仍可播报（历史 state / 既有夹具不破）。"""
        a = station_announcement("ECO-EDIT", "ECO-READ")
        assert a["ok"] is True
        assert a["next"] == "ECO-VERIFY"
        assert station_announcement("ECO-READ")["ok"] is True
        assert station_announcement("ECO-AUDIT")["ok"] is True

    def test_announce_unknown(self):
        a = station_announcement("BAR")
        assert a["ok"] is False

    def test_announce_standard_endpoints(self):
        """S11（2026-09-05）：standard 首站/终站播报实配（STAGE_0 起站、DONE 终站无下一站）。"""
        a0 = station_announcement("STAGE_0")
        assert a0["ok"] is True
        assert a0["route"] == "standard"
        assert a0["prev"] == "(cycle start)"
        assert a0["next"] == "STAGE_1"
        ad = station_announcement("DONE", "STAGE_5")
        assert ad["ok"] is True
        assert ad["prev"] == "STAGE_5"
        assert ad["next"] == "(cycle complete)"
        assert "无下一站" in " ".join(ad["checklist"])
        assert "终站" in ad["gate"]


class TestGuard:
    """前置产物 G 谓词（模板 §2 四件套：代码库地图/基线/源文档/窄任务清单）。"""

    def test_all_prereqs_ok(self, tmp_path):
        ctx_f = tmp_path / "subagent-context.json"
        ctx_f.write_text("{}", encoding="utf-8")
        (tmp_path / "subagent-context.json.sig").write_bytes(b"\x00")  # sig 实存（新鲜度谓词）
        r = node_guard("ECO-EDIT", {
            "context_file": str(ctx_f),
            "baseline_status": "current",
            "source_docs": [],   # 显式声明无缺失
            "narrow_tasks": 2,
        })
        assert r["ok"] is True

    def test_context_sig_missing_blocks(self, tmp_path):
        """代码库地图 sig 缺失（未签名注入面）→ 缺失 + 引导 context --update（A2 防存在性假绿）。"""
        ctx_f = tmp_path / "subagent-context.json"
        ctx_f.write_text("{}", encoding="utf-8")  # 无 .sig
        r = node_guard("ECO-EDIT", {
            "context_file": str(ctx_f),
            "baseline_status": "current",
            "source_docs": [],
            "narrow_tasks": 2,
        })
        assert r["ok"] is False
        assert any("代码库地图" in m and "sig_missing" in m for m in r["missing"])
        assert any("context --update" in f for f in r["fix"])

    def test_context_sig_stale_blocks(self, tmp_path, monkeypatch):
        """sig 早于 context 公钥轮换点 → 判定 stale（密钥轮换后未重签）。"""
        ctx_f = tmp_path / "subagent-context.json"
        ctx_f.write_text("{}", encoding="utf-8")
        sig_f = tmp_path / "subagent-context.json.sig"
        sig_f.write_bytes(b"\x00")
        keys = tmp_path / ".keys"
        keys.mkdir()
        pub_f = keys / "context_ed25519.pub"
        pub_f.write_bytes(b"pub")
        old = sig_f.stat().st_mtime
        import os as _os
        _os.utime(str(pub_f), (old + 10, old + 10))  # 公钥轮换晚于 sig
        monkeypatch.setattr(gk_node_guard, "_keys_dir", lambda: keys)
        r = node_guard("ECO-EDIT", {
            "context_file": str(ctx_f),
            "baseline_status": "current",
            "source_docs": [],
            "narrow_tasks": 2,
        })
        assert r["ok"] is False
        assert any("sig_stale_after_key_rotation" in m for m in r["missing"])

    def test_baseline_status_single_source(self, tmp_path):
        """baseline_status current → 齐备；stale → 需 analyze 刷新（B 单一事实源）。"""
        ctx_f = tmp_path / "ctx.json"
        ctx_f.write_text("{}", encoding="utf-8")
        (tmp_path / "ctx.json.sig").write_bytes(b"\x00")
        base = {"context_file": str(ctx_f), "baseline_status": "current",
                "source_docs": [], "narrow_tasks": 2}
        ctx = dict(base)
        ctx["baseline_status"] = "current"
        assert node_guard("ECO-EDIT", ctx)["ok"] is True
        stale = dict(base)
        stale["baseline_status"] = "stale"
        r = node_guard("ECO-EDIT", stale)
        assert r["ok"] is False
        assert any("stale" in m for m in r["missing"])
        assert any("context --update" in f for f in r["fix"])
        assert not any("analyze --embeddings" in f for f in r["fix"])
        reusable = dict(base)
        reusable["baseline_status"] = "reusable"
        assert node_guard("ECO-EDIT", reusable)["ok"] is True

    def test_missing_prereqs(self):
        r = node_guard("ECO-EDIT", {})
        assert r["ok"] is False
        # 2026-09-10 P1：source_docs 未声明 → info（不再计 missing）；其余三件套仍 fail-closed
        assert len(r["missing"]) == 3
        assert any("代码库地图" in m for m in r["missing"])
        assert any("窄任务清单" in m for m in r["missing"])
        assert any("源文档" in i for i in r["info"])

    def test_source_docs_undeclared_is_info(self, tmp_path):
        """P1（2026-09-10）：计划未声明 source_docs → info 跳过，不恒判缺/恒 BLOCK。"""
        ctx_f = tmp_path / "ctx.json"
        ctx_f.write_text("{}", encoding="utf-8")
        (tmp_path / "ctx.json.sig").write_bytes(b"\x00")
        r = node_guard("ECO-EDIT", {"context_file": str(ctx_f), "baseline_status": "current", "narrow_tasks": 2})
        assert r["ok"] is True
        assert any("源文档" in i and "未声明" in i for i in r["info"])

    def test_source_docs_missing_paths_reported(self, tmp_path):
        """P2（2026-09-10）：声明且缺失 → missing 回显具体路径（模板 §2 列缺失清单）。"""
        ctx_f = tmp_path / "ctx.json"
        ctx_f.write_text("{}", encoding="utf-8")
        (tmp_path / "ctx.json.sig").write_bytes(b"\x00")
        r = node_guard("ECO-EDIT", {"context_file": str(ctx_f), "baseline_status": "current",
                                    "source_docs": ["docs/gone-a.md", "docs/gone-b.md"],
                                    "narrow_tasks": 2})
        assert r["ok"] is False
        assert any("gone-a.md" in m and "缺失 2 项" in m for m in r["missing"])

    def test_source_docs_declared_empty_ok(self, tmp_path):
        """声明且空清单 = 齐备（契约：空 = 全部可读）。"""
        ctx_f = tmp_path / "ctx.json"
        ctx_f.write_text("{}", encoding="utf-8")
        (tmp_path / "ctx.json.sig").write_bytes(b"\x00")
        r = node_guard("ECO-EDIT", {"context_file": str(ctx_f), "baseline_status": "current",
                                    "source_docs": [], "narrow_tasks": 2})
        assert r["ok"] is True
        assert not any("源文档" in m for m in r["missing"])

    def test_unknown_node_guard(self):
        r = node_guard("XYZ", {})
        assert r["ok"] is False
        assert "node_registration" in r["missing"]

    def test_standard_stage_full_ctx_ok(self, tmp_path):
        """S12（2026-09-05）：standard 站 guard 四件套齐备 → ok=True（advance 接入 G 谓词的判定输入）。"""
        ctx_f = tmp_path / "subagent-context.json"
        ctx_f.write_text("{}", encoding="utf-8")
        (tmp_path / "subagent-context.json.sig").write_bytes(b"\x00")
        r = node_guard("STAGE_2", {
            "context_file": str(ctx_f),
            "baseline_status": "current",
            "source_docs": [],
            "narrow_tasks": 1,
        })
        assert r["ok"] is True
        assert r["node"]["route"] == "standard"
        assert r["node"]["next"] == "STAGE_3"

    def test_standard_stage_missing_ctx_fail_closed(self, tmp_path):
        """S12（2026-09-05）：standard 站 guard 前置产物缺窄任务清单 → ok=False + fix 引导（fail-closed）。"""
        ctx_f = tmp_path / "subagent-context.json"
        ctx_f.write_text("{}", encoding="utf-8")
        (tmp_path / "subagent-context.json.sig").write_bytes(b"\x00")
        r = node_guard("DONE", {"context_file": str(ctx_f), "baseline_status": "current", "source_docs": []})
        assert r["ok"] is False
        assert any("窄任务清单" in m for m in r["missing"])
        assert any("narrow_tasks" in f for f in r["fix"])

    def test_context_file_missing(self):
        """代码库地图文件不存在 → 缺失 + 引导 context --update。"""
        r = node_guard("ECO-SCAN", {"context_file": "/nonexistent/ctx.json"})
        assert r["ok"] is False
        assert any("代码库地图" in m for m in r["missing"])
        assert "context --update" in r["fix"][0]

    def test_return_contract_keys_consistent(self, tmp_path):
        """2026-09-10：三条返回路径字段齐备。

        此前未注册节点（缺 node/info/checks）与插件节点（缺 info）两条早返回路径
        JSON 契约不一致 → 消费方 `.get('info')` 取到 None。"""
        keys = {"ok", "node", "missing", "fix", "info", "checks"}
        r_unknown = node_guard("XYZ", {})
        assert keys <= set(r_unknown.keys())
        assert r_unknown["node"] is None and r_unknown["info"] == []
        ctx_f = tmp_path / "c.json"
        ctx_f.write_text("{}", encoding="utf-8")
        (tmp_path / "c.json.sig").write_bytes(b"\x00")
        r_norm = node_guard("ECO-EDIT", {"context_file": str(ctx_f), "baseline_status": "current",
                                         "narrow_tasks": 1})
        assert keys <= set(r_norm.keys())
        assert isinstance(r_norm["info"], list)


class TestMissingSourceDocs:
    """F-REV-15（2026-09-10）：source_docs 相对路径按仓根解析，而非调用方 cwd。

    缺陷形态：cmd_advance 不 cd，cwd 随调用点漂移 → 计划声明相对路径时，
    在主仓目录跑判 OK、在技能目录跑判 missing（误判缺 → P1 已修的"永久噪音 /
    GK_GUARD_STRICT=1 恒 BLOCK"陷阱复活）。
    """

    def test_relative_resolved_against_root(self, tmp_path):
        root = tmp_path / "repo"
        (root / "docs" / "plans").mkdir(parents=True)
        (root / "docs" / "plans" / "a.md").write_text("x", encoding="utf-8")
        assert gk_node_guard.missing_source_docs(["docs/plans/a.md"], str(root)) == []

    def test_relative_not_found_under_root_reported(self, tmp_path):
        root = tmp_path / "repo"
        root.mkdir()
        assert gk_node_guard.missing_source_docs(["docs/plans/nope.md"], str(root)) == ["docs/plans/nope.md"]

    def test_anchoring_ignores_caller_cwd(self, tmp_path, monkeypatch):
        """关键回归：cwd 里存在同名文件也不认——只认仓根（防 cwd 漂移误判）。"""
        root = tmp_path / "repo"
        root.mkdir()
        cwd = tmp_path / "cwd"
        (cwd / "docs" / "plans").mkdir(parents=True)
        (cwd / "docs" / "plans" / "a.md").write_text("x", encoding="utf-8")
        monkeypatch.chdir(cwd)
        assert gk_node_guard.missing_source_docs(["docs/plans/a.md"], str(root)) == ["docs/plans/a.md"]

    def test_absolute_path_verbatim(self, tmp_path):
        p = tmp_path / "abs.md"
        p.write_text("x", encoding="utf-8")
        assert gk_node_guard.missing_source_docs([str(p)], str(tmp_path / "nope")) == []
        assert gk_node_guard.missing_source_docs([str(tmp_path / "ghost.md")]) == [str(tmp_path / "ghost.md")]

    def test_empty_root_keeps_raw_behavior(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "here.md").write_text("x", encoding="utf-8")
        assert gk_node_guard.missing_source_docs(["here.md"], "") == []

    def test_blank_entries_filtered(self):
        """尾随逗号 / 空白项不产生假缺失。"""
        assert gk_node_guard.missing_source_docs(["", "  "], "") == []

    def test_cli_subcommand_merges_ctx(self, tmp_path):
        import subprocess
        root = tmp_path / "repo"
        (root / "docs").mkdir(parents=True)
        (root / "docs" / "ok.md").write_text("x", encoding="utf-8")
        out = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent / "gk_node_guard.py"), "source-docs",
             "--source-docs", "docs/ok.md,docs/miss.md", "--root", str(root),
             "--ctx", '{"narrow_tasks": 3}'],
            capture_output=True, text=True, timeout=30)
        d = json.loads(out.stdout)
        assert d["source_docs"] == ["docs/miss.md"]
        assert d["narrow_tasks"] == 3


class TestPluginGuard:
    """bashpy A/B 环插件生态节点 G 谓词（2026-08-29 实装，references/bashpy-ab-loop-safety-net.md §3）。

    对齐加载安全网 R1：测试只 patch 模块级注入点（_GET_MANIFEST/_CHECK_CAP/_LOAD_STATUS），
    不 patch 被依赖模块（gk_plugin_manifest/gk_bashpy_loader）全局。
    """

    @pytest.fixture(autouse=True)
    def _deps(self, monkeypatch):
        manifest = {"id": "bashpy-migrate", "disabled": False,
                    "intercept": ("analyze", "verify", "audit", "status", "check",
                                  "upgrade", "rollback")}
        monkeypatch.setattr(gk_node_guard, "_GET_MANIFEST", lambda pid: manifest)
        monkeypatch.setattr(gk_node_guard, "_CHECK_CAP", lambda pid, cap: {"ok": True, "capability": cap})
        monkeypatch.setattr(gk_node_guard, "_LOAD_STATUS", lambda: {"source": "dev", "version": "0.1.0-dev"})

    def test_plugin_nodes_registered(self):
        """6 个插件生态节点全部注册（route 归属正确）。"""
        for n in ("ECO-SCAN-PLUGIN", "ECO-EDIT-PLUGIN", "ECO-DOC-PLUGIN"):
            r = register_check(n)
            assert r["ok"] is True and r["node"]["route"] == "plugin-a"
        for n in ("MIGRATE-ANALYZE", "MIGRATE-VERIFY", "MIGRATE-AUDIT"):
            r = register_check(n)
            assert r["ok"] is True and r["node"]["route"] == "plugin-b"
        assert register_check("ECO-SCAN")["node"]["route"] == "standing"  # 无冲突

    def test_plugin_a_scan_all_ok(self):
        r = node_guard("ECO-SCAN-PLUGIN", {"taxonomy_ok": True, "migration_issues_ok": True})
        assert r["ok"] is True
        assert r["checks"]["manifest"] is True
        assert r["checks"]["load_status"] == "dev"
        # 2026-09-10：插件路径返回同样须含 info/node/missing/fix（契约一致）
        assert {"ok", "node", "missing", "fix", "info", "checks"} <= set(r.keys())
        assert isinstance(r["info"], list)

    def test_plugin_a_scan_missing_baseline(self):
        """循环 A 缺分类学基线/权威源 → fail-closed 阻断。"""
        r = node_guard("ECO-SCAN-PLUGIN", {})
        assert r["ok"] is False
        assert any("分类学计数基线" in m for m in r["missing"])
        assert any("migration-issues.md" in m for m in r["missing"])

    def test_plugin_a_edit_needs_plan(self):
        r = node_guard("ECO-EDIT-PLUGIN", {"taxonomy_ok": True, "migration_issues_ok": True})
        assert r["ok"] is False
        assert any("双文档收敛方案" in m for m in r["missing"])

    def test_plugin_a_doc_needs_sync(self):
        r = node_guard("ECO-DOC-PLUGIN",
                       {"taxonomy_ok": True, "migration_issues_ok": True, "doc_synced": True})
        assert r["ok"] is True

    def test_plugin_b_analyze_all_ok(self):
        r = node_guard("MIGRATE-ANALYZE", {"entry_ok": True})
        assert r["ok"] is True
        assert r["checks"]["cap"] == "analyze"

    def test_plugin_b_missing_entry(self):
        """循环 B 统一入口（hook R0.4 拦裸调用）未就绪 → 阻断。"""
        r = node_guard("MIGRATE-ANALYZE", {})
        assert r["ok"] is False
        assert any("统一入口" in m for m in r["missing"])

    def test_plugin_b_missing_cap(self, monkeypatch):
        def bad_cap(pid, cap):
            return {"ok": False, "capability": cap, "error": "not in whitelist"}
        monkeypatch.setattr(gk_node_guard, "_CHECK_CAP", bad_cap)
        r = node_guard("MIGRATE-ANALYZE", {"entry_ok": True})
        assert r["ok"] is False
        assert any("cap 白名单" in m for m in r["missing"])

    def test_plugin_b_load_missing(self, monkeypatch):
        monkeypatch.setattr(gk_node_guard, "_LOAD_STATUS", lambda: {"source": "missing"})
        r = node_guard("MIGRATE-ANALYZE", {"entry_ok": True})
        assert r["ok"] is False
        assert any("load_status=missing" in m for m in r["missing"])

    def test_plugin_b_verify_needs_analyze(self):
        r = node_guard("MIGRATE-VERIFY", {"entry_ok": True})
        assert r["ok"] is False
        assert any("analyze 产物缺失" in m for m in r["missing"])

    def test_plugin_b_audit_needs_verify(self):
        r = node_guard("MIGRATE-AUDIT", {"entry_ok": True, "analyze_ok": True})
        assert r["ok"] is False
        assert any("verify 未通过" in m for m in r["missing"])
        r2 = node_guard("MIGRATE-AUDIT", {"entry_ok": True, "analyze_ok": True, "verify_ok": True})
        assert r2["ok"] is True

    def test_plugin_manifest_disabled(self, monkeypatch):
        monkeypatch.setattr(gk_node_guard, "_GET_MANIFEST",
                            lambda pid: {"id": pid, "disabled": True})
        r = node_guard("MIGRATE-ANALYZE", {"entry_ok": True})
        assert r["ok"] is False
        assert any("管理性关闭" in m for m in r["missing"])

    def test_plugin_unknown_pid(self, monkeypatch):
        monkeypatch.setattr(gk_node_guard, "_GET_MANIFEST", lambda pid: None)
        r = node_guard("MIGRATE-ANALYZE", {"entry_ok": True})
        assert r["ok"] is False
        assert any("manifest 登记缺失" in m for m in r["missing"])

    def test_eco_general_unaffected(self):
        """回归：通用节点仍走四件套路径，插件分支不影响。"""
        r = node_guard("ECO-SCAN", {})
        assert r["ok"] is False
        assert len(r["missing"]) == 3  # 2026-09-10 P1：source_docs 未声明归 info

    def test_cli_guard_plugin_exit2(self):
        code, out = self._run("guard", "--node", "MIGRATE-ANALYZE", "--pid", "bashpy-migrate")
        assert code == 2  # 无 entry_ok → fail-closed
        assert out["pid"] == "bashpy-migrate"

    def _run(self, *argv):
        import io
        from contextlib import redirect_stdout
        old_argv = sys.argv
        sys.argv = ["gk_node_guard.py", *argv]
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                try:
                    gk_node_guard._main()
                    code = 0
                except SystemExit as e:
                    code = e.code
        finally:
            sys.argv = old_argv
        return code, json.loads(buf.getvalue())


class TestCLI:
    def _run(self, *argv):
        import io
        from contextlib import redirect_stdout
        old_argv = sys.argv
        sys.argv = ["gk_node_guard.py", *argv]
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                try:
                    gk_node_guard._main()
                    code = 0
                except SystemExit as e:
                    code = e.code
        finally:
            sys.argv = old_argv
        return code, json.loads(buf.getvalue())

    def test_cli_register_unknown_exit2(self):
        code, out = self._run("register", "--node", "FOO")
        assert code == 2
        assert out["ok"] is False

    def test_cli_announce(self):
        code, out = self._run("announce", "--node", "ECO-READ", "--current", "ECO-SCAN")
        assert code == 0
        assert out["next"] == "ECO-EDIT"

    def test_cli_route_map(self):
        code, out = self._run("route-map", "--route", "standing")
        assert code == 0
        assert out["nodes"][0] == "ECO-RESEARCH"

    def test_cli_guard_missing_exit2(self):
        code, out = self._run("guard", "--node", "ECO-EDIT")
        assert code == 2
        assert out["ok"] is False

    def test_cli_guard_eco_doc_injects_audit_all(self):
        """B3a 行为臂：CLI `guard --state-file` 注入的 audit_all 随 state 证据翻转。

        覆盖 `gk_node_guard._main` 的 state 读点（`ctx["audit_all"] = audit_all_recorded(gd)`）：
        两域齐 ⟹ missing 不含 audit --all；仅 state 域 ⟹ 必含（键缺失 ⟹ 判决翻转）。
        """
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as td:
            st = Path(td) / "s.json"
            st.write_text(json.dumps({"gate_data": {
                "audit_state_result": {"state_checks": []},
                "audit_docs_result": {"docs_checks": []}}}), encoding="utf-8")
            _, out = self._run("guard", "--node", "ECO-DOC", "--state-file", str(st))
            assert not any("audit --all 记录缺失" in m for m in out["missing"]), out
            st.write_text(json.dumps({"gate_data": {
                "audit_state_result": {"state_checks": []}}}), encoding="utf-8")
            _, out2 = self._run("guard", "--node", "ECO-DOC", "--state-file", str(st))
            assert any("audit --all 记录缺失" in m for m in out2["missing"]), out2


class TestCliAdvanceGuardWiring:
    """F-REV-13 / F-REV-16 静态接线断言：cmd_advance 的输出路径不得把 guard 摘要丢掉。

    说明：gatekeeper-cli.sh 依赖 WSL 形态（bash + /mnt 路径 + MAIN_REPO_WSL 硬编码），
    pytest 内无法可靠直跑；故按本仓既有先例（test_eco_integration 的 CLI 结构断言）做
    **定向文本断言**，锁定「只要 guard 摘要可用，每个 result 输出点都必须带上」。
    """

    CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"

    def _advance_body_lines(self):
        lines = self.CLI.read_text(encoding="utf-8", errors="replace").splitlines()
        start = next(i for i, l in enumerate(lines) if l.startswith("cmd_advance() {"))
        end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
        return lines[start:end]

    def test_rejection_path_carries_guard_summary(self):
        """F-REV-16：gk_advance 拒绝的 early return 也须注入 node_guard 摘要。"""
        lines = self._advance_body_lines()
        start = next(i for i, l in enumerate(lines)
                     if l.strip() == 'if [ "$_allowed" = "False" ] && [ "$_ok" = "False" ]; then')
        end = next(i for i in range(start + 1, len(lines)) if lines[i] == "  fi")
        branch = "\n".join(lines[start:end])
        assert "_guard_json" in branch, "拒绝路径未注入 guard 摘要（F-REV-16 回归）"
        assert "sed 's/}$//'" in branch, "拒绝路径缺少带摘要的输出分支（仅有裸兜底）"

    def test_bare_result_echo_only_as_guardless_fallback(self):
        """cmd_advance 内每处裸 `echo "$result"` 都必须处于 _guard_json 为空的兜底分支。"""
        lines = self._advance_body_lines()
        for i, line in enumerate(lines):
            if line.strip() == 'echo "$result"':
                ctx = "\n".join(lines[max(0, i - 4):i])
                assert "_guard_json" in ctx, f"裸抛 result 且无 guard 兜底判据: {line.strip()} @+{i}"

    def test_every_exit_carries_guard_or_precedes_guard_block(self):
        """全覆盖不变式：cmd_advance 内**每个** `return 1` 出口，

        要么带 guard 信息（`_guard_json` 摘要 或 `$guard_out` 全量），要么**位于 guard 块之前**
        （此时摘要尚未构建，结构性不可携带）。防"guard 块前移"后 #2/#3 静默丢摘要而测试全绿。
        """
        import re
        lines = self._advance_body_lines()
        guard_start = next(i for i, l in enumerate(lines) if l.strip().startswith("local guard_out="))
        exits = [i for i, l in enumerate(lines)
                 if re.search(r"\breturn 1\b", l) and not l.strip().startswith("#")]
        assert len(exits) >= 5, f"return 1 出口数异常偏少（{len(exits)}），cmd_advance 结构变更？"
        pre = [i for i in exits if i < guard_start]
        assert len(pre) == 3, f"guard 块前的出口数预期 3（to_stage/state/monitor），实际 {len(pre)}"
        for i in exits:
            if i < guard_start:
                continue
            ctx = "\n".join(lines[max(0, i - 15):i])
            assert ("_guard_json" in ctx or "$guard_out" in ctx), \
                f"guard 块后的出口未携带 guard 信息: {lines[i].strip()} @+{i}"


class TestSubagentTiers:
    """subagent 4 档梯度表静态断言（SUBA_TIERS 常量，30MB 总硬上限）。"""

    @pytest.fixture(scope="class")
    def tiers(self):
        # 2026-10-08（`ECC-46C8BF837715`）后 `SUBA_TIERS` 迁至 gk_suba_tiers.py；夹具须从**真家**读，
        #   原按 subagent_runner.py 的 `ast.Assign` 找 ⟹ 迁移后恒 "SUBA_TIERS not found"
        #   （`ECC-D59A6171817B`，2026-10-12 收口）。
        src = (Path(__file__).parent / "gk_suba_tiers.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        table = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == "SUBA_TIERS":
                        # 安全求值：常量算术（10*1024*1024）→ eval(compile(ast.Expression))
                        table = eval(compile(ast.Expression(node.value), "<SUBA_TIERS>", "eval"))
        assert table is not None, "SUBA_TIERS not found"
        return table

    def test_four_tiers(self, tiers):
        assert set(tiers) == {1, 2, 3, 4}

    def test_monotonic_budgets(self, tiers):
        """token/item/turns 随档位单调不减。"""
        for k in ("token_budget", "item_budget", "max_turns"):
            vals = [tiers[i][k] for i in range(1, 5)]
            assert vals == sorted(vals), f"{k} not monotonic: {vals}"

    def test_max_file_30mb(self, tiers):
        """用户指定总硬上限 30MB：tier 3/4 = 30MB，tier 1/2 更保守。"""
        assert tiers[3]["max_file_bytes"] == 30 * 1024 * 1024
        assert tiers[4]["max_file_bytes"] == 30 * 1024 * 1024
        assert tiers[1]["max_file_bytes"] < 30 * 1024 * 1024

    def test_default_tier_3_matches_current(self, tiers):
        """默认中间档（tier 3）= 2026-09-11 ×2.5 + 2026-10-03 全维 ×2 后 plan-refinement 配置 1000000/4000。"""
        assert tiers[3]["token_budget"] == 1000000
        assert tiers[3]["item_budget"] == 4000

    def test_tier_validation_exit2(self):
        """--tier 5 → UNKNOWN_TIER exit 2（无需 API）。"""
        import subprocess
        r = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "subagent_runner.py"),
             "--task", "t", "--api-base", "http://127.0.0.1:1", "--tier", "5"],
            capture_output=True, text=True, timeout=30,
        )
        assert r.returncode == 2
        assert "UNKNOWN_TIER" in r.stdout


class TestStaleTierDrift:
    """机检锚（`ECC-D59A6171817B`，2026-10-12）：`SUBA_TIERS` 迁家后的**陈旧测试漂移**。

    现象：`SUBA_TIERS` 已于 2026-10-08（`3f2807b` / `ECC-46C8BF837715`）迁至 `gk_suba_tiers.py`，
    而本文件 `TestSubagentTiers` 的夹具仍按 subagent_runner.py 的 `ast.Assign` 去找 ⟹ 恒
    `SUBA_TIERS not found`（4 errors，2026-10-12 实测）。本类钉死两处收口：
      ① 夹具须从**真家** `gk_suba_tiers.py` 读（保留原四档表结构断言，不掉覆盖）；
      ② `test_auto_context_file_found` 属位置依赖（`references/subagent-context.json` 被
         `.gitignore` 忽略 ⟹ linked worktree 天然缺失）⟹ 须进 `_accept_location_exempt.txt`，
         否则 worktree 内 accept 会把它误报为 `NEW`（`ECC-94AA4F0B3D3A`）。
    """

    def test_stale_tier_drift_fixture_reads_gk_suba_tiers(self):
        """① 夹具真家：`TestSubagentTiers` 须读 gk_suba_tiers.py，不得再读 subagent_runner.py。"""
        src = (Path(__file__).parent / "test_gk_node_guard.py").read_text(encoding="utf-8")
        head = src[src.index("class TestSubagentTiers"):src.index("def test_four_tiers")]
        assert '"gk_suba_tiers.py"' in head, \
            "夹具未指向 gk_suba_tiers.py（SUBA_TIERS 真家）；迁移后仍读旧文件 ⟹ 恒 ERROR"
        assert '"subagent_runner.py"' not in head, \
            "夹具仍读 subagent_runner.py（SUBA_TIERS 已于 2026-10-08 迁出）"

    def test_stale_tier_drift_exempt_lists_auto_context(self):
        """② 位置依赖豁免：`test_auto_context_file_found` 须在 `_accept_location_exempt.txt`。"""
        txt = (Path(__file__).parent / "_accept_location_exempt.txt").read_text(encoding="utf-8")
        assert "test_auto_context_file_found" in txt, \
            "位置依赖臂未进豁免表 ⟹ worktree 内 accept 会误报 NEW（ECC-94AA4F0B3D3A）"


class TestCronCalculator:
    """内置 cron next 计算器（替代 croniter，用户环境禁装 pip 包）。
    修复 release-check（0 9 * * *）因 croniter 缺失无法计算 next_run → job 失效。"""

    @pytest.fixture(scope="class")
    def base(self):
        import datetime
        return datetime.datetime(2026, 8, 27, 12, 0, 0)

    def test_daily_hour(self, base):
        """0 9 * * * → 次日 09:00。"""
        import cron_jobs
        n = cron_jobs._cron_next("0 9 * * *", base)
        assert n == datetime.datetime(2026, 8, 28, 9, 0, 0)

    def test_step(self, base):
        """*/15 * * * * → 12:15。"""
        import cron_jobs
        n = cron_jobs._cron_next("*/15 * * * *", base)
        assert n.minute == 15 and n.hour == 12

    def test_weekday(self, base):
        """0 9 * * 1（周一）→ 下一个周一 09:00。"""
        import cron_jobs
        n = cron_jobs._cron_next("0 9 * * 1", base)
        assert n.weekday() == 0  # Monday
        assert n.hour == 9

    def test_specific_minute_today(self, base):
        """30 12 * * * → 当日 12:30。"""
        import cron_jobs
        n = cron_jobs._cron_next("30 12 * * *", base)
        assert n == datetime.datetime(2026, 8, 27, 12, 30, 0)

    def test_compute_next_run_cron_kind(self, base):
        """compute_next_run 对 kind=cron 走内置计算器（不再依赖 croniter）。"""
        import cron_jobs
        n = cron_jobs.compute_next_run({"kind": "cron", "expr": "0 9 * * *"}, base_time=base)
        assert n is not None
        assert n == datetime.datetime(2026, 8, 28, 9, 0, 0)

    def test_invalid_expr(self, base):
        """非法表达式 → None（不抛异常）。"""
        import cron_jobs
        assert cron_jobs._cron_next("bad expr", base) is None
        assert cron_jobs._cron_next("0 9 * *", base) is None  # 4 字段
        assert cron_jobs._cron_next("0 99 * * *", base) is None  # 越界


class TestCronErrorStateRecovery:
    """F-REV-94（2026-09-17，用户裁定「其他都同意」）：`state=error` **不是终态**。

    原 `get_due_jobs` 只认 `state == "scheduled"` ⟹ 一旦置 error（唯一置 error 的路径 =
    "schedule not computable"）就**永不恢复**，即便根因早已消除 —— 上一类
    `TestCronCalculator` 已证明内置计算器能算 `0 9 * * *`，但 job 仍躺在 error 里。

    实测背景：`release-check`（`0 9 * * *`）自 2026-08-23 起恒 `state=error`、`next_run_at`
    冻在 `2026-08-22T09:00:00Z`，`tick.log` 每小时**静默跳过** ⟹ 外循环长期未触发（I7 失效）。

    ⚠ 本类**红先** —— 修复前 `test_error_job_becomes_due_and_self_heals` 必失败。
    """

    @pytest.fixture
    def iso(self, tmp_path, monkeypatch):
        """把 `cron_jobs` 的存储面整体重定向到 tmp —— **绝不触碰真 `~/.gatekeeper/cron`**。

        ⚠ `JOBS_FILE` / `JOBS_DIR` / `OUTPUT_DIR` 是**导入期**常量 ⟹ 必须 monkeypatch 模块属性
        （仅设环境变量对本进程无效）。

        2026-09-20：sidecar 路径已由导入期常量 `_JOBS_CHECKSUM_FILE` 改为函数派生
        `_jobs_checksum_file()`（返回 `JOBS_FILE + ".sha256"`）⟹ 改 `JOBS_FILE` 一处即可，
        无需（也不能）再 monkeypatch sidecar 路径。
        """
        import cron_jobs
        jobs_file = tmp_path / "jobs.json"
        monkeypatch.setattr(cron_jobs, "JOBS_FILE", str(jobs_file))
        monkeypatch.setattr(cron_jobs, "JOBS_DIR", str(tmp_path))
        monkeypatch.setattr(cron_jobs, "OUTPUT_DIR", str(tmp_path / "output"))
        assert cron_jobs._jobs_checksum_file() == str(jobs_file) + ".sha256"
        return cron_jobs, jobs_file

    @staticmethod
    def _job(**over):
        j = {
            "id": "dc937f2f4905", "name": "release-check", "prompt": "run release-check",
            "schedule": {"kind": "cron", "expr": "0 9 * * *"},
            "next_run_at": "2026-08-22T09:00:00Z",  # 远在过去（实测值）
            "enabled": True, "state": "error",
            "last_error": "next run not computable (croniter missing? run: pip install croniter)",
        }
        j.update(over)
        return j

    def _write(self, jobs_file, job):
        import json
        with open(jobs_file, "w") as f:
            json.dump([job], f)

    def test_error_job_becomes_due_and_self_heals(self, iso):
        """error + next_run_at 在过去 ⟹ 必须回到 due，并按 A1 追赶语义 fast-forward + 自愈。"""
        cron_jobs, jobs_file = iso
        self._write(jobs_file, self._job())
        due = cron_jobs.get_due_jobs()
        assert [j["id"] for j in due] == ["dc937f2f4905"], "error 态被永久跳过（终态陷阱复现）"
        saved = cron_jobs.load_jobs()[0]
        assert saved["state"] == "scheduled", "fast-forward 成功后未自愈回 scheduled"
        assert saved["last_error"] == "", "自愈后未清空陈旧的 last_error"
        assert saved["next_run_at"] > "2026-09-01", f"未 fast-forward 到未来: {saved['next_run_at']}"

    def test_missing_next_run_at_self_heals(self, iso):
        """error + next_run_at 缺失 ⟹ 算出下一轮并自愈（原路径同为终态陷阱）。"""
        cron_jobs, jobs_file = iso
        self._write(jobs_file, self._job(next_run_at=None))
        cron_jobs.get_due_jobs()
        saved = cron_jobs.load_jobs()[0]
        assert saved["state"] == "scheduled"
        assert saved["last_error"] == ""
        assert saved["next_run_at"] is not None

    def test_completed_and_paused_stay_dead(self, iso):
        """终态守卫：`completed` / `paused` 是用户/设计意图的终态，**不得复活**（防越权放行）。"""
        cron_jobs, jobs_file = iso
        for st in ("completed", "paused"):
            self._write(jobs_file, self._job(state=st, enabled=True))
            assert cron_jobs.get_due_jobs() == [], f"{st} 被复活（越权）"

    def test_bad_expr_still_errors_without_croniter_hint(self, iso):
        """非法表达式：仍须置 error，但文案**不得**诱导装 croniter（用户环境禁装 pip 包）。"""
        cron_jobs, jobs_file = iso
        self._write(jobs_file, self._job(next_run_at=None,
                                         schedule={"kind": "cron", "expr": "not a cron"}))
        cron_jobs.get_due_jobs()
        saved = cron_jobs.load_jobs()[0]
        assert saved["state"] == "error"
        assert "croniter" not in (saved.get("last_error") or "")


class TestL9CliInjection:
    """L9 深检实装（2026-09-01）：CLI 编排注入 ctx（正本清源——agent 不再自证）。"""

    def test_auto_context_file_found(self):
        """技能目录 subagent-context.json 实存 → 非空路径（代码库地图注入）。"""
        cf = gk_node_guard._auto_context_file()
        assert cf.endswith("subagent-context.json")
        assert Path(cf).exists()

    def test_auto_baseline_existence_fallback_removed(self):
        """F-REV-76：存在性兜底注入端 `_auto_baseline` 已删（.gitnexus 实存不再等价于基线 OK）。"""
        assert not hasattr(gk_node_guard, "_auto_baseline")

    def test_baseline_status_required_fail_closed(self):
        """F-REV-76：baseline_status 未注入且无显式 baseline 声明 → 判缺（不再存在性兜底）。"""
        r = gk_node_guard.node_guard("ECO-EDIT", {})
        assert r["ok"] is False
        assert any("baseline_status 未注入" in m for m in r["missing"])
        assert any("node-guard" in f and "context --update" not in f for f in r["fix"])

    def test_baseline_status_unavailable_blocks(self):
        """F-REV-76：status=unavailable（未索引/不可用）→ 判缺，不再靠 .gitnexus 实存过门。

        四态白名单口径：仅 current|reusable 齐备，stale|unavailable 判缺（`baseline`(bool) 兜底已废除）。
        """
        r = gk_node_guard.node_guard("ECO-EDIT",
                                     {"baseline_status": "unavailable"})
        assert r["ok"] is False
        assert any("unavailable" in m for m in r["missing"])

    def test_guard_ctx_auto_fill(self, tmp_path, monkeypatch):
        """guard CLI 调用时 context_file 由 CLI 自动注入（缺省也能补）；baseline 不再自动补。"""
        import gk_node_guard as ng
        # 构造最小 state（narrow_tasks 空 + 无 ctx）
        state = tmp_path / "s.json"
        state.write_text('{"gate_data": {"narrow_tasks": []}}', encoding="utf-8")
        monkeypatch.setattr(ng, "_auto_context_file", lambda: str(tmp_path / "x.json"))
        r = ng.node_guard("ECO-EDIT", {})
        # 2026-09-10 P1：source_docs 未注入 → info（不再计 missing）；narrow_tasks 仍 fail-closed
        assert r["ok"] is False
        missing = " ".join(r["missing"])
        assert "窄任务" in missing
        # F-REV-76：baseline_status 未注入 → 亦判缺（存在性兜底已撤销）
        assert "baseline_status 未注入" in missing
        assert any("源文档" in i for i in r["info"])


class TestRoundLogC5:
    """C5（2026-09-06）：STAGE_3 首项 round-log 门禁（≥2 轮审查 + 轮间红队挖洞）。"""

    @staticmethod
    def _gd(reviews=0, red_acts=0, ecc_red=0):
        hist = [{"task": "crossrev: L1-L10 交叉审查 轮 1 — stage-3-review"} for _ in range(reviews)]
        hist += [{"task": "redteam: 红队挖洞 X"} for _ in range(red_acts)]
        findings = [{"id": "R-1", "source": "red", "status": "open"}] * ecc_red
        return {"subagent_history": hist, "ecc_findings": findings}

    def _full_ctx(self, tmp_path, round_log):
        cf = tmp_path / "subagent-context.json"
        cf.write_text("{}", encoding="utf-8")
        (tmp_path / "subagent-context.json.sig").write_bytes(b"\x00")
        return {"context_file": str(cf), "baseline_status": "current", "source_docs": [],
                "narrow_tasks": 2, "round_log": round_log}

    def test_ready_two_rounds_plus_red(self, tmp_path):
        rl = gk_node_guard.round_log_from_gate_data(self._gd(reviews=2, red_acts=1))
        assert rl["status"] == "ready" and rl["rounds"] == 2 and rl["inter_red"] is True
        r = node_guard("STAGE_4", self._full_ctx(tmp_path, rl))
        assert r["ok"] is True
        assert r["checks"]["round_log"]["status"] == "ready"

    def test_pending_single_round(self, tmp_path):
        rl = gk_node_guard.round_log_from_gate_data(self._gd(reviews=1, red_acts=1))
        assert rl["status"] == "pending" and "审查轮次" in rl["detail"]
        r = node_guard("STAGE_4", self._full_ctx(tmp_path, rl))
        assert r["ok"] is False
        assert any("round-log 未齐" in m and "审查轮次=1" in m for m in r["missing"])

    def test_pending_no_inter_red(self, tmp_path):
        """2 轮但无红队挖洞（轮间扩展缺）→ pending 阻断（一轮了事 + 无挖洞双缺）。"""
        rl = gk_node_guard.round_log_from_gate_data(self._gd(reviews=2, red_acts=0))
        assert rl["status"] == "pending" and "红队" in rl["detail"]
        r = node_guard("STAGE_4", self._full_ctx(tmp_path, rl))
        assert r["ok"] is False
        assert any("红队" in m for m in r["missing"])

    def test_ecc_red_finding_counts_as_inter(self, tmp_path):
        """轮间扩展证据含 ecc_findings source=red（红队产出，非仅 subagent task）。"""
        rl = gk_node_guard.round_log_from_gate_data(self._gd(reviews=2, ecc_red=1))
        assert rl["status"] == "ready" and rl["red_hits"] >= 1
        r = node_guard("STAGE_4", self._full_ctx(tmp_path, rl))
        assert r["ok"] is True

    def test_stage4_without_round_log_blocks(self, tmp_path):
        """guard CLI 缺 state 注入 → round_log 未注入 → 保守阻断（非静默放行）。"""
        cf = tmp_path / "c.json"; cf.write_text("{}", encoding="utf-8")
        (tmp_path / "c.json.sig").write_bytes(b"\x00")
        r = node_guard("STAGE_4", {"context_file": str(cf), "baseline_status": "current",
                                   "source_docs": [], "narrow_tasks": 2})
        assert r["ok"] is False
        assert any("round-log 未齐" in m and "未注入" in m for m in r["missing"])

    def test_other_nodes_untouched(self, tmp_path):
        """非 STAGE_4 节点不触发 round-log 判定（无 round missing）。"""
        rl = gk_node_guard.round_log_from_gate_data(self._gd(reviews=0, red_acts=0))
        ctx = self._full_ctx(tmp_path, rl)
        r = node_guard("STAGE_2", ctx)
        assert r["ok"] is True  # 四件套齐 → ok；round-log 只挂在 STAGE_4
        assert not any("round-log" in m for m in r["missing"])
        # round_log_from_gate_data 空数据 → pending（detail 双缺）
        assert rl["status"] == "pending"


class TestReviewExitGateP0:
    """P0 ledger（2026-09-07 b1g，㊴/㊵ 收敛缺省）：审查节点出口完整性谓词。

    review_exit_gate(node, gd) —— STAGE_4 只查 round-log（C5 语义），ECO-DOC 叠 audit --all。
    """

    @staticmethod
    def _gd(reviews=0, red_acts=0, audit_state=False, audit_docs=False):
        hist = [{"task": "plan-refinement: 质询 X"} for _ in range(reviews)]
        hist += [{"task": "redteam: 红队挖洞"} for _ in range(red_acts)]
        gd = {"subagent_history": hist}
        if audit_state:
            gd["audit_state_result"] = {"state_checks": [], "audit_summary": {}}
        if audit_docs:
            gd["audit_docs_result"] = {"docs_checks": [], "summary": {}}
        return gd

    def test_stage4_ready_requires_rounds_red(self):
        """STAGE_4：round-log 齐 → ok；round 缺 → missing（无 audit_all 维度）。"""
        r = gk_node_guard.review_exit_gate("STAGE_4", self._gd(reviews=2, red_acts=1))
        assert r["ok"] is True and r["status"] == "ready"
        assert r["audit_all"] is None  # STAGE_4 不判 audit_all
        r2 = gk_node_guard.review_exit_gate("STAGE_4", self._gd(reviews=1, red_acts=1))
        assert r2["ok"] is False and any("审查 ledger 未齐" in m for m in r2["missing"])

    def test_eco_doc_ready_rounds_red_and_audit_all(self):
        """ECO-DOC：round-log 齐 + **有生产者的两域**证据同时落盘（E2，2026-10-28 收紧 all-of）。"""
        gd = self._gd(reviews=2, red_acts=1, audit_state=True, audit_docs=True)
        r = gk_node_guard.review_exit_gate("ECO-DOC", gd)
        assert r["ok"] is True and r["status"] == "ready"
        assert r["audit_all"] is True

    def test_eco_doc_pending_when_only_state_domain(self):
        """E2 负臂（红先）：只落 `audit_state_result` 一域不再算「audit --all 记录」。"""
        gd = self._gd(reviews=2, red_acts=1, audit_state=True)
        r = gk_node_guard.review_exit_gate("ECO-DOC", gd)
        assert r["ok"] is False
        assert r["audit_all"] is False

    def test_eco_doc_pending_when_no_audit_all(self):
        """ECO-DOC：round-log 齐但无 audit --all 记录 → pending（audit_all missing）。"""
        gd = self._gd(reviews=2, red_acts=1)
        r = gk_node_guard.review_exit_gate("ECO-DOC", gd)
        assert r["ok"] is False
        assert any("audit --all 记录缺失" in m for m in r["missing"])
        assert r["audit_all"] is False

    def test_eco_doc_pending_no_rounds_no_audit(self):
        """ECO-DOC：空 state（跳过审查直接出站）→ pending 双缺（round + audit）。"""
        r = gk_node_guard.review_exit_gate("ECO-DOC", {})
        assert r["ok"] is False
        assert len(r["missing"]) == 2
        assert any("audit --all 记录缺失" in m for m in r["missing"])

    def test_node_guard_eco_doc_injects_round_log_audit(self, tmp_path):
        """node_guard("ECO-DOC")：CLI state 注入 round_log+audit_all 后按 P0 判定。"""
        cf = tmp_path / "c.json"; cf.write_text("{}", encoding="utf-8")
        (tmp_path / "c.json.sig").write_bytes(b"\x00")
        # round-log 齐 + audit 落盘 → ok（四件套齐前提）
        gd = self._gd(reviews=2, red_acts=1, audit_docs=True)
        ctx = {"context_file": str(cf), "baseline_status": "current", "source_docs": [],
               "narrow_tasks": 2, "round_log": gk_node_guard.round_log_from_gate_data(gd),
               "audit_all": True}
        r = node_guard("ECO-DOC", ctx)
        assert r["ok"] is True
        # 缺 audit_all → missing 含 audit --all
        ctx2 = dict(ctx, audit_all=False)
        r2 = node_guard("ECO-DOC", ctx2)
        assert r2["ok"] is False
        assert any("audit --all 记录缺失" in m for m in r2["missing"])


class TestEcoCanonAliasSchema:
    """A4（2026-10-28）：standing 只留 4 站规范 schema；旧站名靠单源别名回退。

    纪律：**禁**为别名站再造一份 schema（第二事实源 ⟹ 改一处漂移另一处）。
    """

    MONITOR = Path(__file__).parent.parent / "monitor-schemas"

    def test_canon_cli_resolves_alias(self):
        import subprocess
        r = subprocess.run([sys.executable, str(Path(__file__).parent / "gk_node_guard.py"),
                            "canon", "--node", "ECO-AUDIT"],
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        assert json.loads(r.stdout)["canon"] == "ECO-VERIFY"

    def test_canon_cli_passes_through_known_station(self):
        import subprocess
        r = subprocess.run([sys.executable, str(Path(__file__).parent / "gk_node_guard.py"),
                            "canon", "--node", "ECO-EDIT"],
                           capture_output=True, text=True, timeout=30)
        assert json.loads(r.stdout)["canon"] == "ECO-EDIT"

    def test_standing_schemas_are_canonical_only(self):
        names = sorted(p.stem for p in self.MONITOR.glob("ECO-*.json"))
        assert names == ["ECO-DOC", "ECO-EDIT", "ECO-RESEARCH", "ECO-VERIFY"]

    def test_every_alias_resolves_to_existing_schema(self):
        for alias, canon in gk_node_guard.ECO_ALIASES.items():
            assert not (self.MONITOR / f"{alias}.json").exists(), alias
            assert (self.MONITOR / f"{canon}.json").exists(), canon


