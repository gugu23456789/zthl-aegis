#!/usr/bin/env python3
"""test_gk_list_registry.py — 裁决面清单登记表机检（2026-11-09）。

守三件事：
  ① 登记表与源码同步（跑生成器 --check，漂移即红）；
  ② 字段完整 / id 唯一 / kind 合法；
  ③ 高风险清单不被静默移除（按 (file, symbol) 硬钉子集）。
不做的：全仓「未登记即失败」反向扫描 —— 那会再造一份人工白名单。
"""
import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent
ROOT = SCRIPT.parent
REG = ROOT / "references" / "list-registry.json"
KINDS = {"allowlist", "denylist", "exemption", "baseline", "registry"}


def _data() -> dict:
    return json.loads(REG.read_text(encoding="utf-8"))


class TestListRegistry:
    def test_registry_in_sync(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPT / "gk_list_registry.py"), "--check"],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert r.returncode == 0, (r.stdout or "") + (r.stderr or "")

    def test_schema(self):
        d = _data()
        assert d.get("_generated") is True
        assert d.get("_generator") == "scripts/gk_list_registry.py"
        assert d.get("schema") == 1
        ids = [e["id"] for e in d["entries"]]
        assert len(ids) == len(set(ids)), "id 必须唯一"
        for e in d["entries"]:
            for k in ("id", "kind", "file", "symbol", "failure_mode"):
                assert e.get(k) not in (None, ""), f"{e.get('id')}: {k} 为空"
            assert isinstance(e["referenced_by"], list), f"{e['id']}: referenced_by 非列表"
            assert e["kind"] in KINDS, f"{e['id']}: kind={e['kind']!r}"
            assert isinstance(e["exported"], bool)

    def test_high_risk_present(self):
        keys = {(e["file"], e["symbol"]) for e in _data()["entries"]}
        required = {
            ("scripts/gk_route_center.py", "DEV_WORKTREE_ROOTS"),
            ("scripts/gk_state_route.py", "DEV_WORKTREE_ROOTS"),
            ("scripts/gk_route_center.py", "SEARCH_DIRS"),
            ("scripts/gk_route_center.py", "WORKTREE_ROUTES"),
            ("scripts/gk_role_regions.py", "ROLE_ALLOWED_REGIONS"),
            ("scripts/gk_public_bridge.py", "REMOTE_ALLOW"),
            ("scripts/pre_tool_hook.py", "MCP_EGRESS_ALLOWLIST"),
            ("scripts/gk_evidence.py", "PRIOR_ART_HOSTS"),
            ("scripts/gk_monitor_api.py", "ALLOWED_BASES"),
            ("scripts/pre_tool_hook.py", "_TRUST_ROOT_SCRIPTS"),
            ("scripts/gk_self_check.py", "_EXEMPT8"),
            ("scripts/gk_state_patch.py", "_TOP_DENY"),
            ("references/oss-export-whitelist.json", "<file>"),
            ("references/meta-routing-protocol.md", "## 路由白名单基线"),
        }
        missing = sorted(required - keys)
        assert not missing, f"高风险清单未登记: {missing}"

    def test_consumer_files_exist(self):
        for e in _data()["entries"]:
            for rel in e["referenced_by"]:
                assert (ROOT / rel).exists(), f"{e['id']}: referenced_by 不存在 {rel}"
