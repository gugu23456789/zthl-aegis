#!/usr/bin/env python3
"""R14/R16 机械对齐门的红先/回归用例。"""
import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_sdk_gate_align as G  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "schema" / "gk-sdk-1.json"
CLI = ROOT / "gatekeeper-cli.sh"


@pytest.fixture()
def manifest():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_real_manifest_passes(manifest):
    r = G.check(manifest, CLI)
    assert r["ok"], r["errors"]
    assert r["verbs"] == 4


def test_execute_tier_rejected(manifest):
    m = copy.deepcopy(manifest)
    m["verbs"]["state.get"]["tier"] = "execute"
    r = G.check(m, CLI)
    assert not r["ok"]
    assert any("execute 禁止" in e for e in r["errors"])


def test_gated_cli_rejected(manifest):
    m = copy.deepcopy(manifest)
    m["verbs"]["plan.lint"]["x-cli"] = "advance"   # full gate + state_write
    r = G.check(m, CLI)
    assert not r["ok"]
    assert any("gate_level" in e for e in r["errors"])


def test_unregistered_cli_rejected(manifest):
    m = copy.deepcopy(manifest)
    m["verbs"]["state.get"]["x-cli"] = "no-such-cmd"
    r = G.check(m, CLI)
    assert not r["ok"]
    assert any("不在 _CMD_REG" in e for e in r["errors"])


def test_missing_registry_requires_sdk_readonly(manifest):
    m = copy.deepcopy(manifest)
    m["verbs"]["repo_index.check"]["x-audit"] = "registry"
    r = G.check(m, CLI)
    assert not r["ok"]
    assert any("sdk-readonly" in e for e in r["errors"])


def test_readonly_subcommand_whitelist_only_for_list(manifest):
    m = copy.deepcopy(manifest)
    m["verbs"]["finding.list"]["x-audit"] = "registry"
    r = G.check(m, CLI)
    assert not r["ok"]
    assert any("side_effects" in e for e in r["errors"])
