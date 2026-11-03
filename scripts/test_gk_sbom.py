#!/usr/bin/env python3
"""`gk_sbom.py` 机检臂（2026-11-03，发布链 B 档）。

守三点：
  ① 声明依赖 → CycloneDX components（purl/version），重复声明去重；
  ② 无依赖 ⟹ components 为空 + `zthl:runtime-dependencies=stdlib-only`（不伪造）；
  ③ 确定性：同输入逐字节相同（serialNumber 由内容派生、无墙钟）。
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_sbom as S  # noqa: E402


def _tree(tmp, req=None, pkg=None):
    t = tmp / "tree"
    t.mkdir()
    if req is not None:
        (t / "requirements.txt").write_text(req, encoding="utf-8")
    if pkg is not None:
        (t / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    return t


def test_requirements_become_components(tmp_path):
    t = _tree(tmp_path, req="# deps\npyyaml==6.0.2\npytest\n")
    bom = S.build(str(t), "v1")
    by = {c["name"]: c for c in bom["components"]}
    assert by["pyyaml"]["version"] == "6.0.2"
    assert by["pyyaml"]["purl"] == "pkg:pypi/pyyaml@6.0.2"
    assert "version" not in by["pytest"] and by["pytest"]["purl"] == "pkg:pypi/pytest"
    assert bom["metadata"]["properties"][0]["value"] == "declared"
    assert bom["specVersion"] == "1.5" and bom["bomFormat"] == "CycloneDX"


def test_stdlib_only_is_explicit(tmp_path):
    t = _tree(tmp_path)
    bom = S.build(str(t), "v1")
    assert bom["components"] == []
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["zthl:runtime-dependencies"] == "stdlib-only"
    assert bom["dependencies"][0]["dependsOn"] == []


def test_dedup_and_npm(tmp_path):
    t = _tree(tmp_path, req="pyyaml==6.0.2\npyyaml==6.0.2\n",
              pkg={"dependencies": {"left-pad": "^1.3.0"}})
    bom = S.build(str(t), "v1")
    purls = [c["purl"] for c in bom["components"]]
    assert purls.count("pkg:pypi/pyyaml@6.0.2") == 1
    assert "pkg:npm/left-pad@1.3.0" in purls


def test_deterministic_and_zip_hash(tmp_path):
    t = _tree(tmp_path, req="pyyaml==6.0.2\n")
    a = S.build(str(t), "v1", "a" * 64)
    b = S.build(str(t), "v1", "a" * 64)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["metadata"]["component"]["hashes"][0]["content"] == "a" * 64
    assert a["serialNumber"].startswith("urn:uuid:")


def test_cli_writes_file(tmp_path):
    t = _tree(tmp_path, req="pytest\n")
    out = tmp_path / "dist" / "SBOM.cdx.json"
    assert S.main(["--tree", str(t), "--version", "v1", "--out", str(out)]) == 0
    got = json.loads(out.read_text(encoding="utf-8"))
    assert got["metadata"]["component"]["version"] == "v1"
