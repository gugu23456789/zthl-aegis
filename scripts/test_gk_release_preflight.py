#!/usr/bin/env python3
"""`gk_release_preflight.py` 的机检臂（2026-11-04）。

守什么：
  ① workflow ↔ `pack_release.py` 的**参数契约**（历史事故：workflow 传 --source-*，
     脚本不认 ⟹ v0.9.6.8–v0.9.6.10 连续三版发版 CI 在 pack 步退出 2）；
  ② 发布资产必须是 7 个（5 核心 + 2 基准）；
  ③ 夹具打包必须产出 zip / SHA256SUMS / manifest / PROVENANCE 四件套。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_release_preflight as PF  # noqa: E402


def test_pack_contract_detects_flag_not_in_parser():
    wf = "run: |\n  python scripts/pack_release.py --tree . --bogus-flag x\n"
    r = PF.pack_contract(wf)
    assert r["status"] == "FAIL", r
    assert "--bogus-flag" in r["detail"], r


def test_pack_contract_accepts_real_workflow():
    wf = PF.WORKFLOW.read_text(encoding="utf-8")
    r = PF.pack_contract(wf)
    assert r["status"] == "PASS", r


def test_release_assets_requires_seven():
    base = "\n".join([
        'run: |',
        '  gh release create "$VERSION" --verify-tag \\',
        '    "dist/zthl-aegis-$VERSION.zip" \\',
        '    "dist/SHA256SUMS" \\',
        '    "dist/PROVENANCE.json" \\',
        '    "dist/SBOM.cdx.json" \\',
        '    "dist/release-manifest.json"',
    ])
    r = PF.release_assets(base)
    assert r["status"] == "FAIL", r
    assert "dist/bench/release.json" in r["detail"], r

    full = base + "\n" + "\n".join([
        '  for f in dist/bench/release.json dist/bench/release-compare.json; do',
        '    [ -f "$f" ] && ASSETS+=("$f")',
        '  done',
    ])
    assert PF.release_assets(full)["status"] == "PASS"


def test_release_assets_real_workflow_is_pass():
    wf = PF.WORKFLOW.read_text(encoding="utf-8")
    r = PF.release_assets(wf)
    assert r["status"] == "PASS", r


def test_pack_fixture_produces_four_pieces():
    r = PF.pack_fixture()
    assert r["status"] == "PASS", r
