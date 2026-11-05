#!/usr/bin/env python3
"""`gk_release_preflight.py` 的机检臂（2026-11-04）。

守什么：
  ① workflow ↔ `pack_release.py` 的**参数契约**（历史事故：workflow 传 --source-*，
     脚本不认 ⟹ v0.9.6.8–v0.9.6.10 连续三版发版 CI 在 pack 步退出 2）；
  ② 发布资产必须是 7 个（5 核心 + 2 基准）；
  ③ 夹具打包必须产出 zip / SHA256SUMS / manifest / PROVENANCE 四件套。
"""
import json
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


# ── workflow_paths：导出面一致性（2026-11-05）────────────────────────────────
def _wf_tree(tmp_path, monkeypatch, run_body: str, allow: list = None):
    wfdir = tmp_path / ".github" / "workflows"
    wfdir.mkdir(parents=True)
    (wfdir / "ci.yml").write_text("jobs:\n  a:\n    steps:\n      - name: x\n"
                                  "        run: |\n" + run_body, encoding="utf-8")
    ci = tmp_path / "references" / "ci-external-paths.json"
    ci.parent.mkdir(parents=True, exist_ok=True)
    ci.write_text(json.dumps({"schema": "gk-ci-external-paths/1",
                              "paths": allow or []}), encoding="utf-8")
    monkeypatch.setattr(PF, "ROOT", tmp_path)
    monkeypatch.setattr(PF, "_WORKFLOW_DIR", wfdir)
    monkeypatch.setattr(PF, "_CI_EXTERNAL", ci)


def test_workflow_paths_flags_missing_unregistered(tmp_path, monkeypatch):
    _wf_tree(tmp_path, monkeypatch, "          python scripts/nope.py\n")
    r = PF.workflow_paths()
    assert r["status"] == "FAIL" and "scripts/nope.py" in r["detail"], r


def test_workflow_paths_accepts_existing_and_registered(tmp_path, monkeypatch):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "ok.py").write_text("print(1)\n", encoding="utf-8")
    _wf_tree(tmp_path, monkeypatch,
             "          python scripts/ok.py\n          python docs/x/gone.json\n",
             allow=[{"glob": "docs/x/*.json", "reason": "导出排除面"}])
    r = PF.workflow_paths()
    assert r["status"] == "PASS", r


def test_workflow_paths_flags_stale_allowlist(tmp_path, monkeypatch):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "ok.py").write_text("print(1)\n", encoding="utf-8")
    _wf_tree(tmp_path, monkeypatch, "          python scripts/ok.py\n",
             allow=[{"glob": "docs/x/*.json", "reason": "已无引用"}])
    r = PF.workflow_paths()
    assert r["status"] == "FAIL" and "过期" in r["detail"], r


def test_workflow_paths_requires_reason(tmp_path, monkeypatch):
    _wf_tree(tmp_path, monkeypatch, "          python docs/x/gone.json\n",
             allow=[{"glob": "docs/x/*.json"}])
    r = PF.workflow_paths()
    assert r["status"] == "FAIL" and "reason" in r["detail"], r


def test_run_blocks_skips_comments():
    text = ("# 说明里提到 references/ghost.md 但不在 run 块\n"
            "jobs:\n  a:\n    steps:\n      - run: echo hi >/dev/null\n")
    blocks = PF._run_blocks(text)
    assert blocks and all("references/ghost.md" not in b for b in blocks)


def test_repo_index_real_tree_is_fresh():
    """仓库里的 FILES.md / llms.txt 必须与公开面一致（移动端入口不漂移）。"""
    r = PF.repo_index_check()
    assert r["status"] == "PASS", r
