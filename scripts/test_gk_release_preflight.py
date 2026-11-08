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


# ── 随包 wheel 三件套（2026-11-05）───────────────────────────────────────────

def test_vendor_artifact_real_tree_ok():
    r = PF.vendor_artifact()
    assert r["status"] == "PASS", r


def test_vendor_artifact_missing_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(PF, "_VENDOR", tmp_path / "nope")
    assert PF.vendor_artifact()["status"] == "FAIL"


def test_vendor_artifact_hash_mismatch(tmp_path, monkeypatch):
    d = tmp_path / "v"
    d.mkdir()
    w = d / "zthl_bashpy_migrate-9.9.9-py3-none-any.whl"
    w.write_bytes(b"x")
    (d / "SHA256SUMS").write_text("%s  %s\n" % ("0" * 64, w.name), encoding="utf-8")
    (d / "PROVENANCE.json").write_text(
        json.dumps({"version": "9.9.9", "artifact": w.name, "sha256": "0" * 64}),
        encoding="utf-8")
    monkeypatch.setattr(PF, "_VENDOR", d)
    r = PF.vendor_artifact()
    assert r["status"] == "FAIL" and "SHA256" in r["detail"]


# ── 2026-11-08：发布前性能门（第 9 项）────────────────────────────────────────
def test_bench_gate_skips_without_git(tmp_path, monkeypatch):
    """导出树（无 .git）⟹ SKIP（基线不可定位），不误判红。"""
    monkeypatch.setattr(PF, "ROOT", tmp_path)
    r = PF.bench_regression()
    assert r["status"] == "SKIP" and ".git" in r["detail"], r


def test_bench_gate_skips_on_opt_out(monkeypatch):
    monkeypatch.setenv("GK_PREFLIGHT_BENCH", "0")
    assert PF.bench_regression()["status"] == "SKIP"


def test_bench_gate_fails_on_true_regression(tmp_path, monkeypatch):
    """真回归（机制未变 + 口径一致 + 超阈）⟹ FAIL（唯一判红分支）。"""
    (tmp_path / ".git").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "references").mkdir()
    (tmp_path / "references" / "bench-baseline.json").write_text(json.dumps({
        "schema": "gk-bench-baseline/v1", "git_head": "deadbeef",
        "benchmarks": {"state": {
            "scenarios": [{"scenario": "s", "write_amp": 1.0, "p99_ms": 10.0,
                           "success_ops": 10, "total_ops": 10}],
            "crash": [{"trial": 1, "checksum_ok": True, "tmp_left": 0}], "ok": True}}}),
        encoding="utf-8")
    (tmp_path / "scripts" / "gk_bench_state.py").write_text(
        "import json;print(json.dumps({'ok': True, 'scenarios': ["
        "{'scenario': 's', 'write_amp': 9.0, 'p99_ms': 90.0, 'success_ops': 10,"
        " 'total_ops': 10}], 'crash': [{'trial': 1, 'checksum_ok': True, 'tmp_left': 0}]}))\n",
        encoding="utf-8")
    monkeypatch.setattr(PF, "ROOT", tmp_path)
    import gk_bench_compare as BC
    orig = BC._changed_since
    try:
        BC._changed_since = lambda h, repo=".": []
        r = PF.bench_regression()
    finally:
        BC._changed_since = orig
    assert r["status"] == "FAIL" and "真回归" in r["detail"], r
