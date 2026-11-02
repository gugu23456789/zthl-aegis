"""test_gk_ci_security_lint.py — workflow 供应链/权限静态门。"""
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("yaml")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ROOT = Path(__file__).resolve().parent.parent
SHA = "a" * 40


def _good():
    return {
        "name": "ci",
        "on": ["push"],
        "permissions": {"contents": "read"},
        "jobs": {
            "smoke": {
                "runs-on": "ubuntu-24.04",
                "timeout-minutes": 10,
                "steps": [
                    {"uses": "actions/checkout@" + SHA,
                     "with": {"persist-credentials": False}},
                    {"run": "echo ok"},
                ],
            },
        },
    }


def test_good_workflow_passes():
    import gk_ci_security_lint as L
    r = L.lint_doc("ci.yml", _good())
    assert r["ok"] and not r["issues"], r


def test_missing_permissions_fails():
    import gk_ci_security_lint as L
    d = _good(); d.pop("permissions")
    assert any("permissions" in i["error"] for i in L.lint_doc("ci.yml", d)["issues"])


def test_unpinned_uses_fails():
    import gk_ci_security_lint as L
    d = _good(); d["jobs"]["smoke"]["steps"][0]["uses"] = "actions/checkout@v4"
    assert any("未钉" in i["error"] for i in L.lint_doc("ci.yml", d)["issues"])


def test_checkout_persist_credentials_fails():
    import gk_ci_security_lint as L
    d = _good(); d["jobs"]["smoke"]["steps"][0]["with"] = {"persist-credentials": True}
    assert any("persist-credentials" in i["error"] for i in L.lint_doc("ci.yml", d)["issues"])


def test_missing_timeout_fails():
    import gk_ci_security_lint as L
    d = _good(); d["jobs"]["smoke"].pop("timeout-minutes")
    assert any("timeout-minutes" in i["error"] for i in L.lint_doc("ci.yml", d)["issues"])


def test_run_template_injection_fails():
    import gk_ci_security_lint as L
    d = _good(); d["jobs"]["smoke"]["steps"][1]["run"] = 'echo "${{ inputs.plan }}"'
    assert any("模板注入" in i["error"] or "run" in i["error"]
               for i in L.lint_doc("ci.yml", d)["issues"])


def test_security_job_continue_on_error_fails():
    import gk_ci_security_lint as L
    d = _good(); d["jobs"]["security-audit"] = {
        "runs-on": "ubuntu-24.04", "timeout-minutes": 10,
        "continue-on-error": True, "steps": [{"run": "echo ok"}]}
    assert any("continue-on-error" in i["error"] for i in L.lint_doc("ci.yml", d)["issues"])


def test_release_attestation_warns_and_passes_with_permissions():
    import gk_ci_security_lint as L
    d = {
        "name": "release", "on": ["push"], "permissions": {"contents": "read"},
        "jobs": {"release": {
            "runs-on": "ubuntu-24.04", "timeout-minutes": 10,
            "permissions": {"contents": "write", "id-token": "write", "attestations": "write"},
            "steps": [
                {"uses": "actions/checkout@" + SHA,
                 "with": {"persist-credentials": False}},
                {"uses": "actions/attest-build-provenance@" + SHA,
                 "with": {"subject-path": "dist/*.zip"}},
            ]}},
    }
    r = L.lint_doc("release.yml", d)
    assert r["ok"], r
    assert not r["warnings"], r


def test_repo_workflows_pass():
    import gk_ci_security_lint as L
    r = L.check(ROOT / ".github" / "workflows")
    assert r["ok"] and not r["warnings"], r
