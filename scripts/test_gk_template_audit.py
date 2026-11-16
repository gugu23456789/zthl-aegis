"""test_gk_template_audit.py — 模板登记表统一审计的安全网（2026-11-11）。

红先形态：本模块与 `references/template-registries.json` 落刀前均不存在 ⟹ ImportError/FileNotFoundError。
回归面 = 真仓两张表自洽 + 四类漂移（表/消费方/文档/回环）逐项可判 + 清单级重复可判。
"""
import json
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

import gk_template_audit as ta  # noqa: E402

_ROOT = _HERE.parent


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _fixture(tmp: Path, *, items=None, kind="fill", consumer_mention=True,
             doc_mention=True) -> Path:
    items = items if items is not None else [
        {"id": "t1", "keywords": ["k"], "desc": "d", "when": "w",
         "placeholders": ["{x}"], "body": "# {x}"}]
    _write(tmp / "references" / "foo-templates.json",
           json.dumps({"templates": items}, ensure_ascii=False))
    _write(tmp / "scripts" / "gen.py",
           "REG = 'foo-templates.json'\n" if consumer_mention else "X = 1\n")
    _write(tmp / "scripts" / "gate.sh", "#!/bin/bash\n")
    _write(tmp / "docs" / "foo.md",
           "# foo\n\nfoo-templates.json\n" if doc_mention else "# foo\n")
    man = {"version": 1, "kinds": list(ta.KINDS), "registries": [{
        "id": "foo", "kind": kind, "path": "references/foo-templates.json",
        "items_key": "templates", "consumer": "scripts/gen.py", "doc": "docs/foo.md",
        "post_gate": "scripts/gate.sh", "required_top": ["templates"],
        "required_fields": ["id", "keywords", "desc", "when", "placeholders", "body"],
        "placeholders_from_body": True}]}
    _write(tmp / "references" / "template-registries.json",
           json.dumps(man, ensure_ascii=False))
    return tmp


def _manifest(tmp: Path) -> dict:
    return json.loads((tmp / "references" / "template-registries.json").read_text(encoding="utf-8"))


def _save_manifest(tmp: Path, man: dict):
    _write(tmp / "references" / "template-registries.json",
           json.dumps(man, ensure_ascii=False))


def _issues(res):
    assert res["registries"], res
    out = set()
    for r in res["registries"]:
        out.update(r["issues"])
    return out


# ── 真仓 ────────────────────────────────────────────────────
def test_real_repo_registries_pass():
    res = ta.audit(str(_ROOT))
    assert res["status"] == "PASS", res.get("detail")
    ids = {r["id"] for r in res["registries"]}
    assert {"red-arm", "comment", "ci-checklist", "wasm-checklist"} <= ids


def test_manifest_lists_only_known_kinds():
    man = json.loads((_ROOT / "references" / "template-registries.json").read_text(encoding="utf-8"))
    for r in man["registries"]:
        assert r["kind"] in ta.KINDS


# ── fixture 正向 ─────────────────────────────────────────────
def test_valid_fixture_passes(tmp_path):
    res = ta.audit(str(_fixture(tmp_path)))
    assert res["status"] == "PASS", res.get("detail")


# ── 四类漂移 ────────────────────────────────────────────────
def test_missing_registry_file(tmp_path):
    _fixture(tmp_path)
    (tmp_path / "references" / "foo-templates.json").unlink()
    res = ta.audit(str(tmp_path))
    assert res["status"] == "FAIL"
    assert any(i.startswith("MISSING_FILE:path=") for i in _issues(res))


def test_placeholder_drift(tmp_path):
    bad = [{"id": "t1", "keywords": ["k"], "desc": "d", "when": "w",
            "placeholders": ["{x}", "{y}"], "body": "# {x}"}]
    res = ta.audit(str(_fixture(tmp_path, items=bad)))
    assert "PLACEHOLDER_DRIFT@t1" in _issues(res)


def test_consumer_not_wired(tmp_path):
    res = ta.audit(str(_fixture(tmp_path, consumer_mention=False)))
    assert any(i.startswith("CONSUMER_NOT_WIRED:") for i in _issues(res))


def test_doc_not_mention(tmp_path):
    res = ta.audit(str(_fixture(tmp_path, doc_mention=False)))
    assert any(i.startswith("DOC_NOT_MENTION:") for i in _issues(res))


def test_post_gate_missing(tmp_path):
    _fixture(tmp_path)
    (tmp_path / "scripts" / "gate.sh").unlink()
    res = ta.audit(str(tmp_path))
    assert any(i.startswith("MISSING_FILE:post_gate=") for i in _issues(res))


# ── 表自洽 ──────────────────────────────────────────────────
def test_bad_kind(tmp_path):
    res = ta.audit(str(_fixture(tmp_path, kind="renderer")))
    assert any(i.startswith("BAD_KIND:") for i in _issues(res))


def test_duplicate_id(tmp_path):
    items = [
        {"id": "t1", "keywords": ["k"], "desc": "d", "when": "w",
         "placeholders": ["{x}"], "body": "# {x}"},
        {"id": "t1", "keywords": ["k2"], "desc": "d2", "when": "w2",
         "placeholders": ["{x}"], "body": "# {x}"},
    ]
    res = ta.audit(str(_fixture(tmp_path, items=items)))
    assert any(i.startswith("DUP_ID:") for i in _issues(res))


def test_missing_required_field(tmp_path):
    items = [{"id": "t1", "keywords": [], "desc": "d", "when": "w",
              "placeholders": ["{x}"], "body": "# {x}"}]
    res = ta.audit(str(_fixture(tmp_path, items=items)))
    assert "ITEM_MISSING:keywords@t1" in _issues(res)


def test_duplicate_path(tmp_path):
    _fixture(tmp_path)
    man = _manifest(tmp_path)
    second = dict(man["registries"][0])
    second.update({"id": "foo2", "doc": "docs/foo.md"})
    man["registries"].append(second)
    _save_manifest(tmp_path, man)
    res = ta.audit(str(tmp_path))
    assert res["status"] == "FAIL"
    assert any(i.startswith("DUP_PATH:") for i in _issues(res))


def test_missing_manifest(tmp_path):
    res = ta.audit(str(tmp_path))
    assert res["status"] == "FAIL" and "template-registries.json" in res["detail"]


# ── CLI ─────────────────────────────────────────────────────
def test_cli_check_and_list(tmp_path, capsys):
    sd = _fixture(tmp_path)
    assert ta.main(["check", "--skill-dir", str(sd)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "PASS"
    assert ta.main(["list", "--skill-dir", str(sd)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True and out["registries"][0]["id"] == "foo"
    assert ta.main(["bogus"]) == 2


# ── checklist ───────────────────────────────────────────────
def _checklist_fixture(tmp: Path, *, items=None) -> Path:
    items = items if items is not None else [
        {"id": "must", "desc": "必须出现", "pattern": "set -euo pipefail",
         "level": "ERROR", "mode": "present"},
        {"id": "forbid", "desc": "禁止出现", "pattern": "--closure 1",
         "level": "ERROR", "mode": "absent"},
    ]
    _write(tmp / "references" / "chk.json",
           json.dumps({"target_glob": "*.yml", "items": items}, ensure_ascii=False))
    _write(tmp / "scripts" / "gate.sh", "#!/bin/bash\n")
    _write(tmp / "scripts" / "gk_template_audit.py", "# stub: 泛化消费方实存即可\n")
    _write(tmp / "docs" / "chk.md", "# chk\n\nchk.json\n")
    man = {"version": 1, "kinds": list(ta.KINDS), "registries": [{
        "id": "chk", "kind": "checklist", "path": "references/chk.json",
        "items_key": "items", "consumer": "scripts/gk_template_audit.py",
        "doc": "docs/chk.md", "post_gate": "scripts/gk_template_audit.py",
        "required_top": ["target_glob", "items"],
        "required_fields": ["id", "desc", "pattern", "level"],
        "placeholders_from_body": False}]}
    _write(tmp / "references" / "template-registries.json",
           json.dumps(man, ensure_ascii=False))
    return tmp


def test_checklist_fixture_passes(tmp_path):
    res = ta.audit(str(_checklist_fixture(tmp_path)))
    assert res["status"] == "PASS", res.get("detail")


def test_checklist_bad_regex_and_level(tmp_path):
    bad = [{"id": "x", "desc": "d", "pattern": "[", "level": "FATAL", "mode": "present"}]
    res = ta.audit(str(_checklist_fixture(tmp_path, items=bad)))
    iss = _issues(res)
    assert any(i.startswith("BAD_REGEX@x") for i in iss)
    assert any(i.startswith("BAD_LEVEL:") for i in iss)


def test_checklist_apply_present_and_absent(tmp_path):
    sd = _checklist_fixture(tmp_path / "skill")
    root = tmp_path / "target"
    _write(root / "ci.yml", "set -euo pipefail\n")
    res = ta.apply_checklist(str(sd), "chk", str(root))
    assert res["status"] == "PASS" and res["summary"]["ERROR"] == 0 and res["files"] == 1


def test_checklist_apply_violations(tmp_path):
    sd = _checklist_fixture(tmp_path / "skill")
    root = tmp_path / "target"
    _write(root / "ci.yml", "--closure 1\n")
    res = ta.apply_checklist(str(sd), "chk", str(root))
    assert res["status"] == "FAIL" and res["summary"]["ERROR"] == 2


def test_checklist_apply_warn_only_passes(tmp_path):
    items = [{"id": "w", "desc": "d", "pattern": "concurrency:", "level": "WARN",
              "mode": "present"}]
    sd = _checklist_fixture(tmp_path / "skill", items=items)
    root = tmp_path / "target"
    _write(root / "ci.yml", "x\n")
    res = ta.apply_checklist(str(sd), "chk", str(root))
    assert res["status"] == "PASS" and res["summary"]["WARN"] == 1


def test_apply_unknown_id_loud(tmp_path):
    sd = _checklist_fixture(tmp_path)
    with pytest.raises(ValueError):
        ta.apply_checklist(str(sd), "nope", str(tmp_path))


def test_cli_apply(tmp_path):
    sd = _checklist_fixture(tmp_path / "skill")
    root = tmp_path / "target"
    _write(root / "ci.yml", "set -euo pipefail\n")
    assert ta.main(["apply", "--skill-dir", str(sd), "--id", "chk", "--root", str(root)]) == 0
    assert ta.main(["apply", "--skill-dir", str(sd)]) == 2
