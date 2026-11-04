#!/usr/bin/env python3
"""gk_zenodo_sync.py 单测（全部离线：打桩 `_req`，不发真实请求）。

臂：
  ① 无 ZENODO_TOKEN ⟹ skipped / exit 0（发版不得因存档失败而红）；
  ② 附件缺失 ⟹ exit 2（不静默少传）；
  ③ 正常流程 ⟹ newversion → 删旧文件 → 上传 5 个 → PUT 元数据 → publish；
  ④ newversion 失败 ⟹ exit 1，且**不**发 publish。
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_zenodo_sync as Z  # noqa: E402


def _dist(tmp_path, version="v0.9.6.3"):
    for n in ["zthl-aegis-%s.zip" % version] + list(Z.BASE_FILES):
        (tmp_path / n).write_bytes(b"x")
    (tmp_path / "PROVENANCE.json").write_text(json.dumps(
        {"source": {"commit": "0229405abcdef1234", "tag": version}}), encoding="utf-8")
    return tmp_path


def _run(capsys, *args):
    rc = Z.main(list(args))
    return rc, json.loads(capsys.readouterr().out)


def test_skip_without_token(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("ZENODO_TOKEN", raising=False)
    rc, out = _run(capsys, "--concept", "23934594", "--version", "v0.9.6.3",
                   "--dist", str(_dist(tmp_path)))
    assert rc == 0
    assert out["status"] == "skipped"
    assert len(out["files"]) == 5


def test_missing_file_exit_2(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("ZENODO_TOKEN", "t0ken")
    d = _dist(tmp_path)
    (d / "SBOM.cdx.json").unlink()
    rc, out = _run(capsys, "--concept", "23934594", "--version", "v0.9.6.3", "--dist", str(d))
    assert rc == 2
    assert out["error"] == "附件缺失"


def test_full_flow(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("ZENODO_TOKEN", "t0ken")
    calls = []
    bodies = {}

    def fake(method, url, token=None, body=None, headers=None, timeout=120):
        calls.append((method, url))
        if method == "PUT":
            bodies["put"] = json.loads(body.decode("utf-8"))
        if "/records?q=conceptrecid:" in url:
            return 200, {"hits": {"hits": [{"id": 23934595}]}}
        if url.endswith("/actions/newversion"):
            return 201, {"links": {"latest_draft": "https://zenodo.org/api/deposit/depositions/777"}}
        if method == "GET" and url.endswith("/deposit/depositions/777"):
            return 200, {"metadata": {"title": "T", "doi": "10.1/x", "description": "D",
                                      "dates": [{"type": "issued", "date": ""}]},
                         "files": [{"id": "f1", "links": {"self": "https://z/api/deposit/depositions/777/files/f1"}}]}
        if method == "POST" and url.endswith("/files"):
            return 201, {"id": "new"}
        if method == "PUT":
            return 200, {"metadata": {"title": "T"}}
        if url.endswith("/actions/publish"):
            return 202, {"doi": "10.5281/zenodo.777", "conceptdoi": "10.5281/zenodo.23934594"}
        return 200, {}

    monkeypatch.setattr(Z, "_req", fake)
    rc, out = _run(capsys, "--concept", "23934594", "--version", "v0.9.6.3",
                   "--dist", str(_dist(tmp_path)))
    assert rc == 0
    assert out["status"] == "published"
    assert out["record"] == "777"
    assert out["doi"] == "10.5281/zenodo.777"
    assert len(out["files"]) == 5
    urls = [u for _, u in calls]
    assert any(u.endswith("/depositions/23934595/actions/newversion") for u in urls)
    assert sum(1 for m, u in calls if m == "DELETE") == 1          # 继承的旧文件被清掉
    assert sum(1 for m, u in calls if m == "POST" and u.endswith("/files")) == 5
    assert urls[-1].endswith("/depositions/777/actions/publish")   # publish 最后一步
    # 元数据：只读键不得回写（doi 由服务端生成），标题/版本/许可必须确定性写入
    meta = bodies["put"]["metadata"]
    assert "doi" not in meta and "relations" not in meta
    assert meta["version"] == "v0.9.6.3"
    assert meta["title"] == "ZTHL Aegis v0.9.6.3"          # 不继承旧草稿的旧标题
    assert meta["license"] == {"id": "other-open"}         # 不落成默认 cc-by-4.0
    desc = meta["description"]
    assert "MulanPSL2" in desc                             # 正文写明真实许可
    assert "v0.9.6.3" in desc and "0229405" in desc        # 描述按本版 tag/commit 生成
    assert "v0.9.6.2" not in desc                          # 不继承旧正文
    # 空日期项必须剔除（否则 Zenodo 400: metadata.dates Invalid date provided）
    assert "dates" not in meta


def test_reuse_existing_draft(tmp_path, capsys, monkeypatch):
    """上次失败留下的草稿必须被复用，不能再次 newversion（否则 409/400）。"""
    monkeypatch.setenv("ZENODO_TOKEN", "t0ken")
    calls = []

    def fake(method, url, token=None, body=None, headers=None, timeout=120):
        calls.append((method, url))
        if "/records?q=conceptrecid:" in url:
            return 200, {"hits": {"hits": [{"id": 23934595}]}}
        if method == "GET" and url.endswith("/deposit/depositions/23934595"):
            return 200, {"links": {"latest_draft": "https://zenodo.org/api/deposit/depositions/888"},
                         "metadata": {"title": "T"}}
        if method == "GET" and url.endswith("/deposit/depositions/888"):
            return 200, {"metadata": {"title": "T"}, "files": []}
        if method == "PUT":
            return 200, {"metadata": {"title": "T"}}
        if url.endswith("/actions/publish"):
            return 202, {"doi": "10.5281/zenodo.888"}
        return 201, {}

    monkeypatch.setattr(Z, "_req", fake)
    rc, out = _run(capsys, "--concept", "23934594", "--version", "v0.9.6.3",
                   "--dist", str(_dist(tmp_path)))
    assert rc == 0
    assert out["record"] == "888"
    assert not any(u.endswith("/actions/newversion") for _, u in calls)


def test_find_draft_by_concept_search(tmp_path, capsys, monkeypatch):
    """`latest_draft` 链接缺失时，须按 conceptrecid 检索找到草稿（v0.9.6.4 实测失败路径）。"""
    monkeypatch.setenv("ZENODO_TOKEN", "t0ken")
    calls = []

    def fake(method, url, token=None, body=None, headers=None, timeout=120):
        calls.append((method, url))
        if "/records?q=conceptrecid:" in url:
            return 200, {"hits": {"hits": [{"id": 23934595}]}}
        if method == "GET" and "/deposit/depositions?q=conceptrecid:" in url:
            return 200, [{"id": 23934595, "state": "done"},
                         {"id": 23934610, "state": "unsubmitted"}]
        if method == "GET" and url.endswith("/deposit/depositions/23934595"):
            return 200, {"links": {}, "metadata": {"title": "T"}}
        if method == "GET" and url.endswith("/deposit/depositions/23934610"):
            return 200, {"metadata": {"title": "T"}, "files": []}
        if method == "PUT":
            return 200, {"metadata": {"title": "T"}}
        if url.endswith("/actions/publish"):
            return 202, {"doi": "10.5281/zenodo.23934610"}
        return 201, {}

    monkeypatch.setattr(Z, "_req", fake)
    rc, out = _run(capsys, "--concept", "23934594", "--version", "v0.9.6.3",
                   "--dist", str(_dist(tmp_path)))
    assert rc == 0
    assert out["record"] == "23934610"
    assert not any(u.endswith("/actions/newversion") for _, u in calls)


def test_published_record_without_state_is_not_draft(tmp_path, capsys, monkeypatch):
    """检索结果**没有 state/submitted 字段**的已发布记录，不得被当成草稿（403 Bucket is locked）。"""
    monkeypatch.setenv("ZENODO_TOKEN", "t0ken")
    calls = []

    def fake(method, url, token=None, body=None, headers=None, timeout=120):
        calls.append((method, url))
        if "/records?q=conceptrecid:" in url:
            return 200, {"hits": {"hits": [{"id": 23934595}]}}
        if method == "GET" and "/deposit/depositions?q=conceptrecid:" in url:
            return 200, [{"id": 23934595}, {"id": 23935725}]      # 两条都已发布、且无 state
        if method == "GET" and url.endswith("/deposit/depositions/23934595"):
            return 200, {"links": {}, "metadata": {"title": "T"}}
        if url.endswith("/actions/newversion"):
            return 201, {"links": {"latest_draft": "https://zenodo.org/api/deposit/depositions/999"}}
        if method == "GET" and url.endswith("/deposit/depositions/999"):
            return 200, {"metadata": {"title": "T"}, "files": []}
        if method == "PUT":
            return 200, {}
        if url.endswith("/actions/publish"):
            return 202, {"doi": "10.5281/zenodo.999"}
        return 201, {}

    monkeypatch.setattr(Z, "_req", fake)
    rc, out = _run(capsys, "--concept", "23934594", "--version", "v0.9.6.5",
                   "--dist", str(_dist(tmp_path, "v0.9.6.5")))
    assert rc == 0
    assert out["record"] == "999"                                  # 走了 newversion
    assert any(u.endswith("/actions/newversion") for _, u in calls)
    assert not any(m == "DELETE" for m, _ in calls)                 # 没去删已发布记录的文件


def _archive(tmp_path, **kw):
    data = {"schema": "gk-archive-meta/1", "concept_doi": "10.5281/zenodo.23934594",
            "zenodo_record": "23934595", "swhid": ""}
    data.update(kw)
    p = tmp_path / "archive.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_check_archive_ok(tmp_path, capsys):
    rc = Z.main(["--check-archive", str(_archive(tmp_path))])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["ok"] is True
    assert out["concept_doi"] == "10.5281/zenodo.23934594"


def test_check_archive_bad_doi(tmp_path, capsys):
    p = _archive(tmp_path, concept_doi="https://doi.org/10.5281/zenodo.23934594")
    assert Z.main(["--check-archive", str(p)]) == 2


def test_check_archive_bad_schema(tmp_path, capsys):
    p = _archive(tmp_path, schema="other/1")
    assert Z.main(["--check-archive", str(p)]) == 2


def test_dry_run_allows_missing_dist(tmp_path, capsys, monkeypatch):
    """CI / 发包预检时 dist 尚未产出 ⟹ dry-run 只报告缺失，不判失败。"""
    monkeypatch.setenv("ZENODO_TOKEN", "t0ken")

    def fake(method, url, token=None, body=None, headers=None, timeout=120):
        return 200, {"hits": {"hits": [{"id": 23934595}]}}

    monkeypatch.setattr(Z, "_req", fake)
    rc, out = _run(capsys, "--concept", "23934594", "--version", "v0.9.6.6",
                   "--dist", str(tmp_path / "nope"), "--dry-run")
    assert rc == 0
    assert out["status"] == "dry-run"
    assert len(out["missing"]) == 5


def test_bad_concept_exit_2(tmp_path, capsys, monkeypatch):
    """Concept recid 必须是纯数字（防止把 DOI 前缀/URL 直接塞进来）。"""
    monkeypatch.setenv("ZENODO_TOKEN", "t0ken")
    rc, out = _run(capsys, "--concept", "10.5281/zenodo.23934594", "--version", "v0.9.6.6",
                   "--dist", str(_dist(tmp_path, "v0.9.6.6")))
    assert rc == 2
    assert "纯数字" in out["error"]


def test_newversion_failure_exit_1(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("ZENODO_TOKEN", "t0ken")
    calls = []

    def fake(method, url, token=None, body=None, headers=None, timeout=120):
        calls.append((method, url))
        if "/records?q=conceptrecid:" in url:
            return 200, {"hits": {"hits": [{"id": 23934595}]}}
        if url.endswith("/actions/newversion"):
            return 403, {"message": "Forbidden"}
        return 200, {}

    monkeypatch.setattr(Z, "_req", fake)
    rc, out = _run(capsys, "--concept", "23934594", "--version", "v0.9.6.3",
                   "--dist", str(_dist(tmp_path)))
    assert rc == 1
    assert out["error"] == "newversion 失败"
    assert not any(u.endswith("/actions/publish") for _, u in calls)


def test_dry_run_makes_no_writes(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("ZENODO_TOKEN", "t0ken")
    calls = []

    def fake(method, url, token=None, body=None, headers=None, timeout=120):
        calls.append((method, url))
        return 200, {"hits": {"hits": [{"id": 23934595}]}}

    monkeypatch.setattr(Z, "_req", fake)
    rc, out = _run(capsys, "--concept", "23934594", "--version", "v0.9.6.3",
                   "--dist", str(_dist(tmp_path)), "--dry-run")
    assert rc == 0
    assert out["status"] == "dry-run"
    assert all(m == "GET" for m, _ in calls)
