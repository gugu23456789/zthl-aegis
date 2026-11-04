#!/usr/bin/env python3
"""`pack_release.py` 的机检臂（2026-11-02）。

守发布纪律（对齐 `references/ci-pipeline-template.md`）：
  ① 产物三件套：zip + SHA256SUMS + release-manifest.json，且 SHA256SUMS 与 zip 成员逐字对上；
  ② **确定性**：同输入两次打包 zip sha256 相同；
  ③ **拒发**：身份字面量 / 禁词命中 ⟹ 不产出 zip（fail-closed）；
  ④ 运行期产物（`__pycache__`/`.git`/`.log`）不进包。
"""
import hashlib
import json
import os
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pack_release as P  # noqa: E402


def _tree(tmp: Path) -> Path:
    t = tmp / "tree"
    (t / "scripts").mkdir(parents=True)
    (t / "LICENSE").write_text("Mulan PSL v2\n", encoding="utf-8")
    (t / "README.md").write_text("hello\n", encoding="utf-8")
    (t / "scripts" / "a.py").write_text("print(1)\n", encoding="utf-8")
    return t


def test_pack_produces_triplet_and_checksums_match(tmp_path):
    t = _tree(tmp_path)
    out = tmp_path / "dist"
    r = P.pack(str(t), str(out), "v1.2.3")
    assert r["ok"] and r["file_count"] == 3
    zp = out / "zthl-aegis-v1.2.3.zip"
    assert zp.is_file() and (out / "SHA256SUMS").is_file() \
        and (out / "release-manifest.json").is_file()
    sums = {}
    for ln in (out / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        h, p = ln.split("  ", 1)
        sums[p] = h
    with zipfile.ZipFile(zp) as z:
        for p, h in sums.items():
            assert hashlib.sha256(z.read(p)).hexdigest() == h, p
        assert "SHA256SUMS" in z.namelist()
    man = json.loads((out / "release-manifest.json").read_text(encoding="utf-8"))
    assert man["zip_sha256"] == hashlib.sha256(zp.read_bytes()).hexdigest()
    assert man["file_count"] == 3


def test_pack_is_deterministic(tmp_path):
    t = _tree(tmp_path)
    a = P.pack(str(t), str(tmp_path / "a"), "v1")
    b = P.pack(str(t), str(tmp_path / "b"), "v1")
    assert a["zip_sha256"] == b["zip_sha256"], "同输入 zip 不确定（mtime/排序未固定）"


def test_pack_refuses_identity_and_writes_no_zip(tmp_path):
    t = _tree(tmp_path)
    (t / "leak.md").write_text("home: C:" + "\\Users\\HP\\proj\n", encoding="utf-8")
    out = tmp_path / "dist"
    r = P.pack(str(t), str(out), "v1")
    assert r["ok"] is False and r["refused"] is True
    assert not list(out.glob("*.zip")), "身份命中仍产出 zip（应 fail-closed）"


def test_pack_refuses_unsanitized_public_markers(tmp_path):
    """仍含 GK-PUBLIC 标记 ⟹ 私仓原件 / 漏跑 export ⟹ 拒发（2026-11-02）。"""
    t = _tree(tmp_path)
    # 标记字面量拆开拼：本文件随公开包导出，直接写完整注释会被 export 当成真标记块剥掉
    start = "<!-- " + "GK-PUBLIC:CUT-START" + " -->"
    end = "<!-- " + "GK-PUBLIC:CUT-END" + " -->"
    (t / "note.md").write_text(start + "\nsecret\n" + end + "\n", encoding="utf-8")
    out = tmp_path / "dist"
    r = P.pack(str(t), str(out), "v1")
    assert r["ok"] is False and r["refused"] is True
    assert r.get("public_marker_hits")
    assert not list(out.glob("*.zip"))


def test_pack_refuses_forbidden_term(tmp_path):
    t = _tree(tmp_path)
    (t / "note.md").write_text("contains SECRETTERM here\n", encoding="utf-8")
    terms = tmp_path / "terms.txt"
    terms.write_text("# comment\nSECRETTERM\n", encoding="utf-8")
    out = tmp_path / "dist"
    r = P.pack(str(t), str(out), "v1", str(terms))
    assert r["ok"] is False and not list(out.glob("*.zip"))


def test_pack_excludes_runtime_artifacts(tmp_path):
    t = _tree(tmp_path)
    (t / "__pycache__").mkdir()
    (t / "__pycache__" / "x.pyc").write_bytes(b"\0")
    (t / ".git").mkdir()
    (t / ".git" / "config").write_text("x\n", encoding="utf-8")
    (t / "run.log").write_text("x\n", encoding="utf-8")
    (t / "dist").mkdir()
    (t / "dist" / "old.zip").write_bytes(b"x")
    # 2026-11-02 实测（v0.9.3 CI 包）：release 作业先跑 smoke（CLI 落 `.gatekeeper.*`）+
    #   shell 重定向预建 `pack-report.json` ⟹ 二者被当成发布内容打进 zip。此处钉死排除面。
    (t / ".gatekeeper.write-claims.jsonl").write_text("{}\n", encoding="utf-8")
    (t / ".gatekeeper.state").write_text("{}\n", encoding="utf-8")
    (t / "pack-report.json").write_text("", encoding="utf-8")
    r = P.pack(str(t), str(tmp_path / "dist"), "v1")
    paths = {f["path"] for f in r["manifest"]["files"]}
    assert paths == {"LICENSE", "README.md", "scripts/a.py"}, paths


# ── CI 契约：source 绑定 + PROVENANCE.json（2026-11-04）─────────────────────
# 病象：release.yml 传 `--source-repo/--source-commit/--source-tag` 且 publish 步要求
# `dist/PROVENANCE.json`，而脚本两者都没有 ⟹ v0.9.6.8–v0.9.6.10 发版作业连续三版
# 在 pack 步 argparse 退出 2。此处钉死「参数可接受 + 文件必产出 + 字段可核」。

def test_pack_cli_accepts_source_flags_and_writes_provenance(tmp_path):
    t = _tree(tmp_path)
    out = tmp_path / "dist"
    rc = P.main(["--tree", str(t), "--out", str(out), "--version", "v9.9.9",
                 "--source-repo", "org/repo", "--source-commit", "deadbeef",
                 "--source-tag", "v9.9.9", "--json"])
    assert rc == 0
    prov = json.loads((out / "PROVENANCE.json").read_text(encoding="utf-8"))
    assert prov["schema"] == "zthl-provenance/1"
    assert prov["version"] == "v9.9.9"
    assert prov["source"] == {"repo": "org/repo", "commit": "deadbeef", "tag": "v9.9.9"}
    names = {s["name"] for s in prov["subject"]}
    assert names == {"zthl-aegis-v9.9.9.zip", "SHA256SUMS"}, names
    manifest = json.loads((out / "release-manifest.json").read_text(encoding="utf-8"))
    sha = {s["name"]: s["sha256"] for s in prov["subject"]}
    assert sha["zthl-aegis-v9.9.9.zip"] == manifest["zip_sha256"]


def test_pack_provenance_source_null_when_absent(tmp_path):
    t = _tree(tmp_path)
    out = tmp_path / "dist"
    assert P.pack(str(t), str(out), "v1")["ok"]
    prov = json.loads((out / "PROVENANCE.json").read_text(encoding="utf-8"))
    assert prov["source"] == {"repo": None, "commit": None, "tag": None}
