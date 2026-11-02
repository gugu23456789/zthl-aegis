#!/usr/bin/env python3
"""⑤ 红先臂：ECC 终态须「有据」+「源可核验」（§18.2 判据 9 + c9 加固，2026-10-04）。

缺陷（二轮质询 §18.2 台账一致性）：`gk_finding.close()` 置 `basis_ref = evidence_hash or ""`
**无闸** ⟹ 无证据也可 close。实测 `ECC-DB4E4CBDCF7C` 05:39 登记 / 05:58 `manual` 关闭且
`basis_ref=""`，而计划正文仍写「不可落刀」= 「登记即闭合」**洗白形状**。

修法（拍板：**不复用** `closure_oracle`）：`gk_self_check.check_ecc_form` 增判据 ——
`status ∈ {closed,fixed}` 时 `basis_ref` 非空 **或** `verify_source == "register-only"`，否则 **FAIL**。

c9 加固（2026-10-04 · `ECC-2C7BEBA09A84` / BLUE-FAT-FISH-IDLE-GATE，用户裁「全纳入」）：
v2 的「源质量」只是**自由文本**比对（`closed` 时 vsrc ∉ {"", "manual"}）⟹ 任意串（含 `register-only`
与编造 `commit:xxxx`）即可绕过。加固补三条**真牙齿**：
  · **写边界白名单**：`close()` 的 `verify_source` 逐段验 `kind ∈ _VERIFY_SOURCES`，否则拒写。
  · **kind 白名单**：c9 对终态 vsrc 的每个 kind 复核，非白名单 → FAIL（关「任意串即有源」）。
  · **commit 可核验**：`commit:<sha>` 段须携带可解析 sha 且 `git cat-file -e` 存在，否则 FAIL。
  · **fixed 一并纳入**：`verify()` 增可选 `verify_source`，`fixed` 也须有真源（非空/非 manual/白名单/cat-file）。

臂（HEAD 必红 = 无上述判据）：
  · `closed_without_basis_fails` / `closed_manual_source_fails` / `closed_empty_source_fails`
  · `register_only_escape_passes`（合法出口保留）
  · `closed_bogus_kind_fails` / `closed_fabricated_commit_fails` / `closed_commit_without_sha_fails`
  · `close_rejects_bogus_kind`（写边界 fail-loud）
  · `fixed_without_source_fails` / `fixed_bogus_kind_fails` / `verify_accepts_real_commit_source`
  · 零假阳：`closed_commit_source_passes` / `no_false_positive_on_legit_terminal`
"""
import json
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_finding as GF  # noqa: E402
import gk_self_check as SC  # noqa: E402


def _mk(tmp_path, findings):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": findings}},
                             ensure_ascii=False), encoding="utf-8", newline="\n")
    return str(st)


def _repo_sha():
    """本 worktree 仓的真实 commit（供 `commit:<sha>` 存在性核验的零假阳臂）。"""
    repo = str(Path(__file__).resolve().parent.parent)
    return subprocess.check_output(
        ["git", "-C", repo, "rev-parse", "--short", "HEAD"], text=True).strip()


def test_closed_without_basis_fails(tmp_path):
    out = SC.check_ecc_form(_mk(tmp_path, [
        {"id": "ECC-W", "source": "manual", "status": "closed",
         "basis_ref": "", "verify_source": "manual"}]))
    assert out["status"] == "FAIL" and "无据关闭" in out["detail"], out


def test_register_only_escape_passes(tmp_path):
    """显式「仅登记」标签 = 合法出口（治洗白同时不误伤确为纯登记的关闭）。"""
    out = SC.check_ecc_form(_mk(tmp_path, [
        {"id": "ECC-R", "source": "manual", "status": "closed",
         "basis_ref": "", "verify_source": "register-only"}]))
    assert out["status"] == "PASS", out


def test_closed_with_basis_passes(tmp_path):
    """零假阳：`closed` + 真实 commit 源 → PASS。"""
    out = SC.check_ecc_form(_mk(tmp_path, [
        {"id": "ECC-B", "source": "manual", "status": "closed",
         "basis_ref": "sha256:abc", "evidence_hash": "abc",
         "verify_source": "commit:%s;tests:ok" % _repo_sha()}]))
    assert out["status"] == "PASS", out


def test_open_unaffected(tmp_path):
    """零回归：`open`（含 `basis_ref=""`）不判 —— 未终态不追责。"""
    out = SC.check_ecc_form(_mk(tmp_path, [
        {"id": "ECC-O", "source": "manual", "status": "open", "basis_ref": ""}]))
    assert out["status"] == "PASS", out


def test_register_path_finding_carries_basis_on_verify(tmp_path):
    """P1 红先：`register` 路径须产 `evidence_hash` ⟹ verify（带真源）后 c9 PASS。"""
    st = str(tmp_path / ".gatekeeper.state")
    (tmp_path / ".gatekeeper.state").write_text(
        json.dumps({"gate_data": {"ecc_findings": []}}, ensure_ascii=False),
        encoding="utf-8", newline="\n")
    f = GF.register(st, "T-basis-arm", "manual", root_key="rk/basis-arm",
                    anchors=["anchors-a", "anchors-b"])
    assert len(f.get("evidence_hash", "")) == 16, f
    GF.verify(st, f["id"], True, verify_source="commit:%s;tests:ok" % _repo_sha())
    rec = [x for x in GF.load_findings(st) if x["id"] == f["id"]][0]
    assert rec["basis_ref"] == rec["evidence_hash"] != "", rec
    assert SC.check_ecc_form(st)["status"] == "PASS", SC.check_ecc_form(st)


def test_register_close_flow_c9_green(tmp_path):
    """摩擦消除：新登记全链 register → close（真源）后 c9 PASS。"""
    st = str(tmp_path / ".gatekeeper.state")
    (tmp_path / ".gatekeeper.state").write_text(
        json.dumps({"gate_data": {"ecc_findings": []}}, ensure_ascii=False),
        encoding="utf-8", newline="\n")
    f = GF.register(st, "T-flow-arm", "manual", root_key="rk/flow-arm", anchors=["a"])
    GF.close(st, f["id"], "commit:%s;tests:1 passed;arm:flow green" % _repo_sha())
    rec = [x for x in GF.load_findings(st) if x["id"] == f["id"]][0]
    assert rec["status"] == "closed" and rec["basis_ref"] != "", rec
    assert SC.check_ecc_form(st)["status"] == "PASS", SC.check_ecc_form(st)


def test_no_false_positive_on_legit_terminal(tmp_path):
    """零假阳：引擎路径（带 evidence_hash）+ 真实 commit 源的 `closed` 不得被误判 FAIL。"""
    out = SC.check_ecc_form(_mk(tmp_path, [
        {"id": "RED-LEGIT", "source": "red", "status": "closed",
         "basis_ref": "e" * 16, "evidence_hash": "e" * 16,
         "verify_source": "commit:%s;tests:ok" % _repo_sha()}]))
    assert out["status"] == "PASS", out


def test_closed_manual_source_fails(tmp_path):
    """c9 v2：`closed` 且 `verify_source="manual"` → FAIL（无实据自证）。"""
    out = SC.check_ecc_form(_mk(tmp_path, [
        {"id": "ECC-M", "source": "manual", "status": "closed",
         "basis_ref": "abc", "evidence_hash": "abc", "verify_source": "manual"}]))
    assert out["status"] == "FAIL" and "闭合无源" in out["detail"], out


def test_closed_empty_source_fails(tmp_path):
    """c9 v2：`closed` 且 `verify_source=""` → FAIL。"""
    out = SC.check_ecc_form(_mk(tmp_path, [
        {"id": "ECC-E2", "source": "manual", "status": "closed",
         "basis_ref": "abc", "evidence_hash": "abc"}]))
    assert out["status"] == "FAIL" and "闭合无源" in out["detail"], out


def test_closed_commit_source_passes(tmp_path):
    """零假阳：`closed` + 真实 commit 源 → PASS。"""
    out = SC.check_ecc_form(_mk(tmp_path, [
        {"id": "ECC-C", "source": "manual", "status": "closed",
         "basis_ref": "abc", "evidence_hash": "abc",
         "verify_source": "commit:%s;tests:1 passed" % _repo_sha()}]))
    assert out["status"] == "PASS", out


# ── c9 加固红先臂（HEAD 必红）───────────────────────────────────────────────

def test_closed_bogus_kind_fails(tmp_path):
    """加固①：终态 vsrc 的 kind 非白名单 = 「任意串即有源」⟹ FAIL。"""
    out = SC.check_ecc_form(_mk(tmp_path, [
        {"id": "ECC-BK", "source": "manual", "status": "closed",
         "basis_ref": "abc", "evidence_hash": "abc",
         "verify_source": "whatever-i-say"}]))
    assert out["status"] == "FAIL" and "源 kind 非法" in out["detail"], out


def test_closed_fabricated_commit_fails(tmp_path):
    """加固②：`commit:<sha>` 在仓内不存在 ⟹ FAIL（编造 sha 失效）。"""
    out = SC.check_ecc_form(_mk(tmp_path, [
        {"id": "ECC-FC", "source": "manual", "status": "closed",
         "basis_ref": "abc", "evidence_hash": "abc",
         "verify_source": "commit:deadbeef0badc0de"}]))
    assert out["status"] == "FAIL" and "commit 不可解析" in out["detail"], out


def test_closed_commit_without_sha_fails(tmp_path):
    """加固②边界：`commit:` 段无 sha（`commit:notasha`）⟹ FAIL。"""
    out = SC.check_ecc_form(_mk(tmp_path, [
        {"id": "ECC-NS", "source": "manual", "status": "closed",
         "basis_ref": "abc", "evidence_hash": "abc",
         "verify_source": "commit:notasha"}]))
    assert out["status"] == "FAIL" and "commit 不可解析" in out["detail"], out


def test_close_rejects_bogus_kind(tmp_path):
    """加固③（写边界）：`close()` 拒**结构化**段的非白名单 kind ⟹ ValueError。

    仅结构化（含 `:`）段受写边界约束；无冒号自由文本按历史用法放行（终态由 c9 判）。
    """
    st = str(tmp_path / ".gatekeeper.state")
    (tmp_path / ".gatekeeper.state").write_text(
        json.dumps({"gate_data": {"ecc_findings": []}}, ensure_ascii=False),
        encoding="utf-8", newline="\n")
    f = GF.register(st, "T-close-guard", "manual", root_key="rk/close-guard", anchors=["a"])
    raised = False
    try:
        GF.close(st, f["id"], "bogus-kind:payload")
    except ValueError:
        raised = True
    assert raised, "close() 须拒结构化段的非白名单 kind"


def test_fixed_without_source_fails(tmp_path):
    """加固④（全纳入）：`fixed` 也须有真源；无源 → FAIL（HEAD 该形状 PASS 必红）。"""
    out = SC.check_ecc_form(_mk(tmp_path, [
        {"id": "ECC-FX", "source": "manual", "status": "fixed",
         "basis_ref": "abc", "evidence_hash": "abc"}]))
    assert out["status"] == "FAIL" and "闭合无源" in out["detail"], out


def test_fixed_bogus_kind_fails(tmp_path):
    """加固④：`fixed` 的 vsrc kind 非白名单 → FAIL（证 fixed 已被纳入核验）。"""
    out = SC.check_ecc_form(_mk(tmp_path, [
        {"id": "ECC-FBK", "source": "manual", "status": "fixed",
         "basis_ref": "abc", "evidence_hash": "abc",
         "verify_source": "some-free-text"}]))
    assert out["status"] == "FAIL" and "源 kind 非法" in out["detail"], out


def test_verify_accepts_real_commit_source(tmp_path):
    """加固④：`verify(ok=True, verify_source=真实 commit)` → fixed 承载源 → c9 PASS。"""
    st = str(tmp_path / ".gatekeeper.state")
    (tmp_path / ".gatekeeper.state").write_text(
        json.dumps({"gate_data": {"ecc_findings": []}}, ensure_ascii=False),
        encoding="utf-8", newline="\n")
    f = GF.register(st, "T-verify-src", "manual", root_key="rk/verify-src", anchors=["a"])
    GF.verify(st, f["id"], True, verify_source="commit:%s;tests:ok" % _repo_sha())
    rec = [x for x in GF.load_findings(st) if x["id"] == f["id"]][0]
    assert rec["status"] == "fixed" and rec["verify_source"].startswith("commit:"), rec
    assert SC.check_ecc_form(st)["status"] == "PASS", SC.check_ecc_form(st)


# ── P1 补：存量 finding 经 `register`（同 root_key merge）回填 evidence_hash（红先）──────
def test_register_merge_backfills_evidence_hash(tmp_path):
    """红先：存量 finding（注册早于「register 产指纹」，**无** `evidence_hash`）再经 `register`
    同 `root_key` merge ⟹ **回填**指纹 ⟹ `close`（真源）得 `basis_ref` ⟹ c9 PASS。

    病象：`close()` 取 `basis_ref = evidence_hash or ""` ⟹ 存量条目恒空 ⟹ c9「无据关闭」
    对其**结构性不可满足**（只能退 `register-only`）。修法 = merge 分支缺指纹则按 register
    同式重算（**单一算法源** `_evidence_hash`）。
    """
    st = str(tmp_path / ".gatekeeper.state")
    (tmp_path / ".gatekeeper.state").write_text(json.dumps(
        {"gate_data": {"ecc_findings": [
            {"id": "ECC-LEGACY", "title": "T-legacy", "source": "crossrev", "status": "open",
             "family": "R-CONC-GIT", "root_key": "rk/legacy", "anchors": ["gatekeeper-cli.sh"],
             "facets": [], "closure_oracle": "mechanical"}]}}, ensure_ascii=False),
        encoding="utf-8", newline="\n")
    GF.register(st, "T-legacy", "manual", root_key="rk/legacy")   # merge（root_key 命中）
    rec = [x for x in GF.load_findings(st) if x["id"] == "ECC-LEGACY"][0]
    assert len(rec.get("evidence_hash", "")) == 16, f"merge 未回填 evidence_hash：{rec}"
    GF.close(st, "ECC-LEGACY",
             "commit:%s;arm:test_register_merge_backfills_evidence_hash" % _repo_sha())
    rec = [x for x in GF.load_findings(st) if x["id"] == "ECC-LEGACY"][0]
    assert rec["status"] == "closed" and rec["basis_ref"] != "", rec
    assert SC.check_ecc_form(st)["status"] == "PASS", SC.check_ecc_form(st)
