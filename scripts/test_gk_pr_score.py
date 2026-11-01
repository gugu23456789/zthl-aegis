#!/usr/bin/env python3
"""
test_gk_pr_score.py — C9 PR-SCORE 双盲评分锚定测试（2026-09-06）
覆盖: seal 往返（快照 + plan 区块注入 + A3 seal）/ 篡改检出（快照维度改 · 区块字段改）/ 无 audit key
fail-loud / 无 META 拒绝 / 已含区块防静默覆盖 / verify 无快照 / list / CLI 用法纪律 / --no-update-plan。
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_pr_score as gps  # noqa: E402

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption)
    CRYPTO = True
except Exception:  # pragma: no cover
    CRYPTO = False


def _plan_doc(tmp, name="2026-08-28-security-hardening-assessment", with_meta=True):
    """建带 META 的 plan 文档；返回路径。"""
    p = Path(tmp) / f"{name}.md"
    head = ""
    if with_meta:
        head = "# Plan\n\n<!-- META phases: R7 target_repo: skill -->\n\n正文内容。\n"
    else:
        head = "# Plan\n\n正文内容。\n"
    p.write_text(head, encoding="utf-8")
    return p


def _score(divergence=0.2, dims_scope=58):
    s = {
        "dimensions": {"scope": dims_scope, "evidence": 65, "assumptions": 30,
                       "recovery": 40, "references": 55, "bias": 60, "cost": 25},
        "f1_f7": {"f1": "ok", "f2": "ok", "f3": "warn", "f4": "ok",
                  "f5": "ok", "f6": "ok", "f7": "ok"},
        "divergence": divergence,
        "checkpoint_task": "plan-refinement: 2026-08-28-security-hardening-assessment — SCR 质询",
        "scored_at": "2026-09-06T04:00:00Z",
    }
    return s


def _write_score(tmp, s=None, name="score.json"):
    p = Path(tmp) / name
    p.write_text(json.dumps(s or _score(), ensure_ascii=False), encoding="utf-8")
    return p


def _make_keys(d):
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_pem = priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    Path(d, "audit_ed25519.pem").write_bytes(priv_pem)
    Path(d, "audit_ed25519.pub").write_bytes(pub_pem)
    return priv_pem


def _snapshot(plan_path):
    return str(Path(plan_path).parent / (gps.PRSCORE_PREFIX + gps._plan_name(plan_path) + ".json"))


@pytest.fixture
def env():
    with tempfile.TemporaryDirectory() as tmp:
        yield tmp


def test_seal_roundtrip_snapshot_and_block(env):
    """seal：写快照（含 seal）+ plan 区块注入；verify anchored。"""
    if not CRYPTO:
        pytest.skip("cryptography missing")
    keys = Path(env) / "keys"; keys.mkdir()
    _make_keys(keys)
    plan = _plan_doc(env)
    score = _write_score(env)
    r = gps.cmd_seal(str(plan), str(score), str(keys))
    assert r["ok"] and r["plan_block"] == "injected"
    snap = _snapshot(plan)
    assert os.path.isfile(snap)
    data = json.load(open(snap, encoding="utf-8"))
    assert data["schema"] == gps.SCHEMA
    assert data["seal"]["alg"] == "ed25519"
    assert data["dimensions"]["scope"] == 58
    text = plan.read_text(encoding="utf-8")
    assert "<!-- PR-SCORE" in text and "pr-score/1" in text
    # 区块插在 META 后且正文之前
    assert text.index("<!-- PR-SCORE") > text.index("<!-- META")
    v = gps.cmd_verify(str(plan), str(keys))
    assert v["ok"] and v["anchored"] and v["seal"] == "verified"


def test_seal_fail_loud_without_key(env):
    """无 audit key → fail-loud（不产未签快照/区块）。"""
    plan = _plan_doc(env)
    score = _write_score(env)
    r = gps.cmd_seal(str(plan), str(score), os.path.join(env, "no_keys"))
    assert not r["ok"] and "no_audit_key" in r["error"]
    assert not os.path.exists(_snapshot(plan))
    assert "PR-SCORE" not in plan.read_text(encoding="utf-8")


def test_seal_rejects_plan_without_meta(env):
    """无 META 的 plan → no_meta_block 拒绝（质询对象须先补 META）。"""
    if not CRYPTO:
        pytest.skip("cryptography missing")
    keys = Path(env) / "keys"; keys.mkdir()
    _make_keys(keys)
    plan = _plan_doc(env, with_meta=False)
    score = _write_score(env)
    r = gps.cmd_seal(str(plan), str(score), str(keys))
    assert not r["ok"] and "no_meta_block" in r["error"]


def test_seal_rejects_second_block(env):
    """已含 PR-SCORE 区块 → 拒绝静默覆盖（须人工审阅决定轮换）。"""
    if not CRYPTO:
        pytest.skip("cryptography missing")
    keys = Path(env) / "keys"; keys.mkdir()
    _make_keys(keys)
    plan = _plan_doc(env)
    score = _write_score(env)
    assert gps.cmd_seal(str(plan), str(score), str(keys))["ok"]
    r2 = gps.cmd_seal(str(plan), str(score), str(keys))
    assert not r2["ok"] and "pr_score_block_exists" in r2["error"]


def test_verify_detects_snapshot_tamper(env):
    """快照维度被改 → seal invalid，anchored False。"""
    if not CRYPTO:
        pytest.skip("cryptography missing")
    keys = Path(env) / "keys"; keys.mkdir()
    _make_keys(keys)
    plan = _plan_doc(env)
    score = _write_score(env)
    gps.cmd_seal(str(plan), str(score), str(keys))
    snap = _snapshot(plan)
    data = json.load(open(snap, encoding="utf-8"))
    data["dimensions"]["scope"] = 99  # 事后改写
    json.dump(data, open(snap, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    v = gps.cmd_verify(str(plan), str(keys))
    assert v["ok"] and not v["anchored"] and v["seal"] == "invalid"


def test_verify_detects_block_field_mismatch(env):
    """区块字段被改（与快照不一致）→ mismatches 检出（seal 仍 verified——区块非签对象）。"""
    if not CRYPTO:
        pytest.skip("cryptography missing")
    keys = Path(env) / "keys"; keys.mkdir()
    _make_keys(keys)
    plan = _plan_doc(env)
    score = _write_score(env, _score(dims_scope=58))
    gps.cmd_seal(str(plan), str(score), str(keys))
    text = plan.read_text(encoding="utf-8")
    tampered = text.replace('"scope":58', '"scope":77')
    assert tampered != text
    plan.write_text(tampered, encoding="utf-8")
    v = gps.cmd_verify(str(plan), str(keys))
    assert v["ok"] and not v["anchored"]
    assert any("dimensions" in m for m in v["mismatches"])


def test_verify_block_removed(env):
    """区块被移除 → mismatches 检出（快照存在但分离）。"""
    if not CRYPTO:
        pytest.skip("cryptography missing")
    keys = Path(env) / "keys"; keys.mkdir()
    _make_keys(keys)
    plan = _plan_doc(env)
    score = _write_score(env)
    gps.cmd_seal(str(plan), str(score), str(keys))
    import re
    text = plan.read_text(encoding="utf-8")
    plan.write_text(re.sub(r"<!-- PR-SCORE.*?-->", "", text, flags=re.S), encoding="utf-8")
    v = gps.cmd_verify(str(plan), str(keys))
    assert v["ok"] and not v["anchored"]
    assert any("区块缺失" in m for m in v["mismatches"])


def test_verify_no_snapshot(env):
    """从未锚定 → anchored False（no_snapshot），不崩。"""
    plan = _plan_doc(env)
    v = gps.cmd_verify(str(plan), os.path.join(env, "keys"))
    assert v["ok"] and not v["anchored"] and "no_snapshot" in v["error"]


def test_seal_no_update_plan(env):
    """--no-update-plan：只写快照，不注入区块。"""
    if not CRYPTO:
        pytest.skip("cryptography missing")
    keys = Path(env) / "keys"; keys.mkdir()
    _make_keys(keys)
    plan = _plan_doc(env)
    score = _write_score(env)
    r = gps.cmd_seal(str(plan), str(score), str(keys), update_plan=False)
    assert r["ok"] and r["plan_block"] == "skipped"
    assert os.path.isfile(_snapshot(plan))
    assert "PR-SCORE" not in plan.read_text(encoding="utf-8")


def test_score_validation_fail_loud(env):
    """缺 dimensions/f1_f7 → 显式报错，不产快照。"""
    if not CRYPTO:
        pytest.skip("cryptography missing")
    keys = Path(env) / "keys"; keys.mkdir()
    _make_keys(keys)
    plan = _plan_doc(env)
    bad = _write_score(env, {"dimensions": {}})
    r = gps.cmd_seal(str(plan), str(bad), str(keys))
    assert not r["ok"] and "score_missing_dimensions" in r["error"]


def test_cli_discipline(env):
    """CLI 纪律：缺 --plan / seal 缺 --score → exit 1。"""
    env2 = dict(os.environ)
    cp = subprocess.run([sys.executable, str(SCRIPTS / "gk_pr_score.py")],
                        capture_output=True, text=True, env=env2, cwd=str(SCRIPTS))
    assert cp.returncode == 1
    cp2 = subprocess.run([sys.executable, str(SCRIPTS / "gk_pr_score.py"), "seal"],
                         capture_output=True, text=True, env=env2, cwd=str(SCRIPTS))
    assert cp2.returncode == 1


def test_seal_rotate_replaces_in_place_and_archives(env):
    """ECC-3E10D111D382：--rotate 轮换 —— 旧快照归档 + 新区块原位替换，verify 仍 anchored。"""
    if not CRYPTO:
        pytest.skip("cryptography missing")
    keys = Path(env) / "keys"; keys.mkdir()
    _make_keys(keys)
    plan = _plan_doc(env)
    score = _write_score(env, _score(dims_scope=58))
    r1 = gps.cmd_seal(str(plan), str(score), str(keys))
    assert r1["ok"] and r1["plan_block"] == "injected"
    snap1 = _snapshot(plan)
    old_snap_text = Path(snap1).read_text(encoding="utf-8")

    # 重锚：不带 --rotate → 仍硬拒（防静默覆盖）
    r_block = gps.cmd_seal(str(plan), str(score), str(keys))
    assert not r_block["ok"] and "pr_score_block_exists" in r_block["error"]
    # 新打分 → 显式 rotate
    score2 = _write_score(env, _score(dims_scope=71), name="score2.json")
    r2 = gps.cmd_seal(str(plan), str(score2), str(keys), rotate=True)
    assert r2["ok"]
    assert r2["plan_block"] == "rotated"
    assert r2["archived_snapshot"].endswith(".json")  # 旧快照已归档
    # 当前快照路径内容 = 新 seal；旧锚内容移至归档文件
    new_data = json.loads(Path(snap1).read_text(encoding="utf-8"))
    assert new_data["dimensions"]["scope"] == 71
    archived_path = Path(env) / r2["archived_snapshot"]
    assert archived_path.exists()
    assert archived_path.read_text(encoding="utf-8") == old_snap_text  # 归档内容 = 旧锚
    # 区块原位替换（数量仍为 1）+ verify anchored
    assert plan.read_text(encoding="utf-8").count("<!-- PR-SCORE") == 1
    v = gps.cmd_verify(str(plan), str(keys))
    assert v["ok"] and v["anchored"] and v["seal"] == "verified"
    assert v["snapshot"] == r2["snapshot"]


def test_seal_rotate_first_anchor_is_plain_inject(env):
    """--rotate 但 plan 尚无区块 → 等同普通 seal（无归档，plan_block=injected）。"""
    if not CRYPTO:
        pytest.skip("cryptography missing")
    keys = Path(env) / "keys"; keys.mkdir()
    _make_keys(keys)
    plan = _plan_doc(env)
    score = _write_score(env)
    r = gps.cmd_seal(str(plan), str(score), str(keys), rotate=True)
    assert r["ok"] and r["plan_block"] == "injected"
    assert "archived_snapshot" not in r
    v = gps.cmd_verify(str(plan), str(keys))
    assert v["ok"] and v["anchored"]


def test_seal_rotate_rollback_removes_new_snapshot_on_inject_failure(env, monkeypatch):
    """ECC-3E10D111D382：轮换时注入失败 → 回滚删除已写新快照（不留 snapshot_written 半态）。"""
    if not CRYPTO:
        pytest.skip("cryptography missing")
    keys = Path(env) / "keys"; keys.mkdir()
    _make_keys(keys)
    plan = _plan_doc(env)
    score = _write_score(env)
    assert gps.cmd_seal(str(plan), str(score), str(keys))["ok"]
    snap = _snapshot(plan)
    assert os.path.isfile(snap)

    def _boom(plan_path, block):
        return {"ok": False, "error": "simulated_replace_fail", "detail": "test"}
    monkeypatch.setattr(gps, "_replace_block", _boom)
    r = gps.cmd_seal(str(plan), str(score), str(keys), rotate=True)
    assert not r["ok"]
    assert r.get("snapshot_rolled_back") is True
    assert not os.path.isfile(snap)  # 新快照已回滚删除
    # 归档仍保留（旧锚不因回滚丢失）
    arch = [f for f in os.listdir(env) if f.startswith(gps.PRSCORE_PREFIX) and f != os.path.basename(snap)]
    assert arch, "归档应保留旧锚"


def test_block_sanitizes_double_hyphen(env):
    """HTML 注释安全：区块内容不出现 `--` 序列。"""
    if not CRYPTO:
        pytest.skip("cryptography missing")
    keys = Path(env) / "keys"; keys.mkdir()
    _make_keys(keys)
    # plan 名故意含 "--"（消毒路径验证）
    plan = _plan_doc(env, name="weird--name")
    score = _write_score(env)
    r = gps.cmd_seal(str(plan), str(score), str(keys))
    assert r["ok"]
    text = plan.read_text(encoding="utf-8")
    assert "--" not in text.replace("<!--", "").replace("-->", "").split("PR-SCORE")[1].split("\n-->")[0]
    assert "<!-- PR-SCORE" in text
