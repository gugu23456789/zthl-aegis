#!/usr/bin/env python3
"""审计署交付门 D4 / D5 红先臂（2026-10-24）。

D4（§21.8-a，额度兑换总量上限 + 冷却）
  缺口：`_grant_node_budget` 原先只有「单次 ≤ 硬顶」，**次数/总量无上限、无冷却**
  ⟹ 反复 `--code-fix` 可无限抬 `max`。判据面 = `budget-log` 中 `source=code-fix` 的当日记录。

D5（§21.8-b，一债一票 + 读侧封印）
  缺口①：`gk_credit_ledger.append` 不查重 ⟹ 同一 `ref` 可落多条 `success` = 双重计价。
  缺口②：`reconcile` 从不看封印 ⟹ 判据4b 在消费面恒真（旧账本+旧封印成对回放可静默回滚）。
"""
import datetime
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
SKILL = SCRIPTS.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import gk_budget_ledger as B  # noqa: E402
import gk_credit_ledger as C  # noqa: E402

OUT = {"model_version": "test-model", "temperature": 0.0, "seed": 0}
NOW = datetime.datetime(2026, 10, 24, 12, 0, tzinfo=datetime.timezone.utc)


def _st(tmp: Path) -> str:
    return str(tmp / ".gatekeeper.state")


def _budget_rows(state: str, rows) -> None:
    Path(state + B.SUFFIX).write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
        encoding="utf-8", newline="\n")


def _fx(ts, fm, tm):
    return {"ts": ts, "kind": "raise", "source": "code-fix",
            "from_max": fm, "to_max": tm, "reason": "test"}


def _outcome_rows(state: str, rows) -> None:
    Path(state + C.SUFFIX).write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
        encoding="utf-8", newline="\n")


@pytest.fixture()
def keys(tmp_path):
    """临时 Ed25519 audit key（不依赖仓库 `.keys`）。"""
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    d = tmp_path / "keys"
    d.mkdir()
    priv = Ed25519PrivateKey.generate()
    (d / "audit_ed25519.pem").write_bytes(priv.private_bytes(
        ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    (d / "audit_ed25519.pub").write_bytes(priv.public_key().public_bytes(
        ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
    return str(d)


# ───────────────────────── D4：code-fix 配额 ─────────────────────────
def test_d4_allows_under_quota(tmp_path):
    st = _st(tmp_path)
    _budget_rows(st, [_fx("2026-10-24T10:00:00Z", 12, 24), _fx("2026-10-24T11:00:00Z", 24, 36)])
    q = B.code_fix_quota(st, max_grants=16, total_cap=192, cooldown_s=10,
                         add=12, now=NOW)
    assert q["ok"] is True, q
    assert q["grants_today"] == 2 and q["total_today"] == 24, q


def test_d4_denies_at_max_grants(tmp_path):
    st = _st(tmp_path)
    _budget_rows(st, [_fx("2026-10-24T%02d:00:00Z" % h, 0, 12) for h in range(16)])
    q = B.code_fix_quota(st, max_grants=16, total_cap=9999, cooldown_s=0,
                         add=12, now=NOW)
    assert q["ok"] is False and q["reason"] == "max_grants", q


def test_d4_denies_total_cap_with_proposed_add(tmp_path):
    st = _st(tmp_path)
    rows = [_fx("2026-10-24T%02d:00:00Z" % h, 0, 12) for h in range(15)]   # 180
    _budget_rows(st, rows)
    q = B.code_fix_quota(st, max_grants=16, total_cap=192, cooldown_s=0,
                         add=24, now=NOW)
    assert q["ok"] is False and q["reason"] == "total_cap", q
    ok = B.code_fix_quota(st, max_grants=16, total_cap=192, cooldown_s=0,
                          add=12, now=NOW)
    assert ok["ok"] is True, ok


def test_d4_denies_within_cooldown(tmp_path):
    st = _st(tmp_path)
    _budget_rows(st, [_fx("2026-10-24T11:59:57Z", 0, 12)])        # 3s ago
    q = B.code_fix_quota(st, max_grants=16, total_cap=192, cooldown_s=10,
                         add=12, now=NOW)
    assert q["ok"] is False and q["reason"] == "cooldown", q
    assert q["seconds_since_last"] == 3, q


def test_d4_yesterday_does_not_count_toward_daily_quota(tmp_path):
    st = _st(tmp_path)
    _budget_rows(st, [_fx("2026-10-23T%02d:00:00Z" % h, 0, 12) for h in range(20)])
    q = B.code_fix_quota(st, max_grants=16, total_cap=192, cooldown_s=10,
                         add=12, now=NOW)
    assert q["ok"] is True and q["grants_today"] == 0, q


def test_d4_cli_subcommand_is_wired(tmp_path, capsys):
    """CLI 臂：`code-fix-quota` 必须真的分发（防 `dest` 撞名同族缺陷）。"""
    st = _st(tmp_path)
    _budget_rows(st, [_fx("2026-10-24T10:00:00Z", 12, 24)])
    rc = B.main(["code-fix-quota", "--state", st, "--max-grants", "16",
                 "--total-cap", "192", "--cooldown", "0", "--add", "12"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["ok"] is True, out


def test_d4_grant_function_has_deny_branch_and_kill_switch():
    """接线臂：配额判据必须落在 `_grant_node_budget` 内，且带 kill switch。"""
    txt = (SKILL / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    i = txt.index("_grant_node_budget() {")
    j = txt.index('_budget_override_record "${1:-code-fix}"', i)
    seg = txt[i:j]
    assert "code-fix-quota" in seg, "未在授额函数内调用配额判据"
    assert "GK_CODE_FIX_CAP" in seg, "缺 kill switch"
    assert '"ok": false' in seg and "return 0" in seg, "缺拒付分支"


# ───────────────────────── D5：一债一票 ─────────────────────────
def test_d5_duplicate_ref_same_kind_rejected(tmp_path):
    st = _st(tmp_path)
    assert C.append(st, "success", source="audit", ref="R1", **OUT).get("ok") is True
    dup = C.append(st, "success", source="audit", ref="R1", **OUT)
    assert dup.get("ok") is False, dup
    assert "duplicate_outcome_ref" in str(dup.get("error")), dup
    assert len(Path(st + C.SUFFIX).read_text(encoding="utf-8").splitlines()) == 1


def test_d5_duplicate_ref_cross_kind_rejected(tmp_path):
    st = _st(tmp_path)
    assert C.append(st, "fail", source="audit", ref="R2", **OUT).get("ok") is True
    dup = C.append(st, "success", source="audit", ref="R2", **OUT)
    assert dup.get("ok") is False, "fail 后改判 success 应拒（一次审计只记一票）: %r" % (dup,)
    assert dup["existing"]["kind"] == "fail"


def test_d5_distinct_refs_allowed(tmp_path):
    st = _st(tmp_path)
    assert C.append(st, "success", source="audit", ref="R1", **OUT).get("ok") is True
    assert C.append(st, "success", source="audit", ref="R2", **OUT).get("ok") is True


def test_d5_ref_optional_rows_still_allowed(tmp_path):
    """零回归臂：无 ref 的 outcome 不参与对账，也不应被查重挡下。"""
    st = _st(tmp_path)
    assert C.append(st, "success", source="audit", **OUT).get("ok") is True
    assert C.append(st, "success", source="audit", **OUT).get("ok") is True


def test_d5_reconcile_flags_duplicate_refs(tmp_path):
    st = _st(tmp_path)
    _outcome_rows(st, [
        {"ts": "2026-10-24T00:00:00Z", "id": "a1", "kind": "raise", "delta": 0},
        {"ts": "2026-10-24T00:00:01Z", "id": "a2", "kind": "success", "delta": 5, "ref": "a1"},
        {"ts": "2026-10-24T00:00:02Z", "id": "a3", "kind": "success", "delta": 5, "ref": "a1"},
    ])
    r = C.reconcile(st)
    assert r["duplicate_refs"] == ["a1"], r
    assert r["ok"] is False, "同 ref 两条 success 仍判 ok（双重计价未拦）: %r" % (r,)


def test_d5_reconcile_detects_tampered_seal(tmp_path, keys):
    st = _st(tmp_path)
    C.append(st, "success", source="audit", ref="R1", key_dir=keys, **OUT)
    with open(st + C.SUFFIX, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "x", "id": "zz", "kind": "success", "delta": 5}) + "\n")
    r = C.reconcile(st, key_dir=keys)
    assert r["seal"]["enforced"] is True, r
    assert r["seal"]["reason"] == "digest_mismatch", r
    assert r["ok"] is False, "封印被篡改仍判 ok（消费面恒真）: %r" % (r,)


def test_d5_reconcile_missing_seal_is_visible_not_fatal(tmp_path):
    """auto 模式：无封印的历史夹具不误伤，但必须显式标 `enforced=False`。"""
    st = _st(tmp_path)
    _outcome_rows(st, [{"ts": "x", "id": "a1", "kind": "success", "delta": 5, "ref": "R1"}])
    r = C.reconcile(st)
    assert r["seal"]["enforced"] is False and r["seal"]["reason"] == "seal_missing", r
    assert r["ok"] is True, r


def test_d5_reconcile_key_dir_requires_ed25519(tmp_path):
    st = _st(tmp_path)
    empty = tmp_path / "nokeys"
    empty.mkdir()
    C.append(st, "success", source="audit", ref="R1", key_dir=str(empty), **OUT)  # sha256-only
    r = C.reconcile(st, key_dir=str(empty))
    assert r["seal"]["enforced"] is True, r
    assert r["seal"]["reason"] == "weak_mode", r
    assert r["ok"] is False, "传 key_dir 后弱封印仍判 ok（4b 未收紧）: %r" % (r,)


def test_d5_reconcile_cli_has_require_seal_flag():
    """接线臂：CLI 必须能显式要求封印（`--require-seal`）。"""
    txt = (SCRIPTS / "gk_credit_ledger.py").read_text(encoding="utf-8")
    assert '"--require-seal"' in txt
    assert "require_seal=True if ns.require_seal else None" in txt
